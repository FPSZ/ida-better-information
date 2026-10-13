"""Identify the C runtime / compiler of a binary from its bytes."""
import re

from .binfmt import (_UBUNTU_GLIBC, _comment_toolchain, _glibc_hint_from_comment, _parse_elf_headers,
                     detect_go, detect_packer, detect_pe, detect_rust)
from .fingerprint import _arch_db, _lib_label, _load_fp, _present_in_buffer, _score


# ---------- Linux ELF ----------
def detect_elf(data, arch_hint=None, force=None, top=5, present_hook=None):
    r = {"os": "linux", "kind": None, "arch": None, "banner": None, "glibc_min": None,
         "build_id": None, "toolchain": None, "ranking": [], "best": None,
         "confidence": "low", "notes": []}
    hdr = _parse_elf_headers(data)
    r["arch"] = arch_hint or hdr["arch"]
    r["toolchain"] = _comment_toolchain(data)
    if hdr["tampered"]:
        r["notes"].append(hdr["tampered"] + ".")

    m = re.search(rb"\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00(.{20})", data, re.S)
    if m:
        r["build_id"] = m.group(1).hex()
    m = re.search(rb"GNU C Library[^\x00\n]{0,80}?(?:version|release)[^\x00\n]{0,20}?(\d+\.\d+)", data)
    if not m:
        m = re.search(rb"\bglibc[ -](\d+\.\d+)\b", data)
    if m:
        try:
            r["banner"] = m.group(1).decode()
        except Exception:
            pass
    reqs = [int(x) for x in re.findall(rb"GLIBC_2\.(\d+)", data)]
    if reqs:
        r["glibc_min"] = max(reqs)

    # static vs dynamic from the program headers, not from a string search
    if force:
        r["kind"] = force
    elif hdr["interp"] is not None:
        r["kind"] = "dynamic"
    elif hdr["needed"] > 0:
        r["kind"] = "dynamic"       # a shared object / library: imports its libc
    else:
        r["kind"] = "static"        # includes static-pie (ET_DYN, no interp, no NEEDED)

    if r["toolchain"]:
        r["notes"].append("toolchain: " + r["toolchain"])

    if r["banner"]:
        r["best"] = "glibc " + r["banner"]; r["confidence"] = "high"
        r["notes"].append("version banner present, exact."); return r

    if r["kind"] == "dynamic":
        interp = hdr["interp"] or ""
        if "ld-musl" in interp or b"/ld-musl" in data:
            r["best"] = "musl (dynamic)"; r["confidence"] = "medium"
            r["notes"].append("dynamically linked against musl (Alpine).")
            return r
        if r["glibc_min"] is not None:
            r["best"] = "glibc >=2.%s" % r["glibc_min"]; r["confidence"] = "medium"
            r["notes"].append("dynamic: needs glibc >= 2.%s (lower bound, not exact)." % r["glibc_min"])
        hint = _glibc_hint_from_comment(r["toolchain"])
        if hint:
            r["notes"].append("toolchain suggests ~glibc %s." % hint)
        if hdr["needed"]:
            r["notes"].append("links %d shared object(s); fingerprinting a dynamic target is skipped." % hdr["needed"])
        if r["build_id"]:
            r["notes"].append("build-id present; resolve the exact build at https://libc.rip .")
        if not r["best"]:
            r["best"] = "dynamic (libc version not pinned)"
        return r

    # ---- static: fingerprint against the matching architecture ----
    if r["arch"] not in _load_fp():
        r["notes"].append("no fingerprint DB for arch=%s; static libc version not identified." % r["arch"])
        r["best"] = "static %s (unsupported arch)" % (r["arch"] or "?")
        return r
    index, vers = _arch_db(r["arch"])
    if present_hook is not None:
        present = present_hook(index)               # IDA: scan the loaded image
    else:
        present = set()
        if hdr["exec_ranges"]:
            for off, sz in hdr["exec_ranges"]:
                present |= _present_in_buffer(data[off:off + sz], index)
        else:
            present = _present_in_buffer(data, index)
    ranking, scored = _score(present, vers, top)
    r["ranking"] = [(v, round(s, 3), h, n) for (v, s, h, n) in ranking]
    if not present:
        # nothing matched at all: never promote an all-zero ranking to a verdict
        r["ranking"] = []
        r["best"] = "static %s (no libc code recognised)" % r["arch"]
        r["confidence"] = "low"
        r["notes"].append("no function-byte anchor matched: packed/encrypted code, a libc "
                          "build outside the DB, or no code loaded.")
        return r
    if scored:
        bestver, bests = scored[0][0], scored[0][1]
        second = scored[1][1] if len(scored) > 1 else 0.0
        r["best"] = _lib_label(bestver)
        ratio = (bests / second) if second > 0 else 999.0
        margin = bests - second
        if ratio >= 1.15 and margin >= 0.03:
            r["confidence"] = "high"
        elif ratio >= 1.06 and margin >= 0.015:
            r["confidence"] = "medium"
        else:
            r["confidence"] = "low"
        r["notes"].append("static (%s): function byte-anchor match; clear leader = most likely build." % r["arch"])
        r["notes"].append("lead over #2: %.1f pts (x%.2f)." % (margin * 100, ratio))
        hint = _glibc_hint_from_comment(r["toolchain"])
        if hint and not bestver.startswith("musl"):
            agree = "agrees" if hint == bestver else "cf. toolchain ~%s" % hint
            r["notes"].append("toolchain cross-check: %s." % agree)
        # an explicit Ubuntu release tag in .comment is independent evidence; when it
        # names the same glibc as the fingerprint leader, a narrow lead is still trusted
        tagged = r["toolchain"] and any(t in r["toolchain"] for t, _ in _UBUNTU_GLIBC)
        if bests < 0.05:
            r["confidence"] = "low"
            r["notes"].append("hit-rate very low: build may be outside the DB.")
        elif r["confidence"] == "low" and tagged and hint == bestver:
            r["confidence"] = "medium"
            r["notes"].append("narrow lead, raised to medium: the Ubuntu toolchain tag names the same glibc.")
        elif r["confidence"] == "low":
            r["notes"].append("top candidates are close; try FLIRT for each.")
    return r


def detect(path=None, data=None, force=None, top=5, arch_hint=None, present_hook=None):
    """Identify the runtime/compiler of a binary. Returns a result dict."""
    if data is None:
        with open(path, "rb") as f:
            data = f.read()
    pack = detect_packer(data)
    if data[:2] == b"MZ":
        go = detect_go(data); rust = detect_rust(data)
        r = detect_pe(data)
        if pack:
            r["notes"].insert(0, "packer: " + pack)
        if go:
            r["best"] = "Go " + go["version"]; r["notes"].insert(0, "Go program (PE), version embedded.")
            r["confidence"] = "high"
        elif rust:
            r["best"] = "Rust " + rust["version"]; r["notes"].insert(0, rust["note"] + " (PE).")
            r["confidence"] = "high"
        else:
            r["best"] = "MSVC (see Rich/linker)"; r["confidence"] = "medium"
        r["ranking"] = []; r["kind"] = "pe"
        return r
    if data[:4] == b"\x7fELF":
        go = detect_go(data); rust = detect_rust(data)
        if go:
            return {"os": "linux", "kind": "go", "best": "Go " + go["version"], "ranking": [],
                    "confidence": "high", "build_id": None, "arch": _parse_elf_headers(data)["arch"],
                    "notes": ["Go program (ELF), version string embedded, exact.",
                              "Go ships its own runtime; glibc version is irrelevant."]}
        r = detect_elf(data, arch_hint=arch_hint, force=force, top=top, present_hook=present_hook)
        if rust:
            r["notes"].insert(0, rust["note"] + "; libc below is the system allocator backend.")
        if pack:
            r["notes"].insert(0, "packer: " + pack)
        return r
    if pack:
        return {"os": "?", "kind": None, "best": pack, "ranking": [], "confidence": "medium",
                "notes": ["packed binary"]}
    return {"os": "?", "kind": None, "best": None, "ranking": [], "confidence": "low",
            "notes": ["not an ELF/PE file"]}
