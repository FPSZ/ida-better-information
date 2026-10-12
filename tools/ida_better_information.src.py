#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA Better Information — know your binary before you read a single line.

A single-file IDA Pro plugin (and standalone CLI) that enriches a disassembly with
the context you normally have to dig for by hand:

  1. Runtime/compiler detection — identifies the C runtime or compiler of a target,
     even when it is stripped and statically linked, using function byte-fingerprint
     matching (glibc 2.19-2.44, musl 1.1.24-1.2.6) across x86_64 / i386 / aarch64,
     GLIBC_2.x version requirements, the .comment toolchain string, Go/Rust build
     strings, PE Rich headers, and UPX / PyInstaller / .NET packers.
  2. FLIRT auto-apply — applies the matching glibc/musl FLIRT signature so library
     functions get their real names back.
  3. libc annotations — adds a one-line "what it does" note to recognised libc
     functions (fopen -> open a file, returns FILE*, ...).
  4. Decompiler annotations — in the pseudocode, annotates library calls and MMX/SSE
     intrinsics with their real arguments AND decoded constants: sleep(10) ->
     "sleep 10 sec", open("flag", 0) -> 'open "flag" (O_RDONLY)', mprotect(p, n, 7) ->
     "protect ... (PROT_READ|WRITE|EXEC [RWX])", syscall(59, ...) -> "execve". These
     render live via a Hex-Rays hook (always fresh, nothing written), or can be
     persisted into the database as reversible comments.

The detector and the entire fingerprint database are embedded in THIS single file.
  - In IDA:   drop it into the `plugins/` directory and press Ctrl-Alt-G.
  - As a CLI: `python ida_better_information.py <binary>`.

Your existing names and comments are never clobbered, and every change made in a run
can be reverted with one click (Undo).

Repo:    https://github.com/FPSZ/ida-better-information
License: MIT
"""
import os, re, sys, json, gzip, base64, struct, argparse

__version__ = "2.0.0"

# ======================================================================
#  Embedded fingerprint database  (gzip + base64 of fingerprint.bin)
#  29 builds each for x86_64 / i386 / aarch64: glibc 2.19-2.44 + musl.
#  Rebuild with  tools/build-db.py  →  tools/build-fingerprint.py  →
#  tools/embed-fingerprint.py  (see tools/ for provenance).
# ======================================================================
_FP_CACHE = None       # {arch: {"table":[bytes...], "vers":{key:[idx...]}}}
_ARCH_CACHE = {}       # {arch: (prefix_index, {key:set(idx)})}


def _rd_uvarint(b, p):
    shift = val = 0
    while True:
        x = b[p]; p += 1
        val |= (x & 0x7F) << shift
        if not (x & 0x80):
            return val, p
        shift += 7


def _rd_str(b, p):
    n = b[p]; p += 1
    return b[p:p + n].decode(), p + n


def _decode_fp(blob):
    """Decode the compact IBIFP2 blob into {arch: {"table":[...], "vers":{...}}}."""
    if blob[:6] != b"IBIFP2":
        raise ValueError("bad fingerprint blob")
    p = 6
    narch = blob[p]; p += 1
    out = {}
    for _ in range(narch):
        arch, p = _rd_str(blob, p)
        ntab, p = _rd_uvarint(blob, p)
        table = []
        for _ in range(ntab):
            ln = blob[p]; p += 1
            table.append(blob[p:p + ln]); p += ln
        nver, p = _rd_uvarint(blob, p)
        vers = {}
        for _ in range(nver):
            key, p = _rd_str(blob, p)
            nidx, p = _rd_uvarint(blob, p)
            idx = []; prev = 0
            for _ in range(nidx):
                d, p = _rd_uvarint(blob, p)
                prev += d; idx.append(prev)
            vers[key] = idx
        out[arch] = {"table": table, "vers": vers}
    return out


def _load_fp():
    global _FP_CACHE
    if _FP_CACHE is None:
        try:
            _FP_CACHE = _decode_fp(gzip.decompress(base64.b64decode(_FP_B64)))
        except Exception:
            _FP_CACHE = {}
    return _FP_CACHE


def _arch_db(arch):
    """Return (prefix_index, {key:set(idx)}) for an arch, or (None, None)."""
    if arch in _ARCH_CACHE:
        return _ARCH_CACHE[arch]
    fp = _load_fp().get(arch)
    if not fp:
        _ARCH_CACHE[arch] = (None, None)
        return None, None
    table = fp["table"]
    index = {}
    for i, a in enumerate(table):
        index.setdefault(a[:4], []).append((i, a))
    vers = {k: set(v) for k, v in fp["vers"].items()}
    _ARCH_CACHE[arch] = (index, vers)
    return index, vers


def _lib_label(key):
    if key.startswith("musl"):
        return "musl " + key.split("_", 1)[-1]
    return "glibc " + key


# ======================================================================
#  Scanning — find which anchors are present in a byte buffer
# ======================================================================
def _scan_window(window, index, present):
    """Record ids of anchors occurring anywhere in a short window."""
    get = index.get
    n = len(window)
    for pos in range(max(0, n - 3)):
        for i, a in get(window[pos:pos + 4], ()):
            if i not in present and window[pos:pos + len(a)] == a:
                present.add(i)


def _present_in_buffer(buf, index):
    present = set()
    _scan_window(buf, index, present)
    return present


def _score(present, vers, top):
    scored = []
    for ver, ids in vers.items():
        if not ids:
            continue
        hit = len(present & ids)
        scored.append((ver, hit / len(ids), hit, len(ids)))
    scored.sort(key=lambda t: t[1], reverse=True)
    return scored[:top], scored


# ======================================================================
#  ELF parsing
# ======================================================================
EM_TO_ARCH = {3: "i386", 62: "x86_64", 183: "aarch64", 40: "arm",
              8: "mips", 10: "mips", 21: "ppc", 22: "ppc64", 243: "riscv",
              0xB7: "aarch64", 0x3E: "x86_64"}


def _parse_elf_headers(data):
    """Return dict with arch, class, interp, needed count, exec byte ranges."""
    r = {"arch": None, "bits": None, "etype": None, "interp": None,
         "needed": 0, "exec_ranges": [], "machine": None}
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return r
    is64 = data[4] == 2
    en = "<" if data[5] == 1 else ">"
    r["bits"] = 64 if is64 else 32
    r["etype"] = struct.unpack_from(en + "H", data, 16)[0]
    machine = struct.unpack_from(en + "H", data, 18)[0]
    r["machine"] = machine
    r["arch"] = EM_TO_ARCH.get(machine)
    try:
        if is64:
            phoff = struct.unpack_from(en + "Q", data, 32)[0]
            phentsize, phnum = struct.unpack_from(en + "HH", data, 54)
        else:
            phoff = struct.unpack_from(en + "I", data, 28)[0]
            phentsize, phnum = struct.unpack_from(en + "HH", data, 42)
        for i in range(phnum):
            off = phoff + i * phentsize
            if off + phentsize > len(data):
                break
            p_type = struct.unpack_from(en + "I", data, off)[0]
            if is64:
                p_flags = struct.unpack_from(en + "I", data, off + 4)[0]
                p_offset = struct.unpack_from(en + "Q", data, off + 8)[0]
                p_filesz = struct.unpack_from(en + "Q", data, off + 32)[0]
                dent = 16
            else:
                p_offset = struct.unpack_from(en + "I", data, off + 4)[0]
                p_filesz = struct.unpack_from(en + "I", data, off + 16)[0]
                p_flags = struct.unpack_from(en + "I", data, off + 24)[0]
                dent = 8
            if p_type == 3:                                   # PT_INTERP
                s = data[p_offset:p_offset + p_filesz].split(b"\x00", 1)[0]
                r["interp"] = s.decode("latin1", "replace")
            elif p_type == 2:                                 # PT_DYNAMIC
                for j in range(0, p_filesz, dent):
                    o = p_offset + j
                    if o + dent > len(data):
                        break
                    tag = struct.unpack_from(en + ("q" if is64 else "i"), data, o)[0]
                    if tag == 0:
                        break
                    if tag == 1:                              # DT_NEEDED
                        r["needed"] += 1
            elif p_type == 1 and (p_flags & 1):               # PT_LOAD + X
                r["exec_ranges"].append((p_offset, p_filesz))
    except Exception:
        pass
    return r


def _comment_toolchain(data):
    """Extract the .comment producer string (GCC/clang/rustc) if present."""
    m = re.search(rb"GCC: \(([^)]*)\) ([0-9][^\x00\n]*)", data)
    if m:
        return "gcc %s (%s)" % (m.group(2).decode("latin1", "replace"),
                                m.group(1).decode("latin1", "replace"))
    m = re.search(rb"(?:Ubuntu |Debian )?clang version ([0-9][^\x00\n]{0,40})", data)
    if m:
        return "clang " + m.group(1).decode("latin1", "replace")
    return None


# map an Ubuntu gcc toolchain string to the glibc it ships (coarse cross-check)
_UBUNTU_GLIBC = [
    ("16.04", "2.23"), ("18.04", "2.27"), ("20.04", "2.31"), ("22.04", "2.35"),
    ("23.04", "2.37"), ("23.10", "2.38"), ("24.04", "2.39"), ("24.10", "2.40"),
    ("25.04", "2.41"), ("25.10", "2.42"),
]
# gcc major -> plausible glibc floor, used only when no Ubuntu tag is embedded
_GCC_GLIBC = {"9": "2.31", "10": "2.31", "11": "2.35", "12": "2.35",
              "13": "2.37", "14": "2.39", "15": "2.41"}


def _glibc_hint_from_comment(cmt):
    if not cmt:
        return None
    for tag, ver in _UBUNTU_GLIBC:
        if tag in cmt:
            return ver
    m = re.search(r"gcc (\d+)\.", cmt)
    if m:
        return _GCC_GLIBC.get(m.group(1))
    return None


# ======================================================================
#  Packer / language detection
# ======================================================================
def detect_packer(data):
    if b"UPX!" in data[:4096] or b"UPX!" in data[-4096:] or b"$Info: This file is packed with the UPX" in data:
        return "UPX (run `upx -d` first; fingerprints are meaningless while packed)"
    if b"PyInstaller" in data or b"pyi-" in data or b"_MEIPASS" in data:
        return "PyInstaller (extract with pyinstxtractor, then decompile the .pyc)"
    if b"Nuitka" in data or b"__nuitka" in data:
        return "Nuitka-compiled Python"
    if b"py2exe" in data:
        return "py2exe"
    return None


def detect_rust(data):
    m = re.search(rb"/rustc/([0-9a-f]{8,40})/", data)
    m2 = re.search(rb"rustc-(\d+\.\d+\.\d+)", data) or re.search(rb"rustc version (\d+\.\d+\.\d+)", data)
    if m or m2 or b"__rust_alloc" in data or b"RUST_BACKTRACE" in data:
        ver = m2.group(1).decode() if m2 else "unknown"
        commit = (" (rustc %s)" % m.group(1).decode()[:12]) if m else ""
        return {"lang": "rust", "version": ver, "note": "Rust program" + commit}
    return None


def detect_go(data):
    # require the buildinfo blob, not merely a "go1.x" substring
    has_buildinf = (b"\xff Go buildinf:" in data) or (b"\xfa Go buildinf:" in data)
    if not has_buildinf and b"runtime.buildVersion" not in data and b"Go build ID:" not in data:
        return None
    m = re.search(rb"go1\.\d{1,2}(?:\.\d{1,3})?", data)
    ver = m.group(0).decode() if m else "unknown"
    return {"lang": "go", "version": ver}


# ---------- Windows PE ----------
def _decode_rich(data, pe_off):
    try:
        head = data[:pe_off]
        ri = head.rfind(b"Rich")
        if ri < 0:
            return None
        key = struct.unpack("<I", head[ri + 4:ri + 8])[0]
        di = head.rfind(struct.pack("<I", 0x536E6144 ^ key), 0, ri)   # "DanS" ^ key
        if di < 0:
            return None
        comps = []
        off = di + 16
        while off + 8 <= ri:
            v = struct.unpack("<I", head[off:off + 4])[0] ^ key
            c = struct.unpack("<I", head[off + 4:off + 8])[0] ^ key
            prodid, build = v >> 16, v & 0xFFFF
            if prodid or build:
                comps.append((prodid, build, c))
            off += 8
        return comps
    except Exception:
        return None


def detect_pe(data):
    r = {"os": "windows", "arch": None, "linker": None, "rich": None, "notes": []}
    try:
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            r["notes"].append("MZ but PE header looks off"); return r
        machine = struct.unpack("<H", data[e_lfanew + 4:e_lfanew + 6])[0]
        r["arch"] = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine, hex(machine))
        opt = e_lfanew + 24
        r["linker"] = "%d.%d" % (data[opt + 2], data[opt + 3])
        if b"_CorExeMain" in data or b"mscoree.dll" in data or b"#~\x00" in data:
            r["notes"].append(".NET / managed PE (decompile with ILSpy / dnSpy).")
        if b"__gnu_exception_handler" in data or b"libgcc" in data or b"mingw" in data.lower():
            r["notes"].append("MinGW-compiled (GCC on Windows).")
        comps = _decode_rich(data, e_lfanew)
        if comps:
            top = max(comps, key=lambda t: t[1])
            r["rich"] = comps
            r["notes"].append("Rich header: highest build=%d (bigger = newer MSVC; cross-ref the MSVC table)." % top[1])
        else:
            r["notes"].append("no Rich header (non-MSVC toolchain, or stripped).")
        r["notes"].append("Windows library funcs: IDA's bundled MSVC/UCRT FLIRT usually names them.")
    except Exception as e:
        r["notes"].append("PE parse error: %s" % e)
    return r


# ---------- Linux ELF ----------
def detect_elf(data, arch_hint=None, force=None, top=5, present_hook=None):
    r = {"os": "linux", "kind": None, "arch": None, "banner": None, "glibc_min": None,
         "build_id": None, "toolchain": None, "ranking": [], "best": None,
         "confidence": "low", "notes": []}
    hdr = _parse_elf_headers(data)
    r["arch"] = arch_hint or hdr["arch"]
    r["toolchain"] = _comment_toolchain(data)

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
        present = present_hook(index)               # IDA: scan function starts
    else:
        present = set()
        if hdr["exec_ranges"]:
            for off, sz in hdr["exec_ranges"]:
                _scan_window(data[off:off + sz], index, present)
        else:
            _scan_window(data, index, present)
    ranking, scored = _score(present, vers, top)
    r["ranking"] = [(v, round(s, 3), h, n) for (v, s, h, n) in ranking]
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
        if bests < 0.05:
            r["confidence"] = "low"
            r["notes"].append("hit-rate very low: build may be outside the DB.")
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


# ======================================================================
#  Standalone CLI
# ======================================================================
def _cli():
    ap = argparse.ArgumentParser(
        prog="ida_better_information.py",
        description="Detect the C runtime / compiler of a binary (glibc, musl, Go, Rust, MSVC).")
    ap.add_argument("binary", nargs="?", help="target ELF/PE file")
    ap.add_argument("--static", action="store_true", help="force static analysis")
    ap.add_argument("--dynamic", action="store_true", help="force dynamic analysis")
    ap.add_argument("--arch", choices=["x86_64", "i386", "aarch64"], help="override the detected architecture")
    ap.add_argument("--top", type=int, default=5, help="how many candidates to rank (default 5)")
    ap.add_argument("--json", action="store_true", help="emit the raw result as JSON")
    args = ap.parse_args()
    if not args.binary:
        print("IDA Better Information v%s" % __version__)
        ap.print_help(); sys.exit(1)
    force = "static" if args.static else ("dynamic" if args.dynamic else None)
    r = detect(path=args.binary, force=force, top=args.top, arch_hint=args.arch)
    if args.json:
        print(json.dumps(r, indent=2)); return
    print("=" * 60)
    print("target    :", args.binary)
    print("type      :", r.get("os"), "/", r.get("kind"), "/", r.get("arch") or "?")
    if r.get("build_id"):
        print("build-id  :", r["build_id"])
    if r.get("arch") and r.get("os") == "windows":
        print("linker    :", r.get("linker"))
    if r.get("ranking"):
        print("-" * 60); print("version ranking (hit-rate  hits/anchors):")
        for v, s, h, n in r["ranking"]:
            print("  %-12s %6.1f%%  %d/%d  %s" % (_lib_label(v), s * 100, h, n, "#" * int(s * 30)))
    print("-" * 60)
    print("verdict   :", r.get("best"), "  confidence =", r.get("confidence"))
    for note in r.get("notes", []):
        print("  -", note)
    print("=" * 60)


# ======================================================================
#  Shared tables: libc descriptions, argument templates, constant decoders
# ======================================================================
def canon(name):
    n = name or ''
    n = re.sub(r'^\.+', '', n)               # import-thunk notation: .open -> open
    n = re.sub(r'^j_', '', n)                # jump thunk: j_open -> open
    n = re.sub(r'^_+', '', n); n = re.sub(r'@.*$', '', n)
    n = re.sub(r'^isoc\d+_', '', n)          # __isoc99_scanf / __isoc23_strtol
    n = re.sub(r'_chk$', '', n); n = re.sub(r'_unlocked$', '', n)
    n = re.sub(r'^IO_', '', n); n = re.sub(r'^new_', '', n)
    n = re.sub(r'^libc_', '', n); n = re.sub(r'_internal$', '', n); n = re.sub(r'64$', '', n)
    return n


# __*_chk and friends carry extra leading/trailing args; map to (base, kept-arg-indices).
# A kept index of -1 means "insert a placeholder" (not used); None list = all args.
_VARIANTS = {
    "__printf_chk":    ("printf",    [1]),                 # (flag, fmt, ...)
    "__fprintf_chk":   ("fprintf",   [0, 2]),              # (fp, flag, fmt, ...)
    "__dprintf_chk":   ("dprintf",   [0, 2]),
    "__sprintf_chk":   ("sprintf",   [0, 3]),              # (s, flag, slen, fmt, ...)
    "__snprintf_chk":  ("snprintf",  [0, 1, 4]),           # (s, maxlen, flag, slen, fmt, ...)
    "__vprintf_chk":   ("vprintf",   [1]),
    "__vfprintf_chk":  ("vfprintf",  [0, 2]),
    "__vsnprintf_chk": ("vsnprintf", [0, 1, 4]),
    "__memcpy_chk":    ("memcpy",    [0, 1, 2]),           # (dst, src, len, destlen)
    "__memmove_chk":   ("memmove",   [0, 1, 2]),
    "__mempcpy_chk":   ("mempcpy",   [0, 1, 2]),
    "__memset_chk":    ("memset",    [0, 1, 2]),
    "__strcpy_chk":    ("strcpy",    [0, 1]),
    "__strncpy_chk":   ("strncpy",   [0, 1, 2]),
    "__strcat_chk":    ("strcat",    [0, 1]),
    "__strncat_chk":   ("strncat",   [0, 1, 2]),
    "__stpcpy_chk":    ("stpcpy",    [0, 1]),
}


def resolve_variant(name):
    """Return (base_key, kept_indices_or_None) for a possibly fortified name."""
    n = (name or "").lstrip("._")            # drop import-thunk dots / leading underscores
    key = "__" + n
    if key in _VARIANTS:
        return _VARIANTS[key]
    return canon(name), None


# ======================================================================
#  IDA plugin
# ======================================================================
try:
    import idaapi, ida_kernwin, ida_auto, ida_funcs, idautils, idc, ida_name, ida_bytes
    _IN_IDA = True
except Exception:
    _IN_IDA = False

if _IN_IDA:
    try:
        from PySide6 import QtWidgets; _HAS_QT = True
    except Exception:
        try:
            from PyQt5 import QtWidgets; _HAS_QT = True
        except Exception:
            _HAS_QT = False

    PFX = "libc: "
    OPX = "op: "
    SYS = "sys: "
    _MANAGED = (PFX, OPX, SYS)

    DESC = {
     "fopen":"open a file, returns FILE*","freopen":"reopen/redirect a stream","fclose":"close a stream",
     "fread":"read N bytes from a stream","fwrite":"write N bytes to a stream","fseek":"move file position",
     "fseeko":"move file position (large)","ftell":"current file position","ftello":"file position (large)","rewind":"rewind to start",
     "fgets":"read a line","fputs":"write a string","fgetc":"read one char","fputc":"write one char",
     "getc":"read one char","putc":"write one char","getchar":"read char from stdin","putchar":"write char to stdout",
     "puts":"print string + newline to stdout","gets":"read a line (unsafe)",
     "printf":"formatted output to stdout","fprintf":"formatted output to a stream","dprintf":"formatted output to an fd","sprintf":"formatted write to a string",
     "snprintf":"formatted write (bounded)","vprintf":"printf, va_list","vfprintf":"fprintf, va_list","vsnprintf":"vsnprintf",
     "scanf":"formatted read from stdin","fscanf":"formatted read from stream","sscanf":"parse from a string",
     "perror":"print error to stderr","fflush":"flush stream buffer","setvbuf":"set stream buffering","setbuf":"set stream buffering","feof":"end-of-file?","ferror":"stream error?","fileno":"get stream fd",
     "open":"open a file (fd)","openat":"open relative to a dir fd","close":"close an fd","read":"read from fd","write":"write to fd","lseek":"move fd position",
     "pread":"read fd at offset","pwrite":"write fd at offset","dup":"duplicate fd","dup2":"duplicate fd to number","pipe":"create a pipe","fcntl":"fd control",
     "stat":"file metadata","fstat":"fd metadata","lstat":"link metadata","access":"check file access","chmod":"change mode","chown":"change owner",
     "fork":"create child process","vfork":"create child (shared)","execve":"exec a program (replace image)","execl":"exec a program","execlp":"exec (search PATH)","execvp":"exec (search PATH)",
     "waitpid":"wait for child","wait":"wait for child","kill":"send a signal","raise":"send signal to self","signal":"set signal handler","sigaction":"set signal handler (adv.)",
     "alarm":"schedule SIGALRM","sleep":"sleep (seconds)","usleep":"sleep (microseconds)","nanosleep":"high-res sleep",
     "getpid":"get process id","getppid":"get parent pid","getuid":"get user id","geteuid":"get effective uid","setuid":"set uid","ptrace":"process trace / anti-debug","prctl":"process control","personality":"set exec domain (ASLR off?)",
     "mmap":"map memory/file","munmap":"unmap memory","mprotect":"change page protection","mremap":"resize a mapping","brk":"set program break","sbrk":"grow heap",
     "socket":"create a socket","connect":"connect","bind":"bind address","listen":"listen","accept":"accept connection","setsockopt":"set socket option","getsockopt":"get socket option",
     "send":"send data","recv":"receive data","sendto":"send (UDP)","recvfrom":"receive (UDP)","htons":"host->net short","htonl":"host->net long","ntohs":"net->host short","ntohl":"net->host long",
     "malloc":"allocate heap","calloc":"allocate + zero","realloc":"resize allocation","free":"free heap",
     "aligned_alloc":"aligned alloc","posix_memalign":"aligned alloc","memalign":"aligned alloc","valloc":"page-aligned alloc",
     "exit":"exit process (run cleanup)","_exit":"exit now (no cleanup)","abort":"abnormal exit (SIGABRT)","atexit":"register exit callback",
     "atoi":"string -> int","atol":"-> long","atoll":"-> long long","strtol":"-> long (base)","strtoul":"-> ulong",
     "strtoll":"-> long long","strtod":"-> double","qsort":"quicksort (with cmp)","bsearch":"binary search",
     "rand":"pseudo-random","srand":"seed rand","random":"pseudo-random","srandom":"seed random","getrandom":"random bytes (syscall)",
     "getenv":"read env var","setenv":"set env var","putenv":"set env var","unsetenv":"clear env var","system":"run a shell command","popen":"run a command, get a pipe","getopt":"parse CLI options",
     "abs":"int abs","labs":"long abs",
     "strlen":"string length","strnlen":"length (bounded)","strcpy":"copy string","strncpy":"copy (bounded)","stpcpy":"copy, return end",
     "strcat":"concatenate","strncat":"concatenate (bounded)","strcmp":"compare strings","strncmp":"compare (n bytes)",
     "strcasecmp":"compare (ignore case)","strncasecmp":"compare (ignore case, n)","strchr":"first char","strrchr":"last char",
     "strstr":"find substring","strtok":"split by delimiter","strdup":"duplicate string (malloc)","strndup":"duplicate (bounded)","strerror":"errno -> text","strspn":"prefix length (set)","strcspn":"prefix length (not set)","strpbrk":"find any of set",
     "memcpy":"memory copy (no overlap)","memmove":"memory copy (overlap ok)","memset":"fill memory (often zero)","memcmp":"compare memory",
     "memchr":"find byte in memory","bzero":"zero memory","bcopy":"copy memory","mempcpy":"copy, return end",
     "isalpha":"is letter?","isdigit":"is digit?","isalnum":"is alnum?","isspace":"is whitespace?","isupper":"is upper?",
     "islower":"is lower?","isxdigit":"is hex digit?","toupper":"to upper","tolower":"to lower",
     "time":"time (seconds)","gettimeofday":"time (microseconds)","clock":"CPU time","clock_gettime":"high-res clock","localtime":"time -> local struct","strftime":"format time",
     "stack_chk_fail":"stack canary failed (overflow)","assert_fail":"assertion failed","cxa_atexit":"register destructor","cxa_finalize":"run destructors",
     "start_main":"real entry point, calls main","syscall":"raw system call",
    }

    DESC_ZH = {
     "fopen":"打开文件,返回FILE*","freopen":"重开/重定向文件流","fclose":"关闭文件流",
     "fread":"从文件读N字节到缓冲区","fwrite":"把缓冲区N字节写入文件","fseek":"移动文件读写位置",
     "fseeko":"移动文件读写位置(大文件)","ftell":"取当前文件位置","ftello":"取文件位置(大文件)","rewind":"文件位置回开头",
     "fgets":"读一行到缓冲区","fputs":"写字符串到流","fgetc":"读一个字符","fputc":"写一个字符",
     "getc":"读一个字符","putc":"写一个字符","getchar":"从stdin读字符","putchar":"向stdout写字符",
     "puts":"打印字符串+换行到stdout","gets":"读一行(危险)",
     "printf":"格式化输出到stdout","fprintf":"格式化输出到流","dprintf":"格式化输出到fd","sprintf":"格式化写入字符串",
     "snprintf":"格式化写入(带长度上限)","vprintf":"printf的va_list版","vfprintf":"fprintf的va_list版","vsnprintf":"vsnprintf",
     "scanf":"从stdin格式化读入","fscanf":"从流格式化读入","sscanf":"从字符串解析",
     "perror":"打印错误到stderr","fflush":"刷新流缓冲","setvbuf":"设置流缓冲","setbuf":"设置流缓冲","feof":"是否文件尾","ferror":"流是否出错","fileno":"取流的fd",
     "open":"打开文件(fd)","openat":"相对目录fd打开","close":"关闭fd","read":"从fd读","write":"向fd写","lseek":"移动fd位置",
     "pread":"按偏移读fd","pwrite":"按偏移写fd","dup":"复制fd","dup2":"复制fd到指定号","pipe":"创建管道","fcntl":"fd控制",
     "stat":"取文件信息","fstat":"取fd信息","lstat":"取链接信息","access":"检查访问权限","chmod":"改权限","chown":"改属主",
     "fork":"创建子进程","vfork":"创建子进程(共享)","execve":"执行程序(替换映像)","execl":"执行程序","execlp":"执行程序(查PATH)","execvp":"执行程序(查PATH)",
     "waitpid":"等待子进程","wait":"等待子进程","kill":"发信号","raise":"给自己发信号","signal":"设信号处理","sigaction":"设信号处理(高级)",
     "alarm":"定时SIGALRM","sleep":"睡眠(秒)","usleep":"睡眠(微秒)","nanosleep":"高精度睡眠",
     "getpid":"取进程ID","getppid":"取父进程ID","getuid":"取用户ID","geteuid":"取有效UID","setuid":"设UID","ptrace":"进程跟踪/反调试常用","prctl":"进程控制","personality":"设执行域(常用于关ASLR)",
     "mmap":"映射内存/文件","munmap":"解除内存映射","mprotect":"改内存页权限","mremap":"重设映射大小","brk":"设置program break","sbrk":"扩堆",
     "socket":"创建套接字","connect":"连接","bind":"绑定地址","listen":"监听","accept":"接受连接","setsockopt":"设套接字选项","getsockopt":"取套接字选项",
     "send":"发送数据","recv":"接收数据","sendto":"发送(UDP)","recvfrom":"接收(UDP)","htons":"主机序转网络序(短)","htonl":"主机序转网络序(长)","ntohs":"网络序转主机序(短)","ntohl":"网络序转主机序(长)",
     "malloc":"分配堆内存","calloc":"分配并清零","realloc":"重分配","free":"释放堆内存",
     "aligned_alloc":"对齐分配","posix_memalign":"对齐分配","memalign":"对齐分配","valloc":"页对齐分配",
     "exit":"退出进程(走清理)","_exit":"立即退出(不清理)","abort":"异常终止(SIGABRT)","atexit":"注册退出回调",
     "atoi":"字符串转int","atol":"转long","atoll":"转longlong","strtol":"转long(带进制)","strtoul":"转ulong",
     "strtoll":"转longlong","strtod":"转double","qsort":"快排(带比较)","bsearch":"二分查找",
     "rand":"伪随机数","srand":"设随机种子","random":"伪随机数","srandom":"设随机种子","getrandom":"取随机字节(系统调用)",
     "getenv":"读环境变量","setenv":"设环境变量","putenv":"设环境变量","unsetenv":"清环境变量","system":"执行shell命令","popen":"执行命令并取管道","getopt":"解析命令行选项",
     "abs":"int绝对值","labs":"long绝对值",
     "strlen":"求字符串长度","strnlen":"求长度(上限)","strcpy":"复制字符串","strncpy":"复制(上限)","stpcpy":"复制返回末尾",
     "strcat":"拼接字符串","strncat":"拼接(上限)","strcmp":"比较字符串","strncmp":"比较(前n字节)",
     "strcasecmp":"比较(忽略大小写)","strncasecmp":"比较(忽略大小写,上限)","strchr":"找字符首现","strrchr":"找字符末现",
     "strstr":"找子串","strtok":"按分隔符切分","strdup":"复制字符串(malloc)","strndup":"复制(上限)","strerror":"错误码转描述","strspn":"前缀长度(属于集合)","strcspn":"前缀长度(不属于集合)","strpbrk":"找集合中任一字符",
     "memcpy":"内存复制(不重叠)","memmove":"内存复制(可重叠)","memset":"内存填充(常清零)","memcmp":"内存比较",
     "memchr":"内存找字节","bzero":"内存清零","bcopy":"内存复制","mempcpy":"内存复制返回末尾",
     "isalpha":"是否字母","isdigit":"是否数字","isalnum":"是否字母数字","isspace":"是否空白","isupper":"是否大写",
     "islower":"是否小写","isxdigit":"是否十六进制位","toupper":"转大写","tolower":"转小写",
     "time":"取时间(秒)","gettimeofday":"取时间(微秒)","clock":"取CPU时间","clock_gettime":"高精度时钟","localtime":"时间转本地结构","strftime":"格式化时间",
     "stack_chk_fail":"栈溢出保护触发(canary失败)","assert_fail":"断言失败","cxa_atexit":"注册析构","cxa_finalize":"运行析构",
     "start_main":"程序真正入口,调用main","syscall":"裸系统调用",
    }

    # argument-aware templates (en, zh). {0},{1},... = rendered/decoded actual args.
    TMPL = {
     "sleep":("sleep {0} sec","睡眠 {0} 秒"), "usleep":("sleep {0} us","睡眠 {0} 微秒"),
     "nanosleep":("high-res sleep","高精度睡眠"), "alarm":("SIGALRM in {0}s","{0} 秒后 SIGALRM"),
     "fopen":("open {0} (mode {1})","打开 {0}(模式 {1})"),
     "freopen":("reopen {0} (mode {1})","重开 {0}(模式 {1})"),
     "open":("open {0} ({1})","打开 {0}({1})"), "openat":("openat {1} ({2})","相对打开 {1}({2})"),
     "close":("close fd {0}","关闭 fd {0}"),
     "read":("read {2} bytes from {0}","从 {0} 读 {2} 字节"),
     "write":("write {2} bytes to {0}","向 {0} 写 {2} 字节"),
     "lseek":("seek {0} to {1} ({2})","{0} 定位到 {1} ({2})"),
     "fread":("read {1}x{2} bytes -> {0}","读 {1}x{2} 字节 -> {0}"),
     "fwrite":("write {1}x{2} bytes from {0}","写 {1}x{2} 字节(来自 {0})"),
     "fseek":("seek {0} to {1}","{0} 定位到 {1}"), "fgets":("read a line -> {0} (max {1})","读一行 -> {0}(上限 {1})"),
     "malloc":("alloc {0} bytes","分配 {0} 字节"), "calloc":("alloc {0}x{1}, zeroed","分配 {0}x{1} 并清零"),
     "realloc":("resize {0} -> {1} bytes","把 {0} 重分配为 {1} 字节"), "free":("free {0}","释放 {0}"),
     "aligned_alloc":("alloc {1} bytes, {0}-aligned","分配 {1} 字节,{0} 对齐"),
     "memcpy":("copy {2} bytes {1} -> {0}","复制 {2} 字节 {1} -> {0}"),
     "memmove":("move {2} bytes {1} -> {0}","搬移 {2} 字节 {1} -> {0}"),
     "memset":("fill {0} with {1}, {2} bytes","把 {0} 填成 {1},共 {2} 字节"),
     "memcmp":("compare {2} bytes {0},{1}","比较 {2} 字节 {0},{1}"),
     "mmap":("map {1} bytes, {2}","映射 {1} 字节,{2}"), "mprotect":("protect {1} bytes @ {0}: {2}","{0} 起 {1} 字节权限: {2}"),
     "strlen":("length of {0}","{0} 的长度"), "strcpy":("copy {1} -> {0}","复制 {1} -> {0}"),
     "strncpy":("copy {2} bytes {1} -> {0}","复制 {2} 字节 {1} -> {0}"),
     "strcat":("append {1} to {0}","把 {1} 接到 {0}"), "strcmp":("compare {0}, {1}","比较 {0}, {1}"),
     "strncmp":("compare first {2} bytes of {0}, {1}","比较 {0}, {1} 的前 {2} 字节"),
     "strstr":("find {1} in {0}","在 {0} 里找 {1}"), "strchr":("find char {1} in {0}","在 {0} 里找字符 {1}"),
     "strtol":("{0} -> long (base {2})","{0} 转 long(进制 {2})"),
     "atoi":("{0} -> int","{0} 转 int"), "atol":("{0} -> long","{0} 转 long"),
     "printf":("printf {0}","按 {0} 格式打印"), "fprintf":("fprintf {1} to {0}","向 {0} 按 {1} 格式打印"),
     "sprintf":("sprintf -> {0}, fmt {1}","按 {1} 格式写入 {0}"),
     "snprintf":("write <= {1} bytes -> {0}, fmt {2}","最多 {1} 字节按 {2} 写入 {0}"),
     "puts":("print {0} + newline","打印 {0} 并换行"), "fputs":("write {0}","写字符串 {0}"),
     "putchar":("output char {0}","输出字符 {0}"),
     "system":("run shell: {0}","执行 shell 命令:{0}"), "popen":("run: {0}","执行命令:{0}"),
     "getenv":("read env {0}","读环境变量 {0}"),
     "setenv":("set env {0}={1}","设环境变量 {0}={1}"), "exit":("exit({0})","退出进程 ({0})"),
     "signal":("on {0} -> {1}","{0} 的处理设为 {1}"), "kill":("send {1} to pid {0}","给 pid {0} 发 {1}"),
     "raise":("raise {0}","自发 {0}"),
     "ptrace":("ptrace {0}","ptrace {0}"), "prctl":("prctl {0}","prctl {0}"),
     "socket":("socket {0}/{1}","套接字 {0}/{1}"),
     "access":("access {0} ({1})","检查 {0} 的访问 ({1})"),
     "qsort":("sort {1} items of {2} bytes","排序 {1} 个元素(每个 {2} 字节)"),
     "srand":("seed rand = {0}","随机种子 = {0}"),
     "getrandom":("random {1} bytes -> {0}","取 {1} 随机字节 -> {0}"),
     "memalign":("alloc {1} bytes, {0}-aligned","分配 {1} 字节,{0} 对齐"),
    }

    # ---------- constant decoders ----------
    def _bits(val, table):
        parts = [name for bit, name in table if bit and (val & bit) == bit]
        rest = val
        for bit, _ in table:
            if bit and (val & bit) == bit:
                rest &= ~bit
        zero = [name for bit, name in table if bit == 0]
        if not parts and zero:
            parts = [zero[0]]
        if rest:
            parts.append("0x%X" % rest)
        return "|".join(parts) if parts else "0"

    _O = [(0, "O_RDONLY"), (1, "O_WRONLY"), (2, "O_RDWR"), (0o100, "O_CREAT"),
          (0o200, "O_EXCL"), (0o1000, "O_TRUNC"), (0o2000, "O_APPEND"), (0o4000, "O_NONBLOCK"),
          (0o400000, "O_DIRECTORY"), (0o2000000, "O_CLOEXEC"), (0o40000, "O_LARGEFILE")]

    def _dec_oflags(v):
        acc = v & 3
        base = {0: "O_RDONLY", 1: "O_WRONLY", 2: "O_RDWR"}.get(acc, "?")
        extra = _bits(v & ~3, [(b, n) for b, n in _O if b not in (0, 1, 2)])
        return base + ("|" + extra if extra and extra != "0" else "")

    _PROT = [(1, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC"), (0, "PROT_NONE")]

    def _dec_prot(v):
        s = _bits(v, _PROT)
        return s + (" [RWX]" if (v & 7) == 7 else "")

    _MAP = [(1, "MAP_SHARED"), (2, "MAP_PRIVATE"), (0x10, "MAP_FIXED"), (0x20, "MAP_ANONYMOUS"),
            (0x100, "MAP_GROWSDOWN"), (0x4000, "MAP_POPULATE")]
    _SIG = {1:"SIGHUP",2:"SIGINT",3:"SIGQUIT",4:"SIGILL",5:"SIGTRAP",6:"SIGABRT",7:"SIGBUS",
            8:"SIGFPE",9:"SIGKILL",10:"SIGUSR1",11:"SIGSEGV",12:"SIGUSR2",13:"SIGPIPE",
            14:"SIGALRM",15:"SIGTERM",17:"SIGCHLD",18:"SIGCONT",19:"SIGSTOP",20:"SIGTSTP"}
    _WHENCE = {0:"SEEK_SET",1:"SEEK_CUR",2:"SEEK_END"}
    _PTRACE = {0:"PTRACE_TRACEME",1:"PTRACE_PEEKTEXT",2:"PTRACE_PEEKDATA",3:"PTRACE_PEEKUSER",
               4:"PTRACE_POKETEXT",8:"PTRACE_CONT",9:"PTRACE_KILL",16:"PTRACE_ATTACH",
               17:"PTRACE_DETACH",0x4200:"PTRACE_SETOPTIONS"}
    _AF = {0:"AF_UNSPEC",1:"AF_UNIX",2:"AF_INET",10:"AF_INET6",17:"AF_PACKET"}
    _SOCK = {1:"SOCK_STREAM",2:"SOCK_DGRAM",3:"SOCK_RAW"}
    _ACCESS = [(1,"X_OK"),(2,"W_OK"),(4,"R_OK"),(0,"F_OK")]
    _PRCTL = {1:"PR_SET_PDEATHSIG",4:"PR_SET_DUMPABLE",15:"PR_SET_NAME",22:"PR_SET_SECCOMP",
              38:"PR_SET_NO_NEW_PRIVS",59:"PR_SET_SYSCALL_USER_DISPATCH"}

    def _lut(d):
        return lambda v: d.get(v, "0x%X" % v if v > 9 else str(v))

    # function key -> {arg index: decoder(intval)->str}
    ARG_DEC = {
        "open":   {1: _dec_oflags}, "openat": {2: _dec_oflags},
        "mmap":   {2: _dec_prot, 3: lambda v: _bits(v, _MAP)}, "mprotect": {2: _dec_prot},
        "mremap": {3: lambda v: _bits(v, _MAP)},
        "lseek":  {2: _lut(_WHENCE)}, "fseek": {2: _lut(_WHENCE)},
        "kill":   {1: _lut(_SIG)}, "raise": {0: _lut(_SIG)},
        "signal": {0: _lut(_SIG)}, "sigaction": {0: _lut(_SIG)},
        "ptrace": {0: _lut(_PTRACE)}, "prctl": {0: _lut(_PRCTL)},
        "socket": {0: _lut(_AF), 1: _lut(_SOCK)},
        "access": {1: lambda v: _bits(v, _ACCESS)},
    }
    # functions whose first fd arg reads nicely as stdin/stdout/stderr
    _FD_FIRST = {"read", "write", "close", "dup", "dup2", "fstat", "lseek", "fsync",
                 "ftruncate", "fcntl", "sendfile", "pread", "pwrite"}
    _FD_NAMES = {0: "stdin", 1: "stdout", 2: "stderr"}

    # ---------- magic constants ----------
    MAGIC = {
        0x9E3779B9: ("TEA/XXTEA delta", "TEA/XXTEA delta"),
        0x9E3779B1: ("Fibonacci hashing / xxHash prime", "斐波那契散列常数"),
        0x61707865: ("ChaCha/Salsa 'expa'", "ChaCha/Salsa 'expa'"),
        0x3320646E: ("ChaCha/Salsa 'nd 3'", "ChaCha/Salsa 'nd 3'"),
        0x79622D32: ("ChaCha/Salsa '2-by'", "ChaCha/Salsa '2-by'"),
        0x6B206574: ("ChaCha/Salsa 'te k'", "ChaCha/Salsa 'te k'"),
        0x67452301: ("MD5/SHA1 init A", "MD5/SHA1 初值 A"),
        0xEFCDAB89: ("MD5/SHA1 init B", "MD5/SHA1 初值 B"),
        0x98BADCFE: ("MD5/SHA1 init C", "MD5/SHA1 初值 C"),
        0x10325476: ("MD5/SHA1 init D", "MD5/SHA1 初值 D"),
        0x6A09E667: ("SHA-256 init / sqrt(2)", "SHA-256 初值"),
        0xBB67AE85: ("SHA-256 init h1", "SHA-256 初值 h1"),
        0x5A827999: ("SHA-1 round const", "SHA-1 轮常数"),
        0xEDB88320: ("CRC32 reversed poly", "CRC32 反向多项式"),
        0x04C11DB7: ("CRC32 poly", "CRC32 多项式"),
        0x1F3D5B79: ("Blowfish-ish", "Blowfish 风格常数"),
        0xDEADBEEF: ("0xDEADBEEF marker", "0xDEADBEEF 标记"),
        0xC0FFEE: ("0xC0FFEE marker", "0xC0FFEE 标记"),
        0xCAFEBABE: ("0xCAFEBABE (Java/Mach-O magic)", "0xCAFEBABE 魔数"),
    }

    # ---------- MMX/SSE/AVX intrinsic naming (parsed, not enumerated) ----------
    _VEC_OP = {"add":"+", "sub":"-", "mul":"*", "mullo":"*", "mulhi":"* hi", "and":"&", "andnot":"andnot",
               "or":"|", "xor":"^", "sll":"<<", "slli":"<<", "srl":">>", "srli":">>",
               "sra":">>(signed)", "srai":">>(signed)", "min":"min", "max":"max", "avg":"avg",
               "cmpeq":"==", "cmpgt":">", "unpacklo":"interleave lo", "unpackhi":"interleave hi",
               "shuffle":"shuffle", "shufflelo":"shuffle lo", "shufflehi":"shuffle hi",
               "packs":"pack (sat)", "packus":"pack (usat)", "blend":"blend", "blendv":"blend"}
    _VEC_LANE = {"epi8":"per byte","epu8":"per u8","epi16":"per 16b","epu16":"per u16",
                 "epi32":"per 32b","epu32":"per u32","epi64":"per 64b","epu64":"per u64",
                 "ps":"per f32","pd":"per f64","si128":"128b","si256":"256b","si512":"512b","si64":"64b",
                 "pi8":"per byte","pi16":"per 16b","pi32":"per 32b"}
    _CRYPTO = {"aesenc":"AES encrypt round","aesenclast":"AES encrypt last round",
               "aesdec":"AES decrypt round","aesdeclast":"AES decrypt last round",
               "aesimc":"AES inverse mix columns","aeskeygenassist":"AES key schedule",
               "clmulepi64":"carry-less multiply (GHASH/GCM)","crc32":"CRC32 accumulate",
               "sha1rnds4":"SHA-1 4 rounds","sha1nexte":"SHA-1 next E","sha256rnds2":"SHA-256 2 rounds",
               "sha256msg1":"SHA-256 msg sched 1","sha256msg2":"SHA-256 msg sched 2"}

    def _intrin_note(helper):
        h = (helper or "").lstrip("_")
        # crypto first (highest value)
        for k, v in _CRYPTO.items():
            if k in h:
                return OPX + v
        m = re.match(r"mm(?:256|512)?_(\w+?)_(epi\d+|epu\d+|ps|pd|si\d+|pi\d+)$", h)
        if m and m.group(1) in _VEC_OP:
            lane = _VEC_LANE.get(m.group(2), m.group(2))
            return OPX + "%s (%s)" % (_VEC_OP[m.group(1)], lane)
        # legacy _m_* MMX intrinsics (pxor, psrlwi, paddb, ...)
        m = re.match(r"m_p?(pxor|por|pand|pandn|add|sub|mull|mulh|sll|srl|sra)([bwdq])?i?$", h)
        base = {"pxor":"^","por":"|","pand":"&","pandn":"andnot","add":"+","sub":"-",
                "mull":"*","mulh":"* hi","sll":"<<","srl":">>","sra":">>(signed)"}
        if m and m.group(1) in base:
            lane = {"b":"per byte","w":"per 16b","d":"per 32b","q":"per 64b"}.get(m.group(2), "")
            return OPX + base[m.group(1)] + (" (%s)" % lane if lane else "")
        for simple, sym in (("m_pxor","^ (xor)"),("m_por","| (or)"),("m_pand","& (and)"),
                            ("m_empty","emms (clear MMX)")):
            if h == simple:
                return OPX + sym
        return None

    # ---------- syscall tables (embedded) ----------
    _SYS_CACHE = None

    def _syscalls(arch):
        global _SYS_CACHE
        if _SYS_CACHE is None:
            try:
                raw = json.loads(gzip.decompress(base64.b64decode(_SYS_B64)))
                _SYS_CACHE = {}
                for a, s in raw.items():
                    d = {}
                    for tok in s.split(" "):
                        num, _, nm = tok.partition(":")
                        d[int(num)] = nm
                    _SYS_CACHE[a] = d
            except Exception:
                _SYS_CACHE = {}
        return _SYS_CACHE.get(arch, {})


# ======================================================================
#  IDA plugin — runtime-dependent part
# ======================================================================
if _IN_IDA:
    # ---------- language, persisted ----------
    try:
        import ida_diskio
        _CFG = os.path.join(ida_diskio.get_user_idadir(), "ida_better_information.cfg")
    except Exception:
        _CFG = os.path.join(os.path.expanduser("~"), ".ida_better_information.cfg")
    LANG = "en"

    def _load_lang():
        global LANG
        try:
            v = json.load(open(_CFG)).get("lang", "en")
            LANG = v if v in ("en", "zh") else "en"
        except Exception:
            LANG = "en"

    def _save_lang():
        try:
            json.dump({"lang": LANG}, open(_CFG, "w"))
        except Exception:
            pass
    _load_lang()

    def T(en, zh):
        return zh if LANG == "zh" else en

    # undo snapshots: names + function comments + insn comments + pseudocode comments
    _undo = {"names": {}, "cmts": {}, "icmts": {}, "pcmts": []}

    def _cur_arch():
        try:
            import ida_ida
            if not ida_ida.inf_is_64bit():
                pn = ida_ida.inf_get_procname()
                return "i386" if pn == "metapc" else "arm" if pn.lower().startswith("arm") else pn
            pn = ida_ida.inf_get_procname()
            if pn == "metapc":
                return "x86_64"
            if pn.lower().startswith("arm") or pn.upper() == "AARCH64":
                return "aarch64"
            return pn
        except Exception:
            return None

    def _describe(name):
        d = (DESC_ZH if LANG == "zh" else DESC).get(canon(name))
        return (PFX + d) if d else None

    # ---------- detection using the IDB, not the on-disk file ----------
    def _ida_present_hook(index):
        """Scan the first 32 bytes of every function for anchors (fast, IDB-local)."""
        present = set()
        for ea in idautils.Functions():
            w = ida_bytes.get_bytes(ea, 32)
            if w:
                _scan_window(w, index, present)
        return present

    def _ida_image_bytes():
        """Concatenate the executable segments for packer/string heuristics."""
        import ida_segment
        chunks = []
        seg = ida_segment.get_first_seg()
        while seg is not None:
            if seg.perm & ida_segment.SEGPERM_EXEC:
                b = ida_bytes.get_bytes(seg.start_ea, min(seg.size(), 8 << 20))
                if b:
                    chunks.append(b)
            seg = ida_segment.get_next_seg(seg.start_ea)
        return b"".join(chunks)

    def run_detection():
        arch = _cur_arch()
        path = idaapi.get_input_file_path()
        data = None
        if path and os.path.exists(path):
            try:
                data = open(path, "rb").read()
            except Exception:
                data = None
        try:
            if data is not None:
                return detect(data=data, arch_hint=arch, present_hook=_ida_present_hook), None
            # file is gone: reconstruct enough from the IDB
            hdrbytes = ida_bytes.get_bytes(idaapi.get_imagebase(), 0x1000) or b""
            img = hdrbytes + _ida_image_bytes()
            return detect(data=img, arch_hint=arch, present_hook=_ida_present_hook), None
        except Exception as e:
            return None, "detect error: %s" % e

    def _fmt(r):
        if not r:
            return ""
        conf = {"high": T("high", "高"), "medium": T("medium", "中"),
                "low": T("low", "低")}.get(r.get("confidence"), r.get("confidence"))
        lines = [T("type", "类型") + ": %s / %s / %s" % (r.get("os"), r.get("kind"), r.get("arch") or "?")]
        if r.get("build_id"):
            lines.append("build-id: %s" % r["build_id"])
        for v, s, h, n in r.get("ranking", []):
            lines.append("  %-12s %5.1f%%  %d/%d" % (_lib_label(v), s * 100, h, n))
        lines.append(T("verdict", "结论") + ": %s   " % r.get("best") + T("confidence", "置信度") + "=%s" % conf)
        for note in r.get("notes", []):
            lines.append("  . " + note)
        return "\n".join(lines)

    # ---------- FLIRT ----------
    def _sig_dirs():
        out = []
        for base in (getattr(idaapi, "get_user_idadir", lambda: None)(), idaapi.idadir("")):
            if not base:
                continue
            d = os.path.join(base, "sig", "pc")
            if os.path.isdir(d):
                out.append(d)
        return out

    def _find_sigs(verstr):
        out = []
        for sigdir in _sig_dirs():
            try:
                for fn in os.listdir(sigdir):
                    low = fn.lower()
                    if fn.endswith(".sig") and ("glibc" in low or "musl" in low) and verstr in fn:
                        out.append(fn)
            except Exception:
                pass
        out = sorted(set(out), key=lambda s: (("amd64" not in s and "a64" not in s and "x64" not in s), s))
        return out

    def _ensure_libc_til():
        """Load the gnulnx_x64 type library so named libc funcs get real prototypes."""
        try:
            import ida_typeinf
            til = ida_typeinf.get_idati()
            names = [til.base(i).name for i in range(til.nbases)]
            want = "gnulnx_x64" if (_cur_arch() == "x86_64") else "gnuunx"
            if not any(want in n for n in names):
                ida_typeinf.add_til(want, ida_typeinf.ADDTIL_DEFAULT)
        except Exception:
            pass

    def _apply_one_sig(signame):
        before = {ea: (ida_funcs.get_func_name(ea) or "") for ea in idautils.Functions()}
        idaapi.plan_to_apply_idasgn(signame)
        ida_auto.auto_wait()
        changed = 0
        for ea in idautils.Functions():
            nm = ida_funcs.get_func_name(ea) or ""
            if before.get(ea, "") != nm:
                _undo["names"].setdefault(ea, before.get(ea, ""))
                changed += 1
        return changed

    def do_apply_sig(r):
        kind = r.get("kind"); best = r.get("best") or ""
        if kind in ("pe", "go", "dynamic", "?") or not r.get("ranking"):
            return T("no static glibc/musl signature needed for this type (%s).",
                     "该类型(%s)不需要套静态 glibc/musl 签名。") % kind
        # on a confident call apply the leader; when uncertain, apply the top few and
        # let FLIRT keep only byte-matching functions.
        cands = [v for v, s, h, n in r["ranking"]]
        cands = cands[:1] if r.get("confidence") == "high" else cands[:3]
        _ensure_libc_til()
        applied, total_changed = [], 0
        for ver in cands:
            verstr = _lib_label(ver).replace("glibc", "").replace("musl", "").strip().lstrip(">=")
            sigs = _find_sigs(verstr)
            if not sigs:
                continue
            signame = os.path.splitext(sigs[0])[0]
            total_changed += _apply_one_sig(signame)
            applied.append(signame)
        if not applied:
            return T("no FLIRT .sig for %s in IDA sig/pc. Generate one with FLAIR or grab a community set.",
                     "IDA sig/pc 里没有 %s 的签名。用 FLAIR 生成或从社区签名集拿。") % best
        named = sum(1 for ea in idautils.Functions() if not (ida_funcs.get_func_name(ea) or "").startswith("sub_"))
        return T("applied %s; named %d this run; %d non-sub_ funcs total.",
                 "已套用 %s;本次命名 %d 个,当前非 sub_ 函数共 %d 个。") % (", ".join(applied), total_changed, named)

    # ---------- libc function comments ----------
    def annotate_all():
        n = 0
        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea) or ""
            d = _describe(name)
            if not d:
                continue
            old = idc.get_func_cmt(ea, 1) or ""
            body = _strip_managed(old)
            if body == old and old.startswith(PFX):
                pass  # (can't happen: strip removes it) -- kept for clarity
            new = d if not body else (d + "\n" + body)
            if new == old:
                continue
            if ea not in _undo["cmts"]:
                _undo["cmts"][ea] = old
            try:
                idc.set_func_cmt(ea, new, 1); n += 1
            except Exception:
                pass
        return n

    def _strip_managed(text):
        """Remove our managed lines (libc:/op:/sys:) from a comment, keep the rest."""
        if not text:
            return ""
        keep = [ln for ln in text.split("\n") if not ln.startswith(_MANAGED)]
        return "\n".join(keep).strip("\n")

    # ---------- argument rendering ----------
    def _fmt_num(val, size):
        if size and 0 < size <= 8:
            signed = val - (1 << (8 * size)) if val >= (1 << (8 * size - 1)) else val
        else:
            signed = val - (1 << 64) if val >= (1 << 63) else val
        if -65536 <= signed < 0:
            return str(signed)
        if val > 9999:
            return "0x%X" % val
        return str(val)

    def _str_at(ea):
        """Return a quoted C-string at ea (typed, or raw printable bytes), else None."""
        s = idc.get_strlit_contents(ea, -1, -1)
        if not s:
            raw = ida_bytes.get_bytes(ea, 24) or b""
            raw = raw.split(b"\x00", 1)[0]
            if raw and all(32 <= c < 127 for c in raw):
                s = raw
        if not s:
            return None
        try:
            s = s.decode("utf-8", "replace")
        except Exception:
            s = "%s" % s
        s = s.replace("\n", "\\n")
        if len(s) > 24:
            s = s[:24] + "..."
        return '"%s"' % s

    def _arg_text(cfunc, a):
        import ida_hexrays as hr
        import ida_lines
        try:
            while a.op == hr.cot_cast and a.x is not None:
                a = a.x
            op = a.op
            if op == hr.cot_num:
                sz = a.type.get_size() if a.type else 0
                return _fmt_num(a.numval(), sz)
            if op == hr.cot_str:
                s = a.string
                if len(s) > 24:
                    s = s[:24] + "..."
                return '"%s"' % s
            if op == hr.cot_obj:
                return _str_at(a.obj_ea) or idc.get_name(a.obj_ea) or ("0x%X" % a.obj_ea)
            if op == hr.cot_var:
                return cfunc.lvars[a.v.idx].name
            if op == hr.cot_ref and a.x is not None:
                inner = a.x
                if inner.op == hr.cot_var:
                    return "&" + cfunc.lvars[inner.v.idx].name
                if inner.op == hr.cot_obj:
                    return _str_at(inner.obj_ea) or ("&" + (idc.get_name(inner.obj_ea) or "0x%X" % inner.obj_ea))
            # fall back to Hex-Rays' own rendering: handles buf+8, s->field, arr[i], &x ...
            txt = ida_lines.tag_remove(a.print1(cfunc))
            txt = txt.replace("\n", " ")
            return txt if len(txt) <= 32 else txt[:32] + "..."
        except Exception:
            pass
        return "?"

    def _arg_int(a):
        """Return the integer value of a constant arg (after casts), else None."""
        import ida_hexrays as hr
        try:
            while a.op == hr.cot_cast and a.x is not None:
                a = a.x
            if a.op == hr.cot_num:
                return a.numval()
        except Exception:
            pass
        return None

    def _call_note(cfunc, e, nm):
        base, keep = resolve_variant(nm)
        try:
            raw = list(e.a)
        except Exception:
            raw = []
        args = [raw[i] for i in keep if i < len(raw)] if keep is not None else raw
        # render each arg, decoding known flag/enum/fd positions
        A = []
        decoders = ARG_DEC.get(base, {})
        for i, a in enumerate(args):
            iv = _arg_int(a)
            if i in decoders and iv is not None:
                A.append(decoders[i](iv))
            elif base in _FD_FIRST and i == 0 and iv in _FD_NAMES:
                A.append("fd %d (%s)" % (iv, _FD_NAMES[iv]))
            else:
                A.append(_arg_text(cfunc, a))
        # raw syscall: name it from the number
        if base == "syscall" and A:
            iv = _arg_int(args[0])
            if iv is not None:
                name = _syscalls(_cur_arch() or "x86_64").get(iv)
                if name:
                    return SYS + "%s(%s)" % (name, ", ".join(A[1:]))
        pair = TMPL.get(base)
        if pair:
            t = pair[1] if LANG == "zh" else pair[0]
            try:
                return PFX + t.format(*A)
            except Exception:
                pass
        d = (DESC_ZH if LANG == "zh" else DESC).get(base)
        return (PFX + d) if d else None

    def _magic_note(cfunc, e):
        """If any immediate arg is a known magic constant, note it."""
        import ida_hexrays as hr
        try:
            for a in e.a:
                iv = _arg_int(a)
                if iv is not None:
                    key = iv & 0xFFFFFFFF
                    if key in MAGIC:
                        return OPX + (MAGIC[key][1] if LANG == "zh" else MAGIC[key][0])
        except Exception:
            pass
        return None

    def _collect_notes(cfunc):
        """Walk the ctree once. Returns (by_ea, by_idx):
           by_ea  {ea: text}     — for persisting as user comments (keyed by address)
           by_idx {citem: text}  — for live rendering (keyed by the call's ctree index,
                                    so parent blocks that share an ea don't match)."""
        import ida_hexrays as hr
        by_ea, by_idx = {}, {}

        class _V(hr.ctree_visitor_t):
            def __init__(self):
                hr.ctree_visitor_t.__init__(self, hr.CV_FAST)

            def visit_expr(self, e):
                if e.op == hr.cot_call and e.x is not None and e.ea != idaapi.BADADDR:
                    got = []
                    if e.x.op == hr.cot_helper:
                        n = _intrin_note(e.x.helper)
                        if n:
                            got.append(n)
                    elif e.x.op == hr.cot_obj:
                        nm = ida_funcs.get_func_name(e.x.obj_ea) or idc.get_name(e.x.obj_ea) or ""
                        n = _call_note(cfunc, e, nm)
                        if n:
                            got.append(n)
                    mg = _magic_note(cfunc, e)
                    if mg:
                        got.append(mg)
                    if got:
                        text = "   ".join(dict.fromkeys(got))
                        slot = by_ea.setdefault(e.ea, [])
                        for g in got:
                            if g not in slot:
                                slot.append(g)
                        by_idx[e.index] = text
                return 0
        _V().apply_to(cfunc.body, None)
        return {ea: "   ".join(lst) for ea, lst in by_ea.items()}, by_idx

    # ---------- live decompiler rendering (Hex-Rays hook; writes nothing) ----------
    import ida_lines
    _ADDR_TAG = ida_lines.COLOR_ON + chr(ida_lines.COLOR_ADDR)
    _ADDR_RE = re.compile(re.escape(_ADDR_TAG) + ("([0-9A-Fa-f]{%d})" % ida_lines.COLOR_ADDR_SIZE))

    def _line_item_indices(cfunc, line):
        out = []
        n = cfunc.treeitems.size()
        for m in _ADDR_RE.finditer(line):
            v = int(m.group(1), 16) & 0xFFFFFFFF
            if (v & 0xC0000000) == 0 and v < n:                 # ANCHOR_CITEM index
                out.append(v)
        return out

    def _render_into_sv(cfunc):
        """Append our notes to the pseudocode lines in-place. Returns count.
           Each call's note is placed once, on the line carrying that call's ctree
           item index (never on a parent brace that merely shares the address)."""
        sv = cfunc.get_pseudocode()          # populates item indices (ctree_item numbering)
        _, by_idx = _collect_notes(cfunc)
        if not by_idx:
            return 0
        tail = ida_lines.COLOR_ON + chr(ida_lines.COLOR_AUTOCMT)
        off = ida_lines.COLOR_OFF + chr(ida_lines.COLOR_AUTOCMT)
        placed = set()
        added = 0
        for i in range(sv.size()):
            line = sv[i].line
            hit = []
            for idx in _line_item_indices(cfunc, line):
                if idx in by_idx and idx not in placed:
                    hit.append(by_idx[idx]); placed.add(idx)
            if hit:
                sv[i].line = line + "  " + tail + "// " + "   ".join(dict.fromkeys(hit)) + off
                added += 1
        return added

    _RENDER_ON = [True]

    try:
        import ida_hexrays as _hr_mod

        class _IBIHooks(_hr_mod.Hexrays_Hooks):
            def func_printed(self, cfunc):
                if _RENDER_ON[0]:
                    try:
                        _render_into_sv(cfunc)
                    except Exception:
                        pass
                return 0
        _HOOKS = _IBIHooks()
    except Exception:
        _HOOKS = None

    _hook_installed = [False]

    def set_live_render(on):
        _RENDER_ON[0] = on
        if _HOOKS is None:
            return False
        if on and not _hook_installed[0]:
            _HOOKS.hook(); _hook_installed[0] = True
        try:
            import ida_hexrays as hr
            hr.clear_cached_cfuncs()
            w = ida_kernwin.get_current_widget()
            vu = hr.get_widget_vdui(w) if w else None
            if vu:
                vu.refresh_view(True)
        except Exception:
            pass
        return True

    # ---------- persist pseudocode comments into the IDB (reversible) ----------
    def _hx_put(cfunc, ea, text, func_ea):
        import ida_hexrays as hr
        for itp in (hr.ITP_SEMI, hr.ITP_BLOCK1, hr.ITP_BLOCK2, hr.ITP_CASE, hr.ITP_COLON,
                    hr.ITP_CURLY1, hr.ITP_CURLY2, hr.ITP_BRACE1, hr.ITP_BRACE2, hr.ITP_ELSE):
            tl = hr.treeloc_t(); tl.ea = ea; tl.itp = itp
            try:
                prev = cfunc.get_user_cmt(tl, hr.RETRIEVE_ONCE) or ""
            except Exception:
                prev = ""
            body = _strip_managed(prev)
            newtext = text if not body else (text + "   | " + body)
            cfunc.set_user_cmt(tl, newtext)
            cfunc.save_user_cmts()
            cfunc.refresh_func_ctext()
            if not cfunc.has_orphan_cmts():
                _undo["pcmts"].append((func_ea, ea, itp, prev))
                return True
            cfunc.set_user_cmt(tl, prev)      # wrong spot: restore ONLY this one, try next
            cfunc.del_orphan_cmts()
        return False

    def annotate_pseudo(func_ea=None):
        """Persist decompiler notes as user comments in the CURRENT function.
           Returns count; -1 not in a function; -2 no decompiler; -3 error."""
        try:
            import ida_hexrays as hr
        except Exception:
            return -2
        try:
            if not hr.init_hexrays_plugin():
                return -2
            if func_ea is None:
                func_ea = ida_kernwin.get_screen_ea()
            f = ida_funcs.get_func(func_ea)
            if not f:
                return -1
            cfunc = hr.decompile(f.start_ea)
            if not cfunc:
                return -2
            notes, _ = _collect_notes(cfunc)
            if not notes:
                return 0
            added = sum(1 for ea, txt in notes.items() if _hx_put(cfunc, ea, txt, func_ea))
            cfunc.save_user_cmts(); cfunc.refresh_func_ctext()
            return added
        except Exception as ex:
            _pse_err[0] = "%s" % ex
            return -3
    _pse_err = [""]

    # ---------- disassembly math annotation ----------
    _BIN = {"add":"+", "sub":"-", "and":"&", "or":"|", "xor":"^", "imul":"*",
            "shl":"<<", "sal":"<<", "shr":">>", "sar":">>(signed)",
            "rol":"<<<(rot)", "ror":">>>(rot)", "adc":"+(+CF)", "sbb":"-(-CF)"}
    _UN = {"not":"~{d}", "neg":"-{d}", "inc":"{d} + 1", "dec":"{d} - 1"}
    _VEC = {"pxor":("^",""), "pand":("&",""), "por":("|",""), "pandn":("andnot",""),
            "paddb":("+","per byte"), "paddw":("+","per 16b"), "paddd":("+","per 32b"), "paddq":("+","per 64b"),
            "psubb":("-","per byte"), "psubw":("-","per 16b"), "psubd":("-","per 32b"), "psubq":("-","per 64b"),
            "pmullw":("*","per 16b"), "pmulld":("*","per 32b"), "pmuludq":("*","per 32->64b"),
            "psllw":("<<","per 16b"), "pslld":("<<","per 32b"), "psllq":("<<","per 64b"),
            "psrlw":(">>","per 16b"), "psrld":(">>","per 32b"), "psrlq":(">>","per 64b"),
            "psraw":(">>(signed)","per 16b"), "psrad":(">>(signed)","per 32b")}
    _FP = {"addss":"+","addsd":"+","subss":"-","subsd":"-","mulss":"*","mulsd":"*","divss":"/","divsd":"/"}

    def _ops(ea):
        return (idc.print_operand(ea, 0), idc.print_operand(ea, 1), idc.print_operand(ea, 2))

    def _insn_math(ea):
        m = (idc.print_insn_mnem(ea) or "").lower()
        if not m:
            return None
        d, s, t = _ops(ea)
        if m.startswith("v") and t:
            base = m[1:]
            if base in _VEC:
                sym, g = _VEC[base]; g = (" (%s)" % g) if g else ""
                if base == "pxor" and s == t:
                    return "%s = 0" % d
                if base == "pandn":
                    return "%s = (~%s) & %s" % (d, s, t)
                return "%s = %s %s %s%s" % (d, s, sym, t, g)
            if base in _FP:
                return "%s = %s %s %s" % (d, s, _FP[base], t)
            if base in _BIN:
                return "%s = %s %s %s" % (d, s, _BIN[base], t)
        if m in _VEC:
            sym, g = _VEC[m]; g = (" (%s)" % g) if g else ""
            if m == "pxor" and d == s:
                return "%s = 0" % d
            if m == "pandn":
                return "%s = (~%s) & %s" % (d, d, s)
            return "%s = %s %s %s%s" % (d, d, sym, s, g)
        if m in _FP:
            return "%s = %s %s %s" % (d, d, _FP[m], s)
        if m in _UN and d:
            return "%s = %s" % (d, _UN[m].format(d=d))
        if m == "imul" and t:
            return "%s = %s * %s" % (d, s, t)
        if m in _BIN:
            if m == "xor" and d == s:
                return "%s = 0" % d
            return "%s = %s %s %s" % (d, d, _BIN[m], s)
        if m == "lea" and s:
            return "%s = %s" % (d, s)
        return None

    def annotate_math(func_ea=None):
        if func_ea is None:
            func_ea = ida_kernwin.get_screen_ea()
        f = ida_funcs.get_func(func_ea)
        if not f:
            return -1
        n = 0
        for ea in idautils.FuncItems(f.start_ea):
            expr = _insn_math(ea)
            if not expr:
                continue
            tagged = OPX + expr
            old = idc.get_cmt(ea, 0) or ""
            body = _strip_managed(old)
            new = tagged if not body else (tagged + "  | " + body)
            if new == old:
                continue
            if ea not in _undo["icmts"]:
                _undo["icmts"][ea] = old
            try:
                idc.set_cmt(ea, new, 0); n += 1
            except Exception:
                pass
        return n

    # ---------- undo ----------
    _DUMMY_RE = re.compile(r'^(sub_|loc_|locret_|unk_|byte_|word_|dword_|qword_|off_|asc_|'
                           r'flt_|dbl_|tbyte_|packreal_|stru_|custdata_|algn_|def_|nullsub_|'
                           r'j_|unknown_libname|__imp_)')

    def _is_dummy_name(nm):
        return (not nm) or bool(_DUMMY_RE.match(nm))

    def do_undo():
        nn = nc = ni = npc = 0
        for ea, old in list(_undo["names"].items()):
            try:
                if _is_dummy_name(old):
                    ok = ida_name.set_name(ea, "", ida_name.SN_NOWARN | ida_name.SN_FORCE)
                else:
                    ok = ida_name.set_name(ea, old, ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE)
                if ok:
                    nn += 1
            except Exception:
                pass
        for ea, old in list(_undo["cmts"].items()):
            try:
                idc.set_func_cmt(ea, old or "", 1); nc += 1
            except Exception:
                pass
        for ea, old in list(_undo["icmts"].items()):
            try:
                idc.set_cmt(ea, old or "", 0); ni += 1
            except Exception:
                pass
        if _undo["pcmts"]:
            try:
                import ida_hexrays as hr
                byfunc = {}
                for (fea, ea, itp, old) in _undo["pcmts"]:
                    byfunc.setdefault(fea, []).append((ea, itp, old))
                for fea, items in byfunc.items():
                    try:
                        cf = hr.decompile(fea)
                        if not cf:
                            continue
                        for (ea, itp, old) in items:
                            tl = hr.treeloc_t(); tl.ea = ea; tl.itp = itp
                            cf.set_user_cmt(tl, old or ""); npc += 1
                        cf.save_user_cmts(); cf.refresh_func_ctext()
                    except Exception:
                        pass
            except Exception:
                pass
        _undo["names"].clear(); _undo["cmts"].clear(); _undo["icmts"].clear(); _undo["pcmts"] = []
        try:
            ida_auto.auto_wait()
        except Exception:
            pass
        return T("reverted: %d names, %d func comments, %d insn comments, %d pseudocode comments.",
                 "已撤回:%d 个函数名、%d 处函数注释、%d 处指令注释、%d 处伪代码注释。") % (nn, nc, ni, npc)

    # ---------- dockable panel ----------
    _panel = None

    if _HAS_QT:
        class IBIPanel(ida_kernwin.PluginForm):
            def OnCreate(self, form):
                conv = getattr(self, "FormToPyWidget", None) or getattr(self, "FormToPyQtWidget")
                self.parent = conv(form); self._r = None; self._build()

            def _build(self):
                L = QtWidgets.QVBoxLayout()
                top = QtWidgets.QHBoxLayout()
                self.title = QtWidgets.QLabel("<b>IDA Better Information</b>")
                top.addWidget(self.title, 1)
                top.addWidget(QtWidgets.QLabel("Lang:"))
                self.lang = QtWidgets.QComboBox(); self.lang.addItems(["English", "中文"])
                self.lang.setCurrentIndex(1 if LANG == "zh" else 0)
                self.lang.currentIndexChanged.connect(self.on_lang)
                top.addWidget(self.lang)
                L.addLayout(top)
                self.result = QtWidgets.QTextEdit(); self.result.setReadOnly(True); self.result.setMinimumHeight(150)
                L.addWidget(self.result)
                self.cb_live = QtWidgets.QCheckBox(); self.cb_live.setChecked(True)
                self.cb_live.stateChanged.connect(self.on_live)
                self.cb_sig = QtWidgets.QCheckBox(); self.cb_sig.setChecked(True)
                self.cb_ann = QtWidgets.QCheckBox(); self.cb_ann.setChecked(True)
                self.cb_pse = QtWidgets.QCheckBox(); self.cb_pse.setChecked(False)
                self.cb_math = QtWidgets.QCheckBox(); self.cb_math.setChecked(False)
                for w in (self.cb_live, self.cb_sig, self.cb_ann, self.cb_pse, self.cb_math):
                    L.addWidget(w)
                h = QtWidgets.QHBoxLayout()
                self.b0 = QtWidgets.QPushButton(); self.b1 = QtWidgets.QPushButton(); self.b2 = QtWidgets.QPushButton()
                self.b0.clicked.connect(self.on_detect); self.b1.clicked.connect(self.on_run); self.b2.clicked.connect(self.on_undo)
                h.addWidget(self.b0); h.addWidget(self.b1); h.addWidget(self.b2); L.addLayout(h)
                self.loglabel = QtWidgets.QLabel()
                L.addWidget(self.loglabel)
                self.log = QtWidgets.QTextEdit(); self.log.setReadOnly(True); L.addWidget(self.log)
                self.parent.setLayout(L)
                self._retext()
                set_live_render(True)     # live annotations on by default

            def _retext(self):
                self.cb_live.setText(T("Live decompiler annotations (auto, no database writes)",
                                       "反编译实时注释（自动，不写数据库）"))
                self.cb_sig.setText(T("Apply matching FLIRT signature (name library funcs)",
                                      "套用匹配的 FLIRT 签名（命名库函数）"))
                self.cb_ann.setText(T("Annotate libc functions (repeatable, keeps your comments)",
                                      "给 libc 函数加注释（可重复，保留你的注释）"))
                self.cb_pse.setText(T("Persist decompiler comments to IDB (current function)",
                                      "把反编译注释写进数据库（当前函数）"))
                self.cb_math.setText(T("Annotate math/SIMD in disassembly (current function)",
                                       "在反汇编里标注算术/SIMD（当前函数）"))
                self.b0.setText(T("Detect", "检测"))
                self.b1.setText(T("Run", "执行"))
                self.b2.setText(T("Undo", "撤回"))
                self.loglabel.setText(T("log:", "日志："))

            def on_lang(self, idx):
                global LANG
                LANG = "zh" if idx == 1 else "en"
                _save_lang(); self._retext()
                if self._r:
                    self.result.setPlainText(_fmt(self._r))
                set_live_render(self.cb_live.isChecked())    # re-render in new language

            def on_live(self, _state):
                set_live_render(self.cb_live.isChecked())

            def on_detect(self):
                r, err = run_detection(); self._r = r
                self.result.setPlainText(err if err else _fmt(r))

            def on_run(self):
                out = []
                if self.cb_sig.isChecked():
                    if not self._r:
                        self.on_detect()
                    out.append("[sig] " + (do_apply_sig(self._r) if self._r
                               else T("detect first.", "先检测。")))
                if self.cb_ann.isChecked():
                    out.append("[libc] " + T("+%d function comments.", "+%d 处函数注释。") % annotate_all())
                if self.cb_pse.isChecked():
                    ea = ida_kernwin.get_screen_ea()
                    nm = ida_funcs.get_func_name(ea) if ida_funcs.get_func(ea) else "?"
                    n = annotate_pseudo(ea)
                    out.append("[pseudo] " + self._pseudo_msg(nm, n))
                if self.cb_math.isChecked():
                    n = annotate_math()
                    out.append("[math] " + (T("cursor not in a function.", "光标不在函数里。") if n == -1
                                            else T("+%d insn comments.", "+%d 处指令注释。") % n))
                if not out:
                    out.append(T("(nothing selected)", "（什么都没勾）"))
                self.log.append("\n".join(out))
                if self._r:
                    self.result.setPlainText(_fmt(self._r))

            def _pseudo_msg(self, nm, n):
                if n == -1:
                    return T("cursor not inside a function.", "光标不在函数里。")
                if n == -2:
                    return T("Hex-Rays decompiler unavailable.", "没有 Hex-Rays 反编译器。")
                if n == -3:
                    return T("error: ", "出错：") + _pse_err[0]
                if n == 0:
                    return "%s: " % nm + T("nothing to annotate.", "没有可注释的调用。")
                return "%s: " % nm + T("+%d comment(s).", "+%d 处注释。") % n

            def on_undo(self):
                self.log.append("[undo] " + do_undo())

            def OnClose(self, form):
                global _panel; _panel = None

    def open_panel():
        global _panel
        if not _HAS_QT:
            r, err = run_detection()
            if err:
                ida_kernwin.warning(err); return
            set_live_render(True)
            f = ida_kernwin.Form(r"""IDA Better Information
%s
<##Apply matching FLIRT signature:{rSig}>
<##Annotate libc functions (keep yours):{rAnn}>
<##Persist decompiler comments (current func):{rPse}>
<##Annotate math/SIMD in disassembly:{rMath}>
<##Undo last run:{rUndo}>{cG}>
""" % _fmt(r).replace("%", "%%"),
                {"cG": ida_kernwin.Form.ChkGroupControl(("rSig", "rAnn", "rPse", "rMath", "rUndo"))})
            f.Compile(); f.rSig.checked = True; f.rAnn.checked = True
            f.rPse.checked = False; f.rMath.checked = False; f.rUndo.checked = False
            if f.Execute() == 1:
                msg = []
                if f.rUndo.checked:
                    msg.append("[undo] " + do_undo())
                else:
                    if f.rSig.checked:
                        msg.append("[sig] " + do_apply_sig(r))
                    if f.rAnn.checked:
                        msg.append("[libc] +%d." % annotate_all())
                    if f.rPse.checked:
                        n = annotate_pseudo()
                        msg.append("[pseudo] " + ("not in a function." if n == -1 else
                                                  ("no decompiler." if n == -2 else
                                                   ("error: " + _pse_err[0] if n == -3 else "+%d." % n))))
                    if f.rMath.checked:
                        msg.append("[math] +%d." % annotate_math())
                print("\n".join(msg)); ida_kernwin.info("\n".join(msg) or "nothing to do")
            f.Free(); return
        _panel = IBIPanel()
        try:
            _panel.Show("IDA Better Information", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        except Exception:
            _panel.Show("IDA Better Information")

    class IBIPlugin(idaapi.plugin_t):
        flags = idaapi.PLUGIN_KEEP
        comment = "Detect runtime/compiler, apply FLIRT, annotate libc + math (undoable)"
        help = "Ctrl-Alt-G"
        wanted_name = "IDA Better Information"
        wanted_hotkey = "Ctrl-Alt-G"

        def init(self):
            print("[IDA Better Information] " + T("loaded. Press Ctrl-Alt-G.",
                                                  "已加载。按 Ctrl-Alt-G 打开面板。"))
            return idaapi.PLUGIN_KEEP

        def term(self):
            try:
                if _HOOKS is not None and _hook_installed[0]:
                    _HOOKS.unhook()
            except Exception:
                pass

        def run(self, arg):
            open_panel()

    def PLUGIN_ENTRY():
        return IBIPlugin()


# ======================================================================
#  Embedded data blobs (regenerated by tools/embed-fingerprint.py)
# ======================================================================
_FP_B64 = "@@FINGERPRINT_B64@@"
_SYS_B64 = "@@SYSCALLS_B64@@"

# ======================================================================
#  CLI entry — after the blobs so the DB is loadable when run directly.
# ======================================================================
if __name__ == "__main__":
    _cli()
