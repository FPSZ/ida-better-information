"""Apply FLIRT signatures and prototypes for the identified libc build.

`prog` is a ports.Program, `sigs` a ports.Signatures, `journal` a core.journal.Journal."""
import os
import re

from ..core.fingerprint import _lib_label
from ..core.i18n import T
from ..core.names import _AUTONAME, _is_dummy_name, canon

# per-arch filename markers, most-preferred first
_ARCH_MARK = {"x86_64": ("amd64", "a64", "x64"), "i386": ("i386", "a32"),
              "aarch64": ("aarch64", "arm64", "arm"), "arm": ("arm32", "arm")}


def _find_sigs(sigs, verstr, arch):
    marks = _ARCH_MARK.get(arch, ())
    out = []
    for fn in sigs.sig_files(arch):
        low = fn.lower()
        if fn.endswith(".sig") and ("glibc" in low or "musl" in low) and verstr in fn:
            out.append(fn)

    def rank(s):
        low = s.lower()
        for i, m in enumerate(marks):
            if m in low:
                return (0, i, s)
        return (1, 0, s)                 # no arch marker: lowest priority
    return sorted(set(out), key=rank)


def _apply_prototypes(prog, sigs):
    """Give FLIRT-named libc functions their real prototype from the type library.
       Without it Hex-Rays guesses the arity (mmap shows up as mmap64(0)), and the
       argument decoding has nothing to work with. User-set types are left alone."""
    n = 0
    for ea in prog.functions():
        name = prog.func_name(ea) or ""
        if _is_dummy_name(name) or prog.has_user_type(ea):
            continue
        tif = None
        # the exact name first: lseek64 must keep its 64-bit off_t on 32-bit targets
        cands = [name.lstrip("_"), name]
        if not name.endswith("_chk"):     # a fortified variant must not get its base's prototype
            cands.append(canon(name))
        for cand in dict.fromkeys(cands):
            tif = sigs.prototype(cand) if cand else None
            if tif:
                break
        if tif is None:
            continue
        if prog.apply_type(ea, tif):
            n += 1
    return n


def _apply_one_sig(prog, sigs, journal, signame):
    before = {ea: (prog.func_name(ea) or "", prog.is_lib(ea), prog.func_cmt(ea) or "")
              for ea in prog.functions()}
    sigs.apply(signame)
    changed = 0
    for ea in prog.functions():
        nm = prog.func_name(ea) or ""
        old_nm, old_lib, old_cmt = before.get(ea, ("", False, ""))
        cmt = prog.func_cmt(ea) or ""
        if cmt != old_cmt:
            journal.record("cmts", ea, old_cmt, cmt)     # FLIRT writes the library name here
        if old_nm != nm:
            journal.record("names", ea, old_nm, nm)
            changed += not _AUTONAME.match(nm)
        if not old_lib and prog.is_lib(ea):
            journal.libflag.add(ea)            # FLIRT marks matches as library functions
    return changed


# glibc release -> the GCC that Ubuntu release builds with (when .comment is stripped)
_GLIBC_GCC = [("2.19", "4.8"), ("2.23", "5"), ("2.27", "7"), ("2.31", "9"), ("2.35", "11"),
              ("2.36", "12"), ("2.38", "13"), ("2.40", "14"), ("2.42", "15")]


def _numver(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0,)


def _pick_libgcc_sig(sigs, r, libc_ver):
    """Name of the libgcc_<gcc>_<arch> signature to apply, or None. The GCC version
    comes from the toolchain string, else from the glibc release's Ubuntu default."""
    suffix = {"x86_64": "amd64", "i386": "i386", "aarch64": "aarch64"}.get(r.get("arch"))
    if not suffix:
        return None
    have = {}
    for fn in sigs.sig_files(r.get("arch")):
        m = re.match(r"libgcc_([\d.]+)_%s\.sig$" % suffix, fn)
        if m:
            have[m.group(1)] = fn[:-4]
    if not have:
        return None
    want = None
    m = re.search(r"gcc (\d+)\.(\d+)", r.get("toolchain") or "", re.I)
    if m:
        want = "%s.%s" % m.groups() if m.group(1) == "4" else m.group(1)
    elif re.match(r"\d+\.\d+$", libc_ver or ""):
        for g, c in _GLIBC_GCC:
            if _numver(g) <= _numver(libc_ver):
                want = c
    if not want:
        return None
    if want in have:
        return have[want]
    w = _numver(want)
    near = min(have, key=lambda v: (abs(_numver(v)[0] - w[0]), -_numver(v)[0]))
    return have[near]


def apply_signatures(prog, sigs, journal, r):
    """Name library functions with the signatures matching detection result `r`.
    Returns the log line."""
    kind = r.get("kind"); best = r.get("best") or ""
    if not prog.has_code():
        return T("IDA loaded no code from this file, so there is nothing to name; see the detection notes.",
                 "IDA 没有从该文件加载出代码,无可命名;见识别结果里的说明。")
    if kind in ("pe", "go", "dynamic", "?"):
        return T("no static glibc/musl signature needed for this type (%s).",
                 "该类型(%s)不需要套静态 glibc/musl 签名。") % kind
    if not r.get("ranking"):
        return T("no libc build was identified (%s), so no signature is applied.",
                 "没有识别出 libc 构建(%s),不套用签名。") % best
    # on a confident call apply the leader; when uncertain, apply the top few and
    # let FLIRT keep only byte-matching functions.
    cands = [v for v, s, h, n in r["ranking"]]
    cands = cands[:1] if r.get("confidence") == "high" else cands[:3]
    arch = r.get("arch")
    sigs.ensure_til(prog.arch())
    types_before = prog.type_snapshot()   # FLIRT itself makes IDA apply some types too
    applied, total_changed = [], 0
    for ver in cands:
        verstr = _lib_label(ver).replace("glibc", "").replace("musl", "").strip().lstrip(">=")
        found = _find_sigs(sigs, verstr, arch)
        if not found:
            continue
        signame = os.path.splitext(found[0])[0]
        total_changed += _apply_one_sig(prog, sigs, journal, signame)
        applied.append(signame)
        if len(applied) == 1 and kind == "static":
            lg = _pick_libgcc_sig(sigs, r, verstr)       # the GCC runtime linked next to libc
            if lg:
                total_changed += _apply_one_sig(prog, sigs, journal, lg)
                applied.append(lg)
    if not applied:
        return T("no FLIRT .sig for %s in IDA sig/pc. Generate one with FLAIR or grab a community set.",
                 "IDA sig/pc 里没有 %s 的签名。用 FLAIR 生成或从社区签名集拿。") % best
    # FLIRT tells look-alike modules apart by the names they reference
    # (__printf_chk vs __wprintf_chk call __vfprintf_internal / __vfwprintf_internal).
    # A callee named later in the same pass leaves its caller unmatched, so apply
    # again until a pass names nothing new.
    for _ in range(2):
        more = sum(_apply_one_sig(prog, sigs, journal, s) for s in applied)
        total_changed += more
        if not more:
            break
    typed = _apply_prototypes(prog, sigs)
    types_after = prog.type_snapshot()
    for ea in set(types_before) | set(types_after):
        b, a = types_before.get(ea), types_after.get(ea)
        bs, as_ = (str(b[0]) if b else None), (str(a[0]) if a else None)
        if bs != as_:
            journal.record("types", ea, b, as_)    # b None -> the function had no type before
    named = sum(1 for ea in prog.functions() if not _AUTONAME.match(prog.func_name(ea) or ""))
    return T("applied %s; named %d functions this run (%d named in total); %d prototypes applied.",
             "已套用 %s;本次命名 %d 个函数(共 %d 个有名字);套用原型 %d 个。") % (
                 ", ".join(applied), total_changed, named, typed)
