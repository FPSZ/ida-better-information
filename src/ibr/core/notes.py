"""Call-site notes: arguments, printf/scanf binding, syscalls, segment reads, magic.

Calls are ports.Expr trees; `prog` is a ports.Program."""
import re

from . import i18n
from .comments import OPX, PFX, SYS
from .decoders import (ARG_DEC, MAGIC, _DEC_CTX, _FD_FIRST, _FD_NAMES, _SEG_ELF, _SEG_PE, _SYS_ARGC,
                       _dec_char, _o_creat_bit, set_target)
from .i18n import T
from .libc import DESC, DESC_ZH, TMPL
from .names import resolve_variant
from .render import _arg_int, _arg_text, _cstr_arg, _fmt_num, _global_ea, _is_float
from .simd import _vec_call_note
from .syscalls import _syscalls

# format-string functions: index of the format argument (after variant mapping)
_FMT_FUNCS = {"printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1, "dprintf": 1,
              "sprintf": 1, "vsprintf": 1, "snprintf": 2, "vsnprintf": 2, "syslog": 1,
              "scanf": 0, "fscanf": 1, "sscanf": 1}
# printf: position, width, precision, conversion (MSVC I64/I32/w and %S/%C included)
_CONV = re.compile(r"%(?:(\d+)\$)?[-+ #0']*(\*(?:\d+\$)?|\d+)?(?:\.(\*(?:\d+\$)?|\d+))?"
                   r"(?:hh|h|ll|l|j|z|t|L|q|I64|I32|I|w)?([diouxXeEfFgGaAcCsSpnm%])")
# scanf: '*' suppresses the assignment (no argument), %[set], %ms allocates
_SCONV = re.compile(r"%(\*)?(?:(\d+)\$)?\d*(?:hh|h|ll|l|j|z|t|L|q|m|I64|I32|I|w)?"
                    r"([diouxXeEfFgGaAcCsSpn%]|\[\^?\]?[^\]]*\])")


def _fmt_note(prog, base, args, A):
    """printf/scanf family: show the format and bind each conversion to its argument,
    e.g. `printf "size: %zu bytes..." (%zu = n)`. Only as many arguments as the format
    consumes are used, so Hex-Rays' guessed extra variadic args never show up."""
    fi = _FMT_FUNCS[base]
    if fi >= len(args):
        return None
    fmt = _cstr_arg(prog, args[fi])
    gea = _global_ea(args[fi])
    bug = T("%s: the format (%s) is not a literal, check for a format-string bug",
            "%s 的格式串 %s 不是字面量, 注意格式化字符串漏洞") % (base, A[fi])
    if not fmt and gea is not None and prog.is_writable(gea) and not base.startswith("v"):
        if prog.is_byte_buffer(gea):
            return bug                # printf(global_buf): an empty .bss/.data byte buffer
    if fmt is None:
        if base.startswith("v") or gea is not None:
            # a va_list wrapper passing its format through, or a read-only global we
            # cannot decode: neither is evidence of a format-string bug
            return T("%s %s", "%s 格式串 %s") % (base, A[fi])
        return bug
    q = fmt.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
    q = '"%s"' % (q if len(q) <= 24 else q[:24] + "...")
    binds, k, rest, rest_raw = [], 0, A[fi + 1:], args[fi + 1:]
    # SysV x86-64 / AArch64 pass floating-point varargs in vector registers. Whether
    # Hex-Rays shows them depends on the call (an optimised stripped call often drops
    # them), so a float conversion takes a slot only when that argument is a float.
    fp_apart = not _DEC_CTX["pe"] and _DEC_CTX["arch"] in ("x86_64", "aarch64")
    if not base.startswith("v"):                      # v*printf take a va_list
        scan = base.endswith("scanf")
        for m in (_SCONV if scan else _CONV).finditer(fmt):
            extra = []
            if scan:
                supp, pos, conv = m.groups()
                if conv == "%" or supp:               # %*d reads and discards: no argument
                    continue
            else:
                pos, wid, prec, conv = m.groups()
                if conv == "%":
                    continue
                for star, what in ((wid, T("width", "宽度")), (prec, T("precision", "精度"))):
                    if star and star.startswith("*"):
                        if k < len(rest):
                            extra.append("%s %s" % (what, rest[k]))
                        k += 1
                if conv == "m":                       # %m: strerror(errno), no argument
                    continue
                if fp_apart and conv in "eEfFgGaA" and not pos and \
                        not (k < len(rest_raw) and _is_float(rest_raw[k])):
                    continue
            i = int(pos) - 1 if pos else k
            if 0 <= i < len(rest):
                val = rest[i]
                if conv == "c" and not scan:
                    iv = _arg_int(rest_raw[i])
                    if iv is not None:
                        val = _dec_char(iv & 0xFF)
                spec = m.group(0).replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
                binds.append("%s %s %s%s" % (spec, "->" if scan else "=", val,
                                              " (%s)" % ", ".join(extra) if extra else ""))
            if not pos:
                k += 1
    if len(binds) > 4:
        binds = binds[:4] + ["..."]
    tail = " (%s)" % ", ".join(binds) if binds else ""
    dst = (A[0] if A else "?").replace("%", "%%")    # spliced into the templates below
    cap = (A[1] if len(A) > 1 else "?").replace("%", "%%")
    en, zh = {
        "printf": ("printf %s", "格式打印 %s"), "vprintf": ("vprintf %s", "格式打印 %s"),
        "fprintf": ("fprintf to " + dst + " %s", "向 " + dst + " 格式打印 %s"),
        "vfprintf": ("vfprintf to " + dst + " %s", "向 " + dst + " 格式打印 %s"),
        "dprintf": ("dprintf to " + dst + " %s", "向 " + dst + " 格式打印 %s"),
        "sprintf": ("sprintf into " + dst + " %s", "格式化写入 " + dst + ": %s"),
        "vsprintf": ("vsprintf into " + dst + " %s", "格式化写入 " + dst + ": %s"),
        "snprintf": ("snprintf into %s (max %s) %%s" % (dst, cap),
                     "格式化写入 %s (最多 %s 字节): %%s" % (dst, cap)),
        "vsnprintf": ("vsnprintf into %s (max %s) %%s" % (dst, cap),
                      "格式化写入 %s (最多 %s 字节): %%s" % (dst, cap)),
        "syslog": ("syslog %s", "写 syslog %s"),
        "scanf": ("scanf %s", "格式读入 %s"),
        "fscanf": ("fscanf from " + dst + " %s", "从 " + dst + " 格式读入 %s"),
        "sscanf": ("sscanf " + dst + " with %s", "按 %s 解析 " + dst),
    }[base]
    return T(en, zh) % q + tail


def _call_note(prog, e, nm):
    base, keep = resolve_variant(nm)
    try:
        raw = list(e.args)
    except Exception:
        raw = []
    args = [raw[i] for i in keep if i < len(raw)] if keep is not None else raw
    if keep is not None and base in _FMT_FUNCS and keep:
        args = args + raw[max(keep) + 1:]           # the variadic args after the format
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
            A.append(_arg_text(prog, a))
    # raw syscall: name it from the number, show as many args as the call takes
    if base == "syscall" and A:
        iv = _arg_int(args[0])
        if iv is not None:
            name = _syscalls(_DEC_CTX["arch"] or "x86_64").get(iv)
            if name:
                argc = _SYS_ARGC.get(name)
                if argc is None:                # unknown arity: Hex-Rays' extra args are guesses
                    return SYS + "%s (#%d)" % (name, iv)
                dec = ARG_DEC.get(name) or ARG_DEC.get(name.replace("rt_", "")) or {}
                sa = []
                for k, a in enumerate(args[1:1 + argc]):
                    v = _arg_int(a)
                    if k in dec and v is not None:
                        sa.append(dec[k](v))
                    elif k == 0 and name in _FD_FIRST and v in _FD_NAMES:
                        sa.append("%d (%s)" % (v, _FD_NAMES[v]))
                    else:
                        sa.append(A[1 + k])
                return SYS + "%s(%s) (#%d)" % (name, ", ".join(sa), iv)
    if base in _FMT_FUNCS:
        n = _fmt_note(prog, base, args, A)
        if n:
            return PFX + n
    pair = TMPL.get(base)
    if pair:
        t = pair[1] if i18n.LANG == "zh" else pair[0]
        try:
            return PFX + _dedup_words(t.format(*A, **_derived(base, args, A)))
        except Exception:
            pass
    d = (DESC_ZH if i18n.LANG == "zh" else DESC).get(base)
    return (PFX + d) if d else None


def _dedup_words(s):
    # templates like "close fd {0}" / "send {1} to pid {0}" meet args named fd / pid;
    # quoted string arguments are left exactly as they are
    parts = re.split(r'("(?:[^"\\]|\\.)*")', s)
    return "".join(p if i % 2 else re.sub(r"\b([A-Za-z_]\w*) \1\b", r"\1", p)
                   for i, p in enumerate(parts))


def _derived(base, args, A):
    """Template fields computed from several args: {n} (a byte count or phrase) and
    {mode} (the permission bits of an O_CREAT open)."""
    K = {"n": "", "mode": ""}
    if base in ("fread", "fwrite", "calloc"):
        i, j = (1, 2) if base != "calloc" else (0, 1)
        if j < len(args):
            x, y = _arg_int(args[i]), _arg_int(args[j])
            if x is not None and y is not None:
                K["n"] = _fmt_num(x * y, 8)
            elif x == 1 or y == 1:
                K["n"] = A[j] if x == 1 else A[i]
            else:
                par = lambda s: "(%s)" % s if " " in s and s != "..." else s     # (n + 1) x 16
                K["n"] = "%s x %s" % (par(A[i]), par(A[j]))
    elif base == "sbrk" and args:
        v = _arg_int(args[0])
        if v is not None:
            v = v - (1 << 64) if v >= (1 << 63) else v
        K["n"] = (T("query the program break", "查询当前堆顶") if v == 0 else
                  T("shrink the heap by %d bytes", "堆缩小 %d 字节") % -v if v is not None and v < 0 else
                  T("grow the heap by %s bytes", "堆扩大 %s 字节") % (A[0] if v is None else v))
    elif base in ("lseek", "fseek") and len(args) >= 3:
        # SEEK_CUR/SEEK_END offsets are relative: "to 0 (SEEK_END)" read like the start
        off, wh = _arg_int(args[1]), _arg_int(args[2])
        if off is not None:
            try:
                bits = 8 * args[1].size
            except Exception:
                bits = 64
            bits = bits if bits in (32, 64) else 64
            off &= (1 << bits) - 1             # numval() may already be sign-extended
            off = off - (1 << bits) if off >= 1 << (bits - 1) else off
        where = {1: T("the current position", "当前位置"), 2: T("the end", "末尾")}.get(wh)
        if where is None:
            K["pos"] = A[1] if wh == 0 else "%s (%s)" % (A[1], A[2])
        elif off == 0:
            K["pos"] = where
        elif off is None:
            K["pos"] = "%s + %s" % (where, A[1])
        else:
            K["pos"] = "%s %s %d" % (where, "-" if off < 0 else "+", abs(off))
    elif base in ("open", "openat"):
        fi = 1 if base == "open" else 2
        fl = _arg_int(args[fi]) if fi < len(args) else None
        md = _arg_int(args[fi + 1]) if fi + 1 < len(args) else None
        if fl is not None and fl & _o_creat_bit() and md is not None:
            K["mode"] = T(", mode 0%o", ", 权限 0%o") % md
    return K


def _segread_note(helper, e):
    m = re.match(r"__(read|write)(fs|gs)(byte|word|dword|qword)$", helper or "")
    if not m:
        return None
    try:
        off = _arg_int(e.args[0])
    except Exception:
        off = None
    if off is None:
        return None
    seg = m.group(2)
    signed =off - (1 << 32) if off >= 0x80000000 and off < (1 << 32) else \
        off - (1 << 64) if off >= (1 << 63) else off
    if signed < 0:
        what = ("thread-local variable", "线程局部变量")
    else:
        what = (_SEG_PE if _DEC_CTX["pe"] else _SEG_ELF).get((seg, signed))
        if not what:
            return None
    where = "%s:%s0x%X" % (seg, "-" if signed < 0 else "", abs(signed))
    return OPX + "%s %s %s" % (T("read", "读") if m.group(1) == "read" else T("write", "写"),
                               where, what[1] if i18n.LANG == "zh" else what[0])


def _magic_note(e):
    """If any immediate arg is a known magic constant, note it."""
    try:
        for a in e.args:
            iv = _arg_int(a)
            if iv is not None:
                key = iv & 0xFFFFFFFF
                if key in MAGIC:
                    return OPX + (MAGIC[key][1] if i18n.LANG == "zh" else MAGIC[key][0])
    except Exception:
        pass
    return None


def collect_notes(prog, calls):
    """Notes for one function. `calls` are its call expressions in pre-order (an
    intrinsic before the ones it folds), each with a valid address.
    Returns (by_ea, by_idx):
       by_ea  {ea: text}     — for persisting as user comments (keyed by address)
       by_idx {index: text}  — for live rendering (keyed by the call's item index,
                                so parent blocks that share an ea don't match)."""
    by_ea, by_idx = {}, {}
    set_target(prog.arch() or "", prog.is_pe())
    used = set()          # intrinsic calls already folded into an enclosing note
    for e in calls:
        got = []
        callee = e.x
        if callee.op == "helper":
            if e.uid in used:
                continue
            try:
                n = _vec_call_note(prog, e, used)
            except Exception:
                n = None
            n = n or _segread_note(callee.helper, e)
            if n:
                got.append(n)
        elif callee.op == "obj":
            nm = prog.func_name(callee.obj_ea) or prog.name_at(callee.obj_ea) or ""
            n = _call_note(prog, e, nm)
            if n:
                got.append(n)
        mg = _magic_note(e)
        if mg:
            got.append(mg)
        if got:
            text = "   ".join(dict.fromkeys(got))
            slot = by_ea.setdefault(e.ea, [])
            for g in got:
                if g not in slot:
                    slot.append(g)
            by_idx[e.index] = text
    return {ea: "   ".join(lst) for ea, lst in by_ea.items()}, by_idx
