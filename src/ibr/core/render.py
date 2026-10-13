"""Argument text for notes: numbers, strings, variables, else the decompiler's own text.

Expressions are ports.Expr objects; `prog` is a ports.Program (strings and names)."""
import re


def _fmt_num(val, size):
    if size and 0 < size <= 8:
        val &= (1 << (8 * size)) - 1          # numval() is 64-bit: -1 in an int is 2**64-1
        signed = val - (1 << (8 * size)) if val >= (1 << (8 * size - 1)) else val
    else:
        signed = val - (1 << 64) if val >= (1 << 63) else val
    if -65536 <= signed < 0:
        return str(signed)
    if val > 9999:
        return "0x%X" % val
    return str(val)


def _decode_text(b):
    """bytes -> str for display: UTF-8, else GBK (common in Chinese CTF binaries)."""
    for enc in ("utf-8", "gbk"):
        try:
            s = b.decode(enc)
        except Exception:
            continue
        if all(ch.isprintable() or ch in "\n\r\t" for ch in s):
            return s
    return None


def _raw_cstr(prog, ea):
    """Full C string at ea (typed string literal, or untyped readable bytes), else None.
    Code addresses are never read as text (a function's first bytes can look printable)."""
    b = prog.cstr_bytes(ea)
    return _decode_text(b) if b else None


def _str_at(prog, ea):
    """Return a quoted, shortened C string at ea, else None."""
    s = _raw_cstr(prog, ea)
    if s is None:
        return None
    s = s.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
    if len(s) > 24:
        s = s[:24] + "..."
    return '"%s"' % s


_VALUE_CAST = re.compile(r"\((?:(?:unsigned|signed|const|volatile) )*(?:__int\d+|int|char|short|"
                         r"long long|long|_BYTE|_WORD|_DWORD|_QWORD|_OWORD|_BOOL\d|bool|size_t|"
                         r"float|double|__m64|__m128[id]?|__m256[id]?|__m512[id]?)\)")


def _strip_casts(a):
    while a.op == "cast" and a.x is not None:
        a = a.x
    return a


def _arg_text(prog, a):
    try:
        a = _strip_casts(a)
        op = a.op
        if op == "num":
            return _fmt_num(a.value, a.size)
        if op == "str":
            s = a.string
            if len(s) > 24:
                s = s[:24] + "..."
            return '"%s"' % s
        if op == "obj":
            return _str_at(prog, a.obj_ea) or prog.name_at(a.obj_ea) or ("0x%X" % a.obj_ea)
        if op == "var":
            return a.var_name
        if op == "ref" and a.x is not None:
            inner = a.x
            if inner.op == "var":
                return "&" + inner.var_name
            if inner.op == "obj":
                return _str_at(prog, inner.obj_ea) or ("&" + (prog.name_at(inner.obj_ea) or "0x%X" % inner.obj_ea))
        # fall back to the decompiler's own rendering: handles buf+8, s->field, arr[i], &x ...
        # Value casts go (pointer casts stay: they decide pointer arithmetic). Text
        # still too long becomes "...": cutting it mid-parenthesis reads worse, and
        # the full expression is right there in the call.
        txt = _VALUE_CAST.sub("", a.render())
        return txt if len(txt) <= 36 else "..."
    except Exception:
        pass
    return "?"


def _is_float(a):
    try:
        return a.op == "fnum" or bool(a.is_float)
    except Exception:
        return False


def _arg_int(a):
    """Return the integer value of a constant arg (after casts), else None."""
    try:
        a = _strip_casts(a)
        if a.op == "num":
            return a.value
    except Exception:
        pass
    return None


def _global_ea(a):
    """Address of a global the argument names directly (x or &x), else None."""
    a = _strip_casts(a)
    if a.op == "obj":
        return a.obj_ea
    if a.op == "ref" and a.x is not None and a.x.op == "obj":
        return a.x.obj_ea
    return None


def _cstr_arg(prog, a):
    """Full text of a string-literal argument (untruncated), else None."""
    try:
        a = _strip_casts(a)
        if a.op == "str":
            return a.string
        ea = _global_ea(a)
        return _raw_cstr(prog, ea) if ea is not None else None
    except Exception:
        return None
