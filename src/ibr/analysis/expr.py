"""Expressions of the statement tree as C text and as math, for the flowchart.

c_text writes an expression the way Hex-Rays does (printf-family calls with only the
arguments their format reads). Terms.norm turns one into a math term: MMX/SSE intrinsic
chains folded the way the notes fold them (_m_pxor is ^, a shift pair is a rotation), with
the lane width where there is no carry between lanes. _wrap breaks a long line the way
Hex-Rays does. Nothing here imports IDA."""
import re

from ..core import simd
from ..core.i18n import T
from ..core.names import resolve_variant
from ..core.notes import _CONV, _FMT_FUNCS
from .dataflow import READS, SCANF, WRITES, _call_name, _strip, _writes

# calls a value reaching them says nothing about
_QUIET = {"free", "fclose", "close", "munmap", "fflush", "fseek", "rewind", "setvbuf", "setbuf",
          "ftell", "stack_chk_fail", "emms"}
# library calls whose result is computed from their arguments (others return a count, a
# handle, a status: nothing to follow)
_PURE = set("""strlen strnlen strcmp strncmp memcmp strcasecmp strncasecmp bcmp atoi atol atoll
strtol strtoul strtoll strtoull strtod strtof atof toupper tolower abs labs llabs htonl htons
ntohl ntohs strchr strrchr strstr memchr strspn strcspn""".split())
# where data leaves the program: the argument positions that carry it
_OUT = {"puts": (0,), "fputs": (0,), "putchar": (0,), "putc": (0,), "fputc": (0,), "write": (1,),
        "send": (1,), "sendto": (1,), "fwrite": (0,), "puts_unlocked": (0,)}
_BITWISE = {"^", "&", "|", "~"}
_PREC = {"||": 4, "&&": 5, "|": 6, "^": 7, "&": 8, "==": 9, "!=": 9, "<": 10, "<=": 10, ">": 10,
         ">=": 10, "<<": 11, ">>": 11, "<<<": 11, ">>>": 11, "+": 12, "-": 12, "*": 13, "/": 13,
         "%": 13}
WIDTH = 60                      # a line is wrapped beyond this many characters


# ---------------------------------------------------------------- C text of a tree
def _num_text(t):
    s = t.text or (str(t.value) if 0 <= t.value < 10 else "0x%X" % t.value)
    m = re.fullmatch(r"(-?(?:0x[0-9A-Fa-f]+|\d+))(?:u?i64|ui64|[uU]?[lL]{0,2}|[lL]{1,2}[uU]?)", s)
    return m.group(1) if m else s


def _num_value(text):
    try:
        return int(text, 0)
    except ValueError:
        return None


def _cstr(s, limit=40):
    out = []
    for ch in s or "":
        o = ord(ch)
        out.append({"\n": "\\n", "\t": "\\t", "\r": "\\r", '"': '\\"', "\\": "\\\\"}.get(ch)
                   or (ch if 32 <= o < 127 or o > 160 else "\\x%02X" % (o & 0xFF)))
    t = "".join(out)
    return '"%s"' % (t if len(t) <= limit else t[:limit - 1] + "…")


def _c(e):
    """(C text, precedence) of an expression, casts left out."""
    e = _strip(e)
    if e is None:
        return "", 16
    k = e.kind
    if k == "var":
        return e.name or "v%d" % e.var, 16
    if k == "obj":
        if e.strlit:
            return _cstr(e.string), 16
        return e.text or e.name or "%X" % (e.obj_ea or 0), 16
    if k == "helper":
        return e.name, 16
    if k == "num":
        t = _num_text(e)
        return t, 14 if t.startswith("-") else 16
    if k == "fnum":
        return e.text or "float", 16
    if k == "str":
        return _cstr(e.string), 16
    if k == "ref":
        return "&" + _p(e.x, 14), 14
    if k == "ptr":
        return "*" + _p(e.x, 14), 14
    if k == "idx":
        return _p(e.x, 15) + "[" + _c(e.y)[0] + "]", 15
    if k == "mem":
        return _p(e.x, 15) + e.op + (e.name or "?"), 15
    if k == "call":
        args = list(e.args)
        raw = e.x.name if e.x is not None else ""
        fa = _format_args(raw, args) if raw else None
        if fa is not None:                       # printf: the format and what it prints
            base, keep = resolve_variant(raw)
            fixed = keep if keep is not None else list(range(_FMT_FUNCS[base] + 1))
            args = [args[i] for i in [i for i in fixed if i < len(args)] + sorted(fa)]
        return _c(e.x)[0] + "(" + ", ".join(_c(a)[0] for a in args) + ")", 15
    if k == "asg":
        return _p(e.x, 3) + " " + e.op + "= " + _p(e.y, 2), 2
    if k in ("inc", "dec"):
        o = "++" if k == "inc" else "--"
        return (o + _p(e.x, 14), 14) if e.op == "pre" else (_p(e.x, 15) + o, 15)
    if k == "bin":
        q = _PREC.get(e.op, 12)
        return _pb(e.x, q, e.op) + " " + e.op + " " + _pb(e.y, q + 1, e.op), q
    if k == "un":
        return e.op + _p(e.x, 14), 14
    if k == "tern":
        return _p(e.x, 4) + " ? " + _c(e.y)[0] + " : " + _p(e.z, 3), 3
    if k == "comma":
        return _c(e.x)[0] + ", " + _c(e.y)[0], 1
    return "…", 16


def _p(e, prec):
    t, q = _c(e)
    return t if q >= prec else "(" + t + ")"


_CLEAR = {"<<", ">>", "&", "|", "^"}


def _pb(e, prec, op):
    """An operand of a binary operator: a shift or a bitwise operation mixed with another
    operator is bracketed even where C would not need it, as Hex-Rays does: (n - 1) >> 3."""
    t, q = _c(e)
    c = _strip(e)
    if q < prec or (c is not None and c.kind == "bin" and c.op != op and q < 14
                    and (op in _CLEAR or c.op in _CLEAR)):
        return "(" + t + ")"
    return t


def c_text(e):
    """An expression as C, without casts."""
    return _c(e)[0]


def _strconst(a):
    """The text of a string literal an address points into, or None."""
    a = _strip(a)
    if a is None:
        return None
    if a.kind == "str":
        return _cstr(a.string)
    if a.kind == "obj" and a.strlit:
        return _cstr(a.string)
    if a.kind == "ref" and a.x is not None:
        b = _strip(a.x)
        if b.kind == "obj" and b.strlit:
            return _cstr(b.string)
        if b.kind == "idx" and _strip(b.x) is not None and _strip(b.x).kind == "obj" and \
                _strip(b.x).strlit and _strip(b.y) is not None and _strip(b.y).kind == "num":
            return _cstr(_strip(b.x).string[_strip(b.y).value:])
    if a.kind == "bin" and a.op == "+":
        b, n = _strip(a.x), _strip(a.y)
        if b is not None and n is not None and n.kind == "num" and b.kind in ("obj", "str") and \
                (b.kind == "str" or b.strlit):
            return _cstr(b.string[n.value:])
    return None


def _format_args(raw, args):
    """The argument positions a printf-family call reads through its format: Hex-Rays' extra
    guessed variadic arguments are not data."""
    base, keep = resolve_variant(raw)
    fi = _FMT_FUNCS.get(base)
    if fi is None or base.endswith("scanf"):
        return None
    pos = keep[fi] if keep is not None and fi < len(keep) else fi
    if pos >= len(args):
        return set()
    f = _strip(args[pos])
    if f is None or not (f.kind == "str" or (f.kind == "obj" and f.strlit)):
        return set(range(pos + 1, len(args)))
    out, k = set(), 0
    for m in _CONV.finditer(f.string):
        p, wid, prec, conv = m.groups()
        if conv in ("%", "m"):
            continue
        for star in (wid, prec):
            if star and star.startswith("*"):
                k += 1
        i = int(p) - 1 if p else k
        out.add(pos + 1 + i)
        if not p:
            k += 1
    return {i for i in out if i < len(args)}


def _data_args(raw, name, e):
    """Which arguments of a call carry data into it (None: all of them)."""
    if name in _PURE:
        return None
    fa = _format_args(raw, e.args)
    if fa is not None:
        return fa
    if name in _OUT:
        return set(_OUT[name])
    if name in WRITES or name in SCANF or name in READS or name.startswith("unknown_libname"):
        return set()                              # sizes, handles, flags
    return None                                   # a function of the program: everything


def _show(lv):
    """An lvalue the way the notes write it: `v28->m64_u64` is `*v28`."""
    return simd._vec_operand(c_text(lv))


# ---------------------------------------------------------------- math terms
class _K:
    """A constant, or anything else that is only its text."""
    def __init__(self, text, value=None):
        self.text, self.value = text, value


class _S:
    """A value read: the variables or memory (keys) it comes from."""
    def __init__(self, keys, text, tree):
        self.keys, self.text, self.tree = keys, text, tree


class _Op:
    """kind "bin" x sym y, "un" sym x, "rot" x sym n, "fn" name(args), "tern" a ? b : c.
    lane: (lane bits, register bits) of a vector operation."""
    def __init__(self, kind, sym, args, lane=None):
        self.kind, self.sym, self.args, self.lane = kind, sym, args, lane


def _mtext(m, prec=0):
    if isinstance(m, (_K, _S)):
        t = m.text
        q = 0 if simd._top_ops(t) else 14 if t.startswith(("-", "*", "&", "~", "!")) else 16
        return t if q >= prec else "(" + t + ")"
    if m.kind == "bin" or m.kind == "rot":
        q = _PREC.get(m.sym, 12)
        t = "%s %s %s" % (_mtext(m.args[0], q), m.sym, _mtext(m.args[1], q + 1))
    elif m.kind == "un":
        q, t = 14, m.sym + _mtext(m.args[0], 14)
    elif m.kind == "tern":
        q = 3
        t = "%s ? %s : %s" % (_mtext(m.args[0], 4), _mtext(m.args[1]), _mtext(m.args[2], 3))
    else:
        q, t = 16, "%s(%s)" % (m.sym, ", ".join(_mtext(a) for a in m.args))
    return t if q >= prec else "(" + t + ")"


def _lane_tag(m):
    """` (per byte)` for an arithmetic vector operation on lanes narrower than the register:
    there is no carry between them. Bitwise operations need no tag."""
    if not m.lane or m.sym in _BITWISE:
        return ""
    bits, reg = m.lane
    if not bits or bits >= reg:
        return ""
    return T(" (per byte)", " (每字节)") if bits == 8 else T(" (per %d-bit)" % bits, " (每%d位)" % bits)


def _rot(sym, a, b, lane):
    """(x << n) | (x >> w-n) on w-bit values is a rotation; also with ^ or +."""
    if sym not in ("|", "^", "+"):
        return None
    for l, r in ((a, b), (b, a)):
        if not (isinstance(l, _Op) and isinstance(r, _Op) and l.kind == r.kind == "bin"
                and l.sym == "<<" and r.sym == ">>"):
            continue
        n, k = l.args[1], r.args[1]
        if not (isinstance(n, _K) and isinstance(k, _K) and n.value and k.value):
            continue
        if _mtext(l.args[0]) != _mtext(r.args[0]):
            continue
        w = n.value + k.value
        ln = l.lane or r.lane
        if (ln and ln[0] == w) or (not ln and w in (8, 16, 32, 64)):
            return _Op("rot", "<<<", [l.args[0], n], ln)
    return None


# ---------------------------------------------------------------- an expression as a term
class Terms:
    """An expression of the statement tree as a math term: what it reads, the operations,
    intrinsic chains folded. `an` is the data-flow analysis of the function."""

    def __init__(self, an):
        self.an, self.g = an, an.g

    # ---- what an expression reads ----
    def _objs(self, addr, s):
        return {o for o in self.an._pts(addr, s) if o[0] not in ("unk", "abs")}

    def _read_keys(self, e, s):
        if e.mem:
            return set()                          # an array or a structure stands for its address
        if e.kind == "var":
            if e.var in self.g.memvars:
                return {("stk", e.var)}
            return set() if (e.var in self.g.ptrvars or e.ptr) else {("v", e.var)}
        if e.kind == "obj":
            return set() if e.ptr else {("g", e.obj_ea)}
        if e.ptr:
            return set()                          # a pointer loaded from memory: an address
        r = self.g._root(e)
        if r[0] == "var":
            return {("v", r[1])}
        if r[0] == "obj":
            return {r[1]}
        return self._objs(r[1], s)

    def norm(self, e, s):
        e = _strip(e)
        if e is None:
            return _K("?")
        k = e.kind
        if k == "num":
            t = _num_text(e)
            return _K(t, _num_value(t))
        if k in ("fnum", "str", "ref", "helper") or (k == "obj" and e.strlit):
            return _K(c_text(e))
        if k in ("var", "obj", "ptr", "idx", "mem"):
            keys = self._read_keys(e, s)
            return _S(keys, _show(e), e) if keys else _K(_show(e))
        if k in ("inc", "dec"):
            return self.norm(e.x, s)
        if k == "asg":
            if e.op:
                return _Op("bin", e.op, [self.norm(e.x, s), self.norm(e.y, s)])
            return self.norm(e.y, s)
        if k == "comma":
            return self.norm(e.y, s)
        if k == "call":
            return self._call(e, s)
        if k == "bin":
            a, b = self.norm(e.x, s), self.norm(e.y, s)
            return _rot(e.op, a, b, None) or _Op("bin", e.op, [a, b])
        if k == "un":
            return _Op("un", e.op, [self.norm(e.x, s)])
        if k == "tern":
            return _Op("tern", "?:", [self.norm(c, s) for c in (e.x, e.y, e.z)])
        return _K("…")

    def _arg(self, a, s, written=False):
        """A call argument: what an address points at is what the call reads."""
        if written:
            return _K(c_text(a))
        lit = _strconst(a)
        if lit is not None:
            return _K(lit)
        if self.g._is_addr(a):
            b = _strip(a)
            if b.kind == "ref":
                return self.norm(b.x, s)
            objs = self._objs(a, s)
            return _S(objs, c_text(a), a) if objs else _K(c_text(a))
        return self.norm(a, s)

    def _call(self, e, s):
        raw = e.x.name if e.x is not None else ""
        if e.x is not None and e.x.kind == "helper":
            r = self._intrinsic(raw, e, s)
            if r is not None:
                return r
        ws = _writes(e)
        data = _data_args(raw, _call_name(e), e)
        return _Op("fn", c_text(e.x) or raw, [self._arg(a, s, i in ws or (data is not None and i not in data))
                                             for i, a in enumerate(e.args)])

    def _intrinsic(self, raw, e, s):
        h = raw.lstrip("_")
        if simd._V_ZERO.match(h):
            return _K("0", 0)
        if e.args and simd._V_SCALAR.match(h):
            return self.norm(e.args[0], s)
        if len(e.args) == 1 and simd._V_LOAD.match(h):
            a = _strip(e.args[0])
            lit = _strconst(a)
            if lit is not None:
                return _K(lit)
            if a.kind == "ref":
                return self.norm(a.x, s)
            objs = self._objs(a, s)
            t = "*" + _p(a, 14)
            return _S(objs, t, a) if objs else _K(t)
        m = re.fullmatch(r"__RO([LR])(\d)__", raw)
        if m and len(e.args) == 2:
            w = int(m.group(2)) * 8
            return _Op("rot", "<<<" if m.group(1) == "L" else ">>>",
                       [self.norm(e.args[0], s), self.norm(e.args[1], s)], (w, w))
        vo = simd._vec_op(h)
        if not vo or len(e.args) < 2:
            return None
        op, lane = vo
        bits = simd._LANE_UNIT.get(lane, (0,))[0]
        ln = (bits, simd._reg_bits(h)) if bits else None
        a, b = self.norm(e.args[0], s), self.norm(e.args[1], s)
        if op == "andnot":
            return _Op("bin", "&", [_Op("un", "~", [a]), b], ln)
        sym = simd._INFIX.get(op)
        if not sym or (op in ("sll", "slli", "srl", "srli") and lane in ("128b", "256b", "512b")):
            return None                            # byte shifts, min/max, shuffles: as calls
        if op == "xor" and _mtext(a) == _mtext(b):
            return _K("0", 0)
        return _rot(sym, a, b, ln) or _Op("bin", sym, [a, b], ln)

    # ---- which nodes a read comes from ----


    # ---- one statement ----


# ---------------------------------------------------------------- long lines
def _split_top(t, seps):
    """Positions in t (outside strings and brackets) where one of seps starts."""
    out = []
    for i, c, st in simd._scan(t):
        if not st:
            for sep in seps:
                if t.startswith(sep, i):
                    out.append((i, sep))
    return out


def _wrap(head, inner, tail):
    """`head inner tail` on one line, or broken the way Hex-Rays breaks a long condition
    (before && / ||) or a long call (after a comma)."""
    one = head + inner + tail
    if len(one) <= WIDTH:
        return [one]
    cuts = [i for i, _ in _split_top(inner, (" && ", " || "))]
    lines = []
    if cuts:
        start = 0
        for i in cuts:
            lines.append(inner[start:i])
            start = i + 1
        lines.append(inner[start:])
        out = [head + lines[0]] + ["  " + l for l in lines[1:]]
        out[-1] += tail
        return out
    parts, start = [], 0
    for i, sep in _split_top(inner, (", ",)):
        parts.append(inner[start:i + 1])
        start = i + 2
    parts.append(inner[start:])
    out, cur = [], head
    for p in parts:
        if len(cur) + len(p) + 1 > WIDTH and cur.strip():
            out.append(cur.rstrip())
            cur = "    "
        cur += p + " "
    out.append(cur.rstrip() + tail)
    return out
