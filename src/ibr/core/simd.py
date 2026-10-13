"""MMX/SSE/AVX intrinsic calls folded into plain infix expressions.

Calls are ports.Expr trees; `prog` is a ports.Program."""
import re

from .comments import OPX
from .i18n import T
from .render import _arg_text, _strip_casts


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


_INFIX = {"add":"+", "sub":"-", "mul":"*", "mullo":"*", "and":"&", "or":"|", "xor":"^",
          "sll":"<<", "slli":"<<", "srl":">>", "srli":">>", "sra":">>", "srai":">>"}
_MMX_OP = {"pxor":"xor", "por":"or", "pand":"and", "pandn":"andnot", "mull":"mullo", "mulh":"mulhi"}
_VEC_FN_ZH = {"interleave lo":"交错低半", "interleave hi":"交错高半", "shuffle":"重排",
              "shuffle lo":"重排低半", "shuffle hi":"重排高半", "pack (sat)":"饱和打包",
              "pack (usat)":"无符号饱和打包", "blend":"混合"}
# lane key -> (bits, English unit, Chinese unit), for the plain-language tail
_LANE_UNIT = {"per byte": (8, "byte", "字节"), "per u8": (8, "unsigned byte", "无符号字节"),
              "per 16b": (16, "16-bit lane", "16 位"), "per u16": (16, "unsigned 16-bit lane", "无符号 16 位"),
              "per 32b": (32, "32-bit lane", "32 位"), "per u32": (32, "unsigned 32-bit lane", "无符号 32 位"),
              "per 64b": (64, "64-bit lane", "64 位"), "per u64": (64, "unsigned 64-bit lane", "无符号 64 位"),
              "per f32": (32, "float", "f32"), "per f64": (64, "double", "f64"),
              "64b": (64, "64-bit lane", "64 位"), "128b": (128, "128-bit lane", "128 位"),
              "256b": (256, "256-bit lane", "256 位"), "512b": (512, "512-bit lane", "512 位")}
_BITWISE_SYMS = {"^", "&", "|", "&~", "andnot"}       # no lanes: a bit is a bit


def _reg_bits(h):
    """Register width of an intrinsic: _m_* and *_pi8/16/32/_si64 are MMX."""
    if h.startswith("m_") or re.search(r"_(?:pi\d+|si64)$", h):
        return 64
    return 512 if h.startswith("mm512_") else 256 if h.startswith("mm256_") else 128

_M64_WHOLE = re.compile(r"^(.+?)(->|\.)m64_[iu]64$")


def _vec_operand(t):
    """`p->m64_u64` is the whole 64-bit value at p, `x.m64_u64` is x."""
    m = _M64_WHOLE.match(t)
    if not m:
        return t
    if m.group(2) == ".":
        return m.group(1)
    return "*" + (m.group(1) if re.match(r"^\w+$", m.group(1)) else "(%s)" % m.group(1))


def _intrin_note(helper, args=()):
    """Explain an MMX/SSE/AVX/crypto intrinsic call. `args` are the operands as
    rendered by Hex-Rays, so the note reads `a ^ b (per 64b)` rather than just `^`."""
    h = (helper or "").lstrip("_")
    a = [x for x in args if x]
    # crypto first (highest value)
    for k, v in sorted(_CRYPTO.items(), key=lambda kv: -len(kv[0])):    # aesenclast before aesenc
        if k in h:
            return OPX + v + ("(%s)" % ", ".join(a) if a else "")
    if h == "m_empty":
        return OPX + T("emms (clear MMX state)", "emms(清空 MMX 状态)")
    op = lane = None
    m = re.match(r"mm(?:256|512)?_(?:mask_|maskz_)?(\w+?)_(epi\d+|epu\d+|ps|pd|si\d+|pi\d+)$", h)
    if m and m.group(1) in _VEC_OP:
        op, lane = m.group(1), _VEC_LANE.get(m.group(2), m.group(2))
    else:
        # legacy _m_* MMX intrinsics (pxor, psrlwi, paddb, ...); bare pxor/por/pand are 64-bit
        m = re.match(r"m_p?(pxor|por|pand|pandn|add|sub|mull|mulh|sll|srl|sra)([bwdq])?i?$", h)
        if not m:
            return None
        op = _MMX_OP.get(m.group(1), m.group(1))
        lane = {"b":"per byte", "w":"per 16b", "d":"per 32b", "q":"per 64b"}.get(m.group(2), "64b")
    lk = ("signed " + lane) if op in ("sra", "srai") else lane
    tail = _lane_tail({(lk, _reg_bits(h)): [_INFIX.get(op) or _VEC_OP.get(op, op)]})
    if len(a) >= 2:
        x, y = a[0], a[1]
        if op == "xor" and x == y:
            return OPX + "%s ^ %s = 0 (%s)" % (x, y, T("zeroing", "清零"))
        if op in _INFIX:
            return OPX + "%s %s %s%s" % (x, _INFIX[op], y, tail)
        if op == "andnot":
            return OPX + "~%s & %s%s" % (x, y, tail)
        if op == "mulhi":
            return OPX + T("high half of %s * %s", "%s * %s 的高半部分") % (x, y) + tail
        if op in ("cmpeq", "cmpgt"):
            return OPX + "%s %s %s ? ~0 : 0%s" % (x, _VEC_OP[op], y, tail)
        return OPX + "%s(%s)%s" % (_VEC_OP[op], ", ".join(a), tail)
    return OPX + _VEC_OP.get(op, op) + tail

# data-movement intrinsics, folded into the expression as the value they produce
_V_LOAD = re.compile(r"mm(?:256|512)?_(?:load[lu]?|loadl|lddqu)_\w+$")
_V_SCALAR = re.compile(r"mm(?:256|512)?_cvtsi(?:32|64)_si(?:64|128|256)$|m_from_int(?:64)?$|mm_cvtsi64_m64$")
_V_ZERO = re.compile(r"mm(?:256|512)?_setzero_\w+$")
_V_SPLAT = re.compile(r"mm(?:256|512)?_set1_\w+$")


def _vec_op(h):
    """(op, lane) for an arithmetic/logic/compare intrinsic name, else None."""
    m = re.match(r"mm(?:256|512)?_(?:mask_|maskz_)?(\w+?)_(epi\d+|epu\d+|ps|pd|si\d+|pi\d+)$", h)
    if m and m.group(1) in _VEC_OP:
        return m.group(1), _VEC_LANE.get(m.group(2), m.group(2))
    m = re.match(r"m_p?(pxor|por|pand|pandn|add|sub|mull|mulh|sll|srl|sra)([bwdq])?i?$", h)
    if m:
        return (_MMX_OP.get(m.group(1), m.group(1)),
                {"b":"per byte", "w":"per 16b", "d":"per 32b", "q":"per 64b"}.get(m.group(2), "64b"))
    return None


_BINOP = re.compile(r" (\|\||&&|<<|>>|==|!=|<=|>=|[|^&+\-*/%<>?:]) ")
_ASSOC = {"|", "^", "&", "+", "*"}


def _scan(t, limit=None):
    """Walk `t` outside string literals, yielding (index, char, open brackets)."""
    stack, q, i = [], None, 0
    end = len(t) if limit is None else min(limit, len(t))
    while i < end:
        c = t[i]
        if q:
            if c == "\\":
                i += 1
            elif c == q:
                q = None
        elif c in "\"'":
            q = c
        elif c in "([{":
            stack.append(")]}"["([{".index(c)])
        elif c in ")]}" and stack:
            stack.pop()
        else:
            yield i, c, stack
        i += 1


def _top_ops(t):
    """Binary operators of `t` that are outside every bracket."""
    return {m.group(1) for i, c, st in _scan(t) if c == " " and not st
            for m in [_BINOP.match(t, i)] if m}


def _operand(t, sym=None, left=False):
    """Operand text, bracketed only when needed. A chain of one associative
    operator (`a | b | c`) and a term with no operator outside brackets
    (`*(p + 4)`, `rotl(x, 1)`) need none."""
    if t[1]:
        return t[0]
    ops = _top_ops(t[0])
    if not ops or (sym in _ASSOC and ops == {sym}) or (sym == "-" and left and ops <= {"+", "-"}):
        return t[0]
    return "(%s)" % t[0]


def _clip(t, n=140):
    """Shorten at an operator or comma and close what is still open, so a long
    chain reads `a | b | (c & ...)` instead of stopping mid-bracket."""
    if len(t) <= n:
        return t
    cuts = []
    for i, c, st in _scan(t, n - 8):
        m = _BINOP.match(t, i) if c == " " else None
        if c == "," and t[i + 1:i + 2] == " ":
            cuts.append((i + 2, len(st), "".join(reversed(st))))
        elif m and m.group(1) not in ("?", ":"):
            cuts.append((m.end(), len(st), "".join(reversed(st))))
    if not cuts:
        return t[:n - 3] + "..."
    late = [c for c in cuts if c[0] >= n // 2] or cuts        # the shallowest cut in the second half
    end, _, closers = [c for c in late if c[1] == min(d for _, d, _ in late)][-1]
    return t[:end] + "..." + closers


def _vec_text(h, a, lanes):
    """Render one intrinsic over already-rendered operands [(text, atomic)] as
    (text, atomic), recording its lane in `lanes`; None if it does not fold."""
    p = _operand
    if _V_ZERO.match(h):
        return "0", True
    if a and _V_SPLAT.match(h):
        return "splat(%s)" % a[0][0], True
    if a and _V_SCALAR.match(h):
        return a[0]
    if len(a) == 1 and _V_LOAD.match(h):        # 2-arg loadl/loadh_pd merge into a vector
        t = a[0][0]
        if t.startswith("&") and re.match(r"&[\w.]+$", t):
            return t[1:], True                         # *&x is x
        return "*" + p(a[0]), True
    vo = _vec_op(h)
    if vo and vo[0] in ("shuffle", "shufflelo", "shufflehi") and a:
        sh = _shuffle_text(h, a)
        if sh:
            return sh, True
    if not vo or len(a) < 2:
        return None
    op, lane = vo
    if op in ("unpacklo", "unpackhi") and lane in ("per 64b", "per f64"):
        if op == "unpacklo" and lane == "per 64b":
            # low qword of each: how compilers build a 2-element array, e.g. {"sh", "-c"}
            return "{%s, %s}" % (a[0][0], a[1][0]), True
        k = 0 if op == "unpacklo" else 1
        ix2 = lambda t: t[0] if t[1] and not t[0].startswith(("*", "&")) else "(%s)" % t[0]
        return "{%s[%d], %s[%d]}" % (ix2(a[0]), k, ix2(a[1]), k), True
    x, y = a[0], a[1]
    if op == "xor" and x[0] == y[0]:
        return "0", True
    atomic = False
    reg = _reg_bits(h)
    if op in ("sll", "slli", "srl", "srli") and lane in ("128b", "256b", "512b"):
        # _mm_slli_si128 / _mm_srli_si128 (pslldq/psrldq) shift by BYTES, per 128-bit lane
        sym = _INFIX[op]
        txt = "%s %s %s %s" % (p(x), sym, y[0], T("bytes", "字节"))
        syms = lanes.setdefault(("128b", reg), [])
        if sym not in syms:
            syms.append(sym)
        return txt, False
    if op in ("or", "xor") and not x[1] and not y[1]:
        # (v << n) | (v >> (w - n)) on w-bit lanes is a rotate (ChaCha, BLAKE, SipHash...)
        rot = None
        for a1, a2 in ((x[0], y[0]), (y[0], x[0])):
            m1 = re.fullmatch(r"(.+) << (\d+)", a1)
            m2 = re.fullmatch(r"(.+) >> (\d+)", a2)
            if m1 and m2 and m1.group(1) == m2.group(1):
                w = int(m1.group(2)) + int(m2.group(2))
                # both shifts logical: (v << n) | (v >>(signed) m) sign-fills, no rotate
                keys = [k for k in lanes if k[0] == "per %db" % w and "<<" in lanes[k] and ">>" in lanes[k]]
                if w in (16, 32, 64) and keys:
                    rot = (m1.group(1), int(m1.group(2)), w, keys[0])
        if rot:
            base, n, w, lk = rot
            # rotating by half the lane swaps its two halves (bswap16 for 16-bit lanes)
            lanes[lk] = [s for s in lanes[lk] if s not in ("<<", ">>")] + ["swap" if 2 * n == w else "rotl"]
            return "rotl(%s, %d)" % (base, n), True
    if op in ("or", "xor", "add") and "0" in (x[0], y[0]):
        return y if x[0] == "0" else x          # 0 | v is v (accumulators start at zero)
    if op in ("packs", "packus") and lane in ("per 16b", "per 32b"):
        # narrow two vectors into one, every lane clamped: pack_i8(a, b) for packs_epi16
        half = 8 if lane == "per 16b" else 16
        lo, hi = (-(1 << (half - 1)), (1 << (half - 1)) - 1) if op == "packs" else (0, (1 << half) - 1)
        syms = lanes.setdefault((lane, reg), [])
        if "clamp %d..%d" % (lo, hi) not in syms:
            syms.append("clamp %d..%d" % (lo, hi))
        return "pack_%s%d(%s, %s)" % ("i" if op == "packs" else "u", half, x[0], y[0]), True
    if op in _INFIX:
        sym = _INFIX[op]
        txt = "%s %s %s" % (p(x, sym, True), sym, p(y, sym))
    elif op == "andnot":
        sym, txt = "&~", "~%s & %s" % (p(x), p(y, "&"))
    elif op in ("cmpeq", "cmpgt"):
        sym, txt = _VEC_OP[op], "%s %s %s ? ~0 : 0" % (p(x), _VEC_OP[op], p(y))
    elif op == "mulhi":
        sym, txt, atomic = "hi*", T("hi(%s * %s)", "高半(%s * %s)") % (p(x), p(y)), True
    else:                                   # min/max/avg/shuffle/unpack/blend
        sym = T(_VEC_OP[op], _VEC_FN_ZH.get(_VEC_OP[op], _VEC_OP[op]))
        txt, atomic = "%s(%s)" % (sym, ", ".join(t[0] for t in a)), True
    if op in ("sra", "srai"):
        lane = "signed " + lane
    syms = lanes.setdefault((lane, reg), [])
    if sym not in syms:
        syms.append(sym)
    return txt, atomic


def _shuffle_text(h, a):
    """Spell out the lane selection of a shuffle with a constant immediate."""
    m = re.match(r"mm(?:256|512)?_shuffle(lo|hi)?_(epi32|epi16|ps|pd)$", h)
    if not m or len(a) < 2:
        return None
    imm = a[-1][0]
    try:
        imm = int(imm, 0) if not imm.endswith("u") else int(imm[:-1], 0)
    except ValueError:
        return None
    ix = lambda t: t[0] if t[1] and not t[0].startswith(("*", "&", "-", "~")) else "(%s)" % t[0]
    if m.group(1):                                  # shufflelo/hi_epi16: 4 of 8 words
        off = 0 if m.group(1) == "lo" else 4
        order = " ".join(str(off + ((imm >> (2 * i)) & 3)) for i in range(4))
        return "%s(%s, [%s])" % (T("shuffle " + m.group(1), "重排" + ("低半" if off == 0 else "高半")),
                                 a[0][0], order)
    if m.group(2) == "epi32":
        src = ix(a[0])
        idx = [(imm >> (2 * i)) & 3 for i in range(4)]
        if len(set(idx)) == 1:
            return "splat(%s[%d])" % (src, idx[0])
        if len(src) > 16:                           # do not spell a long source out 4 times
            return "%s(%s, [%s])" % (T("shuffle", "重排"), a[0][0], " ".join(map(str, idx)))
        return "{%s}" % ", ".join("%s[%d]" % (src, i) for i in idx)
    if m.group(2) == "ps" and len(a) >= 3:
        x, y = ix(a[0]), ix(a[1])
        idx = [(imm >> (2 * i)) & 3 for i in range(4)]
        if len(x) + len(y) > 32:
            return "%s(%s, %s, [%d %d | %d %d])" % (T("shuffle", "重排"), a[0][0], a[1][0], *idx)
        return "{%s[%d], %s[%d], %s[%d], %s[%d]}" % (x, idx[0], x, idx[1], y, idx[2], y, idx[3])
    if m.group(2) == "pd" and len(a) >= 3:
        return "{%s[%d], %s[%d]}" % (ix(a[0]), imm & 1, ix(a[1]), (imm >> 1) & 1)
    return None


def _vec_render(prog, x, used, lanes, depth=0):
    """Operand text with nested MMX/SSE intrinsic calls folded into one infix
    expression, e.g. `v7 & (((*v5 ^ v3) + v4) >> 3)`. Folded calls go into `used`
    so they do not get a note of their own."""
    y = _strip_casts(x)
    if depth < 32 and y.op == "call" and y.x is not None and y.x.op == "helper":
        sub_used, sub_lanes = set(), {}
        sub = [_vec_render(prog, a, sub_used, sub_lanes, depth + 1) for a in y.args]
        r = _vec_text((y.x.helper or "").lstrip("_"), sub, sub_lanes)
        if r is not None:
            used.update(sub_used)
            used.add(y.uid)
            for k, v in sub_lanes.items():
                lanes.setdefault(k, []).extend(s for s in v if s not in lanes.get(k, []))
            return r
    t = _vec_operand(_arg_text(prog, x))
    return t, " " not in t


def _lane_tail(lanes):
    """Plain-language conditions after the expression, e.g. `(+ per byte, no carry
    between bytes)`. Bitwise operators and lanes as wide as the register say
    nothing worth a note, so they get none."""
    parts = []
    groups = []
    for (lane, reg), syms in lanes.items():
        signed = lane.startswith("signed ")
        base = lane[7:] if signed else lane
        bits, en, zh = _LANE_UNIT.get(base, (0, base, base))
        syms = [s for s in syms if s not in _BITWISE_SYMS]
        if syms and (bits < reg or base.startswith("per f")):
            groups.append((signed, base, bits, en, zh, syms))
    for signed, base, bits, en, zh, syms in groups:
        for s in [s for s in syms if s.startswith("clamp ")]:
            parts.append(T("each %s clamped to %s" % (en, s[6:]), "每个 %s饱和到 %s" % (zh, s[6:])))
        syms = [s for s in syms if not s.startswith("clamp ")]
        if not syms:
            continue
        if "swap" in syms:
            parts.append(T("swaps the two bytes of every 16-bit lane", "每个 16 位内交换两个字节") if bits == 16
                         else T("swaps the two halves of every %s" % en, "每个 %s 内交换高低两半" % zh))
            syms = [s for s in syms if s != "swap"]
            if not syms:
                continue
        if len(groups) == 1:
            # a named operation (min, interleave lo, ...) is already in the expression
            syms = [s for s in syms if not re.match(r"^[^\W\d]", s)] or [""]
        ops = ((T("signed ", "有符号 ") if signed else "") + " ".join(syms)).strip()
        zu = "%s%s%s" % (" " if zh[:1].isascii() else "", zh, " " if zh[-1:].isascii() else "")
        txt = T(("%s per %s" % (ops, en)).strip(), ("%s 按%s分别算" % (ops, zu)).strip())
        if "+" in syms or "-" in syms:
            txt += T(", no carry between %ss" % ("byte" if bits == 8 else "lane"), ", 互不进位")
        parts.append(txt)
    return " (%s)" % "; ".join(parts) if parts else ""


def _vec_call_note(prog, e, used):
    """Note for an intrinsic call `e`, or None. Nested foldable intrinsics are
    rendered inline and recorded in `used`."""
    h = (e.x.helper or "").lstrip("_")
    sub_used, lanes = set(), {}
    sub = [_vec_render(prog, a, sub_used, lanes) for a in e.args]
    note = None
    if _vec_op(h):
        r = _vec_text(h, sub, lanes)
        if r is not None:
            if r[0] == "0" and len(sub) >= 2 and sub[0][0] == sub[1][0]:
                note = OPX + "%s ^ %s = 0 (%s)" % (sub[0][0], sub[1][0], T("zeroing", "清零"))
            else:
                note = OPX + _clip(r[0]) + _lane_tail(lanes)
    if note is None:
        note = _intrin_note(e.x.helper, [t for t, _ in sub])
    if note:
        used.update(sub_used)
    return note
