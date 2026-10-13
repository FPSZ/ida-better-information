"""One-line math for arithmetic and vector instructions in the disassembly."""
import re


_BIN = {"add":"+", "sub":"-", "and":"&", "or":"|", "xor":"^", "imul":"*",
        "shl":"<<", "sal":"<<", "shr":">>", "sar":">>(signed)",
        "rol":"<<<(rot)", "ror":">>>(rot)"}
_CARRY = {"adc":"%s + %s + CF", "sbb":"%s - %s - CF"}
# ARM/AArch64/MIPS: "op d, a, b" is d = a OP b; IDA prints "op d, b" when a == d
_RISC_BIN = {"add":"+", "adds":"+", "addu":"+", "addi":"+", "addiu":"+", "daddu":"+", "daddiu":"+",
             "sub":"-", "subs":"-", "subu":"-", "dsubu":"-",
             "and":"&", "ands":"&", "andi":"&", "orr":"|", "or":"|", "ori":"|",
             "eor":"^", "xor":"^", "xori":"^", "mul":"*", "udiv":"/", "sdiv":"/(signed)",
             "lsl":"<<", "sll":"<<", "sllv":"<<", "lsr":">>", "srl":">>", "srlv":">>",
             "asr":">>(signed)", "sra":">>(signed)", "srav":">>(signed)", "ror":">>>(rot)"}
_RISC_FMT = {"bic":"%s & ~%s", "bics":"%s & ~%s", "orn":"%s | ~%s", "eon":"%s ^ ~%s",
             "nor":"~(%s | %s)"}
_RISC_UN = {"neg":"-%s", "negs":"-%s", "negu":"-%s", "mvn":"~%s", "not":"~%s"}
_SHIFT_OP = re.compile(r"^(\w+),\s*(LSL|LSR|ASR|ROR)\s*#?(\w+)$", re.I)
_SHIFT_SYM = {"lsl":"<<", "lsr":">>", "asr":">>(signed)", "ror":">>>(rot)"}
_UN = {"not":"~{d}", "neg":"-{d}", "inc":"{d} + 1", "dec":"{d} - 1"}
_VEC = {"pxor":("^",""), "pand":("&",""), "por":("|",""), "pandn":("andnot",""),
        "paddb":("+","per byte"), "paddw":("+","per 16b"), "paddd":("+","per 32b"), "paddq":("+","per 64b"),
        "psubb":("-","per byte"), "psubw":("-","per 16b"), "psubd":("-","per 32b"), "psubq":("-","per 64b"),
        "pmullw":("*","per 16b"), "pmulld":("*","per 32b"), "pmuludq":("*","per 32->64b"),
        "psllw":("<<","per 16b"), "pslld":("<<","per 32b"), "psllq":("<<","per 64b"),
        "psrlw":(">>","per 16b"), "psrld":(">>","per 32b"), "psrlq":(">>","per 64b"),
        "psraw":(">>(signed)","per 16b"), "psrad":(">>(signed)","per 32b")}
_FP = {"addss":"+","addsd":"+","subss":"-","subsd":"-","mulss":"*","mulsd":"*","divss":"/","divsd":"/"}


def _risc_opnd(o):
    o = o[1:] if o.startswith("#") else o
    sh = _SHIFT_OP.match(o)
    if sh:
        return "(%s %s %s)" % (sh.group(1), _SHIFT_SYM[sh.group(2).lower()], sh.group(3))
    return o


def _risc_math(m, d, s, t):
    if not s:
        return None
    s, t = _risc_opnd(s), _risc_opnd(t)
    if m in _RISC_UN and not t:
        return "%s = %s" % (d, _RISC_UN[m] % s)
    a, b = (s, t) if t else (d, s)
    if m in _RISC_FMT:
        return "%s = %s" % (d, _RISC_FMT[m] % (a, b))
    if m in _RISC_BIN:
        if m in ("eor", "xor") and a == b:
            return "%s = 0" % d
        sym = _RISC_BIN[m]
        if sym in "+-" and re.match(r"^-(0x)?[0-9A-F]+$", b, re.I):    # addiu $sp, -0x20
            sym, b = "-+"[sym == "-"], b[1:]
        return "%s = %s %s %s" % (d, a, sym, b)
    return None


def insn_math(m, d, s, t, arch):
    """`d = ...` for one instruction (mnemonic m, operands d, s, t as printed), or None."""
    m = (m or "").lower()
    if not m:
        return None
    if not d:
        return None
    arch = arch or ""
    if arch.startswith("mips") or arch in ("arm", "aarch64"):
        return _risc_math(m, d, s, t)
    if arch not in ("x86_64", "i386"):
        return None
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
    if m in _UN:
        return "%s = %s" % (d, _UN[m].format(d=d))
    if m == "imul" and t:
        return "%s = %s * %s" % (d, s or d, t)    # IDA hides the source when it is d
    if not s:
        return None
    if m in _CARRY:
        return "%s = %s" % (d, _CARRY[m] % (d, s))
    if m in _BIN:
        if m == "xor" and d == s:
            return "%s = 0" % d
        return "%s = %s %s %s" % (d, d, _BIN[m], s)
    if m == "lea":
        # lea computes an address: [base+index*k+disp] -> base+index*k+disp, sym -> &sym
        inner = re.sub(r"^\w+ ptr ", "", s)
        inner = re.sub(r"^\w+:", "", inner)
        if inner.startswith("[") and inner.endswith("]"):
            return "%s = %s" % (d, inner[1:-1])
        disp = re.match(r"^([^\[\]]+)\[([^\[\]]+)\]$", inner)   # ds:1[r8*4]
        if disp:
            off, idx = disp.groups()
            if not re.match(r"^-?[0-9A-F]+h?$", off, re.I):
                return "%s = &%s + %s" % (d, off, idx)
            return "%s = %s" % (d, idx if off == "0" else "%s+%s" % (idx, off))
        return "%s = &%s" % (d, inner)
    return None
