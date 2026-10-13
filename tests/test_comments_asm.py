"""Comment bookkeeping and disassembly math."""
from ibr.core.asm_math import insn_math
from ibr.core.comments import _strip_managed


def test_strip_keeps_user_text():
    assert _strip_managed("libc: allocate heap") == ""
    assert _strip_managed("libc: allocate heap\nmy note") == "my note"
    assert _strip_managed("op: eax = 0  | key loop") == "key loop"
    # a `  | ` inside a quoted string is part of the note, not a join
    assert _strip_managed('libc: printf "a  | b"  | mine') == "mine"
    assert _strip_managed("my own  | text") == "my own  | text"


def test_x86_math():
    assert insn_math("xor", "eax", "eax", "", "x86_64") == "eax = 0"
    assert insn_math("add", "rax", "rbx", "", "x86_64") == "rax = rax + rbx"
    assert insn_math("lea", "rax", "[rbx+rcx*4+8]", "", "x86_64") == "rax = rbx+rcx*4+8"
    assert insn_math("imul", "eax", "", "7", "i386") == "eax = eax * 7"
    assert insn_math("mov", "eax", "ebx", "", "x86_64") is None


def test_three_operand_math():
    assert insn_math("ADD", "X0", "X2", "X20", "aarch64") == "X0 = X2 + X20"
    assert insn_math("add", "X0", "X1", "", "aarch64") == "X0 = X0 + X1"
    assert insn_math("bic", "W0", "W1", "W2", "aarch64") == "W0 = W1 & ~W2"
    assert insn_math("ADD", "X0", "X1", "X2,LSL#3", "aarch64") == "X0 = X1 + (X2 << 3)"
    assert insn_math("addiu", "$sp", "-0x20", "", "mipsb") == "$sp = $sp - 0x20"
    assert insn_math("xor", "$v0", "$a0", "$a0", "mipsl") == "$v0 = 0"
