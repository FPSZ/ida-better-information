"""Run then Undo on a fake database: the plugin's changes go, the user's stay."""
from fakes import FakeDecompiler, FakeProgram, FakeSignatures

from ibr.app.annotate import annotate_all, annotate_math
from ibr.app.signatures import apply_signatures
from ibr.app.undo import undo
from ibr.core.journal import Journal

R = {"kind": "static", "ranking": [("2.39", 1.0, 10, 10)], "confidence": "high", "arch": "x86_64",
     "best": "glibc 2.39", "toolchain": None}


def setup():
    prog = FakeProgram(names={0x10: "sub_10", 0x20: "sub_20", 0x30: "sub_30"})
    sigs = FakeSignatures(prog, ["glibc_2.39_amd64.sig"],
                          {"glibc_2.39_amd64": {0x10: "printf", 0x20: "malloc"}},
                          protos={"malloc": "void *(size_t)"})
    return prog, sigs, FakeDecompiler(), Journal()


def run(prog, sigs, journal):
    apply_signatures(prog, sigs, journal, R)
    annotate_all(prog, journal)


def test_run_twice_then_undo_restores_the_original():
    prog, sigs, dec, j = setup()
    prog.fcmts[0x10] = "my note"
    before = (dict(prog.names), dict(prog.fcmts), dict(prog.types), set(prog.lib))
    run(prog, sigs, j)
    assert prog.names[0x10] == "printf"
    assert prog.fcmts[0x10] == "libc: formatted output to stdout\nmy note"
    assert prog.types[0x20] == "void *(size_t)"
    run(prog, sigs, j)
    undo(prog, dec, j)
    assert prog.names == before[0]
    assert {k: v for k, v in prog.fcmts.items() if v} == before[1]   # empty = no comment
    assert prog.types == before[2] and prog.lib == before[3]


def test_user_edits_after_run_survive_undo():
    prog, sigs, dec, j = setup()
    run(prog, sigs, j)
    prog.names[0x20] = "my_alloc"                                   # renamed by the user
    prog.fcmts[0x10] = prog.fcmts[0x10] + "\nmine"                 # comment edited by the user
    prog.types[0x20] = "char *(int)"                                # retyped by the user
    undo(prog, dec, j)
    assert prog.names[0x20] == "my_alloc"
    assert prog.fcmts[0x10] == "mine"
    assert prog.types[0x20] == "char *(int)"
    assert prog.names[0x10] == "sub_10"


def test_guessed_type_comes_back_guessed():
    prog, sigs, dec, j = setup()
    prog.types[0x20] = "__int64 (int)"                              # IDA's guess, not a user type
    run(prog, sigs, j)
    assert 0x20 in prog.user_types
    undo(prog, dec, j)
    assert prog.types[0x20] == "__int64 (int)" and 0x20 not in prog.user_types


def test_instruction_math_keeps_user_text():
    prog, sigs, dec, j = setup()
    prog.items[0x30] = [(0x31, "xor", "eax", "eax", ""), (0x33, "mov", "eax", "1", "")]
    prog.icmts[0x31] = "key loop"
    assert annotate_math(prog, j, 0x30) == 1
    assert annotate_math(prog, j, 0x30) == 0                        # second run: nothing new
    assert prog.icmts[0x31] == "op: eax = 0  | key loop"
    assert annotate_math(prog, j, 0x99) == -1
    undo(prog, dec, j)
    assert prog.icmts[0x31] == "key loop"


def test_pseudocode_comments():
    prog, sigs, dec, j = setup()
    loc = (0x14, 74)
    dec.cmts[(0x10, loc)] = "op: x"
    j.record("pcmts", (0x10,) + loc, "", "op: x")
    dec.cmts[(0x10, (0x18, 74))] = "op: y  | mine"                 # edited by the user since
    j.record("pcmts", (0x10, 0x18, 74), "", "op: y")
    undo(prog, dec, j)
    assert dec.cmts[(0x10, loc)] == "" and dec.cmts[(0x10, (0x18, 74))] == "mine"
