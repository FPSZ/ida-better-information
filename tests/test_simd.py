"""Intrinsic folding: nested MMX/SSE calls read as one plain expression."""
from fakes import FakeProgram, hcall, num, other, preorder, var

from ibr.core.notes import collect_notes
from ibr.core.simd import _clip, _operand


def notes(e):
    by_ea, by_idx = collect_notes(FakeProgram(), preorder(e))
    return by_idx


def test_rotate_then_bytewise_add():
    # the README example from Butterfly
    e = hcall("_m_paddb", hcall("_m_por", hcall("_m_psllqi", var("v30"), num(1)),
                                hcall("_m_psrlqi", var("v30"), num(0x3F))), other("v42[0]"))
    by_idx = notes(e)
    assert list(by_idx.values()) == ["op: rotl(v30, 1) + v42[0] (+ per byte, no carry between bytes)"]
    assert list(by_idx) == [e.index]            # the folded inner calls get no note of their own


def test_same_operator_chain_is_flat():
    v39, v29 = var("v39"), var("v29")
    e = hcall("_mm_add_epi8", hcall("_mm_add_epi8", hcall("_mm_add_epi8", v39, v39), v39), v29)
    assert list(notes(e).values()) == ["op: v39 + v39 + v39 + v29 (+ per byte, no carry between bytes)"]


def test_xor_with_itself_is_zeroing():
    e = hcall("_mm_xor_si128", var("v1"), var("v1"))
    assert list(notes(e).values()) == ["op: v1 ^ v1 = 0 (zeroing)"]


def test_pack_names_the_target_type():
    e = hcall("_mm_packus_epi16", var("a"), var("b"))
    assert list(notes(e).values()) == ["op: pack_u8(a, b) (each 16-bit lane clamped to 0..255)"]


def test_bitwise_on_whole_register_has_no_lane_rule():
    e = hcall("_mm_or_si128", var("a"), var("b"))
    assert list(notes(e).values()) == ["op: a | b"]


def test_operand_brackets_only_when_needed():
    assert _operand(("a | b", False), "|", True) == "a | b"
    assert _operand(("a & b", False), "|") == "(a & b)"
    assert _operand(("*(__m128i *)((char *)&a17 + v40)", False), "&") == "*(__m128i *)((char *)&a17 + v40)"
    assert _operand(("a - b", False), "-", True) == "a - b"
    assert _operand(("a - b", False), "-") == "(a - b)"


def test_clip_cuts_at_an_operator_and_stays_balanced():
    chain = " | ".join("(*(a3 + %d) & v23[%d])" % (2 * i, 2 * i + 7) for i in range(12))
    out = _clip(chain)
    assert len(out) <= 140 and out.endswith("| ...")
    assert out.count("(") == out.count(")")
    pk = "pack_i8(" + ", ".join("*((char *)this + %d) == -1 ? ~0 : 0" % (16 * i) for i in range(6)) + ")"
    out = _clip(pk)
    assert out.endswith("...)") and out.count("(") == out.count(")")
