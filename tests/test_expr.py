"""Expressions as C and as math (analysis/expr.py) on hand-built statement trees."""
import itertools

from ibr.analysis.dataflow import analyze
from ibr.analysis.expr import Terms, _mtext, _lane_tag, _wrap, c_text
from ibr.core.i18n import set_lang
from ibr.ports import Tree

_ids = itertools.count(1)


def var(n, ptr=False, mem=False):
    return Tree("var", var=n, name="v%d" % n, ptr=ptr, mem=mem)


def num(v, text=""):
    return Tree("num", value=v, text=text)


def s_(t):
    return Tree("str", string=t, index=next(_ids))


def ref(x):
    return Tree("ref", x=x)


def asg(x, y, op=""):
    return Tree("asg", x=x, y=y, op=op)


def call(name, *args):
    return Tree("call", x=Tree("obj", name=name, obj_ea=0x1000 + len(name)), args=list(args),
                index=next(_ids))


def helper(name, *args):
    return Tree("call", x=Tree("helper", name=name), args=list(args), index=next(_ids))


def bin_(op, x, y):
    return Tree("bin", op=op, x=x, y=y)


def st(e):
    return Tree("expr", x=e)


def block(*body):
    return Tree("block", body=list(body))


def math(e):
    """The term of e, read at the statement that holds it."""
    an = analyze(block(st(e)))
    s = next(s for s in an.sites if s.expr is not None and s.role != "join")
    m = Terms(an).norm(e, s)
    return _mtext(m) + (_lane_tag(m) if hasattr(m, "lane") else "")


def setup_module():
    set_lang("en")


def test_arithmetic_is_written_as_math():
    assert math(asg(var(2), bin_("+", bin_("*", var(1), num(3)), num(7)))) == "v1 * 3 + 7"
    assert math(asg(var(2), bin_("*", bin_("+", var(1), num(3)), num(7)))) == "(v1 + 3) * 7"


def test_a_shift_pair_is_a_rotation():
    e = asg(var(1), bin_("|", bin_("<<", var(0), num(3)), bin_(">>", var(0), num(29, "29"))))
    assert math(e) == "v0 <<< 3"
    # not a rotation when the widths do not add up
    e = asg(var(1), bin_("|", bin_("<<", var(0), num(3)), bin_(">>", var(0), num(20, "20"))))
    assert math(e) == "v0 << 3 | v0 >> 20"


def test_intrinsics_are_folded_with_their_lane_width():
    assert math(asg(var(2), helper("_m_pxor", var(0), var(1)))) == "v0 ^ v1"
    assert math(asg(var(2), helper("_m_paddb", var(0), var(1)))) == "v0 + v1 (per byte)"
    assert math(asg(var(2), helper("_m_pxor", var(0), var(0)))) == "0"


def test_printf_shows_only_what_its_format_prints():
    e = call("__printf_chk", num(2), s_("size %d\n"), var(3), var(4), var(5))
    assert c_text(e) == '__printf_chk("size %d\\n", v3)'


def test_a_long_condition_breaks_before_and_or():
    inner = " && ".join("v%d == 0x%X" % (i, 0x1000 + i) for i in range(6))
    lines = _wrap("if ( ", inner, " )")
    assert len(lines) == 6 and lines[0] == "if ( v0 == 0x1000" and lines[-1] == "  && v5 == 0x1005 )"
