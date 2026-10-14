"""Charts opened inside calls: which shape opens which function (analysis/flowchart.py) and
where the panel goes at which zoom (core/nest.py)."""
import itertools

from ibr.analysis.dataflow import analyze
from ibr.analysis.flowchart import build_chart
from ibr.core import nest
from ibr.core.i18n import set_lang
from ibr.ports import Tree

_ids = itertools.count(1)


def var(n, ptr=False):
    return Tree("var", var=n, name="v%d" % n, ptr=ptr, index=next(_ids))


def call(name, *args, lib=False, ea=None):
    return Tree("call", x=Tree("obj", name=name, obj_ea=ea or 0x1000 + len(name), lib=lib),
                args=list(args), index=next(_ids))


def st(e):
    return Tree("expr", x=e, ea=next(_ids))


def setup_module():
    set_lang("en")


def test_the_shape_of_a_call_opens_its_function():
    """A statement, an assignment and a condition that call the program's own function open
    it, with the argument variables (&buf counts as buf); a library call does not."""
    body = Tree("block", body=[
        st(call("encrypt", var(1, ptr=True), Tree("ref", x=var(2)), Tree("num", value=8, text="8"),
                ea=0x401000)),
        st(Tree("asg", x=var(3), y=call("check", var(1, ptr=True), ea=0x402000))),
        Tree("if", x=call("verify", var(3), ea=0x403000), body=[
            Tree("block", body=[st(call("puts", Tree("str", string="ok", index=next(_ids)), lib=True))])],
             ea=next(_ids)),
    ])
    chart = build_chart(body, analyze(body))
    opens = {b.lines[0].text: b.callee().call for b in chart.boxes if b.callee() is not None}
    assert opens == {"encrypt(v1, &v2, 8)": (0x401000, (1, 2, None)),
                     "v3 = check(v1)": (0x402000, (1,)),
                     "verify(v3)": (0x403000, (3,))}, opens


def test_a_panel_hangs_under_its_call_and_holds_the_chart_at_its_width():
    x, y, w, h, s = nest.panel((100, 50, 300, 34), (1200, 3000))
    assert (x, w) == (100, 300) and y == 50 + 34 + nest.GAP     # the call's text stays in sight
    assert abs(s - (300 - 2 * nest.PAD) / 1200) < 1e-9 and abs(h - (3000 * s + 2 * nest.PAD)) < 1e-9
    # a narrow call: the panel is MIN_W wide, centred on it
    x, y, w, h, s = nest.panel((100, 50, 60, 34), (1200, 3000))
    assert w == nest.MIN_W and abs((x + w / 2) - 130) < 1e-9
    # a small chart is not drawn larger than on its own
    x, y, w, h, s = nest.panel((0, 0, 300, 34), (150, 200))
    assert s == 1.0 and w == 300 and h == 200 + 2 * nest.PAD


def test_a_call_opens_as_it_is_zoomed_into_near_the_middle():
    assert nest.opening(1.0) == 0 and nest.opening(nest.OPEN) == 0     # not at the usual zoom
    assert 0 < nest.opening((nest.OPEN + nest.FULL) / 2) < 1
    assert nest.opening(nest.FULL) == 1
    assert 1 < nest.CLOSE < nest.PREFETCH < nest.OPEN < nest.FULL     # made before shown, kept a while
    view = (1000, 800)
    assert nest.middle((400, 350, 200, 40), view)
    assert not nest.middle((900, 350, 200, 40), view)               # at the edge: not looked at
    assert not nest.middle((400, 10, 200, 40), view)
