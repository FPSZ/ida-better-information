"""The program flowchart (analysis/flowchart.py, core/chartlayout.py) on hand-built trees."""
import itertools
import random

from ibr.analysis.dataflow import analyze, var_flow
from ibr.analysis.flowchart import build_chart, lit, marks
from ibr.core import chartlayout as cl
from ibr.core.i18n import set_lang
from ibr.ports import Tree

_ids = itertools.count(1)


def var(n, ptr=False, mem=False):
    return Tree("var", var=n, name="v%d" % n, ptr=ptr, mem=mem, index=next(_ids))


def num(v):
    return Tree("num", value=v, text=str(v))


def s_(t):
    return Tree("str", string=t, index=next(_ids))


def asg(x, y, op=""):
    return Tree("asg", x=x, y=y, op=op)


def call(name, *args, lib=True):
    return Tree("call", x=Tree("obj", name=name, obj_ea=0x1000 + len(name), lib=lib), args=list(args),
                index=next(_ids))


def helper(name, *args):
    return Tree("call", x=Tree("helper", name=name), args=list(args), index=next(_ids))


def bin_(op, x, y):
    return Tree("bin", op=op, x=x, y=y)


def st(e):
    return Tree("expr", x=e, ea=next(_ids))


def block(*body):
    return Tree("block", body=list(body))


def iff(c, then, other=None):
    return Tree("if", x=c, body=[then] + ([other] if other is not None else []), ea=next(_ids))


def ret(e=None):
    return Tree("return", x=e, ea=next(_ids))


def setup_module():
    set_lang("en")


def texts(chart):
    return [(chart.boxes[l.box].kind, l.text) for l in chart.lines]


def overlaps(pos, sizes):
    bad = []
    ks = list(pos)
    for i, a in enumerate(ks):
        for b in ks[i + 1:]:
            (x1, y1), (x2, y2) = pos[a], pos[b]
            (w1, h1), (w2, h2) = sizes[a], sizes[b]
            if x1 < x2 + w2 - 0.5 and x2 < x1 + w1 - 0.5 and y1 < y2 + h2 - 0.5 and y2 < y1 + h1 - 0.5:
                bad.append((a, b))
    return bad


def sizes_of(chart):
    out = {}
    for b in chart.boxes:
        w = max(len(t) for l in b.lines for t in l.text.split("\n")) * 8 + 24
        h = sum(len(l.text.split("\n")) for l in b.lines) * 18 + 12
        if b.kind in ("decision", "switch"):
            w, h = w * 1.6, h + 30
        out[b.id] = (w, h)
    return out


def butterfly():
    """The shape of Butterfly's encoder: read a file, a guard, a do-while over 8-byte words
    with a break, a check that prints."""
    v18, v19, v28 = var(18, ptr=True), var(19, ptr=True), var(28, ptr=True)
    body = block(
        st(asg(var(18, ptr=True), call("sub_412620", bin_("+", var(7), num(8)), lib=False))),
        st(asg(var(19, ptr=True), v18)),
        st(asg(var(20), call("fread", var(18, ptr=True), num(1), var(7), var(16)))),
        st(call("fclose", var(16))),
        iff(bin_("!=", var(7), var(20)), block(st(call("puts", s_("Error"))), ret(num(1)))),
        st(asg(var(28, ptr=True), var(19, ptr=True))),
        Tree("do", x=bin_("!=", var(28, ptr=True), var(21, ptr=True)), ea=next(_ids), body=[block(
            st(asg(var(29), helper("_m_pxor", Tree("ptr", x=var(28, ptr=True)), var(42)))),
            st(asg(Tree("ptr", x=var(28, ptr=True)), helper("_m_paddb", var(29), var(42)))),
            iff(bin_("==", var(28, ptr=True), var(22, ptr=True)), Tree("break")),
            st(Tree("inc", op="pre", x=var(28, ptr=True))),
        )]),
        st(helper("_m_empty")),
        iff(call("sub_401CA0", var(11), var(19, ptr=True), var(7), lib=False),
            block(st(call("printf", s_("Successfully encoded to: %s\n"), var(11), var(31))),
                  st(call("snprintf", var(42, mem=True), num(256), s_("%s.key"), var(11))))),
        ret(num(0)),
    )
    return body, v28


def test_statements_in_order_with_math_and_shapes():
    body, _ = butterfly()
    chart = build_chart(body, analyze(body), title="f()")
    assert texts(chart) == [
        ("start", "f()"),
        ("call", "v18 = sub_412620(v7 + 8)"),
        ("process", "v19 = v18"),
        ("io", "v20 = fread(v18, 1, v7, v16)"),
        ("decision", "v7 != v20"),
        ("io", 'puts("Error")'),
        ("return", "return 1"),
        ("process", "v28 = v19"),
        ("decision", "v28 != v21"),               # a do-while's condition: made before its body
        ("process", "v29 = *v28 ^ v42"),
        ("process", "*v28 = v29 + v42 (per byte)"),
        ("decision", "v28 == v22"),
        ("process", "++v28"),
        ("decision", "sub_401CA0(v11, v19, v7)"),
        ("io", 'printf("Successfully encoded to: %s\\n", v11)'),
        ("process", 'snprintf(v42, 256, "%s.key", v11)'),
        ("return", "return 0"),
        ("end", "End"),
    ]
    # the two steps of the loop body share one box; fclose and _m_empty are not drawn
    loop = [b for b in chart.boxes if b.kind == "process" and len(b.lines) == 2]
    assert len(loop) == 1


def test_a_pointer_shows_where_it_points():
    body, v28 = butterfly()
    an = analyze(body)
    chart = build_chart(body, an)
    on = {chart.lines[i].text for i in lit(chart, an, var_flow(body, var=28, an=an), 28)}
    for t in ("v28 = v19", "v19 = v18", "v18 = sub_412620(v7 + 8)",      # where it points
              "v20 = fread(v18, 1, v7, v16)",                             # what is there
              "v29 = *v28 ^ v42", "*v28 = v29 + v42 (per byte)", "++v28",
              "v28 != v21", "v28 == v22",
              "sub_401CA0(v11, v19, v7)",                                 # where it goes
              'printf("Successfully encoded to: %s\\n", v11)'):           # what that prints
        assert t in on, t
    assert 'puts("Error")' not in on
    assert 'snprintf(v42, 256, "%s.key", v11)' not in on      # writes a buffer: not a print


def by_line(chart, m):
    return {chart.lines[lid].text: kinds for lid, kinds in m.items()}


def test_names_computed_from_it_and_what_it_comes_from():
    """An in-place encryption: buf = malloc; fread(buf); p = buf; do { t = *p ^ k;
    *p = t + k; ++p } while (p != end); puts(buf). Names are marked line by line. Following
    the key k marks what is computed from it: t, the buffer written through p, read by puts.
    Following t marks, on its own line and above, what makes it (k, the buffer p points at,
    filled from the file), and below what it makes; the buffer written back below is not a
    source, though the next pass reads it."""
    p, buf = (lambda: var(4, ptr=True)), (lambda: var(1, ptr=True))
    body = block(
        st(asg(buf(), call("malloc", var(2)))),
        st(call("fread", buf(), num(1), var(2), var(6, ptr=True))),
        st(asg(var(3), num(0x5A))),
        st(asg(p(), buf())),
        Tree("do", x=bin_("!=", p(), var(7, ptr=True)), ea=next(_ids), body=[block(
            st(asg(var(5), bin_("^", Tree("ptr", x=p()), var(3)))),
            st(asg(Tree("ptr", x=p()), bin_("+", var(5), var(3)))),
            st(Tree("inc", op="pre", x=p())),
        )]),
        st(call("puts", buf())),
    )
    an = analyze(body)
    chart = build_chart(body, an)

    def around(n):
        return by_line(chart, marks(chart, an, var_flow(body, var=n, an=an, may=True), n))
    assert around(3) == {"v5 = *v4 ^ v3": {"v5": "into"},
                         "*v4 = v5 + v3": {"v4": "into", "v5": "into"},
                         "puts(v1)": {"v1": "into"}}
    assert around(5) == {"fread(v1, 1, v2, v6)": {"v1": "from", "v6": "from"},
                         "v3 = 90": {"v3": "from"},
                         "v5 = *v4 ^ v3": {"v4": "from", "v3": "from"},
                         "*v4 = v5 + v3": {"v4": "into"},
                         "puts(v1)": {"v1": "into"}}
    # the followed pointer's memory: t is made from it, then makes it again
    assert around(4)["v5 = *v4 ^ v3"] == {"v5": "both", "v3": "from"}


def test_a_source_used_again_later_is_not_marked_there():
    """As in Butterfly: the sources of v29 appear again after it (the loop's check, a call,
    a print). There they make nothing that v29 is made from: not marked. The call that reads
    the buffer v29 went into marks that buffer's pointer as where it goes."""
    P = lambda n: var(n, ptr=True)
    body = block(
        st(asg(P(19), call("malloc", var(7)))),
        st(call("fread", P(19), num(1), var(7), P(6))),
        st(asg(var(3), num(0x5A))),
        st(asg(P(28), P(19))),
        Tree("do", x=bin_("!=", P(28), P(8)), ea=next(_ids), body=[block(
            st(asg(var(29), bin_("^", Tree("ptr", x=P(28)), var(3)))),
            st(asg(Tree("ptr", x=P(28)), bin_("+", var(29), var(3)))),
            st(Tree("inc", op="pre", x=P(28))),
        )]),
        st(call("check", P(19), var(7), lib=False)),
        st(call("printf", s_("%d %d"), var(7), var(3))),
    )
    an = analyze(body)
    chart = build_chart(body, an)
    got = by_line(chart, marks(chart, an, var_flow(body, var=29, an=an, may=True), 29))
    assert got == {"fread(v19, 1, v7, v6)": {"v19": "from", "v6": "from"},
                   "v3 = 90": {"v3": "from"},
                   "v29 = *v28 ^ v3": {"v28": "from", "v3": "from"},
                   "*v28 = v29 + v3": {"v28": "into"},
                   "check(v19, v7)": {"v19": "into"}}


def test_a_count_does_not_make_what_a_call_fills():
    """fread(v18, 1, v7, f): the buffer comes from the file, not from the count v7."""
    body = block(
        st(asg(var(18, ptr=True), call("malloc", var(7)))),
        st(asg(var(20), call("fread", var(18, ptr=True), num(1), var(7), var(16, ptr=True)))),
        st(asg(var(30), Tree("ptr", x=var(18, ptr=True)))),
        st(call("puts", var(30))),
    )
    an = analyze(body)
    chart = build_chart(body, an)
    count = by_line(chart, marks(chart, an, var_flow(body, var=7, an=an, may=True), 7))
    assert all("v30" not in m and "v18" not in m for m in count.values()), count
    data = by_line(chart, marks(chart, an, var_flow(body, var=30, an=an, may=True), 30))
    assert data == {"v20 = fread(v18, 1, v7, v16)": {"v18": "from", "v16": "from"},   # the buffer, the file
                    "v30 = *v18": {"v18": "from"}}


def test_through_unknown_calls_to_the_check_and_back_to_the_input():
    """babyre: getline(Str); memset(buf); sub_1(buf, Str); sub_2(buf, key); a loop compares
    key with the answer and prints "No" through an unnamed printf. Following buf lights the
    input it is made from and the check it ends in."""
    buf, key, ans, k = var(1, mem=True), var(2, mem=True), var(3, mem=True), var(4)
    idx = lambda a, i: Tree("idx", x=a, y=i)
    body = block(
        st(call("getline", var(5, mem=True), num(33), lib=False)),
        iff(bin_("==", call("strlen", var(5, mem=True)), num(32)), block(
            st(call("memset", var(1, mem=True), num(0), num(32))),
            st(call("sub_1", var(1, mem=True), var(5, mem=True), lib=False)),
            st(call("sub_2", var(1, mem=True), var(2, mem=True), lib=False)),
            Tree("for", init=asg(var(4), num(0)), x=bin_("<", var(4), num(32)),
                 step=Tree("inc", op="pre", x=var(4)), ea=next(_ids), body=[block(
                     iff(bin_("!=", idx(var(3, mem=True), var(4)), idx(var(2, mem=True), var(4))),
                         block(st(call("sub_3", s_("No"), lib=False)), ret(num(0)))))]),
            st(call("sub_3", s_("Yes"), lib=False)),
            ret(num(0))),
            block(st(call("sub_3", s_("Wrong length"), lib=False)), ret(num(1)))),
    )
    an = analyze(body)
    chart = build_chart(body, an)
    flow = var_flow(body, var=1, an=an, may=True)
    on = {chart.lines[i].text for i in lit(chart, an, flow, 1)}
    for t in ("getline(v5, 33)", "sub_1(v1, v5)", "sub_2(v1, v2)", "v3[v4] != v2[v4]",
              'sub_3("No")', 'sub_3("Yes")', "return 0", "strlen(v5) == 32"):
        assert t in on, t
    assert 'sub_3("Wrong length")' not in on                   # the other branch of the if


def test_layout_never_overlaps_and_the_main_line_is_straight():
    body, _ = butterfly()
    chart = build_chart(body, analyze(body))
    sizes = sizes_of(chart)
    pos, paths, (w, h) = chart.layout(sizes)
    assert overlaps(pos, sizes) == []
    centre = lambda b: pos[b][0] + sizes[b][0] / 2
    main = [b.id for b in chart.boxes if b.kind in ("start", "call") or b.lines[0].text == "v28 = v19"]
    assert len({round(centre(b)) for b in main}) == 1
    for p in paths:                               # only horizontal and vertical lines
        for (x1, y1), (x2, y2) in zip(p.pts, p.pts[1:]):
            assert abs(x1 - x2) < 0.01 or abs(y1 - y2) < 0.01
    # the error branch sits on the right of its condition, labelled "yes"
    cond = next(b for b in chart.boxes if b.lines[0].text == "v7 != v20")
    err = next(b for b in chart.boxes if b.lines[0].text == 'puts("Error")')
    assert pos[err.id][0] > pos[cond.id][0] + sizes[cond.id][0] / 2
    assert any(p.src == cond.id and p.label == "yes" and p.dst == err.id for p in paths)


def test_the_way_to_a_step():
    """A click on the success print: the way there (the main line, the loop, the check's
    yes), ending there: no error branch that returns, no check's no, nothing after it."""
    body, _ = butterfly()
    chart = build_chart(body, analyze(body))
    sizes = sizes_of(chart)
    pos, paths, _ = chart.layout(sizes)
    box = lambda t: next(b.id for b in chart.boxes if b.lines[0].text.startswith(t))
    goal, check = box('printf("Successfully'), box("sub_401CA0")
    on, lines = cl.route(paths, chart.boxes[0].id, goal, chart.jumps)
    for t in ("v18 = sub_412620", "v7 != v20", "v28 = v19", "v29 = *v28", "v28 == v22", "++v28",
              "v28 != v21", "sub_401CA0"):
        assert box(t) in on, t
    assert box('puts("Error")') not in on
    assert box("return 0") not in on                           # after it: not part of the way
    taken = {(paths[i].src, paths[i].label) for i in lines}
    assert (check, "yes") in taken and (check, "no") not in taken
    assert (box("v7 != v20"), "no") in taken and (box("v7 != v20"), "yes") not in taken


def test_a_goto_leads_to_its_label():
    body = block(st(asg(var(1), num(0))), Tree("goto", target=7),
                 Tree("expr", x=asg(var(2), num(1)), label=7, ea=next(_ids)), ret(var(2)))
    chart = build_chart(body, analyze(body))
    pos, paths, _ = chart.layout(sizes_of(chart))
    goal = next(b.id for b in chart.boxes if b.kind == "return")
    on, _ = cl.route(paths, chart.boxes[0].id, goal, chart.jumps)
    assert next(b.id for b in chart.boxes if b.lines[0].text == "v1 = 0") in on


def test_loops_go_back_on_the_left_and_out_on_the_right():
    body, _ = butterfly()
    chart = build_chart(body, analyze(body))
    sizes = sizes_of(chart)
    pos, paths, _ = chart.layout(sizes)
    cond = next(b for b in chart.boxes if b.lines[0].text == "v28 != v21")
    back = [p for p in paths if p.src == cond.id and p.label == "yes"]
    assert len(back) == 1 and min(x for x, _ in back[0].pts) < pos[cond.id][0]
    brk = next(b for b in chart.boxes if b.lines[0].text == "v28 == v22")
    out = [p for p in paths if p.src == brk.id and p.label == "yes"]
    assert len(out) == 1 and max(x for x, _ in out[0].pts) > pos[brk.id][0] + sizes[brk.id][0]


def random_body(rnd, depth=0):
    items = []
    for _ in range(rnd.randint(1, 4)):
        r = rnd.random()
        if depth < 3 and r < 0.2:
            items.append(iff(bin_("<", var(1), num(rnd.randint(0, 9))), random_body(rnd, depth + 1),
                             random_body(rnd, depth + 1) if rnd.random() < 0.5 else None))
        elif depth < 3 and r < 0.3:
            items.append(Tree("while", x=bin_("<", var(2), num(5)), body=[random_body(rnd, depth + 1)]))
        elif depth < 3 and r < 0.4:
            items.append(Tree("do", x=bin_("<", var(2), num(5)), body=[random_body(rnd, depth + 1)]))
        elif depth < 3 and r < 0.45:
            items.append(Tree("for", init=asg(var(3), num(0)), x=bin_("<", var(3), num(9)),
                              step=Tree("inc", op="post", x=var(3)), body=[random_body(rnd, depth + 1)]))
        elif depth < 3 and r < 0.5:
            cases = []
            for k in range(rnd.randint(1, 4)):
                c = random_body(rnd, depth + 1)
                if rnd.random() < 0.7:
                    c.body.append(Tree("break"))
                c.values = [k] if k else []
                cases.append(c)
            items.append(Tree("switch", x=var(4), body=cases))
        elif r < 0.55 and depth:
            items.append(Tree(rnd.choice(["break", "continue"])))
        elif r < 0.6:
            items.append(ret(num(1)))
        elif r < 0.75:
            items.append(st(call("printf", s_("x" * rnd.randint(1, 50)), var(1))))
        else:
            items.append(st(asg(var(rnd.randint(1, 5)), bin_("+", var(1), num(rnd.randint(0, 99))))))
    return block(*items)


def through(a, b, r):
    """Segment a-b (horizontal or vertical) passes through rectangle r."""
    (x1, y1), (x2, y2) = a, b
    x0, y0, x3, y3 = r
    if abs(y1 - y2) < 0.01:
        return y0 < y1 < y3 and max(min(x1, x2), x0) < min(max(x1, x2), x3)
    return x0 < x1 < x3 and max(min(y1, y2), y0) < min(max(y1, y2), y3)


def test_random_functions_never_overlap():
    rnd = random.Random(11)
    for _ in range(150):
        body = random_body(rnd)
        chart = build_chart(body, analyze(body))
        sizes = sizes_of(chart)
        pos, paths, _ = chart.layout(sizes)
        assert overlaps(pos, sizes) == []
        for p in paths:
            assert p.src is not None
            for (x1, y1), (x2, y2) in zip(p.pts, p.pts[1:]):
                assert abs(x1 - x2) < 0.01 or abs(y1 - y2) < 0.01
            for k, (x, y) in pos.items():          # no line through a shape it does not join
                if k not in (p.src, p.dst):
                    r = (x + 1, y + 1, x + sizes[k][0] - 1, y + sizes[k][1] - 1)
                    assert not any(through(a, b, r) for a, b in zip(p.pts, p.pts[1:]))


def test_a_switch_branches_from_the_left():
    cases = [block(st(asg(var(1), num(5))), Tree("break")), block(st(asg(var(1), num(6))))]
    cases[0].values, cases[1].values = [1, 2], []
    body = block(Tree("switch", x=var(4), body=cases))
    chart = build_chart(body, analyze(body))
    sizes = sizes_of(chart)
    pos, paths, _ = chart.layout(sizes)
    labels = {p.label for p in paths if p.label}
    assert {"case 1, 2", "default"} <= labels
