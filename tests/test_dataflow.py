"""Data flow of one variable (analysis/dataflow.py) on hand-built statement trees."""
import itertools

from ibr.analysis.dataflow import var_flow
from ibr.ports import Tree

_ids = itertools.count(1)


def var(n, ptr=False, mem=False):
    return Tree("var", var=n, name="v%d" % n, ptr=ptr, mem=mem)


def num(v):
    return Tree("num", value=v)


def asg(x, y, op=""):
    return Tree("asg", x=x, y=y, op=op)


def call(name, *args, ptr=False):
    return Tree("call", x=Tree("obj", name=name, obj_ea=0x1000 + len(name)), args=list(args),
                ptr=ptr, index=next(_ids))


def bin_(op, x, y):
    return Tree("bin", op=op, x=x, y=y)


def deref(p):
    return Tree("ptr", x=p)


def st(e, label=None):
    return Tree("expr", x=e, label=label)


def block(*body):
    return Tree("block", body=list(body))


def kept(flow):
    """{statement: role} by the statement objects themselves."""
    return {s.stmt: flow.role[s.id] for s in flow.sites if s.role != "join"}


def test_a_reused_variable_stays_apart():
    a = st(asg(var(0), call("atoi", Tree("str", string="7", index=next(_ids)))))
    b = st(asg(var(1), bin_("^", var(0), num(5))))
    c = st(asg(var(0), num(3)))
    d = st(asg(var(2), bin_("*", var(0), num(2))))
    got = kept(var_flow(block(a, b, c, d), var=1))
    assert got == {a: "src", b: "self"}


def test_memory_through_a_copied_pointer():
    m = st(asg(var(0, ptr=True), call("malloc", num(16), ptr=True)))
    r = st(call("read", num(0), var(0, ptr=True), num(16)))
    q = st(asg(var(1, ptr=True), var(0, ptr=True)))
    x = st(asg(var(2), bin_("^", deref(var(1, ptr=True)), num(0x11))))
    n = st(asg(var(3), num(5)))
    got = kept(var_flow(block(m, r, q, x, n), var=2))
    assert got == {m: "src", r: "src", x: "self"}       # the pointer copy itself is not data


def test_loop_body_and_where_the_buffer_goes():
    buf, p, f = var(0, ptr=True), var(1, ptr=True), var(5, ptr=True)
    m = st(asg(buf, call("malloc", num(64), ptr=True)))
    rd = st(call("fread", buf, num(1), num(64), f))
    cp = st(asg(p, buf))
    key = st(asg(var(2), num(0x1234)))
    x = st(asg(var(3), bin_("^", deref(p), var(2))))
    y = st(asg(var(4), bin_("<<", var(3), num(1))))
    store = st(asg(deref(p), bin_("+", var(4), var(2))))
    inc = st(Tree("inc", x=p, op="pre"))
    loop = Tree("do", body=[block(x, y, store, inc)], x=bin_("!=", p, var(6, ptr=True)))
    out = st(call("write", num(1), buf, num(64)))
    done = st(call("puts", Tree("str", string="done", index=next(_ids))))
    flow = var_flow(block(m, rd, cp, key, loop, out, done), var=3)
    got = kept(flow)
    assert got[x] == "self" and got[y] == "self" and got[store] == "dst" and got[out] == "dst"
    assert got[rd] == "src" and got[key] == "src" and got[m] == "src"
    assert cp not in got and inc not in got and done not in got
    assert not flow.may
    # from v4's side, v3 is where it comes from, although the loop also carries v4 into v3
    got = kept(var_flow(block(m, rd, cp, key, loop, out, done), var=4))
    assert got[x] == "src" and got[y] == "self" and got[store] == "self" and got[out] == "dst"


def test_both_writes_reach_after_a_break():
    one = st(asg(var(0), num(1)))
    brk = Tree("if", x=var(9), body=[Tree("break")])
    two = st(asg(var(0), num(2)))
    loop = Tree("while", x=var(8), body=[block(brk, two)])
    use = st(asg(var(1), var(0)))
    got = kept(var_flow(block(one, loop, use), var=1))
    assert got == {one: "src", two: "src", use: "self"}


def test_goto_and_dead_code():
    one = st(asg(var(0), num(1)))
    jump = Tree("goto", target=7)
    two = st(asg(var(0), num(2)))                        # dead: right after the goto
    use = st(asg(var(1), var(0)), label=7)
    got = kept(var_flow(block(one, jump, two, use), var=1))
    assert got == {one: "src", use: "self"}


def test_unknown_call_may_change_memory():
    b = var(0, mem=True)
    init = st(call("memset", b, num(0), num(16)))
    unk = st(call("sub_401000", b))
    use = st(asg(var(1), Tree("idx", x=b, y=num(3))))
    flow = var_flow(block(init, unk, use), var=1)
    got = kept(flow)
    assert got == {init: "src", unk: "src", use: "self"} and flow.may


def test_a_variable_with_no_writes_shows_where_it_goes():
    use = st(asg(var(1), bin_("+", var(0), num(1))))
    other = st(asg(var(2), num(4)))
    got = kept(var_flow(block(use, other), var=0))
    assert got == {use: "self"}


def test_graph_keeps_layers_clean():
    from ibr.analysis.dataflow import Flow, flow_graph

    class S:
        def __init__(self, i):
            self.id, self.role = i, "stmt"
    sites = [S(i) for i in range(4)]
    # 0 -> 1 -> 2 and a direct 0 -> 2; 3 -> 1 goes back in program order (a loop)
    flow = Flow(sites, [(0, 1), (1, 2), (0, 2), (3, 1), (2, 3)], {}, False, False)
    ids, edges = flow_graph(flow)
    assert ids == [0, 1, 2, 3] and edges == [(0, 1), (1, 2), (2, 3)]
