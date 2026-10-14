"""What the flowchart window draws: one function as a program flowchart, the way textbooks
draw one (core/chartlayout.py places it).

Every statement in program order. Arithmetic is written as math where the notes fold it
(_m_pxor is ^, a shift pair is a rotation <<<, `(每字节)` on a per-byte add); casts and
printf's guessed extra arguments are left out. Shapes: a condition is a diamond, input and
output a parallelogram, a call of the program's own function a box with double sides, a
return a rounded end, other statements boxes (consecutive ones share a box). Statements that
say nothing about the data (fseek, fclose, free, _m_empty) are not drawn.

A line that calls one of the program's own functions remembers it (Line.call: its address and
which variable each argument is), so the window can open that function's chart inside it.

lit() picks the lines that belong to one variable: where its value comes from and goes to
(dataflow.var_flow), what makes a pointer point where it does (v28 = v19, v19 = v18,
v18 = malloc(...)), the conditions around them, and what such a condition prints or returns.
Nothing here imports IDA."""
import re

from ..core import chartlayout as cl
from ..core import simd
from ..core.i18n import T
from . import expr as ex
from .dataflow import _OWN, READS, SCANF, WRITES, _call_name, _strip

# statements that say nothing about the data
_NOISE = ex._QUIET | {"fflush"}
# where data comes in and goes out
_INPUTS = {"read", "pread", "recv", "recvfrom", "fread", "fgets", "gets", "getline", "getdelim",
           "getchar", "fgetc", "getc", "getch", "getche", "getrandom"} | set(SCANF)
_OUTPUTS = {"printf", "vprintf", "fprintf", "vfprintf", "dprintf", "puts", "fputs", "putchar",
            "putc", "fputc", "write", "send", "sendto", "fwrite", "perror", "syslog"}
_IO = re.compile(r"operator<<|operator>>|getline|istream::read|ostream::write|\bReadFile|"
                 r"\bWriteFile|\bReadConsole|\bWriteConsole|\bMessageBox|\bgets_s\b|\bscanf_s\b")


class Line:
    """One statement (or a condition, a loop's init or step) as written in the chart.
    text may hold several lines (a long call broken after a comma). site: its site in the
    analysis; ctx: the condition lines it is inside; outs: for an if, the output and return
    lines its branches start with; for a loop, those right after it (where a check loop that
    did not fail comes out: puts("Yes")). call: (address, (variable number or None for each
    argument)) of the first function of the program's own it calls, or None."""
    __slots__ = ("id", "text", "site", "ea", "box", "ctx", "outs", "loop", "call")

    def __init__(self, lid, text, site, ea, ctx, call=None):
        self.id, self.text, self.site, self.ea, self.ctx = lid, text, site, ea, ctx
        self.box, self.outs, self.loop, self.call = None, (), False, call


class Box:
    """kind: start, end, process, call, io, decision, switch, return, connector."""
    __slots__ = ("id", "kind", "lines")

    def __init__(self, bid, kind, lines):
        self.id, self.kind, self.lines = bid, kind, lines

    def callee(self):
        """The line whose call opens a function's chart here: the only one of the box's lines
        that calls a function of the program's own, or None (none, or several)."""
        calls = [line for line in self.lines if line.call is not None]
        return calls[0] if len({line.call[0] for line in calls}) == 1 else None


class Chart:
    """root: the structure for chartlayout; refs: {identifier: ("var", n), ("obj", ea) or
    ("func", ea)}; jumps: (goto's connector, its label's connector) pairs; ea: the function's
    address, when the caller sets it."""

    def __init__(self, root, boxes, lines, end, refs, jumps=()):
        self.root, self.boxes, self.lines, self.end, self.refs = root, boxes, lines, end, refs
        self.jumps = list(jumps)
        self.ea = None

    def layout(self, sizes):
        return cl.layout(self.root, sizes, end=self.end)

    def mentions(self, word):
        """The lines that name `word`, and the conditions around them."""
        rx = re.compile(r"(?<![\w])%s(?![\w])" % re.escape(word))
        out = set()
        for line in self.lines:
            if line.site is not None and rx.search(line.text):
                out.add(line.id)
                out.update(line.ctx)
        return out


# ---------------------------------------------------------------- text
def _folds(e):
    """e holds an intrinsic the notes fold into math."""
    stack = [e]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if n.kind == "call" and n.x is not None and n.x.kind == "helper":
            raw = n.x.name or ""
            h = raw.lstrip("_")
            if (simd._vec_op(h) or simd._V_LOAD.match(h) or simd._V_ZERO.match(h)
                    or simd._V_SCALAR.match(h) or re.fullmatch(r"__RO[LR]\d__", raw)):
                return True
        stack.extend((n.x, n.y, n.z))
        stack.extend(n.args)
    return False


def _tags(m):
    """The lanes of a vector expression, once at its end: ` (每字节)`."""
    tags, stack = [], [m]
    while stack:
        x = stack.pop()
        if isinstance(x, ex._Op):
            t = ex._lane_tag(x)
            if t and (x.sym, t) not in tags:
                tags.append((x.sym, t))
            stack.extend(x.args)
    if not tags:
        return ""
    if len(tags) == 1:
        return tags[0][1]
    return " (%s)" % ", ".join("%s %s" % (sym, t.strip(" ()")) for sym, t in reversed(tags))


def _call_split(t):
    """(head up to the first call's "(", its arguments, ")") when t ends with that call."""
    depth, q, start, i = 0, None, None, 0
    while i < len(t):
        c = t[i]
        if q:
            if c == "\\":
                i += 1
            elif c == q:
                q = None
        elif c in "\"'":
            q = c
        elif c == "(":
            if depth == 0 and start is None and i and (t[i - 1].isalnum() or t[i - 1] == "_"):
                start = i
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and start is not None:
                return (t[:start + 1], t[start + 1:i], t[i:]) if i == len(t) - 1 else None
        i += 1
    return None


def _wrapped(t):
    """A long line broken the way Hex-Rays breaks it: a call after a comma, a condition
    before && / ||."""
    if len(t) <= ex.WIDTH:
        return t
    parts = _call_split(t)
    if parts is not None and not ex._split_top(t, (" && ", " || ")):
        return "\n".join(ex._wrap(*parts))
    return "\n".join(ex._wrap("", t, ""))


def _flat(st):
    """The statements of a block, nested blocks opened (a labelled one stays a statement)."""
    if st is None:
        return []
    if st.kind != "block":
        return [st]
    out = []
    for c in st.body:
        if c is not None and c.kind == "block" and c.label is None:
            out += _flat(c)
        elif c is not None:
            out.append(c)
    return out


def _prints(st):
    """A call with a string literal among its arguments that writes no buffer: what an
    unnamed printf looks like (sprintf and strcpy are not one)."""
    e = _strip(st.x) if st.kind == "expr" else None
    return (e is not None and e.kind == "call" and _call_name(e) not in WRITES
            and _call_name(e) not in SCANF and any(ex._strconst(a) is not None for a in e.args))


def _own_call(e):
    """(address, argument variables) of the first call of a function of the program's own in
    e, outermost first: f(g(x)) is f. An argument is a variable number when it is one, or its
    address (&buf), else None."""
    stack = [e]
    while stack:
        n = stack.pop(0)
        if n is None:
            continue
        if n.kind == "call" and n.x is not None and n.x.kind == "obj" and not n.x.lib \
                and n.x.obj_ea is not None:
            args = []
            for a in n.args:
                a = _strip(a)
                if a is not None and a.kind == "ref":
                    a = _strip(a.x)
                args.append(a.var if a is not None and a.kind == "var" else None)
            return n.x.obj_ea, tuple(args)
        stack.extend((n.x, n.y, n.z))
        stack.extend(n.args)
    return None


def _vars(e, out):
    stack = [e]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if n.kind == "var":
            out.add(n.var)
        stack.extend((n.x, n.y, n.z))
        stack.extend(n.args)
    return out


# ---------------------------------------------------------------- building
class _Builder:
    def __init__(self, an, info):
        self.an = an
        self.site = {}
        for s in an.sites:
            if s.stmt is not None and s.role != "join":
                self.site.setdefault((id(s.stmt), s.role), s)
        self.vb = ex.Terms(an)
        self.boxes, self.lines = [], []
        self.ctx = []                 # condition lines we are inside
        self.of = {}                  # id(statement) -> its line
        self.labels, self.gotos = {}, []   # label -> its connector; (goto's connector, label)

    def _line(self, text, site, ea, stmt=None, expr=None):
        line = Line(len(self.lines), text, site.id if site is not None else None, ea, tuple(self.ctx),
                    _own_call(expr) if expr is not None else None)
        self.lines.append(line)
        if stmt is not None:
            self.of[id(stmt)] = line
        return line

    def _box(self, kind, lines):
        b = Box(len(self.boxes), kind, list(lines))
        for line in lines:
            line.box = b.id
        self.boxes.append(b)
        return b.id

    # ---- text ----
    def _math(self, e, site):
        if site is not None and _folds(e):
            try:
                m = self.vb.norm(e, site)
                return ex._mtext(m) + _tags(m)
            except Exception:
                pass
        return ex.c_text(e)

    def _text(self, e, site):
        e = _strip(e)
        if e is None:
            return "…"
        if e.kind == "asg":
            rhs = self._math(e.y, site)
            return "%s %s= %s" % (ex._show(e.x), e.op, rhs) if e.op else "%s = %s" % (ex._show(e.x), rhs)
        return self._math(e, site)

    def _class(self, st):
        """noise, call (a function of the program), io, or process."""
        e = _strip(st.x)
        call = None
        if e is not None and e.kind == "call":
            call = e
        elif e is not None and e.kind == "asg" and _strip(e.y) is not None and _strip(e.y).kind == "call":
            call = _strip(e.y)
        if call is None or call.x is None:
            return "process"
        if call.x.kind == "helper":
            return "noise" if re.search(r"m_empty|emms", call.x.name or "") else "process"
        name = _call_name(call)
        if call is e and name in _NOISE:
            return "noise"
        shown = ex.c_text(call.x)
        if name in _INPUTS or name in _OUTPUTS or _IO.search(shown):
            return "io"
        if call.x.kind == "obj" and not call.x.lib:
            return "call"
        return "process"

    # ---- statements ----
    def seq(self, st):
        items, group, gkind = [], [], None

        def flush():
            nonlocal group, gkind
            if group:
                items.append(cl.Leaf(self._box(gkind, group)))
            group, gkind = [], None

        for c in _flat(st):
            if c.label is not None:
                flush()
                box = self._box("connector", [self._line(str(c.label), None, c.ea)])
                self.labels[c.label] = box
                items.append(cl.Leaf(box))
            k = c.kind
            if k == "expr":
                kind = self._class(c)
                if kind == "noise":
                    continue
                site = self.site.get((id(c), "stmt"))
                line = self._line(_wrapped(self._text(c.x, site)), site, c.ea, c, c.x)
                if kind == "call":
                    flush()
                    items.append(cl.Leaf(self._box("call", [line])))
                    continue
                if kind != gkind:
                    flush()
                    gkind = kind
                group.append(line)
                continue
            flush()
            if k == "block":
                items.append(self.seq(c))
            elif k == "return":
                site = self.site.get((id(c), "return"))
                text = "return" + (" " + self._text(c.x, site) if c.x is not None else "")
                items.append(cl.Stop(self._box("return", [self._line(_wrapped(text), site, c.ea, c, c.x)])))
            elif k == "if":
                items.append(self._if(c))
            elif k in ("while", "for"):
                items.append(self._while(c))
            elif k == "do":
                items.append(self._do(c))
            elif k == "switch":
                items.append(self._switch(c))
            elif k == "break":
                items.append(cl.Break())
            elif k == "continue":
                items.append(cl.Continue())
            elif k == "goto":
                box = self._box("connector", [self._line(str(c.target), None, c.ea, c)])
                self.gotos.append((box, c.target))
                items.append(cl.Stop(box))
            else:
                items.append(cl.Leaf(self._box("process", [self._line("…", None, c.ea, c)])))
        flush()
        self._after_loops(_flat(st))
        return cl.Seq(items)

    def _out_line(self, c):
        ln = self.of.get(id(c))
        if ln is not None and (c.kind == "return" or self.boxes[ln.box].kind == "io" or _prints(c)):
            return ln
        return None

    def _after_loops(self, flat):
        for i, c in enumerate(flat):
            if c.kind in ("while", "for", "do") and id(c) in self.of:
                after = []
                for d in flat[i + 1:]:
                    ln = self._out_line(d)
                    if ln is None:
                        if d.kind == "expr" and self._class(d) == "noise":
                            continue
                        break
                    after.append(ln.id)
                self.of[id(c)].outs = tuple(after)

    def _cond(self, st, e, kind="decision"):
        site = self.site.get((id(st), "switch" if kind == "switch" else "cond"))
        text = self._text(e, site) if e is not None else "1"
        line = self._line(_wrapped(text), site, st.ea, expr=e)
        return line, self._box(kind, [line])

    def _inside(self, line, st):
        self.ctx.append(line.id)
        try:
            return self.seq(st)
        finally:
            self.ctx.pop()

    def _outs(self, line, branches):
        out = []
        for b in branches:
            for c in _flat(b):
                ln = self._out_line(c)
                if ln is not None:
                    out.append(ln.id)
        line.outs = tuple(out)

    def _if(self, c):
        line, box = self._cond(c, c.x)
        yes = self._inside(line, c.body[0]) if c.body else None
        no = self._inside(line, c.body[1]) if len(c.body) > 1 else None
        self._outs(line, c.body)
        return cl.If(box, yes, no)

    def _while(self, c):
        init = None
        if c.kind == "for" and c.init is not None:
            site = self.site.get((id(c), "init"))
            init = self._box("process", [self._line(_wrapped(self._text(c.init, site)), site, c.ea,
                                                    expr=c.init)])
        line, box = self._cond(c, c.x)
        self.of[id(c)] = line
        line.loop = True
        body = self._inside(line, c.body[0] if c.body else None)
        step = None
        if c.kind == "for" and c.step is not None:
            site = self.site.get((id(c), "step"))
            self.ctx.append(line.id)
            step = self._box("process", [self._line(_wrapped(self._text(c.step, site)), site, c.ea,
                                                    expr=c.step)])
            self.ctx.pop()
        x = _strip(c.x)
        forever = x is None or (x.kind == "num" and x.value != 0)
        loop = cl.While(box, body, step, forever)
        return cl.Seq([cl.Leaf(init), loop]) if init is not None else loop

    def _do(self, c):
        # the condition's line is made first so the body's lines know they are inside it
        site = self.site.get((id(c), "cond"))
        line = self._line(_wrapped(self._text(c.x, site)), site, c.ea, expr=c.x)
        self.of[id(c)] = line
        line.loop = True
        body = self._inside(line, c.body[0] if c.body else None)
        return cl.DoWhile(body, self._box("decision", [line]))

    def _switch(self, c):
        line, box = self._cond(c, c.x, "switch")
        cases, default = [], False
        for case in c.body:
            vals = list(getattr(case, "values", None) or [])
            if not vals:
                default = True
                lab = "default"
            else:
                shown = ", ".join(_case_value(v) for v in vals[:4]) + (", …" if len(vals) > 4 else "")
                lab = "case " + shown
            cases.append((lab, self._inside(line, case)))
        return cl.Switch(box, cases, default)


def _case_value(v):
    return str(v) if -10 < v < 10 else "0x%X" % (v & 0xFFFFFFFFFFFFFFFF)


def _refs(body):
    """{identifier: ("var", n), ("obj", ea) or ("func", ea)} of what a double-click opens: a
    variable or a global is followed, a called function is gone to."""
    out, stack = {}, [body]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if n.kind == "call" and n.x is not None and n.x.kind == "obj" and n.x.obj_ea is not None:
            out.setdefault(ex.c_text(n.x), ("func", n.x.obj_ea))
            stack.extend(n.args)
            continue
        if n.kind == "var" and n.name:
            out.setdefault(n.name, ("var", n.var))
        elif n.kind == "obj" and n.decl and not n.strlit and n.obj_ea is not None:
            out.setdefault(ex.c_text(n), ("obj", n.obj_ea))
        stack.extend((n.x, n.y, n.z, n.init, n.step))
        stack.extend(n.args)
        stack.extend(n.body)
    return out


def build_chart(body, an, info=None, title=""):
    """The chart of a function body; an = dataflow.analyze(body); title: the start shape's
    text (the function and its arguments)."""
    b = _Builder(an, info or {})
    start = b._box("start", [b._line(title or T("Start", "开始"), None, None)])
    root = b.seq(body)
    root.items.insert(0, cl.Leaf(start))
    end = b._box("end", [b._line(T("End", "结束"), None, None)])
    jumps = [(box, b.labels[t]) for box, t in b.gotos if t in b.labels]
    return Chart(root, b.boxes, b.lines, end, _refs(body), jumps)


# ---------------------------------------------------------------- one variable
def _provenance(an, var, copied=None):
    """Sites that make pointer `var` point where it does; `copied` (a set) gets the pointers
    it is copied from (v28 = v19, v19 = v18)."""
    out, todo, seen = set(), [var], set()
    while todo:
        v = todo.pop()
        if v in seen:
            continue
        seen.add(v)
        for s in an.sites:
            if ("v", v) in s.defs and s.id in an.g.live:
                out.add(s.id)
                rhs = s.vrhs.get(v)
                if rhs is not None and not isinstance(rhs, tuple):
                    todo += [u for u in _vars(rhs, set()) if u in an.g.ptrvars and u not in seen]
    if copied is not None:
        copied.update(seen - {var})
    return out


def _fed(an, sites, keys):
    """Where an unknown call that may write the variable gets its other inputs from
    (sub_140011019(buf, Str): the getline that filled Str). One step only."""
    out = set()
    for sid in sites:
        s = an.sites[sid]
        if not s.mayw & keys:
            continue
        for k in s.reads() - keys:
            if k[0] == "v" and k[1] in an.g.ptrvars:
                continue                          # an address, not what is there
            out.update(w for w in an.reach(sid, k) if w != sid)
    return out


def lit(chart, an, flow, var=None):
    """The line ids that belong to the followed variable (flow = var_flow for it, with
    may=True: past calls that may write it)."""
    sites = {s.id for s in flow.sites if s.role != "join"}
    if var is not None and var in an.g.ptrvars:
        sites |= _provenance(an, var)
    sites |= _fed(an, sites, flow.keys)
    direct = {line.id for line in chart.lines if line.site is not None and line.site in sites}
    out = set(direct)
    for i in direct:
        line = chart.lines[i]
        out.update(line.ctx)
        out.update(line.outs)
        if line.outs:                             # a check: where its loop comes out too
            for c in line.ctx:
                if chart.lines[c].loop:
                    out.update(chart.lines[c].outs)
    return out


# ---------------------------------------------------------------- the names around it
def _known(s):
    """Every call at the site is one whose writes are known (fread, memcpy, an intrinsic)."""
    return all(_call_name(c) in WRITES or _call_name(c) in SCANF or _call_name(c) in READS
               or (c.x is not None and c.x.kind == "helper") for c in s.calls)


def _writes_of(an, s):
    """(what site s writes as data, the part a known call fills). A variable assigned counts,
    a pointer does not (its value is an address); memory stored to counts, a new block
    (malloc) does not, nor what an unknown call only may write outside the function's own
    memory."""
    data = {k for k in s.defs | s.wdefs if k[1] not in an.g.ptrvars}
    filled = set()
    if s.calls and _known(s):
        for c in s.calls:
            for a in c.args:
                if an.g._is_addr(a):
                    filled |= an._pts(a, s)
    for k in s.odef - s.born:
        if k in s.mayw and k[0] not in _OWN:
            continue
        data.add(k)
    return data, filled & data


def marks(chart, an, flow, var=None):
    """around(...)'s names only."""
    return around(chart, an, flow, var)[0]


def around(chart, an, flow, var=None):
    """({name: "from" | "into" | "both"}, {line id: argument positions}).

    The names: the variables and globals the followed value is
    computed from (▲) and those computed from it (▼), step by step along the definitions that
    reach each use. One that is both, through a loop, gets the nearer of the two, or "both"
    when they are as near (tmp = *p ^ k; *p = tmp + k: p is both for tmp). A
    pointer stands for the memory it points at: the pointer an encryption loop writes through
    is "into" when what it writes comes from the value. Data only: the count handed to fread
    does not make fread's buffer, and a pointer copy computes nothing (the pointers a
    followed pointer is copied from are "from").

    The arguments: for each line that calls a function of the program's own, the arguments
    the value is handed over in: the variable itself, a value computed from it, or a pointer
    to its memory or to memory computed from it (the length passed next to a buffer is not)."""
    keys = set(flow.keys)
    kept = {s.id: s for s in flow.sites if s.role != "join"}
    ptr = an.g.ptrvars
    w = {i: _writes_of(an, s) for i, s in kept.items()}
    readers = {}
    for i, s in kept.items():
        for k in s.reads():
            readers.setdefault(k, []).append(i)

    # forward: what each site reads that carries the value, and what it makes from it
    into, carry = {}, {i: s.reads() & keys for i, s in kept.items()}
    frontier, level = {i for i, c in carry.items() if c}, 0
    while frontier and level < 64:
        level += 1
        nxt = set()
        for i in sorted(frontier):
            data, filled = w[i]
            if all(k[0] == "v" for k in carry[i]):   # a count or a flag: not what a known call fills
                data = data - filled
            for k in data - keys:
                into.setdefault(k, level)
                for r in readers.get(k, ()):
                    if r != i and k not in carry[r] and i in an.reach(r, k):
                        carry[r].add(k)
                        nxt.add(r)
        frontier = nxt

    # backward: what each site is asked to make, and what it makes it from
    frm, want = {}, {i: w[i][0] & keys for i in kept}
    frontier, level = {i for i, m in want.items() if m}, 0
    while frontier and level < 64:
        level += 1
        nxt = set()
        for i in sorted(frontier):
            s = kept[i]
            if want[i] <= s.mayw:                     # an unknown call only may make it: not
                continue                              # followed (as dataflow._back)
            rd = {k for k in s.reads() if not (k[0] == "v" and k[1] in ptr)} - keys
            if want[i] <= w[i][1]:                    # fread's buffer: from the file, not the count
                rd = {k for k in rd if k[0] != "v"}
            for k in rd:
                frm.setdefault(k, level)
                for d in an.reach(i, k):
                    if d != i and d in kept and k in w[d][0] and k not in want[d]:
                        want[d].add(k)
                        nxt.add(d)
        frontier = nxt

    names = {}
    for nm, ref in chart.refs.items():
        names.setdefault(ref, nm)

    def name(k):
        if k[0] in ("v", "stk"):
            return names.get(("var", k[1])) if k[1] != var else None
        if k[0] == "g":
            return names.get(("obj", k[1]))
        return None

    dist = {"from": {}, "into": {}}
    for kind, got in (("from", frm), ("into", into)):
        mem = {}
        for k, d in got.items():
            n = name(k)
            if n is not None:
                dist[kind][n] = min(d, dist[kind].get(n, d))
            elif k[0] not in ("v", "stk", "g"):
                mem[k] = d
        if mem:                                   # memory with no name: the pointers into it
            for s in kept.values():
                for p in _vars(s.expr, set()):
                    n = names.get(("var", p))
                    if p in ptr and p != var and n is not None:
                        hit = [mem[o] for o in an._pts_var(p, s) if o in mem]
                        if hit:
                            dist[kind][n] = min(min(hit), dist[kind].get(n, 1e9))
    out = {}
    for n in set(dist["from"]) | set(dist["into"]):
        f, t = dist["from"].get(n, 1e9), dist["into"].get(n, 1e9)
        out[n] = "into" if t < f else "from" if f < t else "both"
    if var is not None and var in ptr:
        copied = set()
        _provenance(an, var, copied)
        for p in copied:
            n = names.get(("var", p))
            if n is not None:
                out[n] = "from"

    data = keys | set(into)
    args = {}
    for line in chart.lines:
        if line.call is None:
            continue
        s = an.sites[line.site] if line.site is not None else None
        at = []
        for i, n in enumerate(line.call[1]):
            if n is None:
                continue
            if ("v", n) in data or ("stk", n) in data or (
                    s is not None and n in ptr and an._pts_var(n, s) & data):
                at.append(i)
        if at:
            args[line.id] = tuple(at)
    return out, args
