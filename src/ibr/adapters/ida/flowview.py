"""Variable data flow windows: the chosen variable's lines of pseudocode and nothing else.

Ctrl-Alt-F (or right-click > Data flow of this variable) in a pseudocode view on a local
variable or a global opens a window with only the lines its value comes from (▲), the lines
that read or write it (●) and the lines its value goes to (▼), inside the if/loop headers
that enclose them. The lines are Hex-Rays' own, colours and notes included.
Space switches to a flowchart in the same place (flowgraph.py): the whole function the way
textbooks draw a program, the chosen variable's lines in full and its name marked, the rest
faded; Space switches back. Zooming into a call of the program's own function opens that
function's chart inside it (_Callees makes it then, not before).
In both: double-click a variable to follow it; Back / Forward (Esc, Ctrl-Enter, Alt-Left /
Alt-Right, the mouse side buttons) move between the variables followed; Enter jumps to the
line in the pseudocode. A variable double-clicked in the pseudocode itself is followed too
while a window is open. Nothing is written to the database."""
import collections
import time

import ida_hexrays as hr
import ida_kernwin
import ida_lines
import ida_name

from ...analysis.dataflow import analyze, var_flow
from ...analysis.flowchart import around, build_chart, lit
from ...core.i18n import T
from .fntree import function_tree, var_info
from .live import _line_item_indices

ACTION = "ibr:varflow"
HOTKEY = "Ctrl-Alt-F"
_MARK = {"src": ("▲ ", ida_lines.SCOLOR_NUMBER), "self": ("● ", ida_lines.SCOLOR_KEYWORD),
         "dst": ("▼ ", ida_lines.SCOLOR_IMPNAME)}
_SITE_OF = {"stmt": "body", "return": "body", "cond": "head", "init": "head", "step": "head",
            "switch": "head"}


_CACHE = {}       # the last function's tree, analysis and flowchart, keyed by its printed text

def _items(t, out=None):
    out = set() if out is None else out
    stack = [t]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if n.index is not None:
            out.add(n.index)
        stack.extend((n.x, n.y, n.z, n.init, n.step))
        stack.extend(n.args)
    return out


class FlowText:
    """The window's content for one variable: [(colored line, ea or None)], title, names."""

    def __init__(self, cfunc, var=None, obj_ea=None):
        self.func_ea = cfunc.entry_ea
        sv = cfunc.get_pseudocode()           # numbers the items; the tree must be read after it
        self.src = [sv[i].line for i in range(sv.size())]
        key = (self.func_ea, hash(tuple(self.src)))
        if _CACHE.get("key") != key:          # following another variable of the same function
            body, names = function_tree(cfunc)
            _CACHE.clear()
            _CACHE.update(key=key, data=(body, names, analyze(body), var_info(cfunc)),
                          title=_title(cfunc))
        body, self.names, an, self.info = _CACHE["data"]
        self.body, self.an = body, an
        self.var, self.obj_ea = var, obj_ea
        self.name = self.names.get(var, "?") if var is not None else (
            ida_lines.tag_remove(ida_name.get_name(obj_ea) or "") or "%X" % obj_ea)
        flow = var_flow(body, var=var, obj_ea=obj_ea, an=an)
        self.flow = flow
        self.at = {}
        for n, line in enumerate(self.src):
            for idx in _line_item_indices(cfunc, line):
                self.at.setdefault(idx, []).append(n)
        # statements and headers to show, with their role
        self.role = {}
        self.shown = set()
        for s in flow.sites:
            if s.role == "join" or s.stmt is None:
                continue
            self.role[(id(s.stmt), _SITE_OF[s.role])] = (flow.role[s.id], s.may)
            for c in s.ctx:
                self.shown.add(id(c))
            if _SITE_OF[s.role] == "head":
                self.shown.add(id(s.stmt))
        self.lines, self._done = [], set()
        self._header()
        self._walk(body)

    # ---- the flowchart ----
    def chart_data(self):
        """(chart, lit line ids, the name to mark, message, {name: "from" | "into" | "both"}
        for the names around it, {line id: argument positions} of the calls it is handed to).
        One chart per function, made once: following another variable only changes what is
        lit."""
        chart = _CACHE.get("chart")
        if chart is None:
            chart = _CACHE["chart"] = build_chart(self.body, self.an, self.info, _CACHE.get("title", ""))
            chart.ea = self.func_ea
        name = self.name
        if self.obj_ea is not None:               # as the chart writes it (_fread_chk, not __fread_chk)
            name = next((k for k, v in chart.refs.items() if v[0] != "var" and v[1] == self.obj_ea), name)
        flow = var_flow(self.body, var=self.var, obj_ea=self.obj_ea, an=self.an, may=True)
        on = lit(chart, self.an, flow, self.var)
        names, args = around(chart, self.an, flow, self.var) if on else ({}, {})
        msg = ""
        if not on:                                # a function, or nothing flows through it
            on = chart.mentions(name)
            msg = (T("%s carries no data here: only where it appears is marked." % name,
                     "%s 在这里不传递数据，只标出它出现的地方。" % name) if on else
                   T("%s is not used in this function." % name, "%s 在这个函数里没有用到。" % name))
        return chart, on, name, msg, names, args

    # ---- output ----
    def _add(self, text, ea=None):
        self.lines.append((text, ea))

    def _comment(self, text):
        self._add(ida_lines.COLSTR("// " + text, ida_lines.SCOLOR_AUTOCMT))

    def _header(self):
        f = self.flow
        count = {"src": 0, "self": 0, "dst": 0}
        for s in f.sites:
            if s.role != "join":
                count[f.role[s.id]] += 1
        fname = ida_lines.tag_remove(ida_name.get_name(self.func_ea) or "") or "%X" % self.func_ea
        self._comment(T("Data flow of %s in %s: ▲ from %d, ● itself %d, ▼ to %d."
                        " Everything else is hidden." % (self.name, fname, count["src"],
                                                        count["self"], count["dst"]),
                        "%s 在 %s 中的数据流：▲ 来源 %d 处，● 自身 %d 处，▼ 去向 %d 处。"
                        "其余代码已隐藏。" % (self.name, fname, count["src"], count["self"],
                                             count["dst"])))
        if f.may:
            self._comment(T("? = a call to an unknown function that may change the memory passed to it.",
                            "? = 调用了未知函数，可能改写传给它的内存。"))
        if f.cut:
            self._comment(T("Too long: only the lines closest to %s are shown." % self.name,
                            "太长：只显示离 %s 最近的部分。" % self.name))
        self._comment(T("Double-click a variable to follow it; Back / Forward (Esc, Ctrl-Enter, mouse"
                        " side buttons) step through them; Enter jumps to the line; Space: flowchart.",
                        "双击变量跟踪它；后退/前进（Esc、Ctrl+Enter、鼠标侧键）在跟踪过的变量间切换；"
                        "回车跳到原伪代码的这一行；空格切换流程图。"))
        self._add("")

    def _src_lines(self, nums, mark, ea):
        first = True
        for n in nums:
            if n in self._done:
                continue
            self._done.add(n)
            gutter = "    "                        # continuation lines and plain headers
            if first and mark is not None:
                (sym, col), may = _MARK[mark[0]], mark[1]
                may = ida_lines.COLSTR("? ", ida_lines.SCOLOR_AUTOCMT) if may else "  "
                gutter = may + ida_lines.COLSTR(sym, col)
            self._add(gutter + self.src[n], ea)
            first = False

    def _lines_of(self, *trees):
        out = set()
        for t in trees:
            for idx in _items(t):
                out.update(self.at.get(idx, ()))
        return sorted(out)

    def _indent(self, nums):
        if not nums:
            return ""
        raw = ida_lines.tag_remove(self.src[nums[0]])
        return raw[:len(raw) - len(raw.lstrip(" "))]

    def _synth(self, indent, text):
        self._add("    " + indent + ida_lines.COLSTR(text, ida_lines.SCOLOR_SYMBOL))

    def _walk(self, st):
        if st is None:
            return
        k = st.kind
        if k == "block":
            for c in st.body:
                self._walk(c)
            return
        if k in ("expr", "return"):
            mark = self.role.get((id(st), "body"))
            if mark:
                self._src_lines(self._lines_of(st.x) or self._lines_of(st), mark, st.ea)
            return
        if id(st) not in self.shown:
            return
        head = self.role.get((id(st), "head"))
        if k in ("if", "while", "switch"):
            nums = self._lines_of(st.x)
            ind = self._indent(nums)
            self._src_lines(nums, head, st.ea)
            if k == "switch":
                for case in st.body:
                    self._block(case, ind)
            else:
                self._block(st.body[0] if st.body else None, ind)
            if k == "if" and len(st.body) > 1 and self._has(st.body[1]):
                self._synth(ind, "else")
                self._block(st.body[1], ind)
        elif k == "for":
            nums = self._lines_of(st.init, st.x, st.step)
            ind = self._indent(nums)
            self._src_lines(nums, head, st.ea)
            self._block(st.body[0] if st.body else None, ind)
        elif k == "do":
            nums = self._lines_of(st.x)
            ind = self._indent(nums)
            body = st.body[0] if st.body else None
            if self._has(body):
                self._synth(ind, "do")
                self._block(body, ind)
            self._src_lines(nums, head, st.ea)

    def _has(self, st):
        """Something under st is shown."""
        stack = [st]
        while stack:
            n = stack.pop()
            if n is None:
                continue
            if id(n) in self.shown or (id(n), "body") in self.role:
                return True
            stack.extend(n.body)
        return False

    def _block(self, st, ind):
        """A shown statement's body, braced; nothing when none of it is shown, except
        a lone break / continue / goto, which says what the condition does."""
        if not self._has(st):
            jumps = _jumps(st)
            if jumps:
                self._src_lines(sorted(n for j in jumps for n in self.at.get(j.index, ())), None, None)
            return
        self._synth(ind, "{")
        self._walk(st)
        self._synth(ind, "}")


def _title(cfunc):
    """The start of the chart: the function and its arguments' names."""
    name = ida_lines.tag_remove(ida_name.get_name(cfunc.entry_ea) or "") or "%X" % cfunc.entry_ea
    try:
        args = [cfunc.lvars[i].name for i in cfunc.argidx]
    except Exception:
        args = []
    return "%s(%s)" % (name, ", ".join(args))


class _Callee:
    """A called function's chart and what lighting it needs."""

    def __init__(self, ea, chart, body, an, names, argidx):
        self.ea, self.chart, self.body, self.an = ea, chart, body, an
        self.names, self.argidx = names, argidx


class _Callees:
    """The charts of the functions the flowchart opens inside their calls: made when a call
    is zoomed into (the view asks for one at a time), kept for the last LIMIT functions and
    forgotten when the window shows another function."""
    LIMIT = 30

    def __init__(self):
        self.cache = collections.OrderedDict()

    def clear(self):
        self.cache.clear()

    def cached(self, ea):
        e = self.cache.get(ea)
        if e is not None:
            self.cache.move_to_end(ea)
        return e

    def load(self, ea):
        e = self.cached(ea)
        if e is not None:
            return e
        cf = hr.decompile(ea)
        if not cf:
            raise RuntimeError("cannot decompile %X" % ea)
        cf.get_pseudocode()                       # numbers the items; the tree is read after it
        body, names = function_tree(cf)
        an = analyze(body)
        chart = build_chart(body, an, var_info(cf), _title(cf))
        chart.ea = ea
        e = self.cache[ea] = _Callee(ea, chart, body, an, names, list(cf.argidx))
        while len(self.cache) > self.LIMIT:
            self.cache.popitem(last=False)
        return e

    def _one(self, e, var=None, obj_ea=None):
        flow = var_flow(e.body, var=var, obj_ea=obj_ea, an=e.an, may=True)
        on = lit(e.chart, e.an, flow, var)
        return (on,) + (around(e.chart, e.an, flow, var) if on else ({}, {}))

    def args(self, e, positions):
        """(lit line ids, names, {name: from / into / both}, {line id: argument positions})
        for the function's arguments at positions."""
        on, chosen, names, args = set(), [], {}, {}
        for i in positions:
            if i < len(e.argidx):
                n = e.argidx[i]
                a, m, g = self._one(e, var=n)
                on |= a
                names.update(m)
                for k, v in g.items():
                    args[k] = tuple(sorted(set(args.get(k, ())) | set(v)))
                chosen.append(e.names.get(n, "?"))
        return on, tuple(chosen), names, args

    def follow(self, e, ref):
        """A name double-clicked inside the chart: (lit, names, around, args, message)."""
        kind, x = ref
        if kind == "var":
            name = e.names.get(x, "?")
            on, names, args = self._one(e, var=x)
        else:
            name = next((k for k, v in e.chart.refs.items() if v == ref), "%X" % x)
            on, names, args = self._one(e, obj_ea=x)
        msg = ""
        if not on:
            on = e.chart.mentions(name)
            msg = (T("%s carries no data here: only where it appears is marked." % name,
                     "%s 在这里不传递数据，只标出它出现的地方。" % name) if on else
                   T("%s is not used in this function." % name, "%s 在这个函数里没有用到。" % name))
        return on, (name,), names, args, msg


_CALLEES = _Callees()


def _jumps(st):
    """The statements of st when all of them are break / continue / goto, else []."""
    if st is None:
        return []
    if st.kind in ("break", "continue", "goto"):
        return [st]
    if st.kind == "block" and st.body and all(c.kind in ("break", "continue", "goto") for c in st.body):
        return list(st.body)
    return []


class _Nav:
    """What both windows show, and the way back and forward through followed variables."""

    def __init__(self):
        self.cur = None         # FlowText on screen
        self.history = []       # (var, obj_ea) followed before it: Back goes there
        self.ahead = []         # and Forward comes back
        self.mode = "text"      # "text" or "graph"; Space switches
        self.last = 0.0         # one side-button click must not step twice
        self.last_toggle = 0.0


NAV = _Nav()
_TEXT = None                    # FlowViewer, when open
_GRAPH = None                   # flowgraph.GraphForm, when open
_CLOSING = [False]              # a window closed by us, not by the user


def _text_title():
    return T("Data flow", "数据流")


def _graph_title():
    return T("Flowchart", "流程图")


def _ours(w):
    """w is one of the data-flow windows."""
    if w is None:
        return False
    title = ida_kernwin.get_widget_title(w)
    return title in (_text_title(), _graph_title())


# ---- navigation, shared by both windows ----
def _refresh(var, obj_ea, activate=True):
    cf = hr.decompile(NAV.cur.func_ea)
    if cf:
        NAV.cur = FlowText(cf, var=var, obj_ea=obj_ea)
        _render(activate)


def follow(var=None, obj_ea=None, activate=True):
    """Show another variable of the same function; Back returns to this one."""
    if NAV.cur is None or (var == NAV.cur.var and obj_ea == NAV.cur.obj_ea):
        return
    NAV.history.append((NAV.cur.var, NAV.cur.obj_ea))
    NAV.ahead = []
    _refresh(var, obj_ea, activate)


def _sync(vu):
    """A local variable double-clicked in the pseudocode (IDA does nothing with that): an open
    data-flow window follows it and the pseudocode keeps the focus. Functions and globals,
    which IDA goes to on a double-click, are left alone."""
    if NAV.cur is None or (_TEXT is None and _GRAPH is None):
        return
    var, obj_ea = _target(vu)
    if var is None or obj_ea is not None:
        return
    if vu.cfunc.entry_ea != NAV.cur.func_ea:      # another function: a new start
        NAV.history, NAV.ahead = [], []
        NAV.cur = FlowText(vu.cfunc, var=var)
        _render(activate=False)
    else:
        follow(var=var, activate=False)


def _step(src, dst):
    now = time.time()
    if not src or NAV.cur is None or now - NAV.last < 0.15:
        return
    NAV.last = now
    dst.append((NAV.cur.var, NAV.cur.obj_ea))
    _refresh(*src.pop())


def back():
    """IDA's Back (Esc, Alt-Left, the mouse back button): the previous variable."""
    _step(NAV.history, NAV.ahead)


def forward():
    """IDA's Forward (Ctrl-Enter, Alt-Right, the mouse forward button)."""
    _step(NAV.ahead, NAV.history)


def toggle():
    """Space: text <-> graph, in the same place."""
    now = time.time()
    if now - NAV.last_toggle < 0.2:
        return
    NAV.last_toggle = now
    NAV.mode = "graph" if NAV.mode == "text" else "text"
    _render()


def jump(ea):
    """Show ea in the pseudocode (IDA's own history records it, so Esc there returns)."""
    if ea is not None:
        hr.open_pseudocode(ea, hr.OPF_REUSE)
        ida_kernwin.jumpto(ea)


def _keys(key, ctrl, alt):
    """The keys both windows share. key: a Windows virtual key code."""
    if key == 0x20 and not (ctrl or alt):
        toggle()
    elif key == 0x1B:
        back()
    elif key == 0x0D and ctrl:
        forward()
    elif key == 0x25 and alt:
        back()
    elif key == 0x27 and alt:
        forward()
    else:
        return False
    return True


# ---- the mouse side buttons ----
def _nav_filter():
    from .qt import QtCore
    E, Qt = QtCore.QEvent, QtCore.Qt

    class F(QtCore.QObject):
        def eventFilter(self, obj, ev):
            try:
                t = ev.type()
                if t in (E.MouseButtonPress, E.MouseButtonRelease, E.MouseButtonDblClick):
                    b = ev.button()
                    if b in (Qt.BackButton, Qt.ForwardButton):
                        if t == E.MouseButtonPress:
                            (back if b == Qt.BackButton else forward)()
                        return True
                elif t == E.KeyPress and ev.key() in (Qt.Key_Back, Qt.Key_Forward):
                    (back if ev.key() == Qt.Key_Back else forward)()      # WM_APPCOMMAND
                    return True
            except Exception:
                pass
            return False
    return F()


def _watch(view):
    """Side buttons over a window and every widget inside it."""
    try:
        from .qt import QtWidgets, qwidget
        w = qwidget(view.GetWidget())
        if w is None:
            return
        view._filter = getattr(view, "_filter", None) or _nav_filter()
        for x in [w] + w.findChildren(QtWidgets.QWidget):
            x.installEventFilter(view._filter)
    except Exception:
        pass


# ---- showing ----
def _render(activate=True):
    if NAV.cur is None:
        return
    if NAV.mode == "graph":
        _show(_graph_view, _TEXT, activate)
    else:
        _show(_text_view, _GRAPH, activate)


def _show(make, other, activate=True):
    """Fill the window of the current mode; it takes the other one's place."""
    global _TEXT, _GRAPH
    view, fresh = make(activate)
    w = view.GetWidget()
    if fresh:
        if other is not None and other.GetWidget():
            ida_kernwin.set_dock_pos(ida_kernwin.get_widget_title(w),
                                     ida_kernwin.get_widget_title(other.GetWidget()), ida_kernwin.DP_TAB)
        else:
            ida_kernwin.set_dock_pos(ida_kernwin.get_widget_title(w), "Pseudocode-A", ida_kernwin.DP_RIGHT)
        _watch(view)
    if other is not None:
        _CLOSING[0] = True
        try:
            other.Close()
        finally:
            _CLOSING[0] = False
        if other is _TEXT:
            _TEXT = None
        if other is _GRAPH:
            _GRAPH = None
    if activate or fresh:
        ida_kernwin.activate_widget(view.GetWidget(), True)
    if view is _TEXT:
        # the ordinary highlight, as if the name had been clicked: the next click replaces it
        ida_kernwin.set_highlight(view.GetWidget(), NAV.cur.name, ida_kernwin.HIF_IDENTIFIER)


def _text_view(activate=True):
    global _TEXT
    fresh = _TEXT is None or not _TEXT.GetWidget()
    if fresh:
        _TEXT = FlowViewer()
        _TEXT.Create(_text_title())
    _TEXT.ClearLines()
    for line, _ in NAV.cur.lines:
        _TEXT.AddLine(line)
    _TEXT.Refresh()
    if fresh or activate:                         # Show() also brings it to the front
        _TEXT.Show()
    return _TEXT, fresh


def _graph_view(activate=True):
    global _GRAPH
    from .flowgraph import GraphForm
    fresh = _GRAPH is None or not _GRAPH.GetWidget()
    if fresh:
        _GRAPH = GraphForm(_keys, _open, _graph_closed, _CALLEES)
        _GRAPH.Show(_graph_title())
    _GRAPH.show_graph(*NAV.cur.chart_data(), take_focus=activate or fresh)
    return _GRAPH, fresh


def _graph_closed(form):
    global _GRAPH
    if not _CLOSING[0] and form is _GRAPH:
        _GRAPH = None


def _open(what, value):
    """From the flowchart: ("follow", ("var", n) or ("obj", ea)) after a double-click on a
    name, ("func", ea) after one on a called function, ("jump", chart line) after Enter."""
    if NAV.cur is None:
        return
    if what == "follow":
        kind, x = value
        if kind == "var":
            follow(var=x)
        else:
            follow(obj_ea=x)
    elif what == "func":
        jump(value)
    else:
        jump(value.ea)


class FlowViewer(ida_kernwin.simplecustviewer_t):
    """The text window: the variable's lines of pseudocode inside their if/loop headers."""

    def _word(self):
        """The identifier under the cursor."""
        word = self.GetCurrentWord()
        if word:
            return word
        pos, line = self.GetPos(), self.GetCurrentLine(notags=1)
        if not pos or not line:
            return None
        x = pos[1]
        ok = lambda c: c.isalnum() or c == "_"
        if x >= len(line) or not ok(line[x]):
            return None
        a = x
        while a > 0 and ok(line[a - 1]):
            a -= 1
        b = x
        while b < len(line) and ok(line[b]):
            b += 1
        return line[a:b]

    def OnDblClick(self, shift):
        word = self._word()
        if word and NAV.cur is not None:
            for n, name in NAV.cur.names.items():
                if name == word:
                    follow(var=n)
                    return True
        return self._jump()

    def _jump(self):
        n = self.GetLineNo()
        if NAV.cur is not None and n is not None and 0 <= n < len(NAV.cur.lines):
            jump(NAV.cur.lines[n][1])
        return True

    def OnKeydown(self, vkey, shift):
        ctrl, alt = bool(shift & ida_kernwin.VES_CTRL), bool(shift & ida_kernwin.VES_ALT)
        if vkey == 0x0D and not ctrl:
            return self._jump()
        return _keys(vkey, ctrl, alt)

    def OnClose(self):
        global _TEXT
        if not _CLOSING[0]:
            _TEXT = None


def open_flow(cfunc, var=None, obj_ea=None):
    """A new start (from the pseudocode): forget the variables followed before."""
    NAV.history, NAV.ahead = [], []
    NAV.cur = FlowText(cfunc, var=var, obj_ea=obj_ea)
    _render()


def _target(vu):
    """(var number, global ea) under the cursor of a pseudocode view."""
    if not vu.get_current_item(hr.USE_KEYBOARD):
        return None, None
    it = vu.item
    if it.citype == hr.VDI_EXPR:
        e = it.e
        if e.op == hr.cot_var:
            return e.v.idx, None
        if e.op == hr.cot_obj:
            return None, e.obj_ea
    if it.citype == hr.VDI_LVAR:
        lv = it.get_lvar()
        for n, v in enumerate(vu.cfunc.lvars):
            if v.name == lv.name:
                return n, None
    return None, None


class _Handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        vu = hr.get_widget_vdui(ctx.widget)
        if not vu:
            return 0
        var, obj_ea = _target(vu)
        if var is None and obj_ea is None:
            ida_kernwin.warning(T("Put the cursor on a variable first.", "请先把光标放在一个变量上。"))
            return 0
        open_flow(vu.cfunc, var=var, obj_ea=obj_ea)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class _UiHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION, None)

    def preprocess_action(self, name):
        # IDA's own graph/text switch (Space) and, where IDA routes them to our windows,
        # its Back / Forward act on the data-flow windows
        acts = {"ToggleRenderer": toggle, "Return": back, "UndoReturn": forward}
        if name in acts and _ours(ida_kernwin.get_current_widget()):
            acts[name]()
            return 1
        return 0


_POPUP = None
_HX = None


class _HxHooks(hr.Hexrays_Hooks):
    def double_click(self, vu, shift):
        try:
            _sync(vu)
        except Exception:
            pass
        return 0                                  # IDA does what it does on a double-click too


def _label():
    return T("Data flow of this variable", "这个变量的数据流")


def _tip():
    return T("Show only the lines this variable's value comes from and goes to",
             "只显示这个变量的值从哪来、到哪去的那些行")


def relabel():
    """After a language switch: the menu entry, and the open window (rebuilt, so its title
    changes too; Back / Forward keep their history)."""
    global _TEXT, _GRAPH
    ida_kernwin.update_action_label(ACTION, _label())
    ida_kernwin.update_action_tooltip(ACTION, _tip())
    if NAV.cur is None or (_TEXT is None and _GRAPH is None):
        return
    _CLOSING[0] = True
    try:
        for v in (_TEXT, _GRAPH):
            if v is not None:
                v.Close()
    finally:
        _CLOSING[0] = False
    _TEXT = _GRAPH = None
    _CACHE.pop("chart", None)                 # its words are in the old language
    _refresh(NAV.cur.var, NAV.cur.obj_ea)


def install():
    """Register the action (Ctrl-Alt-F), its pseudocode context-menu entry, and IDA's Back /
    Forward inside the data-flow windows."""
    global _POPUP
    ida_kernwin.unregister_action(ACTION)
    ok = ida_kernwin.register_action(ida_kernwin.action_desc_t(
        ACTION, _label(), _Handler(), HOTKEY, _tip(), -1))
    if _POPUP is None:
        _POPUP = _UiHooks()
        _POPUP.hook()
    global _HX
    if _HX is None:
        _HX = _HxHooks()
        _HX.hook()
    return ok


def uninstall():
    global _POPUP
    if _POPUP is not None:
        _POPUP.unhook()
        _POPUP = None
    global _HX
    if _HX is not None:
        _HX.unhook()
        _HX = None
    ida_kernwin.unregister_action(ACTION)
