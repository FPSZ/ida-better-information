"""The flowchart window: one function drawn as a program flowchart, the way textbooks draw
one. analysis/flowchart.py says what is in it, core/chartlayout.py where it goes; this file
draws it with Qt inside an IDA form.

The lines that belong to the followed variable are drawn in full, its name marked wherever
it appears, and the names it is computed from (▲) and those computed from it (▼) marked in
their own colours; everything else is faded, so following another variable only moves the
light. A legend in the top-left corner says what the colours mean.
A click on a shape lights the way from the start to it instead (which conditions, which
exit), ending there; a click on empty space or Esc goes back to the variable.
The drawing sits on a canvas, used like a map: drag it anywhere, the wheel zooms about the
mouse, Shift+wheel goes sideways.

Zooming into a call of one of the program's own functions (marked ⊕) opens that function's
chart inside it, and so on further down (core/nest.py says when and where). Resting the mouse
on such a call shows a small picture of that chart first, so it is plain there is more inside. A chart is made
only when its call is zoomed into, one at a time, and dropped when zoomed out again. When the
followed value (or one computed from it, or one it comes from) is handed to the call, the
argument it arrives in is followed inside."""
import html
import math
import re

import ida_kernwin

from ...core import nest
from ...core.chartlayout import route
from ...core.i18n import T
from .qt import QtCore, QtGui, QtWidgets, dark_theme

PAD_X, PAD_Y = 12, 7
BAR = 7                 # the inner sides of a call box
KEEP = 80               # px of the drawing that stay on screen however far it is dragged
GRID = 24               # the canvas's dots, in drawing units
RATIO = 4.0             # a diamond's width to its height
ZOOM = (0.1, 8.0)       # how far the drawing can be zoomed out and in (in, per open chart)
STEP = 1.15             # one notch of the wheel
_KEYWORDS = ("return", "sizeof")
_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\b0x[0-9A-Fa-f]+\b|\b\d+\b|\b[A-Za-z_]\w*\b|.')
_IDENT = re.compile(r"[A-Za-z_]\w*")
_STRING = re.compile(r'"(?:\\.|[^"\\])*"')

# light, dark
_COLORS = {
    "bg": ("#FAFAF9", "#1E1F22"),
    "grid": ("#E2E4E8", "#2F3135"),
    "fill": ("#FFFFFF", "#27292D"),
    "line": ("#2F343B", "#C4C8CE"),
    "text": ("#1B1F24", "#DFE1E5"),
    "faded_line": ("#D2D6DC", "#3D4046"),
    "faded_text": ("#A9AFB7", "#5C6067"),
    "keyword": ("#0B57A4", "#79B8FF"),
    "string": ("#9A3B12", "#E5A66B"),
    "number": ("#1E6B30", "#9CD67E"),
    "mark": ("#FFE27A", "#6E5B10"),       # the followed variable
    "into": ("#BFDDF7", "#1E4A6E"),       # computed from it
    "from": ("#E3D2F7", "#4F3A70"),       # what it is computed from
    "label": ("#59606C", "#9AA1AB"),
    "message": ("#7D8693", "#8E949C"),
}


def _theme():
    k = 1 if dark_theme() else 0
    return {name: QtGui.QColor(v[k]) for name, v in _COLORS.items()}


def _font():
    """The font IDA's pseudocode uses, when it can be found; a fixed-width one otherwise."""
    f = None
    try:
        from .qt import qwidget
        w = qwidget(ida_kernwin.find_widget("Pseudocode-A"))
        if w is not None:
            for c in [w] + w.findChildren(QtWidgets.QWidget):
                cf = c.font()
                if QtGui.QFontInfo(cf).fixedPitch():
                    f = QtGui.QFont(cf)
                    break
    except Exception:
        f = None
    if f is None:
        f = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
        f.setPointSize(max(f.pointSize(), 10))
    return f


def _spans(text, th):
    """C text in coloured pieces: (text, colour, bold)."""
    out = []
    for m in _TOKEN.finditer(text):
        t = m.group(0)
        if t.startswith('"'):
            out.append((t, th["string"], False))
        elif t[0].isdigit():
            out.append((t, th["number"], False))
        elif t in _KEYWORDS:
            out.append((t, th["keyword"], True))
        else:
            out.append((t, th["text"], False))
    return out


def _rx(names):
    names = sorted((n for n in names if n), key=len, reverse=True)
    if not names:
        return None
    return re.compile(r"(?<![\w])(?:%s)(?![\w])" % "|".join(map(re.escape, names)))


def _outside_strings(rx, text):
    if rx is None:
        return
    strings = [m.span() for m in _STRING.finditer(text)]
    for m in rx.finditer(text):
        if not any(a <= m.start() < b for a, b in strings):
            yield m


# ---------------------------------------------------------------- items
class _Holder(QtWidgets.QGraphicsItem):
    """Holds one chart's shapes and lines; a called chart's is scaled into its panel."""

    def __init__(self, parent=None):
        QtWidgets.QGraphicsItem.__init__(self, parent)
        self.setFlag(QtWidgets.QGraphicsItem.ItemHasNoContents, True)

    def boundingRect(self):
        return QtCore.QRectF()

    def paint(self, p, opt, widget=None):
        pass


class _Shape(QtWidgets.QGraphicsItem):
    """One box of the chart: its outline by kind, its lines of text. A call of one of the
    program's own functions can open that function's chart (ea; ⊕ beside it)."""

    def __init__(self, frame, box, w, h):
        QtWidgets.QGraphicsItem.__init__(self, frame.holder)
        self.frame, self.view, self.box, self.w, self.h = frame, frame.view, box, w, h
        self.lit = set()                  # its lines that are lit
        self.rows = self.view.rows(box, w, h)  # [(line id, text, x, baseline y)]
        self.line = box.callee()
        self.call = self.line.call if self.line is not None else None
        self.ea = None
        if (self.call is not None and frame.depth < nest.MAX_DEPTH and self.call[0] not in frame.eas
                and frame.view.provider is not None):
            self.ea = self.call[0]
        self.panel, self.state = None, None      # its open chart; "queued" / "failed"
        if self.ea is None:                       # a call that opens shows a preview instead
            self.setToolTip(T("Click: the way to this step. Double-click a variable to follow it, "
                              "a function to go to it; Enter jumps to the line.",
                              "单击：走到这一步的路。双击变量跟踪它，双击函数名跳过去；回车跳到这一行。"))

    @property
    def on(self):
        return bool(self.lit) or self.box.kind in ("start", "end")

    def boundingRect(self):
        return QtCore.QRectF(-2, -12, self.w + 20, self.h + 14)

    def outline(self):
        w, h, k = self.w, self.h, self.box.kind
        path = QtGui.QPainterPath()
        if k in ("decision", "switch"):
            path.addPolygon(QtGui.QPolygonF([QtCore.QPointF(w / 2, 0), QtCore.QPointF(w, h / 2),
                                             QtCore.QPointF(w / 2, h), QtCore.QPointF(0, h / 2),
                                             QtCore.QPointF(w / 2, 0)]))
        elif k == "io":
            s = self.view.slant(h)
            path.addPolygon(QtGui.QPolygonF([QtCore.QPointF(s, 0), QtCore.QPointF(w, 0),
                                             QtCore.QPointF(w - s, h), QtCore.QPointF(0, h),
                                             QtCore.QPointF(s, 0)]))
        elif k in ("start", "end", "return"):
            path.addRoundedRect(QtCore.QRectF(0, 0, w, h), h / 2, h / 2)
        elif k == "connector":
            path.addEllipse(QtCore.QRectF(0, 0, w, h))
        else:
            path.addRect(QtCore.QRectF(0, 0, w, h))
        return path

    def paint(self, p, opt, widget=None):
        th, view, frame = self.view.th, self.view, self.frame
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        pen = QtGui.QPen(th["line"] if self.on else th["faded_line"], 1.3)
        p.setPen(pen)
        fill = th["fill"]
        if frame.goal == self.box.id:             # the step whose way is shown
            fill = QtGui.QColor(th["mark"])
            fill.setAlpha(150)
            pen.setWidthF(2.2)
            p.setPen(pen)
        p.setBrush(fill)
        p.drawPath(self.outline())
        if self.box.kind == "call":
            p.drawLine(QtCore.QPointF(BAR, 0), QtCore.QPointF(BAR, self.h))
            p.drawLine(QtCore.QPointF(self.w - BAR, 0), QtCore.QPointF(self.w - BAR, self.h))
        if self.ea is not None:
            self._badge(p, th)
        fm = view.fm
        for lid, text, x, y in self.rows:
            lit = lid in self.lit or self.box.kind in ("start", "end")
            for a, b, colour in frame.marked(text):
                x0 = x + fm.horizontalAdvance(text[:a])
                r = QtCore.QRectF(x0 - 1.5, y - fm.ascent() - 1, fm.horizontalAdvance(text[a:b]) + 3,
                                  fm.height() + 2)
                p.setPen(QtCore.Qt.NoPen)
                halves = ((r, colour),) if colour != "both" else (       # from on the left, into on the right
                    (QtCore.QRectF(r.left(), r.top(), r.width() / 2, r.height()), "from"),
                    (QtCore.QRectF(r.center().x(), r.top(), r.width() / 2, r.height()), "into"))
                for part, col in halves:
                    c = QtGui.QColor(th[col])
                    if not lit:
                        c.setAlpha(90)
                    p.setBrush(c)
                    if len(halves) == 1:
                        p.drawRoundedRect(part, 2.5, 2.5)
                    else:
                        p.drawRect(part)
            cx = x
            for t, col, bold in _spans(text, th):
                p.setFont(view.bold if bold else view.font)
                p.setPen(col if lit else th["faded_text"])
                p.drawText(QtCore.QPointF(cx, y), t)
                cx += (view.fmb if bold else fm).horizontalAdvance(t)

    def _badge(self, p, th):
        """⊕ at the top-right corner: zoom in here to open the function; … while it is being
        made, × when it cannot be decompiled."""
        c = QtCore.QPointF(self.w + 8, -4)
        col = th["label"] if self.on else th["faded_text"]
        if self.state in ("queued", "failed"):
            p.setFont(self.view.label_font)
            p.setPen(col)
            p.drawText(QtCore.QRectF(c.x() - 8, c.y() - 8, 16, 16), QtCore.Qt.AlignCenter,
                       "…" if self.state == "queued" else "×")
            return
        p.setPen(QtGui.QPen(col, 1.1))
        p.setBrush(th["fill"])
        p.drawEllipse(c, 5.0, 5.0)
        p.drawLine(QtCore.QPointF(c.x() - 2.8, c.y()), QtCore.QPointF(c.x() + 2.8, c.y()))
        p.drawLine(QtCore.QPointF(c.x(), c.y() - 2.8), QtCore.QPointF(c.x(), c.y() + 2.8))

    def row_at(self, pos):
        """(line id, text, x of the text, baseline) of the text row at item position pos."""
        fm = self.view.fm
        for row in self.rows:
            lid, text, x, y = row
            if y - fm.ascent() - 2 <= pos.y() <= y + fm.descent() + 2:
                return row
        return None

    def token_at(self, pos):
        row = self.row_at(pos)
        if row is None:
            return None, None
        lid, text, x, y = row
        fm = self.view.fm
        # the chart's own names first: Hex-Rays plugins name variables Key_saved_to:_%s_n
        for m in list(self.frame.names_in(text)) + list(_IDENT.finditer(text)):
            a = x + fm.horizontalAdvance(text[:m.start()])
            b = x + fm.horizontalAdvance(text[:m.end()])
            if a - 2 <= pos.x() <= b + 2:
                return lid, m.group(0)
        return lid, None


class _Flow(QtWidgets.QGraphicsItem):
    """One line of the chart: corners, an arrow at its end, yes / no / a case at its start."""

    def __init__(self, frame, path):
        QtWidgets.QGraphicsItem.__init__(self, frame.holder)
        self.view, self.p = frame.view, path
        self.on = True
        self.qpath = QtGui.QPainterPath(QtCore.QPointF(*path.pts[0]))
        for pt in path.pts[1:]:
            self.qpath.lineTo(QtCore.QPointF(*pt))
        self.text = {"yes": T("yes", "是"), "no": T("no", "否")}.get(path.label, path.label)
        self.setZValue(-1)

    def boundingRect(self):
        r = self.qpath.boundingRect().adjusted(-8, -8, 8, 8)
        if self.text:
            x, y = self.p.pts[0]
            r = r.united(QtCore.QRectF(x - 160, y - 24, 320, 48))
        return r

    def paint(self, p, opt, widget=None):
        th = self.view.th
        col = th["line"] if self.on else th["faded_line"]
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setPen(QtGui.QPen(col, 1.3, QtCore.Qt.SolidLine, QtCore.Qt.FlatCap, QtCore.Qt.MiterJoin))
        p.setBrush(QtCore.Qt.NoBrush)
        p.drawPath(self.qpath)
        pts = self.p.pts
        if self.p.arrow and len(pts) > 1:
            (x1, y1), (x2, y2) = pts[-2], pts[-1]
            d = math.hypot(x2 - x1, y2 - y1) or 1
            ux, uy = (x2 - x1) / d, (y2 - y1) / d
            a, b = 9.0, 4.0
            p.setPen(QtCore.Qt.NoPen)
            p.setBrush(col)
            p.drawPolygon(QtGui.QPolygonF([
                QtCore.QPointF(x2, y2),
                QtCore.QPointF(x2 - ux * a - uy * b, y2 - uy * a + ux * b),
                QtCore.QPointF(x2 - ux * a + uy * b, y2 - uy * a - ux * b)]))
        if self.text and len(pts) > 1:
            f = self.view.label_font
            fm = QtGui.QFontMetricsF(f)
            (x1, y1), (x2, y2) = pts[0], pts[1]
            w = fm.horizontalAdvance(self.text)
            if abs(y1 - y2) < 0.5:                       # leaves sideways: above the line
                x = x1 + 6 if x2 > x1 else x1 - 6 - w
                y = y1 - 5
            else:                     # leaves downwards: on its left (what joins comes from the right)
                x, y = x1 - 6 - w, y1 + fm.ascent() + 2
            p.setFont(f)
            p.setPen(th["label"] if self.on else th["faded_text"])
            p.drawText(QtCore.QPointF(x, y), self.text)


class _Panel(QtWidgets.QGraphicsItem):
    """A called function's chart, opened over its call: a call box (double sides) around it."""

    def __init__(self, view, parent):
        QtWidgets.QGraphicsItem.__init__(self, parent)
        self.view, self.w, self.h = view, 0.0, 0.0
        self.frame = None                          # the chart inside
        self.setZValue(10)                         # over the calling chart's shapes and lines

    def boundingRect(self):
        return QtCore.QRectF(-1, -1, self.w + 2, self.h + 2)

    def paint(self, p, opt, widget=None):
        th = self.view.th
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setPen(QtGui.QPen(th["line"], 1.3))
        p.setBrush(th["fill"])
        p.drawRect(QtCore.QRectF(0, 0, self.w, self.h))
        p.drawLine(QtCore.QPointF(BAR, 0), QtCore.QPointF(BAR, self.h))
        p.drawLine(QtCore.QPointF(self.w - BAR, 0), QtCore.QPointF(self.w - BAR, self.h))


# ---------------------------------------------------------------- one chart
class _Frame:
    """One function's chart in the drawing: the main one at the top, a called one in the
    panel over its call (shape). scale: drawing units per chart unit; eas: the functions open
    from the top down to this one (a call of one of them does not open again)."""

    def __init__(self, view, chart, holder, depth=0, scale=1.0, eas=(), entry=None, shape=None):
        self.view, self.chart, self.holder = view, chart, holder
        self.depth, self.scale, self.eas = depth, scale, tuple(eas)
        self.entry, self.shape, self.panel = entry, shape, None
        self.goal = None                          # the shape whose way is shown, if any
        self.chosen, self.marks, self._mark_rx = (), {}, None
        self.args = {}                            # {call line id: arguments the light goes into}
        self._var = (set(), (), "", {})           # what the variable lights: back to it after a way
        self._ref_rx = _rx(chart.refs)
        self._names = {v: k for k, v in chart.refs.items() if v[0] == "var"}
        sizes = {b.id: view.measure(b) for b in chart.boxes}
        pos, paths, (W, H) = chart.layout(sizes)
        self.shapes = {}
        for b in chart.boxes:
            if b.id in pos:
                it = _Shape(self, b, *sizes[b.id])
                it.setPos(*pos[b.id])
                self.shapes[b.id] = it
        self.flows = [_Flow(self, p) for p in paths]
        self.paths, self.size = paths, (W, H)
        self.calls = [s for s in self.shapes.values() if s.ea is not None]

    @property
    def name(self):
        title = self.chart.boxes[0].lines[0].text if self.chart.boxes else "?"
        return title.split("(")[0]

    def chain(self):
        out, f = [], self
        while f is not None:
            out.append(f)
            f = f.shape.frame if f.shape is not None else None
        return out[::-1]

    def var_name(self, n):
        return self._names.get(("var", n))

    # ---- names in the text ----
    def names_in(self, text):
        """The chart's variables, globals and functions named in a text row (outside strings)."""
        return _outside_strings(self._ref_rx, text)

    def marked(self, text):
        """[(start, end, colour)] of the marked names in a text row."""
        return [(m.start(), m.end(), self.marks[m.group(0)])
                for m in _outside_strings(self._mark_rx, text)]

    # ---- light ----
    def light(self, lit, chosen=(), lines=None, around=None):
        """lit: chart line ids drawn in full; lines: the indexes of the lines between shapes
        drawn in full (None: those that touch a lit shape); around: {name: "from" | "into" |
        "both"} marked next to the chosen names."""
        self.chosen = tuple(chosen)
        self.marks = {n: k for n, k in (around or {}).items() if n not in self.chosen}
        for n in self.chosen:
            self.marks[n] = "mark"
        self._mark_rx = _rx(self.marks)
        for it in self.shapes.values():
            it.lit = {line.id for line in it.box.lines if line.id in lit}
            it.update()
        for i, f in enumerate(self.flows):
            if lines is not None:
                f.on = i in lines
            else:
                ends = [self.shapes.get(b) for b in (f.p.src, f.p.dst) if b is not None]
                f.on = any(s is not None and s.lit for s in ends)
            f.setZValue(-1 if f.on else -2)
            f.update()

    def set_var(self, lit, chosen=(), message="", around=None, args=None):
        self.args = dict(args or {})
        self._var = (set(lit), tuple(chosen), message, dict(around or {}))
        self.goal = None
        self.light(lit, chosen, around=around)

    def all_lit(self):
        self.set_var({line.id for line in self.chart.lines})

    def show_way(self, box):
        """The way from the start to shape `box`: every shape the flow can pass on its way
        there and the exits it takes; the rest faded. None: back to the variable. Returns the
        message to show."""
        if box is None:
            if self.goal is None:
                return None
            self.goal = None
            lit, chosen, message, around = self._var
            self.light(lit, chosen, around=around)
            return message
        on, lines = route(self.paths, self.chart.boxes[0].id, box, self.chart.jumps)
        self.goal = box
        self.light({line.id for b in on for line in self.chart.boxes[b].lines}, (), lines)
        back = ", ".join(self._var[1])
        return T("Esc or click empty space: back to %s" % (back or "the variable"),
                 "Esc 或单击空白处：返回 %s" % (back or "变量高亮"))


# ---------------------------------------------------------------- the view
class GraphView(QtWidgets.QGraphicsView):
    """A function's flowchart, with the charts of the calls zoomed into; focus() lights the
    lines of the followed variable. provider makes the called charts (see flowview._Callees)."""

    def __init__(self, parent, on_key, on_open, provider=None):
        QtWidgets.QGraphicsView.__init__(self, parent)
        self.on_key, self.on_open, self.provider = on_key, on_open, provider
        self.setScene(QtWidgets.QGraphicsScene(self))
        self.setRenderHints(QtGui.QPainter.Antialiasing | QtGui.QPainter.TextAntialiasing)
        self.setDragMode(QtWidgets.QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QtWidgets.QGraphicsView.NoAnchor)   # _zoom keeps the point
        self.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.root, self.frames, self.active = None, [], None
        self.target = None
        self.content = QtCore.QRectF()           # where the drawing is, inside the canvas
        self._anim = None
        # messages sit on the view, not on the viewport: what is on the viewport is moved
        # pixel by pixel when the drawing is dragged
        self.note = QtWidgets.QLabel(self)
        self.legend = QtWidgets.QLabel(self)      # what the colours mean, top left
        for lab in (self.note, self.legend):
            lab.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
            lab.move(14, 8)
            lab.hide()
        self.legend.setTextFormat(QtCore.Qt.RichText)
        self._press = self._click_at = None
        self._click = QtCore.QTimer(self)         # a click waits to see it is not a double-click
        self._click.setSingleShot(True)
        self._click.timeout.connect(self._clicked)
        self._queue = []                          # calls whose charts are to be made, one a turn
        self._loader = QtCore.QTimer(self)
        self._loader.setSingleShot(True)
        self._loader.timeout.connect(self._load_next)
        self._nest_later = QtCore.QTimer(self)    # after a drag: which calls are open
        self._nest_later.setSingleShot(True)
        self._nest_later.timeout.connect(self._update_nest)
        # a picture of the called chart while the mouse rests on its call
        self.peek = QtWidgets.QFrame(self)
        self.peek.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        lay = QtWidgets.QVBoxLayout(self.peek)
        lay.setContentsMargins(8, 6, 8, 8)
        lay.setSpacing(4)
        self.peek_title, self.peek_img = QtWidgets.QLabel(), QtWidgets.QLabel()
        lay.addWidget(self.peek_title)
        lay.addWidget(self.peek_img)
        self.peek.hide()
        self._peek_on, self._peek_cache, self._peek_pos = None, {}, QtCore.QPoint()
        self._peek_timer = QtCore.QTimer(self)
        self._peek_timer.setSingleShot(True)
        self._peek_timer.timeout.connect(self._show_peek)
        self.viewport().setMouseTracking(True)
        self.restyle()

    # the main chart's state, as before charts could open inside calls
    chart = property(lambda self: self.root.chart if self.root else None)
    shapes = property(lambda self: self.root.shapes if self.root else {})
    flows = property(lambda self: self.root.flows if self.root else [])
    paths = property(lambda self: self.root.paths if self.root else [])
    goal = property(lambda self: self.root.goal if self.root else None)
    marks = property(lambda self: self.root.marks if self.root else {})
    chosen = property(lambda self: ", ".join(self.root.chosen) if self.root else "")

    def restyle(self):
        self.th = _theme()
        self.font = _font()
        self.bold = QtGui.QFont(self.font)
        self.bold.setBold(True)
        self.label_font = QtGui.QFont(self.font)
        self.label_font.setPointSizeF(max(self.font.pointSizeF() - 1, 8))
        self.fm, self.fmb = QtGui.QFontMetricsF(self.font), QtGui.QFontMetricsF(self.bold)
        self.setBackgroundBrush(self.th["bg"])
        self.note.setFont(self.font)
        self.legend.setFont(self.label_font)
        self.peek_title.setFont(self.label_font)
        self.peek.setStyleSheet("QFrame { background: %s; border: 1px solid %s; border-radius: 5px; } "
                                "QLabel { border: none; color: %s; }"
                                % (self.th["fill"].name(), self.th["line"].name(), self.th["label"].name()))
        self._peek_cache = {}
        bg = self.th["bg"]
        for lab, col in ((self.note, self.th["message"]), (self.legend, self.th["text"])):
            lab.setStyleSheet("color: %s; background: rgba(%d, %d, %d, 235); padding: 4px 8px; "
                              "border: 1px solid %s; border-radius: 4px;"
                              % (col.name(), bg.red(), bg.green(), bg.blue(),
                                 self.th["faded_line"].name()))

    def say(self, text):
        self.note.setText(text or "")
        self.note.adjustSize()
        self.note.setVisible(bool(text))
        self._place()

    def _place(self):
        """The legend in the top-left corner, a message under it."""
        y = 8
        if self.legend.isVisible():
            self.legend.move(14, y)
            self.legend.raise_()
            y += self.legend.height() + 6
        self.note.move(14, y)
        self.note.raise_()

    def _legend(self):
        """Say what the colours mean in the chart being looked at: its variable's, or a
        clicked step's; for a called chart, which calls lead there."""
        th, rows = self.th, []
        fr = self.active or self.root
        if fr is None:
            return

        def chip(colour, text):
            return ('<span style="background-color:%s; color:%s">&nbsp;%s&nbsp;</span>'
                    % (th[colour].name(), th["text"].name(), html.escape(text)))

        def square(colour):
            return '<span style="color:%s">&#9632;</span>' % th[colour].name()
        if fr is not self.root:
            rows.append(" › ".join(html.escape(f.name) for f in fr.chain()))
        if fr.goal is not None:
            rows.append(square("mark") + " " + T("selected step", "选中步骤"))
            rows.append(square("line") + " " + T("path", "经过路径") + "&nbsp;&nbsp;" +
                        square("faded_line") + " " + T("not on the path", "未经过"))
        elif fr.chosen:
            kinds = set(fr.marks.values())
            rows.append(chip("mark", ", ".join(fr.chosen)) + " " + T("current variable", "当前变量"))
            if "from" in kinds:
                rows.append(chip("from", "▲") + " " + T("source", "来源"))
            if "into" in kinds:
                rows.append(chip("into", "▼") + " " + T("destination", "去向"))
            if "both" in kinds:
                rows.append(chip("from", "▲") + chip("into", "▼") + " " +
                            T("source and destination", "来源兼去向"))
            rows.append(square("line") + " " + T("related steps", "相关步骤") + "&nbsp;&nbsp;" +
                        square("faded_line") + " " + T("other steps", "其余步骤"))
        self.legend.setText("<br>".join(rows))
        self.legend.adjustSize()
        self.legend.setVisible(bool(rows))
        self._place()

    # ---- sizes ----
    def slant(self, h):
        return min(16.0, h * 0.35)

    def _text_size(self, box):
        rows = [t for line in box.lines for t in line.text.split("\n")]
        w = max((self.fm.horizontalAdvance(t) for t in rows), default=10)
        h = len(rows) * self.fm.lineSpacing() - self.fm.leading()
        return w, h

    def measure(self, box):
        tw, th = self._text_size(box)
        k = box.kind
        if k in ("decision", "switch"):
            p, q = tw / 2 + 6, th / 2 + 3
            b = max(p / RATIO + q, 22.0)
            return 2 * RATIO * b, 2 * b
        h = th + 2 * PAD_Y
        if k == "io":
            return tw + 2 * PAD_X + 2 * self.slant(h), h
        if k == "call":
            return tw + 2 * PAD_X + 2 * BAR, h
        if k in ("start", "end", "return"):
            return max(tw + 2 * PAD_X + h * 0.6, 72), h
        if k == "connector":
            d = max(tw + 12, th + 12, 28)
            return d, d
        return tw + 2 * PAD_X, h

    def rows(self, box, w, h):
        """Where each row of a box's text goes: [(line id, text, x, baseline)]."""
        fm = self.fm
        rows = [(line.id, t) for line in box.lines for t in line.text.split("\n")]
        tw, th = self._text_size(box)
        y = (h - th) / 2 + fm.ascent()
        out = []
        centred = box.kind in ("decision", "switch", "start", "end", "return", "connector")
        left = PAD_X + (self.slant(h) if box.kind == "io" else BAR if box.kind == "call" else 0)
        for lid, t in rows:
            x = (w - fm.horizontalAdvance(t)) / 2 if centred else left
            out.append((lid, t, x, y))
            y += fm.lineSpacing()
        return out

    # ---- building ----
    def build(self, chart):
        """Lay out and draw a chart; the drawing stays until build() is called again."""
        self._hide_peek()
        self._peek_cache = {}
        self._queue = []
        self._loader.stop()
        self.scene().clear()
        if self.provider is not None:
            self.provider.clear()
        holder = _Holder()
        self.scene().addItem(holder)
        self.root = _Frame(self, chart, holder, eas=(getattr(chart, "ea", None),))
        self.frames, self.active = [self.root], None
        W, H = self.root.size
        self.content = QtCore.QRectF(0, 0, W, H)
        self.resetTransform()
        self._canvas()

    def _extent(self):
        r = QtCore.QRectF(0, 0, *self.root.size) if self.root else QtCore.QRectF()
        for f in self.frames:
            if f.panel is not None and f.panel.isVisible():
                r = r.united(f.panel.sceneBoundingRect())
        return r

    def _canvas(self, z=None):
        """A canvas, not a page: it reaches a window's size past the drawing on every side, so
        any part of the drawing can be dragged to any spot on screen, but not out of sight."""
        if self.content.isEmpty():
            return
        z = z or self.transform().m11()
        vp = self.viewport().size()
        mx, my = max(vp.width() - KEEP, 0) / z, max(vp.height() - KEEP, 0) / z
        c = self.mapToScene(self.viewport().rect().center())
        self.scene().setSceneRect(self.content.adjusted(-mx, -my, mx, my))
        self.centerOn(c)

    def _zmax(self):
        """Further in, the deeper the open charts are drawn."""
        deep = min([f.scale for f in self.frames if f.panel is None or f.panel.isVisible()] or [1.0])
        return ZOOM[1] / deep

    def _zoom(self, f, at=None):
        """Scale by f within ZOOM, keeping the drawing's point at viewport position `at` (the
        mouse; the middle when it is outside) where it is."""
        z = self.transform().m11()
        f = max(ZOOM[0] / z, min(self._zmax() / z, f))
        if abs(f - 1) < 1e-4:
            return
        if at is None:
            at = self.viewport().mapFromGlobal(QtGui.QCursor.pos())
            if not self.viewport().rect().contains(at):
                at = self.viewport().rect().center()
        at = QtCore.QPoint(int(round(at.x())), int(round(at.y())))
        keep = self.mapToScene(at)
        self._canvas(min(z, z * f))             # room for that point to stay put
        self.scale(f, f)
        self._canvas()
        mid = self.mapToScene(self.viewport().rect().center())
        self.centerOn(mid + (keep - self.mapToScene(at)))
        self._update_nest()

    # ---- calls opened inside calls ----
    def _reach(self, sh):
        """How many times its size a call is drawn."""
        return self.transform().m11() * sh.frame.scale

    def _in_middle(self, sh):
        """The call is near the middle of the window and no open chart lies over it."""
        rect = sh.mapToScene(QtCore.QRectF(0, 0, sh.w, sh.h)).boundingRect()
        r = self.mapFromScene(rect).boundingRect()
        vp = self.viewport().rect()
        if not nest.middle((r.x(), r.y(), r.width(), r.height()), (vp.width(), vp.height())):
            return False
        mine = sh.frame.chain()                   # the charts it is inside lie around it, not over
        return not any(f.panel is not None and f.panel.isVisible() and f not in mine
                       and f.panel.sceneBoundingRect().intersects(rect) for f in self.frames)

    def _update_nest(self):
        """Open the calls zoomed into (making their charts first, one at a time), fade them in
        and out with the zoom, drop those zoomed out of."""
        if self.root is None or self.provider is None:
            return
        seen = self.mapToScene(self.viewport().rect()).boundingRect()
        if self.transform().m11() * min(f.scale for f in self.frames) < nest.CLOSE and len(self.frames) == 1:
            self._find_active()
            return                                # nothing open, nothing near opening
        changed = False
        for fr in list(self.frames):
            if fr not in self.frames or (fr.panel is not None and not fr.panel.isVisible()):
                continue
            for sh in fr.calls:
                r = self._reach(sh)
                if sh.panel is not None:
                    if r < nest.CLOSE:
                        self._close(sh)
                        changed = True
                        continue
                    op = nest.opening(r)
                    if abs(sh.panel.opacity() - op) > 1e-3:
                        sh.panel.setOpacity(op)
                    if sh.panel.isVisible() != (op > 0.01):
                        sh.panel.setVisible(op > 0.01)
                        changed = True
                elif r >= nest.PREFETCH and self._in_middle(sh):
                    entry = self.provider.cached(sh.ea)
                    if entry is not None:
                        self._open(sh, entry, r)
                        changed = True
                    elif sh.state is None:
                        sh.state = "queued"
                        sh.update()
                        self._queue.append(sh)
                        self._loader.start(0)
                elif sh.state == "queued" and r < nest.CLOSE:
                    sh.state = None
                    sh.update()
        self._limit(seen)
        if changed:
            self.content = self._extent()
            self._canvas()
        self._find_active()

    def _limit(self, seen):
        """At most MAX_OPEN charts open: those out of sight go first, then the least zoomed into."""
        open_ = [f.shape for f in self.frames if f.shape is not None and f.shape.panel is not None]
        if len(open_) <= nest.MAX_OPEN:
            return
        open_.sort(key=lambda sh: (sh.panel.sceneBoundingRect().intersects(seen), self._reach(sh)))
        for sh in open_[:len(open_) - nest.MAX_OPEN]:
            if sh.panel is not None:
                self._close(sh)

    def _load_next(self):
        """Make one queued chart (decompiling takes a moment); the next on the next turn."""
        while self._queue:
            sh = self._queue.pop(0)
            try:
                alive = sh.scene() is not None and sh.state == "queued"
            except RuntimeError:                  # dropped with the chart it was in
                alive = False
            if not alive:
                continue
            if self._reach(sh) < nest.PREFETCH:   # zoomed out again meanwhile
                sh.state = None
                sh.update()
                continue
            try:
                self.provider.load(sh.ea)
                sh.state = None
            except Exception:
                sh.state = "failed"
            sh.update()
            self._update_nest()
            break
        if self._queue:
            self._loader.start(0)

    def _open(self, sh, entry, r):
        """The called chart in a panel over its call, faded in as far as r says."""
        fr = sh.frame
        panel = _Panel(self, fr.holder)
        holder = _Holder(panel)
        child = _Frame(self, entry.chart, holder, depth=fr.depth + 1, eas=fr.eas + (sh.ea,),
                       entry=entry, shape=sh)
        x, y, w, h, s = nest.panel((sh.pos().x(), sh.pos().y(), sh.w, sh.h), child.size)
        panel.prepareGeometryChange()
        panel.setPos(x, y)
        panel.w, panel.h = w, h
        holder.setPos(nest.PAD, nest.PAD)
        holder.setScale(s)
        child.scale = fr.scale * s
        child.panel, panel.frame, sh.panel = panel, child, panel
        op = nest.opening(r)
        panel.setOpacity(op)
        panel.setVisible(op > 0.01)
        self.frames.append(child)
        self._light_inside(child)

    def _close(self, sh):
        """Drop a call's open chart and every chart opened inside it."""
        panel = sh.panel
        if panel is None:
            return
        gone = {f for f in self.frames if any(g.shape is sh for g in f.chain())}
        self.frames = [f for f in self.frames if f not in gone]
        for f in gone:
            for c in f.calls:
                c.panel = None
        sh.panel = None
        if self.active in gone:
            self.active = None
        self.scene().removeItem(panel)
        sh.update()

    def _light_inside(self, child):
        """What a called chart lights: the arguments the light outside is handed over in (the
        followed value, one computed from it, a pointer to its memory), else everything."""
        at = child.shape.frame.args.get(child.shape.line.id, ())
        if at:
            lit, chosen, around, args = self.provider.args(child.entry, at)
            child.set_var(lit, chosen, "", around, args)
        else:
            child.all_lit()

    def _find_active(self):
        """The chart being looked at: the deepest fully open one under the window's middle."""
        mid = self.mapToScene(self.viewport().rect().center())
        best = self.root
        for f in self.frames:
            if (f.panel is not None and f.panel.isVisible() and f.panel.opacity() > 0.99
                    and f.panel.sceneBoundingRect().contains(mid) and f.depth > best.depth):
                best = f
        best = None if best is self.root else best
        if best is not self.active:
            self.active = best
            self._legend()

    def scrollContentsBy(self, dx, dy):
        QtWidgets.QGraphicsView.scrollContentsBy(self, dx, dy)
        self._nest_later.start(40)

    # ---- light ----
    def show_way(self, box, frame=None):
        """The way to shape `box` in a chart (the main one by default); None: back."""
        frame = frame or self.root
        if frame is None:
            return
        msg = frame.show_way(box)
        if msg is not None:
            self.say(msg)
        self._legend()
        self.viewport().update()

    def focus(self, lit, chosen="", message="", around=None, args=None, animate=True):
        """Full colour for the lit lines (and the shapes and lines that join them), the name
        of the followed variable marked and the names around it (from / into), the rest
        faded; the open charts of calls follow the arguments the light is handed over in."""
        root = self.root
        self._peek_cache = {}
        root.set_var(lit, (chosen,) if chosen else (), message, around, args)
        for f in self.frames[1:]:
            self._light_inside(f)
        self.say(message)
        self._legend()
        self.target = None
        first = None
        for line in root.chart.lines:
            if line.id in lit and line.box in root.shapes:
                first = first or line
                if chosen and re.search(r"(?<![\w])%s(?![\w])" % re.escape(chosen), line.text):
                    self.target = line
                    break
        self.target = self.target or first
        self.home(animate)
        self.viewport().update()

    def line_point(self, line, frame=None):
        """The middle of a line's text, in the drawing."""
        it = (frame or self.root).shapes[line.box]
        rows = [r for r in it.rows if r[0] == line.id]
        _, text, x, y = rows[0]
        return it.mapToScene(QtCore.QPointF(x + self.fm.horizontalAdvance(text) / 2,
                                            y - self.fm.ascent() / 2))

    def home(self, animate=False):
        """The followed variable's first line in the middle of the window; with none, a new
        drawing shows its top and a moved one stays where it is."""
        if self.target is not None:
            p = self.line_point(self.target)
            top = self.content.top() + self.viewport().height() / self.transform().m11() / 2
            if not animate and p.y() < top:       # near the start: show the start too
                p.setY(top)
            self.center_on(p, animate)
        elif not animate:
            h = self.viewport().height() / self.transform().m11()
            self.centerOn(self.content.center().x(),
                          self.content.top() + min(h, self.content.height()) / 2)

    def center_on(self, dest, animate=True):
        if not animate or not self.isVisible():
            self.centerOn(dest)
            return
        start = self.mapToScene(self.viewport().rect().center())
        a = QtCore.QVariantAnimation(self)
        a.setStartValue(QtCore.QPointF(start))
        a.setEndValue(QtCore.QPointF(dest))
        a.setDuration(220)
        a.setEasingCurve(QtCore.QEasingCurve.OutCubic)
        a.valueChanged.connect(lambda v: self.centerOn(v))
        a.start()
        self._anim = a

    def resizeEvent(self, ev):
        QtWidgets.QGraphicsView.resizeEvent(self, ev)
        self._canvas()
        self._nest_later.start(40)

    def drawBackground(self, p, rect):
        """Faint dots that move with the drawing, so a drag over empty space can be seen."""
        p.fillRect(rect, self.th["bg"])
        z = self.transform().m11()
        step = float(GRID)
        while step * z < 16:
            step *= 2
        while step * z > 64:
            step /= 2
        x0, y0 = math.floor(rect.left() / step) * step, math.floor(rect.top() / step) * step
        nx, ny = int((rect.right() - x0) / step) + 1, int((rect.bottom() - y0) / step) + 1
        if nx * ny > 40000:
            return
        pen = QtGui.QPen(self.th["grid"], 2)
        pen.setCosmetic(True)
        pen.setCapStyle(QtCore.Qt.RoundCap)
        p.setPen(pen)
        p.drawPoints(QtGui.QPolygonF([QtCore.QPointF(x0 + i * step, y0 + j * step)
                                      for i in range(nx) for j in range(ny)]))

    # ---- input ----
    # ---- a preview of the chart a call opens ----
    def _peek_at(self, vpos):
        """The call under the mouse that would open, if it is not open yet."""
        frame, sh = self._under(vpos)
        if sh is None or sh.ea is None or sh.state == "failed":
            return None
        if sh.panel is not None and sh.panel.isVisible() and sh.panel.opacity() > 0.5:
            return None
        return sh

    def _hide_peek(self):
        self._peek_timer.stop()
        self._peek_on = None
        self.peek.hide()

    def _peek_image(self, sh):
        """The called chart drawn small, lit as it would be when opened. Made on a scene of its
        own, then dropped; kept per call until the light or the drawing changes."""
        key = (id(sh.frame), sh.box.id)
        if key in self._peek_cache:
            return self._peek_cache[key]
        try:
            entry = self.provider.load(sh.ea)
        except Exception:
            sh.state = "failed"
            sh.update()
            return None
        scene = QtWidgets.QGraphicsScene()
        holder = _Holder()
        scene.addItem(holder)
        fr = _Frame(self, entry.chart, holder, depth=nest.MAX_DEPTH, eas=sh.frame.eas + (sh.ea,),
                    entry=entry, shape=sh)
        self._light_inside(fr)
        W, H = fr.size
        k = min(460.0 / max(W, 1), 340.0 / max(H, 1), 0.7)
        dpr = self.devicePixelRatioF()
        pix = QtGui.QPixmap(int(W * k * dpr) + 1, int(H * k * dpr) + 1)
        pix.setDevicePixelRatio(dpr)
        pix.fill(self.th["fill"])
        p = QtGui.QPainter(pix)
        p.setRenderHints(QtGui.QPainter.Antialiasing | QtGui.QPainter.TextAntialiasing)
        scene.render(p, QtCore.QRectF(0, 0, W * k, H * k), QtCore.QRectF(0, 0, W, H))
        p.end()
        scene.clear()
        self._peek_cache[key] = (fr.name, pix)
        return self._peek_cache[key]

    def _show_peek(self):
        sh = self._peek_on
        if sh is None:
            return
        try:
            got = self._peek_image(sh)
        except RuntimeError:                      # the call was dropped meanwhile
            got = None
        if got is None or self._peek_on is not sh:
            return
        name, pix = got
        self.peek_title.setText("%s  ·  %s" % (name, T("zoom in to open", "滚轮放大展开")))
        self.peek_img.setPixmap(pix)
        self.peek.adjustSize()
        self._place_peek(self._peek_pos)
        self.peek.show()
        self.peek.raise_()

    def _place_peek(self, pos):
        """Beside the mouse, inside the window."""
        w, h = self.peek.width(), self.peek.height()
        x, y = pos.x() + 18, pos.y() + 20
        if x + w > self.width() - 6:
            x = pos.x() - 18 - w
        if y + h > self.height() - 6:
            y = max(6, pos.y() - 20 - h)
        self.peek.move(max(6, x), y)

    def mouseMoveEvent(self, ev):
        QtWidgets.QGraphicsView.mouseMoveEvent(self, ev)
        if ev.buttons() or self.provider is None or self.root is None:
            self._hide_peek()
            return
        sh = self._peek_at(ev.pos())
        self._peek_pos = self.viewport().mapTo(self, ev.pos())
        if sh is not self._peek_on:
            self._hide_peek()
            if sh is not None:
                self._peek_on = sh
                self._peek_timer.start(350)
        elif sh is not None and self.peek.isVisible():
            self._place_peek(self._peek_pos)

    def leaveEvent(self, ev):
        self._hide_peek()
        QtWidgets.QGraphicsView.leaveEvent(self, ev)

    def wheelEvent(self, ev):
        """The wheel zooms about the mouse, by how far it turned (a fine-notched wheel or a
        touchpad zooms smoothly); Shift+wheel, or a sideways swipe, goes sideways."""
        self._hide_peek()
        d = ev.angleDelta()
        if ev.modifiers() & QtCore.Qt.ShiftModifier or (d.x() and not d.y()):
            bar = self.horizontalScrollBar()
            step = QtWidgets.QApplication.wheelScrollLines() * bar.singleStep()
            bar.setValue(bar.value() - int((d.y() or d.x()) / 120 * step))
        elif d.y():
            at = ev.position() if hasattr(ev, "position") else ev.pos()
            self._zoom(STEP ** (d.y() / 120), at)
        ev.accept()

    def _under(self, vpos):
        """(frame, shape or None) under a viewport position: the topmost chart there."""
        for it in self.items(vpos):
            if isinstance(it, _Shape):
                return it.frame, it
            if isinstance(it, _Panel) and it.frame is not None:
                return it.frame, None
        return self.root, None

    def _shape_at(self, vpos):
        return self._under(vpos)[1]

    def mousePressEvent(self, ev):
        self._hide_peek()
        self._press = ev.pos()
        QtWidgets.QGraphicsView.mousePressEvent(self, ev)

    def mouseReleaseEvent(self, ev):
        QtWidgets.QGraphicsView.mouseReleaseEvent(self, ev)
        if (ev.button() == QtCore.Qt.LeftButton and self._press is not None
                and (ev.pos() - self._press).manhattanLength() < 5):       # a click, not a drag
            self._click_at = ev.pos()
            self._click.start(QtWidgets.QApplication.doubleClickInterval())
        self._press = None

    def _clicked(self):
        if self.root is None or self._click_at is None:
            return
        frame, it = self._under(self._click_at)
        self.show_way(it.box.id if it is not None else None, frame)

    def hit(self, vpos):
        """(line, identifier or None) under a viewport position, or (None, None)."""
        frame, line, word = self._hit(vpos)
        return line, word

    def _hit(self, vpos):
        frame, it = self._under(vpos)
        if it is not None:
            lid, word = it.token_at(it.mapFromScene(self.mapToScene(vpos)))
            if lid is not None:
                return frame, frame.chart.lines[lid], word
        return frame, None, None

    def mouseDoubleClickEvent(self, ev):
        self._click.stop()
        frame, line, word = self._hit(ev.pos())
        if word and frame is not None and word in frame.chart.refs:
            kind, x = frame.chart.refs[word]
            if kind == "func":
                self.on_open("func", x)
            elif frame is self.root:
                self.on_open("follow", (kind, x))
            else:                                 # inside a called chart: follow it there
                lit, chosen, around, args, msg = self.provider.follow(frame.entry, (kind, x))
                frame.set_var(lit, chosen, msg, around, args)
                for f in self.frames:
                    if f is not frame and frame in f.chain():
                        self._light_inside(f)
                self.say(msg)
                self._legend()
            ev.accept()
            return
        it = self._shape_at(ev.pos())
        if it is not None:
            self.show_way(it.box.id, it.frame)
            ev.accept()
            return
        QtWidgets.QGraphicsView.mouseDoubleClickEvent(self, ev)

    def keyPressEvent(self, ev):
        k, mods = ev.key(), ev.modifiers()
        ctrl, alt = bool(mods & QtCore.Qt.ControlModifier), bool(mods & QtCore.Qt.AltModifier)
        if k in (QtCore.Qt.Key_Plus, QtCore.Qt.Key_Equal, QtCore.Qt.Key_Minus) and not alt:
            self._zoom(STEP if k != QtCore.Qt.Key_Minus else 1 / STEP)
            return
        if k == QtCore.Qt.Key_0 and ctrl:
            self.resetTransform()
            self._canvas()
            self._update_nest()
            return
        if k == QtCore.Qt.Key_Escape:
            ways = [f for f in self.frames if f.goal is not None]
            if ways:
                for f in sorted(ways, key=lambda f: f is not self.active):
                    self.show_way(None, f)
                    break
                return
        vk = {QtCore.Qt.Key_Space: 0x20, QtCore.Qt.Key_Escape: 0x1B, QtCore.Qt.Key_Return: 0x0D,
              QtCore.Qt.Key_Enter: 0x0D, QtCore.Qt.Key_Left: 0x25, QtCore.Qt.Key_Right: 0x27}.get(k)
        if vk == 0x0D and not ctrl:
            line, _ = self.hit(self.mapFromGlobal(QtGui.QCursor.pos()))
            line = line or self.target
            if line is not None:
                self.on_open("jump", line)
            return
        if vk is not None and self.on_key(vk, ctrl, alt):
            ev.accept()
            return
        QtWidgets.QGraphicsView.keyPressEvent(self, ev)

    def event(self, ev):
        if ev.type() == QtCore.QEvent.ShortcutOverride:
            k, mods = ev.key(), ev.modifiers()
            if k in (QtCore.Qt.Key_Escape, QtCore.Qt.Key_Space, QtCore.Qt.Key_Return,
                     QtCore.Qt.Key_Enter) or (mods & QtCore.Qt.AltModifier and
                                              k in (QtCore.Qt.Key_Left, QtCore.Qt.Key_Right)):
                ev.accept()
                return True
        return QtWidgets.QGraphicsView.event(self, ev)


class GraphForm(ida_kernwin.PluginForm):
    """The dockable IDA window around a GraphView."""

    def __init__(self, on_key, on_open, on_close, provider=None):
        ida_kernwin.PluginForm.__init__(self)
        self._args = (on_key, on_open, provider)
        self._on_close = on_close
        self.view = None
        self.shown = None           # the chart on screen (identity), so a refocus is cheap

    def OnCreate(self, form):
        from .qt import qwidget
        w = qwidget(form)
        lay = QtWidgets.QVBoxLayout()
        lay.setContentsMargins(0, 0, 0, 0)
        self.view = GraphView(w, *self._args)
        lay.addWidget(self.view)
        w.setLayout(lay)
        w.setFocusProxy(self.view)          # keys go to the drawing, not to IDA's frame

    def OnClose(self, form):
        self._on_close(self)

    def Close(self, options=0):
        return ida_kernwin.PluginForm.Close(self, options)

    def show_graph(self, chart, lit, chosen="", message="", around=None, args=None, take_focus=True):
        fresh = self.shown is not chart
        if fresh:
            self.view.build(chart)
            self.shown = chart
        self.view.focus(lit, chosen, message, around, args, animate=not fresh)
        if fresh:
            QtCore.QTimer.singleShot(60, lambda: self._recenter())
        if take_focus:
            self.view.setFocus()

    def _recenter(self):
        try:
            self.view.home()
            self.view._update_nest()
        except Exception:
            pass
