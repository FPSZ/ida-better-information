"""Layout of a program flowchart, drawn the way textbooks draw one (GB/T 1526, ISO 5807):
the steps one under another in program order on one straight line, a condition's other
branch in a column to its right, a loop's way back on its left and its way out on its right,
every line horizontal or vertical.

The input is the statement structure (the classes below) with the size of every shape; the
layout follows that structure, so nothing is searched and nothing moves when a different
variable is lit. Pure Python, no IDA."""

VG = 26         # between one step and the next
VL = 34         # the same below a condition, where its exit carries "yes" / "no"
HG = 34         # between a column and the line or column beside it
J = 14          # above a loop's condition, where the way back comes in
LABEL = 18      # height kept free above a horizontal line for its label


# ---------------------------------------------------------------- the structure
class Seq:
    def __init__(self, items):
        self.items = list(items)


class Leaf:
    """One shape the flow goes through."""
    def __init__(self, box):
        self.box = box


class Stop:
    """One shape the flow ends in: a return, a goto's connector, the end."""
    def __init__(self, box):
        self.box = box


class If:
    def __init__(self, box, yes, no=None):
        self.box, self.yes, self.no = box, yes, no


class While:
    """The condition first; `step` (a for loop's) runs after the body; forever: no way out
    but a break."""
    def __init__(self, box, body, step=None, forever=False):
        self.box, self.body, self.step, self.forever = box, body, step, forever


class DoWhile:
    def __init__(self, body, box):
        self.body, self.box = body, box


class Switch:
    """cases: [(label, body)]; a case without a break runs on into the next one."""
    def __init__(self, box, cases, default=False):
        self.box, self.cases, self.default = box, list(cases), default


class Break:
    pass


class Continue:
    pass


# ---------------------------------------------------------------- the result
class Path:
    """A line: pts from the start to the arrow's tip. src / dst: the shapes it joins (dst None
    while it is still open). label: "yes" / "no" / a case, written at its start."""
    __slots__ = ("pts", "src", "dst", "label", "arrow")

    def __init__(self, pts, src, label=None, arrow=True):
        self.pts, self.src, self.dst, self.label, self.arrow = list(pts), src, None, label, arrow

    def to(self, *pts):
        for p in pts:
            if p != self.pts[-1]:
                self.pts.append(p)
        return self


class _G:
    """A laid-out piece. Its line runs down x = 0: in at (0, entry), out at (0, h).
    opens: paths that go on to whatever comes next, ending at (0, h); breaks / conts: paths
    that go to the enclosing loop's exit or next round."""

    def __init__(self):
        self.pos, self.paths = {}, []
        self.opens, self.breaks, self.conts = [], [], []
        self.wl = self.wr = self.h = self.entry = 0.0
        self.first = None
        self.side = None        # (left edge, bottom) of a right column that does not come back:
                                # what follows may go beside it, h only covers the main line

    def empty(self):
        return not self.pos

    def jump_only(self):
        return self.empty() and not self.opens and bool(self.breaks or self.conts)

    def take(self, o, dx, dy):
        """o's shapes and lines, moved by (dx, dy); o's open ends are moved, not taken."""
        for k, (x, y) in o.pos.items():
            self.pos[k] = (x + dx, y + dy)
        for p in o.paths + o.opens + o.breaks + o.conts:
            p.pts = [(x + dx, y + dy) for x, y in p.pts]
        self.paths += o.paths
        self.breaks += o.breaks
        self.conts += o.conts


def _leaf(box, sizes, falls=True):
    w, h = sizes[box]
    g = _G()
    g.pos[box] = (-w / 2, 0.0)
    g.wl = g.wr = w / 2
    g.h, g.first = h, box
    if falls:
        g.opens = [Path([(0.0, h)], box)]
    return g


def _lay(n, sizes):
    if n is None:
        return _G()
    if isinstance(n, Seq):
        return _seq(n, sizes)
    if isinstance(n, Leaf):
        return _leaf(n.box, sizes)
    if isinstance(n, Stop):
        return _leaf(n.box, sizes, falls=False)
    if isinstance(n, If):
        return _if(n, sizes)
    if isinstance(n, While):
        return _while(n, sizes)
    if isinstance(n, DoWhile):
        return _do(n, sizes)
    if isinstance(n, Switch):
        return _switch(n, sizes)
    g = _G()
    (g.breaks if isinstance(n, Break) else g.conts).append(Path([(0.0, 0.0)], None))
    return g


def _seq(n, sizes):
    """One under another. A step goes beside the right column of a condition above it (an
    error branch that returns) when it fits on the left of it, so the main line does not wait
    for the column to end."""
    g = _G()
    y, opens, started = 0.0, None, False
    columns = []                                  # (left edge, bottom) of such columns
    for it in n.items:
        if isinstance(it, (Break, Continue)):
            if opens is not None:                 # the flow so far leaves the loop here
                low = max([y1 for _, y1 in columns if y1 > y], default=None)
                if low is not None:               # below a column beside it first, then right
                    y = low + VG / 2
                    for p in opens:
                        p.to((p.pts[-1][0], y))
                (g.breaks if isinstance(it, Break) else g.conts).extend(opens)
                opens = []
            elif not started:
                return _lay(it, sizes)
            continue
        c = _lay(it, sizes)
        if c.empty():
            continue
        if started:
            y += VG
        for x0, y1 in columns:                    # a line leaving to the right would cross it
            if c.wr + HG > x0 or c.breaks or c.conts:
                y = max(y, y1 + VG)
        for p in opens or ():
            p.to((0.0, y + c.entry))
            p.dst = c.first
            g.paths.append(p)
        g.take(c, 0.0, y)
        if not started:
            g.first, g.entry = c.first, c.entry
        if c.side is not None:
            columns.append((c.side[0], y + c.side[1]))
        opens = c.opens
        y += c.h
        g.wl, g.wr = max(g.wl, c.wl), max(g.wr, c.wr)
        started = True
    h = max([y] + [y1 for _, y1 in columns])
    for p in opens or ():
        p.to((0.0, h))
    g.h = h
    g.opens = opens if opens is not None else []
    return g


def _if(n, sizes):
    """The branch that goes on runs straight down; the other one in a column on the right
    (a branch that ends in a return sits there, so the main line stays straight)."""
    D = n.box
    dw, dh = sizes[D]
    yes, no = _lay(n.yes, sizes), _lay(n.no, sizes)
    yes = None if yes.empty() and not yes.jump_only() else yes
    no = None if no.empty() and not no.jump_only() else no
    falls = lambda c: c is not None and (bool(c.opens) or c.empty() and not c.jump_only())
    if no is not None and no.jump_only():         # a break / continue leaves by the right corner
        down, side, dl, sl = yes, no, "yes", "no"
    elif yes is not None and (yes.jump_only() or not falls(yes) and (no is None or falls(no))):
        down, side, dl, sl = no, yes, "no", "yes"
    else:
        down, side, dl, sl = yes, no, "yes", "no"
    g = _G()
    g.pos[D] = (-dw / 2, 0.0)
    g.first = D
    g.wl, g.wr = dw / 2, dw / 2
    right = (dw / 2, dh / 2)
    bottom = (0.0, dh)
    # a branch that only breaks or continues leaves the diamond's corner straight for the loop
    for c, at, lab in ((side, right, sl), (down, bottom, dl)):
        if c is not None and c.jump_only():
            p = Path([at], D, lab)
            (g.breaks if c.breaks else g.conts).append(p)
    if side is not None and side.jump_only():
        side = None
        sl = None
    if down is not None and down.jump_only():
        down = None
        dl = None
    # straight down
    bot = dh
    down_opens = []
    if down is not None:
        y = dh + VL
        g.paths.append(Path([bottom, (0.0, y + down.entry)], D, dl))
        g.paths[-1].dst = down.first
        g.take(down, 0.0, y)
        bot = y + down.h
        down_opens = down.opens
        g.wl, g.wr = max(g.wl, down.wl), max(g.wr, down.wr)
    elif dl is not None:
        bot = dh + VL - VG                        # room for the label
        down_opens = [Path([bottom, (0.0, bot)], D, dl)]
    # the column on the right: beyond everything on the main branch; a column that ends
    # (a return) only beyond what is beside it, so it stays near its condition
    side_opens, side_bot = [], 0.0
    xs = max(dw / 2, g.wr) + HG
    if side is not None and not side.opens and down is not None and not (down.breaks or down.conts):
        top = dh / 2 + LABEL + 8
        lines = down.paths + down.opens + down.breaks + down.conts     # already moved into place
        xs = max(dw / 2, _right_edge(g.pos, down.pos, lines, sizes, top, top + side.h)) + HG
    if side is not None:
        x = xs + side.wl
        y = dh / 2 + LABEL + 8
        p = Path([right, (x, dh / 2), (x, y + side.entry)], D, sl)
        p.dst = side.first
        g.paths.append(p)
        g.take(side, x, y)
        side_bot = y + side.h
        for q in side.opens:
            side_opens.append(q)
        g.wr = max(g.wr, x + side.wr)
        sx = x
    elif sl is not None:
        side_opens = [Path([right, (xs, dh / 2)], D, sl)]
        side_bot = dh / 2
        sx = xs
        g.wr = max(g.wr, xs + 4)
    # breaks and continues from the main branch would cross the column on their way right:
    # they go down the gap between the two first, and leave below
    jumps = [q for q in g.breaks + g.conts if side is not None and q.pts[-1][0] < sx - side.wl]
    if side is not None and not side_opens and not jumps:   # what follows may go beside it
        g.side = (sx - side.wl, side_bot)
        h = bot
    else:
        h = max(bot, side_bot)
    if side_opens:
        h += VG / 2                               # the side branch comes back in below
        for q in side_opens:
            q.to((sx, h), (0.0, h))
    for q in down_opens:
        q.to((0.0, h))
    if jumps:
        lane = sx - side.wl - HG / 2
        h += VG / 2
        for q in jumps:
            x, y = q.pts[-1]
            q.to((lane, y), (lane, h))
        for q in down_opens + side_opens:
            q.to((0.0, h))
    g.opens = down_opens + side_opens
    g.h = h
    return g


def _right_edge(pos, keys, paths, sizes, y0, y1):
    """How far right the shapes `keys` (at pos) and the lines reach between heights y0 and y1."""
    edge = 0.0
    for k in keys:
        (x, y), (w, h) = pos[k], sizes[k]
        if y < y1 and y + h > y0:
            edge = max(edge, x + w)
    for p in paths:
        for (xa, ya), (xb, yb) in zip(p.pts, p.pts[1:]):
            if min(ya, yb) <= y1 and max(ya, yb) >= y0:
                edge = max(edge, xa, xb)
    return edge


def _route_out(paths, xr, ye):
    """Breaks: right to the exit line, down it, and in to the main line below the loop."""
    for p in paths:
        x, y = p.pts[-1]
        p.to((xr, y), (xr, ye), (0.0, ye))


def _while(n, sizes):
    D = n.box
    dw, dh = sizes[D]
    g = _G()
    g.first, g.entry = D, J
    g.pos[D] = (-dw / 2, J)
    body = _lay(n.body, sizes)
    step = _leaf(n.step, sizes) if n.step is not None else None
    y = J + dh + VL
    tail = [Path([(0.0, J + dh)], D, "yes")]
    conts = []
    wl, wr = dw / 2, dw / 2
    for part in (body, step):
        if part is None:
            continue
        if part.jump_only():                      # while (x) break; / continue;
            (g.breaks if part.breaks else conts).extend(tail)
            tail = []
            continue
        if part.empty():
            continue
        for p in tail:
            p.to((0.0, y + part.entry))
            p.dst = part.first
            g.paths.append(p)
        if part is step and conts:                # continue: in from the right, above the step
            yc = y - VG / 2
            xc = max(wr, step.wr) + HG / 2        # inside the way out (wr + HG)
            for p in conts:
                px, py = p.pts[-1]
                p.to((xc, py), (xc, yc), (0.0, yc))
                p.dst = part.first
                g.paths.append(p)
            conts = []
        g.take(part, 0.0, y)
        conts += part.conts
        g.conts = []
        tail = part.opens
        y += part.h + VG
        wl, wr = max(wl, part.wl), max(wr, part.wr)
    yb = y - VG / 2                               # the way back starts here
    xl = -(wl + HG)
    for p in tail:
        p.to((0.0, yb), (xl, yb), (xl, J / 2), (0.0, J / 2))
        p.dst = D
        g.paths.append(p)
    xr = wr + HG                                  # the way out
    if conts:                                     # continue: up the right, in above the condition
        xc = xr + HG
        for p in conts:
            px, py = p.pts[-1]
            p.to((xc, py), (xc, J / 2), (0.0, J / 2))
            p.dst = D
            g.paths.append(p)
    ye = yb + VG / 2 + 4
    outs = []
    if not n.forever:
        outs.append(Path([(dw / 2, J + dh / 2), (xr, J + dh / 2), (xr, ye), (0.0, ye)], D, "no"))
    breaks, g.breaks = g.breaks, []
    _route_out(breaks, xr, ye)
    g.opens = outs + breaks
    g.wl, g.wr = -xl + 4, xr + (HG if conts else 4)
    g.h = ye
    return g


def _do(n, sizes):
    D = n.box
    dw, dh = sizes[D]
    g = _G()
    body = _lay(n.body, sizes)
    yd = J
    tail = []
    if not body.empty():
        g.take(body, 0.0, J)
        g.first, g.entry = body.first, J + body.entry
        tail = body.opens
        yd = J + body.h + VG
    else:
        g.first, g.entry = D, J
    conts = g.conts
    g.conts = []
    for p in tail:
        p.to((0.0, yd))
        p.dst = D
        g.paths.append(p)
    wl, wr = max(dw / 2, body.wl), max(dw / 2, body.wr)
    if conts:                                     # continue: in from the right, above the condition
        xc = wr + HG
        for p in conts:
            px, py = p.pts[-1]
            p.to((xc, py), (xc, yd - VG / 2), (0.0, yd - VG / 2))
            p.dst = D
            g.paths.append(p)
        wr = xc
    g.pos[D] = (-dw / 2, yd)
    xl = -(wl + HG)
    back = Path([(-dw / 2, yd + dh / 2), (xl, yd + dh / 2), (xl, J / 2), (0.0, J / 2)], D, "yes")
    back.dst = g.first
    g.paths.append(back)
    h = yd + dh + VL - VG                         # room for the label
    out = Path([(0.0, yd + dh), (0.0, h)], D, "no")
    breaks, g.breaks = g.breaks, []
    if breaks:
        h += VG / 2
        out.to((0.0, h))
        _route_out(breaks, wr + HG, h)
        wr += HG
    g.opens = [out] + breaks
    g.wl, g.wr, g.h = -xl + 4, wr + 4, h
    return g


def _switch(n, sizes):
    """The cases one under another; from the switch a line down the left branches into each
    (labelled with its values); a break leaves on the right."""
    S = n.box
    sw, sh = sizes[S]
    g = _G()
    g.pos[S] = (-sw / 2, 0.0)
    g.first = S
    cases = [(lab, _lay(c, sizes)) for lab, c in n.cases]
    wl = max([sw / 2] + [c.wl for _, c in cases])
    wr = max([sw / 2] + [c.wr for _, c in cases])
    xd = -(wl + HG)
    y = sh + VG
    opens = []
    trunk = Path([(-sw / 2, sh / 2), (xd, sh / 2)], S, arrow=False)
    for lab, c in cases:
        yb = y + LABEL
        trunk.to((xd, yb))
        if c.jump_only():                         # case k: break;
            p = Path([(xd, yb), (0.0, yb)], S, lab)
            (g.breaks if c.breaks else g.conts).append(p)
            y = yb + VG / 2
            continue
        if c.empty():
            continue
        top = yb + VG / 2
        branch = Path([(xd, yb), (0.0, yb), (0.0, top + c.entry)], S, lab)
        branch.dst = c.first
        g.paths.append(branch)
        for p in opens:                           # no break: on into this case
            p.to((0.0, top + c.entry))
            p.dst = c.first
            g.paths.append(p)
        g.take(c, 0.0, top)
        opens = c.opens
        y = top + c.h + VG / 2
    breaks, g.breaks = g.breaks, []
    ye = y + VG / 2
    for p in opens:
        p.to((0.0, ye))
    xr = wr + HG
    _route_out(breaks, xr, ye)
    outs = opens + breaks
    if not n.default:
        trunk.to((xd, ye), (0.0, ye))
        trunk.label, trunk.arrow = None, True
        outs.append(trunk)
    else:
        g.paths.append(trunk)
    g.opens = outs
    g.wl, g.wr, g.h = -xd + 4, xr + 4, ye
    return g


def layout(root, sizes, end=None, margin=40):
    """root: the structure; sizes: {box: (w, h)}; end: a box to end the flow in when it runs
    off the bottom. Returns (pos {box: (x, y) top-left}, paths, (width, height))."""
    g = _lay(root, sizes)
    paths = list(g.paths)
    if g.opens and end is not None:
        e = _leaf(end, sizes, falls=False)
        y = g.h + VG
        for p in g.opens:
            p.to((0.0, y))
            p.dst = end
            paths.append(p)
        g.take(e, 0.0, y)
        g.h = y + e.h
        g.wl, g.wr = max(g.wl, e.wl), max(g.wr, e.wr)
    else:
        for p in g.opens:
            if len(p.pts) > 1:
                p.arrow = False
                paths.append(p)
    for p in g.breaks + g.conts:                  # outside any loop: nowhere to go
        if len(p.pts) > 1:
            p.arrow = False
            paths.append(p)
    xs = [x for x, _ in g.pos.values()] + [x for p in paths for x, _ in p.pts]
    left = min([-g.wl] + xs)
    dx, dy = margin - left, margin
    pos = {k: (x + dx, y + dy) for k, (x, y) in g.pos.items()}
    for p in paths:
        p.pts = [(x + dx, y + dy) for x, y in p.pts]
    right = max([x + sizes[k][0] for k, (x, _) in pos.items()] + [x for p in paths for x, _ in p.pts] + [0])
    bottom = max([y + sizes[k][1] for k, (_, y) in pos.items()] + [y for p in paths for _, y in p.pts] + [0])
    return pos, paths, (right + margin, bottom + margin)


def route(paths, start, target, jumps=()):
    """The way from `start` to `target`, where it ends: (the shapes on it, the indexes of the
    lines on it). A shape is on the way when the flow can reach it from the start and go on
    from it to the target; a branch that can only end elsewhere (an error that returns) is
    not. jumps: (goto's connector, its label's connector) pairs, which no line joins."""
    succ, pred = {}, {}
    edges = [(p.src, p.dst) for p in paths] + list(jumps)
    for a, b in edges:
        if a is not None and b is not None:
            succ.setdefault(a, set()).add(b)
            pred.setdefault(b, set()).add(a)

    def reach(seed, nxt):
        seen, stack = {seed}, [seed]
        while stack:
            for m in nxt.get(stack.pop(), ()):
                if m not in seen:
                    seen.add(m)
                    stack.append(m)
        return seen
    fwd, back = reach(start, succ), reach(target, pred)
    on = fwd & back
    lines = {i for i, p in enumerate(paths) if p.src in fwd and p.dst in back}
    return on, lines
