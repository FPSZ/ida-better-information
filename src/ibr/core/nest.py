"""A called function's chart opened inside its call in the flowchart, the way a map shows a
town's streets when you zoom into it: where the panel goes, how small the chart is drawn in
it, and how far it is open at a zoom. Geometry only (no Qt, no IDA).

The panel hangs under the call's shape (whose text, with the arguments, stays in sight),
centred on it, at least MIN_W wide, and holds the whole called chart scaled to its width
(never larger than drawn on its own). How far a call is zoomed into is how large its chart
draws it on screen (zoom x the chart's own scale), and only calls near the middle of the
window open: the chart is made (decompiled) from PREFETCH on, fades in between OPEN and FULL,
and is dropped under CLOSE, so only the few calls being looked at cost anything."""

PAD = 10            # between the panel's edge and the chart in it
GAP = 6             # between the call and its panel
MIN_W = 240         # a panel is at least this wide, whatever its call's width
PREFETCH = 1.8      # make the chart when the call is drawn this many times its size
OPEN = 2.4          # start showing it here...
FULL = 3.2          # ...fully shown here
CLOSE = 1.6         # drop it under this
MIDDLE = 0.25       # a call opens when it reaches the window less this much off each side
MAX_OPEN = 8        # panels open at once, at most
MAX_DEPTH = 6       # calls inside calls, at most


def panel(box, size):
    """box: (x, y, w, h) of the call's shape; size: (W, H) of the called chart.
    Returns (x, y, w, h, scale): the panel and the scale its chart is drawn at."""
    x, y, w, h = box
    W, H = max(size[0], 1.0), max(size[1], 1.0)
    pw = max(w, MIN_W)
    s = min(1.0, (pw - 2 * PAD) / W)
    if s >= 1.0:
        pw = max(w, W + 2 * PAD)
    return x + w / 2 - pw / 2, y + h + GAP, pw, H * s + 2 * PAD, s


def opening(r):
    """How opaque the panel is when its call is drawn r times its size: 0 up to OPEN, 1 from
    FULL on."""
    return min(1.0, max(0.0, (r - OPEN) / (FULL - OPEN)))


def middle(rect, view):
    """rect (x, y, w, h, on screen) reaches the middle of a view (w, h)."""
    x, y, w, h = rect
    vw, vh = view
    return (x + w > vw * MIDDLE and x < vw * (1 - MIDDLE) and
            y + h > vh * MIDDLE and y < vh * (1 - MIDDLE))
