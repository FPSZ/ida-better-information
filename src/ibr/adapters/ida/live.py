"""Live Hex-Rays rendering: notes appended to printed pseudocode, nothing stored."""
import re

import ida_kernwin
import ida_lines

from ...core.notes import collect_notes
from .context import PROG


_ADDR_TAG = ida_lines.COLOR_ON + chr(ida_lines.COLOR_ADDR)
_ADDR_RE = re.compile(re.escape(_ADDR_TAG) + ("([0-9A-Fa-f]{%d})" % ida_lines.COLOR_ADDR_SIZE))


def _line_item_indices(cfunc, line):
    out = []
    n = cfunc.treeitems.size()
    for m in _ADDR_RE.finditer(line):
        v = int(m.group(1), 16) & 0xFFFFFFFF
        if (v & 0xC0000000) == 0 and v < n:                 # ANCHOR_CITEM index
            out.append(v)
    return out


try:
    from .ctree import calls as _calls
except Exception:                     # no Hex-Rays: nothing calls _collect_notes then
    _calls = None


def _collect_notes(cfunc):
    """(by_ea, by_idx) notes of a decompiled function; see core.notes.collect_notes."""
    return collect_notes(PROG, _calls(cfunc))


def _render_into_sv(cfunc):
    """Append our notes to the pseudocode lines in-place. Returns count.
       Each call's note is placed once, on the line carrying that call's ctree
       item index (never on a parent brace that merely shares the address)."""
    sv = cfunc.get_pseudocode()          # populates item indices (ctree_item numbering)
    _, by_idx = _collect_notes(cfunc)
    if not by_idx:
        return 0
    tail = ida_lines.COLOR_ON + chr(ida_lines.COLOR_AUTOCMT)
    off = ida_lines.COLOR_OFF + chr(ida_lines.COLOR_AUTOCMT)
    placed = set()
    added = 0
    for i in range(sv.size()):
        line = sv[i].line
        hit = []
        for idx in _line_item_indices(cfunc, line):
            if idx in by_idx and idx not in placed:
                hit.append(by_idx[idx]); placed.add(idx)
        if hit:
            shown = ida_lines.tag_remove(line)
            hit = [h for h in dict.fromkeys(hit) if h not in shown]   # persisted already
        if hit:
            sv[i].line = line + "  " + tail + "// " + "   ".join(hit) + off
            added += 1
    return added


_RENDER_ON = [True]


try:
    import ida_hexrays as _hr_mod

    class _IBIHooks(_hr_mod.Hexrays_Hooks):
        def func_printed(self, cfunc):
            if _RENDER_ON[0]:
                try:
                    _render_into_sv(cfunc)
                except Exception:
                    pass
            return 0
    _HOOKS = _IBIHooks()
except Exception:
    _HOOKS = None


_hook_installed = [False]


def _refresh_pseudo_views():
    # every open Pseudocode-X, not just the current widget (that is our panel
    # when a button was clicked)
    try:
        import ida_hexrays as hr
        hr.clear_cached_cfuncs()
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            w = ida_kernwin.find_widget("Pseudocode-%s" % c)
            vu = hr.get_widget_vdui(w) if w else None
            if vu:
                vu.refresh_view(True)
    except Exception:
        pass


def set_live_render(on):
    _RENDER_ON[0] = on
    if _HOOKS is None:
        return False
    if on and not _hook_installed[0]:
        _hook_installed[0] = bool(_HOOKS.hook())      # retried next time if it failed
    _refresh_pseudo_views()
    return True
