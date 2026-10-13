"""Persist pseudocode notes as Hex-Rays user comments (reversible)."""
import ida_funcs
import ida_kernwin
import ida_lines

from ...core.comments import _JOIN, _strip_managed
from .context import JOURNAL
from .live import _RENDER_ON, _collect_notes


def _shown(cfunc, text):
    sv = cfunc.get_pseudocode()
    return sum(ida_lines.tag_remove(sv[i].line).count(text) for i in range(sv.size()))


def _hx_put(cfunc, ea, text, func_ea):
    """Persist one note as a user comment at the first item position of `ea` where
    Hex-Rays actually prints it. A position that would leave it orphaned gets back
    exactly what it held; other orphan comments (possibly the user's) are left alone."""
    import ida_hexrays as hr
    for itp in (hr.ITP_SEMI, hr.ITP_BLOCK1, hr.ITP_BLOCK2, hr.ITP_CASE, hr.ITP_COLON,
                hr.ITP_CURLY1, hr.ITP_CURLY2, hr.ITP_BRACE1, hr.ITP_BRACE2, hr.ITP_ELSE):
        tl = hr.treeloc_t(); tl.ea = ea; tl.itp = itp
        try:
            prev = cfunc.get_user_cmt(tl, hr.RETRIEVE_ALWAYS) or ""
        except Exception:
            prev = ""
        body = _strip_managed(prev)
        newtext = text if not body else (text + " " + _JOIN + body)
        if newtext == prev:
            return True                   # already persisted here
        before = _shown(cfunc, newtext)
        cfunc.set_user_cmt(tl, newtext)
        cfunc.refresh_func_ctext()
        if _shown(cfunc, newtext) > before:
            cfunc.save_user_cmts()
            JOURNAL.record("pcmts", (func_ea, ea, itp), prev, newtext)
            return True
        cfunc.set_user_cmt(tl, prev)      # not printed at this position: put it back
        cfunc.refresh_func_ctext()
    return False


def annotate_pseudo(func_ea=None):
    """Persist decompiler notes as user comments in the CURRENT function.
       Returns count; -1 not in a function; -2 no decompiler; -3 error."""
    try:
        import ida_hexrays as hr
    except Exception:
        return -2
    try:
        if not hr.init_hexrays_plugin():
            return -2
        if func_ea is None:
            func_ea = ida_kernwin.get_screen_ea()
        f = ida_funcs.get_func(func_ea)
        if not f:
            return -1
        cfunc = hr.decompile(f.start_ea)
        if not cfunc:
            return -2
        notes, _ = _collect_notes(cfunc)
        if not notes:
            return 0
        was_live = _RENDER_ON[0]
        _RENDER_ON[0] = False     # _hx_put counts printed copies; live copies would blur that
        try:
            cfunc.refresh_func_ctext()
            added = sum(1 for ea, txt in notes.items() if _hx_put(cfunc, ea, txt, f.start_ea))
        finally:
            _RENDER_ON[0] = was_live
        cfunc.save_user_cmts(); cfunc.refresh_func_ctext()
        return added
    except Exception as ex:
        _pse_err[0] = "%s" % ex
        return -3
_pse_err = [""]
