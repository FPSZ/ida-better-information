"""The plugin's operations for the panel, scripts and idalib, bound to this IDA session.

These names are also what the single-file build exports at top level."""
import ida_kernwin

from ...app import annotate as _annotate
from ...app import detection as _detection
from ...app import signatures as _signatures
from ...app import undo as _undo
from ...core.asm_math import insn_math
from ...core.i18n import T, set_lang
from ...core.names import _is_dummy_name
from .context import DEC, JOURNAL, PROG, SIGS
from .live import _RENDER_ON, _collect_notes, _refresh_pseudo_views, _render_into_sv, set_live_render
from .persist import _pse_err, annotate_pseudo
from .program import cur_arch as _cur_arch

__all__ = ["run_detection", "do_apply_sig", "annotate_all", "annotate_math", "annotate_pseudo",
           "do_undo", "set_live_render", "set_lang", "_collect_notes", "_render_into_sv",
           "_insn_math", "_is_dummy_name", "_cur_arch", "_pse_err"]


def run_detection():
    return _detection.run_detection(PROG)


def do_apply_sig(r):
    return _signatures.apply_signatures(PROG, SIGS, JOURNAL, r)


def annotate_all():
    return _annotate.annotate_all(PROG, JOURNAL)


def annotate_math(func_ea=None):
    if func_ea is None:
        func_ea = ida_kernwin.get_screen_ea()
    return _annotate.annotate_math(PROG, JOURNAL, func_ea)


def _insn_math(ea, arch=None):
    return insn_math(*PROG.insn(ea), arch if arch is not None else (_cur_arch() or ""))


def do_undo():
    msg = _undo.undo(PROG, DEC, JOURNAL)
    # the live notes are plugin output too: without this, notes that do not depend
    # on names (SIMD, syscalls, canary reads) would stay on screen after Undo
    was_live = _RENDER_ON[0]
    _RENDER_ON[0] = False
    _refresh_pseudo_views()
    if was_live:
        msg += T(" Live annotations paused until the next Run.", "实时注释已暂停,下次\"执行\"时恢复。")
    return msg
