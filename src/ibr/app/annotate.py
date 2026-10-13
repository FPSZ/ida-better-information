"""Comments the plugin writes into the database (all journaled, so Undo reverts them)."""
from ..core.asm_math import insn_math
from ..core.comments import OPX, PFX, _JOIN, _strip_managed
from ..core.libc import _describe


def annotate_all(prog, journal):
    """One-line description on every recognised libc function. Returns the count."""
    n = 0
    for ea in prog.functions():
        name = prog.func_name(ea) or ""
        d = _describe(name)
        if not d:
            continue
        old = prog.func_cmt(ea) or ""
        body = _strip_managed(old)
        new = d if not body else (d + "\n" + body)
        if new == old:
            continue
        try:
            prog.set_func_cmt(ea, new); n += 1
            journal.record("cmts", ea, old, new)
        except Exception:
            pass
    return n


def annotate_math(prog, journal, func_ea):
    """`d = s op t` notes on the instructions of the function at func_ea.
    Returns the count, or -1 when func_ea is not in a function."""
    start = prog.func_start(func_ea)
    if start is None:
        return -1
    n = 0
    arch = prog.arch() or ""
    for ea in prog.func_items(start):
        expr = insn_math(*prog.insn(ea), arch)
        if not expr:
            continue
        tagged = OPX + expr
        old = prog.insn_cmt(ea) or ""
        body = _strip_managed(old)
        new = tagged if not body else (tagged + _JOIN + body)
        if new == old:
            continue
        try:
            prog.set_insn_cmt(ea, new); n += 1
            journal.record("icmts", ea, old, new)
        except Exception:
            pass
    return n


__all__ = ["annotate_all", "annotate_math", "PFX"]
