"""Revert what the plugin wrote, keeping edits the user made since."""
from ..core.comments import _strip_managed
from ..core.i18n import T
from ..core.names import _is_dummy_name


def undo(prog, dec, journal):
    """Revert what the plugin wrote. An item the user changed after the plugin wrote it
    keeps the user's version: a renamed function or retyped prototype is left alone,
    and an edited comment only loses the plugin's notes. Returns the log line.

    `prog` is a ports.Program, `dec` a ports.Decompiler, `journal` a core.journal.Journal."""
    E = journal.entries
    nn = nc = ni = npc = nt = 0
    for ea, (old, new) in list(E["names"].items()):
        try:
            if (prog.func_name(ea) or "") != new:
                continue                          # renamed since: the user's name stays
            # an empty name lets IDA regenerate sub_XXXX
            if prog.set_func_name(ea, "" if _is_dummy_name(old) else old):
                nn += 1
        except Exception:
            pass
    for ea, (old, new) in list(E["cmts"].items()):
        try:
            cur = prog.func_cmt(ea) or ""
            prog.set_func_cmt(ea, (old or "") if cur == new else _strip_managed(cur)); nc += 1
        except Exception:
            pass
    for ea, (old, new) in list(E["icmts"].items()):
        try:
            cur = prog.insn_cmt(ea) or ""
            prog.set_insn_cmt(ea, (old or "") if cur == new else _strip_managed(cur)); ni += 1
        except Exception:
            pass
    byfunc = {}
    for (fea, ea, itp), (old, new) in E["pcmts"].items():
        byfunc.setdefault(fea, []).append(((ea, itp), old, new))
    for fea, items in byfunc.items():
        try:
            cur = dec.pseudo_comments(fea, [loc for loc, _, _ in items])
            if cur is None:
                continue
            dec.set_pseudo_comments(fea, {
                loc: (old or "") if (cur.get(loc) or "") == new else _strip_managed(cur.get(loc) or "")
                for loc, old, new in items})
            npc += len(items)
        except Exception:
            pass
    try:
        for ea, (prev, written) in list(E["types"].items()):
            if prog.type_str(ea) != written:
                continue                          # retyped since: the user's type stays
            # a type IDA had only guessed must not come back as a user type
            prog.restore_type(ea, prev)
            nt += 1
    except Exception:
        pass
    for ea in journal.libflag:
        if prog.is_lib(ea):
            prog.clear_lib(ea)
    journal.clear()
    try:
        prog.wait()
    except Exception:
        pass
    return T("reverted: %d names, %d prototypes, %d func comments, %d insn comments, %d pseudocode comments.",
             "已撤回:%d 个函数名、%d 个原型、%d 处函数注释、%d 处指令注释、%d 处伪代码注释。") % (nn, nt, nc, ni, npc)
