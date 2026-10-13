"""How the plugin's notes sit in comments next to the user's own text."""
PFX = "libc: "
OPX = "op: "
SYS = "sys: "
_MANAGED = (PFX, OPX, SYS)

_JOIN = "  | "        # a note and the comment text that was already there share one line


def _after_join(ln):
    """The text after the first `  | ` outside a quoted string, or ''."""
    q, i = False, 0
    while i < len(ln):
        c = ln[i]
        if q and c == "\\":
            i += 2
            continue
        if c == '"':
            q = not q
        elif not q and ln.startswith(_JOIN, i):
            return ln[i + len(_JOIN):].strip()
        i += 1
    return ""


def _strip_managed(text):
    """Remove our notes (libc:/op:/sys:) from a comment and keep everything else,
    including the user's text joined onto a note's line with `  | `."""
    if not text:
        return ""
    keep = []
    for ln in text.split("\n"):
        while ln.startswith(_MANAGED):
            ln = _after_join(ln)
        if ln:
            keep.append(ln)
    return "\n".join(keep).strip("\n")
