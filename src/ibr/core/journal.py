"""Undo journal: what the plugin changed, so Undo can put it back."""


class Journal:
    """Each entry is [value before the plugin's first change, the plugin's latest value].
    The first is what Undo restores (so running twice still undoes to the original); the
    second tells Undo whether the user has edited the item since.

    kinds: names, cmts (function comments), icmts (instruction comments),
    pcmts (pseudocode comments, keyed (func_ea, ea, position)), types; plus libflag,
    the functions FLIRT marked as library code."""

    KINDS = ("names", "cmts", "icmts", "pcmts", "types")

    def __init__(self):
        self.entries = {k: {} for k in self.KINDS}
        self.libflag = set()

    def record(self, kind, key, old, new):
        e = self.entries[kind].get(key)
        if e is None:
            self.entries[kind][key] = [old, new]
        else:
            e[1] = new

    def clear(self):
        for k in self.KINDS:
            self.entries[k].clear()
        self.libflag = set()
