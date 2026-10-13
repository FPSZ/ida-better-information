"""Plain-Python stand-ins for the ports, so core/ and app/ run without IDA."""
import itertools

from ibr import ports

_uid = itertools.count(1)


class E(ports.Expr):
    """A decompiler expression. `text` is what render() returns."""

    def __init__(self, op, text="", **kw):
        self.op, self.text, self.uid = op, text, next(_uid)
        for k, v in kw.items():
            setattr(self, k, v)

    def render(self):
        return self.text


def num(v, size=4):
    return E("num", str(v), value=v & ((1 << 64) - 1), size=size)


def var(name, size=8, is_float=False):
    return E("var", name, var_name=name, size=size, is_float=is_float)


def fvar(name):
    return var(name, 8, True)


def string(s):
    return E("str", '"%s"' % s, string=s)


def obj(ea, text=None):
    return E("obj", text or "0x%X" % ea, obj_ea=ea)


def ref(x):
    return E("ref", "&" + x.text, x=x)


def cast(x, text=None):
    return E("cast", text or x.text, x=x)


def other(text):
    """An expression the note logic only knows by its text (a[i], p->f, x + 1 ...)."""
    return E("other", text)


def call(callee_ea, *args, ea=0x401000, index=None):
    return E("call", x=obj(callee_ea), args=list(args), ea=ea, index=index if index is not None else next(_uid))


def hcall(helper, *args, ea=0x401000, index=None):
    return E("call", x=E("helper", helper=helper), args=list(args), ea=ea,
             index=index if index is not None else next(_uid))


def preorder(e):
    """The calls of an expression tree in pre-order, as the IDA adapter yields them."""
    out = []

    def walk(x):
        if x is None:
            return
        if x.op == "call":
            out.append(x)
        if x.op in ("cast", "ref"):
            walk(x.x)
        for a in getattr(x, "args", ()) or ():
            walk(a)
    walk(e)
    return out


class FakeProgram(ports.Program):
    def __init__(self, arch="x86_64", pe=False, names=None, strings=None, writable=(), data_items=()):
        self._arch, self._pe = arch, pe
        self.names = dict(names or {})          # ea -> function name
        self.strings = dict(strings or {})      # ea -> bytes of a C string
        self.writable = set(writable)
        self.data_items = set(data_items)       # formatted non-byte data (pointers, ints)
        self.fcmts, self.icmts, self.types, self.user_types = {}, {}, {}, set()
        self.lib = set()
        self.default_names = {}
        self.items = {}                         # func ea -> [(ea, mnem, d, s, t)]

    def arch(self):
        return self._arch

    def is_pe(self):
        return self._pe

    def has_code(self):
        return True

    def functions(self):
        return sorted(self.names)

    def func_start(self, ea):
        return ea if ea in self.names else None

    def func_name(self, ea):
        return self.names.get(ea, "")

    def set_func_name(self, ea, name):
        self.names[ea] = name or "sub_%X" % ea
        return True

    def is_lib(self, ea):
        return ea in self.lib

    def clear_lib(self, ea):
        self.lib.discard(ea)

    def func_cmt(self, ea):
        return self.fcmts.get(ea, "")

    def set_func_cmt(self, ea, text):
        self.fcmts[ea] = text

    def insn_cmt(self, ea):
        return self.icmts.get(ea, "")

    def set_insn_cmt(self, ea, text):
        self.icmts[ea] = text

    def type_snapshot(self):
        return {ea: (t, ea in self.user_types) for ea, t in self.types.items()}

    def type_str(self, ea):
        return self.types.get(ea)

    def has_user_type(self, ea):
        return ea in self.user_types

    def apply_type(self, ea, tif):
        self.types[ea] = tif
        self.user_types.add(ea)
        return True

    def restore_type(self, ea, saved):
        self.types.pop(ea, None)
        self.user_types.discard(ea)
        if saved is not None:
            self.types[ea] = saved[0]
            if saved[1]:
                self.user_types.add(ea)

    def name_at(self, ea):
        return self.names.get(ea, "")

    def cstr_bytes(self, ea):
        if ea in self.data_items:
            return None
        return self.strings.get(ea)

    def is_writable(self, ea):
        return ea in self.writable

    def is_byte_buffer(self, ea):
        return ea not in self.data_items

    def func_items(self, ea):
        return [i[0] for i in self.items.get(ea, [])]

    def insn(self, ea):
        for items in self.items.values():
            for i in items:
                if i[0] == ea:
                    return i[1:]
        return ("", "", "", "")

    def wait(self):
        pass


class FakeSignatures(ports.Signatures):
    """apply() renames functions as a signature would: {signame: {ea: name}}."""

    def __init__(self, prog, files, effects, protos=None):
        self.prog, self.files, self.effects, self.protos = prog, files, effects, protos or {}

    def sig_files(self, arch):
        return list(self.files)

    def apply(self, signame):
        for ea, name in self.effects.get(signame, {}).items():
            self.prog.names[ea] = name
            self.prog.lib.add(ea)
            self.prog.fcmts.setdefault(ea, "")

    def ensure_til(self, arch):
        pass

    def prototype(self, sym):
        return self.protos.get(sym)


class FakeDecompiler(ports.Decompiler):
    def __init__(self):
        self.cmts = {}                          # (func_ea, (ea, itp)) -> text

    def pseudo_comments(self, func_ea, locs):
        return {loc: self.cmts.get((func_ea, loc), "") for loc in locs}

    def set_pseudo_comments(self, func_ea, texts):
        for loc, t in texts.items():
            self.cmts[(func_ea, loc)] = t
