"""Hex-Rays ctree expressions seen through ports.Expr (wrapped lazily, no copy)."""
import ida_hexrays as hr
import ida_lines
import idaapi

from ... import ports

_OPNAME = {hr.cot_call: "call", hr.cot_helper: "helper", hr.cot_num: "num", hr.cot_fnum: "fnum",
           hr.cot_str: "str", hr.cot_obj: "obj", hr.cot_var: "var", hr.cot_ref: "ref",
           hr.cot_cast: "cast"}


class IdaExpr(ports.Expr):
    __slots__ = ("e", "cf")

    def __init__(self, e, cf):
        self.e, self.cf = e, cf

    @property
    def op(self):
        return _OPNAME.get(self.e.op, "other")

    @property
    def x(self):
        return IdaExpr(self.e.x, self.cf) if self.e.x is not None else None

    @property
    def args(self):
        return [IdaExpr(a, self.cf) for a in self.e.a]

    @property
    def value(self):
        return self.e.numval()

    @property
    def size(self):
        return self.e.type.get_size() if self.e.type else 0

    @property
    def is_float(self):
        return bool(self.e.type is not None and self.e.type.is_floating())

    @property
    def string(self):
        return self.e.string

    @property
    def obj_ea(self):
        return self.e.obj_ea

    @property
    def var_name(self):
        return self.cf.lvars[self.e.v.idx].name

    @property
    def helper(self):
        return self.e.helper or ""

    @property
    def ea(self):
        return self.e.ea

    @property
    def index(self):
        return self.e.index

    @property
    def uid(self):
        return self.e.obj_id

    def render(self):
        return ida_lines.tag_remove(self.e.print1(self.cf)).replace("\n", " ")


def calls(cfunc):
    """The function's calls with an address, in pre-order."""
    out = []

    class _V(hr.ctree_visitor_t):
        def __init__(self):
            hr.ctree_visitor_t.__init__(self, hr.CV_FAST)

        def visit_expr(self, e):
            if e.op == hr.cot_call and e.x is not None and e.ea != idaapi.BADADDR:
                out.append(IdaExpr(e, cfunc))
            return 0
    _V().apply_to(cfunc.body, None)
    return out
