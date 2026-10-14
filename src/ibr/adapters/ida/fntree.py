"""Hex-Rays ctree -> ports.Tree, the neutral statement tree the analyses read.

Only the fields that belong to an item's operator are read: cexpr_t keeps its operands in a
union, so e.x on a number is not None but garbage."""
import re
import sys

import ida_bytes
import ida_funcs
import ida_hexrays as hr
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import idaapi

from ... import ports

_BIN = {hr.cot_add: "+", hr.cot_sub: "-", hr.cot_mul: "*", hr.cot_sdiv: "/", hr.cot_udiv: "/",
        hr.cot_smod: "%", hr.cot_umod: "%", hr.cot_band: "&", hr.cot_bor: "|", hr.cot_xor: "^",
        hr.cot_shl: "<<", hr.cot_sshr: ">>", hr.cot_ushr: ">>", hr.cot_land: "&&", hr.cot_lor: "||",
        hr.cot_eq: "==", hr.cot_ne: "!=", hr.cot_sge: ">=", hr.cot_uge: ">=", hr.cot_sle: "<=",
        hr.cot_ule: "<=", hr.cot_sgt: ">", hr.cot_ugt: ">", hr.cot_slt: "<", hr.cot_ult: "<",
        hr.cot_fadd: "+", hr.cot_fsub: "-", hr.cot_fmul: "*", hr.cot_fdiv: "/"}
_UN = {hr.cot_neg: "-", hr.cot_lnot: "!", hr.cot_bnot: "~", hr.cot_fneg: "-"}
_ASG = {hr.cot_asg: "", hr.cot_asgbor: "|", hr.cot_asgxor: "^", hr.cot_asgband: "&",
        hr.cot_asgadd: "+", hr.cot_asgsub: "-", hr.cot_asgmul: "*", hr.cot_asgsshr: ">>",
        hr.cot_asgushr: ">>", hr.cot_asgshl: "<<", hr.cot_asgsdiv: "/", hr.cot_asgudiv: "/",
        hr.cot_asgsmod: "%", hr.cot_asgumod: "%"}
_X = (hr.cot_ptr, hr.cot_ref, hr.cot_cast, hr.cot_memref, hr.cot_memptr)


def _ea(item):
    return None if item.ea == idaapi.BADADDR else item.ea


def _printed(e):
    """Hex-Rays' own text of an expression, without colour tags."""
    try:
        return ida_lines.tag_remove(e.print1(None) or "")
    except Exception:
        return ""


def _member_is_array(e, name):
    """The structure member e reads is an array. Hex-Rays types `p->arr` as a pointer where
    the array decays, so the expression's own type does not say it."""
    try:
        t = e.x.type
        if e.op == hr.cot_memptr:
            t = t.get_pointed_object()
        udt = ida_typeinf.udt_type_data_t()
        if not t.get_udt_details(udt):
            return False
        return any(u.name == name and u.type.is_array() for u in udt)
    except Exception:
        return False


def _strlit(ea):
    """The text of a string literal at ea, or None."""
    try:
        if not ida_bytes.is_strlit(ida_bytes.get_flags(ea)):
            return None
        b = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.get_str_type(ea))
        return b.decode("utf-8", "replace") if b is not None else None
    except Exception:
        return None


def _global_array(ea):
    """The global at ea is an array (a string literal included). Passed to a call it decays
    to a pointer, and only its declaration still says so."""
    try:
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, ea):
            return tif.is_array()
        f = ida_bytes.get_flags(ea)
        if ida_bytes.is_strlit(f):
            return True
        if ida_bytes.is_data(f):
            return ida_bytes.get_item_size(ea) > max(1, ida_bytes.get_data_elsize(ea, f))
    except Exception:
        pass
    return False


def _library(ea, name):
    """A function the program did not write: an import, or library code FLIRT recognised.
    False for data and for the program's own functions."""
    f = ida_funcs.get_func(ea)
    if f is None:
        seg = ida_segment.getseg(ea)
        return seg is not None and seg.type == ida_segment.SEG_XTRN
    return bool(f.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK)) or name.startswith("unknown_libname")


def _decl(tif, name):
    """`type name` the way a declaration reads (`char buf[32]`, `__m64 v29`)."""
    try:
        return tif._print(name, ida_typeinf.PRTYPE_1LINE) or name
    except Exception:
        return name


class _Conv:
    def __init__(self, cfunc):
        self.cf = cfunc

    def expr(self, e):
        if e is None or e.op == hr.cot_empty:
            return None
        op, t = e.op, e.type
        kw = {"ea": _ea(e), "index": e.index,
              "ptr": bool(t is not None and t.is_ptr()), "mem": bool(t is not None and t.is_array())}
        if op in _ASG:
            return ports.Tree("asg", op=_ASG[op], x=self.expr(e.x), y=self.expr(e.y), **kw)
        if op in (hr.cot_preinc, hr.cot_postinc, hr.cot_predec, hr.cot_postdec):
            kind = "inc" if op in (hr.cot_preinc, hr.cot_postinc) else "dec"
            pre = "pre" if op in (hr.cot_preinc, hr.cot_predec) else "post"
            return ports.Tree(kind, op=pre, x=self.expr(e.x), **kw)
        if op == hr.cot_var:
            lv = self.cf.lvars[e.v.idx]
            if lv.type().is_array():
                kw["mem"] = True                  # an array passed on decays to a pointer
            return ports.Tree("var", var=e.v.idx, name=lv.name, **kw)
        if op == hr.cot_obj:
            name = ida_name.get_name(e.obj_ea) or ""
            text = _printed(e)
            shown = text if re.fullmatch(r"[\w:~<>]+", text or "") else name   # demangled
            func = t is not None and t.is_func()
            own = ida_typeinf.tinfo_t()
            if not func and ida_nalt.get_tinfo(own, e.obj_ea):
                decl = _decl(own, shown)          # its declaration, not the decayed pointer
            else:
                decl = "" if func else _decl(t, shown)
            lit = _strlit(e.obj_ea)
            if not func and not kw["mem"] and _global_array(e.obj_ea):
                kw["mem"] = True
            return ports.Tree("obj", obj_ea=e.obj_ea, name=name, decl=decl, text=text,
                              string=lit if lit is not None else "", strlit=lit is not None,
                              lib=_library(e.obj_ea, name), **kw)
        if op == hr.cot_num:
            return ports.Tree("num", value=e.numval(), text=_printed(e), **kw)
        if op == hr.cot_fnum:
            return ports.Tree("fnum", **kw)
        if op == hr.cot_str:
            return ports.Tree("str", string=e.string, **kw)
        if op == hr.cot_helper:
            return ports.Tree("helper", name=e.helper or "", **kw)
        if op == hr.cot_call:
            return ports.Tree("call", x=self.expr(e.x), args=[self.expr(a) for a in e.a], **kw)
        if op == hr.cot_idx:
            return ports.Tree("idx", x=self.expr(e.x), y=self.expr(e.y), **kw)
        if op in (hr.cot_memref, hr.cot_memptr):
            m = re.search(r"(\w+)$", _printed(e))
            field = m.group(1) if m else ""
            if not kw["mem"] and _member_is_array(e, field):
                kw["mem"] = True
            return ports.Tree("mem", x=self.expr(e.x), op="->" if op == hr.cot_memptr else ".",
                              name=field, **kw)
        if op in _X:
            kind = {hr.cot_ptr: "ptr", hr.cot_ref: "ref", hr.cot_cast: "cast"}[op]
            return ports.Tree(kind, x=self.expr(e.x), **kw)
        if op in _BIN:
            return ports.Tree("bin", op=_BIN[op], x=self.expr(e.x), y=self.expr(e.y), **kw)
        if op in _UN:
            return ports.Tree("un", op=_UN[op], x=self.expr(e.x), **kw)
        if op == hr.cot_tern:
            return ports.Tree("tern", x=self.expr(e.x), y=self.expr(e.y), z=self.expr(e.z), **kw)
        if op == hr.cot_comma:
            return ports.Tree("comma", x=self.expr(e.x), y=self.expr(e.y), **kw)
        return ports.Tree("other", **kw)          # sizeof, type, statement-in-expression

    def stmt(self, i):
        if i is None:
            return None
        op = i.op
        kw = {"ea": _ea(i), "index": i.index, "label": i.label_num if i.label_num >= 0 else None}
        if op == hr.cit_block:
            return ports.Tree("block", body=[self.stmt(c) for c in i.cblock], **kw)
        if op == hr.cit_expr:
            return ports.Tree("expr", x=self.expr(i.cexpr), **kw)
        if op == hr.cit_if:
            body = [self.stmt(i.cif.ithen)] + ([self.stmt(i.cif.ielse)] if i.cif.ielse else [])
            return ports.Tree("if", x=self.expr(i.cif.expr), body=body, **kw)
        if op == hr.cit_for:
            f = i.cfor
            return ports.Tree("for", init=self.expr(f.init), x=self.expr(f.expr), step=self.expr(f.step),
                              body=[self.stmt(f.body)], **kw)
        if op == hr.cit_while:
            return ports.Tree("while", x=self.expr(i.cwhile.expr), body=[self.stmt(i.cwhile.body)], **kw)
        if op == hr.cit_do:
            return ports.Tree("do", x=self.expr(i.cdo.expr), body=[self.stmt(i.cdo.body)], **kw)
        if op == hr.cit_switch:
            cases = []
            for c in i.cswitch.cases:
                t = self.stmt(c)
                if t is not None:
                    t.values = [int(v) for v in c.values]
                    cases.append(t)
            return ports.Tree("switch", x=self.expr(i.cswitch.expr), body=cases, **kw)
        if op == hr.cit_return:
            return ports.Tree("return", x=self.expr(i.creturn.expr), **kw)
        if op == hr.cit_goto:
            return ports.Tree("goto", target=i.cgoto.label_num, **kw)
        if op == hr.cit_break:
            return ports.Tree("break", **kw)
        if op == hr.cit_continue:
            return ports.Tree("continue", **kw)
        if op == hr.cit_empty:
            return ports.Tree("block", body=[], **kw)
        return ports.Tree("other", **kw)          # asm, try, throw


def function_tree(cfunc):
    """(body as a Tree "block", {var number: name}) of a decompiled function."""
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old, 20000))
    try:
        body = _Conv(cfunc).stmt(cfunc.body)
    finally:
        sys.setrecursionlimit(old)
    return body, {n: v.name for n, v in enumerate(cfunc.lvars)}


def var_info(cfunc):
    """{var number: (declaration, is an argument)}."""
    return {n: (_decl(v.type(), v.name), bool(v.is_arg_var)) for n, v in enumerate(cfunc.lvars)}
