"""The ports implemented on top of idaapi."""
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import idaapi
import idautils
import idc

from ... import ports


def cur_arch():
    try:
        import ida_ida
        if not ida_ida.inf_is_64bit():
            pn = ida_ida.inf_get_procname()
            return "i386" if pn == "metapc" else "arm" if pn.lower().startswith("arm") else pn
        pn = ida_ida.inf_get_procname()
        if pn == "metapc":
            return "x86_64"
        if pn.lower().startswith("arm") or pn.upper() == "AARCH64":
            return "aarch64"
        return pn
    except Exception:
        return None


def is_pe():
    try:
        import ida_ida
        return ida_ida.inf_get_filetype() == ida_ida.f_PE
    except Exception:
        return False


def _exec_segments():
    import ida_segment
    seg = ida_segment.get_first_seg()
    while seg is not None:
        yield seg
        seg = ida_segment.get_next_seg(seg.start_ea)


class IdaProgram(ports.Program):
    def arch(self):
        return cur_arch()

    def is_pe(self):
        return is_pe()

    # ---- bytes ----
    def input_bytes(self):
        path = idaapi.get_input_file_path()
        if path and os.path.exists(path):
            try:
                return open(path, "rb").read()
            except Exception:
                return None
        return None

    def header_bytes(self):
        return ida_bytes.get_bytes(idaapi.get_imagebase(), 0x1000) or b""

    def image_bytes(self):
        """Concatenate the executable segments (for fingerprinting and packer heuristics)."""
        import ida_segment
        chunks = []
        for seg in _exec_segments():
            if seg.perm & ida_segment.SEGPERM_EXEC:
                b = ida_bytes.get_bytes(seg.start_ea, min(seg.size(), 64 << 20))
                if b:
                    chunks.append(b)
        return b"".join(chunks)

    def has_code(self):
        import ida_segment
        for seg in _exec_segments():
            if seg.perm & ida_segment.SEGPERM_EXEC and seg.size() > 0:
                return True
        return any(True for _ in idautils.Functions())

    def function_heads(self, n):
        for ea in idautils.Functions():
            yield ida_bytes.get_bytes(ea, n)

    # ---- functions ----
    def functions(self):
        return list(idautils.Functions())

    def func_start(self, ea):
        f = ida_funcs.get_func(ea)
        return f.start_ea if f else None

    def func_name(self, ea):
        return ida_funcs.get_func_name(ea)

    def set_func_name(self, ea, name):
        if not name:
            # empty name = let IDA regenerate sub_XXXX; SN_FORCE makes this fail
            return ida_name.set_name(ea, "", ida_name.SN_NOWARN)
        return ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE)

    def is_lib(self, ea):
        f = ida_funcs.get_func(ea)
        return bool(f is not None and f.flags & ida_funcs.FUNC_LIB)

    def clear_lib(self, ea):
        f = ida_funcs.get_func(ea)
        if f is not None:
            f.flags &= ~ida_funcs.FUNC_LIB
            ida_funcs.update_func(f)

    # ---- comments ----
    def func_cmt(self, ea):
        return idc.get_func_cmt(ea, 1)

    def set_func_cmt(self, ea, text):
        idc.set_func_cmt(ea, text, 1)

    def insn_cmt(self, ea):
        return idc.get_cmt(ea, 0)

    def set_insn_cmt(self, ea, text):
        idc.set_cmt(ea, text, 0)

    # ---- types ----
    def type_snapshot(self):
        """{ea: (tinfo copy, user-specified?)} for every function that has a stored type."""
        import ida_nalt, ida_typeinf
        snap = {}
        for ea in idautils.Functions():
            t = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(t, ea):
                snap[ea] = (t, bool(ida_nalt.is_userti(ea)))
        return snap

    def type_str(self, ea):
        import ida_nalt, ida_typeinf
        t = ida_typeinf.tinfo_t()
        return str(t) if ida_nalt.get_tinfo(t, ea) else None

    def has_user_type(self, ea):
        import ida_nalt
        return bool(ida_nalt.is_userti(ea))

    def apply_type(self, ea, tif):
        import ida_typeinf
        return bool(ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE))

    def restore_type(self, ea, saved):
        import ida_nalt, ida_typeinf
        ida_nalt.del_tinfo(ea)
        if saved is not None:
            ida_typeinf.apply_tinfo(ea, saved[0], ida_typeinf.TINFO_DEFINITE if saved[1]
                                    else ida_typeinf.TINFO_GUESSED)

    # ---- data ----
    def name_at(self, ea):
        return idc.get_name(ea)

    def cstr_bytes(self, ea):
        f = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(f) or ida_funcs.get_func(ea):
            return None
        if ida_bytes.is_data(f) and not ida_bytes.is_byte(f) and not ida_bytes.is_strlit(f):
            return None                       # a pointer/int variable (e.g. stdout), never text
        b = idc.get_strlit_contents(ea, -1, -1)
        if not b:
            b = (ida_bytes.get_bytes(ea, 256) or b"").split(b"\x00", 1)[0]
        return b

    def is_writable(self, ea):
        try:
            import ida_segment
            s = ida_segment.getseg(ea)
            if s is None:
                return False
            if s.perm:
                return bool(s.perm & ida_segment.SEGPERM_WRITE)
            return (ida_segment.get_segm_name(s) or "").lstrip(".") in ("bss", "data")
        except Exception:
            return False

    def is_byte_buffer(self, ea):
        f = ida_bytes.get_flags(ea)
        return not ida_bytes.is_data(f) or ida_bytes.is_byte(f)

    # ---- instructions ----
    def func_items(self, ea):
        return idautils.FuncItems(ea)

    def insn(self, ea):
        return (idc.print_insn_mnem(ea), idc.print_operand(ea, 0), idc.print_operand(ea, 1),
                idc.print_operand(ea, 2))

    def wait(self):
        ida_auto.auto_wait()


# FLIRT signatures are keyed by directory, not by the .sig processor byte:
# x86 (i386 + x86_64) live in sig/pc, ARM/AArch64 in sig/arm.
_SIG_SUBDIR = {"x86_64": "pc", "i386": "pc", "aarch64": "arm", "arm": "arm"}
_TIL = {"x86_64": "gnulnx_x64", "i386": "gnulnx_x86", "aarch64": "gnulnx_arm64", "arm": "gnulnx_arm"}


class IdaSignatures(ports.Signatures):
    def sig_dirs(self, arch):
        sub = _SIG_SUBDIR.get(arch, "pc")
        out = []
        for base in (getattr(idaapi, "get_user_idadir", lambda: None)(), idaapi.idadir("")):
            if not base:
                continue
            d = os.path.join(base, "sig", sub)
            if os.path.isdir(d) and d not in out:
                out.append(d)
        return out

    def sig_files(self, arch):
        out = []
        for d in self.sig_dirs(arch):
            try:
                out.extend(os.listdir(d))
            except Exception:
                pass
        return out

    def apply(self, signame):
        idaapi.plan_to_apply_idasgn(signame)
        ida_auto.auto_wait()

    def ensure_til(self, arch):
        """Load the gnulnx_* type library so named libc funcs get real prototypes."""
        try:
            import ida_typeinf
            til = ida_typeinf.get_idati()
            names = [til.base(i).name for i in range(til.nbases)]
            want = _TIL.get(arch, "gnuunx")
            if not any(want in n for n in names):
                ida_typeinf.add_til(want, ida_typeinf.ADDTIL_DEFAULT)
        except Exception:
            pass

    def prototype(self, sym):
        try:
            import ida_typeinf
        except Exception:
            return None
        til = ida_typeinf.get_idati()
        # prototypes live in the til's *symbol* table, C names with a leading '_'
        for key in ("_" + sym, sym):
            r = ida_typeinf.get_named_type(til, key, ida_typeinf.NTF_SYMM)
            if r:
                t = ida_typeinf.tinfo_t()
                if t.deserialize(til, r[1], r[2]) and t.is_func():
                    return t
        return None


class IdaDecompiler(ports.Decompiler):
    """Hex-Rays user comments; a location is (ea, item position)."""

    def _cfunc(self, func_ea):
        import ida_hexrays as hr
        return hr.decompile(func_ea)

    def pseudo_comments(self, func_ea, locs):
        import ida_hexrays as hr
        cf = self._cfunc(func_ea)
        if not cf:
            return None
        out = {}
        for ea, itp in locs:
            tl = hr.treeloc_t(); tl.ea = ea; tl.itp = itp
            out[(ea, itp)] = cf.get_user_cmt(tl, hr.RETRIEVE_ALWAYS) or ""
        return out

    def set_pseudo_comments(self, func_ea, texts):
        import ida_hexrays as hr
        cf = self._cfunc(func_ea)
        if not cf:
            return
        for (ea, itp), text in texts.items():
            tl = hr.treeloc_t(); tl.ea = ea; tl.itp = itp
            cf.set_user_cmt(tl, text)
        cf.save_user_cmts(); cf.refresh_func_ctext()
