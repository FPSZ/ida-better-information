"""Ports: what the application needs from a disassembler.

core/ and app/ only talk to these interfaces. adapters/ida implements them on top of
idaapi and Hex-Rays; tests implement them with plain Python objects. A method that is
not supported raises NotImplementedError."""


class Expr:
    """One decompiler expression, as the note logic reads it.

    op        "call", "helper", "num", "fnum", "str", "obj", "var", "ref", "cast" or "other"
    x         operand of cast/ref, callee of a call (an Expr), else None
    args      call arguments (list of Expr)
    value     integer value of a "num" (64-bit, as the decompiler stores it)
    size      byte size of the expression's type, 0 if unknown
    is_float  the expression has a floating-point type
    string    text of a "str" literal
    obj_ea    address of an "obj"
    var_name  name of a "var"
    helper    name of a "helper" (intrinsics: _mm_xor_si128, __readfsqword, ...)
    ea        address the expression belongs to
    index     position in the function's item list (identifies a printed line)
    uid       identity of the expression within one decompilation
    """
    op = "other"
    x = None
    args = ()
    value = 0
    size = 0
    is_float = False
    string = ""
    obj_ea = None
    var_name = ""
    helper = ""
    ea = None
    index = None
    uid = None

    def render(self):
        """The decompiler's own text for this expression (no colour tags, one line)."""
        raise NotImplementedError


class Program:
    """The disassembler database."""

    # ---- target ----
    def arch(self):
        """'x86_64', 'i386', 'aarch64', 'arm', a MIPS processor name, ..., or None."""
        raise NotImplementedError

    def is_pe(self):
        raise NotImplementedError

    # ---- bytes ----
    def input_bytes(self):
        """The input file as loaded, or None when it is no longer on disk."""
        raise NotImplementedError

    def header_bytes(self):
        """The first page of the image (stands in for the file when it is gone)."""
        raise NotImplementedError

    def image_bytes(self):
        """The executable segments, concatenated."""
        raise NotImplementedError

    def has_code(self):
        raise NotImplementedError

    def function_heads(self, n):
        """The first n bytes of every function (fallback for image_bytes)."""
        raise NotImplementedError

    # ---- functions ----
    def functions(self):
        raise NotImplementedError

    def func_start(self, ea):
        """Start of the function containing ea, or None."""
        raise NotImplementedError

    def func_name(self, ea):
        raise NotImplementedError

    def set_func_name(self, ea, name):
        """Rename; an empty name gives the function back its default name. True on success."""
        raise NotImplementedError

    def is_lib(self, ea):
        raise NotImplementedError

    def clear_lib(self, ea):
        raise NotImplementedError

    # ---- comments ----
    def func_cmt(self, ea):
        raise NotImplementedError

    def set_func_cmt(self, ea, text):
        raise NotImplementedError

    def insn_cmt(self, ea):
        raise NotImplementedError

    def set_insn_cmt(self, ea, text):
        raise NotImplementedError

    # ---- types ----
    def type_snapshot(self):
        """{ea: (type, user-specified?)} for every function with a stored type. The type is
        opaque to the caller except for str()."""
        raise NotImplementedError

    def type_str(self, ea):
        raise NotImplementedError

    def has_user_type(self, ea):
        raise NotImplementedError

    def apply_type(self, ea, tif):
        """Set a function's prototype as a user type. True on success."""
        raise NotImplementedError

    def restore_type(self, ea, saved):
        """Drop the function's type, then put back `saved` ((type, user?) or None)."""
        raise NotImplementedError

    # ---- data ----
    def name_at(self, ea):
        raise NotImplementedError

    def cstr_bytes(self, ea):
        """Bytes of the C string at ea, or None if ea is code or a non-byte data item."""
        raise NotImplementedError

    def is_writable(self, ea):
        raise NotImplementedError

    def is_byte_buffer(self, ea):
        """ea is unformatted or byte data (an empty buffer, not a pointer or int)."""
        raise NotImplementedError

    # ---- instructions ----
    def func_items(self, ea):
        """Instruction addresses of the function starting at ea."""
        raise NotImplementedError

    def insn(self, ea):
        """(mnemonic, operand 0, operand 1, operand 2) as printed."""
        raise NotImplementedError

    def wait(self):
        """Let pending auto-analysis finish."""
        raise NotImplementedError


class Signatures:
    """FLIRT signatures and type libraries."""

    def sig_files(self, arch):
        """File names of the installed .sig files for the arch's signature directory."""
        raise NotImplementedError

    def apply(self, signame):
        """Apply a signature now (and wait for it)."""
        raise NotImplementedError

    def ensure_til(self, arch):
        """Load the arch's libc type library."""
        raise NotImplementedError

    def prototype(self, sym):
        """A function type for the symbol from the type libraries, or None."""
        raise NotImplementedError


class Decompiler:
    """Comments stored with decompiled code."""

    def pseudo_comments(self, func_ea, locs):
        """{loc: current text} for the given comment locations of one function."""
        raise NotImplementedError

    def set_pseudo_comments(self, func_ea, texts):
        """Write {loc: text} for one function and save them."""
        raise NotImplementedError
