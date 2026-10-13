"""Call-site notes on hand-built expression trees (shapes taken from real Hex-Rays output)."""
from fakes import FakeProgram, call, cast, fvar, num, obj, ref, string, var

from ibr.core import i18n
from ibr.core.notes import collect_notes

F = {0x1000: "printf", 0x1010: "_isoc99_scanf", 0x1020: "__syslog_chk", 0x1030: "lseek64",
     0x1040: "_exit", 0x1050: "open", 0x1060: "mprotect", 0x1070: "syscall", 0x1080: "calloc",
     0x1090: "__printf_chk", 0x10A0: "setvbuf", 0x4C0000: "gbuf"}


def note(e, **kw):
    prog = FakeProgram(names=F, **kw)
    by_ea, _ = collect_notes(prog, [e])
    return by_ea.get(e.ea)


def test_printf_binds_each_conversion():
    e = call(0x1000, string("%d %s %d\n"), var("v1"), var("v3"), var("v2"))
    assert note(e) == 'libc: printf "%d %s %d\\n" (%d = v1, %s = v3, %d = v2)'


def test_printf_positional():
    e = call(0x1000, string("%2$s %1$d\n"), var("a1"), var("a2"))
    assert note(e) == 'libc: printf "%2$s %1$d\\n" (%2$s = a2, %1$d = a1)'


def test_printf_star_precision_and_char():
    e = call(0x1000, string("%.*s|%5.2f|%c\n"), var("a1"), var("a2"), fvar("a3"), num(113))
    assert note(e) == "libc: printf \"%.*s|%5.2f|%c\\n\" (%.*s = a2 (precision a1), %5.2f = a3, %c = 'q')"


def test_float_arg_hidden_by_decompiler_takes_no_slot_on_sysv():
    # x86-64 passes doubles in xmm registers; an optimised call often shows only the ints
    e = call(0x1000, string("%d %f %s\n"), var("a1"), var("a2"))
    assert note(e) == 'libc: printf "%d %f %s\\n" (%d = a1, %s = a2)'
    assert note(e, pe=True) == 'libc: printf "%d %f %s\\n" (%d = a1, %f = a2)'


def test_scanf_suppressed_and_scanset():
    assert note(call(0x1010, string("%*d %d"), ref(var("v1")))) == 'libc: scanf "%*d %d" (%d -> &v1)'
    e = call(0x1010, string("%99[^\n] %d"), var("v3"), ref(var("v2")))
    assert note(e) == 'libc: scanf "%99[^\\n] %d" (%99[^\\n] -> v3, %d -> &v2)'


def test_fortified_variants_drop_their_extra_args():
    e = call(0x1020, num(6), num(1), string("user %s id %d"), var("a2"), var("a1"))
    assert note(e) == 'libc: syslog "user %s id %d" (%s = a2, %d = a1)'
    e = call(0x1090, num(2), string("%d\n"), var("v1"))
    assert note(e) == 'libc: printf "%d\\n" (%d = v1)'


def test_writable_global_format_is_a_bug():
    e = call(0x1000, obj(0x4C0000, "gbuf"))
    assert note(e, writable={0x4C0000}) == \
        "libc: printf: the format (gbuf) is not a literal, check for a format-string bug"
    # a read-only global we cannot decode is not evidence of a bug
    assert note(e) == "libc: printf gbuf"


def test_seek_reads_relative_offsets():
    fd = var("fd")
    assert note(call(0x1030, fd, num(0, 8), num(2))) == "libc: seek fd to the end"
    assert note(call(0x1030, fd, num(-16, 8), num(1))) == "libc: seek fd to the current position - 16"
    assert note(call(0x1030, fd, num(128, 8), num(0))) == "libc: seek fd to 128"


def test_exit_variants_are_not_merged():
    assert note(call(0x1040, var("n4"))) == "libc: exit now, status n4"


def test_constants_are_decoded_per_architecture():
    e = call(0x1050, string("flag"), num(0x241), num(0o644))
    assert note(e) == 'libc: open "flag" (O_WRONLY|O_CREAT|O_TRUNC, mode 0644)'
    e = call(0x1050, string("flag"), num(0x301), num(0o644))
    assert note(e, arch="mipsb") == 'libc: open "flag" (O_WRONLY|O_CREAT|O_TRUNC, mode 0644)'
    e = call(0x1060, var("p"), num(0x1000), num(7))
    assert note(e) == "libc: protect 4096 bytes @ p: PROT_READ|PROT_WRITE|PROT_EXEC [RWX]"


def test_raw_syscall_named_from_its_number():
    e = call(0x1070, num(59), var("path"), var("argv"), num(0, 8))
    assert note(e) == "sys: execve(path, argv, 0) (#59)"


def test_calloc_parenthesises_compound_counts():
    e = call(0x1080, cast(var("n"), "(n + 1)"), num(16))
    e.args[0] = type(e.args[0])("other", "n + 1")
    assert note(e) == "libc: alloc (n + 1) x 16 bytes, zeroed"


def test_chinese_output():
    i18n.set_lang("zh")
    assert note(call(0x1030, var("fd"), num(0, 8), num(2))) == "libc: fd 定位到 末尾"
    assert note(call(0x10A0, var("stdout"), num(0), num(2), num(0))) == "libc: stdout 缓冲方式:_IONBF(无缓冲)"
