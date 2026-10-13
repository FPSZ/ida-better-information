"""Function-name normalisation: thunks, fortified variants, IDA placeholder names."""
import re


def canon(name):
    n = name or ''
    n = re.sub(r'^\.+', '', n)               # import-thunk notation: .open -> open
    n = re.sub(r'^j_', '', n)                # jump thunk: j_open -> open
    if re.fullmatch(r'_+[eE]xit(?:@.*)?', n):
        return "_exit"                       # _exit/_Exit skip atexit handlers; exit does not
    n = re.sub(r'^_+', '', n); n = re.sub(r'@.*$', '', n)
    n = re.sub(r'^isoc\d+_', '', n)          # __isoc99_scanf / __isoc23_strtol
    n = re.sub(r'_chk$', '', n); n = re.sub(r'_unlocked$', '', n)
    n = re.sub(r'^IO_', '', n); n = re.sub(r'^new_', '', n)
    n = re.sub(r'^libc_', '', n); n = re.sub(r'_internal$', '', n)
    n = re.sub(r'_nocancel$', '', n)         # __read_nocancel / __open_nocancel in static glibc
    n = re.sub(r'64$', '', n)
    return _ALIASES.get(n, n)


# glibc names the signal() implementation __bsd_signal and exports it under aliases
_ALIASES = {"bsd_signal": "signal", "ssignal": "signal", "sysv_signal": "signal"}


# __*_chk and friends carry extra leading/trailing args; map to (base, kept-arg-indices).
# A kept index of -1 means "insert a placeholder" (not used); None list = all args.
_VARIANTS = {
    "__printf_chk":    ("printf",    [1]),                 # (flag, fmt, ...)
    "__fprintf_chk":   ("fprintf",   [0, 2]),              # (fp, flag, fmt, ...)
    "__dprintf_chk":   ("dprintf",   [0, 2]),
    "__sprintf_chk":   ("sprintf",   [0, 3]),              # (s, flag, slen, fmt, ...)
    "__snprintf_chk":  ("snprintf",  [0, 1, 4]),           # (s, maxlen, flag, slen, fmt, ...)
    "__vprintf_chk":   ("vprintf",   [1]),
    "__vfprintf_chk":  ("vfprintf",  [0, 2]),
    "__vsnprintf_chk": ("vsnprintf", [0, 1, 4]),
    "__memcpy_chk":    ("memcpy",    [0, 1, 2]),           # (dst, src, len, destlen)
    "__memmove_chk":   ("memmove",   [0, 1, 2]),
    "__mempcpy_chk":   ("mempcpy",   [0, 1, 2]),
    "__memset_chk":    ("memset",    [0, 1, 2]),
    "__strcpy_chk":    ("strcpy",    [0, 1]),
    "__strncpy_chk":   ("strncpy",   [0, 1, 2]),
    "__strcat_chk":    ("strcat",    [0, 1]),
    "__strncat_chk":   ("strncat",   [0, 1, 2]),
    "__stpcpy_chk":    ("stpcpy",    [0, 1]),
    "__syslog_chk":    ("syslog",    [0, 2]),              # (pri, flag, fmt, ...)
    "__vsprintf_chk":  ("vsprintf",  [0, 3]),              # (s, flag, slen, fmt, ap)
    "__fread_chk":     ("fread",     [0, 2, 3, 4]),        # (ptr, ptrlen, size, n, fp)
    "__read_chk":      ("read",      [0, 1, 2]),           # (fd, buf, nbytes, buflen)
    "__fgets_chk":     ("fgets",     [0, 2, 3]),           # (buf, size, n, fp)
}


def resolve_variant(name):
    """Return (base_key, kept_indices_or_None) for a possibly fortified name."""
    n = (name or "").lstrip("._")            # drop import-thunk dots / leading underscores
    key = "__" + n
    if key in _VARIANTS:
        return _VARIANTS[key]
    return canon(name), None


# IDA's placeholder names: FLIRT's "library code, name unknown" and plain auto-names
_AUTONAME = re.compile(r"^(?:sub|nullsub|j_sub|unknown_libname)_[0-9A-Fa-f]+$")


_DUMMY_RE = re.compile(r'^(sub_|loc_|locret_|unk_|byte_|word_|dword_|qword_|off_|asc_|'
                       r'flt_|dbl_|tbyte_|packreal_|stru_|custdata_|algn_|def_|nullsub_|'
                       r'j_|unknown_libname|__imp_)')


def _is_dummy_name(nm):
    return (not nm) or bool(_DUMMY_RE.match(nm))
