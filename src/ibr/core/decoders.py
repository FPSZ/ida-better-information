"""Decode flag/enum constants of libc and syscall arguments, per target."""
from .i18n import T


def _bits(val, table):
    parts = [name for bit, name in table if bit and (val & bit) == bit]
    rest = val
    for bit, _ in table:
        if bit and (val & bit) == bit:
            rest &= ~bit
    zero = [name for bit, name in table if bit == 0]
    if not parts and zero:
        parts = [zero[0]]
    if rest:
        parts.append("0x%X" % rest)
    return "|".join(parts) if parts else "0"

# Constant values follow the Linux UAPI headers. Several differ per architecture
# (open/mmap flags and socket types on ARM and MIPS, signal numbers on MIPS and in
# the Windows CRT), so the decoders read the target from _DEC_CTX, which
# collect_notes sets (set_target) for every function it annotates.
_DEC_CTX = {"arch": "", "pe": False}


def set_target(arch, pe):
    _DEC_CTX.update(arch=arch or "", pe=bool(pe))


def _family():
    a = _DEC_CTX["arch"] or ""
    return "mips" if a.startswith("mips") else "arm" if a in ("arm", "aarch64") else "x86"


_O_COMMON = [(0x80000, "O_CLOEXEC"), (0x40000, "O_NOATIME"), (0x200000, "O_PATH")]
_O_FLAGS = {
    "x86": [(0x40, "O_CREAT"), (0x80, "O_EXCL"), (0x100, "O_NOCTTY"), (0x200, "O_TRUNC"),
            (0x400, "O_APPEND"), (0x800, "O_NONBLOCK"), (0x1000, "O_DSYNC"), (0x2000, "O_ASYNC"),
            (0x4000, "O_DIRECT"), (0x8000, "O_LARGEFILE"), (0x10000, "O_DIRECTORY"),
            (0x20000, "O_NOFOLLOW"), (0x100000, "O_SYNC"), (0x400000, "O_TMPFILE")],
    "arm": [(0x40, "O_CREAT"), (0x80, "O_EXCL"), (0x100, "O_NOCTTY"), (0x200, "O_TRUNC"),
            (0x400, "O_APPEND"), (0x800, "O_NONBLOCK"), (0x1000, "O_DSYNC"), (0x2000, "O_ASYNC"),
            (0x4000, "O_DIRECTORY"), (0x8000, "O_NOFOLLOW"), (0x10000, "O_DIRECT"),
            (0x20000, "O_LARGEFILE"), (0x100000, "O_SYNC"), (0x400000, "O_TMPFILE")],
    "mips": [(0x8, "O_APPEND"), (0x10, "O_DSYNC"), (0x80, "O_NONBLOCK"), (0x100, "O_CREAT"),
             (0x200, "O_TRUNC"), (0x400, "O_EXCL"), (0x800, "O_NOCTTY"), (0x1000, "O_ASYNC"),
             (0x2000, "O_LARGEFILE"), (0x4000, "O_SYNC"), (0x8000, "O_DIRECT"),
             (0x10000, "O_DIRECTORY"), (0x20000, "O_NOFOLLOW"), (0x400000, "O_TMPFILE")],
}


_O_WIN = [(0x8, "_O_APPEND"), (0x10, "_O_RANDOM"), (0x20, "_O_SEQUENTIAL"), (0x40, "_O_TEMPORARY"),
          (0x80, "_O_NOINHERIT"), (0x100, "_O_CREAT"), (0x200, "_O_TRUNC"), (0x400, "_O_EXCL"),
          (0x4000, "_O_TEXT"), (0x8000, "_O_BINARY")]


def _dec_oflags(v):
    if _DEC_CTX["pe"]:                       # MSVC/MinGW CRT _open()
        base = {0: "_O_RDONLY", 1: "_O_WRONLY", 2: "_O_RDWR"}.get(v & 3, "0x%X" % (v & 3))
        extra = _bits(v & ~3, _O_WIN)
        return base + ("|" + extra if extra and extra != "0" else "")
    base = {0: "O_RDONLY", 1: "O_WRONLY", 2: "O_RDWR"}.get(v & 3, "O_ACCMODE")
    extra = _bits(v & ~3, _O_FLAGS[_family()] + _O_COMMON)
    return base + ("|" + extra if extra and extra != "0" else "")


def _o_creat_bit():
    return 0x100 if _DEC_CTX["pe"] or _family() == "mips" else 0x40


_PROT = [(1, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC"), (0, "PROT_NONE")]


def _dec_prot(v):
    s = _bits(v, _PROT)
    return s + (" [RWX]" if (v & 7) == 7 else "")


_MAP_FLAGS = {
    "x86": [(0x10, "MAP_FIXED"), (0x20, "MAP_ANONYMOUS"), (0x40, "MAP_32BIT"),
            (0x100, "MAP_GROWSDOWN"), (0x800, "MAP_DENYWRITE"), (0x1000, "MAP_EXECUTABLE"),
            (0x2000, "MAP_LOCKED"), (0x4000, "MAP_NORESERVE"), (0x8000, "MAP_POPULATE"),
            (0x10000, "MAP_NONBLOCK"), (0x20000, "MAP_STACK"), (0x40000, "MAP_HUGETLB"),
            (0x100000, "MAP_FIXED_NOREPLACE")],
    "mips": [(0x10, "MAP_FIXED"), (0x400, "MAP_NORESERVE"), (0x800, "MAP_ANONYMOUS"),
             (0x1000, "MAP_GROWSDOWN"), (0x2000, "MAP_DENYWRITE"), (0x4000, "MAP_EXECUTABLE"),
             (0x8000, "MAP_LOCKED"), (0x10000, "MAP_POPULATE"), (0x20000, "MAP_NONBLOCK"),
             (0x40000, "MAP_STACK"), (0x80000, "MAP_HUGETLB")],
}


def _dec_map(v):
    kind = {1: "MAP_SHARED", 2: "MAP_PRIVATE", 3: "MAP_SHARED_VALIDATE"}.get(v & 3)
    fl = [(b, n) for b, n in _MAP_FLAGS["mips" if _family() == "mips" else "x86"]
          if not (n == "MAP_32BIT" and _family() != "x86")]
    extra = _bits(v & ~3, fl) if v & ~3 else ""
    return "|".join(p for p in (kind, extra) if p and p != "0") or "0"


_SIG_LINUX = {1:"SIGHUP",2:"SIGINT",3:"SIGQUIT",4:"SIGILL",5:"SIGTRAP",6:"SIGABRT",7:"SIGBUS",
              8:"SIGFPE",9:"SIGKILL",10:"SIGUSR1",11:"SIGSEGV",12:"SIGUSR2",13:"SIGPIPE",
              14:"SIGALRM",15:"SIGTERM",16:"SIGSTKFLT",17:"SIGCHLD",18:"SIGCONT",19:"SIGSTOP",
              20:"SIGTSTP",21:"SIGTTIN",22:"SIGTTOU",23:"SIGURG",24:"SIGXCPU",25:"SIGXFSZ",
              26:"SIGVTALRM",27:"SIGPROF",28:"SIGWINCH",29:"SIGIO",30:"SIGPWR",31:"SIGSYS"}
_SIG_MIPS = {1:"SIGHUP",2:"SIGINT",3:"SIGQUIT",4:"SIGILL",5:"SIGTRAP",6:"SIGABRT",7:"SIGEMT",
             8:"SIGFPE",9:"SIGKILL",10:"SIGBUS",11:"SIGSEGV",12:"SIGSYS",13:"SIGPIPE",
             14:"SIGALRM",15:"SIGTERM",16:"SIGUSR1",17:"SIGUSR2",18:"SIGCHLD",19:"SIGPWR",
             20:"SIGWINCH",21:"SIGURG",22:"SIGIO",23:"SIGSTOP",24:"SIGTSTP",25:"SIGCONT",
             26:"SIGTTIN",27:"SIGTTOU",28:"SIGVTALRM",29:"SIGPROF",30:"SIGXCPU",31:"SIGXFSZ"}
_SIG_WIN = {2:"SIGINT",4:"SIGILL",6:"SIGABRT",8:"SIGFPE",11:"SIGSEGV",15:"SIGTERM",
            21:"SIGBREAK",22:"SIGABRT"}


def _dec_sig(v):
    t = _SIG_WIN if _DEC_CTX["pe"] else _SIG_MIPS if _family() == "mips" else _SIG_LINUX
    return t.get(v, str(v))


def _dec_handler(v):
    # SIG_DFL / SIG_IGN / SIG_ERR are the constants 0, 1, -1 cast to a function pointer
    return {0: "SIG_DFL", 1: "SIG_IGN"}.get(v, "SIG_ERR" if v in (0xFFFFFFFF, (1 << 64) - 1) else "0x%X" % v)


_WHENCE = {0:"SEEK_SET",1:"SEEK_CUR",2:"SEEK_END",3:"SEEK_DATA",4:"SEEK_HOLE"}
_PTRACE = {0:"PTRACE_TRACEME",1:"PTRACE_PEEKTEXT",2:"PTRACE_PEEKDATA",3:"PTRACE_PEEKUSER",
           4:"PTRACE_POKETEXT",5:"PTRACE_POKEDATA",6:"PTRACE_POKEUSER",7:"PTRACE_CONT",
           8:"PTRACE_KILL",9:"PTRACE_SINGLESTEP",12:"PTRACE_GETREGS",13:"PTRACE_SETREGS",
           14:"PTRACE_GETFPREGS",15:"PTRACE_SETFPREGS",16:"PTRACE_ATTACH",17:"PTRACE_DETACH",
           24:"PTRACE_SYSCALL",0x4200:"PTRACE_SETOPTIONS",0x4201:"PTRACE_GETEVENTMSG",
           0x4202:"PTRACE_GETSIGINFO",0x4206:"PTRACE_SEIZE",0x4207:"PTRACE_INTERRUPT"}
_AF = {0:"AF_UNSPEC",1:"AF_UNIX",2:"AF_INET",10:"AF_INET6",16:"AF_NETLINK",17:"AF_PACKET",
       31:"AF_BLUETOOTH",38:"AF_ALG",40:"AF_VSOCK"}


def _dec_socktype(v):
    mips = _family() == "mips"
    kind = ({1:"SOCK_DGRAM",2:"SOCK_STREAM",3:"SOCK_RAW",4:"SOCK_RDM",5:"SOCK_SEQPACKET"} if mips else
            {1:"SOCK_STREAM",2:"SOCK_DGRAM",3:"SOCK_RAW",4:"SOCK_RDM",5:"SOCK_SEQPACKET",10:"SOCK_PACKET"})
    out = [kind.get(v & 0xF, str(v & 0xF))]
    if v & (0x80 if mips else 0x800):
        out.append("SOCK_NONBLOCK")
    if v & 0x80000:
        out.append("SOCK_CLOEXEC")
    return "|".join(out)


_ACCESS = [(4,"R_OK"),(2,"W_OK"),(1,"X_OK"),(0,"F_OK")]
_PRCTL = {1:"PR_SET_PDEATHSIG",2:"PR_GET_PDEATHSIG",3:"PR_GET_DUMPABLE",4:"PR_SET_DUMPABLE",
          15:"PR_SET_NAME",16:"PR_GET_NAME",21:"PR_GET_SECCOMP",22:"PR_SET_SECCOMP",
          38:"PR_SET_NO_NEW_PRIVS",39:"PR_GET_NO_NEW_PRIVS",59:"PR_SET_SYSCALL_USER_DISPATCH",
          0x59616d61:"PR_SET_PTRACER"}
_FCNTL = {0:"F_DUPFD",1:"F_GETFD",2:"F_SETFD",3:"F_GETFL",4:"F_SETFL",5:"F_GETLK",6:"F_SETLK",
          7:"F_SETLKW",8:"F_SETOWN",9:"F_GETOWN",1030:"F_DUPFD_CLOEXEC"}
# MIPS keeps the old SVR4 numbers for the lock and owner requests
_FCNTL_MIPS = {**_FCNTL, 5: "5", 8: "8", 9: "9", 14: "F_GETLK", 23: "F_GETOWN", 24: "F_SETOWN"}


def _dec_fcntl(v):
    return (_FCNTL_MIPS if _family() == "mips" else _FCNTL).get(v, str(v))


_AF_WIN = {0: "AF_UNSPEC", 1: "AF_UNIX", 2: "AF_INET", 23: "AF_INET6"}


_FUTEX = {0: "FUTEX_WAIT", 1: "FUTEX_WAKE", 2: "FUTEX_FD", 3: "FUTEX_REQUEUE",
          4: "FUTEX_CMP_REQUEUE", 5: "FUTEX_WAKE_OP", 6: "FUTEX_LOCK_PI", 7: "FUTEX_UNLOCK_PI",
          8: "FUTEX_TRYLOCK_PI", 9: "FUTEX_WAIT_BITSET", 10: "FUTEX_WAKE_BITSET"}


def _dec_futex(v):
    s = _FUTEX.get(v & 0x7F, str(v & 0x7F))
    if v & 128:
        s += "|FUTEX_PRIVATE_FLAG"
    if v & 256:
        s += "|FUTEX_CLOCK_REALTIME"
    return s


def _dec_char(v):
    if 32 <= v < 127:
        return "'%s'" % chr(v) if chr(v) not in "'\\" else "'\\%s'" % chr(v)
    return {10: "'\\n'", 9: "'\\t'", 13: "'\\r'", 0: "'\\0'"}.get(v, str(v))


def _lut(d):
    return lambda v: d.get(v, "0x%X" % v if v > 9 else str(v))

# function key -> {arg index: decoder(intval)->str}
ARG_DEC = {
    "open":   {1: _dec_oflags}, "openat": {2: _dec_oflags},
    "mmap":   {2: _dec_prot, 3: _dec_map}, "mprotect": {2: _dec_prot},
    "mremap": {3: lambda v: _bits(v, [(1, "MREMAP_MAYMOVE"), (2, "MREMAP_FIXED"), (4, "MREMAP_DONTUNMAP")])},
    "lseek":  {2: _lut(_WHENCE)}, "fseek": {2: _lut(_WHENCE)},
    "kill":   {1: _dec_sig}, "raise": {0: _dec_sig},
    "signal": {0: _dec_sig, 1: _dec_handler}, "sigaction": {0: _dec_sig},
    "ptrace": {0: _lut(_PTRACE)}, "prctl": {0: _lut(_PRCTL)},
    "socket": {0: lambda v: (_AF_WIN if _DEC_CTX["pe"] else _AF).get(v, str(v)),
               1: _dec_socktype},
    "setvbuf": {2: lambda v: {0: T("_IOFBF (full)", "_IOFBF(全缓冲)"),
                              1: T("_IOLBF (line)", "_IOLBF(行缓冲)"),
                              2: T("_IONBF (unbuffered)", "_IONBF(无缓冲)")}.get(v, str(v))},
    "access": {1: lambda v: _bits(v, _ACCESS)},
    "fcntl":  {1: _dec_fcntl}, "futex": {1: _dec_futex},
    "putchar": {0: _dec_char}, "putc": {0: _dec_char}, "fputc": {0: _dec_char},
}
# functions whose first fd arg reads nicely as stdin/stdout/stderr
_FD_FIRST = {"read", "write", "close", "dup", "dup2", "fstat", "lseek", "fsync",
             "ftruncate", "fcntl", "sendfile", "pread", "pwrite", "dprintf"}
_FD_NAMES = {0: "stdin", 1: "stdout", 2: "stderr"}

# ---------- magic constants ----------
MAGIC = {
    0x9E3779B9: ("TEA/XXTEA delta", "TEA/XXTEA delta"),
    0x9E3779B1: ("Fibonacci hashing / xxHash prime", "斐波那契散列常数"),
    0x61707865: ("ChaCha/Salsa 'expa'", "ChaCha/Salsa 'expa'"),
    0x3320646E: ("ChaCha/Salsa 'nd 3'", "ChaCha/Salsa 'nd 3'"),
    0x79622D32: ("ChaCha/Salsa '2-by'", "ChaCha/Salsa '2-by'"),
    0x6B206574: ("ChaCha/Salsa 'te k'", "ChaCha/Salsa 'te k'"),
    0x67452301: ("MD5/SHA1 init A", "MD5/SHA1 初值 A"),
    0xEFCDAB89: ("MD5/SHA1 init B", "MD5/SHA1 初值 B"),
    0x98BADCFE: ("MD5/SHA1 init C", "MD5/SHA1 初值 C"),
    0x10325476: ("MD5/SHA1 init D", "MD5/SHA1 初值 D"),
    0x6A09E667: ("SHA-256 init / sqrt(2)", "SHA-256 初值"),
    0xBB67AE85: ("SHA-256 init h1", "SHA-256 初值 h1"),
    0x5A827999: ("SHA-1 round const", "SHA-1 轮常数"),
    0xEDB88320: ("CRC32 reversed poly", "CRC32 反向多项式"),
    0x04C11DB7: ("CRC32 poly", "CRC32 多项式"),
    0x1F3D5B79: ("Blowfish-ish", "Blowfish 风格常数"),
    0xDEADBEEF: ("0xDEADBEEF marker", "0xDEADBEEF 标记"),
    0xC0FFEE: ("0xC0FFEE marker", "0xC0FFEE 标记"),
    0xCAFEBABE: ("0xCAFEBABE (Java/Mach-O magic)", "0xCAFEBABE 魔数"),
}


# argument counts of the syscalls worth spelling out (names as in the kernel tables)
_SYS_ARGC = {"read": 3, "write": 3, "open": 3, "openat": 4, "close": 1, "lseek": 3, "mmap": 6,
             "mmap2": 6, "mprotect": 3, "munmap": 2, "brk": 1, "ioctl": 3, "pread64": 4,
             "pwrite64": 4, "readv": 3, "writev": 3, "access": 2, "pipe": 1, "pipe2": 2, "dup": 1,
             "dup2": 2, "dup3": 3, "nanosleep": 2, "getpid": 0, "getppid": 0, "getuid": 0,
             "geteuid": 0, "getgid": 0, "gettid": 0, "socket": 3, "connect": 3, "accept": 3,
             "accept4": 4, "sendto": 6, "recvfrom": 6, "bind": 3, "listen": 2, "fork": 0,
             "vfork": 0, "execve": 3, "execveat": 5, "exit": 1, "exit_group": 1, "wait4": 4,
             "kill": 2, "tkill": 2, "tgkill": 3, "fcntl": 3, "chdir": 1, "mkdir": 2, "rmdir": 1,
             "unlink": 1, "chmod": 2, "ptrace": 4, "prctl": 5, "arch_prctl": 2, "alarm": 1,
             "pause": 0, "getrandom": 3, "memfd_create": 2, "seccomp": 3, "rt_sigaction": 4,
             "rt_sigprocmask": 4, "sendfile": 4, "mremap": 5, "madvise": 3, "fstat": 2,
             "stat": 2, "readlink": 3, "time": 1, "setuid": 1, "setgid": 1, "chroot": 1,
             "getcwd": 2, "sched_yield": 0, "uname": 1, "sync": 0, "ftruncate": 2,
             "process_vm_readv": 6, "process_vm_writev": 6, "futex": 6}

# segment-register reads Hex-Rays renders as __readfsqword(off) / __readgsdword(off)
_SEG_ELF = {("fs", 0x0): ("thread control block", "线程控制块 TCB"),
            ("fs", 0x10): ("TCB self pointer", "TCB 自指针"),
            ("fs", 0x28): ("stack canary", "栈 canary"),
            ("fs", 0x30): ("pointer guard (PTR_MANGLE)", "指针保护值 (PTR_MANGLE)"),
            ("gs", 0x0): ("thread control block", "线程控制块 TCB"),
            ("gs", 0x14): ("stack canary", "栈 canary"),
            ("gs", 0x18): ("pointer guard (PTR_MANGLE)", "指针保护值 (PTR_MANGLE)")}
_SEG_PE = {("gs", 0x30): ("TEB", "TEB"), ("gs", 0x60): ("PEB (IsDebuggerPresent / BeingDebugged)", "PEB（常用于反调试）"),
           ("gs", 0x58): ("TLS array", "TLS 数组"), ("fs", 0x0): ("SEH chain", "SEH 链"),
           ("fs", 0x18): ("TEB", "TEB"), ("fs", 0x2C): ("TLS array", "TLS 数组"),
           ("fs", 0x30): ("PEB (IsDebuggerPresent / BeingDebugged)", "PEB（常用于反调试）")}
