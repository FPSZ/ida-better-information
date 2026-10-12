#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA Better Information — know your binary before you read a single line.

A single-file IDA Pro plugin (and standalone CLI) that enriches a disassembly with
the context you normally have to dig for by hand:

  1. Runtime/compiler detection — identifies the C runtime or compiler of a target,
     even when it is stripped and statically linked, using function byte-fingerprint
     matching (glibc 2.19-2.44, musl 1.1.24-1.2.6), GLIBC_2.x version requirements,
     Go build strings and PE Rich headers.
  2. FLIRT auto-apply — applies the matching glibc/musl FLIRT signature so library
     functions get their real names back.
  3. libc annotations — adds a one-line "what it does" note to recognised libc
     functions (fopen -> open a file, returns FILE*, ...).
  4. Math annotations — rewrites arithmetic / logic / MMX-SSE instructions as plain
     infix math (xor eax, ebx  ->  eax = eax ^ ebx ; psrlw mm0, 8 -> mm0 = mm0 >> 8).

The detector and the entire fingerprint database are embedded in THIS single file.
  - In IDA:   drop it into the `plugins/` directory and press Ctrl-Alt-G.
  - As a CLI: `python ida_better_information.py <binary>`.

Your existing names and comments are never clobbered (annotations are prepended),
and every change made in a run can be reverted with one click (Undo).

Repo:    https://github.com/FPSZ/ida-better-information
License: MIT
"""
import os, re, sys, json, gzip, base64, struct

__version__ = "1.1.0"

# ======================================================================
#  Embedded fingerprint database  (gzip + base64 of fingerprint.json)
#  29 builds: glibc 2.19-2.44 + musl 1.1.24/1.2.2-1.2.6, amd64.
#  Rebuild the blob with  tools/embed-fingerprint.py  (see tools/ for how
#  the raw data was generated from Ubuntu libc6-dev / musl-dev via FLAIR).
# ======================================================================
_FP_CACHE = None

def _load_fp():
    global _FP_CACHE
    if _FP_CACHE is None:
        try:
            _FP_CACHE = json.loads(gzip.decompress(base64.b64decode(_FP_B64)))
        except Exception:
            _FP_CACHE = {}
    return _FP_CACHE

def _lib_label(key):
    if key.startswith("musl"):
        return "musl " + key.split("_", 1)[-1]
    return "glibc " + key

# ======================================================================
#  Detection core
# ======================================================================

# ---------- Go ----------
def detect_go(data):
    is_go = (b"\xff Go buildinf:" in data) or (b"Go build ID:" in data) or (b"runtime.buildVersion" in data)
    m = re.search(rb"go1\.\d{1,2}(?:\.\d{1,3})?", data)
    if is_go or m:
        ver = m.group(0).decode() if m else "unknown"
        return {"lang": "go", "version": ver}
    return None

# ---------- Windows PE ----------
def _decode_rich(data, pe_off):
    try:
        head = data[:pe_off]
        ri = head.rfind(b"Rich")
        if ri < 0:
            return None
        key = struct.unpack("<I", head[ri+4:ri+8])[0]
        di = head.rfind(struct.pack("<I", 0x536E6144 ^ key), 0, ri)   # "DanS" ^ key
        if di < 0:
            return None
        comps = []
        off = di + 16
        while off + 8 <= ri:
            v = struct.unpack("<I", head[off:off+4])[0] ^ key
            c = struct.unpack("<I", head[off+4:off+8])[0] ^ key
            prodid, build = v >> 16, v & 0xFFFF
            if prodid or build:
                comps.append((prodid, build, c))
            off += 8
        return comps
    except Exception:
        return None

def detect_pe(data):
    r = {"os": "windows", "arch": None, "linker": None, "rich": None, "notes": []}
    try:
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
            r["notes"].append("MZ but PE header looks off"); return r
        machine = struct.unpack("<H", data[e_lfanew+4:e_lfanew+6])[0]
        r["arch"] = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine, hex(machine))
        opt = e_lfanew + 24
        r["linker"] = "%d.%d" % (data[opt+2], data[opt+3])
        comps = _decode_rich(data, e_lfanew)
        if comps:
            top = max(comps, key=lambda t: t[1])
            r["rich"] = comps
            r["notes"].append("Rich header: highest build=%d (bigger = newer compiler; cross-ref MSVC table)" % top[1])
        else:
            r["notes"].append("no Rich header (non-MSVC, or stripped)")
        r["notes"].append("Windows library funcs: IDA's bundled MSVC/UCRT FLIRT usually names them.")
    except Exception as e:
        r["notes"].append("PE parse error: %s" % e)
    return r

# ---------- Linux ELF ----------
def detect_elf(data, force=None, top=5):
    r = {"os": "linux", "kind": None, "banner": None, "glibc_min": None,
         "build_id": None, "ranking": [], "best": None, "confidence": "low", "notes": []}
    m = re.search(rb"\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00(.{20})", data, re.S)
    if m:
        r["build_id"] = m.group(1).hex()
    m = re.search(rb"GNU C Library[^\x00\n]{0,80}?(?:version|release)[^\x00\n]{0,20}?(\d+\.\d+)", data)
    if not m:
        m = re.search(rb"\bglibc[ -](\d+\.\d+)\b", data)
    if m:
        try: r["banner"] = m.group(1).decode()
        except Exception: pass
    reqs = [int(x) for x in re.findall(rb"GLIBC_2\.(\d+)", data)]
    if reqs:
        r["glibc_min"] = max(reqs)
    has_interp = (b"/ld-linux" in data) or (b"/ld-musl" in data)
    r["kind"] = force or ("dynamic" if has_interp else "static")

    if r["banner"]:
        r["best"] = "glibc " + r["banner"]; r["confidence"] = "high"
        r["notes"].append("version banner present, exact."); return r
    if r["kind"] == "dynamic":
        if b"/ld-musl" in data:
            r["notes"].append("dynamically linked against musl (Alpine).")
            r["best"] = "musl (dynamic)"; r["confidence"] = "medium"; return r
        if r["glibc_min"] is not None:
            r["best"] = "glibc >=2.%s" % r["glibc_min"]; r["confidence"] = "medium"
            r["notes"].append("dynamic: needs glibc >= 2.%s (lower bound, not exact)." % r["glibc_min"])
        if r["build_id"]:
            r["notes"].append("build-id present; resolve the exact build at https://libc.rip .")
        return r

    fp = _load_fp()
    if not fp:
        r["notes"].append("fingerprint DB missing (rebuild the embedded blob)."); return r
    distinct = set()
    for anchors in fp.values():
        distinct.update(anchors)
    present = {}
    for a in distinct:
        try: present[a] = (data.find(bytes.fromhex(a)) != -1)
        except ValueError: present[a] = False
    scored = []
    for ver, anchors in fp.items():
        if not anchors: continue
        hit = sum(1 for a in anchors if present[a])
        scored.append((ver, hit/len(anchors), hit, len(anchors)))
    scored.sort(key=lambda t: t[1], reverse=True)
    r["ranking"] = [(v, round(s, 3), h, n) for (v, s, h, n) in scored[:top]]
    if scored:
        bestver, bests = scored[0][0], scored[0][1]
        second = scored[1][1] if len(scored) > 1 else 0.0
        r["best"] = _lib_label(bestver)
        ratio  = (bests / second) if second > 0 else 999.0
        margin = bests - second
        if   ratio >= 1.15 and margin >= 0.03:  r["confidence"] = "high"
        elif ratio >= 1.06 and margin >= 0.015: r["confidence"] = "medium"
        else:                                   r["confidence"] = "low"
        r["notes"].append("static: function byte-anchor match; clear leader = most likely build.")
        r["notes"].append("lead over #2: %.1f pts (x%.2f)." % (margin*100, ratio))
        if bests < 0.05:
            r["confidence"] = "low"
            r["notes"].append("hit-rate very low: build may be outside the DB.")
        elif r["confidence"] == "low":
            r["notes"].append("top candidates are close; try FLIRT for each.")
    return r

def detect(path, force=None, top=5):
    """Identify the runtime/compiler of a binary. Returns a result dict."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] == b"MZ":
        go = detect_go(data)
        r = detect_pe(data)
        if go:
            r["best"] = "Go " + go["version"]; r["notes"].insert(0, "Go program (PE), version embedded.")
        else:
            r["best"] = "MSVC (see Rich/linker)"
        r["ranking"] = []; r["kind"] = "pe"; r["confidence"] = "high" if go else "medium"
        return r
    if data[:4] == b"\x7fELF":
        go = detect_go(data)
        if go:
            return {"os": "linux", "kind": "go", "best": "Go " + go["version"], "ranking": [],
                    "confidence": "high", "build_id": None,
                    "notes": ["Go program (ELF), version string embedded, exact.",
                              "Go ships its own runtime; glibc version is irrelevant."]}
        return detect_elf(data, force=force, top=top)
    return {"os": "?", "kind": None, "best": None, "ranking": [], "confidence": "low",
            "notes": ["not an ELF/PE file"]}

# ======================================================================
#  Standalone CLI  (used when run with python outside IDA)
# ======================================================================
def _cli():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    force = "static" if "--static" in sys.argv else ("dynamic" if "--dynamic" in sys.argv else None)
    top = 5
    if "--top" in sys.argv:
        try: top = int(sys.argv[sys.argv.index("--top")+1])
        except Exception: pass
    if not args:
        print("IDA Better Information v%s" % __version__)
        print("usage: python ida_better_information.py <binary> [--static|--dynamic] [--top N]")
        sys.exit(1)
    r = detect(args[0], force=force, top=top)
    print("=" * 60)
    print("target    :", args[0])
    print("type      :", r.get("os"), "/", r.get("kind"))
    if r.get("build_id"): print("build-id  :", r["build_id"])
    if r.get("arch"):     print("arch      :", r["arch"], " linker:", r.get("linker"))
    if r.get("ranking"):
        print("-" * 60); print("version ranking (hit-rate  hits/anchors):")
        for v, s, h, n in r["ranking"]:
            print("  %-12s %6.1f%%  %d/%d  %s" % (_lib_label(v), s*100, h, n, "#" * int(s*30)))
    print("-" * 60)
    print("verdict   :", r.get("best"), "  confidence =", r.get("confidence"))
    for note in r.get("notes", []):
        print("  -", note)
    print("=" * 60)

# ======================================================================
#  IDA plugin  (only active when loaded inside IDA)
# ======================================================================
try:
    import idaapi, ida_kernwin, ida_auto, ida_funcs, idautils, idc, ida_name
    _IN_IDA = True
except Exception:
    _IN_IDA = False

if _IN_IDA:
    try:
        from PySide6 import QtWidgets; _HAS_QT = True
    except Exception:
        try:
            from PyQt5 import QtWidgets; _HAS_QT = True
        except Exception:
            _HAS_QT = False

    # ---------- libc annotation ----------
    def canon(name):
        n = re.sub(r'^_+', '', name); n = re.sub(r'@.*$', '', n)
        n = re.sub(r'_chk$', '', n); n = re.sub(r'_unlocked$', '', n)
        n = re.sub(r'^IO_', '', n); n = re.sub(r'^new_', '', n)
        n = re.sub(r'^libc_', '', n); n = re.sub(r'_internal$', '', n); n = re.sub(r'64$', '', n)
        return n

    DESC = {
     "fopen":"open a file, returns FILE*","freopen":"reopen/redirect a stream","fclose":"close a stream",
     "fread":"read N bytes from a stream","fwrite":"write N bytes to a stream","fseek":"move file position",
     "fseeko":"move file position (large)","ftell":"current file position","ftello":"file position (large)","rewind":"rewind to start",
     "fgets":"read a line","fputs":"write a string","fgetc":"read one char","fputc":"write one char",
     "getc":"read one char","putc":"write one char","getchar":"read char from stdin","putchar":"write char to stdout",
     "puts":"print string + newline to stdout","gets":"read a line (unsafe)",
     "printf":"formatted output to stdout","fprintf":"formatted output to a stream","sprintf":"formatted write to a string",
     "snprintf":"formatted write (bounded)","vprintf":"printf, va_list","vfprintf":"fprintf, va_list","vsnprintf":"vsnprintf",
     "scanf":"formatted read from stdin","fscanf":"formatted read from stream","sscanf":"parse from a string",
     "perror":"print error to stderr","fflush":"flush stream buffer","setvbuf":"set stream buffering","feof":"end-of-file?","ferror":"stream error?","fileno":"get stream fd",
     "open":"open a file (fd)","close":"close an fd","read":"read from fd","write":"write to fd","lseek":"move fd position",
     "dup":"duplicate fd","dup2":"duplicate fd to number","pipe":"create a pipe",
     "fork":"create child process","execve":"exec a program (replace image)","execl":"exec a program","execvp":"exec (search PATH)",
     "waitpid":"wait for child","wait":"wait for child","kill":"send a signal","signal":"set signal handler","sigaction":"set signal handler (adv.)",
     "alarm":"schedule SIGALRM","sleep":"sleep (seconds)","usleep":"sleep (microseconds)","nanosleep":"high-res sleep",
     "getpid":"get process id","getppid":"get parent pid","getuid":"get user id","ptrace":"process trace / anti-debug",
     "mmap":"map memory/file","munmap":"unmap memory","mprotect":"change page protection",
     "socket":"create a socket","connect":"connect","bind":"bind address","listen":"listen","accept":"accept connection",
     "send":"send data","recv":"receive data","sendto":"send (UDP)","recvfrom":"receive (UDP)",
     "malloc":"allocate heap","calloc":"allocate + zero","realloc":"resize allocation","free":"free heap",
     "aligned_alloc":"aligned alloc","posix_memalign":"aligned alloc",
     "exit":"exit process (run cleanup)","_exit":"exit now (no cleanup)","abort":"abnormal exit (SIGABRT)","atexit":"register exit callback",
     "atoi":"string -> int","atol":"-> long","atoll":"-> long long","strtol":"-> long (base)","strtoul":"-> ulong",
     "strtoll":"-> long long","strtod":"-> double","qsort":"quicksort (with cmp)","bsearch":"binary search",
     "rand":"pseudo-random","srand":"seed rand","random":"pseudo-random","srandom":"seed random",
     "getenv":"read env var","setenv":"set env var","putenv":"set env var","system":"run a shell command","getopt":"parse CLI options",
     "abs":"int abs","labs":"long abs",
     "strlen":"string length","strnlen":"length (bounded)","strcpy":"copy string","strncpy":"copy (bounded)",
     "strcat":"concatenate","strncat":"concatenate (bounded)","strcmp":"compare strings","strncmp":"compare (n bytes)",
     "strcasecmp":"compare (ignore case)","strncasecmp":"compare (ignore case, n)","strchr":"first char","strrchr":"last char",
     "strstr":"find substring","strtok":"split by delimiter","strdup":"duplicate string (malloc)","strndup":"duplicate (bounded)","strerror":"errno -> text",
     "memcpy":"memory copy (no overlap)","memmove":"memory copy (overlap ok)","memset":"fill memory (often zero)","memcmp":"compare memory",
     "memchr":"find byte in memory","bzero":"zero memory","bcopy":"copy memory","mempcpy":"copy, return end","stpcpy":"copy, return end",
     "isalpha":"is letter?","isdigit":"is digit?","isalnum":"is alnum?","isspace":"is whitespace?","isupper":"is upper?",
     "islower":"is lower?","isxdigit":"is hex digit?","toupper":"to upper","tolower":"to lower",
     "time":"time (seconds)","gettimeofday":"time (microseconds)","clock":"CPU time","localtime":"time -> local struct","strftime":"format time",
     "stack_chk_fail":"stack canary failed (overflow)","assert_fail":"assertion failed","cxa_atexit":"register destructor",
     "start_main":"real entry point, calls main",
    }
    PFX = "libc: "
    OPX = "op: "

    # ---------- language (en / zh), persisted across sessions ----------
    try:
        import ida_diskio
        _CFG = os.path.join(ida_diskio.get_user_idadir(), "ida_better_information.cfg")
    except Exception:
        _CFG = os.path.join(os.path.expanduser("~"), ".ida_better_information.cfg")
    LANG = "en"
    def _load_lang():
        global LANG
        try:
            import json as _j
            v = _j.load(open(_CFG)).get("lang", "en")
            LANG = v if v in ("en", "zh") else "en"
        except Exception:
            LANG = "en"
    def _save_lang():
        try:
            import json as _j
            _j.dump({"lang": LANG}, open(_CFG, "w"))
        except Exception:
            pass
    _load_lang()
    def T(en, zh):
        return zh if LANG == "zh" else en

    # Chinese libc descriptions (same keys as DESC)
    DESC_ZH = {
     "fopen":"打开文件,返回FILE*","freopen":"重开/重定向文件流","fclose":"关闭文件流",
     "fread":"从文件读N字节到缓冲区","fwrite":"把缓冲区N字节写入文件","fseek":"移动文件读写位置",
     "fseeko":"移动文件读写位置(大文件)","ftell":"取当前文件位置","ftello":"取文件位置(大文件)","rewind":"文件位置回开头",
     "fgets":"读一行到缓冲区","fputs":"写字符串到流","fgetc":"读一个字符","fputc":"写一个字符",
     "getc":"读一个字符","putc":"写一个字符","getchar":"从stdin读字符","putchar":"向stdout写字符",
     "puts":"打印字符串+换行到stdout","gets":"读一行(危险)",
     "printf":"格式化输出到stdout","fprintf":"格式化输出到流(常stderr)","sprintf":"格式化写入字符串",
     "snprintf":"格式化写入(带长度上限)","vprintf":"printf的va_list版","vfprintf":"fprintf的va_list版","vsnprintf":"vsnprintf",
     "scanf":"从stdin格式化读入","fscanf":"从流格式化读入","sscanf":"从字符串解析",
     "perror":"打印错误到stderr","fflush":"刷新流缓冲","setvbuf":"设置流缓冲","feof":"是否文件尾","ferror":"流是否出错","fileno":"取流的fd",
     "open":"打开文件(fd)","close":"关闭fd","read":"从fd读","write":"向fd写","lseek":"移动fd位置",
     "dup":"复制fd","dup2":"复制fd到指定号","pipe":"创建管道",
     "fork":"创建子进程","execve":"执行程序(替换映像)","execl":"执行程序","execvp":"执行程序(查PATH)",
     "waitpid":"等待子进程","wait":"等待子进程","kill":"发信号","signal":"设信号处理","sigaction":"设信号处理(高级)",
     "alarm":"定时SIGALRM","sleep":"睡眠(秒)","usleep":"睡眠(微秒)","nanosleep":"高精度睡眠",
     "getpid":"取进程ID","getppid":"取父进程ID","getuid":"取用户ID","ptrace":"进程跟踪/反调试常用",
     "mmap":"映射内存/文件","munmap":"解除内存映射","mprotect":"改内存页权限",
     "socket":"创建套接字","connect":"连接","bind":"绑定地址","listen":"监听","accept":"接受连接",
     "send":"发送数据","recv":"接收数据","sendto":"发送(UDP)","recvfrom":"接收(UDP)",
     "malloc":"分配堆内存","calloc":"分配并清零","realloc":"重分配","free":"释放堆内存",
     "aligned_alloc":"对齐分配","posix_memalign":"对齐分配",
     "exit":"退出进程(走清理)","_exit":"立即退出(不清理)","abort":"异常终止(SIGABRT)","atexit":"注册退出回调",
     "atoi":"字符串转int","atol":"转long","atoll":"转longlong","strtol":"转long(带进制)","strtoul":"转ulong",
     "strtoll":"转longlong","strtod":"转double","qsort":"快排(带比较)","bsearch":"二分查找",
     "rand":"伪随机数","srand":"设随机种子","random":"伪随机数","srandom":"设随机种子",
     "getenv":"读环境变量","setenv":"设环境变量","putenv":"设环境变量","system":"执行shell命令","getopt":"解析命令行选项",
     "abs":"int绝对值","labs":"long绝对值",
     "strlen":"求字符串长度","strnlen":"求长度(上限)","strcpy":"复制字符串","strncpy":"复制(上限)",
     "strcat":"拼接字符串","strncat":"拼接(上限)","strcmp":"比较字符串","strncmp":"比较(前n字节)",
     "strcasecmp":"比较(忽略大小写)","strncasecmp":"比较(忽略大小写,上限)","strchr":"找字符首现","strrchr":"找字符末现",
     "strstr":"找子串","strtok":"按分隔符切分","strdup":"复制字符串(malloc)","strndup":"复制(上限)","strerror":"错误码转描述",
     "memcpy":"内存复制(不重叠)","memmove":"内存复制(可重叠)","memset":"内存填充(常清零)","memcmp":"内存比较",
     "memchr":"内存找字节","bzero":"内存清零","bcopy":"内存复制","mempcpy":"内存复制返回末尾","stpcpy":"复制返回末尾",
     "isalpha":"是否字母","isdigit":"是否数字","isalnum":"是否字母数字","isspace":"是否空白","isupper":"是否大写",
     "islower":"是否小写","isxdigit":"是否十六进制位","toupper":"转大写","tolower":"转小写",
     "time":"取时间(秒)","gettimeofday":"取时间(微秒)","clock":"取CPU时间","localtime":"时间转本地结构","strftime":"格式化时间",
     "stack_chk_fail":"栈溢出保护触发(canary失败)","assert_fail":"断言失败","cxa_atexit":"注册析构",
     "start_main":"程序真正入口,调用main",
    }

    # MMX/SSE intrinsics as Hex-Rays shows them in the decompiler -> (en, zh).
    # keyed WITHOUT leading underscores; lookup strips them.
    INTRIN = {
     "m_pxor":("^ (xor)","异或 ^"), "m_por":("| (or)","或 |"), "m_pand":("& (and)","与 &"),
     "m_pandn":("(~a) & b","andnot (~a)&b"),
     "m_psllwi":("<< per 16b","每16位 左移 <<"), "m_psrlwi":(">> per 16b","每16位 右移 >>"),
     "m_pslldi":("<< per 32b","每32位 左移 <<"), "m_psrldi":(">> per 32b","每32位 右移 >>"),
     "m_psllqi":("<< whole 64b","整块64位 左移 <<"), "m_psrlqi":(">> whole 64b","整块64位 右移 >>"),
     "m_psllw":("<< per 16b","每16位 左移 <<"), "m_psrlw":(">> per 16b","每16位 右移 >>"),
     "m_pslld":("<< per 32b","每32位 左移 <<"), "m_psrld":(">> per 32b","每32位 右移 >>"),
     "m_psllq":("<< whole 64b","整块64位 左移 <<"), "m_psrlq":(">> whole 64b","整块64位 右移 >>"),
     "m_paddb":("+ per byte","每字节 相加 +"), "m_paddw":("+ per 16b","每16位 相加 +"),
     "m_paddd":("+ per 32b","每32位 相加 +"), "m_paddq":("+ per 64b","每64位 相加 +"),
     "m_psubb":("- per byte","每字节 相减 -"), "m_psubw":("- per 16b","每16位 相减 -"),
     "m_psubd":("- per 32b","每32位 相减 -"), "m_psubq":("- per 64b","每64位 相减 -"),
     "m_pmullw":("* per 16b","每16位 相乘 *"), "m_pmulhw":("* hi per 16b","每16位 相乘取高 *"),
     "m_empty":("emms (clear MMX)","emms(清空MMX状态)"),
     "mm_loadu_si128":("load 16 bytes","载入16字节"), "mm_storeu_si128":("store 16 bytes","写出16字节"),
     "mm_load_si128":("load 16 bytes","载入16字节"), "mm_store_si128":("store 16 bytes","写出16字节"),
    }

    # undo snapshots (accumulated within a session)
    _undo = {"names": {}, "cmts": {}, "icmts": {}, "pcmts": []}

    def _describe(name):
        d = (DESC_ZH if LANG == "zh" else DESC).get(canon(name))
        return (PFX + d) if d else None

    def _intrin_note(helper):
        v = INTRIN.get((helper or "").lstrip("_"))
        if not v or not v[0]:
            return None
        return OPX + (v[1] if LANG == "zh" else v[0])

    def annotate_all():
        """Comment recognised libc funcs; keep the user's existing comment; record for undo."""
        n = 0
        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea) or ""
            d = _describe(name)
            if not d: continue
            old = idc.get_func_cmt(ea, 1) or ""
            if old.startswith(PFX): continue
            new = d if not old else (d + "\n" + old)
            if ea not in _undo["cmts"]: _undo["cmts"][ea] = old
            try: idc.set_func_cmt(ea, new, 1); n += 1
            except Exception: pass
        return n

    # ---------- math annotation (arithmetic / logic / vector -> infix) ----------
    # two-operand integer:  dst = dst OP src
    _BIN = {
        "add":"+", "sub":"-", "and":"&", "or":"|", "xor":"^", "imul":"*",
        "shl":"<<", "sal":"<<", "shr":">>", "sar":">>(signed)",
        "rol":"<<<(rot)", "ror":">>>(rot)", "adc":"+(+CF)", "sbb":"-(-CF)",
    }
    # one-operand integer
    _UN = {"not":"~{d}", "neg":"-{d}", "inc":"{d} + 1", "dec":"{d} - 1"}
    # MMX/SSE vector:  (symbol, lane note)
    _VEC = {
        "pxor":("^",""), "pand":("&",""), "por":("|",""), "pandn":("andnot",""),
        "paddb":("+","per byte"), "paddw":("+","per 16b"), "paddd":("+","per 32b"), "paddq":("+","per 64b"),
        "psubb":("-","per byte"), "psubw":("-","per 16b"), "psubd":("-","per 32b"), "psubq":("-","per 64b"),
        "pmullw":("*","per 16b"), "pmulld":("*","per 32b"), "pmuludq":("*","per 32->64b"),
        "psllw":("<<","per 16b"), "pslld":("<<","per 32b"), "psllq":("<<","per 64b"),
        "psrlw":(">>","per 16b"), "psrld":(">>","per 32b"), "psrlq":(">>","per 64b"),
        "psraw":(">>(signed)","per 16b"), "psrad":(">>(signed)","per 32b"),
    }
    # scalar float SSE
    _FP = {"addss":"+","addsd":"+","subss":"-","subsd":"-","mulss":"*","mulsd":"*","divss":"/","divsd":"/"}

    def _ops(ea):
        return (idc.print_operand(ea, 0), idc.print_operand(ea, 1), idc.print_operand(ea, 2))

    def _insn_math(ea):
        m = (idc.print_insn_mnem(ea) or "").lower()
        if not m: return None
        d, s, t = _ops(ea)
        # AVX 3-operand (v-prefixed):  vpxor d,a,b / vaddsd d,a,b
        if m.startswith("v") and t:
            base = m[1:]
            if base in _VEC:
                sym, g = _VEC[base]; g = (" (%s)" % g) if g else ""
                if base == "pxor" and s == t: return "%s = 0" % d
                if base == "pandn": return "%s = (~%s) & %s" % (d, s, t)
                return "%s = %s %s %s%s" % (d, s, sym, t, g)
            if base in _FP: return "%s = %s %s %s" % (d, s, _FP[base], t)
            if base in _BIN: return "%s = %s %s %s" % (d, s, _BIN[base], t)
        # vector 2-operand
        if m in _VEC:
            sym, g = _VEC[m]; g = (" (%s)" % g) if g else ""
            if m == "pxor" and d == s: return "%s = 0" % d
            if m == "pandn": return "%s = (~%s) & %s" % (d, d, s)
            return "%s = %s %s %s%s" % (d, d, sym, s, g)
        if m in _FP:
            return "%s = %s %s %s" % (d, d, _FP[m], s)
        # integer 1-operand
        if m in _UN:
            return "%s = %s" % (d, _UN[m].format(d=d))
        # imul 3-operand:  imul d, s, imm
        if m == "imul" and t:
            return "%s = %s * %s" % (d, s, t)
        # integer 2-operand
        if m in _BIN:
            if m == "xor" and d == s: return "%s = 0" % d
            return "%s = %s %s %s" % (d, d, _BIN[m], s)
        # lea is frequently used for arithmetic
        if m == "lea":
            return "%s = &%s" % (d, s)
        return None

    def annotate_math(func_ea=None):
        """Annotate arithmetic/logic/vector insns in the current function. Returns count, or -1 if cursor not in a function."""
        if func_ea is None:
            func_ea = ida_kernwin.get_screen_ea()
        f = ida_funcs.get_func(func_ea)
        if not f:
            return -1
        n = 0
        for ea in idautils.FuncItems(f.start_ea):
            expr = _insn_math(ea)
            if not expr: continue
            old = idc.get_cmt(ea, 0) or ""
            if old == expr or old.startswith(expr + "  | "):
                continue
            new = expr if not old else (expr + "  | " + old)
            if ea not in _undo["icmts"]: _undo["icmts"][ea] = old
            try: idc.set_cmt(ea, new, 0); n += 1
            except Exception: pass
        return n

    # ---------- argument-aware libc templates (decompiler only) ----------
    # {0},{1},... = rendered actual arguments of the call. If a template can't be
    # filled, we fall back to the generic DESC text. (en, zh)
    TMPL = {
     "sleep":("sleep {0} sec","睡眠 {0} 秒"), "usleep":("sleep {0} us","睡眠 {0} 微秒"),
     "nanosleep":("high-res sleep","高精度睡眠"), "alarm":("SIGALRM in {0}s","{0} 秒后 SIGALRM"),
     "fopen":("open {0} (mode {1})","打开 {0}(模式 {1})"),
     "freopen":("reopen {0} (mode {1})","重开 {0}(模式 {1})"),
     "open":("open {0}","打开 {0}"), "close":("close fd {0}","关闭 fd {0}"),
     "read":("read {2} bytes from fd {0}","从 fd {0} 读 {2} 字节"),
     "write":("write {2} bytes to fd {0}","向 fd {0} 写 {2} 字节"),
     "lseek":("seek fd {0} to {1}","fd {0} 定位到 {1}"),
     "fread":("read {1}x{2} bytes -> {0}","读 {1}x{2} 字节 -> {0}"),
     "fwrite":("write {1}x{2} bytes from {0}","写 {1}x{2} 字节(来自 {0})"),
     "fseek":("seek {0} to {1}","{0} 定位到 {1}"), "fgets":("read a line -> {0} (max {1})","读一行 -> {0}(上限 {1})"),
     "malloc":("alloc {0} bytes","分配 {0} 字节"), "calloc":("alloc {0}x{1}, zeroed","分配 {0}x{1} 并清零"),
     "realloc":("resize {0} -> {1} bytes","把 {0} 重分配为 {1} 字节"), "free":("free {0}","释放 {0}"),
     "aligned_alloc":("alloc {1} bytes, {0}-aligned","分配 {1} 字节,{0} 对齐"),
     "memcpy":("copy {2} bytes {1} -> {0}","复制 {2} 字节 {1} -> {0}"),
     "memmove":("move {2} bytes {1} -> {0}","搬移 {2} 字节 {1} -> {0}"),
     "memset":("fill {0} with {1}, {2} bytes","把 {0} 填成 {1},共 {2} 字节"),
     "memcmp":("compare {2} bytes {0},{1}","比较 {2} 字节 {0},{1}"),
     "mmap":("map {1} bytes","映射 {1} 字节"), "mprotect":("protect {1} bytes @ {0}","改 {0} 起 {1} 字节的权限"),
     "strlen":("length of {0}","{0} 的长度"), "strcpy":("copy {1} -> {0}","复制 {1} -> {0}"),
     "strncpy":("copy {2} bytes {1} -> {0}","复制 {2} 字节 {1} -> {0}"),
     "strcat":("append {1} to {0}","把 {1} 接到 {0}"), "strcmp":("compare {0}, {1}","比较 {0}, {1}"),
     "strncmp":("compare first {2} bytes of {0}, {1}","比较 {0}, {1} 的前 {2} 字节"),
     "strstr":("find {1} in {0}","在 {0} 里找 {1}"), "strchr":("find char {1} in {0}","在 {0} 里找字符 {1}"),
     "strtol":("{0} -> long (base {2})","{0} 转 long(进制 {2})"),
     "atoi":("{0} -> int","{0} 转 int"), "atol":("{0} -> long","{0} 转 long"),
     "printf":("printf {0}","按 {0} 格式打印"), "fprintf":("fprintf {1}","按 {1} 格式打印到流"),
     "sprintf":("sprintf -> {0}, fmt {1}","按 {1} 格式写入 {0}"),
     "snprintf":("write <= {1} bytes -> {0}, fmt {2}","最多 {1} 字节按 {2} 写入 {0}"),
     "puts":("print {0} + newline","打印 {0} 并换行"), "fputs":("write {0}","写字符串 {0}"),
     "putchar":("output char {0}","输出字符 {0}"),
     "system":("run shell: {0}","执行 shell 命令:{0}"), "getenv":("read env {0}","读环境变量 {0}"),
     "setenv":("set env {0}={1}","设环境变量 {0}={1}"), "exit":("exit({0})","退出进程 ({0})"),
     "signal":("on signal {0} -> {1}","信号 {0} 的处理设为 {1}"), "kill":("send signal {1} to pid {0}","给 pid {0} 发信号 {1}"),
     "ptrace":("ptrace req {0}","ptrace 请求 {0}(常见反调试)"),
     "qsort":("sort {1} items of {2} bytes","排序 {1} 个元素(每个 {2} 字节)"),
     "srand":("seed rand = {0}","随机种子 = {0}"),
    }

    def _arg_text(cfunc, a):
        import ida_hexrays as hr
        try:
            while a.op == hr.cot_cast and a.x is not None:
                a = a.x
            op = a.op
            if op == hr.cot_num:
                return str(a.numval())
            if op == hr.cot_str:
                return '"%s"' % a.string
            if op == hr.cot_obj:
                s = idc.get_strlit_contents(a.obj_ea, -1, -1)
                if s:
                    try: s = s.decode("utf-8", "replace")
                    except Exception: s = "%s" % s
                    s = s.replace("\n", "\\n")
                    if len(s) > 24: s = s[:24] + "..."
                    return '"%s"' % s
                return idc.get_name(a.obj_ea) or ("0x%X" % a.obj_ea)
            if op == hr.cot_var:
                return cfunc.lvars[a.v.idx].name
            if op == hr.cot_ref and a.x is not None and a.x.op == hr.cot_var:
                return "&" + cfunc.lvars[a.x.v.idx].name
        except Exception:
            pass
        return "?"

    def _call_note(cfunc, e, nm):
        key = canon(nm)
        try:
            A = [_arg_text(cfunc, a) for a in e.a]
        except Exception:
            A = []
        pair = TMPL.get(key)
        if pair:
            t = pair[1] if LANG == "zh" else pair[0]
            try:
                return PFX + t.format(*A)
            except Exception:
                pass
        d = (DESC_ZH if LANG == "zh" else DESC).get(key)
        return (PFX + d) if d else None

    # ---------- decompiler (pseudocode) annotation ----------
    # Writes Hex-Rays comments shown IN the decompiler, on the call lines of the
    # current function: libc calls (fopen...) and MMX/SSE intrinsics (_m_pxor...).
    _pse_err = [""]

    def _hx_put(cfunc, ea, text, func_ea):
        import ida_hexrays as hr
        for itp in (hr.ITP_SEMI, hr.ITP_BLOCK1, hr.ITP_BLOCK2, hr.ITP_CASE, hr.ITP_COLON,
                    hr.ITP_CURLY1, hr.ITP_CURLY2, hr.ITP_BRACE1, hr.ITP_BRACE2, hr.ITP_ELSE):
            tl = hr.treeloc_t(); tl.ea = ea; tl.itp = itp
            try: prev = cfunc.get_user_cmt(tl, hr.RETRIEVE_ONCE) or ""
            except Exception: prev = ""
            if prev.startswith(PFX) or prev.startswith(OPX):
                return True                                   # already ours, idempotent
            newtext = text if not prev else (text + "   | " + prev)   # keep user's comment
            cfunc.set_user_cmt(tl, newtext)
            cfunc.save_user_cmts(); cfunc.refresh_func_ctext()
            if not cfunc.has_orphan_cmts():
                _undo["pcmts"].append((func_ea, ea, itp, prev))
                return True
            cfunc.del_orphan_cmts()                           # that spot was wrong, try next
        return False

    def annotate_pseudo(func_ea=None):
        """Annotate the CURRENT function in the decompiler. Returns count; -1 cursor not in a
           function; -2 decompiler unavailable; -3 error (see _pse_err[0])."""
        _pse_err[0] = ""
        try:
            import ida_hexrays as hr
        except Exception:
            return -2
        try:
            if not hr.init_hexrays_plugin():
                return -2
            if func_ea is None:
                func_ea = ida_kernwin.get_screen_ea()
            f = ida_funcs.get_func(func_ea)
            if not f:
                return -1
            cfunc = hr.decompile(f.start_ea)
            if not cfunc:
                return -2
            notes = {}
            class _V(hr.ctree_visitor_t):
                def __init__(self): hr.ctree_visitor_t.__init__(self, hr.CV_FAST)
                def visit_expr(self, e):
                    if e.op == hr.cot_call and e.x is not None and e.ea != idaapi.BADADDR:
                        note = None
                        if e.x.op == hr.cot_helper:
                            note = _intrin_note(e.x.helper)
                        elif e.x.op == hr.cot_obj:
                            nm = ida_funcs.get_func_name(e.x.obj_ea) or idc.get_name(e.x.obj_ea) or ""
                            note = _call_note(cfunc, e, nm)
                        if note:
                            notes.setdefault(e.ea, [])
                            if note not in notes[e.ea]: notes[e.ea].append(note)
                    return 0
            _V().apply_to(cfunc.body, None)
            if not notes:
                return 0
            added = 0
            for ea, lst in notes.items():
                if _hx_put(cfunc, ea, "   ".join(lst), func_ea):
                    added += 1
            cfunc.save_user_cmts(); cfunc.refresh_func_ctext()
            return added
        except Exception as ex:
            _pse_err[0] = "%s" % ex
            return -3

    # ---------- detection / FLIRT ----------
    def run_detection():
        path = idaapi.get_input_file_path()
        if not path or not os.path.exists(path):
            return None, "input file path not found"
        try:
            return detect(path), None
        except Exception as e:
            return None, "detect error: %s" % e

    def _fmt(r):
        if not r: return ""
        conf = {"high": T("high","高"), "medium": T("medium","中"),
                "low": T("low","低")}.get(r.get("confidence"), r.get("confidence"))
        lines = [T("type","类型") + ": %s / %s" % (r.get("os"), r.get("kind"))]
        if r.get("build_id"): lines.append("build-id: %s" % r["build_id"])
        if r.get("arch"):
            lines.append(T("arch","架构") + ": %s  " % r["arch"] + T("linker","链接器") + ": %s" % r.get("linker"))
        for v, s, h, n in r.get("ranking", []):
            lines.append("  %-12s %5.1f%%  %d/%d" % (_lib_label(v), s*100, h, n))
        lines.append(T("verdict","结论") + ": %s   " % r.get("best") + T("confidence","置信度") + "=%s" % conf)
        for note in r.get("notes", []): lines.append("  . " + note)
        return "\n".join(lines)

    def _find_sigs(verstr):
        try: sigdir = os.path.join(idaapi.idadir("sig"), "pc")
        except Exception: return []
        out = []
        try:
            for fn in os.listdir(sigdir):
                low = fn.lower()
                if fn.endswith(".sig") and ("glibc" in low or "musl" in low) and verstr in fn:
                    out.append(fn)
        except Exception: pass
        out.sort(key=lambda s: (("amd64" not in s and "a64" not in s), s))
        return out

    def do_apply_sig(r):
        kind = r.get("kind"); best = r.get("best") or ""
        if kind in ("pe", "go", "dynamic", "?") or not r.get("ranking"):
            return T("no static glibc/musl signature needed for this type (%s).",
                     "该类型(%s)不需要套静态 glibc/musl 签名。") % kind
        verstr = best.replace("glibc", "").replace("musl", "").strip().lstrip(">=")
        sigs = _find_sigs(verstr)
        if not sigs:
            return T("no FLIRT .sig for %s in IDA sig/pc. Generate one with FLAIR or grab from a community set.",
                     "IDA sig/pc 里没有 %s 的签名。用 FLAIR 自己生成,或从社区签名集拿一个。") % best
        signame = os.path.splitext(sigs[0])[0]
        before = {ea: (ida_funcs.get_func_name(ea) or "") for ea in idautils.Functions()}
        idaapi.plan_to_apply_idasgn(signame); ida_auto.auto_wait()
        changed = 0
        for ea in idautils.Functions():
            nm = ida_funcs.get_func_name(ea) or ""
            if before.get(ea, "") != nm:
                _undo["names"].setdefault(ea, before.get(ea, ""))
                changed += 1
        named = sum(1 for ea in idautils.Functions() if not (ida_funcs.get_func_name(ea) or "").startswith("sub_"))
        return T("applied %s; named %d this run; %d non-sub_ funcs total.",
                 "已套用 %s;本次命名 %d 个,当前非 sub_ 函数共 %d 个。") % (signame, changed, named)

    # IDA's auto-generated names are reserved: you cannot set them by hand, only clear
    # a name and let IDA regenerate one. Setting e.g. "sub_401CA0" pops "Invalid parameter".
    _DUMMY_RE = re.compile(r'^(sub_|loc_|locret_|unk_|byte_|word_|dword_|qword_|off_|asc_|'
                           r'flt_|dbl_|tbyte_|packreal_|stru_|custdata_|algn_|def_|nullsub_|'
                           r'j_|unknown_libname|__imp_)')

    def _is_dummy_name(nm):
        return (not nm) or bool(_DUMMY_RE.match(nm))

    def do_undo():
        nn = nc = ni = npc = 0
        for ea, old in list(_undo["names"].items()):
            try:
                if _is_dummy_name(old):
                    ok = ida_name.set_name(ea, "", ida_name.SN_NOWARN | ida_name.SN_FORCE)   # clear -> auto name
                else:
                    ok = ida_name.set_name(ea, old, ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE)
                if ok: nn += 1
            except Exception: pass
        for ea, old in list(_undo["cmts"].items()):
            try: idc.set_func_cmt(ea, old or "", 1); nc += 1
            except Exception: pass
        for ea, old in list(_undo["icmts"].items()):
            try: idc.set_cmt(ea, old or "", 0); ni += 1
            except Exception: pass
        if _undo["pcmts"]:                                    # pseudocode comments: re-decompile, restore
            try:
                import ida_hexrays as hr
                byfunc = {}
                for (fea, ea, itp, old) in _undo["pcmts"]:
                    byfunc.setdefault(fea, []).append((ea, itp, old))
                for fea, items in byfunc.items():
                    try:
                        cf = hr.decompile(fea)
                        if not cf: continue
                        for (ea, itp, old) in items:
                            tl = hr.treeloc_t(); tl.ea = ea; tl.itp = itp
                            cf.set_user_cmt(tl, old or ""); npc += 1
                        cf.save_user_cmts(); cf.refresh_func_ctext()
                    except Exception: pass
            except Exception: pass
        _undo["names"].clear(); _undo["cmts"].clear(); _undo["icmts"].clear(); _undo["pcmts"] = []
        try: ida_auto.auto_wait()
        except Exception: pass
        return T("reverted: %d names, %d func comments, %d insn comments, %d pseudocode comments.",
                 "已撤回:%d 个函数名、%d 处函数注释、%d 处指令注释、%d 处伪代码注释。") % (nn, nc, ni, npc)

    # ---------- dockable panel ----------
    _panel = None

    if _HAS_QT:
        class IBIPanel(ida_kernwin.PluginForm):
            def OnCreate(self, form):
                conv = getattr(self, "FormToPyWidget", None) or getattr(self, "FormToPyQtWidget")
                self.parent = conv(form); self._r = None; self._build()
            def _build(self):
                L = QtWidgets.QVBoxLayout()
                top = QtWidgets.QHBoxLayout()
                self.title = QtWidgets.QLabel("<b>IDA Better Information</b>")
                top.addWidget(self.title, 1)
                top.addWidget(QtWidgets.QLabel("Lang:"))
                self.lang = QtWidgets.QComboBox(); self.lang.addItems(["English", "中文"])
                self.lang.setCurrentIndex(1 if LANG == "zh" else 0)
                self.lang.currentIndexChanged.connect(self.on_lang)
                top.addWidget(self.lang)
                L.addLayout(top)
                self.result = QtWidgets.QTextEdit(); self.result.setReadOnly(True); self.result.setMinimumHeight(140)
                L.addWidget(self.result)
                self.cb_sig = QtWidgets.QCheckBox(); self.cb_sig.setChecked(True)
                self.cb_ann = QtWidgets.QCheckBox(); self.cb_ann.setChecked(True)
                self.cb_pse = QtWidgets.QCheckBox(); self.cb_pse.setChecked(True)
                L.addWidget(self.cb_sig); L.addWidget(self.cb_ann); L.addWidget(self.cb_pse)
                h = QtWidgets.QHBoxLayout()
                self.b0 = QtWidgets.QPushButton(); self.b1 = QtWidgets.QPushButton(); self.b2 = QtWidgets.QPushButton()
                self.b0.clicked.connect(self.on_detect); self.b1.clicked.connect(self.on_run); self.b2.clicked.connect(self.on_undo)
                h.addWidget(self.b0); h.addWidget(self.b1); h.addWidget(self.b2); L.addLayout(h)
                self.loglabel = QtWidgets.QLabel()
                L.addWidget(self.loglabel)
                self.log = QtWidgets.QTextEdit(); self.log.setReadOnly(True); L.addWidget(self.log)
                self.parent.setLayout(L)
                self._retext(); self.on_detect()
            def _retext(self):
                self.cb_sig.setText(T("Apply matching FLIRT signature (name library funcs)",
                                      "套用匹配的 FLIRT 签名（命名库函数）"))
                self.cb_ann.setText(T("Annotate libc functions (repeatable, keeps your comments)",
                                      "给 libc 函数加注释（可重复，保留你的注释）"))
                self.cb_pse.setText(T("Annotate CURRENT function in the decompiler (libc calls + MMX/SSE, with real args)",
                                      "给当前函数写反编译注释（库调用+MMX/SSE，带实参）"))
                self.b0.setText(T("Re-detect", "重新检测"))
                self.b1.setText(T("Run", "执行"))
                self.b2.setText(T("Undo", "撤回"))
                self.loglabel.setText(T("log:", "日志："))
            def on_lang(self, idx):
                global LANG
                LANG = "zh" if idx == 1 else "en"
                _save_lang(); self._retext()
                if self._r: self.result.setPlainText(_fmt(self._r))
            def on_detect(self):
                r, err = run_detection(); self._r = r
                self.result.setPlainText(err if err else _fmt(r))
            def on_run(self):
                out = []
                if self.cb_sig.isChecked():
                    if not self._r: self.on_detect()
                    out.append("[sig] " + (do_apply_sig(self._r) if self._r
                               else T("detection failed, cannot apply sig.", "检测失败，无法套签名。")))
                if self.cb_ann.isChecked():
                    n = annotate_all()
                    out.append("[libc] " + T("+%d (on fopen/malloc-type funcs; visible at call sites in the decompiler).",
                                             "+%d（加在 fopen/malloc 这类函数上；反编译里调用处可见）。") % n)
                if self.cb_pse.isChecked():
                    ea = ida_kernwin.get_screen_ea()
                    nm = ida_funcs.get_func_name(ea) if ida_funcs.get_func(ea) else "?"
                    n = annotate_pseudo(ea)
                    if n == -1:
                        out.append("[pseudo] " + T("cursor is NOT inside a function. Click a line inside a function, then Run.",
                                                   "光标不在函数里。先在某个函数内点一行，再执行。"))
                    elif n == -2:
                        out.append("[pseudo] " + T("the Hex-Rays decompiler is not available.",
                                                   "没有 Hex-Rays 反编译器，写不了伪代码注释。"))
                    elif n == -3:
                        out.append("[pseudo] " + T("error: ", "出错：") + _pse_err[0])
                    elif n == 0:
                        out.append("[pseudo] %s: " % nm + T("0 added (no libc/MMX calls, or already annotated).",
                                                            "+0（没有可识别的库/MMX 调用，或已注释过）。"))
                    else:
                        out.append("[pseudo] %s: " % nm + T("+%d comment(s) right in the pseudocode.",
                                                            "+%d 处注释，就在伪代码里。") % n)
                if not out: out.append(T("(nothing selected)", "（什么都没勾）"))
                self.log.append("\n".join(out))
                if self._r: self.result.setPlainText(_fmt(self._r))
            def on_undo(self):
                self.log.append("[undo] " + do_undo())
            def OnClose(self, form):
                global _panel; _panel = None

    def open_panel():
        global _panel
        if not _HAS_QT:
            r, err = run_detection()
            if err: ida_kernwin.warning(err); return
            f = ida_kernwin.Form(r"""IDA Better Information
%s
<##Apply matching FLIRT signature:{rSig}>
<##Annotate libc functions (keep yours):{rAnn}>
<##Annotate current function in decompiler:{rPse}>
<##Undo last run:{rUndo}>{cG}>
""" % _fmt(r).replace("%", "%%"),
                {"cG": ida_kernwin.Form.ChkGroupControl(("rSig", "rAnn", "rPse", "rUndo"))})
            f.Compile(); f.rSig.checked = True; f.rAnn.checked = True; f.rPse.checked = True; f.rUndo.checked = False
            if f.Execute() == 1:
                msg = []
                if f.rUndo.checked:
                    msg.append("[undo] " + do_undo())
                else:
                    if f.rSig.checked: msg.append("[sig] " + do_apply_sig(r))
                    if f.rAnn.checked: msg.append("[libc] added %d." % annotate_all())
                    if f.rPse.checked:
                        n = annotate_pseudo()
                        msg.append("[pseudo] " + ("cursor not in a function." if n == -1 else
                                                  ("no decompiler." if n == -2 else
                                                   ("error: " + _pse_err[0] if n == -3 else "added %d." % n))))
                print("\n".join(msg)); ida_kernwin.info("\n".join(msg) or "nothing to do")
            f.Free(); return
        _panel = IBIPanel()
        try: _panel.Show("IDA Better Information", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        except Exception: _panel.Show("IDA Better Information")

    class IBIPlugin(idaapi.plugin_t):
        flags = idaapi.PLUGIN_KEEP
        comment = "Detect runtime/compiler, apply FLIRT, annotate libc + math (undoable)"
        help = "Ctrl-Alt-G"
        wanted_name = "IDA Better Information"
        wanted_hotkey = "Ctrl-Alt-G"
        def init(self):
            print("[IDA Better Information] " + T("loaded. Press Ctrl-Alt-G.",
                                                  "已加载。按 Ctrl-Alt-G 打开面板。"))
            return idaapi.PLUGIN_KEEP
        def term(self): pass
        def run(self, arg): open_panel()

    def PLUGIN_ENTRY():
        return IBIPlugin()

# ======================================================================
#  Fingerprint blob (do not edit by hand; regenerate with tools/embed-fingerprint.py)
# ======================================================================
_FP_B64 = "@@FINGERPRINT_B64@@"

# ======================================================================
#  CLI entry — must come AFTER _FP_B64 so the DB is loadable when run directly.
# ======================================================================
if __name__ == "__main__":
    _cli()
