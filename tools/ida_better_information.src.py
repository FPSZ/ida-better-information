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

__version__ = "1.0.0"

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

    # undo snapshots (accumulated within a session)
    _undo = {"names": {}, "cmts": {}, "icmts": {}}

    def _describe(name):
        d = DESC.get(canon(name))
        return (PFX + d) if d else None

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
        lines = ["type: %s / %s" % (r.get("os"), r.get("kind"))]
        if r.get("build_id"): lines.append("build-id: %s" % r["build_id"])
        if r.get("arch"): lines.append("arch: %s  linker: %s" % (r["arch"], r.get("linker")))
        for v, s, h, n in r.get("ranking", []):
            lines.append("  %-12s %5.1f%%  %d/%d" % (_lib_label(v), s*100, h, n))
        lines.append("verdict: %s   confidence=%s" % (r.get("best"), r.get("confidence")))
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
            return "no static glibc/musl signature needed for this type (%s)." % kind
        verstr = best.replace("glibc", "").replace("musl", "").strip().lstrip(">=")
        sigs = _find_sigs(verstr)
        if not sigs:
            return "no FLIRT .sig for %s in IDA sig/pc. Generate one with FLAIR or grab from a community set." % best
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
        return "applied %s; named %d this run; %d non-sub_ funcs total." % (signame, changed, named)

    def do_undo():
        nn = nc = ni = 0
        for ea, old in list(_undo["names"].items()):
            try:
                ida_name.set_name(ea, old or "", ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE)
                nn += 1
            except Exception:
                try: idc.set_name(ea, old or ""); nn += 1
                except Exception: pass
        for ea, old in list(_undo["cmts"].items()):
            try: idc.set_func_cmt(ea, old or "", 1); nc += 1
            except Exception: pass
        for ea, old in list(_undo["icmts"].items()):
            try: idc.set_cmt(ea, old or "", 0); ni += 1
            except Exception: pass
        _undo["names"].clear(); _undo["cmts"].clear(); _undo["icmts"].clear(); ida_auto.auto_wait()
        return "reverted: %d names, %d func comments, %d insn comments." % (nn, nc, ni)

    # ---------- dockable panel ----------
    _panel = None

    if _HAS_QT:
        class IBIPanel(ida_kernwin.PluginForm):
            def OnCreate(self, form):
                conv = getattr(self, "FormToPyWidget", None) or getattr(self, "FormToPyQtWidget")
                self.parent = conv(form); self._r = None; self._build()
            def _build(self):
                L = QtWidgets.QVBoxLayout()
                L.addWidget(QtWidgets.QLabel("<b>IDA Better Information</b> &mdash; runtime detect / FLIRT / annotate"))
                self.result = QtWidgets.QTextEdit(); self.result.setReadOnly(True); self.result.setMinimumHeight(140)
                L.addWidget(self.result)
                self.cb_sig = QtWidgets.QCheckBox("Apply matching FLIRT signature (name library funcs)"); self.cb_sig.setChecked(True)
                self.cb_ann = QtWidgets.QCheckBox("Annotate libc functions (keeps your comments)"); self.cb_ann.setChecked(True)
                self.cb_math = QtWidgets.QCheckBox("Annotate math in CURRENT function (eax = eax ^ ebx)"); self.cb_math.setChecked(False)
                L.addWidget(self.cb_sig); L.addWidget(self.cb_ann); L.addWidget(self.cb_math)
                h = QtWidgets.QHBoxLayout()
                b0 = QtWidgets.QPushButton("Re-detect"); b1 = QtWidgets.QPushButton("Run"); b2 = QtWidgets.QPushButton("Undo")
                b0.clicked.connect(self.on_detect); b1.clicked.connect(self.on_run); b2.clicked.connect(self.on_undo)
                h.addWidget(b0); h.addWidget(b1); h.addWidget(b2); L.addLayout(h)
                L.addWidget(QtWidgets.QLabel("log:"))
                self.log = QtWidgets.QTextEdit(); self.log.setReadOnly(True); L.addWidget(self.log)
                self.parent.setLayout(L); self.on_detect()
            def on_detect(self):
                r, err = run_detection(); self._r = r
                self.result.setPlainText(err if err else _fmt(r))
            def on_run(self):
                out = []
                if self.cb_sig.isChecked():
                    if not self._r: self.on_detect()
                    out.append("[sig] " + (do_apply_sig(self._r) if self._r else "detection failed, cannot apply sig."))
                if self.cb_ann.isChecked():
                    out.append("[libc] added %d comment(s) this run (yours preserved)." % annotate_all())
                if self.cb_math.isChecked():
                    n = annotate_math()
                    out.append("[math] cursor is not inside a function." if n < 0
                               else "[math] current function: %d comment(s) added (yours preserved)." % n)
                if not out: out.append("(nothing selected)")
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
<##Annotate math in current function:{rMath}>
<##Undo last run:{rUndo}>{cG}>
""" % _fmt(r).replace("%", "%%"),
                {"cG": ida_kernwin.Form.ChkGroupControl(("rSig", "rAnn", "rMath", "rUndo"))})
            f.Compile(); f.rSig.checked = True; f.rAnn.checked = True; f.rMath.checked = False; f.rUndo.checked = False
            if f.Execute() == 1:
                msg = []
                if f.rUndo.checked:
                    msg.append("[undo] " + do_undo())
                else:
                    if f.rSig.checked: msg.append("[sig] " + do_apply_sig(r))
                    if f.rAnn.checked: msg.append("[libc] added %d." % annotate_all())
                    if f.rMath.checked:
                        n = annotate_math()
                        msg.append("[math] cursor not in a function." if n < 0 else "[math] added %d." % n)
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
            print("[IDA Better Information] loaded. Press Ctrl-Alt-G.")
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
