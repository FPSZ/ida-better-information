# glibc_detect_plugin.py —— IDA 插件:识别 C 运行库版本 + 套签名 + 给 libc 函数加注释(可撤回)
#   Ctrl-Alt-G 打开面板(停靠页签,不弹窗):
#     - 显示检测到的版本/置信度/排名
#     - 勾选:是否套用匹配 FLIRT 签名、是否给已识别 libc 函数加用途注释
#     - [执行] 按勾选干活;[撤回] 一键恢复(函数名 + 注释都回到执行前)
#   注释保留用户原有注释(把 "libc: ..." 加在最前,不顶掉原内容)。
# 安装:复制到 IDA 的 plugins 目录。依赖 D:\CTF\tool\glibc-detect\detect.py + fingerprint.json
import os, re, sys, importlib
import idaapi, ida_kernwin, ida_auto, ida_funcs, idautils, idc, ida_name

# detect.py / fingerprint.json 的位置:优先环境变量,否则插件自身所在目录(把三者放一起即可)
GLIBC_DETECT_DIR = os.environ.get("GLIBC_DETECT_DIR") or os.path.dirname(os.path.abspath(__file__))
if GLIBC_DETECT_DIR not in sys.path: sys.path.insert(0, GLIBC_DETECT_DIR)

try:
    from PySide6 import QtWidgets; _HAS_QT = True
except Exception:
    try:
        from PyQt5 import QtWidgets; _HAS_QT = True
    except Exception:
        _HAS_QT = False

# ===================== libc 注释字典 =====================
def canon(name):
    n = re.sub(r'^_+', '', name); n = re.sub(r'@.*$', '', n)
    n = re.sub(r'_chk$', '', n); n = re.sub(r'_unlocked$', '', n)
    n = re.sub(r'^IO_', '', n); n = re.sub(r'^new_', '', n)
    n = re.sub(r'^libc_', '', n); n = re.sub(r'_internal$', '', n); n = re.sub(r'64$', '', n)
    return n

DESC = {
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
PFX = "libc: "

# 撤回快照(本次会话内累积):改过的函数名、改过的注释
_undo = {"names": {}, "cmts": {}}

def _describe(name):
    d = DESC.get(canon(name)); return (PFX + d) if d else None

def annotate_all():
    """给已识别 libc 函数加注释;保留用户原注释;记录旧值以便撤回。返回新加条数。"""
    n = 0
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea) or ""
        d = _describe(name)
        if not d: continue
        old = idc.get_func_cmt(ea, 1) or ""
        if old.startswith(PFX): continue          # 已是我们加的,幂等跳过
        new = d if not old else (d + "\n" + old)   # ★ 不顶掉用户原注释,加在最前
        if ea not in _undo["cmts"]: _undo["cmts"][ea] = old
        try: idc.set_func_cmt(ea, new, 1); n += 1
        except Exception: pass
    return n

# ===================== 检测 / 套签名 =====================
def run_detection():
    path = idaapi.get_input_file_path()
    if not path or not os.path.exists(path): return None, "找不到输入文件路径"
    try:
        import detect as _d; importlib.reload(_d)
        return _d.detect(path), None
    except Exception as e:
        return None, "detect.py 出错: %s" % e

def _fmt(r):
    if not r: return ""
    try:
        import detect as _d; lab = _d._lib_label
    except Exception:
        lab = lambda v: v
    lines = ["类型: %s / %s" % (r.get("os"), r.get("kind"))]
    if r.get("build_id"): lines.append("build-id: %s" % r["build_id"])
    if r.get("arch"): lines.append("架构: %s  链接器: %s" % (r["arch"], r.get("linker")))
    for v, s, h, n in r.get("ranking", []):
        lines.append("  %-10s %5.1f%%  %d/%d" % (lab(v), s*100, h, n))
    lines.append("结论: %s   置信度=%s" % (r.get("best"), r.get("confidence")))
    for note in r.get("notes", []): lines.append("  · " + note)
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
        return "此类型无需套静态 glibc/musl 签名(%s)。" % kind
    verstr = best.replace("glibc", "").replace("musl", "").strip().lstrip(">=")
    sigs = _find_sigs(verstr)
    if not sigs:
        return "没有 %s 的签名;可运行 activate-sig.sh %s 装一个。" % (best, verstr)
    signame = os.path.splitext(sigs[0])[0]
    before = {ea: (ida_funcs.get_func_name(ea) or "") for ea in idautils.Functions()}
    idaapi.plan_to_apply_idasgn(signame); ida_auto.auto_wait()
    changed = 0
    for ea in idautils.Functions():
        nm = ida_funcs.get_func_name(ea) or ""
        if before.get(ea, "") != nm:
            _undo["names"].setdefault(ea, before.get(ea, ""))   # ★ 记录原名以便撤回
            changed += 1
    named = sum(1 for ea in idautils.Functions() if not (ida_funcs.get_func_name(ea) or "").startswith("sub_"))
    return "已套用 %s;本次命名 %d 个,当前非sub_函数共 %d 个。" % (signame, changed, named)

def do_undo():
    nn = nc = 0
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
    _undo["names"].clear(); _undo["cmts"].clear(); ida_auto.auto_wait()
    return "已撤回:恢复 %d 个函数名、%d 处注释。" % (nn, nc)

# ===================== 面板(停靠页签) =====================
_panel = None

if _HAS_QT:
    class GDPanel(ida_kernwin.PluginForm):
        def OnCreate(self, form):
            conv = getattr(self, "FormToPyWidget", None) or getattr(self, "FormToPyQtWidget")
            self.parent = conv(form); self._r = None; self._build()
        def _build(self):
            L = QtWidgets.QVBoxLayout()
            L.addWidget(QtWidgets.QLabel("<b>glibc-detect</b> — 运行库版本识别 / 套签名 / 加注释"))
            self.result = QtWidgets.QTextEdit(); self.result.setReadOnly(True); self.result.setMinimumHeight(140)
            L.addWidget(self.result)
            self.cb_sig = QtWidgets.QCheckBox("套用匹配的 FLIRT 签名(命名库函数)"); self.cb_sig.setChecked(True)
            self.cb_ann = QtWidgets.QCheckBox("给已识别的 libc 函数加用途注释(保留你原有注释)"); self.cb_ann.setChecked(True)
            L.addWidget(self.cb_sig); L.addWidget(self.cb_ann)
            h = QtWidgets.QHBoxLayout()
            b0 = QtWidgets.QPushButton("重新检测"); b1 = QtWidgets.QPushButton("执行"); b2 = QtWidgets.QPushButton("撤回")
            b0.clicked.connect(self.on_detect); b1.clicked.connect(self.on_run); b2.clicked.connect(self.on_undo)
            h.addWidget(b0); h.addWidget(b1); h.addWidget(b2); L.addLayout(h)
            L.addWidget(QtWidgets.QLabel("日志:"))
            self.log = QtWidgets.QTextEdit(); self.log.setReadOnly(True); L.addWidget(self.log)
            self.parent.setLayout(L); self.on_detect()
        def on_detect(self):
            r, err = run_detection(); self._r = r
            self.result.setPlainText(err if err else _fmt(r))
        def on_run(self):
            if not self._r:
                self.on_detect()
                if not self._r: return
            out = []
            if self.cb_sig.isChecked(): out.append("[签名] " + do_apply_sig(self._r))
            if self.cb_ann.isChecked(): out.append("[注释] 本次新加 %d 处(原注释已保留)。" % annotate_all())
            if not out: out.append("(两项都没勾)")
            self.log.append("\n".join(out)); self.result.setPlainText(_fmt(self._r))
        def on_undo(self):
            self.log.append("[撤回] " + do_undo())
        def OnClose(self, form):
            global _panel; _panel = None

def open_panel():
    global _panel
    if not _HAS_QT:
        r, err = run_detection()
        if err: ida_kernwin.warning(err); return
        f = ida_kernwin.Form(r"""glibc-detect
%s
<##套用匹配签名:{rSig}>
<##给libc函数加注释(保留原注释):{rAnn}>
<##撤回上次执行:{rUndo}>{cG}>
""" % _fmt(r).replace("%", "%%"),
            {"cG": ida_kernwin.Form.ChkGroupControl(("rSig", "rAnn", "rUndo"))})
        f.Compile(); f.rSig.checked = True; f.rAnn.checked = True; f.rUndo.checked = False
        if f.Execute() == 1:
            msg = []
            if f.rUndo.checked:
                msg.append("[撤回] " + do_undo())
            else:
                if f.rSig.checked: msg.append("[签名] " + do_apply_sig(r))
                if f.rAnn.checked: msg.append("[注释] 新加 %d 处。" % annotate_all())
            print("\n".join(msg)); ida_kernwin.info("\n".join(msg) or "无操作")
        f.Free(); return
    _panel = GDPanel()
    try: _panel.Show("glibc-detect", options=ida_kernwin.PluginForm.WOPN_PERSIST)
    except Exception: _panel.Show("glibc-detect")

class GlibcDetectPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Detect C-runtime version; apply FLIRT sig; annotate libc funcs (undoable)"
    help = "Ctrl-Alt-G"
    wanted_name = "glibc-detect"
    wanted_hotkey = "Ctrl-Alt-G"
    def init(self):
        print("[glibc-detect] loaded. Ctrl-Alt-G 打开面板。")
        return idaapi.PLUGIN_KEEP
    def term(self): pass
    def run(self, arg): open_panel()

def PLUGIN_ENTRY():
    return GlibcDetectPlugin()
