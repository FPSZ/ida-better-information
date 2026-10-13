"""The dockable panel (Qt) and the plain form used when Qt is missing."""
import ida_funcs
import ida_kernwin
import idaapi

from ...core import i18n
from ...core.i18n import T
from ...core.report import _fmt
from .service import (_pse_err, annotate_all, annotate_math, annotate_pseudo, do_apply_sig, do_undo,
                      run_detection, set_live_render)
from .settings import save_lang

# the binding must match IDA's own Qt: Qt6/PySide6 from IDA 9.2, Qt5/PyQt5 before.
# A pip-installed PySide6 inside an IDA 9.1 would otherwise load Qt6 into a Qt5 process.
_HAS_QT = False
for _qt in (("PySide6", "PyQt5") if getattr(idaapi, "IDA_SDK_VERSION", 0) >= 920
            else ("PyQt5", "PySide6")):
    try:
        QtWidgets = __import__(_qt + ".QtWidgets", fromlist=["QtWidgets"]); _HAS_QT = True
        break
    except Exception:
        pass

_panel = None

if _HAS_QT:
    class IBIPanel(ida_kernwin.PluginForm):
        def OnCreate(self, form):
            conv = getattr(self, "FormToPyWidget", None) or getattr(self, "FormToPyQtWidget")
            self.parent = conv(form); self._r = None; self._build()

        def _build(self):
            L = QtWidgets.QVBoxLayout()
            top = QtWidgets.QHBoxLayout()
            self.title = QtWidgets.QLabel("<b>IDA Better Reverse</b>")
            top.addWidget(self.title, 1)
            top.addWidget(QtWidgets.QLabel("Lang:"))
            self.lang = QtWidgets.QComboBox(); self.lang.addItems(["English", "中文"])
            self.lang.setCurrentIndex(1 if i18n.LANG == "zh" else 0)
            self.lang.currentIndexChanged.connect(self.on_lang)
            top.addWidget(self.lang)
            L.addLayout(top)
            self.result = QtWidgets.QTextEdit(); self.result.setReadOnly(True); self.result.setMinimumHeight(150)
            L.addWidget(self.result)
            self.cb_live = QtWidgets.QCheckBox(); self.cb_live.setChecked(True)
            self.cb_live.stateChanged.connect(self.on_live)
            self.cb_sig = QtWidgets.QCheckBox(); self.cb_sig.setChecked(True)
            self.cb_ann = QtWidgets.QCheckBox(); self.cb_ann.setChecked(True)
            self.cb_pse = QtWidgets.QCheckBox(); self.cb_pse.setChecked(False)
            self.cb_math = QtWidgets.QCheckBox(); self.cb_math.setChecked(False)
            for w in (self.cb_live, self.cb_sig, self.cb_ann, self.cb_pse, self.cb_math):
                L.addWidget(w)
            h = QtWidgets.QHBoxLayout()
            self.b0 = QtWidgets.QPushButton(); self.b1 = QtWidgets.QPushButton(); self.b2 = QtWidgets.QPushButton()
            self.b0.clicked.connect(self.on_detect); self.b1.clicked.connect(self.on_run); self.b2.clicked.connect(self.on_undo)
            h.addWidget(self.b0); h.addWidget(self.b1); h.addWidget(self.b2); L.addLayout(h)
            self.loglabel = QtWidgets.QLabel()
            L.addWidget(self.loglabel)
            self.log = QtWidgets.QTextEdit(); self.log.setReadOnly(True); L.addWidget(self.log)
            self.parent.setLayout(L)
            self._retext()
            set_live_render(True)     # live annotations on by default

        def _retext(self):
            # short labels (they truncate in a docked panel); details live in tooltips
            for cb, en, zh, ten, tzh in (
                    (self.cb_live, "Live annotations", "实时注释",
                     "Annotate the decompiler as you browse. Writes nothing to the database.",
                     "浏览时实时给反编译加注释，不写数据库。"),
                    (self.cb_sig, "Apply FLIRT signature", "套用 FLIRT 签名",
                     "Name library functions with the signature matching the detected build.",
                     "用与识别结果匹配的签名给库函数命名。"),
                    (self.cb_ann, "Describe libc functions", "libc 函数说明",
                     "Add a one-line description to recognised libc functions (keeps your comments).",
                     "给识别出的 libc 函数加一行用途说明（保留你的注释）。"),
                    (self.cb_pse, "Persist comments (this function)", "注释落盘（当前函数）",
                     "Write the current function's annotations into the database as comments.",
                     "把当前函数的注释作为普通注释写进数据库。"),
                    (self.cb_math, "Math / SIMD in disassembly", "反汇编算术 / SIMD",
                     "Annotate arithmetic and vector instructions of the current function.",
                     "给当前函数的算术和向量指令加注释。")):
                cb.setText(T(en, zh)); cb.setToolTip(T(ten, tzh))
            self.b0.setText(T("Detect", "检测"))
            self.b1.setText(T("Run", "执行"))
            self.b2.setText(T("Undo", "撤回"))
            self.loglabel.setText(T("log:", "日志："))

        def on_lang(self, idx):
            i18n.set_lang("zh" if idx == 1 else "en")
            save_lang(); self._retext()
            if self._r:
                self.result.setPlainText(_fmt(self._r))
            set_live_render(self.cb_live.isChecked())    # re-render in new language

        def on_live(self, _state):
            set_live_render(self.cb_live.isChecked())

        def on_detect(self):
            r, err = run_detection(); self._r = r
            self.result.setPlainText(err if err else _fmt(r))

        def on_run(self):
            out = []
            if self.cb_sig.isChecked():
                if not self._r:
                    self.on_detect()
                out.append("[sig] " + (do_apply_sig(self._r) if self._r
                           else T("detect first.", "先检测。")))
            if self.cb_ann.isChecked():
                out.append("[libc] " + T("+%d function comments.", "+%d 处函数注释。") % annotate_all())
            if self.cb_pse.isChecked():
                ea = ida_kernwin.get_screen_ea()
                nm = ida_funcs.get_func_name(ea) if ida_funcs.get_func(ea) else "?"
                n = annotate_pseudo(ea)
                out.append("[pseudo] " + self._pseudo_msg(nm, n))
            if self.cb_math.isChecked():
                n = annotate_math()
                out.append("[math] " + (T("cursor not in a function.", "光标不在函数里。") if n == -1
                                        else T("+%d insn comments.", "+%d 处指令注释。") % n))
            if not out:
                out.append(T("(nothing selected)", "（什么都没勾）"))
            set_live_render(self.cb_live.isChecked())     # resumes the notes Undo paused
            self.log.append("\n".join(out))
            if self._r:
                self.result.setPlainText(_fmt(self._r))

        def _pseudo_msg(self, nm, n):
            if n == -1:
                return T("cursor not inside a function.", "光标不在函数里。")
            if n == -2:
                return T("Hex-Rays decompiler unavailable.", "没有 Hex-Rays 反编译器。")
            if n == -3:
                return T("error: ", "出错：") + _pse_err[0]
            if n == 0:
                return "%s: " % nm + T("nothing to annotate.", "没有可注释的调用。")
            return "%s: " % nm + T("+%d comment(s).", "+%d 处注释。") % n

        def on_undo(self):
            # do_undo pauses the live notes; the checkbox keeps the preference and
            # the next Run brings them back
            self.log.append("[undo] " + do_undo())

        def OnClose(self, form):
            global _panel; _panel = None

def open_panel():
    global _panel
    if not _HAS_QT:
        r, err = run_detection()
        if err:
            ida_kernwin.warning(err); return
        set_live_render(True)
        f = ida_kernwin.Form(r"""IDA Better Reverse
%s
<##Apply matching FLIRT signature:{rSig}>
<##Annotate libc functions (keep yours):{rAnn}>
<##Persist decompiler comments (current func):{rPse}>
<##Annotate math/SIMD in disassembly:{rMath}>
<##Undo last run:{rUndo}>{cG}>
""" % _fmt(r).replace("%", "%%"),
            {"cG": ida_kernwin.Form.ChkGroupControl(("rSig", "rAnn", "rPse", "rMath", "rUndo"))})
        f.Compile(); f.rSig.checked = True; f.rAnn.checked = True
        f.rPse.checked = False; f.rMath.checked = False; f.rUndo.checked = False
        if f.Execute() == 1:
            msg = []
            if f.rUndo.checked:
                msg.append("[undo] " + do_undo())
            else:
                if f.rSig.checked:
                    msg.append("[sig] " + do_apply_sig(r))
                if f.rAnn.checked:
                    msg.append("[libc] +%d." % annotate_all())
                if f.rPse.checked:
                    n = annotate_pseudo()
                    msg.append("[pseudo] " + ("not in a function." if n == -1 else
                                              ("no decompiler." if n == -2 else
                                               ("error: " + _pse_err[0] if n == -3 else "+%d." % n))))
                if f.rMath.checked:
                    msg.append("[math] +%d." % annotate_math())
            print("\n".join(msg)); ida_kernwin.info("\n".join(msg) or "nothing to do")
        f.Free(); return
    _panel = IBIPanel()
    try:
        _panel.Show("IDA Better Reverse", options=ida_kernwin.PluginForm.WOPN_PERSIST)
    except Exception:
        _panel.Show("IDA Better Reverse")
