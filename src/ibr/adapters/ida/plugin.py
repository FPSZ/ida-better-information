"""IDA plugin entry (Ctrl-Alt-G)."""
import idaapi

from ...core.i18n import T
from . import live
from .panel import open_panel
from .settings import load_lang

load_lang()


class IBIPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Detect runtime/compiler, apply FLIRT, annotate libc + math (undoable)"
    help = "Ctrl-Alt-G"
    wanted_name = "IDA Better Reverse"
    wanted_hotkey = "Ctrl-Alt-G"

    def init(self):
        print("[IDA Better Reverse] " + T("loaded. Press Ctrl-Alt-G.",
                                          "已加载。按 Ctrl-Alt-G 打开面板。"))
        try:                                      # needs Hex-Rays
            from . import flowview
            flowview.install()
        except Exception:
            pass
        return idaapi.PLUGIN_KEEP

    def term(self):
        try:
            if live._HOOKS is not None and live._hook_installed[0]:
                live._HOOKS.unhook()
        except Exception:
            pass
        try:
            from . import flowview
            flowview.uninstall()
        except Exception:
            pass

    def run(self, arg):
        open_panel()


def PLUGIN_ENTRY():
    return IBIPlugin()
