#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA Better Reverse — know your binary before you read a single line.

An IDA Pro plugin (and standalone CLI) that enriches a disassembly with the context you
normally have to dig for by hand:

  1. Runtime/compiler detection — identifies the C runtime or compiler of a target,
     even when it is stripped and statically linked, using function byte-fingerprint
     matching (glibc 2.19-2.44, musl 1.1.24-1.2.6) across x86_64 / i386 / aarch64,
     GLIBC_2.x version requirements, the .comment toolchain string, Go/Rust build
     strings, PE Rich headers, and UPX / PyInstaller / .NET packers.
  2. FLIRT auto-apply — applies the matching glibc/musl FLIRT signature so library
     functions get their real names back.
  3. libc annotations — adds a one-line "what it does" note to recognised libc
     functions (fopen -> open a file, returns FILE*, ...).
  4. Decompiler annotations — in the pseudocode, annotates library calls and MMX/SSE
     intrinsics with their real arguments AND decoded constants. These render live via
     a Hex-Rays hook (always fresh, nothing written), or can be persisted into the
     database as reversible comments.

  - In IDA:   unzip the release into your IDA user directory, so that `plugins/` holds this
              file and the `ida_better_reverse/` folder, then press Ctrl-Alt-G.
  - As a CLI: `python ida_better_reverse.py <binary>`.

Your existing names and comments are never clobbered, and every change made in a run
can be reverted with one click (Undo).

This file is only the entry point. The code is the `ibr` package in the folder next to it:
ida_better_reverse/ibr when installed, src/ibr in a source checkout.

Repo:    https://github.com/FPSZ/ida-better-reverse
License: MIT
"""
import os as _os
import sys as _sys


def _package_root():
    here = _os.path.dirname(_os.path.abspath(__file__))
    for root in (_os.path.join(here, "ida_better_reverse"), _os.path.join(here, "src")):
        if _os.path.isfile(_os.path.join(root, "ibr", "__init__.py")):
            return root
    raise ImportError(
        "IDA Better Reverse: the folder ida_better_reverse/ is missing next to %s. "
        "Unzip the whole release archive into the IDA user directory. "
        "/ 缺少与本文件同目录的 ida_better_reverse/ 文件夹，请把发布的压缩包完整解压到 IDA 用户目录。" % here)


def _use(root):
    # a single-file build (2.3 and earlier) serves `ibr` from an import hook placed before
    # the path finder; while it is there, `import ibr` would load that old copy instead
    for f in [f for f in _sys.meta_path if getattr(f, "_ibr_bundle", False)]:
        _sys.meta_path.remove(f)
        old = getattr(f, "base", "?")
        print("[IDA Better Reverse] an older single-file copy is also installed, delete it: %s\n"
              "[IDA Better Reverse] 还装着旧版单文件插件，请删除：%s" % (old, old))
    # a reload of this file, or another copy of the plugin, replaces the loaded package
    for m in [m for m in _sys.modules if m == "ibr" or m.startswith("ibr.")]:
        del _sys.modules[m]
    while root in _sys.path:
        _sys.path.remove(root)
    _sys.path.insert(0, root)


_use(_package_root())

# ======================================================================
#  Public names (kept from the single-file versions up to 2.3)
# ======================================================================
from ibr import __version__                             # noqa: E402,F401
from ibr.core.detect import detect                       # noqa: E402,F401
from ibr.core.names import canon, resolve_variant        # noqa: E402,F401
from ibr.core.i18n import set_lang                      # noqa: E402,F401

try:
    import idaapi                                         # noqa: F401
    _IN_IDA = True
except Exception:
    _IN_IDA = False

if _IN_IDA:
    from ibr.adapters.ida.service import *               # noqa: E402,F401,F403
    from ibr.adapters.ida.panel import open_panel        # noqa: E402,F401
    from ibr.adapters.ida.plugin import IBIPlugin, PLUGIN_ENTRY   # noqa: E402,F401


def __getattr__(name):
    """State that now lives in the package, readable under its single-file name."""
    if name == "LANG":
        from ibr.core import i18n
        return i18n.LANG
    if name == "_panel" and _IN_IDA:
        from ibr.adapters.ida import panel
        return panel._panel
    raise AttributeError(name)


if __name__ == "__main__":
    from ibr.adapters.cli import main
    main()
