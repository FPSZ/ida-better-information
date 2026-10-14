#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the release zip from ida_better_reverse.py and the package in src/ibr.

The zip unpacks into the IDA user directory (or the IDA install directory):

    plugins/ida_better_reverse.py          entry point
    plugins/ida_better_reverse/ibr/...     the package, with ibr/data/
    plugins/ida_better_reverse/LICENSE

The output is reproducible: sorted entries, fixed timestamps, text files with LF endings
(a checkout with core.autocrlf=true has CRLF in the working copy).

usage: python tools/package.py [out.zip]      (default: dist/ida_better_reverse.zip)
"""
import hashlib
import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG = os.path.join(ROOT, "src", "ibr")
ENTRY = "ida_better_reverse.py"
FOLDER = "plugins/ida_better_reverse/"
TEXT = (".py", ".json", ".txt", ".md")


def files():
    """(path inside the zip, path on disk), sorted."""
    out = [("plugins/" + ENTRY, os.path.join(ROOT, ENTRY)),
           (FOLDER + "LICENSE", os.path.join(ROOT, "LICENSE"))]
    for dirpath, dirs, names in os.walk(PKG):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for fn in sorted(names):
            if fn.endswith((".pyc", ".pyo")):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, os.path.dirname(PKG)).replace(os.sep, "/")
            out.append((FOLDER + rel, path))
    return sorted(out)


def content(arc, path):
    data = open(path, "rb").read()
    if arc.endswith(TEXT) or arc.endswith("/LICENSE"):
        data = data.replace(b"\r\n", b"\n")
    if arc.endswith(".py"):
        compile(data, arc, "exec")
    return data


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "dist", "ida_better_reverse.zip")
    version = re.search(r'__version__ = "([^"]+)"',
                        open(os.path.join(PKG, "__init__.py"), encoding="utf-8").read()).group(1)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    entries = files()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for arc, path in entries:
            info = zipfile.ZipInfo(arc, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, content(arc, path))
    blob = open(out, "rb").read()
    print("files   : %d" % len(entries))
    print("wrote   : %s (%d bytes, v%s)" % (out, len(blob), version))
    print("md5     : %s" % hashlib.md5(blob).hexdigest())


if __name__ == "__main__":
    main()
