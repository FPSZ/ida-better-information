#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Embed fingerprint.json (gzip+base64) into the single-file plugin.

Reads  ida_better_information.src.py  (template with the @@FINGERPRINT_B64@@ token)
and    fingerprint.json               (the raw byte-anchor database),
writes ida_better_information.py       (self-contained, ready to ship).

usage: python embed-fingerprint.py [src_template] [fingerprint.json] [out.py]
"""
import os, sys, gzip, base64

HERE = os.path.dirname(os.path.abspath(__file__))
src  = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "ida_better_information.src.py")
fpj  = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "fingerprint.json")
out  = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "ida_better_information.py")

TOKEN = "@@FINGERPRINT_B64@@"

raw  = open(fpj, "rb").read()
blob = base64.b64encode(gzip.compress(raw, 9)).decode("ascii")
tmpl = open(src, "r", encoding="utf-8").read()
if TOKEN not in tmpl:
    sys.exit("token %s not found in %s" % (TOKEN, src))
final = tmpl.replace(TOKEN, blob)
open(out, "w", encoding="utf-8", newline="\n").write(final)

print("raw fingerprint : %d bytes" % len(raw))
print("embedded (b64)  : %d bytes" % len(blob))
print("wrote           : %s (%d bytes)" % (out, len(final)))
