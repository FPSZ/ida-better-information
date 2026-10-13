#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FLAIR patterns (<db>/<arch>/<key>.pat) -> fingerprint database.

An anchor is the longest wildcard-free byte run (10..24 bytes) of a function's leading
32-byte FLAIR pattern. Each libc build is represented by the set of its anchors; at
detection time the build whose anchors appear most completely in the target wins.

Two outputs:
  fingerprint.json  human-readable, {"format": 2, "arches": {arch: {key: [hex, ...]}}}
  fingerprint.bin   compact form that gets embedded in the plugin (see _decode_fp in
                    the plugin): anchors stored once per arch, versions as varint deltas.

Bytes the linker fills in or rewrites (TLS IE->LE, relocated AArch64 words; see flair_relax.py) are
wildcarded first, so anchors never span them.

usage: python tools/build-fingerprint.py [db_dir] [out.json] [--no-relax-tls] [--no-relax-got]
"""
import glob, json, os, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flair_relax
_LIBC_GLOB = {"x86_64": "libc6-dev_*_amd64", "i386": "libc6-dev-i386_*_amd64", "aarch64": "libc6-dev_*_arm64"}

MIN_RUN = 10    # shortest anchor kept
MAX_ANCH = 24   # anchors are truncated to this many bytes
MAGIC = b"IBIFP2"


def longest_literal_run(tok):
    best, cur = b"", bytearray()
    for i in range(0, len(tok) - 1, 2):
        c = tok[i:i + 2]
        try:
            cur.append(int(c, 16))
        except ValueError:              # ".." wildcard
            if len(cur) > len(best):
                best = bytes(cur)
            cur = bytearray()
    if len(cur) > len(best):
        best = bytes(cur)
    return best[:MAX_ANCH]


def anchors_from_pat(path, tls=None, arch=None, relocs=False):
    out = set()
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if tls:                      # wildcard bytes the linker rewrites (TLS relaxation)
                line = flair_relax.relax_line(line, tls, arch)[0]
            if relocs:                   # ... and GOT-indirect -> direct relaxation
                line = flair_relax.relax_relocs(line, arch)[0]
            if not line or line.startswith("---"):
                continue
            tok = line.split(" ", 1)[0]
            if len(tok) < 2 * MIN_RUN:
                continue
            run = longest_literal_run(tok)
            if len(run) >= MIN_RUN:
                out.add(run.hex())
    return sorted(out)


def _uvarint(n):
    b = bytearray()
    while True:
        x = n & 0x7F
        n >>= 7
        b.append(x | (0x80 if n else 0))
        if not n:
            return bytes(b)


def _str(s):
    s = s.encode()
    return bytes([len(s)]) + s


def _version_key(k):
    fam = 1 if k.startswith("musl") else 0
    nums = [int(x) for x in k.split("_")[-1].split(".") if x.isdigit()]
    return (fam, nums)


def encode_bin(arches):
    out = bytearray(MAGIC)
    out += bytes([len(arches)])
    for arch, vers in sorted(arches.items()):
        table = sorted({a for anchors in vers.values() for a in anchors})
        index = {a: i for i, a in enumerate(table)}
        out += _str(arch) + _uvarint(len(table))
        for a in table:
            raw = bytes.fromhex(a)
            out += bytes([len(raw)]) + raw
        out += _uvarint(len(vers))
        for key in sorted(vers, key=_version_key):
            idx = sorted(index[a] for a in vers[key])
            out += _str(key) + _uvarint(len(idx))
            prev = 0
            for i in idx:
                out += _uvarint(i - prev)
                prev = i
    return bytes(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    db = args[0] if len(args) > 0 else os.path.join(here, "..", "_db")
    out = args[1] if len(args) > 1 else os.path.join(here, "fingerprint.json")
    relax = "--no-relax-tls" not in sys.argv
    relocs = "--no-relax-got" not in sys.argv
    cache = os.path.join(os.path.dirname(os.path.abspath(db)), "_cache")
    arches = {}
    for arch_dir in sorted(glob.glob(os.path.join(db, "*"))):
        if not os.path.isdir(arch_dir):
            continue
        arch = os.path.basename(arch_dir)
        tls = None
        if relax and arch in _LIBC_GLOB:
            tls = flair_relax.tls_names(glob.glob(os.path.join(cache, "x", _LIBC_GLOB[arch], "libc.a")))
        for p in sorted(glob.glob(os.path.join(arch_dir, "*.pat"))):
            key = os.path.splitext(os.path.basename(p))[0]
            a = anchors_from_pat(p, tls, arch, relocs)
            if a:
                arches.setdefault(arch, {})[key] = a
        if arch in arches:
            n = len({x for v in arches[arch].values() for x in v})
            print("%-8s %2d builds, %5d distinct anchors" % (arch, len(arches[arch]), n))
    if not arches:
        sys.exit("no <arch>/*.pat under %s - run tools/build-db.py first" % db)
    with open(out, "w") as f:
        json.dump({"format": 2, "arches": arches}, f, separators=(",", ":"))
    blob = encode_bin(arches)
    with open(os.path.splitext(out)[0] + ".bin", "wb") as f:
        f.write(blob)
    print("-> %s (%d bytes json, %d bytes bin)" % (out, os.path.getsize(out), len(blob)))


if __name__ == "__main__":
    main()
