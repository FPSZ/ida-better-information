#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate src/ibr/data/syscalls.json (num -> name per arch) from Linux kernel headers.

Run on a Linux box (or WSL) that has libc headers installed:
    sudo apt install libc6-dev gcc-aarch64-linux-gnu
    python3 tools/gen-syscalls.py > src/ibr/data/syscalls.json

x86_64 / i386 come straight from <asm/unistd_{64,32}.h>. aarch64 uses the generic
syscall table (asm-generic/unistd.h) expanded with the __ARCH_WANT_* macros arm64 sets.
"""
import json, re, subprocess, sys

X64 = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
X86 = "/usr/include/x86_64-linux-gnu/asm/unistd_32.h"
A64_WANTS = ["__ARCH_WANT_RENAMEAT", "__ARCH_WANT_NEW_STAT", "__ARCH_WANT_SET_GET_RLIMIT",
             "__ARCH_WANT_TIME32_SYSCALLS", "__ARCH_WANT_SYS_CLONE3", "__ARCH_WANT_MEMFD_SECRET"]


def from_header(path):
    d = {}
    for m in re.finditer(r"#define __NR_(\w+)\s+(\d+)", open(path).read()):
        d[int(m.group(2))] = m.group(1)
    return d


def from_generic():
    cmd = ["gcc", "-E", "-dM"] + ["-D" + w for w in A64_WANTS] + \
          ["-include", "asm-generic/unistd.h", "-"]
    dump = subprocess.run(cmd, input="", capture_output=True, text=True).stdout
    defs = dict(re.findall(r"#define (\w+) (.+)", dump))

    def ev(x, depth=0):
        x = x.strip().strip("()")
        if x.isdigit():
            return int(x)
        if x in defs and depth < 12:
            return ev(defs[x], depth + 1)
        return None
    d = {}
    for k, v in defs.items():
        if k.startswith("__NR_") and not k.startswith("__NR3264") and k != "__NR_syscalls":
            val = ev(v)
            if val is not None and val < 2000:
                d[val] = k[5:]
    return d


def main():
    out = {}
    for arch, d in (("x86_64", from_header(X64)), ("i386", from_header(X86)),
                    ("aarch64", from_generic())):
        out[arch] = " ".join("%d:%s" % (n, d[n]) for n in sorted(d))
        print("%-8s %d syscalls" % (arch, len(d)), file=sys.stderr)
    json.dump(out, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
