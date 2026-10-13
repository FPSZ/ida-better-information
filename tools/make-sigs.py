#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compile the byte-pattern DB (db/<arch>/*.pat) into FLIRT signatures (.sig).

Before compiling, patterns are rewritten to match code as it looks after static
linking (see flair_relax.py): bytes the linker rewrites when it relaxes initial-exec
TLS accesses (errno, h_errno, locale pointers...) are wildcarded, and on AArch64 so
is every relocated instruction word that pelf only partly wildcarded. Against the
unstripped twin of stripped static glibc 2.39 binaries this takes correctly named
functions from 804 to 855 (x86-64) and from 294 to 495 (AArch64).

Patterns with fewer than --min-literal fixed bytes (leading bytes + CRC-covered bytes
+ tail) are dropped: pelf emits a few that are little more than a function prologue
(AArch64 `_dl_start` is `stp x29,x30,[sp,#-16]!; mov x29,sp` followed by wildcards),
and FLIRT would stamp that name on every function it fails to match otherwise.

Collisions (.exc) are resolved by excluding the conflicting modules; in libc they
are almost all same-byte aliases (htons/ntohs, atoi/atol).

Output names:  glibc_<ver>_<arch>.sig   musl_<ver>_<arch>.sig   libgcc_<gcc major>_<arch>.sig
(libgcc.a + libgcc_eh.a + crtbeginT.o + crtend.o: the GCC runtime every static binary carries)
FLIRT keys signatures by directory, not by the .sig processor byte (IDA's own
android_arm.sig also reports processor 0), so x86 sigs install to sig/pc and
AArch64 sigs to sig/arm.

usage:
  python tools/make-sigs.py --sigmake <flair>/sigmake.exe [--db _db]
         [--arch x86_64,i386,aarch64] [--family glibc,musl] [--out _sigs] [--min-literal N]
         [--install <IDA dir>]          # copy into <IDA>/sig/{pc,arm}
"""
import argparse, glob, os, re, shutil, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flair_relax

# where build-db.py extracted each arch's libc.a (used to read the real TLS symbol names)
_LIBC_GLOB = {"x86_64": "libc6-dev_*_amd64", "i386": "libc6-dev-i386_*_amd64", "aarch64": "libc6-dev_*_arm64"}
_TLS_FALLBACK = {"__libc_errno", "errno", "__libc_h_errno", "h_errno", "__h_errno", "__resp",
                 "__libc_resp", "__libc_dlerror_result", "__libc_tsd_CTYPE_B",
                 "__libc_tsd_CTYPE_TOLOWER", "__libc_tsd_CTYPE_TOUPPER", "__libc_tsd_LOCALE"}

MIN_LITERAL = 10   # see the module docstring; chosen from the ground-truth evaluation
SIG_SUBDIR = {"x86_64": "pc", "i386": "pc", "aarch64": "arm"}
ARCH_SUFFIX = {"x86_64": "amd64", "i386": "i386", "aarch64": "aarch64"}


def resolve_exc(path):
    """Resolve the collision file by excluding every conflicting module: drop the
    ';' help header so sigmake treats the file as edited, and leave the remaining
    module lines unmarked (no '+'), which excludes them. Conflicts in libc are
    overwhelmingly same-byte aliases (htons/ntohs, atoi/atol), so excluding them
    costs a couple of names while guaranteeing a clean, collision-free .sig."""
    lines = [ln for ln in open(path, "r", errors="ignore").read().splitlines()
             if not ln.startswith(";")]
    open(path, "w").write("\n".join(lines) + "\n")


def literal_bytes(line):
    """Fixed (non-wildcard) bytes a .pat line pins down: head + CRC range + tail."""
    f = line.split(" ")
    n = sum(f[0][i:i + 2] != ".." for i in range(0, len(f[0]), 2)) + int(f[1], 16)
    total = int(f[3], 16)
    tail = f[-1]
    if len(f) > 5 and re.fullmatch(r"[0-9A-F.]+", tail) and len(tail) == 2 * max(0, total - 32 - int(f[1], 16)):
        n += sum(tail[i:i + 2] != ".." for i in range(0, len(tail), 2))
    return n


def prepare_pat(src, dst, tls, arch, min_literal, relocs=True):
    """Write the pattern file sigmake will compile; returns (relaxed, dropped)."""
    relaxed = dropped = 0
    with open(src, "r", errors="ignore") as fi, open(dst, "w", newline="\n") as fo:
        for line in fi:
            line = line.rstrip("\n")
            c = False
            if tls:
                line, c = flair_relax.relax_line(line, tls, arch)
            if relocs:
                line, c2 = flair_relax.relax_relocs(line, arch)
                c = c or c2
            relaxed += c
            if min_literal and line and not line.startswith("---") and len(line.split(" ")) >= 5 \
                    and literal_bytes(line) < min_literal:
                dropped += 1
                continue
            fo.write(line + "\n")
    return relaxed, dropped


def make_one(sigmake, pat, sig, name):
    exc = os.path.splitext(sig)[0] + ".exc"
    for attempt in range(4):
        for f in (sig, exc) if attempt == 0 else (sig,):
            if os.path.exists(f):
                os.remove(f)
        subprocess.run([sigmake, "-n" + name, pat, sig],
                       capture_output=True, text=True)
        if os.path.exists(sig) and os.path.getsize(sig) > 0:
            return True
        if os.path.exists(exc):
            resolve_exc(exc)
        else:
            return False                       # failed for a non-collision reason
    return os.path.exists(sig) and os.path.getsize(sig) > 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sigmake", default=os.environ.get("FLAIR_SIGMAKE", ""))
    ap.add_argument("--db", default="_db")
    ap.add_argument("--arch", default="x86_64,i386,aarch64")
    ap.add_argument("--family", default="glibc,musl,libgcc")
    ap.add_argument("--versions", default="")
    ap.add_argument("--out", default="_sigs")
    ap.add_argument("--install", default="", help="IDA install dir: copy sigs into sig/{pc,arm}")
    ap.add_argument("--cache", default="_cache", help="build-db.py cache (for libc.a TLS symbols)")
    ap.add_argument("--no-relax-tls", action="store_true",
                    help="keep raw pelf patterns (do not wildcard TLS-relaxable instruction bytes)")
    ap.add_argument("--no-relax-got", action="store_true",
                    help="keep pelf's partial wildcards on relocated instructions (see flair_relax.relax_relocs)")
    ap.add_argument("--min-literal", type=int, default=MIN_LITERAL,
                    help="drop patterns with fewer fixed bytes than this (0 = keep all; default %(default)s)")
    args = ap.parse_args()
    if not args.sigmake or not os.path.exists(args.sigmake):
        sys.exit("need --sigmake path to FLAIR sigmake(.exe)")

    want_fam = set(args.family.split(","))
    only = set(v for v in args.versions.split(",") if v)
    ok, fail, installed = [], [], 0
    for arch in args.arch.split(","):
        tls = set(_TLS_FALLBACK)
        tls |= flair_relax.tls_names(glob.glob(os.path.join(args.cache, "x", _LIBC_GLOB[arch], "libc.a")))
        pats = sorted(glob.glob(os.path.join(args.db, arch, "*.pat"))) +             sorted(glob.glob(os.path.join(args.db, arch, "libgcc", "*.pat")))
        for pat in pats:
            key = os.path.splitext(os.path.basename(pat))[0]      # "2.35", "musl_1.2.5", libgcc/"13"
            if os.path.basename(os.path.dirname(pat)) == "libgcc":
                fam, ver = "libgcc", key
            else:
                fam = "musl" if key.startswith("musl") else "glibc"
                ver = key.split("_", 1)[-1] if fam == "musl" else key
            if fam not in want_fam or (only and ver not in only):
                continue
            outdir = os.path.join(args.out, arch)
            os.makedirs(outdir, exist_ok=True)
            signame = "%s_%s_%s" % (fam, ver, ARCH_SUFFIX[arch])
            sig = os.path.join(outdir, signame + ".sig")
            label = "%s %s %s static (IBR)" % (fam, ver, ARCH_SUFFIX[arch])
            tag = "%s/%s" % (arch, signame)
            src = os.path.join(outdir, signame + ".prep.pat")
            nrel, ndrop = prepare_pat(pat, src, None if args.no_relax_tls else tls, arch,
                                      args.min_literal, not args.no_relax_got)
            tag += " (relaxed %d, weak dropped %d)" % (nrel, ndrop)
            if make_one(args.sigmake, src, sig, label):
                mods = _count_modules(args.sigmake, sig)
                print("ok   %-30s %s modules" % (tag, mods)); ok.append(tag)
                if args.install:
                    dst = os.path.join(args.install, "sig", SIG_SUBDIR[arch])
                    if os.path.isdir(dst):
                        shutil.copy2(sig, dst); installed += 1
            else:
                print("FAIL %-30s" % tag); fail.append(tag)
    print("done: %d ok, %d failed, %d installed %s" % (len(ok), len(fail), installed, " ".join(fail)))
    sys.exit(1 if fail else 0)


def _count_modules(sigmake, sig):
    dumpsig = os.path.join(os.path.dirname(sigmake), "dumpsig.exe")
    if not os.path.exists(dumpsig):
        dumpsig = dumpsig[:-4]
    try:
        out = subprocess.run([dumpsig, sig], capture_output=True, text=True).stdout
        m = re.search(r"(\d+) modules", out)
        return m.group(1) if m else "?"
    except Exception:
        return "?"


if __name__ == "__main__":
    main()
