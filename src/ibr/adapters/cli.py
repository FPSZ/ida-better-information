"""Standalone command line: detect a binary's runtime, or repair its ELF ident."""
import argparse
import json
import sys

from .. import __version__
from ..core.binfmt import _elf_layout
from ..core.detect import detect
from ..core.fingerprint import _lib_label


def main():
    ap = argparse.ArgumentParser(
        prog="ida_better_reverse.py",
        description="Detect the C runtime / compiler of a binary (glibc, musl, Go, Rust, MSVC).")
    ap.add_argument("binary", nargs="?", help="target ELF/PE file")
    ap.add_argument("--static", action="store_true", help="force static analysis")
    ap.add_argument("--dynamic", action="store_true", help="force dynamic analysis")
    ap.add_argument("--arch", choices=["x86_64", "i386", "aarch64"], help="override the detected architecture")
    ap.add_argument("--top", type=int, default=5, help="how many candidates to rank (default 5)")
    ap.add_argument("--json", action="store_true", help="emit the raw result as JSON")
    ap.add_argument("--repair", metavar="OUT",
                    help="write a copy with tampered ELF ident bytes (EI_CLASS/EI_DATA) fixed")
    args = ap.parse_args()
    if not args.binary:
        print("IDA Better Reverse v%s" % __version__)
        ap.print_help(); sys.exit(1)
    try:
        with open(args.binary, "rb") as f:
            raw = f.read()
    except OSError as ex:
        sys.exit("cannot read %s: %s" % (args.binary, ex.strerror or ex))
    if args.repair:
        data = bytearray(raw)
        if data[:4] != b"\x7fELF":
            sys.exit("not an ELF file")
        is64, en, note = _elf_layout(bytes(data))
        if not note:
            sys.exit("ELF ident bytes are consistent; nothing to repair")
        data[4], data[5] = (2 if is64 else 1), (1 if en == "<" else 2)
        try:
            with open(args.repair, "wb") as f:
                f.write(data)
        except OSError as ex:
            sys.exit("cannot write %s: %s" % (args.repair, ex.strerror or ex))
        print("%s.\nwrote %s (bytes 4-5 = %02X %02X)" % (note, args.repair, data[4], data[5]))
        return
    force = "static" if args.static else ("dynamic" if args.dynamic else None)
    r = detect(data=raw, force=force, top=args.top, arch_hint=args.arch)
    if args.json:
        print(json.dumps(r, indent=2)); return
    print("=" * 60)
    print("target    :", args.binary)
    print("type      :", r.get("os"), "/", r.get("kind"), "/", r.get("arch") or "?")
    if r.get("build_id"):
        print("build-id  :", r["build_id"])
    if r.get("arch") and r.get("os") == "windows":
        print("linker    :", r.get("linker"))
    if r.get("ranking"):
        print("-" * 60); print("version ranking (hit-rate  hits/anchors):")
        for v, s, h, n in r["ranking"]:
            print("  %-12s %6.1f%%  %d/%d  %s" % (_lib_label(v), s * 100, h, n, "#" * int(s * 30)))
    print("-" * 60)
    print("verdict   :", r.get("best"), "  confidence =", r.get("confidence"))
    for note in r.get("notes", []):
        print("  -", note)
    print("=" * 60)
