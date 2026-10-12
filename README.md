<div align="center">

# IDA Better Information

**Know your binary before you read a single line.**

A single-file [IDA Pro](https://hex-rays.com/) plugin — and standalone CLI — that recovers
the context a reverse engineer normally reconstructs by hand: the **C runtime / compiler
version**, the **real names of library functions**, and **what every libc call and SIMD
instruction actually does**, rendered with the call's **live arguments and decoded constants**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-7.4%E2%80%939.x-orange.svg)](https://hex-rays.com/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg)](https://www.python.org/)
[![Single file](https://img.shields.io/badge/install-one%20file-success.svg)](ida_better_information.py)
[![Offline](https://img.shields.io/badge/network-none-lightgrey.svg)](#privacy)

English · [简体中文](README.zh-CN.md)

</div>

---

## The problem

A stripped, statically-linked CTF binary opens as a wall of `sub_401A20` calls and bare
`pxor` / `syscall` instructions. Before any real analysis you have to answer the same
mechanical questions by hand — *which libc is this, which `sub_*` are really `fopen` /
`malloc`, and what does `mmap(0, n, 7, 0x22, -1, 0)` actually request?*

IDA Better Information answers them in one keypress, writes the answers back as names and
comments, cross-checks its own verdict, and reverts cleanly if you don't want them.

## What it does

| | | |
|---|---|---|
| 🔎 | **Runtime detection** | Pinpoints the exact **glibc / musl build** of a target — *stripped and statically linked included* — across **x86-64, i386 and aarch64**, and identifies **Go, Rust, MSVC, MinGW, .NET** and **UPX / PyInstaller / Nuitka** packers. |
| 🏷️ | **FLIRT auto-apply** | Applies the matching `glibc_*` / `musl_*` signature (top candidates when the call is close) and loads the libc type library so named functions regain real prototypes. |
| 💬 | **libc annotations** | A one-line *what-it-does* note on every recognised libc function, visible at its call sites. |
| 🧩 | **Decompiler annotations** | In the pseudocode: library calls and MMX/SSE/AVX intrinsics annotated with their **real arguments** and **decoded constants** — `open(..., 0)` → `O_RDONLY`, `mmap(..., 7, ...)` → `PROT_READ\|WRITE\|EXEC [RWX]`, `kill(pid, 9)` → `SIGKILL`, `syscall(59)` → `execve`, `_mm_aesenc_si128` → *AES encrypt round*. Fortified `__*_chk` variants are unwrapped to their real signatures. |
| 🌐 | **Bilingual** | One switch flips both the UI and every annotation between English and 中文. |
| ↩️ | **Non-destructive** | Live annotations are rendered by a decompiler hook and write nothing. Everything you *do* persist is snapshotted and reversible, and your own names and comments are never touched. |

## Install

Drop the one file into your IDA plugins directory and restart — the fingerprint database is
embedded, there is nothing else to copy.

| OS | Plugins directory |
|---|---|
| Windows | `%APPDATA%\Hex-Rays\IDA Pro\plugins\` |
| Linux / macOS | `~/.idapro/plugins/` |

Open a target and press **Ctrl-Alt-G**.

## Use

The panel detects the runtime on demand and offers, independently:

- **Live decompiler annotations** — on by default; follow the cursor, update as you rename,
  write nothing to the database.
- **Apply FLIRT signature** — name the library functions.
- **Annotate libc functions** — persist the one-line descriptions.
- **Persist decompiler comments** — write the current function's annotations into the IDB.
- **Annotate math / SIMD in disassembly** — `xor eax, ebx` → `eax = eax ^ ebx`.
- **Undo** — revert everything this session wrote.

### As a CLI

The same file runs under plain CPython, no IDA required:

```console
$ python ida_better_information.py ./target
$ python ida_better_information.py ./target --arch aarch64 --top 8 --json
```

```text
target    : ./target
type      : linux / static / x86_64
  glibc 2.39     22.2%  348/1566  ######
  glibc 2.40     17.4%  272/1566  #####
verdict   : glibc 2.39   confidence = high
  - toolchain: gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1)
  - toolchain cross-check: agrees.
```

## How detection works

| Target | Method |
|---|---|
| Linux **glibc / musl**, static or stripped | **function byte-fingerprint** match, per architecture |
| Linux **dynamic** | program-header class, interpreter, `GLIBC_2.x` floor + build-id → [libc.rip](https://libc.rip) |
| **Go / Rust** | embedded build metadata (exact version) |
| **Windows PE** | Rich-header build id, linker version, managed/MinGW markers |
| any | `.comment` toolchain string, used as an independent cross-check |

Static-vs-dynamic is decided from the **ELF program headers** (interpreter and `DT_NEEDED`),
not a string search — so a shared object is never mistaken for a static executable. For the
hard case, the tool takes the wildcard-free byte runs of each known build's functions and asks
which build's functions appear most completely in the target.

**Confidence is relative.** A small static binary links only the slice of libc it uses, so
absolute hit-rates are naturally 20–40%. What matters is the **margin over the runner-up**; a
clear leader is a confident call, and the embedded toolchain string is used to corroborate it.

## Coverage

- Fingerprints: glibc **2.19 – 2.44** and musl **1.1.24 / 1.2.2 – 1.2.6**, for
  **x86-64, i386 and aarch64** (29 builds × 3 architectures).
- Syscall tables for x86-64 / i386 / aarch64, from the Linux kernel headers.
- Dynamic targets yield a **lower bound**; pin the exact build via build-id on libc.rip.

## Rebuilding the database

The embedded blob is reproducible from public packages (needs Hex-Rays
[FLAIR](https://hex-rays.com/) for `pelf`):

```console
python tools/build-db.py --pelf /path/to/flair/pelf      # libc6-dev / musl-dev .deb/.apk → db/<arch>/*.pat
python tools/build-fingerprint.py db tools/fingerprint.json   # → fingerprint.bin
python tools/gen-syscalls.py > tools/syscalls.json            # (on Linux/WSL; optional)
python tools/embed-fingerprint.py                             # inject blobs → ida_better_information.py
```

## Privacy

Everything runs locally. The plugin opens no sockets and sends nothing anywhere; the only
outbound link it ever *prints* (never contacts) is libc.rip, as a hint for dynamic binaries.

## Compatibility

IDA Pro 7.4 – 9.x with Python 3. The panel uses PySide6 (IDA 9), falls back to PyQt5, and
again to a native `ida_kernwin.Form` if neither is present. Decompiler features require
Hex-Rays; detection and FLIRT do not.

## License

[MIT](LICENSE). The fingerprint data is derived (via FLAIR patterns) from publicly
distributed Ubuntu/Alpine glibc and musl packages. Built on Hex-Rays FLAIR, and indebted to
the community FLIRT collection [`push0ebp/sig-database`](https://github.com/push0ebp/sig-database).
