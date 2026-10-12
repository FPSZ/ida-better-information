<div align="center">

# IDA Better Information

**Know your binary before you read a single line.**

A single-file [IDA Pro](https://hex-rays.com/) plugin (and standalone CLI) that recovers the
context you normally dig for by hand: the **C runtime / compiler version**, the **names of
library functions**, **what each libc call does**, and the **plain-math meaning** of
arithmetic & SIMD instructions.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-7.x%20%7C%208.x%20%7C%209.x-orange.svg)](https://hex-rays.com/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg)](https://www.python.org/)
[![Single file](https://img.shields.io/badge/install-single%20file-success.svg)](ida_better_information.py)
[![Offline](https://img.shields.io/badge/network-none-lightgrey.svg)](#privacy)

English · [简体中文](README.zh-CN.md)

</div>

---

## Why

Open a stripped, statically-linked CTF binary in IDA and you are staring at a wall of
`sub_401A20` calls and raw `pxor` / `psrlw` instructions. Before you can reason about the
logic you first have to answer three boring questions by hand:

1. *Which libc is this, so I can apply the right FLIRT signature?*
2. *Which of these `sub_*` are just `fopen` / `malloc` / `memcpy`?*
3. *What does `_m_por(_m_psrlwi(x, 8), _m_psllwi(x, 8))` actually compute?*

**IDA Better Information** answers all three in one keypress, writes the answers into the
database as names and comments, and lets you undo the whole thing if you don't like it.

## Features

| | Feature | What you get |
|---|---|---|
| 🔎 | **Runtime / compiler detection** | The exact glibc/musl build of a target — **even stripped & statically linked** — plus Go and MSVC versions. |
| 🏷️ | **FLIRT auto-apply** | Applies the matching `glibc_*` / `musl_*` signature so library functions regain their real names. |
| 💬 | **libc annotations** | A one-line *what-it-does* note on every recognised libc function (`fopen → open a file, returns FILE*`). |
| ➗ | **Math annotations** | Rewrites arithmetic / logic / **MMX-SSE-AVX** instructions as infix math (`xor eax, ebx → eax = eax ^ ebx`). |
| ↩️ | **One-click Undo** | Every name and comment a run changes is snapshotted and reversible. Your own names and comments are **never** overwritten. |
| 📦 | **Single file, offline** | The detector *and* the entire fingerprint database live inside one `.py`. No pip installs, no network. |

## Quick start

```text
1. Copy ida_better_information.py into IDA's  plugins/  directory.
2. Open your target, press  Ctrl-Alt-G.
3. The panel shows the detected runtime. Tick what you want, press Run.
```

```
┌─ IDA Better Information ──────────────────────────────┐
│ type: linux / static                                  │
│   glibc 2.39     22.2%  348/1566                      │
│   glibc 2.40     17.4%  272/1566                      │
│   glibc 2.41     16.5%  256/1551                      │
│ verdict: glibc 2.39   confidence=high                 │
│                                                       │
│ [x] Apply matching FLIRT signature                    │
│ [x] Annotate libc functions (keeps your comments)     │
│ [ ] Annotate math in CURRENT function                 │
│                                                       │
│   [ Re-detect ]   [ Run ]   [ Undo ]                  │
└───────────────────────────────────────────────────────┘
```

## Installation

### As an IDA plugin
Copy the single file into your IDA plugins directory and restart IDA:

| OS | Plugins directory |
|---|---|
| Windows | `%APPDATA%\Hex-Rays\IDA Pro\plugins\` or `<IDA>\plugins\` |
| Linux / macOS | `~/.idapro/plugins/` or `<IDA>/plugins/` |

That's it — the fingerprint database is embedded, there is nothing else to copy.

### As a CLI
The same file runs under plain CPython (no IDA required):

```console
$ python ida_better_information.py ./target
$ python ida_better_information.py ./target --static --top 8
```

```text
============================================================
target    : ./butterfly
type      : linux / static
------------------------------------------------------------
version ranking (hit-rate  hits/anchors):
  glibc 2.39     22.2%  348/1566  ######
  glibc 2.40     17.4%  272/1566  #####
  glibc 2.41     16.5%  256/1551  ####
------------------------------------------------------------
verdict   : glibc 2.39   confidence = high
============================================================
```

## How it works

### Runtime detection

| Target | Method |
|---|---|
| Linux **glibc**, static / stripped | **function byte-fingerprint** match (glibc 2.19 – 2.44) |
| Linux **musl** (Alpine), static | function byte-fingerprint match (1.1.24, 1.2.2 – 1.2.6) |
| Linux **dynamic** | highest `GLIBC_2.x` symbol requirement (lower bound) + GNU build-id → [libc.rip](https://libc.rip) |
| **Go** (ELF / PE) | embedded `go1.x.y` build string (exact) |
| **Windows PE** | Rich-header linker / build id (compiler version) |

For the hard case — a stripped static binary where the version is written nowhere — the plugin
takes the wildcard-free byte runs of each known libc build's functions and asks a simple,
robust question: **which version's functions actually appear in this binary?** The build whose
fingerprints show up most completely wins.

### Confidence is relative, not absolute

A small static binary only links the slice of libc it actually uses, so *absolute* hit-rates
are naturally low (20–40% is normal and healthy). What matters is the **margin over the
runner-up**: a clear leader is a confident call. The tool reports `high` / `medium` / `low`
from that gap, not from the raw percentage — which is why `22.2%` above is still a confident
`glibc 2.39`.

### Math annotations

Reading hand-written crypto in a CTF binary means reading SIMD. The plugin turns the raw
mnemonics into the math you'd write on paper:

| Instruction | Comment it writes |
|---|---|
| `xor eax, ebx` | `eax = eax ^ ebx` |
| `xor eax, eax` | `eax = 0` |
| `add rax, rcx` | `rax = rax + rcx` |
| `shl edx, 4` | `edx = edx << 4` |
| `ror r8, 1` | `r8 = r8 >>>(rot) 1` |
| `lea rax, [rbx+rcx*4]` | `rax = &[rbx+rcx*4]` |
| `pxor mm0, mm1` | `mm0 = mm0 ^ mm1` |
| `psrlw mm0, 8` | `mm0 = mm0 >> 8 (per 16b)` |
| `psllw mm1, 8` | `mm1 = mm1 << 8 (per 16b)` |
| `paddb mm0, mm2` | `mm0 = mm0 + mm2 (per byte)` |
| `vpxor xmm0, xmm1, xmm2` | `xmm0 = xmm1 ^ xmm2` |

Covers `add sub and or xor imul shl/sal shr sar rol ror adc sbb not neg inc dec lea`,
the MMX/SSE family `pxor pand por pandn padd* psub* pmul* psll* psrl* psra*`, scalar float
`add/sub/mul/div ss/sd`, and their AVX 3-operand `v`-prefixed forms. It annotates the function
your cursor is in, so you opt in per function instead of flooding the whole database.

## FLIRT signatures

Detection, libc annotation and math annotation all work **out of the box** — the fingerprint
database is bundled. The optional *Apply FLIRT signature* step applies whatever `glibc_*` /
`musl_*` `.sig` files live in IDA's `sig/pc/`. You can:

- generate them per build with Hex-Rays **FLAIR** (`pelf` + `sigmake`) from each `libc.a`, or
- drop in a community collection such as [`push0ebp/sig-database`](https://github.com/push0ebp/sig-database).

The bundled `fingerprint.json` was produced the same way (FLAIR patterns), from publicly
distributed Ubuntu `libc6-dev` / `musl-dev` packages — see [`tools/`](tools/).

## Coverage & limitations

- Fingerprints: glibc **2.19 – 2.44**, musl **1.1.24 / 1.2.2 – 1.2.6**, **amd64** only.
- Dynamic binaries yield a **lower bound**; pin the exact build via build-id on libc.rip.
- Windows gives a compiler/linker hint, not a precise CRT version.
- Non-Ubuntu or out-of-range builds may score low — the tool says so and still ranks candidates.

## Building the fingerprint database

The embedded blob is fully reproducible from public packages:

```console
# 1. download libc6-dev / musl-dev .debs, extract libc.a, run FLAIR pelf → db/*.pat
tools/build-pattern-db.sh
tools/build-musl-db.sh
# 2. compress patterns into fingerprint.json
python tools/build-fingerprint.py
# 3. embed fingerprint.json into the single-file plugin
python tools/embed-fingerprint.py
```

To add a version, add one line to `tools/build-pattern-db.sh` and re-run the three steps.

## Repository layout

```
ida_better_information.py        the plugin + CLI + embedded DB  (this is all you install)
tools/
  ida_better_information.src.py  source template (no embedded blob)
  embed-fingerprint.py           fingerprint.json → embedded blob in the .py
  build-pattern-db.sh            Ubuntu libc6-dev .deb → FLAIR patterns (glibc)
  build-musl-db.sh               musl-dev → FLAIR patterns (musl)
  build-fingerprint.py           FLAIR patterns → fingerprint.json
  fingerprint.json               raw byte-anchor database (provenance)
README.md · README.zh-CN.md · LICENSE
```

## Privacy

Everything runs locally. The plugin opens no sockets and sends nothing anywhere; the only
outbound link it ever *suggests* (never contacts) is libc.rip, printed as a note for dynamic
binaries.

## Compatibility

IDA Pro 7.x / 8.x / 9.x with Python 3. The panel uses PySide6 (shipped with IDA 9),
falls back to PyQt5, and falls back again to a native `ida_kernwin.Form` if neither is present.

## License

[MIT](LICENSE). The `fingerprint.json` data is derived (via FLAIR patterns) from publicly
distributed Ubuntu glibc / musl packages.

## Acknowledgements

Built on [Hex-Rays FLAIR](https://hex-rays.com/) for pattern generation and inspired by the
community FLIRT collection [`push0ebp/sig-database`](https://github.com/push0ebp/sig-database).
