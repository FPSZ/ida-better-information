# ida-libc-detect

Detect the **C-runtime version** of a binary — including **stripped, statically-linked** ones — and, in IDA, **auto-apply the matching FLIRT signature** and **annotate libc functions** with what they do.

Works as an **IDA plugin** (one dockable panel) and as a **standalone CLI**. Pure Python, offline.

## Why
In stripped static binaries the libc version isn't written anywhere you can just read. This tool identifies it by **matching function byte-fingerprints** of known libc builds against the target — the version whose functions actually appear wins. For dynamic binaries it reads the `GLIBC_2.x` requirement and build-id instead.

## What it detects
| Target | Method |
|---|---|
| Linux **glibc** static/stripped | byte-fingerprint match (glibc 2.19 – 2.44) |
| Linux **musl** (Alpine) static | byte-fingerprint match (1.1.24, 1.2.2 – 1.2.6) |
| Linux dynamic | `GLIBC_2.x` lower bound + GNU build-id (→ libc.rip) |
| **Go** (ELF/PE) | embedded `go1.x.y` version string |
| **Windows PE** | Rich-header linker/build (compiler version) |

Coverage is amd64.

## Install (IDA)
Copy these three files into your IDA `plugins/` directory (keep them together):
```
glibc_detect_plugin.py   detect.py   fingerprint.json
```
Or put `detect.py` + `fingerprint.json` anywhere and set `GLIBC_DETECT_DIR` to that folder.

Then in IDA press **Ctrl-Alt-G** to open the panel:
- shows the detected version + confidence + ranking;
- checkbox **apply matching FLIRT signature** (names the libc functions);
- checkbox **annotate libc functions** (adds a short "what it does" comment at each; **your own comments are preserved**, the note is prepended);
- **Undo** button reverts both the names and the comments from the last run.

## Use (CLI)
```
python detect.py /path/to/binary          # auto
python detect.py ./target --static --top 8
```

## Notes on the FLIRT signatures
Detection and annotation work out of the box (the fingerprint DB is bundled). The optional **auto-apply** step applies whatever `glibc_*` / `musl_*` FLIRT `.sig` files are present in IDA's `sig/pc/`. Get them from community collections (e.g. `push0ebp/sig-database`) or generate per-version with Hex-Rays **FLAIR** (`pelf` + `sigmake`) from each `libc.a`. The bundled `fingerprint.json` was generated the same way from Ubuntu `libc6-dev` / `musl-dev` packages.

## 简要中文
识别一个程序用的 C 运行库版本(**静态/stripped 也能认**),在 IDA 里**一键套用对应 FLIRT 签名**并给 libc 函数**加用途注释**(保留你原有注释,可一键撤回)。原理:静态程序用"函数字节指纹"匹配,哪个版本的函数字节出现得最全就是哪个;动态程序读 `GLIBC_2.x` 下限 + build-id。装法:把三份文件放进 IDA 的 `plugins/`,按 `Ctrl-Alt-G`。

## License
MIT. The `fingerprint.json` data is derived (via FLAIR patterns) from publicly distributed Ubuntu glibc/musl packages.
