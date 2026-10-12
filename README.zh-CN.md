<div align="center">

# IDA Better Information

**读一行反汇编之前,先把这个二进制看明白。**

一个**单文件** [IDA Pro](https://hex-rays.com/) 插件(同时是命令行工具),帮你恢复逆向时平时要手动重建的上下文:
**C 运行库 / 编译器版本**、**库函数的真实名字**、以及**每个 libc 调用和 SIMD 指令到底在做什么**——
而且带上调用现场的**实参和解码后的常量**。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-7.4%E2%80%939.x-orange.svg)](https://hex-rays.com/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg)](https://www.python.org/)
[![Single file](https://img.shields.io/badge/安装-单文件-success.svg)](ida_better_information.py)
[![Offline](https://img.shields.io/badge/联网-无-lightgrey.svg)](#隐私)

[English](README.md) · 简体中文

</div>

---

## 要解决的问题

一个 stripped、静态链接的 CTF 题,打开满屏是 `sub_401A20` 和裸的 `pxor` / `syscall`。
真正开始分析前,你得手动回答同样几个机械问题——*这是哪个 libc、哪些 `sub_*` 其实是
`fopen` / `malloc`、`mmap(0, n, 7, 0x22, -1, 0)` 到底在申请什么?*

IDA Better Information 一个快捷键把这些答案给出来,写回为函数名和注释,自己给结论做交叉验证,
不想要时干净撤回。

## 功能

| | | |
|---|---|---|
| 🔎 | **运行库识别** | 精确定位目标的 **glibc / musl 构建**——*包括 stripped + 静态链接*——覆盖 **x86-64、i386、aarch64**;并识别 **Go、Rust、MSVC、MinGW、.NET** 以及 **UPX / PyInstaller / Nuitka** 壳。 |
| 🏷️ | **FLIRT 自动套用** | 套上匹配的 `glibc_*` / `musl_*` 签名(结论接近时套前几名),并加载 libc 类型库,让命名后的函数恢复真实原型。 |
| 💬 | **libc 用途注释** | 给每个识别出的 libc 函数加一行"干什么的",在调用处可见。 |
| 🧩 | **反编译注释** | 在伪代码里,给库函数调用和 MMX/SSE/AVX 指令加注释,带**真实实参**和**解码后的常量**:`open(..., 0)` → `O_RDONLY`、`mmap(..., 7, ...)` → `PROT_READ\|WRITE\|EXEC [RWX]`、`kill(pid, 9)` → `SIGKILL`、`syscall(59)` → `execve`、`_mm_aesenc_si128` → *AES 加密一轮*。`__*_chk` 加固版会还原成真实签名。 |
| 🌐 | **中英双语** | 一键切换,UI 和所有注释文字一起变。 |
| ↩️ | **不破坏原文** | 实时注释由反编译器钩子渲染,**不写数据库**;你主动落盘的改动都有快照、可逆,绝不碰你自己的名字和注释。 |

## 安装

把这一个文件丢进 IDA 的插件目录,重启即可——指纹库已内嵌,没有别的要装。

| 系统 | 插件目录 |
|---|---|
| Windows | `%APPDATA%\Hex-Rays\IDA Pro\plugins\` |
| Linux / macOS | `~/.idapro/plugins/` |

打开目标,按 **Ctrl-Alt-G**。

## 用法

面板按需检测运行库,并提供以下可独立勾选的操作:

- **反编译实时注释**——默认开启,跟随光标,随改名实时更新,不写数据库。
- **套用 FLIRT 签名**——命名库函数。
- **给 libc 函数加注释**——把一行用途说明落盘。
- **把反编译注释写进数据库**——持久化当前函数的注释。
- **在反汇编里标注算术 / SIMD**——`xor eax, ebx` → `eax = eax ^ ebx`。
- **撤回**——还原本次会话写入的一切。

### 命令行

同一个文件在普通 CPython 下直接跑,不需要 IDA:

```console
python ida_better_information.py ./target
python ida_better_information.py ./target --arch aarch64 --top 8 --json
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

## 检测原理

| 目标 | 方法 |
|---|---|
| Linux **glibc / musl**,静态 / stripped | 按架构做**函数字节指纹**匹配 |
| Linux **动态** | 程序头类型、解释器、`GLIBC_2.x` 下限 + build-id → [libc.rip](https://libc.rip) |
| **Go / Rust** | 内嵌构建信息(精确版本) |
| **Windows PE** | Rich 头构建号、链接器版本、托管 / MinGW 标记 |
| 任意 | `.comment` 工具链字符串,作为独立交叉验证 |

静态还是动态,是从 **ELF 程序头**(解释器 + `DT_NEEDED`)判定的,不是靠找字符串——所以共享库不会
被误判成静态可执行文件。最难的情况下,工具取每个已知构建函数的无通配字节段,比对"哪个构建的函数在
目标里出现得最全"。

**置信度是相对的。** 小的静态程序只链接它用到的那部分 libc,所以绝对命中率天然只有 20–40%。真正重要
的是**和第二名的差距**:领先明显就是可信结论,内嵌工具链字符串再给它一次佐证。

## 覆盖范围

- 指纹:glibc **2.19 – 2.44**、musl **1.1.24 / 1.2.2 – 1.2.6**,覆盖 **x86-64、i386、aarch64**
  (29 个构建 × 3 架构)。
- x86-64 / i386 / aarch64 的系统调用表,取自 Linux 内核头文件。
- 动态目标只给**下限**;精确构建用 build-id 在 libc.rip 上定位。

## 重建指纹库

内嵌数据可从公开软件包完整复现(需要 Hex-Rays [FLAIR](https://hex-rays.com/) 的 `pelf`):

```console
python tools/build-db.py --pelf /path/to/flair/pelf      # libc6-dev / musl-dev .deb/.apk → db/<arch>/*.pat
python tools/build-fingerprint.py db tools/fingerprint.json   # → fingerprint.bin
python tools/gen-syscalls.py > tools/syscalls.json            # (在 Linux/WSL 上;可选)
python tools/embed-fingerprint.py                             # 注入 blob → ida_better_information.py
```

## 隐私

全部本地运行。插件不开任何网络连接,什么都不往外发;唯一会**打印**(从不访问)的外链是 libc.rip,
只作为动态程序的提示。

## 兼容性

IDA Pro 7.4 – 9.x + Python 3。面板优先用 PySide6(IDA 9 自带),退回 PyQt5,再退回原生
`ida_kernwin.Form`。反编译相关功能需要 Hex-Rays;检测和 FLIRT 不需要。

## 许可

[MIT](LICENSE)。指纹数据由公开分发的 Ubuntu/Alpine glibc、musl 软件包经 FLAIR pattern 派生而来。
基于 Hex-Rays FLAIR,并受益于社区 FLIRT 签名集
[`push0ebp/sig-database`](https://github.com/push0ebp/sig-database)。
