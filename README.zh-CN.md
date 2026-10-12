<div align="center">

# IDA Better Information

**读一行反汇编之前,先把这个二进制看明白。**

一个**单文件** [IDA Pro](https://hex-rays.com/) 插件(同时也是命令行工具),帮你自动补齐平时要手动翻半天的信息:
**C 运行库 / 编译器版本**、**库函数的真实名字**、**每个 libc 调用是干嘛的**、以及算术 / SIMD 指令的**数学含义**。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-7.x%20%7C%208.x%20%7C%209.x-orange.svg)](https://hex-rays.com/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg)](https://www.python.org/)
[![Single file](https://img.shields.io/badge/安装-单文件-success.svg)](ida_better_information.py)
[![Offline](https://img.shields.io/badge/联网-无-lightgrey.svg)](#隐私)

[English](README.md) · 简体中文

</div>

---

## 解决什么问题

在 IDA 里打开一个 stripped、静态链接的 CTF 题,满屏都是 `sub_401A20` 和裸的 `pxor` / `psrlw`。
真正开始分析逻辑之前,你得先手动回答三个无聊但必须的问题:

1. **这是哪个版本的 libc?** —— 才能套对应的 FLIRT 签名。
2. **哪些 `sub_*` 其实就是 `fopen` / `malloc` / `memcpy`?**
3. **`_m_por(_m_psrlwi(x, 8), _m_psllwi(x, 8))` 到底在算什么?**

**IDA Better Information** 一个快捷键就把这三件事全答了,把答案以函数名 + 注释的形式写进数据库,
不满意还能一键撤回。

## 功能

| | 功能 | 你得到什么 |
|---|---|---|
| 🔎 | **运行库 / 编译器识别** | 目标用的 glibc/musl 精确构建 —— **stripped + 静态链接也能认**,另支持 Go 和 MSVC 版本。 |
| 🏷️ | **FLIRT 自动套用** | 自动套上匹配的 `glibc_*` / `musl_*` 签名,库函数名字全回来。 |
| 💬 | **libc 用途注释** | 给每个识别出的 libc 函数加一行"干什么的"(`fopen → 打开文件,返回 FILE*`)。 |
| ➗ | **数学表达式注释** | 把算术 / 逻辑 / **MMX-SSE-AVX** 指令改写成中缀数学式(`xor eax, ebx → eax = eax ^ ebx`)。 |
| ↩️ | **一键撤回** | 本次运行改过的每个名字和注释都有快照、可逆。**绝不覆盖**你自己写的名字和注释。 |
| 📦 | **单文件、离线** | 检测器**和整个指纹库**都在一个 `.py` 里。不用 pip、不联网。 |

## 快速上手

```text
1. 把 ida_better_information.py 复制进 IDA 的  plugins/  目录。
2. 打开目标,按  Ctrl-Alt-G。
3. 面板显示识别到的运行库,勾上要做的事,按 Run。
```

```
┌─ IDA Better Information ──────────────────────────────┐
│ type: linux / static                                  │
│   glibc 2.39     22.2%  348/1566                      │
│   glibc 2.40     17.4%  272/1566                      │
│   glibc 2.41     16.5%  256/1551                      │
│ verdict: glibc 2.39   confidence=high                 │
│                                                       │
│ [x] 套用匹配的 FLIRT 签名                              │
│ [x] 给 libc 函数加注释(保留你的注释)                 │
│ [ ] 给当前函数的指令加数学表达式                       │
│                                                       │
│   [ Re-detect ]   [ Run ]   [ Undo ]                  │
└───────────────────────────────────────────────────────┘
```

## 安装

### 作为 IDA 插件
把这个单文件复制进 IDA 插件目录,重启 IDA:

| 系统 | 插件目录 |
|---|---|
| Windows | `%APPDATA%\Hex-Rays\IDA Pro\plugins\` 或 `<IDA>\plugins\` |
| Linux / macOS | `~/.idapro/plugins/` 或 `<IDA>/plugins/` |

就这一步 —— 指纹库是内嵌的,没有别的东西要拷。

### 作为命令行工具
同一个文件在普通 CPython 下直接能跑(不需要 IDA):

```console
$ python ida_better_information.py ./target
$ python ida_better_information.py ./target --static --top 8
```

## 原理

### 运行库识别

| 目标 | 方法 |
|---|---|
| Linux **glibc**,静态 / stripped | **函数字节指纹**匹配(glibc 2.19 – 2.44) |
| Linux **musl**(Alpine),静态 | 函数字节指纹匹配(1.1.24、1.2.2 – 1.2.6) |
| Linux **动态** | 最高的 `GLIBC_2.x` 符号需求(下限)+ GNU build-id → [libc.rip](https://libc.rip) |
| **Go**(ELF / PE) | 读内嵌的 `go1.x.y` 构建串(精确) |
| **Windows PE** | Rich header 的链接器 / 构建号(编译器版本) |

最难的情况 —— 一个 stripped 静态程序,版本号哪都没写 —— 插件取每个已知 libc 构建里各函数的
**无通配连续字节**,问一个简单又稳的问题:**哪个版本的函数字节在这个程序里出现得最全?**
出现得最全的那个版本就是答案。

### 置信度看的是"领先幅度",不是绝对命中率

一个小的静态程序只会链接它真正用到的那部分 libc,所以**绝对命中率天然就低**(20–40% 很正常、很健康)。
关键是**比第二名领先多少**:领先明显就是可信的判断。工具给出的 `high` / `medium` / `low`
来自这个差距,而不是裸百分比 —— 这就是为什么上面 `22.2%` 依然是一个可信的 `glibc 2.39`。

### 数学表达式注释

CTF 里读手写加密往往就是读 SIMD。插件把裸助记符翻译成你会写在草稿纸上的式子:

| 指令 | 写入的注释 |
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

覆盖 `add sub and or xor imul shl/sal shr sar rol ror adc sbb not neg inc dec lea`、
MMX/SSE 家族 `pxor pand por pandn padd* psub* pmul* psll* psrl* psra*`、标量浮点
`add/sub/mul/div ss/sd`,以及它们带 `v` 前缀的 AVX 三操作数形式。它只注释**光标所在的那个函数**,
按函数自愿开启,不会把整个库铺满注释。

> 这正是当初做这个功能的起因:有道题(强网杯 Butterfly)的加密核心全是 MMX,
> `psrlw`/`psllw`/`psllq` 看得人头大 —— 标成数学式之后,"换字节 + 循环移位 + 逐字节加" 一眼就清楚了。

## FLIRT 签名

识别、libc 注释、数学注释都是**开箱即用**的(指纹库已内嵌)。可选的"套用 FLIRT 签名"那一步,
套的是 IDA `sig/pc/` 里现成的 `glibc_*` / `musl_*` `.sig`。你可以:

- 用 Hex-Rays **FLAIR**(`pelf` + `sigmake`)从每个 `libc.a` 自己生成,或
- 直接用社区签名集,例如 [`push0ebp/sig-database`](https://github.com/push0ebp/sig-database)。

内嵌的 `fingerprint.json` 也是同样方式(FLAIR 模式)从公开发行的 Ubuntu `libc6-dev` / `musl-dev`
包生成的 —— 见 [`tools/`](tools/)。

## 覆盖范围与局限

- 指纹:glibc **2.19 – 2.44**、musl **1.1.24 / 1.2.2 – 1.2.6**,仅 **amd64**。
- 动态程序只能给**下限**;精确构建用 build-id 去 libc.rip 查。
- Windows 只给编译器 / 链接器线索,不给精确 CRT 版本。
- 非 Ubuntu 构建或超出范围的版本命中率可能偏低 —— 工具会提示,并仍给出候选排名。

## 重建指纹库

内嵌的数据块完全可从公开包复现:

```console
# 1. 下载 libc6-dev / musl-dev 的 .deb,解出 libc.a,跑 FLAIR pelf → db/*.pat
tools/build-pattern-db.sh
tools/build-musl-db.sh
# 2. 把模式压成 fingerprint.json
python tools/build-fingerprint.py
# 3. 把 fingerprint.json 内嵌进单文件插件
python tools/embed-fingerprint.py
```

要加版本:在 `tools/build-pattern-db.sh` 里加一行,再跑一遍这三步。

## 仓库结构

```
ida_better_information.py        插件 + 命令行 + 内嵌指纹库(你只需要装这一个)
tools/
  ida_better_information.src.py  源码模板(不含内嵌数据块)
  embed-fingerprint.py           fingerprint.json → 注入 .py 里的数据块
  build-pattern-db.sh            Ubuntu libc6-dev .deb → FLAIR 模式(glibc)
  build-musl-db.sh               musl-dev → FLAIR 模式(musl)
  build-fingerprint.py           FLAIR 模式 → fingerprint.json
  fingerprint.json               原始字节锚点库(溯源用)
README.md · README.zh-CN.md · LICENSE
```

## 隐私

全程本地运行。插件不开任何 socket、不往外发任何东西;唯一会"提到"的外链(也只是打印、从不主动访问)
是给动态程序的一条 libc.rip 提示。

## 兼容性

IDA Pro 7.x / 8.x / 9.x + Python 3。面板优先用 PySide6(IDA 9 自带),没有则退回 PyQt5,
再没有则退回原生 `ida_kernwin.Form`。

## 许可

[MIT](LICENSE)。`fingerprint.json` 的数据由公开发行的 Ubuntu glibc / musl 包经 FLAIR 模式派生而来。

## 致谢

模式生成基于 [Hex-Rays FLAIR](https://hex-rays.com/),并受社区签名集
[`push0ebp/sig-database`](https://github.com/push0ebp/sig-database) 启发。
