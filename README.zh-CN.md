<div align="center">

# IDA Better Reverse

**认出去符号静态编译程序里的 libc 版本，恢复库函数名，并把反编译结果里的每个库调用讲清楚。**

[![Release](https://img.shields.io/github/v/release/FPSZ/ida-better-reverse?color=4c1)](https://github.com/FPSZ/ida-better-reverse/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![IDA Pro 7.4–9.x](https://img.shields.io/badge/IDA%20Pro-7.4%E2%80%939.x-555)
![x86-64 · i386 · AArch64](https://img.shields.io/badge/arch-x86--64%20%C2%B7%20i386%20%C2%B7%20AArch64-555)

[English](README.md) · 简体中文

</div>

<picture>
  <source srcset="docs/demo.zh-CN.avif" type="image/avif">
  <img src="docs/demo-poster.zh-CN.png" alt="IDA Better Reverse 识别静态程序中的 glibc 2.39、恢复函数名并注释伪代码" width="100%">
</picture>
<p align="center"><sub>IDA Pro 9.1，去符号的静态 x86-64 程序，一键完成（v2.2.0 录制）。<a href="https://github.com/FPSZ/ida-better-reverse/releases/download/v2.2.0/demo.zh-CN.mp4">MP4，1080p60</a></sub></p>

IDA Better Reverse 是一个面向**静态编译、去符号 ELF** 的 IDA Pro 插件。大多数 CTF 逆向/Pwn
题和不少 Linux 恶意样本都是这种形态。插件先判断链接进来的是哪个 C 运行库构建（glibc 或
musl，精确到版本），然后用为这个构建以及随它链接的 GCC 运行库专门生成的 FLIRT 签名恢复库函数名，
并套用函数原型。
最后它在 Hex-Rays 伪代码里注明每个 libc 调用和系统调用在做什么，常量会被解码出来。整个插件
是一个 Python 文件，数据内嵌，同一个文件不装 IDA 也能当命令行工具用。

## 示例

把演示录像里那个去符号程序重新用 IDA 打开，`main` 的一段在 Hex-Rays 中原本是这样：

```c
  sub_405110(off_4AA6D0, 0, 2, 0);
  sub_404600(14, sub_4019C0);
  sub_4195B0(30);
  v2 = sub_41A310(0, 0, 0, 0, v0, v1, v17[0]);
  result = 1;
  if ( v2 >= 0 )
  {
    v4 = sub_419640("flag.txt", 0, v17[0]);
    sub_419760(v4, v17, 64);
    v5 = sub_41A1F0(0);
```

点一次 **执行**（识别、套签名、套原型）之后，904 个函数被命名。注释由反编译器钩子在显示时
绘制，不写入数据库。下面是中文模式，面板右上角可以切换成英文：

```c
  v13 = __readfsqword(0x28u);  // op: 读 fs:0x28 栈 canary
  IO_setvbuf((FILE *)stream, 0, 2, 0);  // libc: stream 缓冲方式:_IONBF(无缓冲)
  _bsd_signal(14, (__sighandler_t)sub_4019C0);  // libc: SIGALRM 的处理设为 sub_4019C0
  alarm(0x1Eu);  // libc: 30 秒后 SIGALRM
  v0 = ptrace(PTRACE_TRACEME, 0, 0, 0);  // libc: ptrace PTRACE_TRACEME
  result = 1;
  if ( v0 >= 0 )
  {
    fd = _libc_open64("flag.txt", 0);  // libc: 打开 "flag.txt"(O_RDONLY)
    _libc_read(fd, buf, 0x40u);  // libc: 从 fd 读 64 字节
    v3 = _mmap64(0, 0x1000u, 7, 34, -1, 0);  // libc: 映射 4096 字节,PROT_READ|PROT_WRITE|PROT_EXEC [RWX],MAP_PRIVATE|MAP_ANONYMOUS
    ...
    v8 = syscall(39, buf_1);  // sys: getpid() (#39)
    __printf_chk(2, (unsigned int)"pid %ld\n", v8, v9, v10, v11, buf[0]);  // libc: 格式打印 "pid %ld\n" (%ld = v8)
```

命令行下，对一道 2024 强网杯题目的输出。这道题篡改了 ELF 头，让 `file`/`readelf`
无法识别：

```console
$ python ida_better_reverse.py remem
target    : remem
type      : linux / static / x86_64
build-id  : f522110408101510e7e36e66dedffe341035255d
------------------------------------------------------------
version ranking (hit-rate  hits/anchors):
  glibc 2.35     25.7%  381/1480  #######
  glibc 2.34     21.9%  323/1474  ######
  glibc 2.33     19.8%  247/1250  #####
  glibc 2.32     18.9%  235/1243  #####
  glibc 2.31     16.7%  212/1272  #####
------------------------------------------------------------
verdict   : glibc 2.35   confidence = high
  - ELF ident bytes tampered: EI_CLASS/EI_DATA claim 32-bit big-endian, header decodes as 64-bit little-endian x86_64 (to load it in IDA, set file byte 4 to 2 and byte 5 to 1).
  - toolchain: gcc 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)
  - static (x86_64): function byte-anchor match; clear leader = most likely build.
  - lead over #2: 3.8 pts (x1.17).
  - toolchain cross-check: agrees.
```

## 问题在哪

静态程序里的库函数识别靠 FLIRT，但签名必须来自**同一个** libc 版本，而去符号的静态程序
几乎不会告诉你是哪个版本。常见做法是把几十个 sig 文件全套一遍碰运气。就算版本选对了，
也还有第二个问题：用 `pelf` 从 `libc.a` 生成的签名描述的是目标文件里的代码，而静态链接会
改写其中一部分字节。在 AArch64 上，按常规流程生成的签名只能正确命名测试程序中 38% 的函数
（见[评测](#评测)）。

## 原理

### 识别运行库

1. **程序类型。** 静态还是动态，由 ELF 程序头（`PT_INTERP`、`DT_NEEDED`）判断，不搜字符串，
   所以共享库和 static-pie 都不会误判。`EI_CLASS`/`EI_DATA` 被篡改时（程序照常运行，
   `file`、`readelf` 却会失败），按能解出合法机器类型和文件类型的那种布局解析。动态程序
   给出由符号版本推出的 `GLIBC_2.x` 下限和 build-id。
2. **指纹。** 每个架构收录 29 个构建（glibc 2.19–2.44，musl 1.1.24 与 1.2.2–1.2.6，取自
   Ubuntu/Alpine 软件包）。每个函数的 32 字节 FLAIR 头部模式中，最长的无通配连续字节段
   （10–24 字节）作为一个**锚点**。生成锚点前，先把链接器会填写或改写的字节设为通配
   （见下一节），所以锚点不会跨过这些字节。每个架构约有 1.2–1.4 万个不同锚点，压缩后
   内嵌进插件。
3. **查找。** 每个锚点按它**最稀有**的 8 字节窗口（在最少锚点中出现的那个）建索引。对可
   执行字节扫描一遍，每个偏移查一次字典，再校验少量候选。x86-64 索引有 11,568 个键，
   每个键下最多 7 个锚点。纯 Python 实现，没有第三方依赖。
4. **判定。** 每个构建的得分是它的锚点在目标中出现的比例。静态程序只链接了 libc 的一小部分，
   所以绝对命中率通常只有 20–40%，置信度取决于领先第二名的幅度。如果 `.comment` 里有发行版
   工具链字符串（如 `GCC (Ubuntu 11.4.0-1ubuntu1~22.04)`），它对应的 glibc 版本会作为独立的
   交叉验证。

### 能匹配链接后代码的签名

`pelf` 根据目标文件判断哪些字节由重定位填写，把这些字节设为通配。但静态链接改动的不止这些：

| 架构 | `libc.a` 中 | 链接后的程序中 | `pelf` 留成字面量的字节 |
|---|---|---|---|
| x86-64 | `mov rcx, [rip+__libc_errno@gottpoff]` &nbsp;`48 8B 0D` | `mov rcx, -0x40` &nbsp;`48 C7 C1` | REX、操作码、ModRM |
| AArch64 | `adrp x0, sym` &nbsp;模式 `......90` | `600400F0` | 最高字节（`immlo`，第 29–30 位） |
| AArch64 | `ldr x0, [x0, #:lo12:sym]` &nbsp;模式 `....40F9` | `002446F9` | 含 `imm12` 高位的那个字节 |
| i386 | `mov eax, [ebx+sym@GOT]` &nbsp;`8B 83` | `mov eax, imm32` &nbsp;`C7 C0` | 操作码、ModRM |

第一行是 TLS 的 initial-exec → local-exec 松弛，多数系统调用包装函数（`read`、`mmap`、`ptrace`、
`alarm`……）都会通过 `errno` 碰到它。中间两行是 `pelf` 只通配了一部分的 AArch64 重定位立即数，
只有这几位恰好为 0 时模式才能匹配。最后一行是 i386 的 `R_386_GOT32X` 松弛，`getenv` 和字符串
函数的 IFUNC 解析器里的 GOT 读取会被改写成立即数。[`tools/flair_relax.py`](tools/flair_relax.py)
在 `sigmake` 之前改写模式：
- 把引用归档中 `STT_TLS` 符号的指令字节设为通配，受影响字节落在 CRC 范围内时去掉 CRC；
- 把 `pelf` 只通配了一部分的 AArch64 指令字整体设为通配；
- 把 i386 中位移被重定位的 基址+disp32 读取、调用和算术指令的操作码与 ModRM 设为通配。

随后 [`tools/make-sigs.py`](tools/make-sigs.py) 去掉固定字节少于 10 个的模式。其中一个是
AArch64 的 `_dl_start`，它只剩一段 `stp x29, x30, [sp,#-16]!; mov x29, sp` 函数序言，否则
FLIRT 会把这个名字安到一堆无关函数上。字节完全相同的模块（`strtol`/`strtoul`、
`fseek`/`fseeko`）直接排除，不去猜。准确率优先。

静态程序里还带着 GCC 运行库：`libgcc_eh` 的栈展开器、`libgcc` 里 `__udivti3` 这类整数运算辅助
函数，以及 `crtbeginT.o` 里的 `frame_dummy` 等。这些函数用 Ubuntu 的 `libgcc-N-dev` 软件包
（GCC 4.8 到 15）单独生成签名，和 libc 签名一起套用。GCC 版本取自 `.comment`，被去掉时按
glibc 版本对应发行版的默认编译器推断。

### 类型与注释

函数有了名字后，原型取自 IDA 自带的类型库（`gnulnx_*`）。`Hexrays_Hooks.func_printed`
钩子遍历正在显示的函数的 ctree，按 ctree 节点把注释挂到调用点上。加固版 `__*_chk` 和
`__isoc99_*` 按被包装的原函数理解，参数按调用的实际值解码：
- `open` 标志与创建权限、`mmap` 权限与标志（RWX 会标出）、信号以及 `SIG_DFL`/`SIG_IGN`，
  按目标平台的实际取值解码（x86、ARM、MIPS 与 Windows CRT 各不相同）；
- `ptrace`、`prctl`、`fcntl`、`futex` 请求，socket 协议族与类型，`lseek` 的 whence，标准 fd；
- printf/scanf 格式串，每个转换符都绑定到对应参数（`%zu = n`），格式串不是字面量时给出提示；
- `syscall(n)`，按各架构内核调用表命名，并解码参数；
- 嵌套的 MMX/SSE/AVX intrinsic 写成一个普通表达式，和标量代码不同的分组规则写在后面。
  以 2025 强网杯的 `butterfly` 为例：

  | Hex-Rays | 注释 |
  |---|---|
  | `_m_pxor((__m64)v28->m64_u64, v42[0])` | `*v28 ^ v42[0]` |
  | `_m_por(_m_psrlwi(v29, 8u), _m_psllwi(v29, 8u))` | `rotl(v29, 8) (每个 16 位内交换两个字节)` |
  | `_m_paddb(_m_por(_m_psllqi(v30, 1u), _m_psrlqi(v30, 0x3Fu)), v42[0])` | `rotl(v30, 1) + v42[0] (+ 按字节分别算, 互不进位)` |

注释会随重命名和语言切换更新，且不写入任何内容。持久化注释，以及插件做的其他所有改动
（函数名、类型、库函数标记、注释），都记入撤销日志，**撤回**能把数据库恢复原状（见下面的审计）。

## 评测

以下数据都在发布的数据上实测：IDA Pro 9.1（idalib）+ Python 3.14，AMD Ryzen AI MAX+ 395。

### 对照符号真值的函数命名

两个小 C 程序用 Ubuntu 24.04 的 GCC 13.3、glibc 2.39 以 `-static` 编译，然后去符号。IDA
分析去符号的程序并套用签名。每个被 IDA 标为库函数的函数，都和未去符号版本中同一地址的
全部符号比较：`read`/`__read`/`__libc_read` 这类别名算正确，IDA 的占位名
（`unknown_libname_N`）不算已命名。基线是同一 glibc 直接用 `pelf` → `sigmake` 生成的签名，
冲突处理方式相同。

| 目标 | 签名 | 已命名 | 正确 | 准确率 | 覆盖率¹ |
|---|---|--:|--:|--:|--:|
| x86-64 | `pelf` → `sigmake` | 810 | 804 | 99.3% | 82.4% |
| x86-64 | **本项目** | **903** | **902** | **99.9%** | **91.3%** |
| i386 | `pelf` → `sigmake` | 751 | 750 | 99.9% | 79.4% |
| i386 | **本项目** | **859** | **858** | **99.9%** | **90.8%** |
| AArch64 | `pelf` → `sigmake` | 340 | 301 | 88.5% | 38.1% |
| AArch64 | **本项目** | **603** | **596** | **98.8%** | **75.4%** |

<sub>¹ 正确命名数 ÷ 未去符号版本中有符号的函数数（976–988、945、789–790；IDA 每次分析的函数边界略有不同）。分母包含任何签名都
覆盖不到的代码（`_start`、`main` 和程序自己的函数），也包含被有意留空的字节完全相同的模块。
"本项目"指模式改写后的 libc 签名加上 libgcc 签名。两行都按插件的方式套用签名：重复套用，
直到某一轮不再命名新函数。因为像 `__printf_chk`/`__wprintf_chk` 这样相似的模块，FLIRT 要等
它们调用的函数有了名字才能区分。</sub>

### CTF 题目上的运行库识别

样本是 2023–2025 年强网杯逆向题中全部 19 个 ELF/PE 文件，共 63.6 MB：

| 类别 | 数量 | 结果 |
|---|--:|---|
| 静态 x86-64 glibc | 5 | glibc 2.31、2.35（×3）、2.39。其中 2 个篡改了 ELF 头。带 GCC/Ubuntu 工具链字符串的 4 个全部与之一致。 |
| 动态 ELF（含一个 41 MB 的共享库） | 7 | 判为动态，给出 `GLIBC_2.x` 下限 |
| Windows PE | 6 | 识别出 MSVC（Rich 头）、MinGW 与 .NET |
| 静态 MIPS | 1 | 报告不支持，不给结论 |

没有任何一个被判错类型。上面三个真值程序（x86-64、i386、AArch64）都被识别为 glibc 2.39，
置信度 high。

### 全流程审计

每次改动都用 idalib 无界面地跑一遍完整流程，共 36 种配置：
- 上面的 19 个文件；
- x86-64、i386、AArch64 的静态与动态测试程序，中英文界面各一遍；
- 真值程序。

每次运行都会识别运行库、套用签名和原型、反编译最多 860 个函数并渲染注释，然后持久化注释和
反汇编注释，最后全部撤销。最近一次运行中没有任何步骤抛出异常，**Undo** 之后也没有残留任何
由插件写入的函数名、类型、注释或库函数标记。撤销后仅有的差异出现在三个程序上：Hex-Rays 在
反编译时给程序自身函数推断出的类型，以及其中一个程序上 IDA 根据这些类型生成的参数注释。

### 速度

| 方式 | 输入 | 耗时 |
|---|---|--:|
| 命令行 | `emu`，静态 x86-64，12.7 MB | 0.58 s |
| 命令行 | `iked`，静态 x86-64，4.5 MB | 0.42 s |
| 命令行 | `butterfly`，静态 x86-64，0.7 MB | 0.23 s |
| 命令行 | 上述全部 19 个文件，63.6 MB | 2.0 s |
| IDA 内 | `emu`，13,861 个函数 | 0.54 s |

## 安装

1. 从 [最新 Release](https://github.com/FPSZ/ida-better-reverse/releases/latest) 下载
   `ida_better_reverse.py` 和 `ibr-sigs.zip`。
2. 把 `ida_better_reverse.py` 放进 IDA 用户目录下的 `plugins/`，再把 `ibr-sigs.zip` 解压到
   同一个用户目录。压缩包里是 117 个签名（glibc、musl 和 libgcc），位于 `sig/pc/` 与 `sig/arm/`：

   | 系统 | IDA 用户目录 |
   |---|---|
   | Windows | `%APPDATA%\Hex-Rays\IDA Pro\` |
   | Linux / macOS | `~/.idapro/` |

3. 重启 IDA，打开程序，按 **Ctrl-Alt-G**。

支持 IDA Pro 7.4–9.x（Python 3）。面板优先用 PySide6（IDA 9），其次 PyQt5，都没有时退回
原生表单。注释功能需要 Hex-Rays 反编译器，识别和 FLIRT 不需要。插件不发起任何网络连接。

## 使用

面板显示识别结果和候选排名，并提供以下选项（括号里是英文界面的名称）：

| 选项 | 作用 |
|---|---|
| **实时注释**（Live annotations） | 伪代码注释，显示时绘制，不写数据库（默认开启） |
| **套用 FLIRT 签名**（Apply FLIRT signature） | 套用识别出的 libc 构建及其 GCC 运行库的签名，并套用原型 |
| **libc 函数说明**（Describe libc functions） | 给每个已命名的 libc 函数写一行说明作为函数注释 |
| **注释落盘（当前函数）**（Persist comments） | 把当前函数的注释写入数据库 |
| **反汇编算术 / SIMD**（Math / SIMD in disassembly） | 给当前函数的运算指令加注释：`xor eax, ebx` → `eax = eax ^ ebx`，`ADD X0, X2, X20` → `X0 = X2 + X20`（ARM、AArch64、MIPS），SSE/AVX 按通道展开 |

**检测**给出候选排名，**执行**按勾选的选项运行，**撤回**撤销插件写入的一切，并暂停实时注释，
直到下次**执行**。界面和注释
都有中英文两种，在面板右上角切换。

命令行用法，不需要 IDA：

```console
$ python ida_better_reverse.py ./target                  # 候选排名与结论
$ python ida_better_reverse.py ./target --top 8 --json   # 机器可读输出
$ python ida_better_reverse.py ./target --arch aarch64   # 覆盖被破坏的 e_machine
$ python ida_better_reverse.py ./target --repair out     # 修复被篡改的 EI_CLASS/EI_DATA,让 IDA 能加载
```

## 从源码构建

发布的是一个生成出来的单文件。源码在 `src/ibr`，按“逻辑不依赖 IDA”的原则拆分：

| 目录 | 内容 |
|---|---|
| `src/ibr/core/` | 运行库识别、常量解码、注释文本、撤销日志。纯 Python，不 import IDA。 |
| `src/ibr/ports.py` | 逻辑需要反汇编器提供什么：数据库、反编译表达式、签名。 |
| `src/ibr/app/` | 识别、套签名、加注释、撤销，只依赖 ports。 |
| `src/ibr/adapters/` | 在 idaapi 和 Hex-Rays 上实现 ports，以及面板和命令行。 |
| `src/ibr/analysis/` | 预留给辅助解题的分析，目前为空。 |

```console
python tools/bundle.py          # src/ibr -> ida_better_reverse.py
python -m pytest tests          # 用内存里的假实现测 core 和 app，不需要 IDA
```

`core/` 或 `app/` 一旦 import IDA 或适配器，`tests/test_architecture.py` 就会失败。

### 重建数据

所有数据都由公开的发行版软件包生成，需要 Hex-Rays FLAIR（`pelf`、`sigmake`）：

```console
python tools/build-db.py --pelf <flair>/pelf      # libc6-dev、musl-dev、libgcc-N-dev -> _db/<arch>/
python tools/build-fingerprint.py                 # -> src/ibr/data/fingerprint.bin
python tools/make-sigs.py --sigmake <flair>/sigmake --install <IDA 目录>   # -> _sigs/，117 个 .sig
python tools/gen-syscalls.py > src/ibr/data/syscalls.json   # 可选，需要 Linux 内核头文件
python tools/bundle.py                            # -> ida_better_reverse.py
```

## 局限

- 静态识别要求该构建在库中。其他发行版用不同编译选项构建的 libc 匹配度会下降。
- 运行库识别和签名只覆盖 x86-64、i386、AArch64。其他处理器上（比如审计里的静态 MIPS 程序），
  反编译注释照常可用，但不识别运行库，也不命名函数。
- 动态程序只给出版本下限，不给精确构建；可用 build-id 在 [libc.rip](https://libc.rip)
  查到精确构建。
- 与其他函数字节完全相同的库函数不会被命名。
- AArch64 上，多函数目标模块里的函数只有在模块第一个函数匹配时才会被命名，所以覆盖率较低
  （测试程序上为 75%）。

## 许可

代码采用 [MIT](LICENSE) 许可。指纹和签名用 Hex-Rays FLAIR 从 Ubuntu/Alpine 的公开软件包生成：

| 库 | 软件包 | 许可证 |
|---|---|---|
| glibc | `libc6-dev`、`libc6-dev-i386` | LGPL-2.1-or-later |
| musl | `musl-dev` | MIT |
| GCC 运行库 | `libgcc-N-dev`、`lib32gcc-N-dev` | GPL-3.0 附 GCC Runtime Library Exception |

指纹和签名里只有函数名、校验值和很短的字节模式。签名保留每个函数开头的 32 字节（重定位
字节已通配）；两个函数会撞车时，再保留几个用于区分的字节。指纹每个函数只保留一段 10–24
字节。不再分发任何库或完整函数；下载的软件包和中间产物 `.pat` 文件都不在本仓库中。FLAIR 同样不包含在内，重建数据
需要你自己的 FLAIR。本项目受社区 FLIRT 签名集
[`push0ebp/sig-database`](https://github.com/push0ebp/sig-database) 启发，但没有使用它的数据。
