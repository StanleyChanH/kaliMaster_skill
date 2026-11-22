# Reverse Engineering & Fuzzing

> **When to read this file**: when you need to analyze unknown binary (ELF/PE)/APK/Office macro samples, crack CTF crackmes, dynamically debug processes and reproduce vulnerabilities, write shellcode, or fuzz target services/programs.

## Quick Decision Table

| Scenario | First choice | Alternatives | Key difference |
|---|---|---|---|
| Cracking a CTF crackme | file/strings triage → Ghidra or radare2 static + gdb/gef dynamic | edb | static analysis locates the validation function; dynamic analysis verifies jumps and patched values |
| First triage of malware samples (no execution) | file + strings + olevba (macros) | Ghidra | triage first for IOC/C2 leads, then decide whether to move to dynamic analysis in an isolated VM |
| In-depth static analysis of large binaries (GUI) | ghidra | cutter | Ghidra has stronger decompilation; Cutter is lighter and starts faster |
| Fast static analysis from the command line | radare2 | rizin | the r2 ecosystem is mature; rizin is its fork with highly compatible commands |
| Dynamic debugging of local ELF binaries | gdb + gef | edb | gef adds exploit-development helper commands to GDB; edb is an OllyDbg-style GUI |
| Remote/embedded debugging | gdbserver + gdb | gdb-multiarch | the target runs only the lightweight gdbserver; the analysis side stays on the host |
| Windows 32-bit crackme | ollydbg (wine) | ghidra | Olly is handy for dynamic debugging; 64-bit PE can only use Ghidra/edb |
| Reading Java logic in an APK | jadx | dex2jar + jd-gui | jadx produces Java source in one step; the d2j legacy workflow has good compatibility |
| Modifying resources/repackaging an APK | apktool | — | the standard tool for restoring resources + rebuilding the APK |
| Reading source from Java jar/class | jd-gui | bytecode-viewer | BCV can run multiple decompiler engines side by side for complementary coverage |
| Interception and value tampering at Java runtime | javasnoop | — | attaches to a local Java process and tampers with method calls |
| Malicious Office macro documents | olevba | olefile | olevba extracts VBA directly and flags suspicious behavior |
| Assembly↔machine-code quick lookup | msf-nasm_shell | rasm2 / cstool | nasm_shell is interactive; cstool parses hex byte streams |
| Production-ready shellcode output | sickle-pdk | shellnoob | sickle supports bad-character avoidance and output in multiple language formats |
| Fuzzing network services | sfuzz | bed | sfuzz templates are customizable; bed works out of the box with per-protocol plugins |
| Fuzzing programs with source code | afl++ | sfuzz | afl++ is coverage-guided and finds paths an order of magnitude more efficiently |

## Core Tools in Depth

### ghidra — NSA's open-source software reverse engineering framework (the standard GUI decompiler)

**Purpose**: imports a binary and auto-analyzes it, providing disassembly, C-like pseudocode decompilation, function/data cross-references, call graphs, and scripting extensions (Java/Python); supports Windows/macOS/Linux executable formats and a large set of instruction set architectures.
**Installation**: `sudo apt install ghidra` (about 816 MB, JDK dependency included)
**When to use**: the first choice when you need to read pseudocode to understand program logic; better than radare2 for large samples and long-term analysis that benefits from a persistent project (function renames, annotations).

```bash
# 启动 GUI:新建工程 → Import File → 双击进 CodeBrowser 自动分析
ghidra

# 无界面批量分析(headless;Kali 路径可用 dpkg -L ghidra | grep analyzeHeadless 定位)
/usr/lib/ghidra/support/analyzeHeadless /tmp/ghidra_proj crackme_proj -import ./crackme

# 分析后自动运行 Ghidra 脚本(如批量导出)再退出
/usr/lib/ghidra/support/analyzeHeadless /tmp/ghidra_proj proj -import ./sample.exe -postScript <ScriptName>.java
```

**Practical tips**:
- CrackMe workflow: first Search > For Strings for a "wrong password"-style prompt → right-click References to find the referencing function → read the validation logic in the Decompile window; shortcut `L` renames, `;` adds a comment, and analysis results are saved in the .gpr project
- Packed samples (detected first with `strings`/`file`, e.g. UPX) cannot be analyzed by direct import; unpack first (`upx -d <file>`) and then import
- With Ghidra, malware analysis is purely static and never executes the sample, which is relatively safe; still run sample-unpacking scripts in an isolated VM
- Use analyzeHeadless for batch processing on servers/CI; keep the GUI for interactive review only

### radare2 — command-line reverse engineering framework (first choice for scripted analysis)

**Purpose**: an all-in-one command-line hex editor + disassembler + analysis + debugging framework; the suite also bundles rabin2 (binary info), rasm2 (assembly/disassembly), rafind2 (byte search), and rax2 (base conversion).
**Installation**: `sudo apt install radare2`
**When to use**: over SSH or when analysis steps should be written as scripts (`-c` batch mode); to quickly inspect one function without opening a GUI.

```bash
# 打开并自动全量分析(-A 等价于进入后执行 aaa)
radare2 -A ./crackme

# 批处理模式:分析后列出函数 / 反汇编 main,不进交互
r2 -q -c "aaa; afl" ./crackme
r2 -q -c "aaa; pdf @ main" ./crackme

# 交互模式常用命令
radare2 ./crackme
[0x004005a0]> aaa                  # 全量分析
[0x004005a0]> afl                  # 列出识别到的函数(afl~main 可过滤含 main 的行)
[0x004005a0]> s main; pdf          # seek 到 main 并反汇编
[0x004005a0]> iz                   # 数据段字符串
[0x004005a0]> ii                   # 导入符号(看调用了哪些库函数)
[0x004005a0]> axt @ sym.imp.strcmp # 谁调用了 strcmp(crackme 常见突破口)
[0x004005a0]> V                    # 可视模式,p/P 切换视图

# 调试模式
radare2 -d ./crackme               # 进入后 db <addr> 下断点、dc 继续、ds 单步

# 套件配套
rabin2 -I ./crackme                # 架构/入口/保护信息
rasm2 "mov eax, 0x33"              # 汇编 → 机器码
```

**Practical tips**:
- Before analyzing, run `rabin2 -I` to confirm the architecture and whether the binary is stripped; for stripped binaries, after `aaa`, use `afl` to find the largest functions or follow the trail from the entry point with `ie`
- Locating password validation in a crackme: iz to find the prompt string → `axt` to trace references back → `pdf` to read the logic; escalate to Ghidra if that fails
- Output can be piped (`pdf @ main > main.asm`), fitting AI/CI-assisted analysis pipelines
- Install plugins and signature libraries with the `r2pm` package manager

### rizin — a radare2 fork (a command-line framework with cleaner code)

**Purpose**: a fork of radare2 with a highly compatible command system (aaa/afl/pdf/s/V are all identical), shipping companion tools such as rz-bin and rz-asm; the Cutter GUI is built on it.
**Installation**: `sudo apt install rizin`
**When to use**: for new projects just pick either r2 or rizin; if you use Cutter as the GUI, pairing it with rizin on the command line is the most consistent.

```bash
rizin -q -c "aaa; afl; pdf @ main" ./crackme

rz-bin -I ./crackme                # 等价 rabin2:二进制元信息

rizin -d ./crackme                 # 调试模式
```

**Practical tips**:
- Migration cost from r2 is minimal; common commands are nearly identical
- Pair decompilation needs with Ghidra; rizin itself is positioned for analysis/debugging/hex editing
- Package family: librizin0 (libraries), librizin-dev (secondary development)

### gdb — the GNU debugger (the foundation of dynamic debugging)

**Purpose**: breakpoints, single-stepping, inspecting/modifying registers and memory, tracing system calls, and analyzing core dumps; combined with gef it is the workhorse of pwn/reversing dynamic analysis.
**Installation**: preinstalled on Kali; for cross-architecture samples (ARM/MIPS) `sudo apt install gdb-multiarch`; for remote debugging targets `sudo apt install gdbserver`
**When to use**: when you need to observe a program "while it runs" — comparing validation results, inspecting crash sites, verifying exploits; use Ghidra/r2 for purely static logic reading.

```bash
# 基础调试会话
gdb -q ./crackme
(gdb) set disassembly-flavor intel    # Intel 语法(默认 AT&T)
(gdb) break main
(gdb) run <args>
(gdb) disassemble main
(gdb) info registers
(gdb) x/16xw $rsp                     # 看栈内存
(gdb) x/s $rdi                        # 把寄存器当字符串指针看

# CTF 常用技巧:断在字符串比较函数,直接抓取被比较的口令
(gdb) break strcmp
(gdb) run
(gdb) x/s $rsi

# 分析崩溃 core dump
gdb ./crackme ./core

# 远程调试:目标机执行
gdbserver :1337 ./crackme
# 本机 gdb 内执行
(gdb) target remote <ip>:1337

# 附加到已运行进程
gdb -p <pid>
```

**Practical tips**:
- For binaries without symbols, break on an address: `break *0x401234`; `info functions` lists known symbols
- Remote/embedded scenarios: gdbserver has a tiny footprint and can be deployed on routers/IoT firmware emulation environments
- Debug ARM/MIPS samples with `gdb-multiarch ./<arm-binary>` (paired with qemu-user)
- Bare gdb commands have low information density; for exploit development use gef below

### gef — an exploit-enhancement GDB plugin (a CTF pwn must-have)

**Purpose**: adds a one-screen context to GDB (registers/stack/disassembly), `checksec` protection checks, cyclic-pattern overflow offset locating, memory-map viewing, and more; supports x86/64, ARM, MIPS, PowerPC, and SPARC.
**Installation**: `sudo apt install gef` (provides the `gef` wrapper command that starts gdb with gef loaded)
**When to use**: buffer overflow/format string challenges; same category as pwndbg, install only one per environment (both hijack gdb startup).

```bash
# 以 gef 包装启动
gef -q ./crackme
gef> checksec                 # 看 NX/Canary/PIE/RELRO,决定利用思路
gef> pattern create 200       # 生成 200 字节 De Bruijn 序列,输入程序
gef> pattern offset 0x41414141  # 用崩溃时 EIP/RIP 值算溢出偏移
gef> vmmap                    # 进程内存映射,找 libc 基址
gef> canary                   # 读当前 canary 值
gef> aslr off                 # 关闭地址随机化,便于本地调试
```

**Practical tips**:
- `pattern create/offset` is the standard workflow for locating overflow offsets: after the crash, look up the offset from the register value
- `checksec` results directly decide the strategy: everything on → ROP; no NX → ret2shellcode; Partial RELRO → GOT overwrite
- Use `vmmap` to find libc/stack base addresses and compute offsets from leaks
- Output is color-highlighted; when archiving logs, add a `--no-color`-style flag or strip ANSI afterwards

### apktool — Android APK decode & rebuild (the standard repackaging tool)

**Purpose**: decodes an APK to near-original form (resources, AndroidManifest.xml, smali), supports repackaging after modification, and can single-step debug smali with an IDE.
**Installation**: `sudo apt install apktool`
**When to use**: when you need to modify resources/Manifest, strip ads or certificate checks, and repack; jadx is faster for read-only Java source.

```bash
# 解码 APK(官网示例:资源还原 + classes.dex 反汇编为 smali)
apktool d <app>.apk

# 指定输出目录并强制覆盖已有目录
apktool d -f -o <out_dir> <app>.apk

# 只要资源不要 smali(快很多)
apktool d -s <app>.apk

# 修改后重建 APK
apktool b <out_dir> -o <modified>.apk
```

**Practical tips**:
- Repacked APKs must be re-signed before installation: `sudo apt install apksigner`, then sign with apksigner/jarsigner
- Output directory layout: smali/ (smali_classes2/... for multiple dex), res/, AndroidManifest.xml, apktool.yml
- Common spots to remove validation: search smali for `checkSignature`/`getPackageInfo` related calls
- Framework files live in ~/.local/share/apktool/framework/; delete them and retry if decoding misbehaves

### jadx — a Dex → Java decompiler (first choice for APK reversing)

**Purpose**: decompiles Dalvik bytecode in APK/dex/aar/zip straight into Java source, decodes AndroidManifest.xml and resources, and ships with deobfuscation; available as both CLI and GUI.
**Installation**: `sudo apt install jadx` (provides both the `jadx` and `jadx-gui` commands)
**When to use**: when the goal is to "understand app logic" (API endpoints, crypto algorithms, hidden features); switch back to apktool when repackaging is needed.

```bash
# 反编译到目录(得到 sources/ 与 resources/)
jadx -d <out_dir> <app>.apk

# 开启反混淆重命名,并保留反编译失败的代码片段
jadx --deobf --show-bad-code -d <out_dir> <app>.apk

# GUI 交互浏览(全文搜索、重命名、跳转引用)
jadx-gui <app>.apk
```

**Practical tips**:
- For obfuscated packages (nothing but a.b.c), adding `--deobf` noticeably improves readability
- Large APKs decompile slowly and eat memory; CLI is more stable than GUI; failed pieces are flagged in comments
- To find key logic, search strings first (API URLs, prompt texts) — faster than browsing class by class
- Decompilation output is an approximate reconstruction; check smali (apktool) for exact behavior

### d2j-dex2jar — dex to Java jar converter (the classic legacy workflow)

**Purpose**: converts Dalvik .dex into a standard Java .class jar, which Java decompilers then read as source.
**Installation**: `sudo apt install dex2jar`
**When to use**: when integrating with Java toolchains such as jd-gui; for new APKs, jadx alone is the easier one-step path.

```bash
# dex → jar(官网示例)
d2j-dex2jar classes.dex          # 输出 classes-dex2jar.jar

# 从 APK 取 dex 再转换的完整流程
unzip -o <app>.apk classes.dex
d2j-dex2jar classes.dex
jd-gui classes-dex2jar.jar
```

**Practical tips**:
- Conversion failures (newer dex features) are a common pitfall; fall back to direct decompilation with jadx
- The jd-gui combo was once the standard workflow; its strength is reuse of the whole Java decompiler ecosystem

### jd-gui — a Java .class decompiler GUI

**Purpose**: rebuilds .class/.jar into browsable Java source with instant jumps to methods and fields.
**Installation**: `sudo apt install jd-gui`
**When to use**: quick reading when you already have jar/class files (dex2jar output, Java malware samples, CTF Java challenges).

```bash
jd-gui classes-dex2jar.jar
```

**Practical tips**:
- File > Save All Sources exports all .java files for archiving
- Reconstruction quality for Java 8+ new syntax is mediocre; if unsatisfied, switch to bytecode-viewer for multi-engine comparison
- A read-only tool with no editing; modifications follow the decompile → recompile workflow

### file / strings / objdump — the static analysis trio (always run first)

**Purpose**: `file` identifies the type (ELF/PE/APK, architecture, static/dynamic, stripped or not); `strings` extracts visible strings (C2 domains, password prompts, packer signatures); `objdump`/`readelf` provide quick disassembly and ELF header reading.
**Installation**: preinstalled on Kali (binutils + file)
**When to use**: the 30-second triage of any unknown sample; decides whether to continue with Ghidra, olevba, or unpacking first.

```bash
# 定性:架构/链接方式/是否 stripped
file <binary>

# 提字符串:-n 8 过滤短串;-el 提取 Windows UTF-16LE 宽字符串
strings -n 8 <binary>
strings -el <binary>
strings <binary> | grep -iE 'pass|key|flag|http'

# 反汇编(ELF;Intel 语法)与动态符号
objdump -d -M intel <binary> | less
objdump -T <binary>             # 看调用了哪些动态库函数

# ELF 头:入口点、架构、程序头
readelf -h <binary>

# UPX 壳直接脱(出现 UPX! 字样时)
upx -d <packed-binary>
```

**Practical tips**:
- For malware samples, the first step is file/strings only (no execution); it often yields C2 domains/IPs and family leads directly
- No `strings` output / all garbage = packed or encrypted; unpack before any analysis
- objdump mainly targets ELF; leave in-depth PE analysis to Ghidra/radare2
- The trio's output pipes nicely into grep/awk for bulk first-pass filtering

### cstool — the Capstone disassembly CLI (machine-code quick lookup)

**Purpose**: the command-line tool of the Capstone multi-architecture disassembly framework; disassembles hex byte strings for a specified architecture/mode; the Python bindings (python3-capstone) support automated analysis scripts.
**Installation**: `sudo apt install capstone-tool` (Python bindings: `sudo apt install python3-capstone`; dev library: libcapstone-dev)
**When to use**: quickly confirming opcodes and instruction lengths (computing jump offsets in pwn), parsing extracted shellcode fragments; when a full r2/Ghidra analysis is unnecessary.

```bash
# x86-64 模式反汇编机器码(架构+模式是单个 token,字节串需整体加引号)
cstool x64 "0x48 0x8b 0x05 0xf9 0xff 0xff 0xff"

# 通用形式:<arch-mode> "<hex bytes>"(例:cstool x64 "48 8b 05")
cstool <arch-mode> "<hex bytes>"
```

**Practical tips**:
- Single-instruction disassembly only, no function/cross-reference analysis; use r2/Ghidra for depth
- On variable-length instruction sets (x86), use it to confirm instruction boundaries — essential when patching by hand
- For batch/automation scenarios, script directly against python3-capstone — the same engine as cstool

### afl++ — a coverage-guided fuzzing framework (first choice for source-available fuzzing)

**Purpose**: the community-maintained edition of american fuzzy lop; measures code coverage through instrumentation, automatically evolves inputs to explore new paths, and saves crashes.
**Installation**: `sudo apt install afl++`
**When to use**: the target program has source code (C/C++) and you want to systematically hunt memory-corruption bugs; use sfuzz/bed for black-box network fuzzing.

```bash
# 源码插桩编译(平时怎么编译就换成 afl-gcc)
afl-gcc -o <target>_fuzz <target>.c

# 准备种子输入目录(每个文件一个合法样本)
mkdir in && echo "AAAA" > in/seed1

# 启动模糊测试(@@ 表示输入以文件路径传入;省略 @@ 则走 stdin)
afl-fuzz -i in -o out -- ./<target>_fuzz @@
```

**Practical tips**:
- On first run, follow the hints to adjust system settings (root): `echo core > /proc/sys/kernel/core_pattern`; on cloud hosts/containers add `AFL_SKIP_CPUFREQ=1`
- Crashes are saved in `out/default/crashes/`; replay each one and confirm exploitability with gdb
- For binaries without source, try `-Q` QEMU mode (distro packaging has limited QEMU support; you may need to build a full afl++ yourself)
- Seed quality drives efficiency: use valid samples as seeds, not empty files

### sfuzz — Simple Fuzzer (template-customizable black-box network fuzzing)

**Purpose**: a lightweight black-box testing suite that generates malformed requests from template files and fires them at target services; the same package ships sfo (a local controlled-run oracle) and the generic_* series of manual packet tools.
**Installation**: `sudo apt install sfuzz`
**When to use**: malformed-input testing of in-house/proprietary TCP protocols or HTTP services; when request templates need fine-grained customization (more flexible than bed).

```bash
# TCP 模式 fuzz 目标(官网示例)
sfuzz -S <ip> -p 10443 -T -f /usr/share/sfuzz/sfuzz-sample/basic.http

# 复制示例模板定制自己的请求后运行
cp /usr/share/sfuzz/sfuzz-sample/basic.http /tmp/my.http
sfuzz -S <ip> -p <port> -T -f /tmp/my.http
```

**Practical tips**:
- `-S` target, `-p` port, `-T` TCP output, `-f` template; use escapes like `\r\n` inside templates to write raw request bytes
- Built-in sample templates live in /usr/share/sfuzz/sfuzz-sample/; tweaking the request line adapts them to most text protocols
- Black-box fuzzing needs external crash observation (service exit, unresponsive port, connection RST); pair it with a monitoring script
- For local programs under test, use sfo to launch them under control and watch the exit status

### bed — a plugin-driven network protocol fuzzer (works out of the box)

**Purpose**: checks common daemons for legacy flaws such as buffer overflows and format strings; sends known malicious patterns via per-protocol plugins.
**Installation**: `sudo apt install bed`
**When to use**: quickly "running through" legacy services (FTP/SMTP/POP/HTTP/IRC/IMAP/PJL/LPD/FINGER/SOCKS4/SOCKS5); less suited for deep template customization than sfuzz.

```bash
# HTTP 插件 fuzz 目标(官网示例)
bed -s HTTP -t <ip>

# 指定端口与每次测试后的等待秒数(默认 2)
bed -s FTP -t <ip> -p 21 -o 3

# 查看某插件需要的附加参数
bed -s <plugin>
```

**Practical tips**:
- Testing is quite aggressive and easily crashes targets: run only in authorized, recoverable environments and confirm the service survives afterwards
- Increasing the interval with `-o` mitigates cascading crashes on fragile targets
- In the output, watch the test numbers where the service disconnects abnormally/stops responding, then manually replay those requests

### sickle-pdk — a shellcode/payload development kit

**Purpose**: reads shellcode binaries and outputs them in the target language's format (C/Python, etc.), supporting bad-character avoidance, architecture selection, and variable naming; also usable for organizing non-binary payloads.
**Installation**: `sudo apt install sickle-pdk`
**When to use**: turning machine code compiled and extracted with nasm into arrays/strings pasteable into an exploit, with `-b` handling bad characters.

```bash
# 列出可用格式与模块
sickle-pdk -l

# 从二进制读 shellcode,输出 C 格式并规避坏字符
sickle-pdk -r <payload.bin> -f c -b "\x00\x0a\x0d"

# 指定输出格式与变量名(格式列表见 -l)
sickle-pdk -r <payload.bin> -f <format> -v <varname>

# 典型上游流程:写汇编 → 编译 → objdump 查看(nasm 需自行安装)
nasm -f elf64 <file>.asm -o <file>.o
objdump -d -M intel <file>.o
```

**Practical tips**:
- The exact `-b` bad-character syntax follows `sickle-pdk -h`; validate on a small sample before batch use
- The exploit development loop: nasm compile → extract raw bytes → sickle formatting → gdb execution check
- Overlaps in functionality with shellnoob; the two are interchangeable

### msf-nasm_shell — Metasploit's interactive assembler

**Purpose**: type an assembly statement and get machine-code bytes instantly; a zero-configuration tool for verifying shellcode fragments and measuring instruction lengths.
**Installation**: metasploit-framework (preinstalled on Kali)
**When to use**: quick opcode lookups while writing shellcode/building ROP gadgets; faster than opening a full IDE.

```bash
# 交互式:输入汇编,回车输出机器码
msf-nasm_shell
> mov eax, 0x66        # => b8 66 00 00 00
```

**Practical tips**:
- Suited to one-liner verification; compile full assembly listings with nasm
- Non-interactive alternative: `rasm2 "mov eax, 0x66"` from the radare2 suite
- For the reverse direction (bytes → assembly), use cstool or rasm2 -d

### olevba — Office document VBA macro analysis (first choice for malicious macros)

**Purpose**: extracts VBA macro source from OLE2 containers such as .doc/.xls (and OOXML formats), auto-flags suspicious API calls and known malicious patterns, and recognizes obfuscated strings.
**Installation**: `sudo apt install oletools`
**When to use**: the first step in analyzing phishing attachments/malicious macro samples: confirm whether macros exist, what they do, and whether they drop artifacts.

```bash
# 提取并分析文档中的 VBA 宏
olevba <file>.doc
```

**Practical tips**:
- Watch for auto-execution entry points (AutoOpen/DocumentOpen/Workbook_Open) and dangerous calls (CreateObject, WScript.Shell, Shell, URLDownloadToFile)
- The output lists suspicious keywords and IOCs (base64/hex-obfuscated strings often decode straight into C2 addresses)
- The oletools suite also has mraptor (quick macro triage) and ftguess (file format detection) that combine well
- Never double-click the document itself; do the whole analysis from the command line

### cutter — the official rizin GUI

**Purpose**: a graphical reversing platform built on rizin: function graphs, disassembly/hex multi-views, and symbol management — positioned as "a tool reverse engineers made for themselves".
**Installation**: `sudo apt install rizin-cutter`
**When to use**: when you want a GUI but find Ghidra heavy and slow to start; it analyzes on open with fluid interaction.

```bash
# 启动后在 GUI 中 File > Open 导入目标并自动分析
cutter
```

**Practical tips**:
- The core is rizin; analysis done in the GUI can be reproduced on the command line with rizin commands, which eases archiving
- Versus Ghidra: lighter and faster, but a tier weaker in decompilation and scripting ecosystem
- Good for interactively browsing function call relationships; return to Ghidra for deep decompilation

### edb — a Qt graphical x86/x86-64 debugger

**Purpose**: an OllyDbg-style debugger on Linux: registers, memory dump, and disassembly in a three-pane layout, with full breakpoints/single-stepping/memory search — aimed at source-less binary analysis.
**Installation**: `sudo apt install edb-debugger` (plugin package: edb-debugger-plugins)
**When to use**: debugging local Linux crackmes for people used to the OllyDbg workflow; when you don't want to memorize gdb commands.

```bash
# 启动 GUI 后 File > Open 选择目标程序
edb
```

**Practical tips**:
- The classic way to locate validation logic: break on a libc comparison function → trigger the input → inspect the compared values
- Supports local Linux x86/x86-64 programs only; use gdb-multiarch for ARM/MIPS
- For complex exploit development (heap layout, ROP), gdb+gef still delivers information more efficiently

### ollydbg — a Windows 32-bit analysis debugger (runs under wine)

**Purpose**: the classic Windows 32-bit assembly-level debugger, packaged for Kali through wine; excels at binary code analysis, a classic tool for source-less scenarios.
**Installation**: `sudo apt install ollydbg`
**When to use**: following old crackme tutorials (heavy on Olly idiom); dynamic debugging of 32-bit PE.

```bash
# 启动(wine 自动拉起),GUI 内打开 .exe
ollydbg
```

**Practical tips**:
- 32-bit PE only; for 64-bit programs switch to Ghidra/edb, or install wine + x64dbg yourself
- Common locating trick: break on GetWindowTextA/MessageBoxA/string-comparison APIs
- The wine environment occasionally has rendering/stability issues; prefer Ghidra for important analysis

### bytecode-viewer — a multi-engine Java/APK decompiler GUI suite

**Purpose**: runs multiple Java decompilers (Procyon/CFR/FernFlower/Krakatau, etc.) side by side in one interface, plus smali/baksmali, DEX↔jar conversion, a hex viewer, code search, a debugger, and a plugin system.
**Installation**: `sudo apt install bytecode-viewer`
**When to use**: when single-engine decompilation output is unreadable (new syntax/obfuscation); side-by-side multi-engine comparison fills the blind spots.

```bash
# 启动 GUI 后拖入 .jar/.class/.apk
bytecode-viewer
```

**Practical tips**:
- Open two decompiler views on the same file and compare — high success rate and free
- dex2jar/jar2dex built in, so APKs are directly digestible
- For command-line batch scenarios jadx is faster; this is an interactive close-reading tool

### shellnoob — a Python shellcode writing assistant

**Purpose**: a lightweight toolbox for converting between assembly source and multiple shellcode formats; can register itself as a command inside gdb.
**Installation**: `sudo apt install shellnoob` (the package has been dropped from some newer Kali releases; `pip install shellnoob` works as a replacement)
**When to use**: quickly turning .asm into a usable shellcode file; lighter than sickle but weaker at bad-character handling.

```bash
# 汇编源文件转 shellcode(输出 shellcode.hex 等多种格式文件)
shellnoob --from-asm <file>.asm

# 注册为 gdb 内命令(之后可在 gdb 会话中直接调用)
shellnoob --install
```

**Practical tips**:
- Fits rapid one-command iteration; move complex needs (bad characters, multi-format output) to sickle-pdk
- Output format files (.hex/.bin, etc.) are created in the same directory; remember to clean them up so they don't slip into deliverables

## Remaining Tools — Quick Reference

| Tool | One-line purpose | Package | Most common command |
|---|---|---|---|
| generic_send_tcp | SPIKE-style TCP script sender shipped with sfuzz; replays/tweaks malformed requests | sfuzz | `generic_send_tcp <ip> <port> <script> 0 0` |
| generic_send_udp | UDP version of the above; replays payloads at UDP services | sfuzz | `generic_send_udp <ip> <port> <script> 0 0` |
| generic_listen_tcp | Listens on a TCP port and dumps received data (fuzz outcome observation) | sfuzz | `generic_listen_tcp <port>` |
| generic_chunked | HTTP chunked transfer-encoding helper sender shipped with sfuzz | sfuzz | `generic_chunked` |
| olefile | OLE2 compound document structure parsing library (the low-level dependency of oletools) | oletools | `python3 -c "import olefile; print(olefile.OleFileIO('<file>').listdir())"` |
| javasnoop | Attaches to local Java processes and intercepts/tampers with method calls and return values | javasnoop | `javasnoop` (GUI) |
| pyinstaller | Packs Python scripts into single-file executables (reversing side: identify/unpack PyInstaller samples; extract with pyinstxtractor) | pyinstaller | `pyinstaller --onefile <script>.py` |
| code-oss | The open-source build of VS Code, for reading/tidying decompiled output and writing analysis scripts | code-oss | `code-oss <dir>` |
| nasm | Assembler, upstream of the shellcode workflow (asm → object file) | nasm | `nasm -f elf64 <file>.asm -o <file>.o` |

---

**Compliance reminder**: all techniques and commands in this document are for penetration testing, CTF competitions, and security education scenarios with written authorization only.
