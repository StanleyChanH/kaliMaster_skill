# 逆向工程与模糊测试(Reverse Engineering & Fuzzing)

> **何时读本文件**:需要分析未知二进制(ELF/PE)/APK/Office 宏样本、破解 CTF crackme、动态调试进程与漏洞复现、编写 shellcode,或对目标服务/程序做模糊测试时。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| CTF crackme 通关 | file/strings 定性 → Ghidra 或 radare2 静态 + gdb/gef 动态 | edb | 静态定位校验函数,动态验证跳转与改值 |
| 恶意样本初筛(不执行) | file + strings + olevba(宏) | Ghidra | 先定性拿 IOC/C2 线索,再决定是否进隔离 VM 动态分析 |
| 大型二进制深度静态分析(GUI) | ghidra | cutter | Ghidra 反编译能力强;Cutter 轻、启动快 |
| 命令行快速静态分析 | radare2 | rizin | r2 生态成熟;rizin 是其分支,命令高度兼容 |
| 本地 ELF 动态调试 | gdb + gef | edb | gef 给 GDB 加漏洞利用辅助命令;edb 是 OllyDbg 风格 GUI |
| 远程/嵌入式调试 | gdbserver + gdb | gdb-multiarch | 目标机只跑轻量 gdbserver,分析端在主机 |
| Windows 32 位 crackme | ollydbg(wine) | ghidra | Olly 动态调试顺手;64 位 PE 只能用 Ghidra/edb |
| APK 看 Java 逻辑 | jadx | dex2jar + jd-gui | jadx 一步出 Java 源码;d2j 老流程兼容性好 |
| APK 改资源/重打包 | apktool | — | 还原资源 + 重建 APK 的标准工具 |
| Java jar/class 读源码 | jd-gui | bytecode-viewer | BCV 可同时跑多款反编译引擎互补 |
| Java 运行时拦截改值 | javasnoop | — | 附加到本地 Java 进程篡改方法调用 |
| Office 宏恶意文档 | olevba | olefile | olevba 直接抽取 VBA 并标出可疑行为 |
| 汇编↔机器码速查 | msf-nasm_shell | rasm2 / cstool | nasm_shell 交互式;cstool 解析十六进制字节流 |
| shellcode 成品化输出 | sickle-pdk | shellnoob | sickle 支持坏字符规避与多语言格式输出 |
| 网络服务模糊测试 | sfuzz | bed | sfuzz 模板可定制;bed 按协议插件开箱即用 |
| 有源码程序模糊测试 | afl++ | sfuzz | afl++ 覆盖率引导,发现路径效率高一个量级 |

## 核心工具详解

### ghidra — NSA 开源的软件逆向框架(GUI 反编译标准工具)

**用途**:导入二进制后自动分析,提供反汇编、类 C 伪代码反编译、函数/数据交叉引用、调用图、脚本扩展(Java/Python);支持 Windows/macOS/Linux 多平台可执行格式与大量指令集。
**安装**:`sudo apt install ghidra`(约 816 MB,自带 JDK 依赖)
**使用场景**:需要读伪代码理解程序逻辑时首选;比 radare2 适合大样本和需要持久化工程(函数重命名、注释)的长期分析。

```bash
# 启动 GUI:新建工程 → Import File → 双击进 CodeBrowser 自动分析
ghidra

# 无界面批量分析(headless;Kali 路径可用 dpkg -L ghidra | grep analyzeHeadless 定位)
/usr/lib/ghidra/support/analyzeHeadless /tmp/ghidra_proj crackme_proj -import ./crackme

# 分析后自动运行 Ghidra 脚本(如批量导出)再退出
/usr/lib/ghidra/support/analyzeHeadless /tmp/ghidra_proj proj -import ./sample.exe -postScript <ScriptName>.java
```

**实战要点**:
- CrackMe 套路:先 Search > For Strings 找"wrong password"类提示 → 右键 References 找引用函数 → Decompile 窗口读校验逻辑;快捷键 `L` 重命名、`;` 加注释,分析成果保存在 .gpr 工程里
- 加壳样本(先 `strings`/`file` 判断,如 UPX)直接导入分析无效,先脱壳(`upx -d <file>`)再导入
- 恶意样本用 Ghidra 是纯静态、不执行样本,相对安全;但样本解包脚本仍应在隔离 VM 中跑
- 服务器/CI 环境用 analyzeHeadless 批处理,GUI 只做交互复核

### radare2 — 命令行逆向分析框架(脚本化分析首选)

**用途**:一体化的命令行十六进制编辑器 + 反汇编 + 分析 + 调试框架;套件还含 rabin2(二进制信息)、rasm2(汇编/反汇编)、rafind2(字节搜索)、rax2(进制转换)。
**安装**:`sudo apt install radare2`
**使用场景**:SSH 环境或需要把分析步骤写成脚本(`-c` 批处理)时;快速看某个函数不用开 GUI。

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

**实战要点**:
- 分析前先 `rabin2 -I` 确认架构与是否 stripped;stripped 二进制 `aaa` 后用 `afl` 找最大函数或从入口 `ie` 顺藤摸瓜
- crackme 定位口令校验:iz 找提示串 → `axt` 回溯引用 → `pdf` 读逻辑,不行再上 Ghidra
- 输出可管道处理(`pdf @ main > main.asm`),适合 AI/CI 辅助分析流程
- 插件与签名库用 `r2pm` 包管理器安装

### rizin — radare2 分支(代码更整洁的命令行框架)

**用途**:radare2 的 fork,命令体系高度兼容(aaa/afl/pdf/s/V 均相同),配套 rz-bin、rz-asm 等工具;Cutter GUI 即基于它。
**安装**:`sudo apt install rizin`
**使用场景**:新项目在 r2 与 rizin 之间二选一即可;若用 Cutter 做 GUI,命令行配套用 rizin 最一致。

```bash
rizin -q -c "aaa; afl; pdf @ main" ./crackme

rz-bin -I ./crackme                # 等价 rabin2:二进制元信息

rizin -d ./crackme                 # 调试模式
```

**实战要点**:
- 从 r2 迁移成本极低,常用命令几乎一致
- 反编译需求配合 Ghidra;rizin 自身定位是分析/调试/十六进制编辑
- 包族:librizin0(库)、librizin-dev(二次开发)

### gdb — GNU 调试器(动态调试基础)

**用途**:断点、单步、查看/修改寄存器与内存、追调系统调用、分析 core dump;配合 gef 后是 pwn/逆向动态分析主力。
**安装**:Kali 默认已装;跨架构(ARM/MIPS 样本)`sudo apt install gdb-multiarch`;远程调试目标机 `sudo apt install gdbserver`
**使用场景**:需要"运行中"观察程序——比对校验结果、观察崩溃现场、验证漏洞利用;纯静态看逻辑用 Ghidra/r2。

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

**实战要点**:
- 无符号二进制按地址下断:`break *0x401234`;`info functions` 列出已知符号
- 远程/嵌入式场景:gdbserver 占资源极小,可部署到路由器/IoT 固件模拟环境
- 调 ARM/MIPS 样本用 `gdb-multiarch ./<arm-binary>`(配合 qemu-user)
- gdb 裸命令信息密度低,漏洞利用开发建议直接用下面的 gef

### gef — GDB 漏洞利用增强插件(CTF pwn 必备)

**用途**:给 GDB 加一屏式上下文(寄存器/栈/反汇编)、`checksec` 保护检测、循环模式定位溢出偏移、内存映射查看等,支持 x86/64、ARM、MIPS、PowerPC、SPARC。
**安装**:`sudo apt install gef`(提供 `gef` 包装命令,直接以 gef 启动 gdb)
**使用场景**:缓冲区溢出/格式化字符串类题;与 pwndbg 同类,同一环境只装其一(都劫持 gdb 启动)。

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

**实战要点**:
- `pattern create/offset` 是定位溢出偏移的标准流程:崩溃后用寄存器值反查
- `checksec` 结果直接决定策略:全开 → ROP;无 NX → ret2shellcode;Partial RELRO → GOT 改写
- `vmmap` 找 libc/stack 基址配合 leak 计算偏移
- 输出彩色高亮,日志留档时可加 `--no-color` 类参数或事后去 ANSI

### apktool — Android APK 解码与重建(改包标准工具)

**用途**:把 APK 解码到接近原始形式(resources、AndroidManifest.xml、smali),支持修改后重新打包,并可配合 IDE 单步调试 smali。
**安装**:`sudo apt install apktool`
**使用场景**:需要改资源/Manifest/去广告/去证书校验再重打包时;只读 Java 源码用 jadx 更快。

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

**实战要点**:
- 重打包后必须重新签名才能安装:`sudo apt install apksigner` 后用 apksigner/jarsigner 签名
- 输出目录结构:smali/(多 dex 时为 smali_classes2/...)、res/、AndroidManifest.xml、apktool.yml
- 去除校验的常见落点:smali 里搜 `checkSignature`/`getPackageInfo` 相关调用
- 帧框架文件在 ~/.local/share/apktool/framework/,解码异常时可删掉重试

### jadx — Dex → Java 反编译器(APK 逆向首选)

**用途**:把 APK/dex/aar/zip 中的 Dalvik 字节码直接反编译为 Java 源码,解码 AndroidManifest.xml 与资源,自带反混淆;CLI 与 GUI 双形态。
**安装**:`sudo apt install jadx`(同时提供 `jadx` 与 `jadx-gui` 命令)
**使用场景**:目标是"读懂 App 逻辑"(API 接口、加密算法、隐藏功能)时;需要改包回 apktool。

```bash
# 反编译到目录(得到 sources/ 与 resources/)
jadx -d <out_dir> <app>.apk

# 开启反混淆重命名,并保留反编译失败的代码片段
jadx --deobf --show-bad-code -d <out_dir> <app>.apk

# GUI 交互浏览(全文搜索、重命名、跳转引用)
jadx-gui <app>.apk
```

**实战要点**:
- 混淆包(全是 a.b.c)加 `--deobf` 可读性显著提升
- 大 APK 反编译慢且吃内存,CLI 比 GUI 稳;失败类会标注注释
- 找关键逻辑先搜字符串(接口 URL、提示文案),比逐个类翻快
- 反编译结果是近似还原,精确行为要看 smali(apktool)

### d2j-dex2jar — dex 转 Java jar(经典老流程)

**用途**:把 Dalvik .dex 转换为标准 Java .class jar,再用 Java 反编译器读源码。
**安装**:`sudo apt install dex2jar`
**使用场景**:需要与 jd-gui 等 Java 工具链联动时;新 APK 直接用 jadx 一步到位更省事。

```bash
# dex → jar(官网示例)
d2j-dex2jar classes.dex          # 输出 classes-dex2jar.jar

# 从 APK 取 dex 再转换的完整流程
unzip -o <app>.apk classes.dex
d2j-dex2jar classes.dex
jd-gui classes-dex2jar.jar
```

**实战要点**:
- 转换失败(新版 dex 特性)是常见坑,此时改用 jadx 直接反编译
- 与 jd-gui 组合曾是标准流程,优点是能复用整套 Java 反编译生态

### jd-gui — Java .class 反编译 GUI

**用途**:把 .class/.jar 重建为可浏览的 Java 源码,即时跳转方法与字段。
**安装**:`sudo apt install jd-gui`
**使用场景**:已有 jar/class(dex2jar 产物、Java 恶意样本、CTF Java 题)时快速阅读。

```bash
jd-gui classes-dex2jar.jar
```

**实战要点**:
- File > Save All Sources 可导出全部 .java 留档
- 对 Java 8+ 新语法还原质量一般,不满意换 bytecode-viewer 多引擎对比
- 只读工具,不能编辑;修改走反编译→重编译流程

### file / strings / objdump — 静态分析三件套(第一步永远先跑)

**用途**:`file` 判类型(ELF/PE/APK、架构、静态/动态、是否 stripped);`strings` 提取可见字符串(C2 域名、口令提示、加壳特征);`objdump`/`readelf` 快速反汇编与读 ELF 头。
**安装**:Kali 默认已装(binutils + file)
**使用场景**:拿到任何未知样本的 30 秒定性;决定后续用 Ghidra 还是 olevba 还是先脱壳。

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

**实战要点**:
- 恶意样本第一步只做 file/strings(不执行),常能直接拿到 C2 域名/IP 与家族线索
- `strings` 无输出/全是乱码 = 加壳或加密,先脱壳再谈分析
- objdump 主要面向 ELF;PE 深度分析交给 Ghidra/radare2
- 三件套输出适合管道给 grep/awk 做批量初筛

### cstool — Capstone 反汇编 CLI(机器码速查)

**用途**:Capstone 多架构反汇编框架的命令行工具,把十六进制字节串按指定架构/模式反汇编;Python 绑定(python3-capstone)可写自动化分析脚本。
**安装**:`sudo apt install capstone-tool`(Python 绑定:`sudo apt install python3-capstone`;开发库:libcapstone-dev)
**使用场景**:快速确认 opcode 与指令长度(pwn 里算跳转偏移)、解析提取出的 shellcode 片段;不需要 r2/Ghidra 的完整分析时。

```bash
# x86-64 模式反汇编机器码(架构+模式是单个 token,字节串需整体加引号)
cstool x64 "0x48 0x8b 0x05 0xf9 0xff 0xff 0xff"

# 通用形式:<arch-mode> "<hex bytes>"(例:cstool x64 "48 8b 05")
cstool <arch-mode> "<hex bytes>"
```

**实战要点**:
- 只做单指令反汇编,不带函数/交叉引用分析;深度分析用 r2/Ghidra
- 变长指令集(x86)下用它确认指令边界,手动 patch 时必备
- 批量/自动化场景直接用 python3-capstone 写脚本,与 cstool 同引擎

### afl++ — 覆盖率引导模糊测试框架(有源码 fuzz 首选)

**用途**:american fuzzy lop 的社区维护版;通过插桩统计代码覆盖,自动演化输入探索新路径并保存 crash。
**安装**:`sudo apt install afl++`
**使用场景**:目标程序有源码(C/C++)且想系统性找内存破坏漏洞;网络黑盒 fuzz 用 sfuzz/bed。

```bash
# 源码插桩编译(平时怎么编译就换成 afl-gcc)
afl-gcc -o <target>_fuzz <target>.c

# 准备种子输入目录(每个文件一个合法样本)
mkdir in && echo "AAAA" > in/seed1

# 启动模糊测试(@@ 表示输入以文件路径传入;省略 @@ 则走 stdin)
afl-fuzz -i in -o out -- ./<target>_fuzz @@
```

**实战要点**:
- 首次运行按提示调整系统设置(root):`echo core > /proc/sys/kernel/core_pattern`;云主机/容器加 `AFL_SKIP_CPUFREQ=1`
- crash 保存在 `out/default/crashes/`,逐个重放并配合 gdb 确认可利用性
- 无源码二进制可尝试 `-Q` QEMU 模式(发行版打包对 QEMU 支持有限,可能需自行编译完整版 afl++)
- 种子质量决定效率:先用合法样本做种子,而不是空文件

### sfuzz — Simple Fuzzer(模板定制型网络黑盒 fuzz)

**用途**:轻量黑盒测试套件,按模板文件生成畸形请求打目标服务;同包附带 sfo(本地受控运行 oracle)与 generic_* 系列手工发包工具。
**安装**:`sudo apt install sfuzz`
**使用场景**:对自研/私有 TCP 协议或 HTTP 服务做畸形输入测试;需要精细自定义请求模板时(比 bed 灵活)。

```bash
# TCP 模式 fuzz 目标(官网示例)
sfuzz -S <ip> -p 10443 -T -f /usr/share/sfuzz/sfuzz-sample/basic.http

# 复制示例模板定制自己的请求后运行
cp /usr/share/sfuzz/sfuzz-sample/basic.http /tmp/my.http
sfuzz -S <ip> -p <port> -T -f /tmp/my.http
```

**实战要点**:
- `-S` 目标、`-p` 端口、`-T` TCP 输出、`-f` 模板;模板内用 `\r\n` 等转义写原始请求字节
- 内置示例模板在 /usr/share/sfuzz/sfuzz-sample/,改请求行即可适配多数文本协议
- 黑盒 fuzz 需外部观察崩溃(服务退出、端口无响应、连接 RST),建议配合监控脚本
- 本地被测程序可用 sfo 受控拉起观察退出状态

### bed — 内置插件的网络协议 fuzzer(开箱即用)

**用途**:针对常见守护进程检查缓冲区溢出、格式化字符串等老式缺陷;按协议插件发送已知恶意模式。
**安装**:`sudo apt install bed`
**使用场景**:快速"过一遍"老旧服务(FTP/SMTP/POP/HTTP/IRC/IMAP/PJL/LPD/FINGER/SOCKS4/SOCKS5);模板深度定制不如 sfuzz。

```bash
# HTTP 插件 fuzz 目标(官网示例)
bed -s HTTP -t <ip>

# 指定端口与每次测试后的等待秒数(默认 2)
bed -s FTP -t <ip> -p 21 -o 3

# 查看某插件需要的附加参数
bed -s <plugin>
```

**实战要点**:
- 测试相当暴力,极易压崩目标:只在授权且可恢复的环境跑,结束后确认服务存活
- `-o` 调大间隔可缓解对脆弱目标的连环崩溃
- 输出中关注服务异常断开/无响应的测试编号,再手工重放该请求

### sickle-pdk — shellcode/payload 开发套件

**用途**:读取 shellcode 二进制并按目标语言格式输出(C/Python 等),支持坏字符规避、架构指定、变量命名;也可用于非二进制 payload 整理。
**安装**:`sudo apt install sickle-pdk`
**使用场景**:把 nasm 编译提取出的机器码做成可粘贴进 exploit 的数组/字符串,并按 `-b` 处理坏字符。

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

**实战要点**:
- `-b` 坏字符的具体写法以 `sickle-pdk -h` 为准,先小样本验证再批量
- exploit 开发闭环:nasm 编译 → 提取 raw 字节 → sickle 格式化 → gdb 验证执行
- 与 shellnoob 功能重叠,二者可互为替代

### msf-nasm_shell — Metasploit 交互式汇编器

**用途**:输入汇编语句即时得到机器码字节;验证 shellcode 片段、计算指令长度的零配置工具。
**安装**:metasploit-framework(Kali 默认已装)
**使用场景**:写 shellcode/构造 ROP gadget 时随手查 opcode;比开完整 IDE 快。

```bash
# 交互式:输入汇编,回车输出机器码
msf-nasm_shell
> mov eax, 0x66        # => b8 66 00 00 00
```

**实战要点**:
- 适合"一句话"验证;整段汇编编译走 nasm
- 非交互替代:radare2 套件的 `rasm2 "mov eax, 0x66"`
- 需要反方向(字节→汇编)用 cstool 或 rasm2 -d

### olevba — Office 文档 VBA 宏分析(恶意宏首选)

**用途**:从 .doc/.xls 等 OLE2 容器(及 OOXML 格式)提取 VBA 宏源码,自动标记可疑 API 调用与已知恶意模式,识别混淆字符串。
**安装**:`sudo apt install oletools`
**使用场景**:钓鱼附件/恶意宏样本分析第一步:确认有没有宏、宏干什么、是否落地产物。

```bash
# 提取并分析文档中的 VBA 宏
olevba <file>.doc
```

**实战要点**:
- 关注自动执行入口(AutoOpen/DocumentOpen/Workbook_Open)与危险调用(CreateObject、WScript.Shell、Shell、URLDownloadToFile)
- 输出会给出可疑关键词与 IOC(base64/hex 混淆串常能直接解出 C2 地址)
- oletools 套件还有 mraptor(宏快速检凶)、ftguess(文件格式探测)可组合使用
- 文档本身不要双击打开,分析全程命令行

### cutter — rizin 官方 GUI

**用途**:基于 rizin 的图形化逆向平台:函数图、反汇编/十六进制多视图、符号管理,面向"逆向工程师给自己做的工具"。
**安装**:`sudo apt install rizin-cutter`
**使用场景**:想要 GUI 但嫌 Ghidra 重、启动慢时;打开即分析,交互流畅。

```bash
# 启动后在 GUI 中 File > Open 导入目标并自动分析
cutter
```

**实战要点**:
- 内核是 rizin,GUI 里做的分析可在命令行用 rizin 命令复现,便于留档
- 与 Ghidra 的差异:更轻、更快,但反编译与脚本生态弱一档
- 适合交互式浏览函数调用关系;深度反编译仍回 Ghidra

### edb — Qt 图形化 x86/x86-64 调试器

**用途**:Linux 上的 OllyDbg 风格调试器:寄存器、内存 dump、反汇编三栏布局,断点/单步/内存搜索齐全,面向无源码二进制分析。
**安装**:`sudo apt install edb-debugger`(插件包:edb-debugger-plugins)
**使用场景**:习惯 OllyDbg 操作流的人调试本地 Linux crackme;不想记 gdb 命令时。

```bash
# 启动 GUI 后 File > Open 选择目标程序
edb
```

**实战要点**:
- 定位校验逻辑的老套路:对 libc 比较函数下断 → 触发输入 → 看比较值
- 只支持 x86/x86-64 本地 Linux 程序;ARM/MIPS 用 gdb-multiarch
- 复杂利用开发(堆布局、ROP)还是 gdb+gef 信息效率更高

### ollydbg — Windows 32 位分析调试器(wine 运行)

**用途**:经典 Windows 32 位汇编级调试器,Kali 通过 wine 打包;二进制代码分析见长,无源码场景经典工具。
**安装**:`sudo apt install ollydbg`
**使用场景**:跟着老 crackme 教程(大量 Olly 语法)复现;32 位 PE 的动态调试。

```bash
# 启动(wine 自动拉起),GUI 内打开 .exe
ollydbg
```

**实战要点**:
- 仅支持 32 位 PE;64 位程序改用 Ghidra/edb,或自行装 wine + x64dbg
- 常用定位法:对 GetWindowTextA/MessageBoxA/字符串比较 API 下断
- wine 环境偶有渲染/稳定性问题,重要分析优先 Ghidra

### bytecode-viewer — Java/APK 多引擎反编译 GUI 套件

**用途**:一个界面内同时跑 Procyon/CFR/FernFlower/Krakatau 等多款 Java 反编译器,附 smali/baksmali、DEX↔jar 转换、hex viewer、代码搜索、调试器与插件系统。
**安装**:`sudo apt install bytecode-viewer`
**使用场景**:单引擎反编译结果不可读(新语法/混淆)时,多引擎并排对比补盲区。

```bash
# 启动 GUI 后拖入 .jar/.class/.apk
bytecode-viewer
```

**实战要点**:
- 同一文件开两个反编译器视图对比,成功率高且免费
- 内置 dex2jar/jar2dex,APK 也能直接吃
- 命令行批量场景用 jadx 更快;这是交互式精读工具

### shellnoob — Python shellcode 编写助手

**用途**:汇编源码与多种 shellcode 格式互转的轻量工具箱,可注册为 gdb 内命令使用。
**安装**:`sudo apt install shellnoob`(部分新版 Kali 已下架该包,可用 `pip install shellnoob` 替代)
**使用场景**:快速把 .asm 变成可用的 shellcode 文件;比 sickle 轻,但坏字符处理能力弱。

```bash
# 汇编源文件转 shellcode(输出 shellcode.hex 等多种格式文件)
shellnoob --from-asm <file>.asm

# 注册为 gdb 内命令(之后可在 gdb 会话中直接调用)
shellnoob --install
```

**实战要点**:
- 适合"一条命令出结果"的快速迭代;复杂需求(坏字符、多格式输出)转 sickle-pdk
- 输出格式文件(.hex/.bin 等)在同目录生成,记得清理避免混入交付物

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| generic_send_tcp | sfuzz 同包的 SPIKE 风格 TCP 脚本发包器,重放/微调畸形请求 | sfuzz | `generic_send_tcp <ip> <port> <script> 0 0` |
| generic_send_udp | 同上的 UDP 版,对 UDP 服务重放 payload | sfuzz | `generic_send_udp <ip> <port> <script> 0 0` |
| generic_listen_tcp | 监听 TCP 端口并 dump 收到的数据(fuzz 结果观测) | sfuzz | `generic_listen_tcp <port>` |
| generic_chunked | sfuzz 同包的 HTTP chunked 传输编码辅助发包工具 | sfuzz | `generic_chunked` |
| olefile | OLE2 复合文档结构解析库(oletools 底层依赖) | oletools | `python3 -c "import olefile; print(olefile.OleFileIO('<file>').listdir())"` |
| javasnoop | 附加到本地 Java 进程,拦截/篡改方法调用与返回值 | javasnoop | `javasnoop`(GUI) |
| pyinstaller | 把 Python 脚本打包成单文件可执行(逆向方向:识别/解包 PyInstaller 样本,可用 pyinstxtractor 提取) | pyinstaller | `pyinstaller --onefile <script>.py` |
| code-oss | VS Code 开源构建版,阅读/整理反编译产物与写分析脚本 | code-oss | `code-oss <dir>` |
| nasm | 汇编器,shellcode 工作流上游(asm → 目标文件) | nasm | `nasm -f elf64 <file>.asm -o <file>.o` |

---

**合规提醒**:本文档所有技术与命令仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景。
