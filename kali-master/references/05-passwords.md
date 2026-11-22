# Password Attacks

**English** · [简体中文](05-passwords.zh-CN.md)

> **When to read this file**: read when a task involves hash type identification and offline cracking (hashcat/john), online login brute forcing (hydra/medusa/ncrack/patator/crowbar), wordlist generation and mangling (cewl/crunch/PACK/rsmangler/bopscrk), Windows credential extraction (mimikatz/samdump2/chntpw), or encrypted file/volume password recovery.

## Quick Decision Table

| Scenario | First choice | Alternatives | Key difference |
|---|---|---|---|
| Offline hash cracking (GPU available) | hashcat | john | hashcat is 10-100x faster on GPU, 300+ algorithms, requires `-m` |
| Offline hash cracking (CPU only / unknown format) | john | hashcat | john auto-detects hash formats and runs a single file directly |
| Cracking Linux /etc/shadow | john + unshadow | hashcat -m 500/1800/7400 | unshadow merges passwd/shadow in one step |
| Windows NTLM (SAM extraction) | hashcat -m 1000 | john --format=NT | see their respective cheat sheets for formats |
| NetNTLMv2 / Kerberoast captured hashes | hashcat -m 5600/13100 | john netntlmv2/krb5tgs | Responder/impacket output feeds in directly |
| Online brute forcing, general protocols | hydra | medusa / ncrack / legba | hydra has the broadest protocol coverage and the quickest start |
| Large-scale parallel multi-host auditing | ncrack | medusa | ncrack mimics nmap syntax, dynamic timing engine |
| Web/database brute forcing needing fine control | patator | hydra http-post-form | patator supports multi-file cross combinations and fgrep/regex verdicts |
| SSH key auth / RDP (NLA) / OpenVPN | crowbar | hydra (partial) | crowbar uniquely does key-based SSH and NLA RDP |
| Custom wordlists (target site vocabulary) | cewl | twofi / bopscrk | cewl crawls the target site; twofi uses social media; bopscrk combines personal info |
| Generating wordlists by charset/template | crunch | policygen / maskgen | crunch does full enumeration; PACK derives masks from statistics or password policy |
| Wordlist mangling/expansion | rsmangler | hashcat -r rules | rsmangler permutes and combines; output grows explosively |
| Identifying hash types | hashid | hash-identifier / `hashcat --identify` | hashid directly reports hashcat mode numbers and john format names |
| Windows online plaintext/NTLM capture | mimikatz | impacket-secretsdump (see also the SMB domain) | mimikatz pulls plaintext from lsass memory |
| Offline Windows SAM extraction | samdump2 | creddump7 / chntpw | chntpw can additionally blank/rewrite the password outright without knowing the old one |
| Zip archive passwords | fcrackzip | john (zip2john) | AES-encrypted zips must go through john/hashcat, see tips |
| TrueCrypt volumes | truecrack | hashcat -m 6211+ | VeraCrypt volumes use hashcat 137xx (extremely slow) |
| BIOS/CMOS password decryption | cmospwd | — | targets the CMOS storage of legacy BIOS passwords |

## Core Tools in Depth

### hashcat — the world's fastest GPU password recovery tool

**Purpose**: Offline hash cracking. Supports 300+ hash algorithms, CPU/GPU/hardware accelerators, and five attack modes (straight dictionary / combination / brute-force mask / hybrid ×2), plus built-in potfile checkpointing, session restore, and distributed cracking helpers.
**Installation**: `sudo apt install hashcat` (installed by default on Kali)
**When to use**: The first choice when you already have a hash file (shadow, SAM, Responder captures, Kerberoast tickets, etc.) and an NVIDIA/AMD GPU or a decent CPU; without a GPU and with an unknown format, use john's auto-detection first.

```bash
# 字典攻击:破解 MD5
hashcat -m 0 <hashfile> /usr/share/wordlists/rockyou.txt

# 字典 + 规则(性价比最高的一档,先跑这个)
hashcat -m 1000 <hashfile> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 识别未知 hash 的可能模式(较新版本 ≥6.2.5;老版本用 hashid)
hashcat --identify <hashfile>

# 基准测试(评估算力/预估耗时)
hashcat -b -m 1000

# 掩码暴力破解:?l 小写 ?u 大写 ?d 数字 ?s 符号 ?a 全部
hashcat -m 1000 -a 3 <hashfile> ?u?l?l?l?l?l?d?d?d?d

# 自定义字符集(-1)并递增长度(-i)
hashcat -m 0 -a 3 <hashfile> -1 ?l?d ?1?1?1?1?1?1?1?1 -i --increment-min 6

# 混合攻击:字典+后缀掩码(-a 6)/ 掩码+字典(-a 7)
hashcat -m 1000 -a 6 <hashfile> /usr/share/wordlists/rockyou.txt ?d?d?d?d

# 常用优化参数:优化内核(-O,明文长度上限降为 31)+ 高负载档(-w 3)+ 状态输出
hashcat -m 1800 <hashfile> <wordlist> -O -w 3 --status --status-timer=30

# 命名会话 + 断点续跑
hashcat --session poc1 -m 1000 <hashfile> <wordlist>
hashcat --restore --session poc1

# 查看已破解结果(potfile)
hashcat -m 1000 --show <hashfile>

# NetNTLMv2(Responder 捕获,整行 user::domain:... 直接喂入;--username 自动剥离用户名字段)
hashcat -m 5600 <hashfile> /usr/share/wordlists/rockyou.txt --username
# Kerberoast(impacket-GetUserSPNs 输出)/ AS-REP Roast
hashcat -m 13100 <kerberoast>.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 <asrep>.txt /usr/share/wordlists/rockyou.txt
# /etc/shadow 中的 $6$ sha512crypt
hashcat -m 1800 <shadow_hashes>.txt /usr/share/wordlists/rockyou.txt
# WPA 握手/PMKID:先转换(hcxtools),再破解
hcxpcapngtool -o capture.22000 <capture>.pcapng
hashcat -m 22000 capture.22000 /usr/share/wordlists/rockyou.txt
```

**Hash mode quick reference** (common `-m` values):

| Hash type | -m | Notes / identifying traits |
|---|---|---|
| MD5 | 0 | 32 hex characters |
| MD5($pass.$salt) | 10 | input format `hash:salt` |
| MD5($salt.$pass) | 20 | same as above |
| SHA1 | 100 | 40 hex characters |
| SHA1($pass.$salt) | 110 / SHA1($salt.$pass) 120 | `hash:salt` |
| MySQL323 | 200 | legacy MySQL `password()` |
| MySQL4.1/MySQL5 | 300 | starts with `*`, 41 characters |
| md5crypt ($1$, Unix) | 500 | `$1$` in shadow |
| MD4 | 900 | |
| NTLM | 1000 | 32 characters, Windows SAM/memory dumps |
| Domain Cached Credentials (DCC/MSCache) | 1100 | locally cached credentials |
| SHA2-256 | 1400 | |
| SHA2-512 | 1700 | |
| sha512crypt ($6$, Unix) | 1800 | `$6$` in shadow |
| sha256crypt ($5$, Unix) | 7400 | `$5$` in shadow |
| DCC2 / MSCache2 | 2100 | domain cached credentials v2 |
| bcrypt ($2*$) | 3200 | extremely slow, prefer `-S` |
| Joomla | 11 | |
| WordPress / phpBB3 (phpass) | 400 | starts with `$P$` |
| Drupal7 | 7900 | starts with `$S$` |
| macOS 10.8+ (PBKDF2-HMAC-SHA512) | 7100 | |
| PBKDF2-HMAC-SHA256 | 10000 | |
| scrypt | 8900 | |
| Kerberos AS-REQ pre-auth etype 23 | 7500 | krb5pa-md5 |
| NetNTLMv1 / NetNTLMv1+ESS | 5500 | choose between relay and cracking |
| NetNTLMv2 | 5600 | the standard output of Responder captures |
| Kerberos TGS-REP etype 23(Kerberoast) | 13100 | etype 17/18 are 19600/19700 |
| Kerberos AS-REP etype 23(AS-REP Roast) | 18200 | etype 17/18 are 19900/20000 |
| RAR3-hp / RAR5 | 12500 / 13000 | |
| ZIP (PKZIP) / WinZip | 17200 series / 13600 | convert with zip2john first |
| KeePass 1/2 | 13400 | convert with keepass2john |
| JWT (HS256) | 16500 | |
| LUKS | 14600 | |
| TrueCrypt RIPEMD160+XTS 512bit | 6211 | 6212/6213 are SHA512/Whirlpool |
| VeraCrypt | 13711+ series | very high iteration count, extremely slow |
| WPA-PBKDF2-PMKID+EAPOL | 22000 | old 16800 (PMKID)/2500 (WPA) have been merged in |

**Practical tips**:
- Ammo order: plain `rockyou` → `rockyou + best64.rule` → `rockyou + dive.rule/d3ad0ne.rule` (all under `/usr/share/hashcat/rules/`) → mask/hybrid attacks.
- `-O` optimizes kernels but caps plaintext length at 31 — watch out for long all-digit passwords; `-w 4` (nightmare) can freeze the desktop; for slow KDF algorithms (bcrypt/Kerberos 5900 series) add `-S` so the CPU generates candidates to feed the GPU.
- The potfile automatically records cracked entries and re-runs skip them; `--show` displays results; there is no need to delete the potfile when switching attack modes.
- A wrong salt format is the most common pitfall: salted modes require exactly two fields, `hash:salt`; for NetNTLMv2/Kerberoast use `--username` so hashcat does not fail parsing by treating the username as the salt.

### john — John the Ripper, a CPU cracker with automatic format detection

**Purpose**: Offline hash cracking with excellent CPU optimization and automatic hash type detection; the jumbo build ships hundreds of formats plus the `*2john` conversion scripts (zip/ssh/rar/keepass, etc.), along with companion tools such as `unshadow` and `unique`.
**Installation**: `sudo apt install john` (installed by default on Kali; conversion scripts live in `/usr/share/john/`)
**When to use**: The first choice when there is no GPU, the format is uncertain and you just want to get it running, you need to crack SSH private key passphrases/encrypted document passwords, or you need to merge and crack shadow files.

```bash
# 1) Linux 密码:先合并 passwd 与 shadow(官网流程)
unshadow passwd.txt shadow.txt > unshadowed.txt
john --wordlist=/usr/share/john/password.lst --rules unshadowed.txt

# 2) 单 hash 文件:指定格式 + 字典(官网 raw-md5 示例)
john --format=raw-md5 --wordlist=<wordlist> <hashfile>

# 3) 单一破解模式:用用户名/GECOS 字段生成候选(撞"用户名=密码"类)
john --single <hashfile>

# 4) 查看已破解结果
john --show <hashfile>
john --show --format=NT <hashfile>

# 5) 列出全部支持格式(常配合 grep 选格式)
john --list=formats | tr ',' '\n' | grep -i ntlm

# 6) 常见格式指定
john --format=netntlmv2 --wordlist=<wordlist> <hashfile>
john --format=sha512crypt --wordlist=<wordlist> unshadowed.txt

# 7) 加密文件口令:先转换再破解
/usr/share/john/zip2john <file>.zip > zip.hash
/usr/share/john/ssh2john.py id_rsa > ssh.hash
john --wordlist=<wordlist> ssh.hash

# 8) 多核并行(--fork)
john --fork=4 --wordlist=<wordlist> <hashfile>
```

**Practical tips**:
- Division of labor with hashcat: john handles automatic format detection and CPU scenarios; for large batches or slow algorithms, move to hashcat on GPU.
- When the warning `detected hash type X, but also recognized as Y` appears, set `--format=` explicitly to avoid burning a run against the wrong format.
- Cracked records live in `~/.john/john.pot` and are read by `--show`; deleting the potfile forces a full re-run.
- The `unique` tool (same package) deduplicates large wordlists: `unique -v -inp=allwords.txt uniques.txt`.

### hydra — THC Hydra, the online login brute forcer with the widest protocol coverage

**Purpose**: Parallelized network login brute forcing that supports ssh/ftp/http(s) forms and Basic/smb/rdp/mysql/postgres/telnet/vnc/ldap/pop3/imap/smtp among dozens of protocols; ships with `pw-inspector` for filtering password lists.
**Installation**: `sudo apt install hydra` (installed by default on Kali; install `hydra-gtk` for the GUI)
**When to use**: The first choice for online dictionary/spraying attacks against known open authentication services; for web forms, choose between it and patator.

```bash
# SSH(官网示例:单用户 + 字典 + 6 线程)
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 6 ssh://<ip>

# 通用参数:-l/-L 单用户/用户列表  -p/-P 单密码/密码列表  -t 线程
# -f 找到即停  -V 显示每次尝试  -e nsr(空口令/密码=用户名/反序)  -s 指定端口

# HTTP Basic 认证
hydra -l <user> -P <wordlist> <ip> http-get /protected/

# Web 登录表单:格式 "路径:POST参数:失败特征";^USER^/^PASS^ 为占位符
hydra -l <user> -P <wordlist> <ip> http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Login failed"
# HTTPS 表单用 https-post-form;成功判定用 S=<成功特征串>

# SMB
hydra -l administrator -P <wordlist> <ip> smb

# RDP(线程务必压低,建议 -t 4)
hydra -l administrator -P <wordlist> -t 4 <ip> rdp

# FTP / MySQL / PostgreSQL / Telnet
hydra -l <user> -P <wordlist> ftp://<ip>
hydra -l root -P <wordlist> <ip> mysql
hydra -l postgres -P <wordlist> <ip> postgres
hydra -l <user> -P <wordlist> -s 2323 <ip> telnet

# VNC(无用户名,只用 -P)
hydra -P <wordlist> -t 4 <ip> vnc

# 多目标批量:目标文件每行一个 ip/URI
hydra -L <userlist> -P <wordlist> -M <targets>.txt ssh

# 密码表预过滤(官网 pw-inspector 示例:长度 6-10)
pw-inspector -i <wordlist> -o passes.txt -m 6 -M 10
```

**Practical tips**:
- Log in once manually and capture the traffic to confirm the form field names and the failure-page signature (`F=`) before writing the command; mismatched placeholders, cookies, or CSRF tokens are the most common failure causes.
- Assess the account lockout policy before online brute forcing: start with a small dictionary/spraying (1-5 passwords per user) before the big lists, to avoid locking out every account.
- The `-e nsr` triple costs almost nothing — always add it first; on a single target always add `-f` to stop early instead of grinding through the whole list.
- For web form failure signatures, prefer a unique substring of the error message; when the page changes on every load (e.g. a timestamp), replace `F=` with the `S=` success signature.

### medusa — a stable, parallel, modular login brute forcer

**Purpose**: Thread-based modular network login brute forcing with an emphasis on stability; supports concurrent multi-host/multi-user/multi-password runs, with modules covering ssh/ftp/telnet/smb/rdp/http/mysql/mssql/postgres/vnc/webDav, etc.
**Installation**: `sudo apt install medusa` (installed by default on Kali)
**When to use**: When hydra module behavior is flaky (e.g. SMB/HTTP on old systems) or when you need to test the same credential set against a batch of hosts.

```bash
# 单主机:用户表 + 密码表 + 模块 + 线程
medusa -h <ip> -U <userlist> -P <wordlist> -M ssh -t 10

# 批量主机(每行一个目标)
medusa -H <hostlist>.txt -u <user> -P <wordlist> -M rdp -T 16

# 指定端口与结果输出
medusa -h <ip> -u <user> -P <wordlist> -M ftp -n 2121 -O results.txt

# 列出全部可用模块
medusa -d
```

**Practical tips**:
- `-t` is threads per host and `-T` is parallel hosts; combined they set total concurrency; keep threads low for RDP/SMB.
- Covers slightly fewer protocols than hydra but is steadier on long runs; `-O` writes results to disk for later documentation.
- Module names are protocol names; run `medusa -d` first to confirm spelling (e.g. `smbnt` is the legacy SMB module name).

### ncrack — a high-speed authentication brute forcing tool from the nmap project

**Purpose**: Modular high-speed network authentication brute forcing with nmap-like syntax and a built-in timing/reconnect engine that adapts dynamically to network feedback, suited to large-scale multi-host audits.
**Installation**: `sudo apt install ncrack`
**When to use**: Credential audits across dozens to hundreds of hosts; more reliable than hydra against high-latency/drop-prone targets (old devices, embedded systems).

```bash
# 官网示例:目标列表 + 单用户 + 密码表 + RDP + 单连接限制
ncrack -v -iL win.txt --user victim -P passes.txt -p rdp CL=1

# 单目标直连
ncrack --user root -P <wordlist> ssh://<ip>

# 多服务同扫:22/3389 端口映射到 ssh/rdp
ncrack -p 22,3389 --user admin -P <wordlist> <ip>
```

**Practical tips**:
- `CL=n` limits concurrent connections per target; set it to 1-4 for services that trip protection easily, such as RDP/SSH.
- A hit prints like `Discovered credentials on rdp://<ip>:3389 '<user>' '<pass>'`; results can also be saved with `-oN <file>`.
- Timing parameters (`to=/time`) provide overall rate limiting so large-scale runs do not knock the target over.

### patator — a multipurpose programmable brute forcing framework

**Purpose**: A highly configurable brute forcing framework written in Python, modular (ftp/ssh/telnet/smb/mssql/mysql/oracle/postgres/http_basic/http_form/ldap/vnc, etc.), supporting FILE0/FILE1 multi-file cross combinations and fgrep/regex result verdicts.
**Installation**: `sudo apt install patator`
**When to use**: Complex logic hydra cannot express — multi-field forms, cross-combining users × passwords × other parameters, or fine-grained success/failure conditions.

```bash
# 官网示例:MySQL 爆破,过滤 "Access denied" 响应
patator mysql_login user=root password=FILE0 0=<wordlist> host=<ip> -x ignore:fgrep='Access denied for user'

# SSH 登录(忽略连接 reset)
patator ssh_login host=<ip> user=FILE0 0=<userlist> password=FILE1 1=<wordlist> -x ignore:reset

# Web 表单:用户表×密码表交叉(follow=1 跟随 302 跳转)
patator http_form url=http://<ip>/login.php method=POST body='username=FILE0&password=FILE1' 0=<userlist> 1=<wordlist> follow=1 -x ignore:fgrep='Login failed'
```

**Practical tips**:
- `FILE0` and `FILE1` are file placeholders bound with `0=file 1=file`; the same file can be reused across multiple fields for cross combinations.
- In older versions the module is spelled `http_fomr` (a historical project typo); newer versions use `http_form`; when unsure, check the module list with `patator -h`.
- `-x ignore:fgrep=...`/`-x ignore:egrep=...` suppress failed attempts so the terminal only shows hits — essential with large dictionary output.

### crowbar — a special brute forcer supporting key-based authentication

**Purpose**: For protocols traditional username+password brute forcers cannot cover: SSH private key authentication, RDP with NLA, OpenVPN, VNC keys, with subnet-wide batch support.
**Installation**: `sudo apt install crowbar`
**When to use**: You obtained an SSH private key and want to mass-test which hosts accept it; the target enforces NLA on RDP so hydra fails; testing OpenVPN gateway credentials.

```bash
# 用 SSH 私钥扫整个网段(默认 22 端口)
crowbar -b sshkey -s 192.168.1.0/24 -u root -k id_rsa

# RDP(NLA)密码喷洒:单密码大面积尝试
crowbar -b rdp -s 192.168.1.100/32 -u administrator -c <password>

# 查看帮助与模块
crowbar -h
```

**Practical tips**:
- `-b` selects the mode (`sshkey`/`rdp`/`openvpn`/`vnckey`) and `-s` accepts CIDR ranges, a natural fit for the lateral movement phase.
- For RDP NLA, crowbar is the proper hydra replacement; failures are usually wrong credentials rather than tool issues — watch with `-v`.
- OpenVPN mode requires an `.ovpn` config (`-m`) and a certificate (`-k`).

### cewl — build custom wordlists by spidering the target website

**Purpose**: A Ruby website spider that crawls URLs to a set depth and builds a password wordlist from words on the returned pages; optionally extracts mailto addresses (usable as a username list) and can add numeric variants.
**Installation**: `sudo apt install cewl` (installed by default on Kali)
**When to use**: Company-specific targets where generic wordlists fail; passwords built from target vocabulary (product names, departments, acronyms) hit significantly more often than rockyou.

```bash
# 官网示例:深度 2、最短 5 字符,写入文件
cewl -d 2 -m 5 -w docswords.txt https://<url>

# 带数字变体 + 提取邮箱(邮箱另存,可作 hydra -L 用户表)
cewl -d 2 -m 5 --with-numbers -e -w cewl_words.txt https://<url>
```

**Practical tips**:
- A deeper `-d` yields more words but more noise; 2-3 levels usually suffice; `-m 5` filters out meaningless short words.
- Feed the output straight into john/hashcat with rule mangling: `hashcat -m 0 <hashfile> cewl_words.txt -r /usr/share/hashcat/rules/best64.rule`.
- Ineffective against JS-rendered pages (it does not execute scripts); for SPA sites, grab the sitemap/API responses first and feed words manually.

### crunch — generate full-permutation wordlists from charsets/templates

**Purpose**: Specify min/max length and a charset (or a preset charset file) to generate permutation wordlists; supports templates, size-split output, compression, and piping.
**Installation**: `sudo apt install crunch` (installed by default on Kali)
**When to use**: When the password pattern is known (e.g. "brand name + 4 digits", "8-digit numeric"), generate precisely instead of brute forcing the entire space.

```bash
# 官网示例:定长 6、字符集 0123456789abcdef,输出到文件(16M 行)
crunch 6 6 0123456789abcdef -o 6chars.txt

# 使用预置字符集文件(/usr/share/crunch/charset.lst)
crunch 8 10 -f /usr/share/crunch/charset.lst mixalpha-numeric -o wl.txt

# 模板 -t:@=小写 %=数字 ^=符号(大写占位符是逗号,需引号)
crunch 10 10 -t @@@@%%%%^^ -o wl.txt

# 固定前缀 + 3 位数字(pwd000-pwd999)
crunch 6 6 -t pwd%%% -o wl.txt

# 排列模式:对给定词做全排列(长度参数写占位即可)
crunch 0 0 -p root admin toor

# 大文件压缩输出(-z zip/gzip/bzip2/lzma)
crunch 8 8 abcdefghijklmnopqrstuvwxyz -o wl.txt -z gzip

# 直接管道给 john,不落盘
crunch 6 6 0123456789 | john --stdin --format=raw-md5 <hashfile>
```

**Practical tips**:
- Estimate the size before generating: output lines = charset_length^positions; crunch prints the data volume at startup — 16^6 is already 112MB, and 8 lowercase letters is 26^8 ≈ 2TB. Never write that to disk with `-o`; use a pipe or split output (`-b` splits by size).
- Complements PACK: use crunch when the pattern is known; when you only have statistical regularities, derive masks with statsgen→maskgen.
- `-s` sets the starting block, handy for resuming or generating in segments.

### rsmangler — a wordlist mangling/combination expander

**Purpose**: Reads a small seed wordlist, first generates permutations and abbreviations, then applies case, leet, prefix/suffix, year, and other mangling, outputting a variant list that grows geometrically.
**Installation**: `sudo apt install rsmangler`
**When to use**: When you have a small set of high-confidence seed words (company, person, or project names, often from cewl/bopscrk) and want to expand 10 words into tens of thousands of variants.

```bash
# 官网示例:种子词经 stdin 输入,限长度 6-8,输出重定向
cat words.txt | rsmangler -m 6 -x 8 --file - > mangled.txt
```

**Practical tips**:
- Output explodes exponentially: the official site's 3 words plus length filtering already yield 367 lines; without `-m/-x` length filters a slightly larger seed set spirals out of control — always do a small trial run first.
- A leaner alternative: mangle inside the cracker with hashcat rules (`best64.rule`/`d3ad0ne.rule`) and skip the intermediate file.
- Typical chain: `cewl → rsmangler → hydra/hashcat`.

### bopscrk — a smart wordlist generator based on the target's personal information

**Purpose**: Takes personal information related to the target (name, birthday, pets, company, etc.), combines and mangles it into likely passwords; the lyricpass module can scrape song lyrics into the list.
**Installation**: `sudo apt install bopscrk`
**When to use**: Building social-engineering wordlists before targeted attacks (authorized tests/CTF where the target's personal information is known); far more precise than generic lists.

```bash
# 交互模式(逐项询问目标信息)
bopscrk -i

# 非交互:直接给词根,逗号分隔,输出到文件
bopscrk -w <word1,word2> -o <wordlist>
```

**Practical tips**:
- `-i` interactive mode covers the most information (birthday, phone, nicknames, etc., with combination rules applied automatically).
- Output is usually small, well suited to a second mangling pass with rsmangler or hashcat rules.
- Together with twofi (social media words) and cewl (site words), it forms the three sources of "targeted corpora".

### statsgen — PACK: profile the password mask distribution of existing leak corpora

**Purpose**: Analyzes a plaintext password corpus and outputs length distribution, charset composition, and simple/advanced masks (?l?d notation) with their shares, providing the basis for mask attacks; does not crack anything itself.
**Installation**: `sudo apt install pack`
**When to use**: When you have cracked password samples (leak corpora or passwords already recovered in this engagement), profile the patterns first and then generate targeted masks — much higher hit rates than blindly guessing templates.

```bash
# 官网示例:统计 rockyou 中长度恰为 10 的密码
statsgen --minlength=10 --maxlength=10 /usr/share/wordlists/rockyou.txt

# 输出统计文件供 maskgen 使用
statsgen /usr/share/wordlists/rockyou.txt -o rockyou.stats
```

**Practical tips**:
- Focus on the "Advanced Masks" section: the first dozen-plus masks usually cover 30-60% of samples and set the priority order for mask attacks.
- More effective against the target environment: sample from that project's/client's already-leaked passwords rather than rockyou.
- The resulting `.stats` file is maskgen's direct input.

### maskgen — PACK: generate statistically optimal hashcat mask sequences

**Purpose**: Reads statsgen's statistics file, generates a probability-ordered mask list (.hcmask), and estimates brute-force time; `--optindex` sorts by optimal index.
**Installation**: `sudo apt install pack` (same package as statsgen)
**When to use**: Turning "statistical patterns" into an executable hashcat attack file so mask attacks run from highest to lowest hit rate.

```bash
# 由统计文件生成按概率排序的掩码文件
maskgen rockyou.stats --optindex -o rockyou.hcmask

# 生成的 .hcmask 直接作为 -a 3 的"掩码文件"参数
hashcat -m 1000 -a 3 <hashfile> rockyou.hcmask
```

**Practical tips**:
- An `.hcmask` file holds one mask per line; hashcat executes them in order, equivalent to an automatically orchestrated multi-round mask attack.
- `--optindex` usually cuts total attempts significantly; first verify with a small hash sample that the mask file loads correctly.
- Distinguish it from policygen: maskgen works from historical statistics, policygen from the target's password policy.

### policygen — PACK: generate policy-compliant masks from a password policy

**Purpose**: Given the target system's password policy (length, minimum counts of uppercase/digits/symbols), enumerates every hashcat mask that satisfies the policy and estimates runtime.
**Installation**: `sudo apt install pack` (same package as statsgen)
**When to use**: When the target enforces a complexity policy (e.g. "at least 1 uppercase and 1 digit"), prune the impossible mask space first, then brute force.

```bash
# 官网示例:长度 8、至少 1 大写 + 1 数字,输出掩码文件
policygen --minlength 8 --maxlength 8 --minupper 1 --mindigit 1 -o complexity.hcmask

# 生成结果直接喂 hashcat 掩码模式
hashcat -m 1000 -a 3 <hashfile> complexity.hcmask
```

**Practical tips**:
- The output prints both Total/Policy mask counts plus estimated runtime; check the time estimate before committing to a run.
- Combine with statsgen: policygen sets the policy boundary, and maskgen orders by probability within it — the standard "policy + statistics" two-step.
- Common parameters: `--minlower/--minupper/--mindigit/--minspecial` and `--maxlength`.

### hashid — identify hash types and map them to hashcat/john

**Purpose**: A Python 3 tool that identifies 175+ hash types by regex; supports single hashes and batch files, and can directly output the corresponding hashcat mode number (-m) and john format name (-j).
**Installation**: `sudo apt install hashid`
**When to use**: The first step after obtaining an unknown hash: deciding the `-m` value to feed hashcat or the `--format` value for john.

```bash
# 识别单条 hash(加引号防止 shell 解析特殊字符)
hashid '<hash>'

# 同时显示 hashcat 模式号与 john 格式
hashid -m -j '<hash>'

# 批量识别文件中的 hash 并保存结果
hashid -m -j -o result.txt <hashfile>
```

**Practical tips**:
- "Ambiguous hashes" like plain MD5/SHA1 (dozens of salted/HMAC variants) only get a candidate list; final confirmation comes from source context (database type, capture protocol).
- Validate the identified mode number with `hashcat --identify <hashfile>` or a few seconds of actual cracking; a `Separator unmatched` error means the mode is wrong.
- hashid is newer and scriptable; hash-identifier suits quick interactive lookups.

### hash-identifier — the veteran interactive hash type identifier

**Purpose**: A small interactive tool: paste a hash and it lists hash types ranked from most to least likely.
**Installation**: `sudo apt install hash-identifier`
**When to use**: Quickly confirming a single hash by hand; unsuitable for batch and scripted use.

```bash
# 启动后在 HASH: 提示符粘贴 hash
hash-identifier
```

**Practical tips**:
- Output is sorted by likelihood; check the first few entries under "Possible Hashs" first.
- A 32-character hex gets a long list of MD5-family variants by default and needs source context to decide; for batch work switch to hashid.

### seclists — the full collection of security testing lists (usernames/passwords/directories/fuzz)

**Purpose**: A collection of lists commonly used in security assessments: usernames, passwords, leak corpora, default credentials, web directories, fuzz payloads, and more — ready to use once installed.
**Installation**: `sudo apt install seclists` (installed by default on Kali)
**When to use**: Look here for ready-made lists before any brute forcing/enumeration; the default ammunition depot for hydra `-L/-P`, hashcat dictionaries, and directory-scanning wordlists.

```bash
# 常用路径(均为 /usr/share/seclists/ 下)
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
/usr/share/seclists/Passwords/Leaked-Databases/          # 各泄露库打包
/usr/share/seclists/Passwords/Default-Credentials/       # 设备/中间件默认口令
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Usernames/Names/names.txt            # 英文人名
/usr/share/seclists/Discovery/Web-Content/common.txt     # Web 目录/文件
/usr/share/seclists/Fuzzing/                             # 各类 payload

# 组合示例:hydra 用户表 + seclists 密码表
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
      -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
      <ip> ssh
```

**Practical tips**:
- Scale lists up gradually: top-100 → top-1000 → top-10000 → the full corpus; prefer small lists for online attacks (saves time, fewer lockouts).
- `Usernames/Names/` fits generating corporate usernames from naming conventions (first.last, flast) to pair with hydra.
- The directory structure maps cleanly to purpose; one `ls` level locates the right list, no need to memorize paths.

### wordlists — rockyou and Kali's built-in wordlist packages

**Purpose**: Provides rockyou.txt (about 14.34 million entries; the 2009 leak corpus and the benchmark password-cracking wordlist); Kali's `/usr/share/wordlists/` also contains metasploit dictionaries and several classic small lists.
**Installation**: `sudo apt install wordlists` (installed by default on Kali)
**When to use**: The first round of ammunition for any dictionary attack; rockyou + rule mangling cracks the vast majority of weak passwords.

```bash
# 首次使用前解压(默认以 .gz 提供)
gunzip /usr/share/wordlists/rockyou.txt.gz

# 确认规模
wc -l /usr/share/wordlists/rockyou.txt

# 同目录其他常用表
/usr/share/wordlists/metasploit/unix_passwords.txt
/usr/share/wordlists/metasploit/unix_users.txt
/usr/share/wordlists/nmap.lst
/usr/share/wordlists/fasttrack.txt

# 标准首攻:rockyou + best64 规则
hashcat -m 1000 <hashfile> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**Practical tips**:
- rockyou contains a few non-UTF-8 lines; some tools (e.g. older john) may warn — fix with `iconv` or ignore; hashcat is unaffected.
- Do not throw the full rockyou at online brute forcing: filter first with pw-inspector or seclists top-1000.
- About 134MB after decompression; keep the .gz and pipe it to tools with `zcat` when disk space is tight.

### chntpw — offline viewing/resetting of Windows SAM passwords

**Purpose**: Edits the Windows NT/2000+ SAM user database directly: view information, blank or change a user's password without knowing the old one; ships with a simple registry editor.
**Installation**: `sudo apt install chntpw`
**When to use**: Offline resets once you have disk access to the target (physical access, Live USB, mounted image); not for cracking — it rewrites directly.

```bash
# 挂载 Windows 分区后,交互式菜单(现代 Windows 需同时给 SYSTEM hive)
chntpw -i /mnt/win/Windows/System32/config/SAM /mnt/win/Windows/System32/config/SYSTEM

# 仅列出用户
chntpw -l /mnt/win/Windows/System32/config/SAM

# 直接指定用户进入编辑/清空流程
chntpw -u <user> -i <SAM> <SYSTEM>
```

**Practical tips**:
- In the interactive menu pick "1" to blank the password and "3" to promote to administrator; after the write-back you must exit normally so the tool syncs the hive.
- If the target uses BitLocker, modifying the SAM triggers a recovery-key requirement; confirm the encryption status before acting.
- Use samdump2 when you only need to extract hashes for offline cracking (preserving evidence, not touching the system); use chntpw only to change passwords.

### samdump2 — extract Windows hashes from the SAM

**Purpose**: Decrypts the SAM with the syskey bootkey from the SYSTEM hive and exports LM/NT hashes in pwdump format; includes the former bkhive functionality (bootkey recovery).
**Installation**: `sudo apt install samdump2`
**When to use**: After obtaining both the `SAM` and `SYSTEM` hive files, dump NTLM hashes and hand them to hashcat -m 1000 / john --format=NT for offline cracking.

```bash
# 从挂载的 Windows 分区导出哈希(参数顺序:SYSTEM 在前,SAM 在后)
samdump2 /mnt/win/Windows/System32/config/SYSTEM /mnt/win/Windows/System32/config/SAM > hashes.txt

# 交给破解器
john --format=NT --wordlist=<wordlist> hashes.txt
```

**Practical tips**:
- Output format is `user:rid:LM:NT:::`; hashcat needs field 4 (NT) while john consumes the whole line.
- In modern local account hashes the LM field is usually `aad3b435b51404eeaad3b435b51404ee` (the empty-LM placeholder); that is normal.
- Without the SYSTEM hive, recover the bootkey first via the `bkhive` flow (integrated into this package); for remote scenarios use impacket/secretsdump instead.

### mimikatz — Windows in-memory credential extraction (plaintext passwords)

**Purpose**: Leverages Windows administrator privileges to extract currently logged-on users' plaintext passwords, NTLM hashes, tickets, and DPAPI data from lsass process memory and other locations; can also export domain hashes via dcsync.
**Installation**: `sudo apt install mimikatz` (the package ships Windows PE binaries — copy them to the target to run, or run locally under wine)
**When to use**: Once you have administrator/SYSTEM on a Windows target and can execute binaries, prefer this over guess-based cracking — read the plaintext directly.

```text
# 以下在 Windows 目标的 mimikatz 控制台内执行
privilege::debug
token::elevate
sekurlsa::logonpasswords        # 提取 lsass 中的明文/NTLM
lsadump::sam                    # 本机 SAM 哈希
lsadump::dcsync /domain:<domain> /user:krbtgt    # 域控同步导出 krbtgt
```

**Practical tips**:
- The `Privilege '20' OK` output is expected; when antivirus blocks it, a common alternative is dumping lsass with procdump and parsing it offline with pypykatz/mimikatz.
- Under Windows 8.1+ default configurations plaintext (Wdigest) is mostly empty, but NTLM/Kerberos tickets can still be extracted for pass-the-hash.
- The Kali package may lag behind the official GitHub release; in practice, target compatibility decides; in domain environments prefer `lsadump::dcsync`.

### fcrackzip — Zip archive password cracking

**Purpose**: Dictionary/brute-force cracking of legacy ZipCrypto-encrypted zip files, partly implemented in assembly for speed; results can be double-checked with unzip.
**Installation**: `sudo apt install fcrackzip`
**When to use**: Password-protected .zip files in CTF and forensics work; confirm ZipCrypto rather than AES first.

```bash
# 字典模式(-D)并用 unzip 验证(-u 过滤误报)
fcrackzip -u -D -p <wordlist> <file>.zip

# 暴力模式:小写+数字,长度 4-8
fcrackzip -b -c a1 -l 4-8 -u <file>.zip
```

**Practical tips**:
- Always add `-u`: ZipCrypto has a high false-positive rate and without it you get piles of wrong passwords.
- AES-encrypted zips (created by newer WinZip/7-Zip) are unsupported; use `zip2john` + john or hashcat -m 13600 (WinZip)/17200 series (PKZIP) instead.
- To tell the encryption type: check the "file encrypted" type with `zipinfo <file>.zip`, or look for the "AES-256" hint from 7z.

### truecrack — brute-force cracking of TrueCrypt volume passwords

**Purpose**: Password cracking for TrueCrypt volumes (CUDA-optimized), supporting the RIPEMD160/SHA512/Whirlpool KDFs (PBKDF2) + XTS/AES.
**Installation**: `sudo apt install truecrack`
**When to use**: When you have a TrueCrypt encrypted volume file and an NVIDIA GPU.

```bash
# 官网示例结构:卷文件 + KDF + 字典
truecrack -t <volume> -k ripemd160 -w <wordlist>
```

**Practical tips**:
- `-k` accepts `ripemd160`/`sha512`/`whirlpool`; only the one chosen when the volume was created will hit, so try them in turn.
- Not applicable to VeraCrypt volumes (KDF iterations are roughly 1000x higher); use the hashcat -m 137xx series instead and expect it to be extremely slow.
- Without a GPU, the same scenario works with john's `truecrypt` format.

### ophcrack-cli — instant rainbow-table lookup of Windows passwords (command line)

**Purpose**: Windows password cracking via rainbow tables (a time-memory trade-off); the official tables claim 99.9% of alphanumeric passwords cracked in seconds; the CLI version serves scripts and headless environments.
**Installation**: `sudo apt install ophcrack-cli`
**When to use**: Fast NT hash table lookups when you already have rainbow tables (downloaded separately, GB to tens of GB); works best on LM-era passwords.

```bash
# 哈希文件 + 表目录 + 表集名(表集名如 xp_free_fast、vista_free)
ophcrack-cli -f <hashfile> -d /path/to/tables -t <tableset>
```

**Practical tips**:
- Table sets must match the target password composition (small alphanumeric tables, larger tables covering symbols); anything the tables do not cover stays uncracked.
- On modern Windows without LM hashes and with high-complexity passwords, it is far less valuable than hashcat dictionary + rules; keep it low priority.
- Table directories can live on removable drives; the `-t` table-set name must match the downloaded table directory name.

### rcrack — RainbowCrack rainbow-table hash cracking

**Purpose**: The classic time-space trade-off implementation: cracks hashes by lookup against pre-generated rainbow tables (.rt/.rtc, etc.), as opposed to brute forcing each candidate.
**Installation**: `sudo apt install rainbowcrack`
**When to use**: When you already hold rainbow tables (or generate them yourself with rtgen/rtsort) and need repeatable fast lookups over a fixed charset space.

```bash
# 单条哈希查表(-h)
rcrack /path/to/tables/*.rt -h <hash>

# 哈希列表文件(-l)
rcrack /path/to/tables/*.rt -l <hashfile>
```

**Practical tips**:
- Tables must be sorted (rtsort) before lookup; the table file format (rt/rti/rtc) must match the tool version.
- Building your own tables runs `rtgen` (generate) → `rtsort` (sort) → `rcrack` (lookup); the cost is high and it only pays off for heavily reused scenarios.
- Support for newer hash types is limited; prefer hashcat for modern algorithms.

### sipcrack — SIP digest authentication extraction and cracking (VoIP)

**Purpose**: Extracts digest authentication challenges/responses from pcap or SIP signaling (sipdump), then runs offline dictionary cracking against the accounts (sipcrack).
**Installation**: `sudo apt install sipcrack`
**When to use**: Password recovery in VoIP penetration tests after capturing SIP digest authentication traffic for REGISTER/INVITE.

```bash
# 从抓包提取登录挑战响应到文件
sipdump -p <capture>.pcap sip-logins.txt

# 用字典离线破解
sipcrack -w <wordlist> sip-logins.txt
```

**Practical tips**:
- Only works against digest accounts with weak passwords; an empty extraction usually means the capture lacks a complete 401/200 exchange.
- A cracked extension password can be used directly for registration hijacking/toll-fraud verification (within the authorized scope).
- Pair with a Wireshark `sip` filter to confirm the pcap actually contains `Authorization` headers.

### sucrack — local multi-threaded su brute forcing (privilege escalation aid)

**Purpose**: On a Linux/Unix host where you already hold a low-privilege shell, brute forces other users' (usually root) passwords via multi-threaded su attempts through pseudo-terminals.
**Installation**: `sudo apt install sucrack`
**When to use**: When you have a low-privilege shell, su is available, but no interactive terminal supports scripting — brute force the root password to escalate.

```bash
# 指定并行线程数与字典
sucrack -w 10 <wordlist>
```

**Practical tips**:
- su needs a TTY, which plain scripts/pipes can hardly provide — exactly why this tool exists; before using it over a reverse shell, confirm the shell supports pseudo-terminals.
- Failed attempts write to auth.log and leave obvious traces; mind log-cleanup agreements and lockout policies in authorized tests.
- Try the `hydra -e nsr` mindset first: a handful of manual weak passwords like `root/root` and `root/toor` is often enough.

### thc-pptp-bruter — high-speed brute forcing of PPTP VPN gateways

**Purpose**: Brute forces PPTP VPN endpoints (TCP 1723) with MSChapV2 support; exploits a flaw in Microsoft's anti-brute-force implementation to reach roughly 300 attempts per second.
**Installation**: `sudo apt install thc-pptp-bruter`
**When to use**: Credential testing when the target exposes PPTP VPN (common on legacy gateways); far faster than general-purpose tools.

```bash
# 默认用户 administrator,stdin 或 -w 供字典
thc-pptp-bruter -u administrator -w <wordlist> <ip>
```

**Practical tips**:
- Help: `-u` user, `-w` wordlist file (default stdin), `-p` port, `-n` parallelism, `-v` debug, `-W` disables the Windows anti-brute-force flaw exploit (add `-W` up front for non-Windows gateways like Cisco).
- The PPTP protocol itself is broken (MSChapv2 can be recovered offline); your report should also recommend retiring PPTP.

### legba — a Rust async multi-protocol brute forcer/sprayer

**Purpose**: A multi-protocol credential brute forcing, password spraying, and enumeration tool built with Rust + Tokio, using fewer resources than its peers; plugin-based, with YAML recipes for reusable configuration.
**Installation**: `sudo apt install legba`
**When to use**: As a modern hydra replacement, for long-running or low-memory constrained environments, or batch tests that reuse standardized "recipes".

```bash
# 列出全部协议插件
legba -L

# 插件式调用(以 legba <plugin> -h 查看该插件完整参数)
legba ssh --target <ip> --username <user> --password <wordlist>
```

**Practical tips**:
- Subcommands are plugin names; check `-L` first to confirm a plugin exists and how it is named (not fully identical to hydra module names).
- `-R/--recipe` loads a YAML config, a good fit for recurring regression testing.
- The young tool's ecosystem is still evolving; validate the verdict logic on a small sample before critical tasks.

## Remaining Tools — Quick Reference

| Tool | One-line purpose | Package | Most common command |
|---|---|---|---|
| creddump7 | Extract credentials/keys from Windows registry hives (pwdump/lsadump/cachedump) | creddump7 | `python /usr/share/creddump7/pwdump.py <SYSTEM> <SAM>` |
| cmospwd | Decrypt BIOS setup passwords stored in CMOS | cmospwd | `sudo cmospwd` |
| eapmd5pass | Extract and offline-crack 802.1X EAP-MD5 authentication | eapmd5pass | `eapmd5pass -r <capture>.pcap -w <wordlist>` |
| freeradius | RADIUS server; freeradius-utils provides radtest/radclient for credential testing | freeradius-utils | `radtest <user> <pass> <server> 0 <secret>` |
| gitxray | Scan GitHub repositories/contributors/organizations to gather OSINT | gitxray | `gitxray -r <owner>/<repo>` |
| hydra-gtk | GTK graphical front end for hydra | hydra-gtk | `hydra-gtk` |
| johnny | Cross-platform GUI for John the Ripper | johnny | `johnny` |
| mifare-classic-format | Mifare Classic RFID key recovery toolset (mfcuk, etc.) | mfcuk | `mfcuk -C -R 0:A -v 2` |
| ophcrack | Windows password rainbow-table cracking (GUI version) | ophcrack | `ophcrack` |
| rcracki_mt | Multi-threaded/hybrid-table RainbowCrack variant | rainbowcrack | `rcracki_mt <tables>/*.rti -h <hash>` |
| sqldict | SQL Server dictionary attacks (a Windows program, needs wine32) | sqldict | `dpkg --add-architecture i386 && apt update && apt -y install wine32` |
| trufflehog | Dig through git history and branches for accidentally committed secrets/credentials | trufflehog | `trufflehog git https://github.com/<org>/<repo> --only-verified` |
| twofi | Fetch high-frequency Twitter terms by keyword to build custom wordlists | twofi | `twofi -t <keyword1,keyword2>` |
| xspy | Sniff local/remote X server keyboard input | xspy | `xspy` |

> Every command in this file is for penetration testing, CTF competitions, and security education scenarios with prior written authorization only.
