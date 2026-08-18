# 密码攻击(Password Attacks)

> **何时读本文件**:任务涉及哈希类型识别与离线破解(hashcat/john)、在线登录爆破(hydra/medusa/ncrack/patator/crowbar)、字典生成与变形(cewl/crunch/PACK/rsmangler/bopscrk)、Windows 凭据提取(mimikatz/samdump2/chntpw)或加密文件/卷口令恢复时读取。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| 离线破解哈希(有 GPU) | hashcat | john | hashcat GPU 快 10-100 倍,300+ 算法,需指定 `-m` |
| 离线破解哈希(仅 CPU/格式不明) | john | hashcat | john 自动识别 hash 格式,单文件直接跑 |
| Linux /etc/shadow 破解 | john + unshadow | hashcat -m 500/1800/7400 | unshadow 合并 passwd/shadow 一条龙 |
| Windows NTLM(SAM 提取) | hashcat -m 1000 | john --format=NT | 格式见各自速查表 |
| NetNTLMv2 / Kerberoast 捕获哈希 | hashcat -m 5600/13100 | john netntlmv2/krb5tgs | Responder/impacket 输出直接喂入 |
| 在线爆破通用协议 | hydra | medusa / ncrack / legba | hydra 协议覆盖最全,上手最快 |
| 大规模多主机并行审计 | ncrack | medusa | ncrack 语法仿 nmap,动态调时引擎 |
| 需精细控制的 Web/数据库爆破 | patator | hydra http-post-form | patator 支持多文件交叉、fgrep/regex 判定 |
| SSH 私钥认证 / RDP(NLA) / OpenVPN | crowbar | hydra(部分) | crowbar 独有 key-based SSH 与 NLA RDP |
| 定制字典(目标网站词汇) | cewl | twofi / bopscrk | cewl 爬目标站点;twofi 用社媒;bopscrk 用个人信息组合 |
| 按字符集/模板生成字典 | crunch | policygen / maskgen | crunch 全排列;PACK 按统计或密码策略出掩码 |
| 字典变形扩容 | rsmangler | hashcat -r 规则 | rsmangler 排列组合,输出爆炸式增长 |
| 识别 hash 类型 | hashid | hash-identifier / `hashcat --identify` | hashid 直接给出 hashcat 模式号与 john 格式名 |
| Windows 在线抓明文/NTLM | mimikatz | impacket-secretsdump(另见 SMB 领域) | mimikatz 从 lsass 内存取明文 |
| Windows 离线 SAM 提取 | samdump2 | creddump7 / chntpw | chntpw 还能不清不楚地直接清空/改写密码 |
| Zip 压缩包口令 | fcrackzip | john(zip2john) | AES 加密 zip 只能走 john/hashcat,见要点 |
| TrueCrypt 卷 | truecrack | hashcat -m 6211+ | VeraCrypt 卷用 hashcat 137xx(极慢) |
| BIOS/CMOS 口令解密 | cmospwd | — | 针对老式 BIOS 的 CMOS 存储 |

## 核心工具详解

### hashcat — 世界最快的 GPU 密码恢复工具

**用途**:离线破解哈希。支持 300+ 哈希算法、CPU/GPU/硬件加速器,五种攻击模式(字典 straight / 组合 combination / 掩码 brute-force / 混合 hybrid×2),自带 potfile 断点记录、会话恢复与分布式辅助能力。
**安装**:`sudo apt install hashcat`(Kali 默认已装)
**使用场景**:已拿到 hash 文件(shadow、SAM、Responder 捕获、Kerberoast 票据等)且有 NVIDIA/AMD GPU 或 decent CPU 时的第一选择;无 GPU 且格式不明时先用 john 自动识别。

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

**Hash 模式速查表**(常用 `-m` 值):

| 哈希类型 | -m | 备注/识别特征 |
|---|---|---|
| MD5 | 0 | 32 位十六进制 |
| MD5($pass.$salt) | 10 | 输入格式 `hash:salt` |
| MD5($salt.$pass) | 20 | 同上 |
| SHA1 | 100 | 40 位十六进制 |
| SHA1($pass.$salt) | 110 / SHA1($salt.$pass) 120 | `hash:salt` |
| MySQL323 | 200 | 旧版 MySQL `password()` |
| MySQL4.1/MySQL5 | 300 | `*` 开头 41 位 |
| md5crypt ($1$, Unix) | 500 | shadow 中 `$1$` |
| MD4 | 900 | |
| NTLM | 1000 | 32 位,Windows SAM/内存转储 |
| Domain Cached Credentials (DCC/MSCache) | 1100 | 本机缓存凭据 |
| SHA2-256 | 1400 | |
| SHA2-512 | 1700 | |
| sha512crypt ($6$, Unix) | 1800 | shadow 中 `$6$` |
| sha256crypt ($5$, Unix) | 7400 | shadow 中 `$5$` |
| DCC2 / MSCache2 | 2100 | 域缓存凭据 v2 |
| bcrypt ($2*$) | 3200 | 极慢,优先 `-S` |
| Joomla | 11 | |
| WordPress / phpBB3 (phpass) | 400 | `$P$` 开头 |
| Drupal7 | 7900 | `$S$` 开头 |
| macOS 10.8+ (PBKDF2-HMAC-SHA512) | 7100 | |
| PBKDF2-HMAC-SHA256 | 10000 | |
| scrypt | 8900 | |
| Kerberos AS-REQ pre-auth etype 23 | 7500 | krb5pa-md5 |
| NetNTLMv1 / NetNTLMv1+ESS | 5500 | 中继/破解二选一 |
| NetNTLMv2 | 5600 | Responder 捕获的标准产出 |
| Kerberos TGS-REP etype 23(Kerberoast) | 13100 | etype 17/18 为 19600/19700 |
| Kerberos AS-REP etype 23(AS-REP Roast) | 18200 | etype 17/18 为 19900/20000 |
| RAR3-hp / RAR5 | 12500 / 13000 | |
| ZIP (PKZIP) / WinZip | 17200 系列 / 13600 | 配合 zip2john 转换 |
| KeePass 1/2 | 13400 | keepass2john 转换 |
| JWT (HS256) | 16500 | |
| LUKS | 14600 | |
| TrueCrypt RIPEMD160+XTS 512bit | 6211 | 6212/6213 为 SHA512/Whirlpool |
| VeraCrypt | 13711+ 系列 | 迭代次数极高,极慢 |
| WPA-PBKDF2-PMKID+EAPOL | 22000 | 旧 16800(PMKID)/2500(WPA)已并入 |

**实战要点**:
- 弹药顺序:`rockyou` 直跑 → `rockyou + best64.rule` → `rockyou + dive.rule/d3ad0ne.rule`(均在 `/usr/share/hashcat/rules/`)→ 掩码/混合攻击。
- `-O` 优化内核把明文长度上限降为 31,纯数字长口令场景注意;`-w 4`(nightmare)会卡死桌面;慢 KDF 算法(bcrypt/Kerberos 5900 系)加 `-S` 让 CPU 生成候选喂 GPU。
- potfile 自动记录已破解项,重跑自动跳过;`--show` 查结果;换攻击方式不必删 potfile。
- salt 格式错误是最常见翻车点:带盐模式必须 `hash:salt` 两段;NetNTLMv2/Kerberoast 用 `--username` 避免 hashcat 把用户名当盐解析失败。

### john — John the Ripper,自动识别格式的 CPU 破解器

**用途**:离线破解哈希,CPU 优化极佳,自动检测 hash 类型;jumbo 版内置数百格式与 `*2john` 系列转换脚本(zip/ssh/rar/keepass 等),另有 `unshadow`、`unique` 等配套工具。
**安装**:`sudo apt install john`(Kali 默认已装;转换脚本在 `/usr/share/john/`)
**使用场景**:无 GPU、格式不确定想"先跑起来"、需要爆破 SSH 私钥口令/加密文档口令,或做 shadow 合并破解时的第一选择。

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

**实战要点**:
- 与 hashcat 分工:john 负责格式自动识别与 CPU 场景;大批量/慢算法上 GPU 用 hashcat。
- 出现 `detected hash type X, but also recognized as Y` 警告时,用 `--format=` 显式指定,避免按错误格式跑空。
- 已破解记录在 `~/.john/john.pot`,`--show` 读取;删除 potfile 可强制重跑。
- `unique` 工具(同包)给大字典去重:`unique -v -inp=allwords.txt uniques.txt`。

### hydra — THC Hydra,协议覆盖最全的在线登录爆破器

**用途**:并行化网络登录爆破,支持 ssh/ftp/http(s) 表单与 Basic/smb/rdp/mysql/postgres/telnet/vnc/ldap/pop3/imap/smtp 等数十种协议;配套 `pw-inspector` 过滤密码表。
**安装**:`sudo apt install hydra`(Kali 默认已装;GUI 版装 `hydra-gtk`)
**使用场景**:对已知开放认证服务做在线字典/喷洒攻击的首选;Web 表单场景与 patator 二选一。

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

**实战要点**:
- 先手动登录一次抓包,确认表单字段名与失败页特征串(`F=`)再写命令,占位符、Cookie、CSRF token 不匹配是最常见失败原因。
- 在线爆破前评估账户锁定策略:先小字典/喷洒(每用户 1-5 个密码)再上大字典,防止锁死全部账户。
- `-e nsr` 三连几乎零成本,永远先加;`-f` 单目标必加以免跑完整本字典。
- Web 表单失败特征优先选错误提示唯一子串;页面每次都变(如时间戳)时用 `S=` 成功特征替代 `F=`。

### medusa — 稳定的并行模块化登录爆破器

**用途**:基于多线程的模块化网络登录爆破,强调稳定性;支持多主机/多用户/多密码并发,模块覆盖 ssh/ftp/telnet/smb/rdp/http/mysql/mssql/postgres/vnc/webDav 等。
**安装**:`sudo apt install medusa`(Kali 默认已装)
**使用场景**:hydra 模块行为异常(如老系统 SMB/HTTP)或需要对一批主机批量测试同一组凭据时。

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

**实战要点**:
- `-t` 是每主机线程,`-T` 是并行主机数,二者叠加决定总并发;RDP/SMB 压低线程。
- 与 hydra 相比协议略少但长跑更稳;`-O` 落盘结果便于事后留档。
- 模块名即协议名,`medusa -d` 先确认拼写(如 `smbnt` 为老版本 SMB 模块名)。

### ncrack — nmap 出品的高速认证爆破工具

**用途**:模块化高速网络认证爆破,语法仿 nmap,内置根据网络反馈动态调整的超时/重连引擎,适合大规模多主机审计。
**安装**:`sudo apt install ncrack`
**使用场景**:数十到数百台主机的凭据审计;对高延迟/易断连目标(老设备、嵌入式)比 hydra 更可靠。

```bash
# 官网示例:目标列表 + 单用户 + 密码表 + RDP + 单连接限制
ncrack -v -iL win.txt --user victim -P passes.txt -p rdp CL=1

# 单目标直连
ncrack --user root -P <wordlist> ssh://<ip>

# 多服务同扫:22/3389 端口映射到 ssh/rdp
ncrack -p 22,3389 --user admin -P <wordlist> <ip>
```

**实战要点**:
- `CL=n` 限制每目标并发连接数,对 RDP/SSH 等易触发防护的服务设 1-4。
- 命中输出形如 `Discovered credentials on rdp://<ip>:3389 '<user>' '<pass>'`,结果也可 `-oN <file>` 保存。
- 支持时机参数(`to=/时间`)整体限速,大规模场景避免打瘫目标。

### patator — 多用途可编程爆破框架

**用途**:Python 编写的高度可配置爆破框架,模块化(ftp/ssh/telnet/smb/mssql/mysql/oracle/postgres/http_basic/http_form/ldap/vnc 等),支持 FILE0/FILE1 多文件交叉组合与 fgrep/regex 结果判定。
**安装**:`sudo apt install patator`
**使用场景**:hydra 表达不了的复杂逻辑——多字段表单、需要交叉组合用户×密码×其他参数、需要精细条件判断成功/失败时。

```bash
# 官网示例:MySQL 爆破,过滤 "Access denied" 响应
patator mysql_login user=root password=FILE0 0=<wordlist> host=<ip> -x ignore:fgrep='Access denied for user'

# SSH 登录(忽略连接 reset)
patator ssh_login host=<ip> user=FILE0 0=<userlist> password=FILE1 1=<wordlist> -x ignore:reset

# Web 表单:用户表×密码表交叉(follow=1 跟随 302 跳转)
patator http_form url=http://<ip>/login.php method=POST body='username=FILE0&password=FILE1' 0=<userlist> 1=<wordlist> follow=1 -x ignore:fgrep='Login failed'
```

**实战要点**:
- `FILE0`、`FILE1` 是文件占位符,对应 `0=文件 1=文件`,同一文件可复用到多个字段实现交叉。
- 模块名在旧版本中拼作 `http_fomr`(项目历史 typo),新版为 `http_form`;不确定时 `patator -h` 查看模块列表。
- `-x ignore:fgrep=...`/`-x ignore:egrep=...` 抑制失败行,终端只留命中,对大字典输出至关重要。

### crowbar — 支持"密钥认证"的特殊爆破器

**用途**:面向传统用户名+密码爆破工具覆盖不了的协议:SSH 私钥认证、带 NLA 的 RDP、OpenVPN、VNC 密钥,支持网段批量。
**安装**:`sudo apt install crowbar`
**使用场景**:拿到了 SSH 私钥想批量试哪些主机接受它;目标 RDP 强制 NLA 导致 hydra 失败;OpenVPN 网关凭据测试。

```bash
# 用 SSH 私钥扫整个网段(默认 22 端口)
crowbar -b sshkey -s 192.168.1.0/24 -u root -k id_rsa

# RDP(NLA)密码喷洒:单密码大面积尝试
crowbar -b rdp -s 192.168.1.100/32 -u administrator -c <password>

# 查看帮助与模块
crowbar -h
```

**实战要点**:
- `-b` 选模式(`sshkey`/`rdp`/`openvpn`/`vnckey`),`-s` 支持CIDR 网段,天然适合横向移动阶段。
- RDP NLA 场景 crowbar 是 hydra 的正统替代;失败多为凭据错误而非工具问题,可 `-v` 观察。
- OpenVPN 模式需提供 `.ovpn` 配置(`-m`)与证书(`-k`)。

### cewl — 通过爬取目标网站生成定制字典

**用途**:Ruby 编写的站点蜘蛛,按深度爬取 URL 返回页面中的词汇生成密码字典;可选提取 mailto 邮箱(可当用户名表),可附带数字变体。
**安装**:`sudo apt install cewl`(Kali 默认已装)
**使用场景**:面向特定公司的目标,通用字典打不动时;目标词汇(产品名、部门、缩写)构成的密码命中率显著高于 rockyou。

```bash
# 官网示例:深度 2、最短 5 字符,写入文件
cewl -d 2 -m 5 -w docswords.txt https://<url>

# 带数字变体 + 提取邮箱(邮箱另存,可作 hydra -L 用户表)
cewl -d 2 -m 5 --with-numbers -e -w cewl_words.txt https://<url>
```

**实战要点**:
- `-d` 越深词汇越多但噪音越大,通常 2-3 层够用;`-m 5` 过滤无意义短词。
- 产出直接接 john/hashcat 规则变形:`hashcat -m 0 <hashfile> cewl_words.txt -r /usr/share/hashcat/rules/best64.rule`。
- 对 JS 渲染页面无效(不执行脚本),SPA 站点考虑先抓 sitemap/接口响应再手工喂词。

### crunch — 按字符集/模板生成全排列字典

**用途**:指定最小/最大长度与字符集(或预置字符集文件),生成排列组合字典;支持模板、分段输出、压缩与管道。
**安装**:`sudo apt install crunch`(Kali 默认已装)
**使用场景**:已知密码模式(如"品牌名+4 位数字"、"纯数字 8 位")时精确生成,避免全空间暴力。

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

**实战要点**:
- 生成前估算体积:输出行数 = 字符集长度^位数,crunch 启动时会打印数据量,16^6 即 112MB;8 位小写字母 26^8 ≈ 2TB,切勿 `-o` 落盘,用管道或分卷(`-b` 按大小切分)。
- 与 PACK 互补:模式明确用 crunch,只有统计规律用 statsgen→maskgen 出掩码。
- `-s` 可指定起始块,便于断点续跑分段生成。

### rsmangler — 字典变形/组合扩容器

**用途**:读入小词表,先做全排列与缩写生成,再套用大小写、leet、前后缀、年份等变形,输出几何级膨胀的变体表。
**安装**:`sudo apt install rsmangler`
**使用场景**:已有少量高置信种子词(公司名、人名、项目名,常来自 cewl/bopscrk)时,把 10 个词扩成数万变体。

```bash
# 官网示例:种子词经 stdin 输入,限长度 6-8,输出重定向
cat words.txt | rsmangler -m 6 -x 8 --file - > mangled.txt
```

**实战要点**:
- 输出是指数级爆炸:官网 3 个词 + 长度过滤即产出 367 行;不加 `-m/-x` 长度过滤、种子稍多就会失控,务必先小规模试跑。
- 更省资源的替代:直接用 hashcat 规则(`best64.rule`/`d3ad0ne.rule`)在破解器内做变形,不生成中间文件。
- 典型链路:`cewl → rsmangler → hydra/hashcat`。

### bopscrk — 基于目标个人信息的智能字典生成器

**用途**:输入与目标相关的个人信息(姓名、生日、宠物、公司等),组合并变形为可能的密码;lyricpass 模块可抓取歌手歌词入表。
**安装**:`sudo apt install bopscrk`
**使用场景**:定向攻击(已知目标个人信息的授权测试/CTF)前的社工字典制作,比通用字典精准。

```bash
# 交互模式(逐项询问目标信息)
bopscrk -i

# 非交互:直接给词根,逗号分隔,输出到文件
bopscrk -w <word1,word2> -o <wordlist>
```

**实战要点**:
- `-i` 交互模式覆盖信息最全(可填生日、电话、绰号等并自动套组合规则)。
- 产出通常不大,适合再经 rsmangler/hashcat 规则二次变形。
- 与 twofi(社媒词汇)、cewl(站点词汇)构成三类"定向语料"来源。

### statsgen — PACK:统计已有泄露库的密码掩码分布

**用途**:分析一份明文密码库,输出长度分布、字符集构成、简单/高级掩码(?l?d 记法)及其占比,为掩码攻击提供依据;本身不破解。
**安装**:`sudo apt install pack`
**使用场景**:有已破解密码样本(泄露库、本项目已得手口令)时,先统计规律再生成针对性掩码,比盲猜模板命中率高得多。

```bash
# 官网示例:统计 rockyou 中长度恰为 10 的密码
statsgen --minlength=10 --maxlength=10 /usr/share/wordlists/rockyou.txt

# 输出统计文件供 maskgen 使用
statsgen /usr/share/wordlists/rockyou.txt -o rockyou.stats
```

**实战要点**:
- 关注 "Advanced Masks" 段:前十几个掩码通常覆盖 30-60% 样本,是掩码攻击的优先顺序表。
- 对目标环境更有效的做法:用该项目/该客户已泄露的口令做样本,而非 rockyou。
- 产出的 `.stats` 文件是 maskgen 的直接输入。

### maskgen — PACK:按统计最优生成 hashcat 掩码序列

**用途**:读取 statsgen 的统计文件,生成按概率排序的掩码列表(.hcmask),并预估暴力时间;`--optindex` 按最优索引排序。
**安装**:`sudo apt install pack`(与 statsgen 同包)
**使用场景**:把"统计规律"变成可执行的 hashcat 攻击文件,让掩码攻击按命中率从高到低跑。

```bash
# 由统计文件生成按概率排序的掩码文件
maskgen rockyou.stats --optindex -o rockyou.hcmask

# 生成的 .hcmask 直接作为 -a 3 的"掩码文件"参数
hashcat -m 1000 -a 3 <hashfile> rockyou.hcmask
```

**实战要点**:
- `.hcmask` 文件每行一个掩码,hashcat 按序执行,等效于"自动编排的多轮掩码攻击"。
- `--optindex` 通常能显著减少总尝试次数;先用小 hash 样本验证掩码文件被正确加载。
- 与 policygen 区分:maskgen 基于历史统计,policygen 基于目标密码策略。

### policygen — PACK:按密码策略生成合规掩码

**用途**:根据目标系统的密码策略(长度、大写/数字/符号最少个数)穷举生成所有满足策略的 hashcat 掩码,并预估运行时间。
**安装**:`sudo apt install pack`(与 statsgen 同包)
**使用场景**:目标强制复杂度策略(如"至少 1 大写 1 数字")时,先剪枝掉不可能的掩码空间再暴力。

```bash
# 官网示例:长度 8、至少 1 大写 + 1 数字,输出掩码文件
policygen --minlength 8 --maxlength 8 --minupper 1 --mindigit 1 -o complexity.hcmask

# 生成结果直接喂 hashcat 掩码模式
hashcat -m 1000 -a 3 <hashfile> complexity.hcmask
```

**实战要点**:
- 输出会同时打印 Total/Policy 两组掩码数与预估运行时间,先看时间预估再决定是否开跑。
- 结合 statsgen:用 policygen 定策略边界,再用 maskgen 在边界内按概率排序,是"策略+统计"的标准两步。
- 常见参数:`--minlower/--minupper/--mindigit/--minspecial` 与 `--maxlength`。

### hashid — 识别哈希类型并映射到 hashcat/john

**用途**:Python 3 工具,正则识别 175+ 种哈希类型;支持单条、文件批量,可直接输出对应的 hashcat 模式号(-m)与 john 格式名(-j)。
**安装**:`sudo apt install hashid`
**使用场景**:拿到不明 hash 后的第一步,决定喂给 hashcat 的 `-m` 值或 john 的 `--format` 值。

```bash
# 识别单条 hash(加引号防止 shell 解析特殊字符)
hashid '<hash>'

# 同时显示 hashcat 模式号与 john 格式
hashid -m -j '<hash>'

# 批量识别文件中的 hash 并保存结果
hashid -m -j -o result.txt <hashfile>
```

**实战要点**:
- 纯 MD5/SHA1 这类"多义 hash"(加盐、HMAC 变体数十种)只能给候选列表,最终确认靠来源上下文(数据库类型、抓包协议)。
- 识别出的模式号先 `hashcat --identify <hashfile>` 或直接跑几秒验证,报 `Separator unmatched` 即模式不对。
- hashid 较新、可脚本化;hash-identifier 适合交互式快查。

### hash-identifier — 老牌交互式哈希类型识别

**用途**:交互式小工具,粘贴 hash 后列出"可能/最不可能"的哈希类型清单。
**安装**:`sudo apt install hash-identifier`
**使用场景**:快速人肉确认一条 hash;不适合批量与脚本化。

```bash
# 启动后在 HASH: 提示符粘贴 hash
hash-identifier
```

**实战要点**:
- 输出按可能性排序,优先看 "Possible Hashs" 前几项。
- 32 位 hex 默认按 MD5 系给一大串变体,需要结合来源判断;批量场景改用 hashid。

### seclists — 安全测试列表全集(用户名/密码/目录/fuzz)

**用途**:安全评估常用列表合集:用户名、密码、泄露库、默认凭据、Web 目录、fuzz payload 等,装好即用。
**安装**:`sudo apt install seclists`(Kali 默认已装)
**使用场景**:任何爆破/枚举前先到这里找现成表;是 hydra `-L/-P`、hashcat 字典、目录扫描词表的默认弹药库。

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

**实战要点**:
- 字典从小到大:top-100 → top-1000 → top-10000 → 完整库,在线爆破小表优先(省时间、少触发锁定)。
- `Usernames/Names/` 适合按命名规范生成企业用户名(first.last、flast)后配合 hydra。
- 目录结构与用途对应明确,选表前 `ls` 一层即可定位,不必背路径。

### wordlists — rockyou 及 Kali 内置字典包

**用途**:提供 rockyou.txt(约 1434 万条,2009 年泄露库,密码破解基准字典);Kali 的 `/usr/share/wordlists/` 还含 metasploit 字典与若干经典小表。
**安装**:`sudo apt install wordlists`(Kali 默认已装)
**使用场景**:一切字典攻击的第一发弹药;rockyou + 规则变形可解绝大多数弱口令。

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

**实战要点**:
- rockyou 含少量非 UTF-8 行,个别工具(如老版本john)可能告警,可 `iconv` 或忽略,hashcat 不受影响。
- 在线爆破不要直接上全量 rockyou:先用 pw-inspector 或 seclists top-1000 过滤。
- 解压后约 134MB,磁盘紧张可保持 .gz 并用 `zcat` 管道喂工具。

### chntpw — 离线查看/重置 Windows SAM 密码

**用途**:直接编辑 Windows NT/2000+ 的 SAM 用户数据库:查看信息、不清不知旧密码即可清空/修改用户密码;附带简单注册表编辑器。
**安装**:`sudo apt install chntpw`
**使用场景**:已获得目标磁盘访问权(物理接触、Live USB、镜像挂载)时的离线重置;不用于破解,直接改写。

```bash
# 挂载 Windows 分区后,交互式菜单(现代 Windows 需同时给 SYSTEM hive)
chntpw -i /mnt/win/Windows/System32/config/SAM /mnt/win/Windows/System32/config/SYSTEM

# 仅列出用户
chntpw -l /mnt/win/Windows/System32/config/SAM

# 直接指定用户进入编辑/清空流程
chntpw -u <user> -i <SAM> <SYSTEM>
```

**实战要点**:
- 交互菜单里选 "1" 清空密码、"3" 提升为管理员;写回后必须正常退出让工具同步 hive。
- 目标开了 BitLocker 时改 SAM 会触发恢复密钥要求,动手前确认加密状态。
- 只需提取 hash 离线破解(留证据、不改系统)时用 samdump2,改密码才用 chntpw。

### samdump2 — 从 SAM 提取 Windows 哈希

**用途**:用 SYSTEM hive 中的 syskey bootkey 解密 SAM,导出 pwdump 格式的 LM/NT 哈希;内置原 bkhive 功能(恢复 bootkey)。
**安装**:`sudo apt install samdump2`
**使用场景**:拿到 `SAM`+`SYSTEM` 两个 hive 文件后转出 NTLM 哈希,交给 hashcat -m 1000 / john --format=NT 离线破解。

```bash
# 从挂载的 Windows 分区导出哈希(参数顺序:SYSTEM 在前,SAM 在后)
samdump2 /mnt/win/Windows/System32/config/SYSTEM /mnt/win/Windows/System32/config/SAM > hashes.txt

# 交给破解器
john --format=NT --wordlist=<wordlist> hashes.txt
```

**实战要点**:
- 输出为 `user:rid:LM:NT:::` 格式;hashcat 需取第 4 字段(NT),john 可直接吃整行。
- 现代本地账户哈希中 LM 字段通常为 `aad3b435b51404eeaad3b435b51404ee`(空 LM 占位),属正常。
- 未能取得 SYSTEM hive 时可先 `bkhive` 流程恢复 bootkey(本包已整合);远程场景改走 impacket/secretsdump。

### mimikatz — Windows 内存凭据提取(明文密码)

**用途**:利用 Windows 管理员权限从 lsass 进程内存与其他位置提取当前登录用户的明文密码、NTLM 哈希、票据、DPAPI 数据;亦可用于 dcsync 导出域哈希。
**安装**:`sudo apt install mimikatz`(包内为 Windows PE 二进制,拷贝到目标执行,或在本机以 wine 运行)
**使用场景**:已在 Windows 目标拿到管理员/SYSTEM 且可执行二进制时,优先于猜测式破解——直接读明文。

```text
# 以下在 Windows 目标的 mimikatz 控制台内执行
privilege::debug
token::elevate
sekurlsa::logonpasswords        # 提取 lsass 中的明文/NTLM
lsadump::sam                    # 本机 SAM 哈希
lsadump::dcsync /domain:<domain> /user:krbtgt    # 域控同步导出 krbtgt
```

**实战要点**:
- 需要 `Privilege '20' OK` 输出;被杀软拦截时常见替代路径为 procdump 转储 lsass 后离线用 pypykatz/mimikatz 解析。
- Windows 8.1+ 默认配置下明文(Wdigest)多为空,但 NTLM/Kerberos 票据仍可提取用于哈希传递。
- Kali 包版本可能落后于官方 GitHub 版,实战以目标兼容性为准;域环境优先 `lsadump::dcsync`。

### fcrackzip — Zip 压缩包口令破解

**用途**:针对传统 ZipCrypto 加密的 zip 文件做字典/暴力破解,部分汇编实现速度快,可用 unzip 复核结果。
**安装**:`sudo apt install fcrackzip`
**使用场景**:CTF 与取证中遇到口令保护的 .zip;先确认是 ZipCrypto 而非 AES。

```bash
# 字典模式(-D)并用 unzip 验证(-u 过滤误报)
fcrackzip -u -D -p <wordlist> <file>.zip

# 暴力模式:小写+数字,长度 4-8
fcrackzip -b -c a1 -l 4-8 -u <file>.zip
```

**实战要点**:
- `-u` 必加:ZipCrypto 假阳性率高,不加会输出大量错误密码。
- AES 加密 zip(由 WinZip/7-Zip 新版创建)本工具不支持,改走 `zip2john` + john 或 hashcat -m 13600(WinZip)/17200 系(PKZIP)。
- 判别加密类型:`zipinfo <file>.zip` 看 "file encrypted" 类型,或 7z 提示 "AES-256"。

### truecrack — TrueCrypt 卷口令暴力破解

**用途**:针对 TrueCrypt 卷(CUDA 优化)的口令破解,支持 RIPEMD160/SHA512/Whirlpool KDF(PBKDF2)+ XTS/AES。
**安装**:`sudo apt install truecrack`
**使用场景**:拿到 TrueCrypt 加密卷文件且具备 NVIDIA GPU 时。

```bash
# 官网示例结构:卷文件 + KDF + 字典
truecrack -t <volume> -k ripemd160 -w <wordlist>
```

**实战要点**:
- `-k` 可选 `ripemd160`/`sha512`/`whirlpool`,与建卷时选择一致才能命中,可依次尝试。
- VeraCrypt 卷不适用(KDF 迭代高 1000 倍量级),改用 hashcat -m 137xx 系列,且预期极慢。
- 无 GPU 时同样场景可用 john 的 `truecrypt` 格式。

### ophcrack-cli — 彩虹表秒查 Windows 密码(命令行)

**用途**:基于彩虹表(时空折衷)的 Windows 密码破解,官方表宣称秒级解出 99.9% 字母数字口令;CLI 版供脚本/无桌面环境使用。
**安装**:`sudo apt install ophcrack-cli`
**使用场景**:有现成彩虹表(需另行下载,GB~数十 GB)时的 NT 哈希快速查表;LM 时代口令效果最佳。

```bash
# 哈希文件 + 表目录 + 表集名(表集名如 xp_free_fast、vista_free)
ophcrack-cli -f <hashfile> -d /path/to/tables -t <tableset>
```

**实战要点**:
- 表集需与目标口令构成匹配(纯字母数字小表、含符号大表),表未覆盖的空间照样解不出。
- 现代 Windows 无 LM 哈希、口令复杂度高时,价值远低于 hashcat 字典+规则,优先级放后。
- 表目录可放移动盘;`-t` 的表名与下载的表目录名一致。

### rcrack — RainbowCrack 彩虹表哈希破解

**用途**:经典时间-空间折衷实现,用预生成的彩虹表(.rt/.rtc 等)查表破解哈希,区别于逐条暴力。
**安装**:`sudo apt install rainbowcrack`
**使用场景**:已持有(或用 rtgen/rtsort 自生成)彩虹表,对固定字符集空间做可重复快速查询。

```bash
# 单条哈希查表(-h)
rcrack /path/to/tables/*.rt -h <hash>

# 哈希列表文件(-l)
rcrack /path/to/tables/*.rt -l <hashfile>
```

**实战要点**:
- 查表前表必须已排序(rtsort);表文件格式(rt/rti/rtc)要与工具版本匹配。
- 自建表流程 `rtgen`(生成)→ `rtsort`(排序)→ `rcrack`(查询),成本高,仅高频复用场景划算。
- 新哈希类型支持有限,现代算法优先 hashcat。

### sipcrack — SIP 摘要认证提取与破解(VoIP)

**用途**:从 pcap 或 SIP 信令中提取 digest 认证的挑战/响应(sipdump),再对账号做离线字典破解(sipcrack)。
**安装**:`sudo apt install sipcrack`
**使用场景**:VoIP 渗透中抓到注册/INVITE 的 SIP digest 认证流量后的口令恢复。

```bash
# 从抓包提取登录挑战响应到文件
sipdump -p <capture>.pcap sip-logins.txt

# 用字典离线破解
sipcrack -w <wordlist> sip-logins.txt
```

**实战要点**:
- 只对使用弱口令的 digest 账号有效;提取不到条目多为抓包不含完整 401/200 交互。
- 破出的分机口令可直接用于注册劫持/话费盗打验证(在授权范围内)。
- 与 Wireshark 过滤 `sip` 配合先确认 pcap 中存在 `Authorization` 头。

### sucrack — 本地 su 多线程爆破(提权辅助)

**用途**:在已有低权 shell 的 Linux/Unix 主机上,通过多线程 + 伪终端 su 尝试爆破其他用户(通常是 root)密码。
**安装**:`sudo apt install sucrack`
**使用场景**:拿到低权限 shell、su 可用但无交互终端支持脚本时,爆破 root 口令提权。

```bash
# 指定并行线程数与字典
sucrack -w 10 <wordlist>
```

**实战要点**:
- su 需要 TTY,普通脚本/管道难以实现,这正是该工具存在的意义;经 reverse shell 使用前确认 shell 支持伪终端。
- 失败尝试会写 auth.log,痕迹明显;授权测试中注意日志清理约定与锁定策略。
- 先试 `hydra -e nsr` 同思路:`root/root`、`root/toor` 类弱口令人工几条往往已够。

### thc-pptp-bruter — PPTP VPN 网关高速爆破

**用途**:对 PPTP VPN 端点(TCP 1723)的暴力破解,支持 MSChapV2;利用微软防爆破实现的缺陷可达约 300 次/秒。
**安装**:`sudo apt install thc-pptp-bruter`
**使用场景**:目标暴露 PPTP VPN(老旧网关常见)时的凭据测试;速度远超通用工具。

```bash
# 默认用户 administrator,stdin 或 -w 供字典
thc-pptp-bruter -u administrator -w <wordlist> <ip>
```

**实战要点**:
- 帮助信息:`-u` 用户、`-w` 字典文件(默认 stdin)、`-p` 端口、`-n` 并行数、`-v` 调试、`-W` 禁用 Windows 反爆破缺陷利用(对非 Windows 网关如 Cisco 可先加 `-W`)。
- PPTP 协议本身已被破解(MSChapv2 可离线还原),报告中应同时建议淘汰 PPTP。

### legba — Rust 异步多协议爆破/喷洒器

**用途**:Rust + Tokio 实现的多协议凭据爆破、密码喷洒与枚举工具,资源占用低于同类;插件化,支持 YAML recipe 复用配置。
**安装**:`sudo apt install legba`
**使用场景**:作为 hydra 的现代替代,长时运行/低内存受限环境,或需要复用标准化"配方"的批量测试。

```bash
# 列出全部协议插件
legba -L

# 插件式调用(以 legba <plugin> -h 查看该插件完整参数)
legba ssh --target <ip> --username <user> --password <wordlist>
```

**实战要点**:
- 子命令即插件名,`-L` 先确认插件存在与命名(与 hydra 模块名不完全一致)。
- `-R/--recipe` 加载 YAML 配置,适合周期性回归测试场景。
- 新工具生态尚在演进,关键任务前先小样本验证判定逻辑。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| creddump7 | 从 Windows 注册表 hive 提取凭据/密钥(pwdump/lsadump/cachedump) | creddump7 | `python /usr/share/creddump7/pwdump.py <SYSTEM> <SAM>` |
| cmospwd | 解密 CMOS 中存储的 BIOS 设置密码 | cmospwd | `sudo cmospwd` |
| eapmd5pass | 提取并离线破解 802.1X EAP-MD5 认证 | eapmd5pass | `eapmd5pass -r <capture>.pcap -w <wordlist>` |
| freeradius | RADIUS 服务器;freeradius-utils 提供凭据测试用的 radtest/radclient | freeradius-utils | `radtest <user> <pass> <server> 0 <secret>` |
| gitxray | 扫描 GitHub 仓库/贡献者/组织收集 OSINT 信息 | gitxray | `gitxray -r <owner>/<repo>` |
| hydra-gtk | hydra 的 GTK 图形前端 | hydra-gtk | `hydra-gtk` |
| johnny | John the Ripper 的跨平台 GUI | johnny | `johnny` |
| mifare-classic-format | Mifare Classic RFID 卡密钥恢复工具集(mfcuk 等) | mfcuk | `mfcuk -C -R 0:A -v 2` |
| ophcrack | Windows 密码彩虹表破解(GUI 版) | ophcrack | `ophcrack` |
| rcracki_mt | RainbowCrack 多线程/混合表变体 | rainbowcrack | `rcracki_mt <tables>/*.rti -h <hash>` |
| sqldict | SQL Server 字典攻击(Windows 程序,需 wine32) | sqldict | `dpkg --add-architecture i386 && apt update && apt -y install wine32` |
| trufflehog | 深挖 git 历史与分支中误提交的密钥/凭据 | trufflehog | `trufflehog git https://github.com/<org>/<repo> --only-verified` |
| twofi | 按关键词抓取 Twitter 高频词生成定制字典 | twofi | `twofi -t <keyword1,keyword2>` |
| xspy | 嗅探本地/远程 X server 键盘输入 | xspy | `xspy` |

> 本文件全部命令仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教学场景。
