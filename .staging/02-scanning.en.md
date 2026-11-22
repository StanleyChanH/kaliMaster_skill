# Network & Vulnerability Scanning

> **When to read this file**: Read this file after the target scope has been determined and you need host discovery, port/service scanning (nmap/masscan), automated reconnaissance (autorecon), service enumeration (SMB/SNMP/SMTP), SSL/TLS auditing, or systematic vulnerability scanning (GVM/OpenVAS); for how scan results lead into exploitation, see the "Scan Results → Handoff to Exploitation" section. Template-based web vulnerability scanning (nuclei) is covered in `03-web-testing.md`.

## Quick Decision Table

| Task scenario | First choice | Alternatives | Key difference |
|---|---|---|---|
| High-speed full-port scan | masscan | nmap `-T5`, unicornscan | masscan has the highest rate; nmap yields the most complete results |
| In-depth single-target identification (version/OS/NSE) | nmap `-sV -A` | autorecon | nmap gives manual fine-grained control; autorecon runs the full suite in one shot |
| Large network range, "find ports first, then examine closely" | masscan + nmap split | autorecon -t <file> | masscan finds open ports; nmap -sV scans only the hits |
| Full-workflow enumeration of a single host (CTF/OSCP) | autorecon | legion (GUI) | autorecon outputs structured directories and is reproducible from the CLI |
| Windows/Samba information enumeration | enum4linux-ng | enum4linux, nbtscan | ng supports JSON output/credentials/Kerberos |
| SNMP enumeration | snmp-check | onesixtyone (community string guessing), braa (large scale) | snmp-check has the most readable output |
| SMTP user enumeration | smtp-user-enum | swaks (interactive testing), mxcheck (surface check) | smtp-user-enum does batch VRFY/EXPN |
| SSL/TLS configuration audit | sslscan | sslyze, tlssled | sslscan is fast; sslyze gives detailed reports; tlssled is a long-standing wrapper |
| WAF identification | wafw00f | nmap `--script http-waf-fingerprint` | wafw00f has a specialized fingerprint database |
| Systematic CVE vulnerability scanning | gvm (Greenbone/OpenVAS) | nmap `--script vuln` | GVM works from a full vulnerability database; nmap does rapid spot checks |
| IPsec VPN (IKE) discovery | ike-scan | nmap -sU -p 500,4500 | ike-scan fingerprints vendors and captures PSK hashes |
| Oracle TNS (1521) enumeration | tnscmd10g | sidguess, oscanner | tnscmd10g probes versions/sidguess guesses SIDs/oscanner tests passwords |
| Apache user directory enumeration | apache-users | nmap `--script http-userdir-enum` | Same functionality; the NSE route integrates more easily |
| IPv6 host discovery | thc-ipv6 suite (alive6) | nmap -6 | alive6 leverages ICMPv6 for link-local alive checks |
| SCTP scanning | sctpscan | nmap -sY | SCTP is a protocol specific to telecom/signaling scenarios |
| Periodic comparison of scan results | ndiff | grep -oG output | ndiff is purpose-built for diffing nmap XML |

## Scan Results → Handoff to Exploitation

The outputs of the scanning phase (open ports, service versions, username lists, SNMP community strings, PSK hashes, CVE lists) are direct inputs to subsequent exploitation:

| Scan finding | Resulting next step |
|---|---|
| Products and versions from `nmap -sV` | `searchsploit <product> <version>`, MSF `search` for public exploits; on a hit, move to the matching exploitation volume |
| 445/tcp open with a `smb-vuln-ms17-010` hit | MS17-010 (EternalBlue) exploitation chain |
| SMB null session enumeration possible (enum4linux) | user/share lists → `smbclient` to dig into share contents; username list for credential spraying |
| Valid SNMP community string | `snmp-check` full enumeration → routing table/interfaces/processes to reconstruct internal network topology and running services |
| SMTP VRFY/EXPN confirms users | username list → password spraying and pre-phishing intelligence |
| sslscan/sslyze reports heartbleed/weak ciphers/old protocols | run the matching public PoCs to verify; merge certificate CN/SAN into the subdomain asset inventory |
| 1521/tcp TNS open | tnscmd10g status → sidguess to guess the SID → oscanner/sqlplus (database volume) |
| 500/4500/udp IKE answers in Aggressive Mode | `ike-scan -A -P` captures the PSK hash → `psk-crack` offline cracking → gain VPN access |
| CVEs reported by GVM | prioritize verifying entries that have public exploits; note that scanner false positives require manual confirmation |
| WAF detected by `wafw00f` | adjust the web attack strategy (encoding obfuscation/chunked transfer/direct-to-origin) |
| autorecon's results directory | dig into each scans/ output following the matching volume (HTTP/SQL/SMB, etc.) |
| XML archived by nmap `-oA` | `ndiff` periodic comparison to catch new ports; import into other tools for reuse |

## Core Tools in Depth

### nmap — the de facto standard for network scanning: host discovery, port scanning, version/OS detection, NSE scripts

**Purpose**: Host alive checks, a dozen-plus port scanning techniques (SYN/Connect/UDP/ACK, etc.), service version detection (`-sV`), OS fingerprinting (`-O`), and the NSE script engine (categories such as vuln/auth/brute/exploit, hundreds of scripts). The most frequently used scanner in penetration testing.
**Installation**: Preinstalled on Kali by default (`nmap` package, includes ncat/nping/ndiff).
**When to use**: Any situation where you need to "know what the target has open, what versions are running, and which known vulnerabilities exist"; irreplaceable when you need precise control over scan behavior (timing/fragmentation/decoys).

```bash
# 官网模式:详细输出 + OS/版本/NSE/traceroute 全开
nmap -v -A -sV <target>

# 主机发现(ping 扫描,不扫端口)
nmap -sn 192.168.1.0/24

# 快速扫描 Top 100 端口
nmap -T4 -F <target>

# 全 65535 TCP 端口 SYN 扫描,高速率
sudo nmap -sS -p- --min-rate 10000 -T4 -v --open <target>

# UDP 关键端口(UDP 扫描慢,只挑 top 100)
sudo nmap -sU --top-ports 100 --open -v <target>

# 对已发现端口做服务版本 + OS + 默认脚本精查
sudo nmap -sV -O -sC -p <ports> <target>

# 从文件读目标,排除特定地址
nmap -iL <target-file> --exclude <ip>
```

The NSE script engine (common patterns):

```bash
# SMB 经典漏洞点名(MS17-010 等)
nmap --script smb-vuln* -p 139,445 <target>

# 对已知端口跑全部 vuln 分类脚本
nmap --script vuln -p <ports> <target>

# HTTP 目录/标题/漏洞
nmap --script http-enum,http-title,http-vuln* -p 80,443 <target>

# TLS 经典漏洞
nmap --script ssl-heartbleed,ssl-poodle -p 443 <target>

# 匿名 FTP 检测
nmap --script ftp-anon -p 21 <target>

# 组合表达式:safe 且 discovery
nmap --script "safe and discovery" -p <ports> <target>

# 爆破脚本指定用户/密码字典
nmap --script ssh-brute --script-args userdb=<userlist>,passdb=<wordlist> -p 22 <target>

# 更新 NSE 脚本库
nmap --script-updatedb
```

Timing templates `-T0` ~ `-T5`:

```bash
# -T0 paranoid 极慢(IDS 规避) | -T1 sneaky 慢速隐蔽
# -T2 polite 降速礼让 | -T3 normal 默认
# -T4 aggressive 局域网推荐 | -T5 insane 最快、可能漏报端口
nmap -T4 -sV -p <ports> <target>
```

Output formats:

```bash
# 三种格式同时输出:txt(XML 给 ndiff/工具导入,greppable 给 grep)
nmap -sV -p <ports> -oA <output-prefix> <target>

# grepable 输出快速提取开放端口
nmap -p- --open -oG - <target> | grep "/open/"
```

**Practical tips**:
- Standard three-step rhythm: `-sn` first to confirm alive hosts → then `-p-` for all ports → finally `-sV -sC` for close inspection of the open ports; an order of magnitude faster than running `-A` across all ports directly
- A `filtered` state mostly means firewall interception; `-Pn` skips host discovery and forces the scan (a must when the target blocks ping)
- Version numbers from `-sV` are direct input to `searchsploit`; the more accurate version detection is (raise `--version-intensity`), the more accurate the later exploitation
- Always archive with `-oA`: the XML feeds `ndiff` and automation tools; `-v` surfaces findings in real time and avoids long blind waits

### masscan — asynchronous SYN mass port scanner

**Purpose**: Scans large address ranges at extremely high packet rates (tens of thousands of packets/s on internal networks), producing nmap-like open port results. Suited to full-port/first-pass scans of large ranges.
**Installation**: `sudo apt install masscan`.
**When to use**: With many targets or when all 65535 ports are needed, run masscan first to find open ports, then hand them to nmap for version identification; for a single small-scope target, just use nmap directly.

```bash
# 官网模式:子网多端口 SYN 扫描
sudo masscan -p22,80,445 192.168.1.0/24

# 大地址段高速率(授权范围内)
sudo masscan -p80,443 10.0.0.0/8 --rate=10000

# 全端口 + 抓 banner,XML 落盘
sudo masscan -p0-65535 <target> --rate=1000 --banners --output-format xml --output-filename <file>

# 排除特定地址、绑定网卡
sudo masscan -p443 192.168.0.0/16 --exclude 192.168.0.1 --adapter eth0

# 导出/复用配置
sudo masscan -p80 <target> --rate=1000 --echo > <conf-file>
sudo masscan --conf <conf-file>
```

**Practical tips**:
- Set `--rate` by bandwidth: on gigabit internal networks start around 10000; the rule of thumb is bandwidth/8/64; exceeding it drops packets and causes false negatives
- masscan only answers "is the port open" and does no service identification; on a hit, pass the port list to `nmap -sV -p<ports> --open` for deeper digging
- `--banners` works only for some protocols and slows scanning noticeably; for complete fingerprints, still hand off to nmap
- Its option style deliberately stays nmap-compatible (`-p`, `--open-only`, `--exclude`, etc.), easing pipeline-style division of labor

### unicornscan — userspace asynchronous TCP/IP information gathering engine

**Purpose**: A userspace distributed TCP/IP stack, asynchronous packet sending + a correlation engine, for high-speed port/protocol scanning.
**Installation**: `sudo apt install unicornscan`.
**When to use**: An asynchronous high-speed scanner in the same class as masscan; the alternative when you need fine control over mode flags and rates.

```bash
# 官网模式:TCP SYN+FIN 标记扫描全部 65535 端口,1000 packets/s
sudo unicornscan -mTsf -Iv -r 1000 <target>:a

# UDP 模式扫指定端口
sudo unicornscan -mU -p 161,500 <target>
```

**Practical tips**:
- Syntax essentials: `:a` = all 65535 ports; `-r 1000` = 1000 packets per second; `-Iv` = print results immediately
- `-mT` is TCP scan mode, followed by flag letter combinations (e.g., `sf` = SYN+FIN)
- Its role overlaps with masscan: it handles "quickly finding open ports", while service identification still goes to `nmap -sV`

### autorecon — multithreaded automated network reconnaissance (first choice for CTF/OSCP)

**Purpose**: Automatically runs port scans against the target plus large numbers of enumeration plugins concurrently by service type (HTTP/SMB/SNMP/SMTP, etc.), outputting a structured results directory.
**Installation**: `sudo apt install autorecon`.
**When to use**: When you want to "set it running unattended for broad surface coverage" against one or a few targets (CTF, the OSCP exam, authorized single-host assessments); large-scale network ranges suit masscan plus scripted division of labor better.

```bash
# 单目标全自动侦察(需 root 跑全部插件)
sudo autorecon <ip>

# 多目标混合(单 IP 与网段可混写)
sudo autorecon <ip1> 192.168.1.0/24 <ip2>

# 从目标文件批量跑
sudo autorecon -t <target-file>

# 只跑指定标签插件,限制并发扫描数
sudo autorecon <ip> --tags discovery -m 4

# 剔除危险标签
sudo autorecon <ip> --exclude-tags dos
```

**Practical tips**:
- Results are written to `./results/<ip>/` by default: one output file per plugin under `scans/`, and `_commands.log` records every executed command (pull them out directly for manual replay or parameter-tweaked re-runs)
- The usage pattern is "autorecon for broad coverage first, then manual deep dives into suspicious services"; do not rely only on its summary
- `-m` (max concurrent scans)/`-mp` (port scan concurrency) control the load; lower them when targets are numerous to avoid knocking over fragile services
- For each service type it calls exactly the tools covered in this volume (nmap/enum4linux/snmpcheck, etc.), so output formats stay mutually consistent

### gvm — the Greenbone vulnerability management platform (formerly OpenVAS)

**Purpose**: An enterprise-grade vulnerability scanning framework that runs authenticated and unauthenticated scans against complete CVE/NVT/SCAP databases and produces structured vulnerability reports.
**Installation**: `sudo apt install gvm` (not a Kali default).
**When to use**: When you need systematic CVE scanning and reporting (rather than nmap script-style quick spot checks); create tasks in the web UI, automate through the CLI.

```bash
# 首次初始化:下载 NVT/SCAP/GVM 漏洞库(耗时较长)
sudo gvm-setup

# 环境自检
sudo gvm-check-setup

# 启动/停止服务
sudo gvm-start
sudo gvm-stop

# 更新漏洞库
sudo gvm-feed-update

# GVM CLI(管理端口 9390,账号密码在 setup 输出中)
gvm-cli tls --hostname 127.0.0.1 --port 9390 --username admin --password <password> --xml "<get_version/>"
```

**Practical tips**:
- Once the service is up, open the Greenbone Security Assistant in a browser: `https://127.0.0.1:9392` (self-signed certificate, ignore the warning); the initial admin password is in the `gvm-setup` output
- Task creation flow: Configuration → Targets (can carry credentials for authenticated scans) → Scan Configs, pick "Full and fast" → Tasks, create and launch
- The scanner produces false positives: manually verify the versions behind reported CVEs first, then validate entries with public exploits through `searchsploit`/MSF
- Complements nmap `--script vuln`: GVM covers broadly and produces reports; nmap is fast and embeds into recon workflows

### enum4linux — Windows/Samba information enumeration (the classic)

**Purpose**: Wraps smbclient/rpcclient/net/nmblookup to enumerate Windows/Samba users, groups, shares, password policy, and OS information.
**Installation**: `sudo apt install enum4linux`.
**When to use**: The first round of SMB information gathering when the target exposes 139/445 and allows null sessions; works best on legacy environments (Samba 3/XP/2003).

```bash
# 官网模式:枚举用户列表 + OS 信息
enum4linux -U -o <ip>

# 全量简单枚举(用户/组/共享/密码策略等)
enum4linux -a <ip>

# 带凭证枚举(空会话被禁时)
enum4linux -a -u <user> -p <pass> <ip>
```

**Practical tips**:
- The `-P` password policy output (lockout threshold/minimum length) directly sets the pacing parameters for later credential spraying
- Share list → dig through writable shares one by one with `smbclient`; user list → the credential attacks volume
- Frequently fails against modern Windows (SMBv3/signing enforced) with RPC_S_ACCESS_DENIED; switch to enum4linux-ng or retry with credentials
- The output is verbose; focus on the three parts: `[+] Got domain/workgroup name`, the user list, and the share enumeration

### enum4linux-ng — next-generation Windows/Samba enumeration (recommended)

**Purpose**: A rewrite of enum4linux that adds JSON/YAML export, Kerberos ticket/NTLM authentication, and per-item success markers.
**Installation**: `sudo apt install enum4linux-ng`.
**When to use**: Prefer ng by default; it is a must when you need machine-readable output or enumeration with credentials in domain environments.

```bash
# 全量枚举(-A 等价旧版全套)
enum4linux-ng -A <ip>

# JSON 输出,便于程序化处理
enum4linux-ng -A -oJ <output>.json <ip>

# 带凭证 + 本地认证(针对本地账户而非域账户)
enum4linux-ng -A -u <user> -p <pass> --local-auth <ip>

# Kerberos 票据 / NTLM Hash 认证
enum4linux-ng -A -K <ticket-file> <ip>
enum4linux-ng -A -H <nthash> <ip>
```

**Practical tips**:
- The output marks each enumeration item with its success/failure reason (e.g., "5xx ACCESS_DENIED"), making it easier than the classic version to tell which layer blocked you
- The `-oJ` JSON can be consumed directly by automation pipelines; the user+group+password policy trio is direct input to credential attacks
- In domain environments prefer domain credentials (omit `--local-auth`); add it only for local accounts

### nbtscan — NetBIOS name table subnet scanner

**Purpose**: Sends NetBIOS status queries across an IP range, returning IP, NetBIOS computer name, logged-on username, and MAC.
**Installation**: `sudo apt install nbtscan`.
**When to use**: Quickly mapping out Windows hosts and currently logged-on users on an internal network; far lighter than full SMB enumeration.

```bash
# 扫描整个网段的 NetBIOS 名称表
sudo nbtscan -r 192.168.1.0/24

# 单目标详细输出
nbtscan -v <ip>
```

**Practical tips**:
- Name suffix meanings: `<03>` messenger service (often exposes the current logged-on username), `<20>` file sharing service (worth an enum4linux deep dive), `<1B>` domain controller
- The output directly yields a "hostname → username" mapping — targeting input for internal lateral movement
- Relies solely on NetBIOS (UDP 137); modern Windows with NetBIOS over TCP/IP disabled gives no response

### snmp-check — SNMP device enumeration (human-readable output)

**Purpose**: Similar to snmpwalk but with output formatted into sections: system information, network interfaces, IPs, routing table, TCP/UDP listening ports, processes, mount points, software, and more.
**Installation**: `sudo apt install snmpcheck` (binary command name snmp-check).
**When to use**: Full information extraction once 161/udp is confirmed open and a community string is in hand; the output can go straight into a report.

```bash
# 官网模式:public 社区串枚举
snmp-check <ip> -c public

# 检查社区串是否具有写权限
snmp-check <ip> -c <community> -w
```

**Practical tips**:
- The routing table and interface table are first-hand material for reconstructing the internal topology; the process list often exposes running security software (a basis for bypass planning)
- If `-w` reports writable: on legacy devices you can change configuration or even trigger RCE — a high-severity finding
- The output contains the system description (sysDescr), i.e., the OS/kernel version → pass it to `searchsploit`

### onesixtyone — extremely fast SNMP community string guesser

**Purpose**: Sends SNMPv1/2c requests asynchronously to guess community strings; an entire class-C range takes only seconds.
**Installation**: `sudo apt install onesixtyone`.
**When to use**: When 161/udp is open but the community string is unknown; on a hit, dig deeper with snmp-check/snmpwalk.

```bash
# 字典爆破社区串(主机列表 + 社区串列表)
onesixtyone -c <community-wordlist> -i <target-file>

# 单目标
onesixtyone -c <community-wordlist> <ip>
```

**Practical tips**:
- Put the common defaults first in the candidate wordlist: public/private/cisco/management names; the Seclists SNMP directory ships ready-made wordlists
- Confirm authorization and thresholds before running against a range: high-rate UDP packets can strain legacy devices
- A hit prints like `192.168.1.2 [public] Linux ...`; record the community string in your documentation for reuse in every later SNMP operation

### braa — single-process mass SNMP scanner

**Purpose**: Ships its own SNMP stack (no net-snmp dependency) and queries dozens to hundreds of hosts concurrently in a single process, for batch-validating community strings or fetching specified OIDs.
**Installation**: `sudo apt install braa`.
**When to use**: When you already hold a community string and want to batch-query the same OID (sysName/interface table, etc.) across a whole range; keep using snmp-check for single-target deep dives.

```bash
# 官网模式:单目标遍历 .1.3.6 整棵树
braa public@<ip>:.1.3.6.*

# 地址段批量取 sysName(OID .1.3.6.1.2.1.1.5.0)
braa <community>@<start-ip>-<end-ip>:.1.3.6.1.2.1.1.5.0
```

**Practical tips**:
- Syntax is `[community@]host[:oid]`; the `*` wildcard performs a walk; address ranges are joined with `-` (CIDR notation is not supported)
- Output format is `host:elapsed:oid:value`, well suited to grep/pipeline post-processing
- The protocol implementation is "non-standard" and individual devices may not respond; fall back to snmpwalk when things go wrong

### smtp-user-enum — SMTP username enumeration (VRFY/EXPN/RCPT)

**Purpose**: Leverages the three SMTP mechanisms VRFY, EXPN, and RCPT TO to guess/verify whether usernames exist.
**Installation**: `sudo apt install smtp-user-enum`.
**When to use**: When 25/587 are open and the MTA has not disabled these commands, quickly producing a valid username list.

```bash
# 官网模式:VRFY 验证单用户
smtp-user-enum -M VRFY -u root -t <ip>

# 字典批量 EXPN(EXPN 还能展开邮件列表)
smtp-user-enum -M EXPN -U <userlist> -t <ip>

# RCPT 模式(VRFY/EXPN 被禁时尝试;需伪造发件人地址)
smtp-user-enum -M RCPT -U <userlist> -t <ip> -f <from-addr>

# 指定非默认端口(如 587)
smtp-user-enum -M VRFY -U <userlist> -t <ip> -p 587
```

**Practical tips**:
- A hit prints `192.168.1.25: root exists`; distinguish "exists" (the user is present) from a rejection (not present/disabled)
- The username list feeds password spraying and phishing groundwork; cross-check it first against mxcheck's VRFY disclosure detection
- Modern MTAs often rate-limit or return 252 for every VRFY; on failure switch to EXPN, then RCPT; if all are disabled, move to web-side enumeration

### swaks — the Swiss Army knife for SMTP (interactive command-line testing)

**Purpose**: Builds a complete SMTP conversation from the command line, supports STARTTLS and several AUTH methods (PLAIN/LOGIN/CRAM-MD5, etc.), and can break off at any stage.
**Installation**: `sudo apt install swaks`.
**When to use**: Verifying open relay, testing authentication and relay rules, and working through SMTP protections stage by stage; replaces typing `telnet <host> 25` over and over.

```bash
# 基本发送测试
swaks --to <addr> --from <addr> --server <smtp-host>

# 开放中继判定:向外部地址 RCPT,到 RCPT 即停不真正发信
swaks --to <external-addr> --server <smtp-host> --quit-after RCPT

# STARTTLS + 认证测试
swaks --tls --auth PLAIN --auth-user <user> --auth-password <pass> --to <addr> --server <smtp-host>

# 自定义主题与正文
swaks --to <addr> --server <smtp-host> --header "Subject: test" --body "test"
```

**Practical tips**:
- For the relay verdict, check whether the final RCPT returns 250 (accept): an accept means an open relay — high severity
- `--quit-after <stage>` (HELO/MAIL/RCPT/DATA, etc.) pinpoints the stage where rejection begins, and along the way profiles the protection devices' behavior
- Chained with smtp-user-enum: verify RCPT and authentication for each enumerated username with swaks

### mxcheck — mail server information and security checkup

**Purpose**: One-stop checks for a mail domain: A/MX/PTR/SPF/MTA-STS/DKIM/DMARC, ASN, StartTLS and certificates, ports 25/465/587, blacklists, VRFY information disclosure, and open relay.
**Installation**: `sudo apt install mxcheck`.
**When to use**: A surface check of a domain's mail infrastructure, quickly producing a mail security overview.

```bash
# 域名邮件安全体检(自动解析 MX 后逐项检查)
mxcheck --domain <domain>
```

**Practical tips**:
- Runs DNS record compliance, TLS configuration, and blacklist checks in one pass; a ready skeleton for the mail section of a report
- Re-verify any flagged VRFY disclosure/open relay interactively with swaks to avoid single-tool misjudgment
- SPF `+all`/DMARC `p=none` are configuration flaws that can go straight into the report

### sslscan — fast SSL/TLS cipher and certificate probing

**Purpose**: Probes the protocol versions, cipher suites, key exchange, signature algorithms, and certificate details a target supports, flags weaknesses, and can output XML.
**Installation**: `sudo apt install sslscan`.
**When to use**: Fast configuration audits of any TLS service such as HTTPS/SMTPS; the first choice for batch checks.

```bash
# 目标 TLS 全套件探测
sslscan <host>:443

# 全 TLS 版本 + 显示完整证书
sslscan --tlsall --show-certificate <host>:<port>

# 只显示被接受的套件,XML 落盘供程序处理
sslscan --no-failed --xml=<file> <host>:443

# 明文升级协议(STARTTLS)
sslscan --starttls=smtp <host>:25
```

**Practical tips**:
- The output directly highlights deprecated protocols (SSLv2/v3, TLS 1.0/1.1) and weak suites (NULL/EXPORT/RC4/3DES) in red; just write them into the report line by line
- Fold the certificate CN/SAN fields into the subdomain asset inventory along the way
- It only checks the configuration layer; for vulnerabilities requiring deep handshake interaction such as heartbleed, supplement with nmap NSE or sslyze

### sslyze — fast and comprehensive SSL/TLS scanner

**Purpose**: Plugin-based analysis of server SSL configuration: certificate chain validation, compression (CRIME), renegotiation (CVE-2009-3555), session resumption, per-protocol cipher suite matrices, with JSON output support.
**Installation**: `sudo apt install sslyze`.
**When to use**: When you need finer reports than sslscan (certificate chain/renegotiation/session) or automated comparison.

```bash
# 常规全项扫描:直接指定目标即默认全扫
sslyze <host>:443

# 明文升级协议
sslyze --starttls=smtp <host>:25

# JSON 报告
sslyze --json_out=<file> <host>:443
```

**Practical tips**:
- Detecting "client-initiated renegotiation" means the renegotiation vulnerability, which can feed a DoS attack-surface assessment
- `--json_out` makes pipeline-based periodic scanning and differential alerting easy
- Either sslyze or sslscan covers routine TLS auditing; add nmap `--script ssl-heartbleed` to dig into an individual vulnerability (heartbleed, etc.)

### tlssled — SSL/TLS server security assessment wrapper script

**Purpose**: A shell wrapper around sslscan and `openssl s_client`: checks SSLv2, NULL ciphers, weak 40/56-bit ciphers, MD5 certificates, and renegotiation, and auto-generates a report directory.
**Installation**: `sudo apt install tlssled`.
**When to use**: A long-standing one-shot assessment; for new projects, go straight to sslscan/sslyze.

```bash
# 官网模式:评估目标 SSL/TLS
tlssled <ip> 443
```

**Practical tips**:
- Automatically writes output into a `TLSSLed_<ver>_<ip>_<port>_<timestamp>/` directory for easy archiving
- The checks skew old (the SSLv2/MD5-certificate era); modern targets come back almost entirely green, so use it only as a quick screen

### ncat — the nmap suite's netcat implementation (connect/listen/forward)

**Purpose**: A netcat reimplementation that adds IPv6, SSL, access control (`--allow/--deny`), staying open across connections (`--keep-open`), and `--exec` command execution.
**Installation**: Preinstalled on Kali by default (ships with the nmap package).
**When to use**: Port connectivity verification, simple file transfer, listening reverse shells, and encrypted channels; common in post-exploitation.

```bash
# 官网模式:仅允许指定 IP 连接的 bash 监听,断开保持监听
ncat -v --exec "/bin/bash" --allow <ip> -l 4444 --keep-open

# 普通连接与端口连通测试
ncat -v <ip> <port>

# 简易文件传输(接收端/发送端)
ncat -l 9999 --recv-only > <file>
ncat --send-only <ip> 9999 < <file>

# 加密监听
ncat --ssl -l 4444
```

**Practical tips**:
- `--allow <ip>`/`--deny <ip>` act as a whitelist, more controllable than a bare netcat listener; `--keep-open` lets multiple connections reuse one listener
- A listener with `--exec`/`--sh-exec` is a minimal shell service; add `--ssl` and it becomes an encrypted channel
- Day-to-day connectivity troubleshooting: `ncat -vz <ip> <port>` quickly tells whether a port is reachable (the vz pair matches netcat habits)

### nping — the nmap suite's controllable packet generator (ping, upgraded)

**Purpose**: Generates ARP/TCP/UDP/ICMP/Ethernet frames and displays SENT/RCVD per packet, with control over flags, TTL, rate, and count.
**Installation**: Preinstalled on Kali by default (ships with the nmap package).
**When to use**: Precisely probing firewall allow rules, TTL trimming, and packet loss; protocol-level troubleshooting.

```bash
# 官网模式:SYN 探测 22 端口,TTL 设为 2(观测路径截断)
nping --tcp -p 22 --flags syn --ttl 2 <ip>

# ICMP 探活
nping --icmp -c 3 <ip>

# UDP 探测
nping --udp -p 53 <ip>

# 固定速率发包(压力与丢包观测)
nping --icmp --rate 100 -c 100 <ip>
```

**Practical tips**:
- Comparing SENT/RCVD packet by packet directly shows the difference between "sent, no reply" (dropped) and "RST/ICMP unreachable received" (explicitly denied) — the basis for judging firewall policy
- Incrementing `--ttl` roughly locates the hop where the filtering device sits
- Alive check priority: nmap -sn → if that fails, nping for fine-grained control

### ndiff — nmap scan result comparison tool

**Purpose**: Compares two nmap XML outputs, flagging hosts going up/down and ports opening/closing.
**Installation**: Preinstalled on Kali by default (ships with the nmap package).
**When to use**: Periodic scan monitoring and quickly spotting new services during incident response.

```bash
# 官网模式:对比两次扫描
ndiff <old-scan>.xml <new-scan>.xml

# 机器可读 XML 输出
ndiff --xml <old-scan>.xml <new-scan>.xml
```

**Practical tips**:
- Input must be XML produced by `nmap -oX`/`-oA`; `-` can substitute for standard input
- The `-`/`+` prefixes mark gone/newly added respectively; newly open ports get priority review
- Archive baseline scans with `-oA`; after an incident, rescan with the same parameters and diff

### zenmap — the official nmap GUI frontend

**Purpose**: A graphical nmap: preset scan profiles, result comparison, and topology graphs.
**Installation**: `sudo apt install zenmap` (not a Kali default).
**When to use**: GUI-leaning beginners or reporting scenarios that need topology visualization; command-line automation still revolves around nmap.

```bash
sudo zenmap
```

**Practical tips**:
- Preset profiles (Intense scan/Quick scan, etc.) are essentially nmap argument templates; view them in the UI and copy them out as command lines
- The Topology view builds on traceroute results, good for walking non-technical stakeholders through network paths
- Search/filter open ports in Results — more intuitive than scrolling back through a terminal

### ike-scan — IKE (IPsec VPN) discovery and fingerprinting tool

**Purpose**: Discovers IPsec VPN servers (UDP 500/4500) and fingerprints vendor versions from response and retransmission patterns; in Aggressive Mode it can capture PSK hashes that can be cracked offline.
**Installation**: `sudo apt install ike-scan`.
**When to use**: A must-run tool when perimeter testing finds 500/udp open.

```bash
# 发现 + 指纹(主模式,-M 多行显示单个握手)
sudo ike-scan -M <ip>

# 激进模式探测 + 抓 PSK 哈希落盘
sudo ike-scan -M -A -P <psk-file> <ip>

# 离线破解抓到的 PSK 哈希
psk-crack -d <wordlist> <psk-file>

# 观测重传 backoff 指纹
sudo ike-scan --showbackoff <ip>
```

**Practical tips**:
- Vendor ID strings in responses identify the vendor/version (e.g., Cisco/StrongSwan); look up known vulnerabilities from there
- Aggressive Mode is itself a finding (XAUTH/PSK hashes travel in plaintext and can be captured); pair it with `psk-crack` dictionary cracking; a hit yields VPN access credentials
- The file captured by `-P` must be processed by psk-crack shipped with the ike-scan suite (not an ordinary hashcat format)

### wafw00f — web application firewall detection and fingerprinting

**Purpose**: Sends malicious-signature payloads and observes response/behavior fingerprints to identify the WAF product sitting in front of the target (Cloudflare, ModSecurity, F5, etc.).
**Installation**: `sudo apt install wafw00f`.
**When to use**: A preliminary step in web penetration testing: first confirm whether a WAF exists and which type, then decide the exploitation strategy.

```bash
# 识别 WAF
wafw00f https://<domain>

# 跑全部检测方式
wafw00f -a https://<domain>

# 批量(空格分隔多个目标)
wafw00f https://<domain1> https://<domain2>
```

**Practical tips**:
- Output of `is behind WAF` means a hit and names the product; when there is no WAF it still prints a best-guess for reference
- Once a WAF is detected, adjust strategy: payload encoding/case obfuscation/chunked transfer/slow testing, or look for a direct-to-origin IP
- Cross-check with nmap `--script http-waf-fingerprint` to avoid single-fingerprint misjudgment

### tnscmd10g — Oracle TNS listener probing tool

**Purpose**: Sends commands (ping/version/status) to the Oracle TNS listener on 1521/tcp to obtain the version, running platform, listening endpoints, and other information.
**Installation**: `sudo apt install tnscmd10g`.
**When to use**: First-step information gathering after finding port 1521 open.

```bash
# 官网模式:读监听器版本(含平台信息)
tnscmd10g version -h <ip>

# 监听器状态(泄露监听端点、日志路径、启动参数等)
tnscmd10g status -h <ip>

# 非默认端口
tnscmd10g version -h <ip> -p <port>
```

**Practical tips**:
- The `version` output directly gives the Oracle and TNS version numbers → look up known listener vulnerabilities (e.g., TNS poisoning)
- The `status` output contains log file paths and service handles — a configuration information disclosure point
- Next-step handoff: sidguess to guess the SID → oscanner to test default passwords → sqlplus (database volume)

### sidguess — Oracle SID dictionary guessing

**Purpose**: Enumerates Oracle instance names (SIDs) against a dictionary at roughly 80-100 guesses per second.
**Installation**: `sudo apt install sidguesser` (command name sidguess).
**When to use**: After obtaining the TNS version, a valid SID must be known before connecting to the database.

```bash
# 官网模式:字典猜 SID
sidguess -i <ip> -d <wordlist>

# 非默认端口 + 结果报告 + 命中即停
sidguess -i <ip> -p <port> -d <wordlist> -r <report> -m findfirst
```

**Practical tips**:
- Common SID candidates: orcl, xe, prod, and words related to company/project names; Seclists has dedicated Oracle SID wordlists
- A hit SID is a prerequisite for connecting with oscanner/sqlplus; with multiple SIDs, feed each into the subsequent tools
- The low speed is a protocol trait; large wordlists need patience or parallel multi-instance runs split into segments

### oscanner — Oracle assessment framework

**Purpose**: An Oracle assessment framework written in Java: enumerates SIDs, tries default passwords, and presents results as a tree.
**Installation**: `sudo apt install oscanner`.
**When to use**: A round of default-credential and baseline assessment against Oracle once a SID is in hand.

```bash
# 官网模式:指定主机与端口评估
oscanner -s <ip> -P <port>
```

**Practical tips**:
- Feed in SIDs hit by sidguess first to raise the hit rate; it also tries common SIDs on its own
- Valid credentials found → `sqlplus <user>/<pass>@<ip>:<port>/<sid>` to go deeper (database volume)
- A rather old tool that often fails against recent Oracle versions; on failure, switch to a dedicated Oracle attack toolkit approach (manual enumeration)

### apache-users — Apache UserDir username enumeration

**Purpose**: Enumerates system usernames via the Apache UserDir module (personal directories in ~user form) and a dictionary.
**Installation**: `sudo apt install apache-users`.
**When to use**: Username collection when the target web service enables mod_userdir (`https://<host>/~<user>/`).

```bash
# 官网模式:字典枚举用户名(HTTP、403 判定不存在、10 线程)
apache-users -h <ip> -l /usr/share/wordlists/metasploit/unix_users.txt -p 80 -s 0 -e 403 -t 10

# HTTPS 目标(-s 1 启用 SSL,404 判定)
apache-users -h <ip> -l <userlist> -p 443 -s 1 -e 404 -t 10
```

**Practical tips**:
- Decision logic: a `/~<user>/` request whose return code differs from the value specified by `-e` is treated as existing; choose 403 or 404 as the error code according to the target's actual responses
- The username list feeds SSH/FTP/SMB credential brute forcing and spraying
- Equivalent alternative: `nmap --script http-userdir-enum -p 80 <ip>`, easier to fold into a unified scanning workflow

## Remaining Tools — Quick Reference

| Tool | One-line purpose | Package | Most common commands |
|---|---|---|---|
| atk6-thcping6 (thc-ipv6 suite) | IPv6/ICMPv6 attack and discovery suite | thc-ipv6 | `atk6-alive6 eth0` (discover alive IPv6 hosts); `atk6-address6 fe80::...` (IPv6/MAC conversion); `atk6-detect-new-ip6 eth0` (detect new addresses via DAD); `atk6-dnsdict6 <domain>` (IPv6 subdomain enumeration). Note: the thc-ipv6 binaries packaged in Kali all carry the `atk6-` prefix |
| sctpscan | SCTP protocol discovery and security scanning | sctpscan | `sctpscan -s -F -r 192.168.1.*` |
| mdb-sql (mdbtools) | Read/export JET and MS Access .mdb databases | mdbtools | `mdb-tables <file.mdb>` (list tables); `mdb-export <file.mdb> <table>` (export CSV); `mdb-sql <file.mdb>` (SQL queries) |
| sqlitebrowser | GUI browse/edit/export for SQLite databases | sqlitebrowser | `sqlitebrowser <file>.sqlite` |
| legion | Semi-automated network penetration GUI (scanning + enumeration + exploitation entry, a SPARTA fork) | legion | `sudo legion` |

> This file is for penetration testing with written authorization, CTF competitions, and security education only; unauthorized testing is strictly prohibited.
