# Reconnaissance & OSINT

**English** · [简体中文](01-recon.zh-CN.md)

> **When to read this file**: when you have a target domain/organization name/IP and need to gather subdomains, DNS records, email addresses, employee usernames, social footprints, or public document metadata, or when you need to build a "passive-first → active-supplement" recon pipeline.

## Quick Decision Table

| Scenario | First choice | Alternatives | Key difference |
|---|---|---|---|
| Passive subdomain enumeration (no contact with the target) | subfinder | amass enum -passive / sublist3r / assetfinder | subfinder is fast and supports API keys; amass has the most data sources but is heavier |
| Emails + subdomains + hosts + names in one command | theHarvester | recon-ng / spiderfoot | theHarvester returns multiple result types in a single command; recon-ng is modular and stores results in a database |
| In-depth DNS enumeration + active brute forcing | amass enum -active | dnsrecon / dnsenum / fierce | amass = passive sources + brute force + permutation + graph database; dnsrecon is fastest for single tasks |
| Lightweight subdomain dictionary brute forcing | dnsmap | fierce / sublist3r -b | dnsmap is simple and stable with CSV output; fierce auto-detects DNS wildcards |
| AXFR (zone transfer) testing | dnsrecon -t axfr | dnswalk / dnsenum (built-in attempt) | dnsrecon tests all NS at once; dnswalk adds consistency checks |
| Bulk resolving and validating massive domain/subdomain lists | massdns | — (compose a pipeline) | Hundreds of thousands of resolutions per second; output feeds straight into alive-check tools |
| Continuous subdomain asset monitoring + alerting | findomain | amass track | findomain has built-in Discord/Slack/Telegram alerts |
| OSINT automation frameworks | recon-ng | spiderfoot | recon-ng is interactive in the MSF style; spiderfoot is a Web UI + a large set of data sources |
| Graph-based correlation analysis and reporting | maltego | — | Entity-transform relationship graphs; the free CE edition is quota-limited |
| Cross-platform username footprinting (SOCMINT) | sherlock | tookie-osint | sherlock covers 300+ sites; tookie supports threads/proxies/multiple output formats |
| Generate employee username tables from a company name | linkedin2username | theHarvester (-b linkedin) | Produces a table of username variants directly, ready for later password spraying |
| Domain-related email collection | theHarvester | emailharvester | theHarvester has more sources; emailharvester is email-only |
| Public document metadata mining | metagoofil | exiftool (companion) | Auto-searches + downloads; metadata needs a second extraction pass with exiftool |
| Website crawling / URL collection | gospider | photon | gospider offers Go concurrency and wayback sources; photon additionally extracts emails/parameters and other intel |
| robots.txt leak auditing | parsero | uniscan -e | parsero can also check whether search engines have already indexed the sensitive paths |
| One-shot web recon | finalrecon | dmitry | finalrecon has the most complete module set (SSL/whois/subdomains/directories/wayback); dmitry leans toward whois + ports |
| Load balancing detection | lbd | — | Confirm the LB before settling on a scan strategy; avoids misreading it as a single node |
| Typosquatting / lookalike domain detection | urlcrazy | — | Generates keyboard/omission and other typo variants and checks whether they resolve |

## Passive vs. Active: What to Do First

- **Passive (first stage, preferred)**: query only third-party data sources (search engines, certificate transparency, Wayback, VirusTotal, etc.), send no packets to target assets, and leave no trace in target-side logs. Tools: theHarvester, subfinder, `amass enum -passive`, sublist3r (without `-b`), assetfinder, findomain, sherlock, most recon-ng/spiderfoot modules, metagoofil.
- **Active (after passive work is done and the authorized scope is confirmed)**: send requests directly to the target's authoritative NS or web servers; will leave DNS query/HTTP access records. Tools: dnsrecon, dnsenum, dnsmap, fierce, dnswalk (AXFR), massdns, `sublist3r -b`, `amass enum -active`, `dmitry -p`, parsero, lbd, finalrecon, gospider, photon.
- **The criterion**: whether, while the tool runs, your IP will appear in the target's authoritative NS logs or HTTP access logs; if yes, it is active.
- **Recommended pipeline**:

```bash
# 1) 被动多源枚举
subfinder -d <domain> -all -silent > subs.txt
assetfinder --subs-only <domain> >> subs.txt
theHarvester -d <domain> -b crtsh,duckduckgo -f harvest.json
# 2) 合并去重
sort -u subs.txt -o subs.txt
# 3) 解析验证存活
massdns -r <resolvers.txt> -t A -o S -w resolved.txt subs.txt
# 4) 主动补盲区:AXFR + 字典暴力(见 dnsrecon / amass / dnsmap 条目)
```

- **Wildcard DNS pre-check**: before dictionary brute forcing, run `host <random-string>.<domain>`; if the random string still resolves to an IP, a wildcard record exists and brute-force results will contain many false positives (fierce and dnsenum auto-detect this and warn you).

## Core Tools in Depth

### theHarvester — Passive intelligence gathering, step one (emails/subdomains/hosts/names)

**Purpose**: Collects email addresses, subdomains, virtual hosts, IPs, and employee names from public sources such as search engines, PGP key servers, and certificate transparency (crtsh); purely passive, never touches the target.
**Installation**: `sudo apt install theharvester`
**When to use**: The opening command of an external pentest; quickly grab an email list for phishing drills or username inference, and cross-check the subdomain list against subfinder/amass.

```bash
# 官方示例:指定域名、限 500 条、用 duckduckgo 源
theHarvester -d <domain> -l 500 -b duckduckgo

# 多数据源聚合,保存为 JSON(crtsh 证书透明度通常回报子域最多)
theHarvester -d <domain> -b crtsh,bing,linkedin -f <file>.json

# 输出 HTML 报告
theHarvester -d <domain> -b google -f <file>.html
```

**Practical tips**:
- `-b` accepts comma-separated multiple sources: crtsh, bing, duckduckgo, google, netcraft, virustotal, github-code, linkedin, etc.; some sources need an API key configured in `/etc/theHarvester/api-keys.yaml`, crtsh/duckduckgo need no key.
- Results come in emails / hosts / ips sections; the `host:ip` entries under hosts can be tidied straight into an asset table.
- Well suited to repeated runs during the passive phase (across different data sources); generates no traffic toward the target.

### amass — The most complete attack surface mapping and in-depth DNS enumeration

**Purpose**: OWASP Amass, the de facto standard for attack surface mapping: aggregates a large set of passive data sources + DNS enumeration + dictionary brute forcing + subdomain permutation + graph database storage; the intel subcommand additionally does asset/whois reverse lookups.
**Installation**: `sudo apt install amass`
**When to use**: When you need the most complete subdomain/asset inventory or long-term asset tracking; upgrade to amass when subfinder alone seems to have blind spots.

```bash
# 纯被动枚举(只查数据源,不向目标 DNS 发包)
amass enum -passive -d <domain> -o passive.txt

# 主动枚举 = 被动数据源 + DNS 解析 + 字典暴力 + 置换
amass enum -active -d <domain> -o active.txt

# 指定字典做暴力枚举
amass enum -d <domain> -brute -w /usr/share/wordlists/dnsmap.txt -o brute.txt

# 资产发现:whois 反查同注册人的其他域名
amass intel -whois -d <domain>

# 由组织名找相关 ASN
amass intel -org <org-name>
```

**Practical tips**:
- Passive first: `-passive` triggers no target-side logs; once you have a baseline, follow up with `-active` to fill gaps; the active mode can run for tens of minutes on large domains, so always save output with `-o`.
- Data source API key configuration: in amass v4 it is `~/.config/amass/owasp_amass_config.yaml` (v3 legacy used `config.ini`); filling in keys noticeably increases result volume.
- Past enumeration results are stored in the graph database and can later be queried and reused with the `amass db` command family.
- Feed output into resolution/alive checks: run `amass enum -d <domain> -o subs.txt` and follow with massdns.

### subfinder — Fast, purely passive subdomain enumeration

**Purpose**: From ProjectDiscovery, focused solely on passive subdomain discovery: fast, clean output, pipeline-friendly.
**Installation**: `sudo apt install subfinder`
**When to use**: When you need results fast, or as the upstream of a pipeline feeding the subdomain list to HTTP alive-check/vulnerability scanning tools.

```bash
# 基础被动枚举
subfinder -d <domain>

# 静默模式只输出子域列表,-all 汇总全部数据源
subfinder -d <domain> -all -silent -o subs.txt

# 从文件批量枚举多个域名
subfinder -dL <domains>.txt -silent -o subs.txt
```

**Practical tips**:
- High-value data sources (SecurityTrails, Censys, Shodan, BinaryEdge, etc.) need API keys in `~/.config/subfinder/provider-config.yaml`; `subfinder -ls` lists all data sources and whether a key is required.
- Merging and deduplicating output with assetfinder/amass (`sort -u`) is standard practice; each tool covers different data sources.
- Emitted subdomains are unresolved by default; leave alive-filtering to massdns or HTTP probing tools.

### sublist3r — Veteran aggregator-style subdomain enumeration

**Purpose**: Subdomain enumeration aggregating Google/Yahoo/Bing/Baidu/Ask/Netcraft/VirusTotal/ThreatCrowd/DNSdumpster and similar sources, with built-in subbrute dictionary brute forcing.
**Installation**: `sudo apt install sublist3r`
**When to use**: Lightweight, quick validation; a third-party cross-check source beyond amass/subfinder.

```bash
# 被动聚合枚举,结果存文件
sublist3r -d <domain> -o subs.txt

# 启用 subbrute 字典暴力(主动,直接查询目标 NS),50 线程
sublist3r -d <domain> -b -t 50 -o subs.txt

# 只用指定引擎
sublist3r -d <domain> -e google,netcraft
```

**Practical tips**:
- The project is old, some engines are dead, and output is less reliable than subfinder/amass; treat it as a supplementary source.
- `-b` performs active DNS queries that hit the target's authoritative NS directly; mind the authorized scope and query rate.

### assetfinder — One-liner passive subdomain discovery

**Purpose**: Queries passive sources such as crt.sh, Facebook CT, Riddler, ThreatCrowd, VirusTotal, and Wayback, and outputs domains related to the given domain (including parent domains and sibling assets).
**Installation**: `sudo apt install assetfinder`
**When to use**: A fast, zero-configuration supplementary source; merged with subfinder output in scripted pipelines.

```bash
# 输出所有相关域名(含主域/父域)
assetfinder <domain>

# 只输出子域名
assetfinder --subs-only <domain>
```

**Practical tips**:
- No API keys are configurable and the data sources are fixed; it is fast and works well as a low-effort cross-check.
- Standard usage: `assetfinder --subs-only <domain> >> subs.txt` followed by `sort -u`.

### findomain — Fast subdomain enumeration and asset monitoring

**Purpose**: A cross-platform subdomain enumerator centered on certificate transparency logs + multi-source aggregation, with high speed; supports continuous subdomain monitoring with Discord/Slack/Telegram alerting.
**Installation**: `sudo apt install findomain`
**When to use**: When you need a resolved subdomain list with IPs, or long-term monitoring of asset changes on a target.

```bash
# 只输出已解析的子域
findomain -t <domain> -r

# 同时显示解析 IP
findomain -t <domain> -ri
```

**Practical tips**:
- `-r` filters out unresolved records, so the output can go straight into the alive-checking stage.
- Multiple data sources accept several API keys to raise quotas; monitoring mode suits asset-surface tracking on long-running red team engagements.

### dnsrecon — The most full-featured DNS enumeration script

**Purpose**: A DNS enumeration/scanning all-in-one written in Python: standard enumeration, AXFR, reverse lookups, cache snooping, SRV records, dictionary brute forcing, with XML/CSV output support.
**Installation**: `sudo apt install dnsrecon`
**When to use**: Systematic DNS enumeration during the active phase; one task covers NS/MX/A/AAAA/SRV/AXFR/brute force across multiple fronts.

```bash
# 官方示例:标准枚举 + 字典暴力,输出 XML
dnsrecon -d <domain> -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml

# 对域内所有 NS 测试 zone transfer
dnsrecon -d <domain> -t axfr

# 反向查找一个网段内的 PTR 记录
dnsrecon -t rvl -r <cidr>

# 指定权威 NS 做枚举
dnsrecon -d <domain> -t std -n <ns-ip>
```

**Practical tips**:
- Run `-t std` first, then `-t axfr` once the NS list is confirmed; a successful AXFR is a major finding (equivalent to obtaining all records).
- Output is printed to the terminal and simultaneously written to `--xml`/`-c` files, easy for scripted post-processing.
- DNSSEC-signed domains additionally report DNSKEY/RRSIG information, useful for later attack surface assessment.

### dnsenum — Multithreaded Perl DNS enumeration

**Purpose**: Automatically performs: host A records, NS, MX, AXFR, Google dictionary queries, subdomain brute forcing, and reverse lookups; can discover non-contiguous IP ranges.
**Installation**: `sudo apt install dnsenum`
**When to use**: When you want one command for the full routine DNS enumeration workflow with XML output for archiving.

```bash
# 官方示例:跳过反向查找,结果存 XML
dnsenum --noreverse -o mydomain.xml <domain>

# 深度枚举快捷方式(等价于较高强度的 google 抓取+递归+whois 组合)
dnsenum --enum <domain>

# 指定子域字典暴力
dnsenum -f /usr/share/wordlists/dnsmap.txt <domain>
```

**Practical tips**:
- Ships with wildcard DNS detection and warns when a wildcard record exists, avoiding false positives during dictionary brute forcing.
- Sends queries directly to the target's NS and scrapes Google results, so it counts as active recon; high query rates can trip defenses.

### fierce — A locator-style DNS scanner that precedes nmap

**Purpose**: A semi-lightweight DNS scanner: first attempts a zone transfer, then checks for wildcards, then brute forces with a built-in wordlist to locate non-contiguous IP space and hostnames; a targeting tool to run before nmap/nessus.
**Installation**: `sudo apt install fierce`
**When to use**: When the goal is "which IP ranges to hit" rather than exhaustively enumerating all subdomains; misconfigured enterprise DNS often leaks internal address ranges.

```bash
# 官方示例:默认全流程扫描
fierce --domain <domain>

# 自定义子域列表 + 指定 DNS 服务器
fierce --domain <domain> --subdomain-file <subdomains>.txt --dns-servers <ip>

# 对发现的 IP 所在 C 段做相邻主机探测
fierce --domain <domain> --wide
```

**Practical tips**:
- The first block of output is the NS list and AXFR attempt results; failure is normal (most NS have AXFR disabled).
- Automatically performs wildcard detection ("Checking for wildcard DNS"); when a wildcard exists, brute-force results need manual review.
- Once IP ranges are located, hand off to the port scanning stage; do not do port-level work inside fierce.

### dnsmap — Lightweight subdomain dictionary brute forcing

**Purpose**: Brute forces subdomains with the built-in wordlist (~1000 English/Spanish entries) or an external one; outputs plain text and CSV; no root required and it should not be run as root.
**Installation**: `sudo apt install dnsmap`
**When to use**: Low-rate, stealthy subdomain brute forcing; or batch dictionary scanning of many domains.

```bash
# 官方示例:指定字典扫描
dnsmap <domain> -w /usr/share/wordlists/dnsmap.txt

# 保存为文本与 CSV
dnsmap <domain> -w /usr/share/wordlists/dnsmap.txt -r results.txt -c results.csv

# 批量扫多个域名
echo "<domain>" >> domains.txt
dnsmap-bulk.sh domains.txt
```

**Practical tips**:
- All queries go directly to the target's authoritative NS, making it active recon; the built-in request delay (on the order of 10ms by default) can lower the rate.
- Each hit subdomain is printed together with its resolved IP; the CSV can go straight into an asset table.
- Domains with wildcard records produce masses of false positives; check for wildcards first.

### dnswalk — DNS database debugger (AXFR + consistency checks)

**Purpose**: Performs a zone transfer against the specified domain and runs internal consistency and accuracy checks on the retrieved DNS database.
**Installation**: `sudo apt install dnswalk`
**When to use**: Confirming whether AXFR is open, and analyzing record quality after obtaining the full database.

```bash
# 官方示例:注意域名必须以点结尾
dnswalk <domain>.

# 递归检查 + 调试输出
dnswalk -r -d <domain>.
```

**Practical tips**:
- A successful AXFR = the target's entire DNS record set (internal hostnames and internal IPs are often directly exposed); a high-value finding, while failure is the norm.
- It also reports configuration problems along the way (e.g., CNAMEs pointing to nonexistent records), which often point to legacy assets.

### massdns — Bulk DNS resolution at massive scale

**Purpose**: A high-performance DNS stub resolver that can resolve over 350,000 domains per second using public resolvers; used to resolve and validate large subdomain/domain lists.
**Installation**: `sudo apt install massdns`
**When to use**: The "filter for alive" step after enumeration tools produce tens of thousands of subdomains; also a high-performance engine for pure wordlist subdomain brute forcing.

```bash
# 用 resolver 列表解析域名列表,A 记录,简单输出
massdns -r <resolvers.txt> -t A -o S -w <results>.txt <domains>.txt

# 纯字典爆破常见用法:字典与域名拼接后批量解析
awk -v d="<domain>" '{print $1"."d}' <wordlist> > input.txt
massdns -r <resolvers.txt> -t A -o S -w <results>.txt input.txt
```

**Practical tips**:
- The resolver list can come from the massdns project's own `lists/resolvers.txt`; resolver quality decides the success rate, and stale resolvers are the main cause of sparse results.
- Going through public resolvers (e.g., 8.8.8.8) avoids hitting the target's authoritative NS directly, so it is stealthier than direct brute forcing; high concurrency can still trigger rate limits on public resolvers.
- The `-o S` simple output format (`domain,resolver,answer`) is the best for grep/awk post-processing.

### sherlock — Username footprint discovery across 300+ platforms

**Purpose**: Exploits the "unique username URL" property of many sites to batch-check whether a username is registered on 300+ social networks/developer platforms (GitHub, GitLab, Instagram, Telegram, TikTok, PyPI, etc.).
**Installation**: `sudo apt install sherlock`
**When to use**: Building a full-platform account profile of a target person from a leaked email/nickname; pre-phishing footprinting.

```bash
# 检查单个用户名
sherlock <user>

# 多个用户名批量检查
sherlock <user1> <user2>

# 限定单个站点并设超时
sherlock <user> --site github --timeout 10
```

**Practical tips**:
- A hit ≠ the same person: cross-validate using avatars, registration dates, and bios; common false positives come from username collisions.
- Add `--proxy <proxy>` when a proxy is needed; some sites require network reachability, and failed sites can be rerun to fill the gaps.
- Complements tookie-osint; for high-value targets, run both.

### recon-ng — A Metasploit-style web recon framework

**Purpose**: A modular web recon framework: standalone modules + database interaction + a marketplace; the interactive experience resembles MSF with a low learning curve.
**Installation**: `sudo apt install recon-ng`
**When to use**: Structured OSINT work that needs multi-source recon results unified in a database, deduplicated, and turned into reports.

```bash
recon-ng
# 以下为交互 shell 内操作:
[recon-ng][default] > marketplace refresh
[recon-ng][default] > marketplace install all
[recon-ng][default] > modules search subdomain
[recon-ng][default] > use recon/domains-hosts/bing_domain_web
[recon-ng][default][bing_domain_web] > set SOURCE <domain>
[recon-ng][default][bing_domain_web] > run
[recon-ng][default] > back
[recon-ng][default] > show hosts

# 官方示例:查询域名的公开 XSS 历史记录
[recon-ng][default] > use recon/domains-vulnerabilities/xssed
[recon-ng][default][xssed] > set SOURCE <domain>
[recon-ng][default][xssed] > run
```

**Practical tips**:
- After `marketplace install all`, data sources still need API keys: add them with `keys add <provider> <key>` and view with `keys list`; modules without keys error out or return empty results.
- Results are stored in a per-workspace SQLite database, viewed with `show hosts/contacts/domains`, and exported via `reporting/*` modules (e.g., reporting/csv).
- Common module families: `recon/domains-hosts/*` (subdomains), `recon/hosts-domains/*` (IP-to-domain reverse lookup), `recon/domains-vulnerabilities/*` (historical vulnerabilities).

### spiderfoot — Automated OSINT platform (Web UI + CLI)

**Purpose**: Automated OSINT collection: targets can be IPs, domains, hostnames, network ranges, ASNs, emails, or person names; automatically queries many data sources and correlates results, usable both for offensive recon and for assessing your own exposure.
**Installation**: `sudo apt install spiderfoot`
**When to use**: When you want an automated OSINT engine where you "fill in a target, click start", or need graph-style correlation of results.

```bash
# 启动 Web UI,浏览器访问 http://127.0.0.1:5001 新建扫描
spiderfoot -l 127.0.0.1:5001

# 纯 CLI 跑指定模块(-s 指定扫描目标,-t 是要收集的事件类型)
spiderfoot -s <target> -m sfp_dnsresolve
```

**Practical tips**:
- In the Web UI, pick a "use case" (e.g., all/footprint) to run the full module set in one click; in the CLI, `-m` takes comma-separated module combinations.
- Configure API keys first for large scans (under Settings in the UI); otherwise many data sources get skipped.
- The same package provides the equivalent `sf` command (the spiderfoot-cli entry point); results can be exported to CSV/JSON/GEXF for reporting.

### maltego — Graphical OSINT correlation analysis

**Purpose**: A desktop OSINT/forensics application: mines and visualizes related information as "entity (Domain/IP/Person/Email) — transform" relationship graphs.
**Installation**: `sudo apt install maltego`
**When to use**: Manual pivot analysis (email→domain→DNS→IP→organization) and graph-based reporting; for automation, choose recon-ng/spiderfoot instead.

```bash
# 启动桌面客户端(需图形环境;首次运行需登录 maltego.com 免费账号)
maltego
```

**Practical tips**:
- Typical flow: create a blank graph → drag Domain/Website entities in from the left entity palette → right-click an entity and run transforms (e.g., the "To DNS Name" series) to expand layer by layer.
- The free CE edition caps the number of results per transform; transforms run through Maltego's official servers, so be cautious with sensitive targets.
- Supports CSV import for correlating local data; good for visualizing recon-ng/spiderfoot output.

### metagoofil — Public document search and download (metadata front end)

**Purpose**: Searches Google for public documents of the target domain (pdf/doc/xls/ppt/docx/pptx/xlsx) and downloads them in bulk, ready for later metadata extraction (internal usernames, paths, software versions).
**Installation**: `sudo apt install metagoofil`
**When to use**: Recovering a target's internal naming conventions, staff lists, and share paths from public document leaks.

```bash
# 官方示例:搜 pdf、100 条结果、下载 25 个、保存目录与报告文件
metagoofil -d <domain> -t pdf -l 100 -n 25 -o kalipdf -f kalipdf.html
```

**Practical tips**:
- Recent metagoofil only searches and downloads; it no longer auto-extracts metadata. After the downloads finish, analyze fields such as Author/Creator/paths manually with `exiftool <outdir>/*`.
- `-t` accepts multiple comma-separated types (e.g., `pdf,docx,xlsx`); too many Google queries trigger CAPTCHAs, so use `-l` to pace them.
- Extracted internal username formats (`first.last`, `flast`) feed directly into the linkedin2username/password spraying stage.

### dmitry — All-in-one information gathering (Deepmagic)

**Purpose**: A UNIX command-line collector written in C: domain/IP whois, Netcraft information, subdomain search, email search, and TCP port scanning, with one-stop output to a file.
**Installation**: `sudo apt install dmitry`
**When to use**: When one command should quickly produce a fairly broad initial report; tiny footprint, few dependencies.

```bash
# 官方示例:域 whois(w)+IP whois(i)+Netcraft(n)+子域(s)+邮箱(e)+TCP 端口扫描(p),输出存文件
dmitry -winsepo example.txt <domain>

# 只做被动部分(去掉 -p 端口扫描)
dmitry -winseo <output>.txt <domain>
```

**Practical tips**:
- `-p` is an active TCP connect scan; drop it when stealth matters. The other options are mostly third-party-source based.
- Its subdomain and email search sources are dated and return few results; treat it as a quick overview, not an exhaustive method.
- The output is a plain-text report, ready to archive directly into project notes.

### photon — Fast Python OSINT crawler

**Purpose**: Crawls the target website and extracts by category: URLs (with parameters), intel (email/social account/API key leads), files, endpoints inside JS, and more.
**Installation**: `sudo apt install photon`
**When to use**: Content-layer recon of a single web asset; collecting attack-surface URLs and external reference information.

```bash
# 抓取目标站点,输出到目录
photon -u <url> -o <outdir>

# 深度 2 层、50 线程
photon -u <url> -l 2 -t 50 -o <outdir>

# 从 Wayback Machine 拉取历史 URL
photon -u <url> --wayback
```

**Practical tips**:
- The output directory is split into files such as keys/robots/intel/js; emails/social accounts in the intel file often yield fresh leads directly.
- It sends many HTTP requests to the target, so it is active recon; control `-l` depth and `-d` delay to avoid tripping a WAF.
- `--wayback` mode goes through third-party archives and can be considered semi-passive historical asset mining.

### gospider — Fast web spider written in Go

**Purpose**: A parallel multi-site crawler: crawls links, parses sitemap.xml/robots.txt, generates and verifies endpoints from JS files, discovers AWS-S3 buckets and subdomains, and aggregates historical URLs from Wayback/Common Crawl/VirusTotal and others.
**Installation**: `sudo apt install gospider`
**When to use**: URL/endpoint collection across many (not single) web assets, with grep-friendly output.

```bash
# 单站爬取,深度 2、30 并发(-c 控制单站请求并发,默认 5;-t 是并行爬取的站点数,仅批量模式使用)
gospider -s <url> -d 2 -c 30

# 从文件批量爬多个站点(-t 控制并行站点数)
gospider -S <urls>.txt -d 2 -c 30 -t 20 -o <outdir>

# 额外纳入 sitemap/robots/wayback 源(--robots 默认已开启,可省略;-a 从 Archive.org/CommonCrawl/VirusTotal/AlienVault 拉 URL,-r 把其他源的 URL 纳入结果)
gospider -s <url> -d 2 --sitemap --robots -a --include-other-source
```

**Practical tips**:
- Crawling the target directly is active; `-a/--other-source` pulls URLs from third-party archives such as Archive.org/CommonCrawl, so part of the traffic goes through third-party sources.
- Output files are categorized by URL/JS/subdomain; JS files often leak API endpoints and keys and are worth grepping separately.
- Run alongside photon: photon extracts finer-grained intel, while gospider has broader coverage and better concurrency.

### finalrecon — All-in-one web recon script

**Purpose**: Modular Python web recon: headers, SSL certificate details, whois, crawler, DNS, subdomains, directory brute forcing, Wayback history, and port scanning — a full report in one command.
**Installation**: `sudo apt install finalrecon`
**When to use**: When you want a "one-command, all-items" recon report for a single URL; replaces manually chaining several small tools.

```bash
# 全量侦察
finalrecon --url <url> --full

# 分项:header + SSL + whois
finalrecon --url <url> --headers --sslinfo --whois

# 子域 + 目录 + wayback
finalrecon --url <url> --sub --dir --wayback
```

**Practical tips**:
- `--full` includes active items such as directory brute forcing that hit the target directly, so mind the scope; use the individual switches to combine purely passive items.
- The SSL module lists certificate SANs, a high-quality supplementary source for subdomain discovery.
- Output is a terminal report; archive it with `tee <file>`.

### parsero — robots.txt leak auditing

**Purpose**: Reads the Disallow entries of the target's robots.txt, and optionally: visits those paths directly to verify status codes (-o), or searches Bing for whether these "noindex" paths have already been indexed (-sb).
**Installation**: `sudo apt install parsero`
**When to use**: Quickly finding admin panels, backups, test environments, and other paths that robots.txt "advertises" by disallowing them.

```bash
# 官方示例:读取 robots.txt 并用 Bing 核查 Disallow 路径收录情况
parsero -u <url> -sb
```

**Practical tips**:
- `-sb` checks search engine indexes (passive); `-o` requests the target paths directly (active).
- Disallow paths that return 200/302 are high-value entry points; 404/405 can be deprioritized.
- Do the opposite of the crawler: the paths listed in robots.txt are exactly the ones the site admin considers "sensitive".

### lbd — Load balancing detection

**Purpose**: Detects whether a target domain uses DNS load balancing (multiple A records for one hostname) or HTTP load balancing (varying Server header fingerprints).
**Installation**: `sudo apt install lbd`
**When to use**: Confirming before port scanning and vulnerability validation whether the target sits behind an LB/CDN, avoiding missed hits and misjudgments.

```bash
# 官方示例:检测域名是否使用负载均衡
lbd <domain>
```

**Practical tips**:
- Self-described as a POC tool and may yield false positives; the HTTP load balancing verdict is based on response fingerprint differences, and CDNs can skew results.
- After detecting an LB, subsequent scans should cover every backend IP; a vulnerability validated on a single backend does not represent the whole cluster.

### urlcrazy — Domain typo variant generation and detection

**Purpose**: Generates typo variants of the target domain — keyboard mistypes (qwerty/dvorak etc.), character omission, transposition, repeated characters, and more — and can resolve them to check registration/usage, for discovering typosquatting, URL hijacking, and phishing lookalikes.
**Installation**: `sudo apt install urlcrazy`
**When to use**: Defensively: audit which lookalike domains exist against your own brand; offensively: assess a target's brand-protection blind spots.

```bash
# 官方示例:用 dvorak 键盘布局生成变体,不做 DNS 解析
urlcrazy -k dvorak -r <domain>

# 默认 qwerty 布局,解析检测已注册的变体
urlcrazy <domain>
```

**Practical tips**:
- The Kali package may miss Ruby dependencies; run `bundle install` inside `/usr/share/urlcrazy` before use.
- Typo domains that resolve and serve content are a phishing warning sign; `-r` only generates without resolving, good for reviewing the list first.
- The number of variants grows quickly with domain length; do a first pass in `-r` mode, then pick the interesting ones to resolve.

## Remaining Tools — Quick Reference

| Tool | One-line purpose | Package | Most common command |
|---|---|---|---|
| caido | Web security auditing toolbox (desktop; intercepting proxy/replay/automation) | caido | `caido` launches the desktop client |
| caido-cli | Caido's CLI/headless mode (separate proxy and UI listeners) | caido-cli | `caido-cli --proxy-listen 127.0.0.1:8080 --ui-listen 127.0.0.1:8085 --no-open` |
| dnstracer | Traces the DNS resolution chain up to the authoritative server to locate the true origin | dnstracer | `dnstracer -r 3 -v <domain>` |
| email2phonenumber | Infers a target's phone number from an email address by abusing password-reset flow flaws | email2phonenumber | `email2phonenumber discover -e <email>` |
| emailharvester | Collects domain-related emails from search engines | emailharvester | `emailharvester -d <domain> -e google -l 500 -s <file>` |
| instaloader | Downloads public Instagram content (photos/stories/comments/geotags) | instaloader | `instaloader --comments --geotags <profile>` |
| linkedin2username | Logs in with a LinkedIn account to scrape company employees and generate username lists | linkedin2username | `linkedin2username -c <company> -d <domain>` |
| owasp-mantra-ff | Firefox-based security testing browser (bundled extension set) | owasp-mantra-ff | `owasp-mantra-ff` launches the browser |
| spiderfoot-cli | SpiderFoot's CLI entry point (same package as spiderfoot) | spiderfoot | `spiderfoot-cli -s http://127.0.0.1:5001` |
| tookie-osint | Cross-site username discovery (a sherlock alternative with threads/proxy/multi-format support) | tookie-osint | `tookie-osint -u <user> -o json` |
| uniscan-gui | GUI entry package for the LFI/RFI/RCE scanner uniscan | uniscan | `uniscan -u <url> -qd` |
| uro | Deduplicates and cleans URL lists with grep-friendly output | uro | `cat <urls>.txt \| uro` or `uro -i <urls>.txt -o <clean>.txt` |
| wpprobe | WordPress plugin enumeration mapped to known vulnerabilities (update the vuln DB first) | wpprobe | `wpprobe update-db` (see `wpprobe -h` for scan options) |

---

For use only in penetration testing with written authorization, CTF competitions, and security education scenarios.
