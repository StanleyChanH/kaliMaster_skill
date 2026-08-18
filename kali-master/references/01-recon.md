# 侦察与 OSINT(Reconnaissance & OSINT)

> **何时读本文件**:拿到目标域名/组织名/IP,需要收集子域名、DNS 记录、邮箱、员工用户名、社交足迹、公开文档元数据,或需要搭建"被动优先→主动补充"侦察流水线时。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| 被动子域名收集(不接触目标) | subfinder | amass enum -passive / sublist3r / assetfinder | subfinder 快、可配 API key;amass 数据源最多但更重 |
| 一条命令拿邮箱+子域+主机+人名 | theHarvester | recon-ng / spiderfoot | theHarvester 单命令多类结果;recon-ng 模块化、结果入库 |
| 深度 DNS 枚举 + 主动暴力 | amass enum -active | dnsrecon / dnsenum / fierce | amass = 被动源+暴力+置换+图数据库;dnsrecon 单项任务最快 |
| 轻量子域字典暴力 | dnsmap | fierce / sublist3r -b | dnsmap 简单稳定、可出 CSV;fierce 自动检测 DNS wildcard |
| AXFR(zone transfer)测试 | dnsrecon -t axfr | dnswalk / dnsenum(内建尝试) | dnsrecon 一次测全部 NS;dnswalk 附带一致性检查 |
| 海量域名/子域批量解析验证 | massdns | —(管道组合) | 每秒数十万解析,输出可直接接存活检测工具 |
| 子域资产持续监测+告警 | findomain | amass track | findomain 内置 Discord/Slack/Telegram 告警 |
| OSINT 自动化框架 | recon-ng | spiderfoot | recon-ng 类 MSF 交互式;spiderfoot 是 Web UI + 大量数据源 |
| 图形化关联分析与汇报 | maltego | — | 实体-变换关系图;免费 CE 版有限额 |
| 用户名跨平台踩点(SOCMINT) | sherlock | tookie-osint | sherlock 覆盖 300+ 站点;tookie 支持线程/代理/多格式输出 |
| 由公司名生成员工用户名表 | linkedin2username | theHarvester(-b linkedin) | 直接产出用户名变体表,供后续口令喷洒 |
| 域名关联邮箱收集 | theHarvester | emailharvester | theHarvester 源更多;emailharvester 专注邮箱 |
| 公开文档元数据挖掘 | metagoofil | exiftool(配合) | 自动搜+下载,元数据需 exiftool 二次提取 |
| 网站爬取/URL 收集 | gospider | photon | gospider Go 并发、含 wayback 源;photon 额外提取邮箱/参数等 intel |
| robots.txt 泄露审计 | parsero | uniscan -e | parsero 还能查搜索引擎是否已索引敏感路径 |
| 一键式 web 侦察 | finalrecon | dmitry | finalrecon 模块全(SSL/whois/子域/目录/wayback);dmitry 偏 whois+端口 |
| 负载均衡检测 | lbd | — | 确认 LB 后再定扫描策略,避免误判单节点 |
| Typosquatting/仿冒域名检测 | urlcrazy | — | 生成键盘/省字等 typo 变体并检测解析情况 |

## 被动 vs 主动:先做什么

- **被动(第一阶段,首选)**:只查第三方数据源(搜索引擎、证书透明度、Wayback、VirusTotal 等),不向目标资产发任何包,目标侧日志无感知。工具:theHarvester、subfinder、`amass enum -passive`、sublist3r(不带 `-b`)、assetfinder、findomain、sherlock、recon-ng/spiderfoot 多数模块、metagoofil。
- **主动(被动做完、授权范围确认后)**:直接向目标权威 NS 或 Web 服务器发请求,会留下 DNS 查询/HTTP 访问记录。工具:dnsrecon、dnsenum、dnsmap、fierce、dnswalk(AXFR)、massdns、`sublist3r -b`、`amass enum -active`、`dmitry -p`、parsero、lbd、finalrecon、gospider、photon。
- **判断标准**:工具执行时你的 IP 是否会出现在目标的权威 NS 日志或 HTTP 访问日志中;会,即为主动。
- **推荐流水线**:

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

- **Wildcard DNS 前置检查**:字典暴力前先查 `host <random-string>.<domain>`,随机串仍能解析出 IP 说明存在泛解析,暴力结果会有大量误报(fierce、dnsenum 会自动检测并提示)。

## 核心工具详解

### theHarvester — 被动情报收集第一步(邮箱/子域/主机/人名)

**用途**:从搜索引擎、PGP key server、证书透明度(crtsh)等公开源收集邮箱地址、子域名、虚拟主机、IP、员工姓名;纯被动,不触碰目标。
**安装**:`sudo apt install theharvester`
**使用场景**:外部渗透开局的第一条命令;快速拿邮箱列表用于钓鱼演练或用户名推断,子域列表与 subfinder/amass 交叉验证。

```bash
# 官方示例:指定域名、限 500 条、用 duckduckgo 源
theHarvester -d <domain> -l 500 -b duckduckgo

# 多数据源聚合,保存为 JSON(crtsh 证书透明度通常回报子域最多)
theHarvester -d <domain> -b crtsh,bing,linkedin -f <file>.json

# 输出 HTML 报告
theHarvester -d <domain> -b google -f <file>.html
```

**实战要点**:
- `-b` 支持逗号分隔多源:crtsh、bing、duckduckgo、google、netcraft、virustotal、github-code、linkedin 等;部分源需在 `/etc/theHarvester/api-keys.yaml` 配置 API key,crtsh/duckduckgo 免 key。
- 结果分 emails / hosts / ips 几段,hosts 里的 `host:ip` 可直接整理进资产表。
- 适合在被动阶段反复跑(不同数据源),不产生任何指向目标的流量。

### amass — 最全的攻击面映射与深度 DNS 枚举

**用途**:OWASP Amass,攻击面映射事实标准:聚合大量被动数据源 + DNS 枚举 + 字典暴力 + 子域置换 + 图数据库存储;另有 intel 子命令做资产/whois 反查。
**安装**:`sudo apt install amass`
**使用场景**:需要最完整子域/资产清单、或要做长期资产跟踪时;单靠 subfinder 感觉结果有盲区时升级到 amass。

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

**实战要点**:
- 被动先行:`-passive` 不触发目标侧日志,拿到基线后再 `-active` 补充;主动模式大域名可能跑几十分钟,务必 `-o` 保存。
- 数据源 API key 配置:amass v4 为 `~/.config/amass/owasp_amass_config.yaml`(v3 旧版为 `config.ini`),配齐 key 后结果量显著提升。
- 历史枚举结果存在图数据库中,后续可用 `amass db` 系列命令查询复用。
- 输出喂给解析/存活检测:`amass enum -d <domain> -o subs.txt` 后接 massdns。

### subfinder — 快速纯被动子域枚举

**用途**:ProjectDiscovery 出品,专注被动子域发现这一件事:速度快、输出干净、管道友好。
**安装**:`sudo apt install subfinder`
**使用场景**:需要快速出结果、或作为流水线上游把子域列表喂给 HTTP 存活检测/漏洞扫描工具时。

```bash
# 基础被动枚举
subfinder -d <domain>

# 静默模式只输出子域列表,-all 汇总全部数据源
subfinder -d <domain> -all -silent -o subs.txt

# 从文件批量枚举多个域名
subfinder -dL <domains>.txt -silent -o subs.txt
```

**实战要点**:
- 高价值数据源(SecurityTrails、Censys、Shodan、BinaryEdge 等)需在 `~/.config/subfinder/provider-config.yaml` 配 API key;`subfinder -ls` 可列出全部数据源及是否需要 key。
- 与 assetfinder/amass 输出合并去重(`sort -u`)是标准做法,各家数据源覆盖不同。
- 输出的子域默认未验证解析,存活过滤交给 massdns 或 HTTP 探测工具。

### sublist3r — 老牌聚合式子域枚举

**用途**:聚合 Google/Yahoo/Bing/Baidu/Ask/Netcraft/VirusTotal/ThreatCrowd/DNSdumpster 等源的子域枚举,内置 subbrute 字典暴力。
**安装**:`sudo apt install sublist3r`
**使用场景**:轻量快速验证;作为 amass/subfinder 之外的第三方交叉源。

```bash
# 被动聚合枚举,结果存文件
sublist3r -d <domain> -o subs.txt

# 启用 subbrute 字典暴力(主动,直接查询目标 NS),50 线程
sublist3r -d <domain> -b -t 50 -o subs.txt

# 只用指定引擎
sublist3r -d <domain> -e google,netcraft
```

**实战要点**:
- 项目较老,部分引擎已失效,产出不如 subfinder/amass 稳定,定位是补充源。
- `-b` 为主动 DNS 查询,会直接触碰目标权威 NS,注意授权范围与频率。

### assetfinder — 一行式被动子域查找

**用途**:查询 crt.sh、Facebook CT、Riddler、ThreatCrowd、VirusTotal、Wayback 等被动源,输出与给定域相关的域名(含父域与同级资产)。
**安装**:`sudo apt install assetfinder`
**使用场景**:快速、零配置的补充源;脚本管道中与 subfinder 输出合并。

```bash
# 输出所有相关域名(含主域/父域)
assetfinder <domain>

# 只输出子域名
assetfinder --subs-only <domain>
```

**实战要点**:
- 不可配 API key,数据源固定;速度快,适合作为"顺手一跑"的交叉验证。
- 标准用法:`assetfinder --subs-only <domain> >> subs.txt` 后 `sort -u`。

### findomain — 快速子域枚举与资产监测

**用途**:跨平台子域枚举器,主打证书透明度日志 + 多数据源聚合,速度快;支持子域持续监测并推送 Discord/Slack/Telegram 告警。
**安装**:`sudo apt install findomain`
**使用场景**:需要带 IP 的已解析子域列表,或对目标做长期资产变更监控时。

```bash
# 只输出已解析的子域
findomain -t <domain> -r

# 同时显示解析 IP
findomain -t <domain> -ri
```

**实战要点**:
- `-r` 过滤掉未解析记录,产出可直接进入存活检测阶段。
- 多数据源支持多组 API key 以提升配额;监测模式适合红队长期驻留项目的资产面跟踪。

### dnsrecon — 功能最全的 DNS 枚举脚本

**用途**:Python 编写的 DNS 枚举/扫描全家桶:标准枚举、AXFR、反向查找、缓存侦测、SRV 记录、字典暴力,支持 XML/CSV 输出。
**安装**:`sudo apt install dnsrecon`
**使用场景**:主动阶段系统化枚举 DNS;一次任务覆盖 NS/MX/A/AAAA/SRV/AXFR/暴力多个面。

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

**实战要点**:
- `-t std` 先跑,确认 NS 列表后 `-t axfr`;AXFR 成功是重大发现(等同拿到全部记录)。
- 输出同时打印到终端并写 `--xml`/`-c` 文件,便于脚本后处理。
- DNSSEC 域名会额外报 DNSKEY/RRSIG 信息,对后续攻击面判断有用。

### dnsenum — 多线程 Perl DNS 枚举

**用途**:自动完成:主机 A 记录、NS、MX、AXFR、Google 字典查询、子域暴力、反向查找,能发现非连续 IP 段。
**安装**:`sudo apt install dnsenum`
**使用场景**:想一个命令完成常规 DNS 枚举全流程、输出 XML 存档时。

```bash
# 官方示例:跳过反向查找,结果存 XML
dnsenum --noreverse -o mydomain.xml <domain>

# 深度枚举快捷方式(等价于较高强度的 google 抓取+递归+whois 组合)
dnsenum --enum <domain>

# 指定子域字典暴力
dnsenum -f /usr/share/wordlists/dnsmap.txt <domain>
```

**实战要点**:
- 自带 wildcard DNS 检测,有泛解析时会提示,避免字典暴力误报。
- 会向目标 NS 直接发查询并抓取 Google 结果,属主动侦察;频率高易触发防护。

### fierce — nmap 前置的定位型 DNS 扫描器

**用途**:半轻量 DNS 扫描:先尝试 zone transfer,再检测 wildcard,再用内置字典暴力定位非连续 IP 空间与主机名,是 nmap/nessus 等的前置定位工具。
**安装**:`sudo apt install fierce`
**使用场景**:目标是"找出该打哪些 IP 段",而不是穷举全部子域时;配置错误的企业 DNS 常泄露内部地址段。

```bash
# 官方示例:默认全流程扫描
fierce --domain <domain>

# 自定义子域列表 + 指定 DNS 服务器
fierce --domain <domain> --subdomain-file <subdomains>.txt --dns-servers <ip>

# 对发现的 IP 所在 C 段做相邻主机探测
fierce --domain <domain> --wide
```

**实战要点**:
- 输出第一段就是 NS 列表与 AXFR 尝试结果,失败属正常(多数 NS 已禁 AXFR)。
- 自动做 wildcard 检测("Checking for wildcard DNS"),有泛解析时暴力结果需人工复核。
- 定位到 IP 段后交给端口扫描阶段,不在 fierce 内做端口级工作。

### dnsmap — 轻量子域字典暴力

**用途**:用内置(约 1000 英/西词条)或外部字典爆破子域,可输出普通文本与 CSV;无需 root 且不应用 root 运行。
**安装**:`sudo apt install dnsmap`
**使用场景**:低速率、隐蔽需求的子域暴力;或给多个域名做批量字典扫描。

```bash
# 官方示例:指定字典扫描
dnsmap <domain> -w /usr/share/wordlists/dnsmap.txt

# 保存为文本与 CSV
dnsmap <domain> -w /usr/share/wordlists/dnsmap.txt -r results.txt -c results.csv

# 批量扫多个域名
echo "<domain>" >> domains.txt
dnsmap-bulk.sh domains.txt
```

**实战要点**:
- 全部查询直达目标权威 NS,属主动侦察;内置请求延迟(默认 10ms 级)可降低速率。
- 每个命中子域会连同解析 IP 一起输出,CSV 可直接进资产表。
- 有泛解析的域会产生海量假阳性,先做 wildcard 检查再用。

### dnswalk — DNS 数据库调试器(AXFR + 一致性检查)

**用途**:对指定域执行 zone transfer,并对拿到的 DNS 数据库做内部一致性与准确性检查。
**安装**:`sudo apt install dnswalk`
**使用场景**:确认 AXFR 是否开放、以及拿到整库记录后做质量分析。

```bash
# 官方示例:注意域名必须以点结尾
dnswalk <domain>.

# 递归检查 + 调试输出
dnswalk -r -d <domain>.
```

**实战要点**:
- AXFR 成功 = 拿到目标全部 DNS 记录(内部主机名、内部 IP 常直接暴露),是高价值发现;失败则是常态。
- 会顺带报告配置问题(如 CNAME 指向不存在记录),这些常指向遗留资产。

### massdns — 海量 DNS 批量解析

**用途**:高性能 DNS stub resolver,使用公共 resolver 每秒可解析 35 万以上域名,用于对大规模子域/域名清单做解析验证。
**安装**:`sudo apt install massdns`
**使用场景**:枚举工具产出上万子域后的"过滤存活"步骤;也是纯字典子域爆破的高性能引擎。

```bash
# 用 resolver 列表解析域名列表,A 记录,简单输出
massdns -r <resolvers.txt> -t A -o S -w <results>.txt <domains>.txt

# 纯字典爆破常见用法:字典与域名拼接后批量解析
awk -v d="<domain>" '{print $1"."d}' <wordlist> > input.txt
massdns -r <resolvers.txt> -t A -o S -w <results>.txt input.txt
```

**实战要点**:
- resolver 列表可取 massdns 项目自带的 `lists/resolvers.txt`;resolver 质量决定成功率,过期 resolver 是结果偏少的主因。
- 走公共 resolver(如 8.8.8.8)时不直连目标权威 NS,隐蔽性高于直连暴力;但高并发仍可能触发公共 resolver 限速。
- `-o S` 简单输出格式(`domain,resolver,answer`)最利于 grep/awk 后处理。

### sherlock — 跨 300+ 平台的用户名足迹发现

**用途**:利用各站点"用户名唯一 URL"特性,批量检测一个用户名在 300+ 社交网络/开发者平台(GitHub、GitLab、Instagram、Telegram、TikTok、PyPI 等)是否被注册。
**安装**:`sudo apt install sherlock`
**使用场景**:由泄露邮箱/昵称还原目标人物的全平台账号画像;钓鱼前置踩点。

```bash
# 检查单个用户名
sherlock <user>

# 多个用户名批量检查
sherlock <user1> <user2>

# 限定单个站点并设超时
sherlock <user> --site github --timeout 10
```

**实战要点**:
- 命中 ≠ 同一人:结合头像、注册时间、简介交叉验证;常见误报来自用户名撞车。
- 需要代理时加 `--proxy <proxy>`;部分站点需要网络可达性,失败站点可重跑补齐。
- 与 tookie-osint 互为补充,重要目标建议双跑。

### recon-ng — 类 Metasploit 的 Web 侦察框架

**用途**:模块化 Web 侦察框架:独立模块 + 数据库交互 + marketplace,交互体验类似 MSF,上手成本低。
**安装**:`sudo apt install recon-ng`
**使用场景**:需要把多源侦察结果统一入库、去重、生成报告的结构化 OSINT 工作。

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

**实战要点**:
- `marketplace install all` 后仍需为数据源配 API key:`keys add <provider> <key>`、`keys list` 查看;无 key 的模块会报错或空结果。
- 结果存每工作区的 SQLite 数据库,`show hosts/contacts/domains` 查看,`reporting/*` 模块(如 reporting/csv)导出。
- 常用模块族:`recon/domains-hosts/*`(子域)、`recon/hosts-domains/*`(IP 反查域)、`recon/domains-vulnerabilities/*`(历史漏洞)。

### spiderfoot — 自动化 OSINT 平台(Web UI + CLI)

**用途**:OSINT 自动化收集:目标可为 IP、域名、主机名、网段、ASN、邮箱、人名;自动调用大量数据源并做关联,既可攻击性侦察也可评估自身暴露面。
**安装**:`sudo apt install spiderfoot`
**使用场景**:需要一个"填目标、点开始"的自动化 OSINT 引擎,或要对结果做图谱式关联时。

```bash
# 启动 Web UI,浏览器访问 http://127.0.0.1:5001 新建扫描
spiderfoot -l 127.0.0.1:5001

# 纯 CLI 跑指定模块(-s 指定扫描目标,-t 是要收集的事件类型)
spiderfoot -s <target> -m sfp_dnsresolve
```

**实战要点**:
- Web UI 中选择"用例"(如 all/footprint)即可一键跑全量模块;CLI `-m` 逗号分隔可组合模块。
- 扫描量大时优先配 API key(界面 Settings 里),否则大量数据源被跳过。
- 同包提供 `sf` 等价命令(spiderfoot-cli 入口);结果可导出 CSV/JSON/GEXF 供报告使用。

### maltego — 图形化 OSINT 关联分析

**用途**:桌面 OSINT/取证应用:以"实体(Domain/IP/Person/Email)—变换(Transform)"关系图的方式挖掘与可视化关联信息。
**安装**:`sudo apt install maltego`
**使用场景**:人工 pivot 分析(邮箱→域名→DNS→IP→组织)与出图汇报;自动化场景应选 recon-ng/spiderfoot。

```bash
# 启动桌面客户端(需图形环境;首次运行需登录 maltego.com 免费账号)
maltego
```

**实战要点**:
- 典型流程:新建空白图 → 从左侧实体面板拖入 Domain/Website 实体 → 右键实体运行 transforms(如 "To DNS Name" 系列变换)逐层展开。
- 免费 CE 版对每变换返回条数有限制;变换走 Maltego 官方服务器,敏感目标慎用。
- 支持导入 CSV 做本地数据关联,适合把 recon-ng/spiderfoot 的输出可视化。

### metagoofil — 公开文档搜索与下载(元数据前置)

**用途**:在 Google 搜索目标域名的公开文档(pdf/doc/xls/ppt/docx/pptx/xlsx)并批量下载,供后续元数据提取(内部用户名、路径、软件版本)。
**安装**:`sudo apt install metagoofil`
**使用场景**:从公开文档泄露中还原目标内部命名规范、员工名单、共享路径。

```bash
# 官方示例:搜 pdf、100 条结果、下载 25 个、保存目录与报告文件
metagoofil -d <domain> -t pdf -l 100 -n 25 -o kalipdf -f kalipdf.html
```

**实战要点**:
- 新版 metagoofil 只负责搜索与下载,不再自动提取元数据;下载完成后用 `exiftool <outdir>/*` 手工分析 Author/Creator/路径等字段。
- `-t` 支持逗号分隔多类型(如 `pdf,docx,xlsx`);Google 查询过多会触发验证码,`-l` 控制节奏。
- 提取到的内部用户名格式(`first.last`、`flast`)直接喂给 linkedin2username/口令喷洒阶段。

### dmitry — 一体化信息收集(Deepmagic)

**用途**:C 编写的 UNIX 命令行收集器:域名/IP whois、Netcraft 信息、子域搜索、邮箱搜索、TCP 端口扫描,一站式输出到文件。
**安装**:`sudo apt install dmitry`
**使用场景**:需要单命令快速拿一份数据面较全的初始报告时;体积极小、依赖少。

```bash
# 官方示例:域 whois(w)+IP whois(i)+Netcraft(n)+子域(s)+邮箱(e)+TCP 端口扫描(p),输出存文件
dmitry -winsepo example.txt <domain>

# 只做被动部分(去掉 -p 端口扫描)
dmitry -winseo <output>.txt <domain>
```

**实战要点**:
- `-p` 是主动 TCP 连接扫描,隐匿需求时去掉;其余选项基本基于第三方源。
- 子域与邮箱搜索源较老,结果偏少,作为快速概览而非穷举手段。
- 输出即纯文本报告,适合直接归档进项目笔记。

### photon — Python 高速 OSINT 爬虫

**用途**:对目标网站爬取并分类提取:URL(含参数)、intel(邮箱/社交账号/API key 线索)、文件、JS 内端点等。
**安装**:`sudo apt install photon`
**使用场景**:对单个 Web 资产做内容层侦察,收集攻击面 URL 与外联信息。

```bash
# 抓取目标站点,输出到目录
photon -u <url> -o <outdir>

# 深度 2 层、50 线程
photon -u <url> -l 2 -t 50 -o <outdir>

# 从 Wayback Machine 拉取历史 URL
photon -u <url> --wayback
```

**实战要点**:
- 输出目录按 keys/robots/intel/js 等分文件,intel 文件里的邮箱/社交账号常直接产出新线索。
- 会向目标发大量 HTTP 请求,属主动侦察;控制 `-l` 深度与 `-d` 延迟避免触发 WAF。
- `--wayback` 模式走第三方存档,可视为半被动的历史资产挖掘。

### gospider — Go 编写的高速 Web Spider

**用途**:多站点并行爬虫:爬取链接、解析 sitemap.xml/robots.txt、从 JS 文件生成并验证端点、发现 AWS-S3 桶与子域,并从 Wayback/Common Crawl/VirusTotal 等聚合历史 URL。
**安装**:`sudo apt install gospider`
**使用场景**:批量(而非单个)Web 资产的 URL/端点收集,输出 grep 友好。

```bash
# 单站爬取,深度 2、30 并发(-c 控制单站请求并发,默认 5;-t 是并行爬取的站点数,仅批量模式使用)
gospider -s <url> -d 2 -c 30

# 从文件批量爬多个站点(-t 控制并行站点数)
gospider -S <urls>.txt -d 2 -c 30 -t 20 -o <outdir>

# 额外纳入 sitemap/robots/wayback 源(--robots 默认已开启,可省略;-a 从 Archive.org/CommonCrawl/VirusTotal/AlienVault 拉 URL,-r 把其他源的 URL 纳入结果)
gospider -s <url> -d 2 --sitemap --robots -a --include-other-source
```

**实战要点**:
- 直接爬目标属主动;`-a/--other-source` 从 Archive.org/CommonCrawl 等第三方存档拉 URL,部分走第三方源。
- 输出文件按 URL/JS/subdomain 分类,JS 文件常泄露 API 端点与密钥,值得单独 grep。
- 与 photon 双跑:photon 提取 intel 更细,gospider 覆盖面与并发更好。

### finalrecon — 一体化 Web 侦察脚本

**用途**:Python 模块化 web 侦察:Header、SSL 证书信息、whois、爬虫、DNS、子域、目录爆破、Wayback 历史与端口扫描,一条命令出全量报告。
**安装**:`sudo apt install finalrecon`
**使用场景**:对单个 URL 想要"一键全项"侦察报告时;替代手工串多个小工具。

```bash
# 全量侦察
finalrecon --url <url> --full

# 分项:header + SSL + whois
finalrecon --url <url> --headers --sslinfo --whois

# 子域 + 目录 + wayback
finalrecon --url <url> --sub --dir --wayback
```

**实战要点**:
- `--full` 包含目录爆破等主动项,会直接触碰目标,注意范围;纯被动项组合用分项开关。
- SSL 模块会列出证书 SAN,是子域发现的高质量补充来源。
- 产出为终端报告,建议 `tee <file>` 存档。

### parsero — robots.txt 泄露审计

**用途**:读取目标 robots.txt 的 Disallow 条目,并可选:直接访问这些路径验证状态码(-o),或在 Bing 中检索这些"禁止索引"路径是否已被收录(-sb)。
**安装**:`sudo apt install parsero`
**使用场景**:快速发现管理员面板、备份、测试环境等被 robots.txt"此地无银"暴露的路径。

```bash
# 官方示例:读取 robots.txt 并用 Bing 核查 Disallow 路径收录情况
parsero -u <url> -sb
```

**实战要点**:
- `-sb` 查的是搜索引擎索引(被动);`-o` 会直接请求目标路径(主动)。
- 返回 200/302 的 Disallow 路径是高价值入口,404/405 可降低优先级。
- 与爬虫反着来:robots.txt 里的路径恰是站点管理员认为"敏感"的清单。

### lbd — 负载均衡检测

**用途**:检测目标域名是否使用 DNS 负载均衡(同一主机名多 A 记录)或 HTTP 负载均衡(Server 头指纹变化)。
**安装**:`sudo apt install lbd`
**使用场景**:端口扫描与漏洞验证前确认目标是否在 LB/CDN 后面,避免打偏与误判。

```bash
# 官方示例:检测域名是否使用负载均衡
lbd <domain>
```

**实战要点**:
- 自述为 POC 工具,可能误报;HTTP-Loadbalancing 判定基于响应指纹差异,CDN 会干扰结果。
- 检出 LB 后,后续扫描应覆盖全部后端 IP;对单一后端的漏洞验证结论不能代表全集群。

### urlcrazy — 域名 Typo 变体生成与检测

**用途**:生成目标域名的键盘误击(qwerty/dvorak 等)、省字、换位、重复字符等 typo 变体,并可解析检测其注册/使用情况,用于发现 typosquatting、URL hijacking 与仿冒钓鱼。
**安装**:`sudo apt install urlcrazy`
**使用场景**:防守视角:审计自家品牌存在哪些仿冒域名;攻击视角:评估目标的品牌保护盲区。

```bash
# 官方示例:用 dvorak 键盘布局生成变体,不做 DNS 解析
urlcrazy -k dvorak -r <domain>

# 默认 qwerty 布局,解析检测已注册的变体
urlcrazy <domain>
```

**实战要点**:
- Kali 包可能缺 Ruby 依赖,需到 `/usr/share/urlcrazy` 目录执行 `bundle install` 后使用。
- 已解析且有内容的 typo 域名是钓鱼预警信号;`-r` 只生成不解析,适合先看清单。
- 变体数量随域名长度增长很快,`-r` 模式先行筛一遍再选重点解析。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| caido | Web 安全审计工具箱(桌面版,拦截代理/重放/自动化) | caido | `caido` 启动桌面客户端 |
| caido-cli | Caido 的 CLI/无头模式(代理与 UI 监听分离) | caido-cli | `caido-cli --proxy-listen 127.0.0.1:8080 --ui-listen 127.0.0.1:8085 --no-open` |
| dnstracer | 追踪 DNS 解析链直到权威服务器,定位真实来源 | dnstracer | `dnstracer -r 3 -v <domain>` |
| email2phonenumber | 利用密码重置流程缺陷由邮箱推测目标手机号 | email2phonenumber | `email2phonenumber discover -e <email>` |
| emailharvester | 从搜索引擎收集域名关联邮箱 | emailharvester | `emailharvester -d <domain> -e google -l 500 -s <file>` |
| instaloader | Instagram 公开内容下载(照片/故事/评论/地理标签) | instaloader | `instaloader --comments --geotags <profile>` |
| linkedin2username | 用 LinkedIn 账号登录抓取公司员工并生成用户名列表 | linkedin2username | `linkedin2username -c <company> -d <domain>` |
| owasp-mantra-ff | 基于 Firefox 的安全测试浏览器(内置扩展集) | owasp-mantra-ff | `owasp-mantra-ff` 启动浏览器 |
| spiderfoot-cli | SpiderFoot 的 CLI 入口(与 spiderfoot 同包) | spiderfoot | `spiderfoot-cli -s http://127.0.0.1:5001` |
| tookie-osint | 跨站点用户名发现(sherlock 替代,支持线程/代理/多格式) | tookie-osint | `tookie-osint -u <user> -o json` |
| uniscan-gui | LFI/RFI/RCE 扫描器 uniscan 的 GUI 入口包 | uniscan | `uniscan -u <url> -qd` |
| uro | URL 列表去重清洗,输出 grep 友好 | uro | `cat <urls>.txt \| uro` 或 `uro -i <urls>.txt -o <clean>.txt` |
| wpprobe | WordPress 插件枚举并映射已知漏洞(先更新漏洞库) | wpprobe | `wpprobe update-db`(扫描参数见 `wpprobe -h`) |

---

仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景。
