# 漏洞评估(Vulnerability Assessment)

> **何时读本文件**:用户要求对已授权资产做"漏洞扫描 / 漏洞评估 / 合规基线检查 / 出漏洞报告",只发现与验证漏洞、不进行利用时。若任务涉及 getshell、提权、横向移动、数据窃取等利用环节,请转渗透测试流程文件。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| 大网段(≥/16)端口清点 | masscan | naabu, rustscan | masscan 极高速但需限速;naabu 控速更精细 |
| 单主机全端口发现 | nmap -p- | rustscan | rustscan 发现后无缝转交 nmap 精扫 |
| 同网段主机发现(含禁 ping) | arp-scan | netdiscover | ARP 二层发现不受主机 ICMP 防火墙策略影响 |
| 子域名资产收集 | assetfinder | amass, sublist3r | assetfinder 秒级出结果;amass 深而慢 |
| 服务/版本识别 | nmap -sV | whatweb(Web) | -sV 是所有版本比对类检测的前提 |
| 网络层已知漏洞速查 | nmap --script vuln | vulners.nse, vulscan | vuln 为内置脚本集;vulners/vulscan 按版本比对 CVE,需另装 |
| Web 漏洞/暴露面/配置缺陷 | nuclei | wapiti, nikto | nuclei 模板生态最大且带严重级标签;wapiti 是爬虫式黑盒 |
| CMS 专项扫描 | wpscan(WordPress) | joomscan, droopescan | 按 CMS 类型对应选择 |
| TLS/证书配置审计 | testssl.sh | sslscan, sslyze | testssl.sh 报告最完整;sslscan 快速单项确认 |
| 企业级全量扫描+报告体系 | OpenVAS(GVM) | Legion | GVM 自带资产库/任务调度/报告导出;Legion 轻量 GUI |
| 公开 PoC 存在性核验 | searchsploit | — | 离线 Exploit-DB,只检索不执行 |
| SMB/Windows 信息泄露审计 | enum4linux-ng | netexec | enum4linux-ng 面向枚举;netexec 面向批量核验 |
| 误报手动验证与证据留存 | curl | openssl s_client | curl 留 HTTP 证据;openssl 留 TLS 证据 |
| 主机层基线合规审计 | lynis | oscap | lynis 轻量快速;oscap 走 SCAP/XCCDF 标准 |

## 评估边界与红线(vs 渗透测试)

- **目标差异**:漏洞评估只回答"有什么漏洞、多严重、怎么修";渗透测试回答"能造成多大实际危害"。本流程止步于**验证存在性**,不做利用。
- **必做**:执行任何命令前核对授权范围(scope 文件,一行一个 CIDR/域名);扫描窗口预约;限速;危急/高危 100% 人工复核;每条漏洞留存可复现证据。
- **禁做**:DoS/资源耗尽类测试;利用获取 shell/数据/凭据;写操作类 PoC(PUT 上传、RCE 落文件);生产数据库注入提取数据;生产环境时间盲注实测;密码爆破(属渗透流程);扫描超出授权范围的任何资产。
- **目录约定**:`scans/` 存原始扫描输出,`evidence/` 存人工验证证据(文件名带漏洞编号),报告引用两者。

## 五阶段评估流水线

### 阶段 1:资产清点

```bash
# 授权网段内存活主机(ICMP/ARP/TCP 混合发现)
nmap -sn <cidr> -oA scans/stage1_nmap

# 同网段视角:ARP 发现,可找到禁 ping 主机
sudo arp-scan <cidr> > scans/stage1_arp.txt

# 外部资产:子域名收集与收敛(纯被动,不留扫描痕迹)
assetfinder --subs-only <domain> > scans/subs_assetfinder.txt
amass enum -passive -d <domain> -o scans/subs_amass.txt
sort -u scans/subs_assetfinder.txt scans/subs_amass.txt > scans/subs_all.txt

# 过滤出存活的 Web 资产(按授权范围人工核对后)
cat scans/subs_all.txt | httpx -silent -sc -title -tech-detect -ip > scans/web_alive.txt
```

**产出**:`hosts_alive.txt`——经授权范围核对后的可扫描资产清单(后续所有命令的目标来源)。

### 阶段 2:服务识别

```bash
# 全 TCP 端口发现(快扫,只列开放端口)
nmap -p- --min-rate 2000 --open -oA scans/stage2_ports <ip>

# 对发现端口做版本+默认脚本精扫(-sC 为安全脚本组)
nmap -sV -sC -p <found_ports> -oA scans/stage2_services <ip>

# UDP 高频端口(需 root,慢,只做 top N)
sudo nmap -sU --top-ports 50 --open -oA scans/stage2_udp <ip>

# Web 资产指纹,为阶段 3 选择专项扫描器做准备
whatweb -a 3 http://<ip>:<port>
```

**产出**:`stage2_services.xml`——所有后续 CVE 比对与漏洞扫描的数据源。

### 阶段 3:漏洞扫描

```bash
# 网络服务层:内置 vuln 类脚本(SMB/RDP/TLS/FTP 等已知漏洞)
nmap --script vuln -p <found_ports> <ip> -oA scans/stage3_nse

# 版本比对 CVE 清单(候选,需阶段 4 复核)
nmap -sV --script vulners -p <found_ports> <ip>

# Web 层:模板化扫描,只收中危及以上
nuclei -l scans/web_alive.txt -tags cve,exposure,misconfig -severity critical,high,medium -o scans/stage3_nuclei.txt

# TLS 层
testssl.sh --severity HIGH --htmlfile scans/stage3_tls.html <host>:443

# 全量兜底:OpenVAS(GVM)任务安排在授权的夜间窗口,见工具详解
```

**分层覆盖原则**:网络服务用 NSE/vulners,Web 用 nuclei,加密层用 testssl.sh,补丁级全量用 OpenVAS(有凭据时优先凭据扫描)。

### 阶段 4:误报验证

**验证原则**(本阶段核心纪律):

1. 只证明**存在性**,不利用:不 getshell、不提权、不导数据、不横向移动、不留任何持久化。
2. 优先级:危急/高危 100% 人工复核;中危抽查;低危可标注"仅扫描器报告,未复核"。
3. 版本匹配类(OpenVAS CPE / vulners / vulscan)误报率最高:以实测 banner/响应头版本为准,对照厂商 advisory 的受影响区间(注意区间开闭与小版本)。
4. 状态码/内容匹配类(nuclei exposure、misconfig 模板)一般可信,仍需人工复现一次作为证据。
5. 验证替代方案:写操作类漏洞用"版本证明"替代"利用证明"(版本落在受影响区间即成立,不执行写入)。
6. 证据四要素:**命令(可复现)+ 关键输出 + 时间戳 + 来源(扫描器/人工)**,存 `evidence/VULN-<nnn>_*.txt`。

```bash
# 版本复核:提高探测强度重取 banner,并与厂商 advisory 区间比对
nmap -sV --version-all -p <port> <ip>

# HTTP 证据留存示例见 curl 工具详解;公开 PoC 存在性核验
searchsploit <service> <version>
```

### 阶段 5:报告产出

- 同一 CVE 命中多资产时合并为一条漏洞,资产列表化;同一资产多漏洞按 CVSS 排序。
- 每条漏洞给出 CVSS 基础分 + 向量串,并在"暴露面/资产重要性"上做环境修正说明(同一漏洞在 DMZ 与纯内网资产分级呈现)。
- 修复建议区分"版本升级"与"临时缓解",给到具体版本号或配置项。
- 按模板(见文末)填充,漏洞编号 VULN-001 起连续分配,复测时沿用编号追加复测结果。

## 核心工具详解

### nmap — 资产清点、服务识别与 NSE 漏洞检查的一体化基线

**用途**:主机发现、端口/服务/版本识别、内置 `vuln` 类脚本检查网络层已知漏洞(SMB 永恒之蓝、Heartbleed、RDP MS12-020、SMB 签名缺失等)。阶段 1–3 的主干。
**安装**:Kali 默认已装(`sudo apt install nmap`)。
**使用场景**:任何评估的第一步;比全量扫描器轻量可控,单点高危 CVE 检查首选。

```bash
# 阶段1:网段存活主机清点(不扫端口)
nmap -sn 192.168.1.0/24 -oA scans/discovery

# 阶段2:全端口 + 版本精扫
nmap -p- -sV -sC --min-rate 2000 --open -oA scans/full_tcp <ip>

# 阶段2:UDP top 端口(需 root)
sudo nmap -sU --top-ports 50 --open -oA scans/udp_top <ip>

# 阶段3:运行全部 vuln 类脚本(部分脚本有侵入性,生产环境先约窗口)
nmap --script vuln -p 80,135,445,3389 <ip> -oA scans/vuln_nse

# 单点检查:SMB 永恒之蓝 / TLS Heartbleed / RDP MS12-020 / SMB 安全模式
nmap -p 445 --script smb-vuln-ms17-010 <ip>
nmap -p 443 --script ssl-heartbleed <ip>
nmap -p 3389 --script rdp-vuln-ms12-020 <ip>
nmap -p 445 --script smb-security-mode <ip>

# 快速从结果里筛漏洞命中
grep -i 'vulnerable' scans/vuln_nse.nmap
```

**实战要点**:
- `-sV` 是版本比对类检测的前提,缺了它多数 NSE 漏洞脚本与 vulners/vulscan 都不生效。
- `vuln` 类别含 intrusive 脚本;保守环境先跑 `nmap --script safe -p <ports> <ip>`。
- `-oA <basename>` 同时生成 .nmap/.gnmap/.xml,xml 用于解析入库与报告生成。
- 全端口快扫后按端口做二次 `-sV --version-all` 精扫,可显著降低版本识别误报。

### nuclei — 模板驱动的 Web 漏洞/暴露面/配置缺陷扫描

**用途**:基于 yaml 模板批量检测 CVE、信息暴露、错误配置、子域接管等;模板带 severity/tags 元数据,天然适合分级出报告。
**安装**:`sudo apt install nuclei`(模板需联网更新)。
**使用场景**:阶段 3 Web 层主力;模板生态(官方 + 社区)覆盖远超同类;结果可直接映射报告字段。

```bash
nuclei -update-templates

# 对全部存活 Web 资产扫 CVE+暴露+配置缺陷,只收中危及以上
nuclei -l scans/web_alive.txt -tags cve,exposure,misconfig -severity critical,high,medium -o scans/nuclei_high.txt

# JSONL 结构化输出,便于脚本解析合并进报告
nuclei -l scans/web_alive.txt -tags exposure,misconfig,takeover,default-logins -jsonl -o scans/nuclei.jsonl

# 单目标:先指纹后按目录精扫
nuclei -u https://<domain> -tags tech
nuclei -u https://<domain> -t ~/nuclei-templates/http/cves/2021/ -severity critical,high

# 生产环境控速:每秒请求上限 50,并发 25
nuclei -u https://<domain> -tags cve -rl 50 -c 25
```

**实战要点**:
- 命中记录中的模板 ID/名称(如 `CVE-2021-41773.yaml`)要写进报告"发现方式",复测可复现。
- exposure/misconfig 类命中多为确定性证据,但仍需 curl 复现一次并截图/存输出。
- `-tags tech` 指纹结果可用于决定是否追加 wpscan/droopescan 等专项。
- 模板持续更新,评估当天先 `-update-templates`,报告中注明 nuclei 版本与模板日期。

### OpenVAS / Greenbone(GVM)— 企业级全量漏洞扫描与报告体系

**用途**:全量网络漏洞扫描器(NVT 数万条),含资产库、任务调度、凭据扫描、PDF/CSV/XML 报告导出,是合规评估的"兜底全量"工具。
**安装**:`sudo apt install openvas`(Kali 打包为 GVM 体系)。
**使用场景**:需要覆盖"缺补丁/服务漏洞/配置基线"的全面清单、客户要独立扫描器报告、或资产量大需要任务化管理时。

```bash
sudo apt install openvas
sudo gvm-setup            # 首次初始化:下载 NVT/feed,可能超过 30 分钟
sudo gvm-check-setup      # 安装自检
sudo gvm-start            # 启动服务
# Web 控制台(GSA,自签证书):https://127.0.0.1:9392

sudo greenbone-nvt-sync   # 更新漏洞库

# GMP 命令行(脚本化取任务/报告)
gvm-cli tls --hostname 127.0.0.1 --gmp-username admin --gmp-password <password> --xml '<get_tasks/>'
```

**实战要点**:
- GSA 建任务路径:Configuration → Targets 填资产 → Tasks 新建任务 → Scan Config 选 "Full and fast"。
- 授权若提供系统凭据,配置 Credential 扫描(如 SMB/SSH 登录),补丁缺失类结果准确度大幅提升、误报骤降。
- CPE 版本匹配误报率高(尤其小版本号探测缺失),高危项必须进入阶段 4 人工复核后才入报告。
- 报告在 GSA Reports 页导出 CSV 去重合并;大网段任务注意并发/超时配置并安排夜间窗口。

### masscan — 大范围资产快速端口清点

**用途**:对 /16 及以上网段做高速 TCP 端口发现,速率可达万级 pps;只做端口发现,不做版本/漏洞。
**安装**:Kali 默认已装(`sudo apt install masscan`)。
**使用场景**:授权网段大、评估窗口短;先 masscan 圈出开放端口,再交 nmap 精扫。

```bash
# 高速端口清点(速率必须与客户网络团队确认)
sudo masscan <cidr> -p80,443,8000-8100 --rate=10000 -oL scans/masscan_ports.txt

# 排除不可触碰网段
sudo masscan <cidr> -p80,443 --rate=5000 --excludefile scope_exclude.txt -oL scans/ports.txt
```

**实战要点**:
- `--rate` 过高会打瘫老旧网络设备,生产环境从 1000 起步,并对齐授权书中的速率上限。
- 服务识别能力弱于 nmap,标准流水线:masscan 发现端口 → 提取 IP/端口 → `nmap -sV -sC -p<ports> -iL hosts.txt` 精扫。
- `-oL` 列表格式易解析;扫描源特征明显(SYN flood 相似),确保扫描出口 IP 在授权范围备案。
- 不支持 UDP 有效扫描,UDP 覆盖仍需 nmap -sU。

### vulners.nse / vulscan — nmap 版本比对 CVE 匹配(第三方 NSE)

**用途**:基于 `-sV` 识别出的产品+版本,比对 Vulners 在线库或本地 CVE/exploitdb 库,输出候选 CVE 列表。
**安装**:

```bash
# vulners.nse(Vulners 在线 API)
sudo wget -O /usr/share/nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
sudo nmap --script-updatedb

# vulscan(本地库,可离线)
git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan
sudo nmap --script-updatedb
```

**使用场景**:已拿到服务清单,需要快速给全部服务拉一份"候选 CVE"初筛,再排优先级深挖时。

```bash
nmap -sV --script vulners -p 80,443,8080 <ip>
nmap -sV --script vulscan -p 22,80,443 <ip>

# vulscan 指定本地库
nmap -sV --script vulscan --script-args 'vulscandb=cve.csv' -p 80 <ip>
```

**实战要点**:
- 必须 `-sV`,否则无版本信息可匹配。
- 输出语义是"该版本可能受影响的 CVE",非确认漏洞;入报告前逐条核对实际版本是否落在受影响区间。
- vulners 走在线 API(需外网),离线环境用 vulscan。
- 结果与 OpenVAS 高危项交叉比对,双源同时命中的项优先人工验证。

### searchsploit — 离线 Exploit-DB 检索(验证与修复优先级佐证)

**用途**:本地检索公开 exploit/PoC,用于确认"该 CVE 是否有公开利用代码",佐证可利用性评级与修复优先级;只检索,不执行。
**安装**:Kali 默认已装(包名 `exploitdb`)。
**使用场景**:阶段 4 判定某个 CVE 的实际威胁等级时(有公开 RCE PoC 的版本匹配命中,优先级显著上调)。

```bash
searchsploit <service> <version>       # 例: searchsploit apache 2.4.49
searchsploit --cve 2021-41773          # 按 CVE 编号反查
searchsploit -t "remote code execution"  # 只搜标题
searchsploit -x 50383                  # 查看条目详情
searchsploit -m 50383                  # 复制到当前目录供审阅代码
searchsploit -u                        # 更新本地库
```

**实战要点**:
- 评估报告中"参考"字段可直接引用 Exploit-DB 条目编号(EDB-ID)。
- 有 PoC ≠ 漏洞存在:仍是版本匹配逻辑,先复核版本再看 PoC。
- 检出的 exploit 代码仅用于阅读理解触发条件(帮助写漏洞描述),不运行。

### whatweb — Web 指纹识别

**用途**:识别 Web 资产的服务器/CMS/框架/JS 库及版本,是 Web 漏洞匹配与专项扫描器选择的前置。
**安装**:Kali 默认已装(`sudo apt install whatweb`)。
**使用场景**:拿到 URL 清单后先指纹,再决定走 nuclei 通用模板还是 wpscan/droopescan 等专项。

```bash
whatweb -a 3 http://<ip>:<port>          # -a 3 更激进(请求量增大,注意窗口)
whatweb --no-errors -i scans/web_alive.txt | sort -u
```

**实战要点**:
- `-a` 1(默认隐蔽)到 4(重度)递增,生产环境保守用默认。
- 指纹结果与 nuclei `-tags tech` 交叉确认,双源一致才作为版本类漏洞判定依据。
- 输出直接抄进报告"资产清单"的版本列,并注明指纹来源。

### nikto — Web 服务器配置与已知漏洞检查

**用途**:检查 Web 服务器层配置缺陷与已知问题:危险方法、默认安装文件、信息泄露头、过时软件提示等。
**安装**:Kali 默认已装(`sudo apt install nikto`)。
**使用场景**:对每个 Web 端口做一次服务器层体检,补充 nuclei 侧重应用层的不足。

```bash
nikto -h http://<ip>/ -o scans/nikto.html -Format html
nikto -h <ip> -p 80,443,8000,8080,8443 -Tuning x6   # x6 排除 DoS 类测试
```

**实战要点**:
- 输出噪音大,大量条目为 informational;报告只收 misconfiguration / OSVDB 漏洞类条目。
- 条目基于字符串匹配,误报常见,入报告前逐条 curl 复核。
- `-Format` 可选 html/csv/txt/json,`-o` 落盘存 `scans/`。
- 与授权对齐: nikto 会产生大量 404 探测请求,避免高峰期跑。

### wapiti — Web 应用黑盒漏洞扫描(可限定模块与范围)

**用途**:爬虫式 Web 应用漏洞扫描,支持 SQL 注入、XSS、命令执行、文件处理、备份文件、SSRF、开放重定向等模块,发现项自带请求/响应证据。
**安装**:`sudo apt install wapiti`。
**使用场景**:授权范围明确到某个应用、需要应用层注入类检查但不开利用时;范围控制粒度比 nikto 细。

```bash
wapiti -u <url> --scope folder -m "sql,xss,exec,file,backup,ssrf,redirect" -f json -o scans/wapiti.json
```

**实战要点**:
- `--scope` 取值 page/folder/domain/url,严格对齐授权范围,domain 会扩到整站。
- 发现项自带证据(HTTP 请求/响应),可直接截取进报告"证据"字段。
- `-m` 关闭不需要的模块可显著减少请求量;注入探测对生产库有风险时,只保留 backup/redirect/file 等无副作用模块。

### testssl.sh — TLS/SSL 配置与已知漏洞全量审计

**用途**:一次性审计 TLS 协议版本、套件强度、证书链、renegotiation、Heartbleed/ROBOT/CCS 等已知 TLS 漏洞,输出即报告素材。
**安装**:`sudo apt install testssl.sh`(命令名含 .sh)。
**使用场景**:所有 HTTPS/SMTPS/STARTTLS 端口的加密层评估;产出直接映射报告"漏洞描述+证据"。

```bash
testssl.sh <host>:443
testssl.sh --severity HIGH --htmlfile scans/testssl.html <host>:443   # 只显示 HIGH 及以上
testssl.sh -U <host>:443                          # 集中跑漏洞类检查(Heartbleed/CCS/旧协议/弱套件)
testssl.sh --file scans/tls_targets.txt           # 批量
```

**实战要点**:
- 输出含每个问题的明确结论与证据(握手报文摘要),报告直接引用。
- 弱协议(TLS1.0/1.1)、弱套件、自签/过期证书、缺失 HSTS 均为可报告配置缺陷,给配置级修复建议。
- 与 sslscan 交叉复核单点结论;批量时 `--parallel` 加速仍需限速。

### wpscan — WordPress 专项漏洞与枚举

**用途**:枚举 WordPress 用户、插件、主题、配置备份,并比对漏洞库报告易受攻击的插件/主题版本。
**安装**:`sudo apt install wpscan`。
**使用场景**:whatweb/nuclei 确认为 WordPress 后的专项深扫。

```bash
# 枚举用户/易受攻击插件/易受攻击主题/配置备份/数据库导出
wpscan --url <url> --enumerate u,vp,vt,cb,dbe

# 全量插件被动检测 + API 提升漏洞库比对准确度
wpscan --url <url> --enumerate ap,at --plugins-detection passive --api-token <token>
```

**实战要点**:
- 免费注册获取 API token(Wordfence Intelligence),无 token 时漏洞比对数据受限且过期。
- `vp/vt` 结果基于插件版本号,版本探测失败的条目必须人工确认(读插件 readme/静态资源路径)。
- `--plugins-detection aggressive` 请求量大,生产环境默认用 passive,窗口允许再升级。
- 枚举出的用户名列表属于信息泄露证据,与登录页一起留存。

### sslscan — 快速 TLS 套件与证书检查

**用途**:快速列出目标支持的协议版本、加密套件、证书信息,适合单点确认与复核。
**安装**:`sudo apt install sslscan`。
**使用场景**:testssl.sh 已给出全量报告后,对单条结论做快速复现取证。

```bash
sslscan --no-failed <host>:443                  # 只列成功协商的套件
sslscan --show-certificate <host>:443 | grep -iE 'issuer|subject|valid'   # 证书关键字段
```

**实战要点**:
- 支持任意 `<host>:<port>`,对非 443 的 TLS 服务(8443、数据库 TLS 端口)同样适用。
- `--no-failed` 让输出只剩实际可协商套件,直接作为"弱套件仍启用"的证据。
- 深度分析(漏洞链、报告)仍以 testssl.sh 为准,sslscan 用于快速复核。

### rustscan — 快速全端口扫描并自动转交 nmap

**用途**:单主机全端口高速发现,发现的端口自动交给 nmap 完成版本/脚本扫描。
**安装**:`sudo apt install rustscan`。
**使用场景**:单机/少量主机的全端口评估,比 `nmap -p-` 快一个量级且保留 nmap 生态。

```bash
# 全端口发现后自动执行 nmap 精扫(-- 之后参数原样传给 nmap)
rustscan -a <ip> -r 1-65535 --ulimit 5000 -- -sV -sC -oA scans/rustscan_full
```

**实战要点**:
- `--ulimit 5000` 防止文件句柄耗尽报错。
- 速率高但不如 nmap 稳定可控,面向互联网的授权目标注意限速参数。
- 输出与 nmap 完全兼容(`-oA`),无缝进入既有流水线。

### arp-scan — 二层资产清点(同网段/VPN 内)

**用途**:ARP 层主机发现与 MAC 厂商识别,不受目标主机 ICMP/主机防火墙策略影响。
**安装**:Kali 默认已装(`sudo apt install arp-scan`)。
**使用场景**:评估机与目标同广播域(内网接入/VPN),需要完整清点含禁 ping 主机时。

```bash
sudo arp-scan --localnet
sudo arp-scan 192.168.1.0/24
```

**实战要点**:
- 只在同一广播域有效,跨网段 ARP 不可达。
- 输出的 MAC 厂商(OUI)列可用于资产归类与虚拟机识别。
- 与 `nmap -sn` 结果对比,只在 ARP 出现而 ICMP 缺失的主机即"禁 ping"资产,单独标注。

### amass — 深度子域名枚举

**用途**:多数据源聚合的子域名枚举,支持被动收集与主动字典爆破,结果最全。
**安装**:`sudo apt install amass`。
**使用场景**:外部资产清点阶段,资产清单要求完整(尤其是客户自己都不清楚的影子资产)时。

```bash
amass enum -passive -d <domain> -o scans/subs_amass.txt
amass enum -d <domain> -brute -w <wordlist> -o scans/subs_brute.txt   # 主动枚举,请求量注意窗口
```

**实战要点**:
- `-passive` 只查第三方数据源,对目标零流量,评估前的安全选项。
- 结果必须与授权范围比对:枚举出的子域若不在授权清单,不得扫描,可列入"范围外资产建议"附录。
- 耗时较长(可能 30 分钟+),适合后台运行。

### assetfinder — 秒级被动子域名收集

**用途**:从 crt.sh、ThreatCrowd 等公开源快速拉取子域,秒级出结果。
**安装**:`sudo apt install assetfinder`。
**使用场景**:外部资产清点的第一枪,先快速圈范围再决定是否上 amass 深挖。

```bash
assetfinder --subs-only <domain> > scans/subs_assetfinder.txt
```

**实战要点**:
- 纯被动,不向目标发包。
- 结果杂音多(CNAME、历史记录),过 httpx 存活过滤后再人工核对授权范围。
- 与 amass 结果 `sort -u` 合并去重使用。

### enum4linux-ng — SMB/NetBIOS 信息泄露审计

**用途**:枚举 Windows/Samba 目标的用户、组、共享、密码策略,并检测空会话/匿名枚举等配置缺陷。
**安装**:`sudo apt install enum4linux-ng`(经典版 `enum4linux` 亦在源中,新版对新 Samba 兼容更好)。
**使用场景**:内网评估中 445/139 开放的资产;匿名可枚举本身即应报告为信息泄露漏洞。

```bash
sudo enum4linux-ng -A <ip> -oA scans/enum4linux_<ip>
```

**实战要点**:
- `-A` 为全量枚举(用户/组/共享/密码策略/空会话),`-oA` 多格式落盘(含 JSON)。
- "空会话可匿名枚举用户列表"直接作为中危信息泄露入报告,证据为枚举输出。
- 密码策略(最短长度/锁定阈值)输出可作为弱口令策略缺陷的修复依据。
- 目标开 SMB 签名与否用 `nmap -p 445 --script smb-security-mode <ip>` 交叉确认。

### curl — 手动 PoC 验证与证据留存(阶段 4 主力)

**用途**:以最小副作用复现扫描器结论,留存可复现命令与输出作为报告证据。
**安装**:Kali 默认已装。
**使用场景**:所有 HTTP 类漏洞的误报验证;任何"存在性证明"场景。

```bash
# 证据基线:记录响应头(版本暴露、安全头缺失)
curl -sI http://<ip>/ | tee evidence/VULN-001_headers.txt

# 验证危险 HTTP 方法暴露(OPTIONS 列表 / TRACE 可达 = 配置缺陷,不落利用)
curl -sI -X OPTIONS http://<ip>/ | grep -i '^allow'
curl -s -o /dev/null -w '%{http_code}\n' -X TRACE http://<ip>/

# 验证 nuclei 报告的 .git 目录泄露(只读 HEAD 一个标记文件,不整库下载)
curl -s http://<url>/.git/HEAD

# 验证目录列表开启
curl -s http://<url>/uploads/ | grep -i 'index of'

# 路径穿越类最小化验证:只读取无害标记文件等证明可读,不读敏感数据(Apache CVE-2021-41773 示例)
curl --path-as-is '<url>/cgi-bin/.%2e/.%2e/.%2e/etc/hostname'

# 记录状态码与响应时间,供修复后复测对比
curl -s -o /dev/null -w 'code=%{http_code} time=%{time_total}s ip=%{remote_ip}\n' http://<url>/
```

**实战要点**:
- 每条证据 = 命令 + 关键输出 + 时间戳(`date -Is` 记录),文件名带漏洞编号。
- 只做存在性证明:读一个标记文件、看一个状态码;不批量下载、不上传测试文件、不执行写入。
- 注入类验证最多用无害探测串(如单引号)观察报错差异判定"疑似",生产库不做数据提取,报告标注验证边界。
- 输出重定向统一 `tee` 到 `evidence/`,保证终端所见与文件一致。

### lynis — 主机层安全基线审计

**用途**:对已获得登录权限的主机做系统层加固审计,输出 Hardening Index 与逐条 WARNING/SUGGESTION 建议。
**安装**:`sudo apt install lynis`。
**使用场景**:内部评估/配置合规检查,需要把主机层问题(密码策略、权限、日志、内核参数)纳入报告时。

```bash
sudo lynis audit system
less /var/log/lynis-report.dat     # 结构化结果;日志在 /var/log/lynis.log
```

**实战要点**:
- 只审计本机,不做网络扫描;多主机逐台执行。
- report.dat 中每条建议带 TESTID,可直接映射为报告中的修复建议条目。
- WARNING 级条目对应报告"中危及以上"候选,需结合资产角色人工定级。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| netdiscover | ARP 主动/被动主机发现 | netdiscover | `sudo netdiscover -r 192.168.1.0/24` |
| dig | DNS 记录查询与 AXFR 区域传送检测 | dnsutils | `dig axfr <domain> @<ns-ip>` |
| fierce | DNS 侦察(子域+相邻网段) | fierce | `fierce --domain <domain>` |
| sublist3r | 多引擎子域名枚举 | sublist3r | `sublist3r -d <domain> -o subs.txt` |
| httpx | Web 存活/标题/技术栈批量探测 | httpx | `cat hosts.txt \| httpx -sc -title -tech-detect -ip` |
| naabu | 高性能 SYN 端口扫描 | naabu | `sudo naabu -host <ip> -top-ports 1000 -o ports.txt` |
| cmseek | CMS 识别与基础信息 | cmseek | `cmseek -u <url>` |
| joomscan | Joomla 专项漏洞扫描 | joomscan | `joomscan -u <url>` |
| droopescan | Drupal 专项漏洞扫描 | droopescan | `droopescan scan drupal -u <url>` |
| arachni | Web 应用深度扫描(AFR 报告) | arachni | `arachni <url> --report-save-path=scan.afr` |
| sslyze | TLS 服务器分析(JSON 输出) | sslyze | `sslyze --heartbleed --robot --reneg <host>:443` |
| wafw00f | WAF 产品指纹识别 | wafw00f | `wafw00f <url>` |
| netexec | SMB/WinRM 批量配置核验(空会话/签名/共享) | netexec | `netexec smb <ip> -u 'guest' -p '' --shares` |
| oscap | SCAP/XCCDF 标准合规评估 | openscap-scanner | `oscap xccdf eval --profile <profile> --report report.html <file-xccdf.xml>` |
| legion | 图形化编排 nmap/nikto/枚举 | legion | `sudo legion` |
| faraday | 多扫描器结果汇聚与协同报告 | faraday | `faraday-server`(Web 端 http://127.0.0.1:5985) |
| openssl s_client | 手动 TLS 握手与证书核验 | openssl | `echo \| openssl s_client -connect <host>:443 -servername <domain> 2>/dev/null \| openssl x509 -noout -dates` |
| redis-cli | Redis 未授权访问验证 | redis-tools | `redis-cli -h <ip> -p 6379 ping` |

## CVSS 评级速查

| Base Score | 等级 | 建议修复时限(参考) |
|---|---|---|
| 9.0–10.0 | Critical(危急) | 24–72 小时 |
| 7.0–8.9 | High(高危) | 7 天 |
| 4.0–6.9 | Medium(中危) | 30 天 |
| 0.1–3.9 | Low(低危) | 90 天或纳入下一迭代 |
| 0.0 | None | 无需处理 |

**向量串构成**(v3.1):`AV`(N 网络/A 邻接/L 本地/P 物理)· `AC`(攻击复杂度)· `PR`(所需权限)· `UI`(用户交互)· `S`(作用域 U/C)· `C/I/A`(机密性/完整性/可用性,各 N/L/H)。
示例:`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8;`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5(仅信息读取)。

```bash
# 本地计算 CVSS 基础分(pip install cvss)
python3 -c "from cvss import CVSS3; c=CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'); print(c.scores()[0], c.severities()[0])"
```

**定级纪律**:报告标注基础分+向量串(可复核);环境修正(互联网暴露、资产承载敏感数据、是否有公开 PoC)在"影响"字段用文字说明,不篡改基础分。有公开 RCE PoC 的版本匹配项(searchsploit 命中)至少按高危对待。

## 报告模板(markdown 片段)

````markdown
# 漏洞评估报告 — <客户/项目名>

| 项 | 值 |
|---|---|
| 评估日期 | <YYYY-MM-DD> ~ <YYYY-MM-DD> |
| 评估范围 | <cidr> / <domain>(以授权书 <编号> 为准) |
| 评估视角 | 远程未授权(黑盒)/ 内网 / 主机本地 |
| 使用工具 | nmap <version> / nuclei <version> / OpenVAS <version> / testssl.sh <version> |
| 报告版本 | v1.0 |

## 1. 执行摘要

本次评估共发现 <N> 个漏洞:危急 <a> / 高危 <b> / 中危 <c> / 低危 <d>。

- Top 1:<一句话风险 + 受影响资产数>
- Top 2:...
- Top 3:...

**总体建议**:<升级 X / 收敛暴露面 Y / 统一配置基线 Z>

## 2. 资产清单

| # | 资产名 | IP/域名 | 端口 | 服务 | 版本 | 暴露面 | 备注 |
|---|--------|---------|------|------|------|--------|------|
| 1 | web-01 | <ip> | 443/tcp | nginx | 1.18.0 | 互联网 | — |

## 3. 漏洞明细

### VULN-001:<漏洞标题,如 Apache 路径穿越导致任意文件读取>

- **资产**:<ip>:<port>(资产 #1)
- **风险等级**:高危 — CVSS v3.1 Base 7.5,向量:`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **漏洞描述**:<2–3 句:成因 + 触发条件 + 受影响版本区间>
- **发现方式**:nuclei 模板 `CVE-2021-41773.yaml` / OpenVAS NVT OID <oid> / 人工核查
- **验证状态**:已人工确认(见证据)/ 仅扫描器报告,未复核
- **证据**:
  - 命令与关键输出:
    ```console
    $ curl --path-as-is 'http://<ip>/cgi-bin/.%2e/.%2e/.%2e/etc/hostname'
    web-01
    ```
  - 时间:<YYYY-MM-DD HH:MM TZ>(evidence/VULN-001_hostname.txt)
- **影响**:<信息泄露范围 / 可能的链式利用方向(仅文字描述,不演示)>
- **修复建议**:
  1. 升级 Apache httpd 至 2.4.51 及以上;
  2. 短期缓解:移除或收紧 `<Directory /cgi-bin>` 挂载,拒绝 `.%2e` 形态请求;
- **参考**:CVE-2021-41773、EDB-50383、<厂商 advisory URL>
- **复测**:待修复后复测 □ 通过 □ 未通过(复测沿用本编号)

## 4. 修复优先级路线图

| 优先级 | 漏洞编号 | 建议完成时限 | 负责人 |
|---|---|---|---|
| P0 | VULN-001 | <YYYY-MM-DD> | <owner> |

## 5. 复测计划

复测窗口 <date>:对每条漏洞重跑原始命令/模板,对比证据输出,更新"复测"字段并出复测版报告(v1.1)。
````

---

本文件仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景。
