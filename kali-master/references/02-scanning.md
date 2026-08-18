# 网络与漏洞扫描(Network & Vulnerability Scanning)

> **何时读本文件**:已确定目标范围后,需要做主机发现、端口/服务扫描(nmap/masscan)、自动化侦察(autorecon)、服务枚举(SMB/SNMP/SMTP)、SSL/TLS 审计或系统性漏洞扫描(GVM/OpenVAS)时读本文件;扫描结果如何导向利用见"扫描结果 → 下一步利用衔接"一节。基于模板的 Web 漏洞扫描(nuclei)见 `03-web-testing.md`。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| 全端口高速扫描 | masscan | nmap `-T5`、unicornscan | masscan 速率最高;nmap 结果信息最全 |
| 单目标深度识别(版本/OS/NSE) | nmap `-sV -A` | autorecon | nmap 手动精细控制;autorecon 一键全套 |
| 大网段"先找端口再精查" | masscan + nmap 分工 | autorecon -t <file> | masscan 找开放端口,nmap -sV 只扫命中端口 |
| CTF/OSCP 单机全流程枚举 | autorecon | legion(GUI) | autorecon 输出结构化目录,CLI 可复现 |
| Windows/Samba 信息枚举 | enum4linux-ng | enum4linux、nbtscan | ng 支持 JSON 输出/凭证/Kerberos |
| SNMP 枚举 | snmp-check | onesixtyone(猜社区串)、braa(大规模) | snmp-check 输出最可读 |
| SMTP 用户枚举 | smtp-user-enum | swaks(交互测试)、mxcheck(面检) | smtp-user-enum 批量 VRFY/EXPN |
| SSL/TLS 配置审计 | sslscan | sslyze、tlssled | sslscan 快;sslyze 报告细;tlssled 老牌封装 |
| WAF 识别 | wafw00f | nmap `--script http-waf-fingerprint` | wafw00f 指纹库专门化 |
| 系统性 CVE 漏洞扫描 | gvm(Greenbone/OpenVAS) | nmap `--script vuln` | GVM 走完整漏洞库;nmap 快速点名 |
| IPsec VPN(IKE)发现 | ike-scan | nmap -sU -p 500,4500 | ike-scan 可指纹厂商 + 抓 PSK 哈希 |
| Oracle TNS(1521)枚举 | tnscmd10g | sidguess、oscanner | tnscmd10g 探版本/sidguess 猜 SID/oscanner 测口令 |
| Apache 用户目录枚举 | apache-users | nmap `--script http-userdir-enum` | 同类功能,NSE 更易集成 |
| IPv6 主机发现 | thc-ipv6 套件(alive6) | nmap -6 | alive6 利用 ICMPv6 发现链路本地存活 |
| SCTP 扫描 | sctpscan | nmap -sY | SCTP 为电信/信令场景专用协议 |
| 扫描结果周期对比 | ndiff | grep -oG 输出 | ndiff 专门对比 nmap XML |

## 扫描结果 → 下一步利用衔接

扫描阶段的产出(开放端口、服务版本、用户名列表、SNMP 社区串、PSK 哈希、CVE 列表)是后续利用的直接输入:

| 扫描发现 | 指向的下一步 |
|---|---|
| `nmap -sV` 的产品与版本 | `searchsploit <product> <version>`、MSF `search` 查公开漏洞,命中后转对应利用分册 |
| 445/tcp open 且 `smb-vuln-ms17-010` 命中 | MS17-010(永恒之蓝)利用链 |
| SMB 空会话可枚举(enum4linux) | 用户列表/共享列表 → `smbclient` 深挖共享内容、用户名列表做凭证喷洒 |
| SNMP 有效社区串 | `snmp-check` 全量枚举 → 路由表/接口/进程还原内网拓扑与运行服务 |
| SMTP VRFY/EXPN 命中用户 | 用户名列表 → 密码喷洒、钓鱼前期情报 |
| sslscan/sslyze 报 heartbleed/弱套件/旧协议 | 跑对应公开 PoC 验证;证书 CN/SAN 并入子域名资产清单 |
| 1521/tcp TNS 开放 | tnscmd10g status → sidguess 猜 SID → oscanner/sqlplus(数据库分册) |
| 500/4500/udp IKE 响应 Aggressive Mode | `ike-scan -A -P` 抓 PSK 哈希 → `psk-crack` 离线破解 → 接入 VPN |
| GVM 报告的 CVE | 优先验证有公开 exploit 的条目;注意扫描器误报需人工确认 |
| `wafw00f` 检出 WAF | 调整 Web 攻击策略(编码混淆/分块传输/直连源站) |
| autorecon 的 results 目录 | 逐个 scans/ 输出按对应分册深挖(HTTP/SQL/SMB 等) |
| nmap `-oA` 留档的 XML | `ndiff` 周期对比发现新增端口,导入其他工具复用 |

## 核心工具详解

### nmap — 网络扫描事实标准:主机发现、端口扫描、版本/OS 识别、NSE 脚本

**用途**:主机存活探测、十几种端口扫描技术(SYN/Connect/UDP/ACK 等)、服务版本探测(`-sV`)、OS 指纹(`-O`)、NSE 脚本引擎(vuln/auth/brute/exploit 等分类,数百个脚本)。渗透测试中使用频率最高的扫描器。
**安装**:Kali 默认已装(`nmap` 包,含 ncat/nping/ndiff)。
**使用场景**:任何需要"知道目标开了什么、跑的什么版本、有什么已知漏洞"的场景;精确控制扫描行为(时序/分片/诱饵)时不可替代。

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

NSE 脚本引擎(常用模式):

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

时序模板 `-T0` ~ `-T5`:

```bash
# -T0 paranoid 极慢(IDS 规避) | -T1 sneaky 慢速隐蔽
# -T2 polite 降速礼让 | -T3 normal 默认
# -T4 aggressive 局域网推荐 | -T5 insane 最快、可能漏报端口
nmap -T4 -sV -p <ports> <target>
```

输出格式:

```bash
# 三种格式同时输出:txt(XML 给 ndiff/工具导入,greppable 给 grep)
nmap -sV -p <ports> -oA <output-prefix> <target>

# grepable 输出快速提取开放端口
nmap -p- --open -oG - <target> | grep "/open/"
```

**实战要点**:
- 标准节奏三步走:先 `-sn` 确认存活 → 再 `-p-` 全端口 → 最后对开放端口 `-sV -sC` 精查;比直接 `-A` 全端口快一个量级
- `filtered` 状态多为防火墙拦截;`-Pn` 可跳过主机发现强扫(目标禁 ping 时必加)
- `-sV` 的版本号是 `searchsploit` 的直接输入,版本探测越准(`--version-intensity` 调高),后续利用越准
- 务必 `-oA` 留档:XML 供 `ndiff` 与自动化工具复用;`-v` 实时观察发现,避免长时间黑盒等待

### masscan — 异步 SYN 大规模端口扫描器

**用途**:以极高发包速率(可内网数万 packets/s)扫描大地址段,输出类似 nmap 的开放端口结果。适合全端口/大网段首扫。
**安装**:`sudo apt install masscan`。
**使用场景**:目标数量多或需要 65535 全端口时,先用 masscan 找开放端口,再交给 nmap 做版本识别;单目标小范围直接用 nmap 即可。

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

**实战要点**:
- `--rate` 按带宽定:千兆内网约 10000 起步,公式约为 带宽/8/64;超速丢包会产生漏报
- masscan 只回答"端口开没开",不做服务识别;命中后把端口列表交给 `nmap -sV -p<ports> --open` 深挖
- `--banners` 只对部分协议有效,且显著降速;需要完整指纹时仍交给 nmap
- 参数风格刻意兼容 nmap(`-p`、`--open-only`、`--exclude` 等),便于管道式分工

### unicornscan — 用户态异步 TCP/IP 信息收集引擎

**用途**:用户态分布式 TCP/IP 栈,异步发包 + 关联引擎,高速端口/协议扫描。
**安装**:`sudo apt install unicornscan`。
**使用场景**:与 masscan 同类的异步高速扫描器;需要精细控制模式标记与速率时的备选。

```bash
# 官网模式:TCP SYN+FIN 标记扫描全部 65535 端口,1000 packets/s
sudo unicornscan -mTsf -Iv -r 1000 <target>:a

# UDP 模式扫指定端口
sudo unicornscan -mU -p 161,500 <target>
```

**实战要点**:
- 语法要点:`:a` = 全部 65535 端口;`-r 1000` = 每秒 1000 包;`-Iv` = 结果立即打印
- `-mT` 为 TCP 扫描模式,后接标志位字母组合(如 `sf` = SYN+FIN)
- 定位与 masscan 重叠:负责"快找开放端口",服务识别仍交 `nmap -sV`

### autorecon — 多线程自动化网络侦察(CTF/OSCP 首选)

**用途**:对目标自动跑端口扫描 + 按服务类型并发执行大量枚举插件(HTTP/SMB/SNMP/SMTP 等),输出结构化结果目录。
**安装**:`sudo apt install autorecon`。
**使用场景**:单台/少量目标(CTF、OSCP 考试、授权单机评估)想"挂机铺面"时;大规模网段更适合 masscan + 脚本分工。

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

**实战要点**:
- 结果默认写入 `./results/<ip>/`:`scans/` 下每个插件一个输出文件,`_commands.log` 记录全部执行的命令(可直接抽出来手动复现、改参重跑)
- 用法是"先 autorecon 铺面,再对可疑服务手动深挖",不要只看它的汇总
- `-m`(最大并发扫描)/`-mp`(端口扫描并发)控制负载;目标多时下调避免打挂脆弱服务
- 对每类服务它调用的就是本分册这些工具(nmap/enum4linux/snmpcheck 等),输出格式互相一致

### gvm — Greenbone 漏洞管理平台(前称 OpenVAS)

**用途**:企业级漏洞扫描框架,基于完整 CVE/NVT/SCAP 数据库做认证与非认证扫描,产出结构化漏洞报告。
**安装**:`sudo apt install gvm`(Kali 非默认)。
**使用场景**:需要系统性 CVE 扫描与报告(而不是 nmap 脚本式快速点名)时;Web UI 建任务,CLI 做自动化。

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

**实战要点**:
- 服务起来后浏览器访问 Greenbone Security Assistant:`https://127.0.0.1:9392`(自签证书,忽略告警);admin 初始密码看 `gvm-setup` 输出
- 建任务流程:Configuration → Targets(可带凭证做认证扫描)→ Scan Configs 选 "Full and fast" → Tasks 新建并启动
- 扫描器有误报:报告中的 CVE 优先人工核对版本,再 `searchsploit`/MSF 验证有公开利用的条目
- 与 nmap `--script vuln` 互补:GVM 覆盖全、出报告;nmap 快、可嵌入侦察流程

### enum4linux — Windows/Samba 信息枚举(经典版)

**用途**:封装 smbclient/rpcclient/net/nmblookup,枚举 Windows/Samba 的用户、组、共享、密码策略、OS 信息。
**安装**:`sudo apt install enum4linux`。
**使用场景**:目标开放 139/445 且允许空会话时的第一轮 SMB 信息收集;老环境(Samba 3/XP/2003)效果最好。

```bash
# 官网模式:枚举用户列表 + OS 信息
enum4linux -U -o <ip>

# 全量简单枚举(用户/组/共享/密码策略等)
enum4linux -a <ip>

# 带凭证枚举(空会话被禁时)
enum4linux -a -u <user> -p <pass> <ip>
```

**实战要点**:
- `-P` 密码策略输出(锁定阈值/最短长度)直接决定后续凭证喷洒的节奏参数
- 共享列表 → `smbclient` 逐个深挖可写共享;用户列表 → 凭证攻击分册
- 对现代 Windows(SMBv3/签名强制)常枚举失败(RPC_S_ACCESS_DENIED),换 enum4linux-ng 或带凭证重试
- 输出冗长,重点看 `[+] Got domain/workgroup name`、用户列表和 share 枚举三段

### enum4linux-ng — 新一代 Windows/Samba 枚举(推荐)

**用途**:enum4linux 重写版,增加 JSON/YAML 导出、Kerberos 票据/NTLM 认证、逐项成功标记。
**安装**:`sudo apt install enum4linux-ng`。
**使用场景**:默认优先用 ng;需要机器可读输出或域环境凭证枚举时必用。

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

**实战要点**:
- 输出对每个枚举项标注成功/失败原因(如 "5xx ACCESS_DENIED"),比旧版更易判断被哪层挡住
- `-oJ` 的 JSON 可直接被自动化流水线消费;用户+组+密码策略三件套是凭证攻击的直接输入
- 域环境下优先用域凭证(不加 `--local-auth`);本地账户才加

### nbtscan — NetBIOS 名称表网段扫描

**用途**:向 IP 段发 NetBIOS 状态查询,返回 IP、NetBIOS 计算机名、登录用户名、MAC。
**安装**:`sudo apt install nbtscan`。
**使用场景**:内网快速圈出 Windows 主机与当前登录用户;比完整 SMB 枚举轻量得多。

```bash
# 扫描整个网段的 NetBIOS 名称表
sudo nbtscan -r 192.168.1.0/24

# 单目标详细输出
nbtscan -v <ip>
```

**实战要点**:
- 名称后缀含义:`<03>` 消息服务(常暴露当前登录用户名),`<20>` 文件共享服务(值得 enum4linux 深挖),`<1B>` 域控制器
- 输出直接给"主机名 → 用户名"映射,是内网横向移动的定位输入
- 仅依赖 NetBIOS(UDP 137),现代 Windows 若禁用 NetBIOS over TCP/IP 则无响应

### snmp-check — SNMP 设备枚举(人类可读输出)

**用途**:类似 snmpwalk 但输出分节格式化:系统信息、网络接口、IP、路由表、TCP/UDP 监听端口、进程、挂载点、软件等。
**安装**:`sudo apt install snmpcheck`(二进制命令名 snmp-check)。
**使用场景**:已确认 161/udp 开放且拿到社区串后的全量信息提取;输出可直接进报告。

```bash
# 官网模式:public 社区串枚举
snmp-check <ip> -c public

# 检查社区串是否具有写权限
snmp-check <ip> -c <community> -w
```

**实战要点**:
- 路由表和接口表是还原内网拓扑的第一手材料;进程列表常暴露运行的安全软件(绕过依据)
- `-w` 若报可写:旧设备可改配置甚至触发 RCE,属高危发现
- 输出包含系统描述(sysDescr)即 OS/内核版本 → 转 `searchsploit`

### onesixtyone — 极快的 SNMP 社区串猜解器

**用途**:异步发送 SNMPv1/2c 请求猜解社区串,整 C 段扫完只要几秒。
**安装**:`sudo apt install onesixtyone`。
**使用场景**:161/udp 开放但不知道社区串时;命中后再用 snmp-check/snmpwalk 深挖。

```bash
# 字典爆破社区串(主机列表 + 社区串列表)
onesixtyone -c <community-wordlist> -i <target-file>

# 单目标
onesixtyone -c <community-wordlist> <ip>
```

**实战要点**:
- 候选词表优先放 public/private/cisco/管理名等常见默认值;Seclists 的 SNMP 目录有现成字典
- 对网段跑前先确认授权与阈值:高速 UDP 包对老设备可能有压力
- 命中输出形如 `192.168.1.2 [public] Linux ...`,把社区串记入文档供后续所有 SNMP 操作复用

### braa — 单进程大规模 SNMP 扫描器

**用途**:自带 SNMP 协议栈(不依赖 net-snmp),单进程同时查询数十上百台主机,批量验证社区串或抓取指定 OID。
**安装**:`sudo apt install braa`。
**使用场景**:已经掌握社区串、想对整个网段批量取同一 OID(sysName/接口表等)时;单目标深挖仍用 snmp-check。

```bash
# 官网模式:单目标遍历 .1.3.6 整棵树
braa public@<ip>:.1.3.6.*

# 地址段批量取 sysName(OID .1.3.6.1.2.1.1.5.0)
braa <community>@<start-ip>-<end-ip>:.1.3.6.1.2.1.1.5.0
```

**实战要点**:
- 语法 `[community@]host[:oid]`,通配 `*` 做 walk,地址段用 `-` 连接(不支持 CIDR 写法)
- 输出格式 `host:耗时:oid:value`,非常适合 grep/管道二次处理
- 协议实现"非标准",个别设备可能不响应;异常时回退 snmpwalk

### smtp-user-enum — SMTP 用户名枚举(VRFY/EXPN/RCPT)

**用途**:利用 SMTP 的 VRFY、EXPN、RCPT TO 三种方式猜测/验证用户名是否存在。
**安装**:`sudo apt install smtp-user-enum`。
**使用场景**:25/587 端口开放且 MTA 未禁用这些命令时,快速产出有效用户名列表。

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

**实战要点**:
- 命中输出 `192.168.1.25: root exists`;注意区分 "exists"(存在)与被拒(不存在/被禁)
- 产出用户名列表 → 密码喷洒与钓鱼前置;先与 mxcheck 的 VRFY 泄露检测互相印证
- 现代 MTA 常限速或对 VRFY 一律返回 252;失败先换 EXPN 再换 RCPT,全禁则转 Web 侧枚举

### swaks — SMTP 的瑞士军刀(交互式命令行测试)

**用途**:命令行构造完整 SMTP 对话,支持 STARTTLS 与多种 AUTH(PLAIN/LOGIN/CRAM-MD5 等),可在任意阶段中断。
**安装**:`sudo apt install swaks`。
**使用场景**:验证 open relay、测试认证、中继规则、逐阶段排查 SMTP 防护;替代反复手敲 `telnet <host> 25`。

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

**实战要点**:
- 中继判定看最后 RCPT 是否返回 250(accept):accept 即开放中继,高危
- `--quit-after <stage>`(HELO/MAIL/RCPT/DATA 等)精确定位哪个阶段开始被拒,顺带摸清防护设备行为
- 与 smtp-user-enum 衔接:枚举出的用户名用 swaks 逐个验证 RCPT 与认证

### mxcheck — 邮件服务器信息与安全体检

**用途**:一站式检查邮件域名:A/MX/PTR/SPF/MTA-STS/DKIM/DMARC、ASN、StartTLS 与证书、25/465/587 端口、黑名单、VRFY 信息泄露、开放中继。
**安装**:`sudo apt install mxcheck`。
**使用场景**:面向域名做邮件基础设施面检,快速产出邮件安全概览。

```bash
# 域名邮件安全体检(自动解析 MX 后逐项检查)
mxcheck --domain <domain>
```

**实战要点**:
- 一次跑齐 DNS 记录合规性、TLS 配置与黑名单,适合报告中的邮件章节骨架
- 指出的 VRFY 泄露/open relay 再用 swaks 交互验证,避免单工具误判
- SPF `+all`/DMARC `p=none` 属可写进报告的配置缺陷

### sslscan — SSL/TLS 套件与证书快速探测

**用途**:探测目标支持的协议版本、加密套件、密钥交换、签名算法与证书详情,标出弱点,可输出 XML。
**安装**:`sudo apt install sslscan`。
**使用场景**:对 HTTPS/SMTPS 等任意 TLS 服务做快速配置审计;批量检查首选。

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

**实战要点**:
- 输出直接标红弃用协议(SSLv2/v3、TLS 1.0/1.1)与弱套件(NULL/EXPORT/RC4/3DES),按行写报告即可
- 证书 CN/SAN 字段顺手并入子域名资产清单
- 只做配置层面检测;heartbleed 等需握手深交互的漏洞用 nmap NSE 或 sslyze 补

### sslyze — 快速且全面的 SSL/TLS 扫描器

**用途**:插件化分析服务端 SSL 配置:证书链校验、压缩(CRIME)、重协商(CVE-2009-3555)、会话恢复、各协议套件矩阵,支持 JSON 输出。
**安装**:`sudo apt install sslyze`。
**使用场景**:需要比 sslscan 更细的报告(证书链/重协商/会话)或自动化比对时。

```bash
# 常规全项扫描:直接指定目标即默认全扫
sslyze <host>:443

# 明文升级协议
sslyze --starttls=smtp <host>:25

# JSON 报告
sslyze --json_out=<file> <host>:443
```

**实战要点**:
- 检出 "client-initiated renegotiation" 即重协商漏洞,可配合 DoS 攻击面评估
- `--json_out` 便于流水线周期扫描与差异告警
- 与 sslscan 二选一即可覆盖常规 TLS 审计;深挖单个漏洞(heartbleed 等)再加 nmap `--script ssl-heartbleed`

### tlssled — SSL/TLS 服务器安全评估封装脚本

**用途**:基于 sslscan 与 `openssl s_client` 的 shell 封装:检查 SSLv2、NULL 密码、40/56 位弱密码、MD5 证书、重协商,并自动生成报告目录。
**安装**:`sudo apt install tlssled`。
**使用场景**:老牌一键评估;新项目建议直接用 sslscan/sslyze。

```bash
# 官网模式:评估目标 SSL/TLS
tlssled <ip> 443
```

**实战要点**:
- 自动把输出落到 `TLSSLed_<ver>_<ip>_<port>_<timestamp>/` 目录,便于归档
- 检测项偏老(SSLv2/MD5 证书时代),现代目标基本全绿,仅作快速过筛

### ncat — nmap 套件的 netcat 实现(连接/监听/转发)

**用途**:netcat 重实现,新增 IPv6、SSL、访问控制(`--allow/--deny`)、连接后保持(`--keep-open`)与 `--exec` 执行命令。
**安装**:Kali 默认已装(随 nmap 包)。
**使用场景**:端口连通性验证、简易文件传输、监听反弹 shell、加密通道;后利用阶段常用。

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

**实战要点**:
- `--allow <ip>`/`--deny <ip>` 做白名单,比裸 netcat 监听更可控;`--keep-open` 支持多连接复用同一监听
- `--exec`/`--sh-exec` 的监听即简易 shell 服务,配合 `--ssl` 变加密通道
- 日常连通排查:`ncat -vz <ip> <port>` 快速判断端口可达(vz 组合与 netcat 习惯一致)

### nping — nmap 套件的可控发包工具(ping 升级版)

**用途**:生成 ARP/TCP/UDP/ICMP/以太网帧并逐包显示 SENT/RCVD,可控制标志位、TTL、速率、计数。
**安装**:Kali 默认已装(随 nmap 包)。
**使用场景**:精确探测防火墙放行规则、TTL 裁剪、丢包率;协议级排错。

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

**实战要点**:
- 逐包 SENT/RCVD 对照能直接看出"发出无回应"(被丢)与"收到 RST/ICMP 不可达"(被显式拒绝)的区别,这是判断防火墙策略的依据
- `--ttl` 递增可粗略定位过滤设备所在跳数
- 探活优先级:nmap -sn → 不行再 nping 精细控制

### ndiff — nmap 扫描结果对比工具

**用途**:对比两个 nmap XML 输出,标出主机上下线、端口开闭变化。
**安装**:Kali 默认已装(随 nmap 包)。
**使用场景**:周期性扫描监控、入侵应急时快速发现新增服务。

```bash
# 官网模式:对比两次扫描
ndiff <old-scan>.xml <new-scan>.xml

# 机器可读 XML 输出
ndiff --xml <old-scan>.xml <new-scan>.xml
```

**实战要点**:
- 输入必须是 `nmap -oX`/`-oA` 产生的 XML;`-` 可代标准输入
- `-`/`+` 前缀分别表示消失/新增;新增 open 端口优先核查
- 建议基线扫描用 `-oA` 留档,事件后同参数重扫再 diff

### zenmap — nmap 官方 GUI 前端

**用途**:图形化 nmap:预置扫描 profile、结果对比、拓扑图。
**安装**:`sudo apt install zenmap`(Kali 非默认)。
**使用场景**:偏好 GUI 的初学者或需要拓扑可视化的汇报场景;命令行自动化仍以 nmap 为主。

```bash
sudo zenmap
```

**实战要点**:
- 预置 profile(Intense scan/Quick scan 等)本质是 nmap 参数模板,界面里可查看并复制成命令行
- Topology 视图基于 traceroute 结果,适合给非技术干系人讲网络路径
- Results 里搜索/过滤开放端口,比翻终端滚动条直观

### ike-scan — IKE(IPsec VPN)发现与指纹工具

**用途**:发现 IPsec VPN 服务端(UDP 500/4500),通过响应与重传模式指纹厂商版本;Aggressive Mode 下可抓取可离线破解的 PSK 哈希。
**安装**:`sudo apt install ike-scan`。
**使用场景**:边界测试发现 500/udp 开放时的必跑工具。

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

**实战要点**:
- 响应中的 Vendor ID 字符串可识别厂商/版本(如 Cisco/StrongSwan),据此查已知漏洞
- Aggressive Mode 本身就是发现(XAUTH/PSK 明文哈希可抓),配合 `psk-crack` 字典破解;命中即获 VPN 接入凭证
- `-P` 抓到的文件格式需 ike-scan 套件自带 psk-crack 处理(非普通 hashcat 格式)

### wafw00f — Web 应用防火墙识别与指纹

**用途**:发送恶意特征载荷并观察响应/行为指纹,识别目标前面的 WAF 产品(Cloudflare、ModSecurity、F5 等)。
**安装**:`sudo apt install wafw00f`。
**使用场景**:Web 渗透前置步骤:先确认 WAF 存在与其类型,再决定利用策略。

```bash
# 识别 WAF
wafw00f https://<domain>

# 跑全部检测方式
wafw00f -a https://<domain>

# 批量(空格分隔多个目标)
wafw00f https://<domain1> https://<domain2>
```

**实战要点**:
- 输出 `is behind WAF` 即命中并给出产品名;无 WAF 时也输出 best-guess 供参考
- 检出 WAF 后调整策略:载荷编码/大小写混淆/分块传输/慢速测试,或寻找源站直连 IP
- 与 nmap `--script http-waf-fingerprint` 互相印证,避免单一指纹误判

### tnscmd10g — Oracle TNS 监听器探测工具

**用途**:向 1521/tcp 的 Oracle TNS 监听器发送命令(ping/version/status),获取版本、运行平台、监听端点等信息。
**安装**:`sudo apt install tnscmd10g`。
**使用场景**:发现 1521 端口开放后的第一步信息收集。

```bash
# 官网模式:读监听器版本(含平台信息)
tnscmd10g version -h <ip>

# 监听器状态(泄露监听端点、日志路径、启动参数等)
tnscmd10g status -h <ip>

# 非默认端口
tnscmd10g version -h <ip> -p <port>
```

**实战要点**:
- `version` 输出直接给 Oracle 与 TNS 版本号 → 查监听器已知漏洞(如 TNS poisoning)
- `status` 的输出包含日志文件路径与服务句柄,是配置信息泄露点
- 下一步衔接:sidguess 猜 SID → oscanner 测默认口令 → sqlplus(数据库分册)

### sidguess — Oracle SID 字典猜解

**用途**:按字典对 Oracle 实例名(SID)做枚举,速度约 80-100 次/秒。
**安装**:`sudo apt install sidguesser`(命令名 sidguess)。
**使用场景**:拿到 TNS 版本后,连接数据库前必须先知道有效 SID。

```bash
# 官网模式:字典猜 SID
sidguess -i <ip> -d <wordlist>

# 非默认端口 + 结果报告 + 命中即停
sidguess -i <ip> -p <port> -d <wordlist> -r <report> -m findfirst
```

**实战要点**:
- 常见 SID 候选:orcl、xe、prod、与公司/项目名相关的词;Seclists 有 Oracle SID 专用字典
- 命中 SID 是 oscanner/sqlplus 连接的前置条件;多个 SID 时逐个带入后续工具
- 速度慢是协议特性,大字典需耐心或并行多实例分段

### oscanner — Oracle 评估框架

**用途**:Java 编写的 Oracle 评估框架:枚举 SID、尝试默认口令,结果以树形呈现。
**安装**:`sudo apt install oscanner`。
**使用场景**:拿到 SID 后对 Oracle 做一轮默认凭证与基础评估。

```bash
# 官网模式:指定主机与端口评估
oscanner -s <ip> -P <port>
```

**实战要点**:
- 优先输入 sidguess 命中的 SID 提高命中率;它也会自行尝试常见 SID
- 发现的有效凭证 → `sqlplus <user>/<pass>@<ip>:<port>/<sid>` 深入(数据库分册)
- 较老工具,新版 Oracle 常失败;失败时换专用 Oracle 攻击套件思路(手动枚举)

### apache-users — Apache UserDir 用户名枚举

**用途**:利用 Apache UserDir 模块(~user 形式的个人目录)与字典枚举系统用户名。
**安装**:`sudo apt install apache-users`。
**使用场景**:目标 Web 服务启用 mod_userdir(`https://<host>/~<user>/`)时的用户名收集。

```bash
# 官网模式:字典枚举用户名(HTTP、403 判定不存在、10 线程)
apache-users -h <ip> -l /usr/share/wordlists/metasploit/unix_users.txt -p 80 -s 0 -e 403 -t 10

# HTTPS 目标(-s 1 启用 SSL,404 判定)
apache-users -h <ip> -l <userlist> -p 443 -s 1 -e 404 -t 10
```

**实战要点**:
- 判定逻辑:请求 `/~<user>/` 返回码与 `-e` 指定值不同即视为存在;错误码按目标实际响应选 403 或 404
- 产出用户名列表 → SSH/FTP/SMB 凭证爆破与喷洒的输入
- 等价替代:`nmap --script http-userdir-enum -p 80 <ip>`,更易并入统一扫描流程

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| atk6-thcping6(thc-ipv6 套件) | IPv6/ICMPv6 攻击与发现套件 | thc-ipv6 | `atk6-alive6 eth0`(发现存活 IPv6);`atk6-address6 fe80::...`(IPv6 与 MAC 互转);`atk6-detect-new-ip6 eth0`(DAD 检测新地址);`atk6-dnsdict6 <domain>`(IPv6 子域枚举)。注意:Kali 打包的 thc-ipv6 二进制均带 `atk6-` 前缀 |
| sctpscan | SCTP 协议发现与安全扫描 | sctpscan | `sctpscan -s -F -r 192.168.1.*` |
| mdb-sql(mdbtools) | 读取/导出 JET 与 MS Access .mdb 数据库 | mdbtools | `mdb-tables <file.mdb>`(列表);`mdb-export <file.mdb> <table>`(导出 CSV);`mdb-sql <file.mdb>`(SQL 查询) |
| sqlitebrowser | SQLite 数据库 GUI 浏览/编辑/导出 | sqlitebrowser | `sqlitebrowser <file>.sqlite` |
| legion | 半自动化网络渗透 GUI(扫描+枚举+利用入口,SPARTA 分支) | legion | `sudo legion` |

> 本文件仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景,严禁用于未授权测试。
