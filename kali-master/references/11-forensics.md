# 数字取证与隐写(Digital Forensics & Steganography)

> **何时读本文件**:需要对磁盘/分区做取证镜像(dc3dd/guymager)、恢复丢失分区或删除文件(testdisk/photorec/foremost/extundelete)、用 Sleuth Kit 分析镜像与时间线、检测 rootkit、破解图片/文本隐写(steghide/outguess/stegsnow)、做哈希基线对比或恶意样本特征匹配(yara)时;CTF 取证题(附件分析、内嵌文件提取、元数据、隐写)也读本文件。

## 快速决策表

| 任务场景 | 首选工具 | 备选 | 关键区别 |
|---|---|---|---|
| 命令行取证镜像(边做边算哈希) | dc3dd | dcfldd | dc3dd 支持 hashlog/piecewise;dcfldd 支持分割输出与状态显示 |
| GUI 快速镜像(E01/AFF/多线程压缩) | guymager | — | Qt 界面,并行压缩最快,适合大批量取证获取 |
| 坏盘/坏扇区抢救镜像 | dd_rescue | myrescue / safecopy / recoverdm | dd_rescue 遇 I/O 错误不中断;myrescue 先读好区域后回头补坏区 |
| 恢复丢失分区表 | testdisk | scrounge-ntfs | testdisk 交互式重建分区表;scrounge-ntfs 专攻 NTFS 文件树 |
| 按文件头雕刻恢复(不分文件系统) | foremost | scalpel / magicrescue / photorec | foremost 上手最快;scalpel 可配 conf 更快;photorec 支持类型最多 |
| ext3/ext4 删除文件恢复 | extundelete | ext4magic / ext3grep | extundelete 按 journal 恢复单文件;ext4magic 利用多版本 journal 更强 |
| 镜像内文件系统分析(NTFS/FAT/ext) | Sleuth Kit(mmls/fls/icat) | autopsy(GUI) | TSK 命令行可脚本化;autopsy 是 TSK 的图形/时间线前端 |
| 全镜像时间线(body → CSV) | fls -m + mactime | tsk_gettimes | fls -m 生成 body 文件,mactime 转可读时间线 |
| 不解析文件系统直接抽证据(邮箱/URL/信用卡) | bulk_extractor | — | 特征文件+直方图,适合大镜像快速过一遍 |
| rootkit 检测 | chkrootkit | rkhunter / unhide | chkrootkit 快;rkhunter 有基线属性库;unhide 找隐藏进程/端口 |
| JPEG/BMP/WAV 隐写(密码保护) | steghide | outguess | steghide 支持 bmp/jpeg/wav/au + 加密;outguess 支持 JPEG/PPM/PNM |
| 纯文本隐写(行尾空白) | stegsnow | — | 追加空格/tab 藏消息,可带 ICE 加密 |
| 镜像/目录哈希基线与审计 | hashdeep | ssdeep | hashdeep 精确哈希+审计模式;ssdeep 模糊哈希找"相似"文件 |
| 恶意样本特征规则匹配 | yara | — | 规则语法事实标准,可递归扫目录 |
| PDF 可疑特征检测(JS/OpenAction) | pdfid | pdf-parser | pdfid 只数关键词;pdf-parser 可深入对象与流 |
| Windows 注册表取证 | regripper | reglookup | regripper 插件化输出解读;reglookup 更轻、含删除键恢复 |
| 回收站取证(INFO2 / $I 文件) | rifiuti2 | rifiuti | rifiuti2 支持 Vista+ $I 文件和 INFO2 双格式 |
| PE 文件结构分析 | readpe | missidentify | readpe 解析 PE 头;missidentify 专找无扩展名可执行文件 |
| 邮件存储转换(PST/DBX) | readpst | undbx | readpst 转 PST;undbx 处理 Outlook Express .dbx |
| pcap 中应用数据还原(邮件/HTTP/VoIP) | xplico | — | NFAT 流量解码,输出 Web UI 查看 |
| CTF 附件/固件内嵌文件提取 | binwalk | foremost | binwalk 识别签名+可提取;foremost 按类型雕刻 |

## 取证工作流黄金规则

1. **永远不直接分析原始证据**:先 `dc3dd`/`guymager` 做镜像并同步计算哈希,后续全部操作针对镜像副本。
2. **获取时同步算哈希**:`dc3dd ... hash=sha256 hashlog=... log=...` 一条命令完成获取+校验+日志(证据链)。
3. **Sleuth Kit 分析路径**:`mmls` 看分区偏移 → `fls -o <offset>` 列文件 → `icat`/`tsk_recover` 提取 → `mactime` 出时间线。
4. **删除文件恢复前提**:目标分区必须先卸载(或只对镜像操作),否则恢复操作本身会覆盖待恢复数据。
5. **rootkit 检测交叉验证**:chkrootkit 与 rkhunter 都有误报,单一工具报"INFECTED"不能下结论,需第二工具+基线对比。

## CTF 取证快速通道

拿到一个未知附件(图片/PDF/压缩包/固件)的标准首查流水线:

```bash
file <file>                        # 文件真实类型(扩展名可能伪造)
exiftool <file>                    # 元数据:注释/作者/GPS 字段常藏 flag(sudo apt install libimage-exiftool-perl)
strings -n 8 <file> | grep -iE "flag|ctf|key|pass"   # 可见字符串初筛
binwalk <file>                     # 签名扫描:内嵌压缩包/文件系统/加密段
binwalk -e <file>                  # 自动提取到 <file>.extracted/ 目录
foremost -i <file> -o carved -t jpg,png,pdf,zip  # binwalk 无果时按类型雕刻
```

隐写排查顺序(按载体类型):

```bash
# JPEG/BMP/WAV → steghide(有密码先试空/题目提示词)
steghide info <file>                       # 是否含嵌入数据
steghide extract -sf <file> -p <password>  # 提取嵌入内容
# JPEG → outguess(无密钥统计提取)
outguess -r <file> out.txt
# PNG/ BMP 附加数据或 LSB → binwalk / zsteg(ruby gem, Kali 外安装)
binwalk -e <file>
# 纯文本(.txt/.log)→ 行尾空白隐写
stegsnow -C <file> out.txt
```

## 核心工具详解

### binwalk — 固件/二进制内嵌文件识别与提取(CTF 高频)

**用途**:基于 libmagic 签名(含自定义固件签名库:压缩包、固件头、Linux 内核、bootloader、squashfs 等)扫描二进制中嵌入的文件和代码,可自动提取、做熵分析。
**安装**:Kali 默认已装(`sudo apt install binwalk`);Python 库形式为 `python3-binwalk`。
**使用场景**:固件分析第一步;CTF 中任何"文件里套文件"(PNG 尾部藏 zip、固件藏 squashfs)的场景首选。

```bash
# 官方示例:签名扫描固件(默认即签名扫描,-B 显式指定)
binwalk -B ddwrt-linksys-wrt1200ac-webflash.bin

# 自动按签名提取内嵌对象(输出到 <file>.extracted/)
binwalk -e <firmware.bin>

# 递归提取(对提取结果继续提取,固件套层常用)
binwalk -Me <firmware.bin>

# 熵分析:高熵段 ≈ 加密/压缩,定位可疑嵌入区
binwalk -E <file>
```

**实战要点**:
- 提取 squashfs(cramfs 等变体)需要 `sudo apt install sasquatch`,否则提取失败或解包报错。
- `binwalk -e` 识别出的压缩流会尝试解压,解不出来时记下偏移用 `dd if=<file> of=chunk.bin bs=1 skip=<offset>` 手工截取再处理。
- 新版 Rust 重写为 `binwalk3`(见速查表),命令行为有差异;Kali 主命令仍是 `binwalk`。
- 与 `strings`/`file` 配合:binwalk 找"结构",strings 找"内容",file 验证提取产物真实类型。

### dc3dd — 取证增强版 dd(镜像获取+同步哈希)

**用途**:美国国防部网络犯罪中心(DC3)修补版 GNU dd,镜像获取时同步计算哈希、写审计日志、支持多路输出、分段哈希(piecewise hashing)。
**安装**:`sudo apt install dc3dd`
**使用场景**:任何需要对磁盘/分区/文件做可复现取证获取的场合;比裸 `dd` 的优势是哈希与日志一体化,满足证据链要求。

```bash
# 官方示例:复制文件并计算 SHA512
dc3dd if=/var/log/messages of=/tmp/dc3dd hash=sha512

# 取证镜像:整盘镜像 + SHA256 + 哈希日志 + 操作日志
dc3dd if=/dev/sdc of=/evidence/sdc.raw hash=sha256 hashlog=/evidence/sdc.sha256 log=/evidence/acquisition.log

# 双路输出(同时写两份镜像,一份分析一份封存)
dc3dd if=/dev/sdc of=/evidence/sdc.raw of=/vault/sdc-copy.raw hash=sha256 log=/evidence/log.txt

# 分段哈希:每 64K 算一次 MD5(便于与 md5deep/hashdeep 交叉验证)
dc3dd if=<image.dd> hash=md5 hashwindow=64k hashlog=/evidence/piecewise.txt
```

**实战要点**:
- `hashlog=` 与 `log=` 分开:前者只记哈希,后者记完整操作审计(含起止时间、命令行)。
- 源设备用写阻断器(write blocker)或确保只读挂载;输出目录必须有足够空间(镜像=整盘大小)。
- 需要分割大镜像或实时进度显示可用 `dcfldd`(速查表);需要 E01 格式用 `guymager`。

### guymager — 高速 GUI 取证成像工具

**用途**:基于 Qt 的取证获取程序,支持 EWF(E01)、AFF、raw 多种镜像格式,多线程并行压缩,成像过程中同步计算 MD5/SHA1/SHA256。
**安装**:`sudo apt install guymager`
**使用场景**:需要 E01 格式(商业工具链兼容)、批量对多块盘同时成像、或不想背命令行参数的现场获取。

```bash
# 启动 GUI(root 权限):设备列表右键 → Acquire Image → 选格式/压缩/哈希
sudo guymager
```

**实战要点**:
- 并行压缩使其在多核机器上成像速度通常优于 dc3dd/dcfldd 的单流写入。
- 可同时输出 E01 + 副本 + 多算法哈希,一步满足证据链要求。
- 无 CLI 参数化成像;自动化流水线请用 dc3dd。

### dd_rescue — 坏盘数据抢救(遇错不中断)

**用途**:把数据从损坏介质复制出来;标准工具(cp/dd)遇到 I/O 错误即中止,dd_rescue 会缩小块重试、支持反向复制、稀疏复制,可用于坏硬盘/光盘抢救与多次覆写安全擦除。
**安装**:`sudo apt install ddrescue`(注意:该包提供的二进制是 `dd_rescue`,与 GNU ddrescue 的 `ddrescue` 是两个不同项目)。
**使用场景**:源盘有坏道、读取报错时做镜像;健康盘直接用 dc3dd。

```bash
# 官方示例:从输入文件位置 100 开始,写到输出文件位置 0
dd_rescue -s 100 /var/log/messages -S 0 /tmp/ddrescue-out

# 抢救整块坏盘到镜像文件(遇到坏块自动缩小块重试)
dd_rescue /dev/sdb /recovery/sdb.img
```

**实战要点**:
- `-s <pos>` 指定输入起始位置,`-S <pos>` 指定输出起始位置,可分段接力复制。
- 同类选择:myrescue 先跳过坏区抢救健康区域后回头补读;safecopy 面向 CD/软盘等光磁介质;recoverdm 恢复时对无法读取的扇区写空扇区占位(均见速查表)。

### testdisk — 分区扫描与恢复

**用途**:检查磁盘分区表与引导扇区,恢复丢失分区、修复分区表、从备份引导扇区还原 NTFS/FAT 引导区,支持众多文件系统。
**安装**:`sudo apt install testdisk`(同一包提供 photorec)。
**使用场景**:分区表损坏/被删、误克隆导致分区丢失、可启动盘引导损坏的分析与修复。

```bash
# 交互式分析:Create log → 选磁盘 → 选分区表类型 → Analyse → Quick Search
sudo testdisk <image.dd>
sudo testdisk /dev/sdc
```

**实战要点**:
- 全交互式菜单驱动,典型路径:`Analyse` → `Quick Search` → `Deeper Search` → 选中找到的分区 → `Write` 恢复分区表(写操作前确认目标正确)。
- 先对整盘做镜像、在镜像上跑 testdisk,避免对原始证据直接写入。
- 找回分区后若文件系统也损坏,转 photorec 直接按签名雕刻文件。

### photorec — 文件签名雕刻恢复(文件系统无关)

**用途**:TestDisk 套件的文件数据恢复软件,按文件头/内部结构签名雕刻丢失文件,不依赖文件系统,支持照片、文档、压缩包等大量格式。
**安装**:`sudo apt install testdisk`
**使用场景**:文件系统已损坏/被格式化、删除文件太多不适合按 journal 恢复、或只需要"把能恢复的都恢复出来"。

```bash
# 交互式:选介质 → 选分区 → 选文件系统类型 → 选恢复目录 → Search
sudo photorec <image.dd>
sudo photorec /dev/sdb
```

**实战要点**:
- 恢复按签名进行,**不保留原文件名与目录结构**,输出为 recup_dir.* 目录下的编号文件,需按内容二次整理。
- 菜单 `File Opt` 可只勾选需要的类型(如只要 JPG/PDF),大幅减少垃圾输出。
- 与 foremost/scalpel 的取舍:photorec 类型库最全且带内部结构校验;foremost 更轻、命令行参数化适合脚本;scalpel 配置文件可自定义头尾对。

### foremost — 基于头/尾/结构的文件雕刻

**用途**:依据文件头、尾与内部数据结构从镜像(dd/Safeback/EnCase 生成)或直接从驱动器恢复丢失文件,内置类型按数据结构校验,恢复更可靠。
**安装**:`sudo apt install foremost`
**使用场景**:已知要找哪几类文件(doc/jpg/pdf/xls/zip 等)时,指定类型雕刻比全量扫描快且噪音小;CTF 中提取图片尾部附加的压缩包。

```bash
# 官方示例:在镜像中雕刻 doc、jpg、pdf、xls 四类文件
foremost -t doc,jpg,pdf,xls -i image.dd

# 指定输出目录(目录必须不存在或为空,-T 可自动加时间戳)
foremost -t jpg,png,zip,pdf -i <image.dd> -o carved_out
```

**实战要点**:
- 结果目录含 `audit.txt` 审计文件,记录每个恢复文件的偏移与大小,可作证据附件。
- `-t` 支持类型见 `foremost -h`(如 avi,bmp,exe,gif,jpg,mov,mpg,pdf,png,rar,txt,wav,zip);`-t all` 全类型。
- 同类更快的替代是 scalpel(见下),自定义头尾规则写入 `/etc/scalpel/scalpel.conf`。

### scalpel — 快速文件系统无关雕刻(可配置规则)

**用途**:读取头/尾定义数据库,从一组镜像或裸设备中提取匹配文件;文件系统无关,FAT/exFAT/NTFS/ext2-4/JFS/XFS/ReiserFS/裸分区均可。
**安装**:`sudo apt install scalpel`
**使用场景**:需要自定义 carving 规则(特定 magic 头尾)、或 foremost 速度不够时。

```bash
# 从镜像雕刻到输出目录(目录须为空/不存在)
scalpel <image.dd> -o carved_out

# 编辑规则库后按自定义头尾雕刻
sudo vim /etc/scalpel/scalpel.conf
```

**实战要点**:
- 默认配置中大多数规则被注释,按需取消注释,否则什么都雕不出来(常见坑)。
- 输出同样带审计文件;大镜像上比 foremost 更快、内存占用更低。

### extundelete — ext3/ext4 删除文件恢复(按 journal)

**用途**:利用 ext3/ext4 分区 journal 中保留的元数据尝试恢复被删除文件(不保证成功)。
**安装**:`sudo apt install extundelete`
**使用场景**:已知被删文件路径、目标为 ext3/ext4 文件系统时的第一选择;NTFS 用别的工具。

```bash
# 官方示例:从分区恢复指定文件(相对分区根的路径,不带开头 /)
extundelete /dev/sda1 --restore-file root/importantfile

# 恢复整个目录 / 全部分配删除文件
extundelete <image.img> --restore-directory var/log
extundelete <image.img> --restore-all

# 只查某 inode 的元数据,确认可恢复性
extundelete <image.img> --inode <inode_num>
```

**实战要点**:
- **目标分区必须已卸载**(或直接对镜像操作),继续挂载写入会覆盖待恢复数据——工具自身也会如此警告。
- 恢复结果写入当前目录 `RECOVERED_FILES/`;不支持恢复扩展属性(xattr)。
- 删除时间较久 journal 已轮转覆盖时,改用 ext4magic(利用多个 journal 历史版本,恢复率更高)。

### ext4magic — 从 ext3/ext4 journal 深度恢复

**用途**:ext3/ext4 文件雕刻/恢复工具:删除文件后 inode 块指针被清零,但 journal 中往往还留有旧版本元数据,ext4magic 据此恢复大量"不可能恢复"的文件。
**安装**:`sudo apt install ext4magic`
**使用场景**:extundelete 失败后的第二道防线;灾难恢复与取证。

```bash
# 快速模式:恢复最近删除的文件
ext4magic <image.img> -r -d recovered/

# 全量模式:遍历所有 journal 版本尽力恢复(耗时长)
ext4magic <image.img> -m -d recovered/

# 恢复指定路径(目录或文件)
ext4magic <image.img> -f path/to/dir -d recovered/
```

**实战要点**:
- `-r` 用最新 journal 状态(快),`-m` 用全部历史 journal(慢但更全)。
- 同样要求分区已卸载/只对镜像操作;恢复输出由 `-d` 指定。
- ext3 老文件系统还可试 `ext3grep --restore-all`(速查表)。

### mmls — Sleuth Kit 入口:查看镜像分区布局

**用途**:显示磁盘镜像的卷系统(分区表)布局,列出各分区的起始偏移(Offset)、长度、类型——该偏移是后续所有 TSK 文件系统工具的 `-o` 参数来源。
**安装**:`sudo apt install sleuthkit`
**使用场景**:Sleuth Kit 分析流程第一步;拿到镜像先 mmls 确定分区结构。

```bash
# 列出镜像分区表:关注 Offset 列(单位:扇区)
mmls <image.dd>

# 带偏移分析嵌套镜像
mmls -o <offset> <image.dd>
```

**实战要点**:
- 输出中 "000: Meta" 或 "Unallocated" 是卷系统自身/未分配区域,文件系统分区通常标 "NTFS / ext* / Linux filesystem"。
- 后续命令统一用 `fls -o <Offset列的值> <image.dd>`;`-o` 接受 `2048` 或 `2048s`(扇区)两种写法。
- mmls 认不出分区表时,用 `mmstat`(看卷系统类型)或 testdisk 先修复/识别。

### fls — Sleuth Kit:列出镜像文件系统内容(含已删除)

**用途**:列出镜像内文件与目录,不依赖宿主 OS 解析文件系统,可显示已删除与隐藏条目;`-m` 输出 body 格式供 mactime 做时间线。
**安装**:`sudo apt install sleuthkit`
**使用场景**:确定"当时存在哪些文件、哪些已被删除",是取证文件清单的基础命令。

```bash
# 列出分区(o 偏移来自 mmls)全部条目
fls -o <offset> <image.dd>

# 递归 + 完整路径(接近 find 的输出)
fls -r -p -o <offset> <image.dd>

# 只看已删除条目
fls -d -r -p -o <offset> <image.dd>

# 生成 body 文件(时间线输入;-m 的参数为挂载点标识,会写进输出)
fls -m / -r -p -o <offset> <image.dd> > body.txt
```

**实战要点**:
- 输出格式:`r/r * 1234-1234-5: path/to/file`,`*` 表示已删除,`r/r` 是文件类型/元数据类型,数字串是 inode(NTFS 为 inode-seqid)。
- `*` 标记条目的 inode 可直接交给 `icat` 提取内容、`istat` 查时间属性。
- 已删除条目 inode 后带 `-seqid` 的镜像(NTFS)在 icat 时要带完整 inode-seqid。

### icat — Sleuth Kit:按 inode 提取文件内容

**用途**:按 inode 号从镜像中直接输出文件数据,支持恢复已删除文件的内容(`-r`),不需要文件名仍然有效。
**安装**:`sudo apt install sleuthkit`
**使用场景**:fls 找到目标 inode 后把文件内容"抠"出来;文件名已被抹除/覆盖但 inode 仍在时尤其有用。

```bash
# 提取指定 inode 的文件内容
icat -o <offset> <image.dd> <inode> > recovered_file

# 恢复已删除文件内容(含 resident data 处理)
icat -r -o <offset> <image.dd> <inode> > recovered_file
```

**实战要点**:
- inode 参数用 fls/ils 输出的原始值;NTFS 记账形式 `inode-seqid` 原样传入。
- 内容取回后立即 `file recovered_file` 验证真实类型;哈希后入库(hashdeep)。
- 与 tsk_recover 的取舍:icat 是"点名提取",tsk_recover 是"批量导出"。

### fsstat — Sleuth Kit:文件系统整体信息

**用途**:显示镜像中某文件系统的详细结构信息:类型、块/扇区大小、inode 范围、挂载时间、卷标、NTFS 序列号等。
**安装**:`sudo apt install sleuthkit`
**使用场景**:确认 `-o` 偏移处的文件系统类型与参数;报告中的"卷信息"一节素材。

```bash
# 查看分区文件系统详情
fsstat -o <offset> <image.dd>
```

**实战要点**:
- 输出包含 Last Mounted、最后写入时间等时间元素,可交叉验证系统时钟篡改。
- 看到报错 "Cannot determine file system type" 说明偏移不对,回 mmls 核对。

### tsk_recover — Sleuth Kit:批量导出镜像中的文件

**用途**:从镜像批量恢复文件到目录,可只导已分配文件或全部(含已删除)。
**安装**:`sudo apt install sleuthkit`
**使用场景**:需要把镜像内容整体导出后用常规工具(grep/杀毒/审阅)处理,而不是逐 inode 提取。

```bash
# 导出全部文件(已分配 + 已删除)
tsk_recover -e -o <offset> <image.dd> /out/recovered/

# 只导出(当前文件系统可见的)已分配文件
tsk_recover -a -o <offset> <image.dd> /out/allocated/
```

**实战要点**:
- 已删除文件恢复出的内容不保证完整(块可能被重用),用 `file`/打开验证。
- 输出目录需已存在;大量小文件导出较慢,只要少量文件时 icat 更快。

### mactime — 时间线生成(body 文件 → CSV)

**用途**:读取 TSK body 格式文件(fl -m / ils -m / tsk_gettimes 生成),按时间排序输出文件系统时间线(macb:modified/accessed/changed/born)。
**安装**:`sudo apt install sleuthkit`
**使用场景**:入侵时间线还原:结合日志时间点,定位"某时刻前后哪些文件被创建/修改/删除"。

```bash
# 标准 pipeline:fls 生成 body,mactime 转 CSV(-d 逗号分隔,可直接进表格)
fls -m / -r -p -o <offset> <image.dd> > body.txt
mactime -b body.txt -d > timeline.csv
```

**实战要点**:
- 输出列 `MACB` 中字母表示该时间字段非零(M=修改 A=访问 C=inode 变更 B=创建);`*` 表示时间戳早于 1970 或可疑。
- NTFS 的"出生时间"(B)对定位攻击者落地文件非常有用;EXT 文件系统无 B 时间。
- 大批量镜像可先 `tsk_gettimes <image>` 生成 body(速查表)再统一 mactime。

### autopsy — Sleuth Kit 图形化取证浏览器

**用途**:The Sleuth Kit 的 GUI 前端,提供 NTFS/FAT/ext 等文件系统分析、关键词搜索、时间线、哈希过滤等,近似商业取证工具的免费替代。
**安装**:`sudo apt install autopsy`
**使用场景**:不想逐条敲 TSK 命令、需要交互式浏览镜像文件/已删除内容/时间线做案件分析。

```bash
# Kali 仓库为 legacy 2.x 版本:启动内置 Web 服务,按提示用浏览器打开
sudo autopsy
# 浏览器访问: http://localhost:9999/autopsy
```

**实战要点**:
- 2.x 为 Web 界面流程(New Case → Add Image → Analyze),底层就是 fls/icat/mactime 那套,学会 CLI 后 GUI 只是加速器。
- 需要现代 Autopsy 4.x 的完整功能(_ingest 插件、视频等)需到 Windows 平台运行官方版。
- 无头/自动化场景直接用 Sleuth Kit 命令行,不要依赖 autopsy。

### bulk_extractor — 不解析文件系统的全量证据抽取

**用途**:C++ 扫描器,对磁盘镜像/文件/目录提取有用信息(email、URL、域名、IP、信用卡号、EXIF、电话等)而不解析文件系统,结果写入特征文件并生成直方图。
**安装**:`sudo apt install bulk-extractor`
**使用场景**:大镜像快速"过筛":不关心文件结构,只关心里面出现过哪些邮箱/网址/加密线索(如 TrueCrypt 头)。

```bash
# 官方示例:分析镜像并输出到目录
bulk_extractor -o bulk-out xp-laptop-2005-07-04-1430.img

# 常规用法:输出目录会包含 email.txt、url.txt、domain.txt、ccn.txt 等特征文件
bulk_extractor -o /evidence/be-out <image.dd>
```

**实战要点**:
- 输出目录每个特征文件一个类别;`*_histogram.txt` 是频次排序,"高频即重要"。
- 信用卡特征(ccn.txt)涉及敏感数据,处理与留存需符合案件授权范围。
- 提示 CPU bound 时加 `-j <线程数>` 提速(多核机器)。

### chkrootkit — rootkit 特征扫描

**用途**:在系统中搜索 70+ 种 rootkit 感染迹象(签名比对、隐藏文件、网络接口 promisc 检测、wtmp/lastlog 篡改等)。
**安装**:`sudo apt install chkrootkit`
**使用场景**:主机入侵排查第一轮快扫;与 rkhunter 交叉验证。

```bash
# 全量扫描(主要输出:每项检测结果 + 可能的 INFECTED 提示)
sudo chkrootkit

# 专家模式(输出更多原始数据供人工判读)
sudo chkrootkit -x
```

**实战要点**:
- 单独一条 "INFECTED" 常是误报(如包升级导致二进制与包装器不一致),需结合 rkhunter、文件哈希基线二次确认。
- 扫描应使用可信环境:严重 rootkit 会感染扫描工具自身,必要时从只读介质运行。
- 检查项含 `sniffer` 检测(网卡混杂模式),可作为流量窃听线索。

### rkhunter — Rootkit Hunter(rootkit/后门/嗅探器扫描)

**用途**:扫描已知/未知 rootkit、后门、嗅探器与漏洞利用痕迹:文件哈希比对、隐藏文件、可疑权限、内核模块、启动项等。
**安装**:`sudo apt install rkhunter`
**使用场景**:需要可维护的基线属性数据库(减少误报)与日志输出的常态化 rootkit 检查。

```bash
# 先更新特征库
sudo rkhunter --update

# 全量检查(--sk 跳过逐段按键确认)
sudo rkhunter --check --sk

# 建立文件属性基线(系统干净时做一次;之后变更才报警)
sudo rkhunter --propupd

# 查看历史结果:直接读日志文件(旧一轮日志为 rkhunter.log.old)
less /var/log/rkhunter.log
```

**实战要点**:
- Warning 不等于感染:常见于包更新后哈希漂移,复核后 `--propupd` 刷新基线。
- 日志在 `/var/log/rkhunter.log`,事件响应时保留原始日志再处理。
- 与 chkrootkit/unhide 三件套组合使用:签名比对 + 属性基线 + 隐藏进程检测互补。

### steghide — BMP/JPEG/WAV/AU 隐写(带加密)

**用途**:把数据文件藏入载体文件最低有效位,存在性不可见不可证明;支持 bmp/jpeg/wav/au,Blowfish 加密、MD5 口令散列,支持压缩嵌入。
**安装**:`sudo apt install steghide`
**使用场景**:CTF 图片/音频隐写第一猜;授权演练中的隐写演示与检测训练。

```bash
# 嵌入:把 secret.txt 藏进 cover.jpg(-p 口令,可省略则交互输入)
steghide embed -cf cover.jpg -ef secret.txt -p <password>

# 检查文件是否含嵌入数据
steghide info stego.jpg

# 提取(输出默认原名;可用 -xf 指定输出路径)
steghide extract -sf stego.jpg -p <password>
steghide extract -sf stego.jpg -p <password> -xf out.bin
```

**实战要点**:
- 只支持 bmp/jpeg/wav/au;PNG 用别的思路(附加数据/LSB)。
- CTF 无口令提示时先试空口令、题目名、文件名;批量猜口令可用 `stegseek`(Kali 仓库)挂字典跑 steghide 短语。
- 提取出二进制后接 `file`+`binwalk` 二次分析,常是嵌套题目。

### outguess — JPEG/PPM/PNM 通用隐写(统计抗检测)

**用途**:通用隐写工具,把信息嵌入数据源的冗余位,依赖格式 handler(支持 JPEG、PPM、PNM),因做统计修正而较抗隐写分析。
**安装**:`sudo apt install outguess`
**使用场景**:steghide 无果时的 JPEG 第二猜;题目给出的是 jpg 且 steghide 提示无嵌入数据时。

```bash
# 嵌入:-k 密钥,-d 要藏的数据文件
outguess -k <key> -d hidden.txt cover.jpg stego.jpg

# 带密钥提取
outguess -r -k <key> stego.jpg output.txt

# 无密钥统计提取(CTF 常见:未设 key)
outguess -r stego.jpg output.txt
```

**实战要点**:
- 嵌入后可 `outguess -k <key> -r ... ` 自校验;提取成功会显示 "Reading ... done" 与隐写帧统计。
- 与 steghide 的载体偏重不同:outguess 只吃 JPEG/PPM/PNM,两者互为补充而非替代。

### stegsnow — 文本隐写(行尾空白 + ICE 加密)

**用途**:把消息藏在 ASCII 文本每行末尾追加的空格/tab 中——文本查看器里不可见;内置加密后即使被发现也无法读取。
**安装**:`sudo apt install stegsnow`
**使用场景**:CTF 中纯 .txt/.log 附件、`cat` 看内容"正常"但题目暗示隐写;检测文本尾部空白隐写。

```bash
# 提取(不带 -p 则用默认口令;先试无口令再试题目提示词)
stegsnow -C stego.txt out.txt

# 带口令提取
stegsnow -C -p <password> stego.txt out.txt

# 嵌入:-m 直接藏消息,或 -f 藏文件内容;-C 压缩
stegsnow -C -p <password> -f secret.txt cover.txt stego.txt
```

**实战要点**:
- 快速判断是否用了空白隐写:`cat -A stego.txt` 行尾出现大量 ` `/$ 前空格即可疑。
- `-C` 表示启用压缩(嵌入与提取需一致);加密口令未知时输出为乱码。

### yara — 恶意样本模式识别与分类

**用途**:用文本/二进制模式描述(字符串集合+布尔条件)识别与分类恶意样本;规则语法是行业事实标准,可递归扫描目录。
**安装**:`sudo apt install yara`(库 `libyara-dev`、文档 `yara-doc` 同源)。
**使用场景**:批量样本家族归类、IOC 落地扫描、事件响应中快速筛选可疑文件。

```bash
# 用规则文件扫单个文件
yara <rules.yar> <sample.exe>

# 递归扫描目录(-r),合并多规则文件可逗号分隔或给目录
yara -r <rules.yar> /malware/samples/

# 规则编写示例:suspicious.yar
cat > suspicious.yar <<'EOF'
rule webshell_cmd_marker
{
    strings:
        $a = "cmd.exe /c" ascii
        $b = "WScript.Shell" ascii
        $c = { 4D 5A 90 00 03 00 00 00 }
    condition:
        any of them
}
EOF
yara suspicious.yar <file>
```

**实战要点**:
- 编译规则加速:`yarac <rules.yar> compiled.yarc` 后把编译文件作为第一参数使用。
- 规则来源:社区规则库(YARA 官方仓库、Florian Roth signature-base)可直接下载使用,注意时效性。
- 命中只说明特征匹配,定性仍需动态/人工分析;`-s` 可打印命中字符串位置辅助研判。

### hashdeep — 递归哈希计算与审计模式

**用途**:递归计算 MD5/SHA1/SHA256/Tiger/Whirlpool 哈希;支持分段哈希(piecewise)、审计模式(与已知哈希集合比对增删改)。
**安装**:`sudo apt install hashdeep`
**使用场景**:证据完整性基线、镜像/目录前后对比(是否被篡改、新增哪些文件)、合规审计。

```bash
# 递归计算目录 SHA256 基线
hashdeep -c sha256 -r /evidence > baseline.txt

# 审计模式:与基线比对,输出匹配/不匹配/新增(证据链完整性证明)
hashdeep -c sha256 -r -a -k baseline.txt /evidence

# 只显示不在基线中的文件(-x 负向匹配,找"新出现的文件")
hashdeep -c sha256 -r -x -k baseline.txt /evidence
```

**实战要点**:
- 审计前后哈希算法必须一致(同 `-c` 参数),否则全部 mismatch。
- 大文件分段哈希(piecewise)适合网络传输中断点续传校验场景;`-l` 输出相对路径便于迁移。
- 找"相似但不同"的文件(如恶意样本变种)用 ssdeep,不用 hashdeep。

### ssdeep — 模糊哈希(相似文件匹配)

**用途**:上下文触发的分段哈希(CTPH/模糊哈希):不仅像 md5sum 那样比对完全相同文件,还能按相似度百分比匹配有少量差异的文件。
**安装**:`sudo apt install ssdeep`
**使用场景**:恶意样本变种聚类、同一木马多版本归并、重复文档溯源。

```bash
# 递归生成目录模糊哈希集合
ssdeep -r /samples > hashes.txt

# 匹配模式:拿目录/文件与哈希集合比对,输出相似度百分比
ssdeep -m hashes.txt -r /new_samples

# 比较两个文件相似度
ssdeep file1.bin file2.bin
```

**实战要点**:
- 输出的百分比是相似度不是置信度,>90% 基本同源,<50% 需人工复核。
- 模糊哈希对"整体相似"有效,对加壳/加密样本失真——先脱壳再比。

### pdfid — PDF 可疑关键词快速筛查

**用途**:不解析 PDF,只统计文件中 PDF 关键词出现次数(如 /JS、/JavaScript、/OpenAction、/Launch、/AA),并处理名称混淆,快速识别含脚本或自动动作的 PDF。
**安装**:`sudo apt install pdfid`
**使用场景**:批量 PDF 首轮风险筛查、CTF PDF 题第一步。

```bash
# 官方示例:统计关键词计数
pdfid /usr/share/doc/texmf/fonts/lm/lm-info.pdf

# 目标文件筛查
pdfid <file.pdf>
```

**实战要点**:
- `/JS`、`/JavaScript`、`/OpenAction`、`/Launch`、`/AA`、`/AcroForm` 任一非 0 都值得深挖(可能是嵌 JS 或打开即触发动作)。
- 名称混淆(如 `/J#61vaScript`)pdfid 会归一化处理,不易被绕过。
- 计数异常后转 pdf-parser 定位具体对象。

### pdf-parser — PDF 结构解析与对象提取

**用途**:解析 PDF 文档基本元素(对象、流、xref、trailer)并按需提取/解压,不做渲染。
**安装**:`sudo apt install pdf-parser`
**使用场景**:pdfid 报可疑后定位到具体对象;提取内嵌文件流;分析 JS 与恶意 payload。

```bash
# 官方示例:统计文档元素(间接对象数等)
pdf-parser -a /usr/share/doc/texmf/fonts/lm/lm-info.pdf

# 搜索包含指定关键词的对象(如 JavaScript、OpenAction)
pdf-parser -s /JavaScript <file.pdf>

# 查看指定编号对象;配合 -f 解压流,-d 导出流内容到文件
pdf-parser -o <obj_id> <file.pdf>
pdf-parser -o <obj_id> -f -d stream.bin <file.pdf>
```

**实战要点**:
- `-a` 的统计先看 indirect object 总数与 stream 数,再决定挖哪个对象。
- 流解压(-f)后 dump 出来的常是 zlib 解压后的 JS 或嵌入文件,直接接 `file`/文本搜索。
- 对象流(ObjStm)内的对象需用 pdf-parser 解开后逐层查,不要只看表面 xref。

### regripper — Windows 注册表取证插件框架

**用途**:用 Perl 插件从注册表 hive(SAM/SYSTEM/SOFTWARE/NTUSER.DAT)中"外科手术式"提取、翻译并展示数据;可按插件或 profile(插件列表)运行,结果到 STDOUT。
**安装**:`sudo apt install regripper`
**使用场景**:从 Windows 镜像提取用户痕迹、自启动项、USB 历史、网络配置等取证要点。

```bash
# 单插件运行(-r hive,-p 插件)
regripper -r <NTUSER.DAT> -p userassist

# 按 profile 批量运行(-f 如 system/software/sam/ntuser/all)
regripper -r <SYSTEM> -f system

# 常用插件示例:run(自启动)、usbstor(USB 设备)、shellbags、recentdocs
regripper -r <SOFTWARE> -p run
regripper -r <SYSTEM> -p usbstor
```

**实战要点**:
- 先从镜像中把 hive 文件取出来(通常在 `/Windows/System32/config/` 与用户目录 `NTUSER.DAT`),不要在挂载的系统上直接跑。
- `-p` 与 `-f` 二选一;插件名/概览可查看随包插件目录(`/usr/share/regripper`)。
- hive 脏(未正常关机)时配 `reglookup-recover`(速查表)读删除键与残留数据。

## 其余工具速查

| 工具 | 一句话用途 | 安装包 | 最常用命令 |
|---|---|---|---|
| binwalk3 | binwalk 新一代 Rust 重写,单二进制扫描/提取内嵌文件 | binwalk3 | `binwalk3 <file>` |
| blkcalc | TSK:磁盘块地址与文件系统块地址换算 | sleuthkit | `blkcalc -o <offset> <image> <block>` |
| blkcat | TSK:按数据块号 dump 块内容 | sleuthkit | `blkcat -o <offset> <image> <block>` |
| blkls | TSK:导出未分配空间(供 carving) | sleuthkit | `blkls -o <offset> <image> > unalloc.bin` |
| blkstat | TSK:查询数据块分配状态与时间 | sleuthkit | `blkstat -o <offset> <image> <block>` |
| dcfldd | 美国防部实验室增强 dd(哈希/分割/进度) | dcfldd | `dcfldd if=/dev/sdc of=disk.img hash=sha256 hashlog=hash.txt` |
| ext3grep | ext3 文件系统删除文件恢复 | ext3grep | `ext3grep <image.img> --restore-all` |
| ffind | TSK:由 inode 反查文件名(含已删除) | sleuthkit | `ffind -o <offset> <image> <inode>` |
| galleta | 解析 IE Cookie 文件为分隔字段表 | galleta | `galleta -d";" <cookie.txt>` |
| grokevt-addlog | 向 grokevt 数据库追加 Windows 事件日志 | grokevt | `grokevt-addlog <db-dir> <log.evt>` |
| grokevt-builddb | 从挂载的 Windows 分区构建事件日志数据库 | grokevt | `grokevt-builddb /mnt/windows /tmp/grokevt-db` |
| grokevt-findlogs | 在挂载分区中搜寻 Windows 事件日志文件 | grokevt | `grokevt-findlogs /mnt/windows` |
| grokevt-parselog | 将事件日志解析为人类可读格式 | grokevt | `grokevt-parselog <db-dir> System`(`-l <db-dir>` 列出可用日志名) |
| grokevt-ripdll | 从 PE DLL 提取事件消息模板 | grokevt | `grokevt-ripdll <msgdll.dll>` |
| hexwalk | GUI 十六进制编辑/分析器(集成 binwalk/哈希/字符串) | hexwalk | `hexwalk`(GUI) |
| hfind | TSK:哈希数据库索引与查询 | sleuthkit | `hfind -i sha1sum <hashdb.txt>`(建索引后 `hfind <hashdb.txt> <hash>`) |
| ifind | TSK:按块号/文件名反查 inode | sleuthkit | `ifind -o <offset> -d <block> <image>` |
| ils | TSK:列出 inode 元数据结构 | sleuthkit | `ils -o <offset> <image>` |
| img_cat | TSK:输出镜像原始数据流 | sleuthkit | `img_cat <image>` |
| img_stat | TSK:显示镜像格式信息 | sleuthkit | `img_stat <image>` |
| istat | TSK:inode 详细元数据(时间戳/块列表) | sleuthkit | `istat -o <offset> <image> <inode>` |
| jcat | TSK:读取文件系统日志(NTFS $Log/ext journal)块 | sleuthkit | `jcat -o <offset> <image> <journal_block>` |
| jls | TSK:列出文件系统日志条目 | sleuthkit | `jls -o <offset> <image>` |
| magicrescue | 按魔数+recipe 从设备/镜像抢救文件 | magicrescue | `magicrescue -r jpeg-exif -d /out /dev/sdb1` |
| missidentify | 找无扩展名的 win32 PE 可执行文件 | missidentify | `missidentify -a <dir>` |
| mmcat | TSK:导出分区(volume)原始数据 | sleuthkit | `mmcat <image> <vol_id> > part.raw` |
| mmstat | TSK:显示卷系统类型信息 | sleuthkit | `mmstat <image>` |
| myrescue | 损坏介质数据抢救(先好区后坏区) | myrescue | `myrescue /dev/sdb1 /out/sdb1.img` |
| pasco | 解析 IE index.dat 缓存记录 | pasco | `pasco <index.dat>` |
| readpe | 解析 Windows PE 头/节/导入导出 | readpe | `readpe <file.exe>` |
| readpst | Outlook PST 转 mbox/eml | pst-utils | `readpst -o <outdir> <file.pst>` |
| recoverdm | 坏扇区介质恢复(不可读扇区置空续跑) | recoverdm | `recoverdm -h`(参数较复杂,按提示用) |
| recoverjpeg | 从设备/镜像恢复 JPEG/MOV(附 recovermov、remove-duplicates、sort-pictures) | recoverjpeg | `recoverjpeg -o <outdir> /dev/sdb1` |
| reglookup | Windows 注册表命令行读取/路径查询 | reglookup | `reglookup -p /Microsoft/Windows/CurrentVersion/Run <SOFTWARE>` |
| rifiuti | 旧版 Windows 回收站 INFO2 分析 | rifiuti | `rifiuti <INFO2>` |
| rifiuti2 | 回收站分析(INFO2 + Vista+ $I 文件,输出删除时间/原路径) | rifiuti2 | `rifiuti2 <recycle_dir>` |
| safecopy | 坏媒体(CD/软盘/硬盘)数据恢复 | safecopy | `safecopy /dev/sr0 cd.img` |
| scrounge-ntfs | NTFS 分区文件树恢复 | scrounge-ntfs | `scrounge-ntfs -d <outdir> /dev/sda1` |
| sigfind | 按十六进制签名搜索镜像中的偏移 | sleuthkit | `sigfind <hex_signature> <image>` |
| sorter | TSK:按文件类型分类整理镜像内容并扩展名校验 | sleuthkit | `sorter -o <offset> -d <outdir> <image>` |
| srch_strings | TSK:镜像字符串提取(等价 strings) | sleuthkit | `srch_strings -t d <image>` |
| stegosuite | GUI 图片隐写(BMP/GIF/JPG/PNG,AES 加密) | stegosuite | `stegosuite`(GUI) |
| tailscale | WireGuard 安全组网(取证团队远程接入/证据传输) | tailscale | `tailscale up` |
| tsk_comparedir | TSK:镜像与本地目录内容差异比对 | sleuthkit | `tsk_comparedir -o <offset> <image> <dir>` |
| tsk_gettimes | TSK:直接生成 body 文件(时间线输入) | sleuthkit | `tsk_gettimes -o <offset> <image> > body.txt` |
| tsk_loaddb | TSK:镜像元数据导入 SQLite 便于 SQL 查询 | sleuthkit | `tsk_loaddb -d <db.sqlite> <image>` |
| undbx | Outlook Express .dbx 邮件提取/恢复/反删除 | undbx | `undbx <dbx文件或目录> <outdir>` |
| unhide | 检测被 rootkit/LKM 隐藏的进程与 TCP/UDP 端口 | unhide | `sudo unhide brute; sudo unhide-tcp` |
| vinetto | 解析 Windows Thumbs.db 缩略图及元数据 | vinetto | `vinetto -o ./thumbs_out <Thumbs.db>` |
| xplico-webui-start | 启动 Xplico 网络取证(pcap 应用数据还原)Web 服务 | xplico | `sudo xplico-webui-start` |
| xplico-webui-stop | 停止 Xplico 服务 | xplico | `sudo xplico-webui-stop` |

---

仅用于已获得书面授权的渗透测试、CTF 竞赛与安全教育场景。
