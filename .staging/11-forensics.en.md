# Digital Forensics & Steganography

> **When to read this file**: When you need to take forensic images of disks/partitions (dc3dd/guymager), recover lost partitions or deleted files (testdisk/photorec/foremost/extundelete), analyze images and timelines with Sleuth Kit, detect rootkits, crack image/text steganography (steghide/outguess/stegsnow), or perform hash baseline comparison and malicious sample signature matching (yara); also read it for CTF forensics challenges (attachment analysis, embedded file extraction, metadata, steganography).

## Quick Decision Table

| Task Scenario | Preferred Tool | Alternatives | Key Differences |
|---|---|---|---|
| CLI forensic imaging (hashing on the fly) | dc3dd | dcfldd | dc3dd supports hashlog/piecewise; dcfldd supports split output and status display |
| Fast GUI imaging (E01/AFF/multithreaded compression) | guymager | — | Qt interface, fastest parallel compression, ideal for high-volume forensic acquisition |
| Rescue imaging of failing disks/bad sectors | dd_rescue | myrescue / safecopy / recoverdm | dd_rescue does not abort on I/O errors; myrescue reads good areas first, then goes back for the bad ones |
| Recovering a lost partition table | testdisk | scrounge-ntfs | testdisk interactively rebuilds the partition table; scrounge-ntfs specializes in NTFS file trees |
| Carving by file header (filesystem-agnostic) | foremost | scalpel / magicrescue / photorec | foremost is the fastest to pick up; scalpel is faster with a tuned conf; photorec supports the most types |
| ext3/ext4 deleted file recovery | extundelete | ext4magic / ext3grep | extundelete restores single files from the journal; ext4magic leverages multiple journal versions for stronger recovery |
| Filesystem analysis inside images (NTFS/FAT/ext) | Sleuth Kit(mmls/fls/icat) | autopsy(GUI) | TSK is scriptable from the command line; autopsy is TSK's graphical/timeline front end |
| Full-image timeline (body → CSV) | fls -m + mactime | tsk_gettimes | fls -m generates the body file, mactime turns it into a readable timeline |
| Pulling evidence without parsing the filesystem (emails/URLs/credit cards) | bulk_extractor | — | Feature files + histograms, ideal for a quick pass over large images |
| Rootkit detection | chkrootkit | rkhunter / unhide | chkrootkit is fast; rkhunter ships a baseline attribute database; unhide finds hidden processes/ports |
| JPEG/BMP/WAV steganography (password protected) | steghide | outguess | steghide supports bmp/jpeg/wav/au + encryption; outguess supports JPEG/PPM/PNM |
| Plain-text steganography (trailing whitespace) | stegsnow | — | Hides messages in appended spaces/tabs, with optional ICE encryption |
| Image/directory hash baselines and audits | hashdeep | ssdeep | hashdeep does exact hashing + audit mode; ssdeep uses fuzzy hashing to find "similar" files |
| Malicious sample signature rule matching | yara | — | De-facto-standard rule syntax, recursive directory scanning |
| Suspicious PDF feature detection (JS/OpenAction) | pdfid | pdf-parser | pdfid only counts keywords; pdf-parser drills into objects and streams |
| Windows registry forensics | regripper | reglookup | regripper interprets output through plugins; reglookup is lighter and includes deleted-key recovery |
| Recycle Bin forensics (INFO2 / $I files) | rifiuti2 | rifiuti | rifiuti2 supports both Vista+ $I files and the INFO2 format |
| PE file structure analysis | readpe | missidentify | readpe parses PE headers; missidentify specializes in finding extensionless executables |
| Mail store conversion (PST/DBX) | readpst | undbx | readpst converts PST; undbx handles Outlook Express .dbx |
| Reconstructing application data from pcap (mail/HTTP/VoIP) | xplico | — | NFAT traffic decoding, output viewed in a Web UI |
| Extracting embedded files from CTF attachments/firmware | binwalk | foremost | binwalk identifies signatures and extracts; foremost carves by type |

## Golden Rules of Forensic Workflow

1. **Never analyze original evidence directly**: first image with `dc3dd`/`guymager` while computing hashes in parallel, then run all subsequent operations against the image copy.
2. **Hash while acquiring**: `dc3dd ... hash=sha256 hashlog=... log=...` completes acquisition + verification + logging (chain of custody) in one command.
3. **Sleuth Kit analysis path**: `mmls` for partition offsets → `fls -o <offset>` to list files → `icat`/`tsk_recover` to extract → `mactime` for the timeline.
4. **Prerequisite for deleted file recovery**: the target partition must be unmounted first (or operate on an image only); otherwise the recovery operation itself overwrites the data being recovered.
5. **Cross-validate rootkit detection**: both chkrootkit and rkhunter produce false positives; a single tool reporting "INFECTED" is not conclusive — a second tool plus baseline comparison is required.

## CTF Forensics Fast Track

The standard first-pass pipeline when you receive an unknown attachment (image/PDF/archive/firmware):

```bash
file <file>                        # 文件真实类型(扩展名可能伪造)
exiftool <file>                    # 元数据:注释/作者/GPS 字段常藏 flag(sudo apt install libimage-exiftool-perl)
strings -n 8 <file> | grep -iE "flag|ctf|key|pass"   # 可见字符串初筛
binwalk <file>                     # 签名扫描:内嵌压缩包/文件系统/加密段
binwalk -e <file>                  # 自动提取到 <file>.extracted/ 目录
foremost -i <file> -o carved -t jpg,png,pdf,zip  # binwalk 无果时按类型雕刻
```

Steganography triage order (by carrier type):

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

## Core Tools in Depth

### binwalk — Embedded file identification and extraction in firmware/binaries (frequent in CTF)

**Purpose**: Scans binaries for embedded files and code using libmagic signatures (including a custom firmware signature library: archives, firmware headers, Linux kernels, bootloaders, squashfs, etc.); supports automatic extraction and entropy analysis.
**Install**: Preinstalled on Kali (`sudo apt install binwalk`); the Python library form is `python3-binwalk`.
**Use cases**: The first step of firmware analysis; the go-to for any CTF "file inside a file" scenario (a zip hidden after a PNG, squashfs hidden in firmware).

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

**Practical tips**:
- Extracting squashfs (and variants such as cramfs) requires `sudo apt install sasquatch`; otherwise extraction fails or unpacking errors out.
- `binwalk -e` tries to decompress the compressed streams it identifies; when decompression fails, note the offset and carve it manually with `dd if=<file> of=chunk.bin bs=1 skip=<offset>` for further processing.
- The new-generation Rust rewrite is `binwalk3` (see quick reference); its command-line behavior differs, and Kali's primary command remains `binwalk`.
- Combine with `strings`/`file`: binwalk finds "structure", strings finds "content", file verifies the real type of extracted artifacts.

### dc3dd — Forensically enhanced dd (image acquisition + concurrent hashing)

**Purpose**: A GNU dd patched by the US Department of Defense Cyber Crime Center (DC3); computes hashes during acquisition, writes audit logs, and supports multi-output and piecewise hashing.
**Install**: `sudo apt install dc3dd`
**Use cases**: Any situation requiring reproducible forensic acquisition of a disk/partition/file; its edge over bare `dd` is integrated hashing and logging that satisfies chain-of-custody requirements.

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

**Practical tips**:
- `hashlog=` and `log=` are separate: the former records hashes only, the latter a full operation audit (including start/end times and the command line).
- Use a write blocker on the source device or make sure it is mounted read-only; the output directory must have enough space (the image equals the full disk size).
- Use `dcfldd` (see quick reference) when you need to split large images or get live progress display; use `guymager` for E01 format.

### guymager — High-speed GUI forensic imager

**Purpose**: A Qt-based forensic acquisition program supporting EWF (E01), AFF, and raw image formats, with multithreaded parallel compression and on-the-fly MD5/SHA1/SHA256 hashing during imaging.
**Install**: `sudo apt install guymager`
**Use cases**: When you need E01 format (commercial toolchain compatibility), bulk imaging of many disks at once, or on-site acquisition without memorizing command-line arguments.

```bash
# 启动 GUI(root 权限):设备列表右键 → Acquire Image → 选格式/压缩/哈希
sudo guymager
```

**Practical tips**:
- Parallel compression usually makes it faster than dc3dd/dcfldd's single-stream writes on multi-core machines.
- Can output E01 + a duplicate copy + multi-algorithm hashes at the same time, satisfying chain-of-custody requirements in one step.
- No parameterized CLI imaging; use dc3dd for automated pipelines.

### dd_rescue — Data rescue from failing disks (does not abort on errors)

**Purpose**: Copies data off damaged media; standard tools (cp/dd) abort on the first I/O error, while dd_rescue retries with smaller blocks and supports reverse copying and sparse copying — usable for rescuing failing hard disks/optical discs and for secure multi-pass overwrite erasure.
**Install**: `sudo apt install ddrescue` (note: the binary provided by this package is `dd_rescue`, a different project from GNU ddrescue's `ddrescue`).
**Use cases**: Imaging source disks with bad sectors or read errors; use dc3dd directly for healthy disks.

```bash
# 官方示例:从输入文件位置 100 开始,写到输出文件位置 0
dd_rescue -s 100 /var/log/messages -S 0 /tmp/ddrescue-out

# 抢救整块坏盘到镜像文件(遇到坏块自动缩小块重试)
dd_rescue /dev/sdb /recovery/sdb.img
```

**Practical tips**:
- `-s <pos>` sets the input start position and `-S <pos>` the output start position, enabling segmented relay copying.
- Similar options: myrescue skips bad areas to rescue healthy regions first and comes back for them later; safecopy targets optical/magnetic media such as CDs and floppies; recoverdm writes placeholder empty sectors for unreadable sectors during recovery (all in the quick reference).

### testdisk — Partition scanning and recovery

**Purpose**: Examines disk partition tables and boot sectors, recovers lost partitions, repairs partition tables, and restores NTFS/FAT boot areas from backup boot sectors; supports numerous filesystems.
**Install**: `sudo apt install testdisk` (the same package provides photorec).
**Use cases**: Analyzing and repairing damaged/deleted partition tables, partitions lost to mistaken cloning, and broken boot sectors on bootable disks.

```bash
# 交互式分析:Create log → 选磁盘 → 选分区表类型 → Analyse → Quick Search
sudo testdisk <image.dd>
sudo testdisk /dev/sdc
```

**Practical tips**:
- Fully interactive menu-driven; the typical path is `Analyse` → `Quick Search` → `Deeper Search` → select the found partitions → `Write` to restore the partition table (confirm the target is correct before writing).
- Image the whole disk first and run testdisk on the image, avoiding direct writes to original evidence.
- If the filesystem is also damaged after partitions are found, switch to photorec and carve files directly by signature.

### photorec — Signature-based file carving recovery (filesystem-agnostic)

**Purpose**: The file data recovery software of the TestDisk suite; carves lost files by file-header/internal-structure signatures without depending on the filesystem, supporting a large number of formats such as photos, documents, and archives.
**Install**: `sudo apt install testdisk`
**Use cases**: When the filesystem is damaged/reformatted, too many deleted files make journal-based recovery impractical, or you simply need to "recover everything recoverable".

```bash
# 交互式:选介质 → 选分区 → 选文件系统类型 → 选恢复目录 → Search
sudo photorec <image.dd>
sudo photorec /dev/sdb
```

**Practical tips**:
- Recovery is signature-based and **does not preserve original filenames or directory structure**; output is numbered files under recup_dir.* directories that require secondary sorting by content.
- The `File Opt` menu lets you check only the types you need (e.g. JPG/PDF only), greatly reducing junk output.
- Choosing between photorec/foremost/scalpel: photorec has the most complete type library with internal-structure validation; foremost is lighter and its command-line parameters suit scripting; scalpel's configuration file allows custom header/footer pairs.

### foremost — Header/footer/structure-based file carving

**Purpose**: Recovers lost files from images (produced by dd/Safeback/EnCase) or directly from drives based on file headers, footers, and internal data structures; built-in types are validated against data structures, making recovery more reliable.
**Install**: `sudo apt install foremost`
**Use cases**: When you know which file types you are after (doc/jpg/pdf/xls/zip etc.), carving with specified types is faster and less noisy than a full scan; extracting archives appended to images in CTF.

```bash
# 官方示例:在镜像中雕刻 doc、jpg、pdf、xls 四类文件
foremost -t doc,jpg,pdf,xls -i image.dd

# 指定输出目录(目录必须不存在或为空,-T 可自动加时间戳)
foremost -t jpg,png,zip,pdf -i <image.dd> -o carved_out
```

**Practical tips**:
- The output directory contains an `audit.txt` audit file recording the offset and size of every recovered file, usable as an evidence attachment.
- Supported `-t` types are listed in `foremost -h` (e.g. avi,bmp,exe,gif,jpg,mov,mpg,pdf,png,rar,txt,wav,zip); `-t all` covers all types.
- A faster alternative is scalpel (see below); custom header/footer rules go into `/etc/scalpel/scalpel.conf`.

### scalpel — Fast filesystem-agnostic carving (configurable rules)

**Purpose**: Reads a header/footer definition database and extracts matching files from a set of images or raw devices; filesystem-agnostic — FAT/exFAT/NTFS/ext2-4/JFS/XFS/ReiserFS/raw partitions all work.
**Install**: `sudo apt install scalpel`
**Use cases**: When you need custom carving rules (specific magic headers/footers) or foremost is not fast enough.

```bash
# 从镜像雕刻到输出目录(目录须为空/不存在)
scalpel <image.dd> -o carved_out

# 编辑规则库后按自定义头尾雕刻
sudo vim /etc/scalpel/scalpel.conf
```

**Practical tips**:
- Most rules are commented out in the default configuration; uncomment them as needed, otherwise nothing gets carved (a common pitfall).
- Output likewise includes an audit file; faster than foremost on large images with lower memory usage.

### extundelete — ext3/ext4 deleted file recovery (journal-based)

**Purpose**: Attempts to recover deleted files using metadata preserved in the ext3/ext4 partition journal (success not guaranteed).
**Install**: `sudo apt install extundelete`
**Use cases**: The first choice when the deleted file's path is known and the target is an ext3/ext4 filesystem; use other tools for NTFS.

```bash
# 官方示例:从分区恢复指定文件(相对分区根的路径,不带开头 /)
extundelete /dev/sda1 --restore-file root/importantfile

# 恢复整个目录 / 全部分配删除文件
extundelete <image.img> --restore-directory var/log
extundelete <image.img> --restore-all

# 只查某 inode 的元数据,确认可恢复性
extundelete <image.img> --inode <inode_num>
```

**Practical tips**:
- **The target partition must already be unmounted** (or operate directly on an image); continued mounted writes overwrite the data being recovered — the tool itself warns of this.
- Recovered results are written to `RECOVERED_FILES/` in the current directory; recovery of extended attributes (xattr) is not supported.
- When the deletion is old enough that the journal has rotated and been overwritten, switch to ext4magic (leverages multiple historical journal versions for a higher recovery rate).

### ext4magic — Deep recovery from the ext3/ext4 journal

**Purpose**: An ext3/ext4 file carving/recovery tool: after a file is deleted its inode block pointers are zeroed, but older versions of the metadata often remain in the journal; ext4magic uses them to recover many "unrecoverable" files.
**Install**: `sudo apt install ext4magic`
**Use cases**: The second line of defense after extundelete fails; disaster recovery and forensics.

```bash
# 快速模式:恢复最近删除的文件
ext4magic <image.img> -r -d recovered/

# 全量模式:遍历所有 journal 版本尽力恢复(耗时长)
ext4magic <image.img> -m -d recovered/

# 恢复指定路径(目录或文件)
ext4magic <image.img> -f path/to/dir -d recovered/
```

**Practical tips**:
- `-r` uses the latest journal state (fast); `-m` uses all historical journals (slow but more complete).
- Likewise requires the partition to be unmounted/operating on an image only; recovery output is specified with `-d`.
- For legacy ext3 filesystems you can also try `ext3grep --restore-all` (see quick reference).

### mmls — Sleuth Kit entry point: inspect the image partition layout

**Purpose**: Displays the volume system (partition table) layout of a disk image, listing each partition's start offset, length, and type — that offset is the source of the `-o` argument for all subsequent TSK filesystem tools.
**Install**: `sudo apt install sleuthkit`
**Use cases**: The first step of the Sleuth Kit analysis workflow; run mmls on a new image first to determine the partition layout.

```bash
# 列出镜像分区表:关注 Offset 列(单位:扇区)
mmls <image.dd>

# 带偏移分析嵌套镜像
mmls -o <offset> <image.dd>
```

**Practical tips**:
- In the output, "000: Meta" or "Unallocated" is the volume system itself/unallocated space; filesystem partitions are usually labeled "NTFS / ext* / Linux filesystem".
- Subsequent commands uniformly take the form `fls -o <value from the Offset column> <image.dd>`; `-o` accepts both `2048` and `2048s` (sectors) notations.
- When mmls cannot recognize the partition table, use `mmstat` (to check the volume system type) or testdisk to repair/identify it first.

### fls — Sleuth Kit: list filesystem contents of an image (including deleted)

**Purpose**: Lists files and directories inside an image without relying on the host OS to parse the filesystem; can show deleted and hidden entries; `-m` outputs body format for mactime timelines.
**Install**: `sudo apt install sleuthkit`
**Use cases**: Determining "which files existed at the time and which had been deleted"; the foundational command for a forensic file inventory.

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

**Practical tips**:
- Output format: `r/r * 1234-1234-5: path/to/file`, where `*` marks a deleted entry, `r/r` is the file type/metadata type, and the digit string is the inode (inode-seqid on NTFS).
- The inode of a `*`-marked entry can be handed directly to `icat` to extract content or to `istat` to inspect time attributes.
- On images (NTFS) where deleted entries carry `-seqid` after the inode, pass the full inode-seqid to icat.

### icat — Sleuth Kit: extract file content by inode

**Purpose**: Outputs file data straight from the image by inode number; supports recovering the content of deleted files (`-r`) and does not need the filename to still be valid.
**Install**: `sudo apt install sleuthkit`
**Use cases**: Pulling out file content once fls has located the target inode; especially useful when the filename has been wiped/overwritten but the inode survives.

```bash
# 提取指定 inode 的文件内容
icat -o <offset> <image.dd> <inode> > recovered_file

# 恢复已删除文件内容(含 resident data 处理)
icat -r -o <offset> <image.dd> <inode> > recovered_file
```

**Practical tips**:
- Pass the raw inode value from fls/ils output as the inode argument; for NTFS pass the `inode-seqid` form verbatim.
- Run `file recovered_file` immediately after retrieving content to verify its real type; hash it and record it (hashdeep).
- icat vs tsk_recover: icat is targeted extraction, tsk_recover is bulk export.

### fsstat — Sleuth Kit: overall filesystem information

**Purpose**: Displays detailed structural information about a filesystem in an image: type, block/sector size, inode range, mount times, volume label, NTFS serial number, etc.
**Install**: `sudo apt install sleuthkit`
**Use cases**: Confirming the filesystem type and parameters at an `-o` offset; source material for the "volume information" section of a report.

```bash
# 查看分区文件系统详情
fsstat -o <offset> <image.dd>
```

**Practical tips**:
- The output includes time elements such as Last Mounted and last-write time, useful for cross-checking system clock tampering.
- An error like "Cannot determine file system type" means the offset is wrong; go back to mmls and verify.

### tsk_recover — Sleuth Kit: bulk export of files from an image

**Purpose**: Recovers files from an image into a directory in bulk; can export only allocated files or everything (including deleted).
**Install**: `sudo apt install sleuthkit`
**Use cases**: When you need to export image contents wholesale and process them with conventional tools (grep/AV/review) instead of extracting inode by inode.

```bash
# 导出全部文件(已分配 + 已删除)
tsk_recover -e -o <offset> <image.dd> /out/recovered/

# 只导出(当前文件系统可见的)已分配文件
tsk_recover -a -o <offset> <image.dd> /out/allocated/
```

**Practical tips**:
- Content recovered for deleted files is not guaranteed to be complete (blocks may have been reused); verify with `file`/by opening it.
- The output directory must already exist; exporting large numbers of small files is slow — icat is faster when you only need a few files.

### mactime — Timeline generation (body file → CSV)

**Purpose**: Reads TSK body-format files (generated by fl -m / ils -m / tsk_gettimes) and outputs a time-sorted filesystem timeline (macb: modified/accessed/changed/born).
**Install**: `sudo apt install sleuthkit`
**Use cases**: Intrusion timeline reconstruction: combined with log timestamps, locate "which files were created/modified/deleted around a given moment".

```bash
# 标准 pipeline:fls 生成 body,mactime 转 CSV(-d 逗号分隔,可直接进表格)
fls -m / -r -p -o <offset> <image.dd> > body.txt
mactime -b body.txt -d > timeline.csv
```

**Practical tips**:
- In the `MACB` output column, a letter means that time field is non-zero (M=modified, A=accessed, C=inode change, B=created); `*` marks timestamps earlier than 1970 or otherwise suspicious.
- NTFS "birth time" (B) is very useful for pinpointing attacker-dropped files; EXT filesystems have no B time.
- For large batches of images, first generate body files with `tsk_gettimes <image>` (see quick reference), then run mactime across them uniformly.

### autopsy — Graphical forensic browser for Sleuth Kit

**Purpose**: A GUI front end for The Sleuth Kit providing filesystem analysis for NTFS/FAT/ext and more, keyword search, timelines, and hash filtering — a free near-replacement for commercial forensic tools.
**Install**: `sudo apt install autopsy`
**Use cases**: When you would rather not type TSK commands one by one and need to interactively browse an image's files/deleted content/timelines for case analysis.

```bash
# Kali 仓库为 legacy 2.x 版本:启动内置 Web 服务,按提示用浏览器打开
sudo autopsy
# 浏览器访问: http://localhost:9999/autopsy
```

**Practical tips**:
- 2.x uses a web interface flow (New Case → Add Image → Analyze); underneath it is the same fls/icat/mactime toolchain, so once you know the CLI the GUI is just an accelerator.
- Full modern Autopsy 4.x features (_ingest plugins, video, etc.) require running the official version on Windows.
- For headless/automated scenarios use the Sleuth Kit command line directly; do not depend on autopsy.

### bulk_extractor — Whole-image evidence extraction without filesystem parsing

**Purpose**: A C++ scanner that extracts useful information (emails, URLs, domains, IPs, credit card numbers, EXIF, phone numbers, etc.) from disk images/files/directories without parsing the filesystem; results are written to feature files and histograms are generated.
**Install**: `sudo apt install bulk-extractor`
**Use cases**: A quick sift through large images: you do not care about file structure, only about which emails/URLs/encryption clues (e.g. TrueCrypt headers) appear inside.

```bash
# 官方示例:分析镜像并输出到目录
bulk_extractor -o bulk-out xp-laptop-2005-07-04-1430.img

# 常规用法:输出目录会包含 email.txt、url.txt、domain.txt、ccn.txt 等特征文件
bulk_extractor -o /evidence/be-out <image.dd>
```

**Practical tips**:
- Each feature file in the output directory covers one category; `*_histogram.txt` files are frequency-sorted — "high frequency means important".
- Credit card features (ccn.txt) involve sensitive data; processing and retention must stay within the case's authorized scope.
- When it reports being CPU bound, add `-j <number of threads>` to speed it up (on multi-core machines).

### chkrootkit — Rootkit signature scanning

**Purpose**: Searches the system for signs of 70+ rootkits (signature comparison, hidden files, network interface promiscuous-mode detection, wtmp/lastlog tampering, etc.).
**Install**: `sudo apt install chkrootkit`
**Use cases**: The first quick scan in host intrusion triage; cross-validated with rkhunter.

```bash
# 全量扫描(主要输出:每项检测结果 + 可能的 INFECTED 提示)
sudo chkrootkit

# 专家模式(输出更多原始数据供人工判读)
sudo chkrootkit -x
```

**Practical tips**:
- A lone "INFECTED" line is often a false positive (e.g. a package upgrade leaving the binary inconsistent with its wrapper); confirm with rkhunter and a file hash baseline before drawing conclusions.
- Scanning should happen from a trusted environment: severe rootkits can infect the scanner itself; run from read-only media if necessary.
- Checks include `sniffer` detection (NIC promiscuous mode), which can be a clue to traffic eavesdropping.

### rkhunter — Rootkit Hunter (rootkit/backdoor/sniffer scanning)

**Purpose**: Scans for known/unknown rootkits, backdoors, sniffers, and exploit traces: file hash comparison, hidden files, suspicious permissions, kernel modules, startup items, etc.
**Install**: `sudo apt install rkhunter`
**Use cases**: Routine rootkit checks that need a maintainable baseline attribute database (fewer false positives) and log output.

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

**Practical tips**:
- A warning does not mean infection: it commonly follows hash drift after package updates; re-verify, then refresh the baseline with `--propupd`.
- Logs are in `/var/log/rkhunter.log`; in incident response, preserve the original log before processing.
- Use alongside chkrootkit/unhide as a trio: signature comparison + attribute baselines + hidden process detection complement one another.

### steghide — BMP/JPEG/WAV/AU steganography (with encryption)

**Purpose**: Hides data files in the least significant bits of carrier files, making the presence of the embedded data invisible and hard to prove; supports bmp/jpeg/wav/au, Blowfish encryption, MD5 password hashing, and compressed embedding.
**Install**: `sudo apt install steghide`
**Use cases**: The first guess for CTF image/audio steganography; steganography demos and detection training in authorized exercises.

```bash
# 嵌入:把 secret.txt 藏进 cover.jpg(-p 口令,可省略则交互输入)
steghide embed -cf cover.jpg -ef secret.txt -p <password>

# 检查文件是否含嵌入数据
steghide info stego.jpg

# 提取(输出默认原名;可用 -xf 指定输出路径)
steghide extract -sf stego.jpg -p <password>
steghide extract -sf stego.jpg -p <password> -xf out.bin
```

**Practical tips**:
- Only supports bmp/jpeg/wav/au; for PNG take a different approach (appended data/LSB).
- In CTF, when there is no password hint, try the empty password, the challenge title, and the filename first; for bulk password guessing, use `stegseek` (in the Kali repository) to run a dictionary against steghide passphrases.
- After extracting a binary, follow up with `file`+`binwalk` for second-stage analysis; these are often nested challenges.

### outguess — JPEG/PPM/PNM general steganography (statistically resistant to detection)

**Purpose**: A general steganography tool that embeds information into the redundant bits of a data source and relies on format handlers (supports JPEG, PPM, PNM); its statistical correction makes it relatively resistant to steganalysis.
**Install**: `sudo apt install outguess`
**Use cases**: The second guess for JPEG when steghide comes up empty; when the challenge provides a jpg and steghide reports no embedded data.

```bash
# 嵌入:-k 密钥,-d 要藏的数据文件
outguess -k <key> -d hidden.txt cover.jpg stego.jpg

# 带密钥提取
outguess -r -k <key> stego.jpg output.txt

# 无密钥统计提取(CTF 常见:未设 key)
outguess -r stego.jpg output.txt
```

**Practical tips**:
- After embedding, self-verify with `outguess -k <key> -r ... `; successful extraction displays "Reading ... done" plus stego frame statistics.
- Carrier focus differs from steghide: outguess only takes JPEG/PPM/PNM; the two complement rather than replace each other.

### stegsnow — Text steganography (trailing whitespace + ICE encryption)

**Purpose**: Hides messages in spaces/tabs appended to the end of each line of ASCII text — invisible in text viewers; with built-in encryption, the message cannot be read even if discovered.
**Install**: `sudo apt install stegsnow`
**Use cases**: Plain .txt/.log attachments in CTF that look "normal" under `cat` while the challenge hints at steganography; detecting trailing-whitespace steganography in text.

```bash
# 提取(不带 -p 则用默认口令;先试无口令再试题目提示词)
stegsnow -C stego.txt out.txt

# 带口令提取
stegsnow -C -p <password> stego.txt out.txt

# 嵌入:-m 直接藏消息,或 -f 藏文件内容;-C 压缩
stegsnow -C -p <password> -f secret.txt cover.txt stego.txt
```

**Practical tips**:
- Quick check for whitespace steganography: if `cat -A stego.txt` shows many ` ` before $ at line ends, it is suspicious.
- `-C` enables compression (embedding and extraction must match); with an unknown encryption password the output is gibberish.

### yara — Malicious sample pattern identification and classification

**Purpose**: Identifies and classifies malicious samples using text/binary pattern descriptions (sets of strings + boolean conditions); the rule syntax is the industry de facto standard and supports recursive directory scanning.
**Install**: `sudo apt install yara` (the library `libyara-dev` and docs `yara-doc` come from the same source).
**Use cases**: Bulk sample family classification, IOC sweep scans, and fast triage of suspicious files in incident response.

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

**Practical tips**:
- Compile rules for speed: after `yarac <rules.yar> compiled.yarc`, use the compiled file as the first argument.
- Rule sources: community rule repositories (the official YARA repository, Florian Roth's signature-base) can be downloaded and used directly; mind their freshness.
- A hit only means a signature matched; classification still requires dynamic/manual analysis; `-s` prints the positions of matched strings to aid analysis.

### hashdeep — Recursive hash computation and audit mode

**Purpose**: Recursively computes MD5/SHA1/SHA256/Tiger/Whirlpool hashes; supports piecewise hashing and audit mode (comparison against a known hash set for additions, deletions, and modifications).
**Install**: `sudo apt install hashdeep`
**Use cases**: Evidence integrity baselines, before/after comparison of images/directories (whether tampered, which files are new), and compliance audits.

```bash
# 递归计算目录 SHA256 基线
hashdeep -c sha256 -r /evidence > baseline.txt

# 审计模式:与基线比对,输出匹配/不匹配/新增(证据链完整性证明)
hashdeep -c sha256 -r -a -k baseline.txt /evidence

# 只显示不在基线中的文件(-x 负向匹配,找"新出现的文件")
hashdeep -c sha256 -r -x -k baseline.txt /evidence
```

**Practical tips**:
- The hash algorithm must be identical before and after auditing (same `-c` argument), otherwise everything mismatches.
- Piecewise hashing of large files suits resumed-transfer verification scenarios; `-l` outputs relative paths for easier migration.
- Use ssdeep, not hashdeep, to find "similar but not identical" files (e.g. malware variants).

### ssdeep — Fuzzy hashing (similar file matching)

**Purpose**: Context-triggered piecewise hashing (CTPH/fuzzy hashing): beyond matching fully identical files the way md5sum does, it also matches files with small differences by similarity percentage.
**Install**: `sudo apt install ssdeep`
**Use cases**: Clustering malware variants, consolidating multiple versions of the same trojan, and tracing duplicate documents.

```bash
# 递归生成目录模糊哈希集合
ssdeep -r /samples > hashes.txt

# 匹配模式:拿目录/文件与哈希集合比对,输出相似度百分比
ssdeep -m hashes.txt -r /new_samples

# 比较两个文件相似度
ssdeep file1.bin file2.bin
```

**Practical tips**:
- The output percentage is similarity, not confidence: >90% essentially means the same origin; <50% requires manual review.
- Fuzzy hashing works for "broadly similar" files but is distorted by packed/encrypted samples — unpack first, then compare.

### pdfid — Quick screening of suspicious PDF keywords

**Purpose**: Does not parse the PDF; it only counts occurrences of PDF keywords in the file (e.g. /JS, /JavaScript, /OpenAction, /Launch, /AA) and handles name obfuscation, quickly identifying PDFs that contain scripts or automatic actions.
**Install**: `sudo apt install pdfid`
**Use cases**: First-round risk screening of PDF batches; the first step of CTF PDF challenges.

```bash
# 官方示例:统计关键词计数
pdfid /usr/share/doc/texmf/fonts/lm/lm-info.pdf

# 目标文件筛查
pdfid <file.pdf>
```

**Practical tips**:
- Any non-zero count for `/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/AA`, or `/AcroForm` is worth digging into (possibly embedded JS or an action triggered on open).
- pdfid normalizes name obfuscation (e.g. `/J#61vaScript`), so it is not easily bypassed.
- Once a count looks abnormal, move to pdf-parser to locate the specific objects.

### pdf-parser — PDF structure parsing and object extraction

**Purpose**: Parses the basic elements of a PDF document (objects, streams, xref, trailer) and extracts/decompresses them on demand; no rendering.
**Install**: `sudo apt install pdf-parser`
**Use cases**: Locating specific objects after pdfid flags a PDF; extracting embedded file streams; analyzing JS and malicious payloads.

```bash
# 官方示例:统计文档元素(间接对象数等)
pdf-parser -a /usr/share/doc/texmf/fonts/lm/lm-info.pdf

# 搜索包含指定关键词的对象(如 JavaScript、OpenAction)
pdf-parser -s /JavaScript <file.pdf>

# 查看指定编号对象;配合 -f 解压流,-d 导出流内容到文件
pdf-parser -o <obj_id> <file.pdf>
pdf-parser -o <obj_id> -f -d stream.bin <file.pdf>
```

**Practical tips**:
- With `-a` statistics, look at the total number of indirect objects and streams first, then decide which object to dig into.
- After stream decompression (-f), what gets dumped is often zlib-decompressed JS or an embedded file — feed it directly to `file`/text search.
- Objects inside object streams (ObjStm) must be unwrapped with pdf-parser and inspected layer by layer; do not look only at the surface xref.

### regripper — Windows registry forensics plugin framework

**Purpose**: Uses Perl plugins to "surgically" extract, translate, and present data from registry hives (SAM/SYSTEM/SOFTWARE/NTUSER.DAT); can run per plugin or per profile (a plugin list), with results to STDOUT.
**Install**: `sudo apt install regripper`
**Use cases**: Extracting user traces, autostart entries, USB history, network configuration, and other forensically relevant points from Windows images.

```bash
# 单插件运行(-r hive,-p 插件)
regripper -r <NTUSER.DAT> -p userassist

# 按 profile 批量运行(-f 如 system/software/sam/ntuser/all)
regripper -r <SYSTEM> -f system

# 常用插件示例:run(自启动)、usbstor(USB 设备)、shellbags、recentdocs
regripper -r <SOFTWARE> -p run
regripper -r <SYSTEM> -p usbstor
```

**Practical tips**:
- Pull the hive files out of the image first (usually under `/Windows/System32/config/` and the user profile's `NTUSER.DAT`); do not run directly against a mounted system.
- Choose either `-p` or `-f`; plugin names/overview are in the bundled plugin directory (`/usr/share/regripper`).
- For dirty hives (no clean shutdown), pair with `reglookup-recover` (see quick reference) to read deleted keys and leftover data.

## Remaining Tools — Quick Reference

| Tool | One-line Purpose | Package | Most Common Command |
|---|---|---|---|
| binwalk3 | New-generation Rust rewrite of binwalk; scans/extracts embedded files as a single binary | binwalk3 | `binwalk3 <file>` |
| blkcalc | TSK: converts between disk block addresses and filesystem block addresses | sleuthkit | `blkcalc -o <offset> <image> <block>` |
| blkcat | TSK: dumps block content by data block number | sleuthkit | `blkcat -o <offset> <image> <block>` |
| blkls | TSK: exports unallocated space (for carving) | sleuthkit | `blkls -o <offset> <image> > unalloc.bin` |
| blkstat | TSK: queries data block allocation status and times | sleuthkit | `blkstat -o <offset> <image> <block>` |
| dcfldd | US DoD lab-enhanced dd (hashing/splitting/progress) | dcfldd | `dcfldd if=/dev/sdc of=disk.img hash=sha256 hashlog=hash.txt` |
| ext3grep | Deleted file recovery for ext3 filesystems | ext3grep | `ext3grep <image.img> --restore-all` |
| ffind | TSK: reverse-looks-up filenames from inodes (including deleted) | sleuthkit | `ffind -o <offset> <image> <inode>` |
| galleta | Parses IE cookie files into delimited field tables | galleta | `galleta -d";" <cookie.txt>` |
| grokevt-addlog | Appends Windows event logs to a grokevt database | grokevt | `grokevt-addlog <db-dir> <log.evt>` |
| grokevt-builddb | Builds an event log database from a mounted Windows partition | grokevt | `grokevt-builddb /mnt/windows /tmp/grokevt-db` |
| grokevt-findlogs | Searches mounted partitions for Windows event log files | grokevt | `grokevt-findlogs /mnt/windows` |
| grokevt-parselog | Parses event logs into human-readable format | grokevt | `grokevt-parselog <db-dir> System` (`-l <db-dir>` lists available log names) |
| grokevt-ripdll | Extracts event message templates from PE DLLs | grokevt | `grokevt-ripdll <msgdll.dll>` |
| hexwalk | GUI hex editor/analyzer (integrates binwalk/hashing/strings) | hexwalk | `hexwalk` (GUI) |
| hfind | TSK: hash database indexing and lookup | sleuthkit | `hfind -i sha1sum <hashdb.txt>` (`hfind <hashdb.txt> <hash>` after indexing) |
| ifind | TSK: reverse-looks-up inodes by block number/filename | sleuthkit | `ifind -o <offset> -d <block> <image>` |
| ils | TSK: lists inode metadata structures | sleuthkit | `ils -o <offset> <image>` |
| img_cat | TSK: outputs the image raw data stream | sleuthkit | `img_cat <image>` |
| img_stat | TSK: shows image format information | sleuthkit | `img_stat <image>` |
| istat | TSK: detailed inode metadata (timestamps/block lists) | sleuthkit | `istat -o <offset> <image> <inode>` |
| jcat | TSK: reads filesystem journal (NTFS $Log/ext journal) blocks | sleuthkit | `jcat -o <offset> <image> <journal_block>` |
| jls | TSK: lists filesystem journal entries | sleuthkit | `jls -o <offset> <image>` |
| magicrescue | Rescues files from devices/images by magic bytes + recipes | magicrescue | `magicrescue -r jpeg-exif -d /out /dev/sdb1` |
| missidentify | Finds extensionless win32 PE executables | missidentify | `missidentify -a <dir>` |
| mmcat | TSK: exports partition (volume) raw data | sleuthkit | `mmcat <image> <vol_id> > part.raw` |
| mmstat | TSK: shows volume system type information | sleuthkit | `mmstat <image>` |
| myrescue | Data rescue from damaged media (good areas first, then bad) | myrescue | `myrescue /dev/sdb1 /out/sdb1.img` |
| pasco | Parses IE index.dat cache records | pasco | `pasco <index.dat>` |
| readpe | Parses Windows PE headers/sections/imports/exports | readpe | `readpe <file.exe>` |
| readpst | Converts Outlook PST to mbox/eml | pst-utils | `readpst -o <outdir> <file.pst>` |
| recoverdm | Bad-sector media recovery (fills unreadable sectors with zeros and continues) | recoverdm | `recoverdm -h` (parameters are complex; follow the prompts) |
| recoverjpeg | Recovers JPEG/MOV from devices/images (ships with recovermov, remove-duplicates, sort-pictures) | recoverjpeg | `recoverjpeg -o <outdir> /dev/sdb1` |
| reglookup | Windows registry command-line reading/path queries | reglookup | `reglookup -p /Microsoft/Windows/CurrentVersion/Run <SOFTWARE>` |
| rifiuti | INFO2 analysis for legacy Windows Recycle Bins | rifiuti | `rifiuti <INFO2>` |
| rifiuti2 | Recycle Bin analysis (INFO2 + Vista+ $I files; outputs deletion times/original paths) | rifiuti2 | `rifiuti2 <recycle_dir>` |
| safecopy | Data recovery from damaged media (CD/floppy/HDD) | safecopy | `safecopy /dev/sr0 cd.img` |
| scrounge-ntfs | NTFS partition file tree recovery | scrounge-ntfs | `scrounge-ntfs -d <outdir> /dev/sda1` |
| sigfind | Searches an image for offsets matching a hexadecimal signature | sleuthkit | `sigfind <hex_signature> <image>` |
| sorter | TSK: sorts image contents by file type with extension validation | sleuthkit | `sorter -o <offset> -d <outdir> <image>` |
| srch_strings | TSK: string extraction from images (equivalent to strings) | sleuthkit | `srch_strings -t d <image>` |
| stegosuite | GUI image steganography (BMP/GIF/JPG/PNG, AES encryption) | stegosuite | `stegosuite` (GUI) |
| tailscale | WireGuard secure networking (remote access/evidence transfer for forensic teams) | tailscale | `tailscale up` |
| tsk_comparedir | TSK: diffs image contents against a local directory | sleuthkit | `tsk_comparedir -o <offset> <image> <dir>` |
| tsk_gettimes | TSK: generates body files directly (timeline input) | sleuthkit | `tsk_gettimes -o <offset> <image> > body.txt` |
| tsk_loaddb | TSK: loads image metadata into SQLite for SQL queries | sleuthkit | `tsk_loaddb -d <db.sqlite> <image>` |
| undbx | Outlook Express .dbx mail extraction/recovery/un-deletion | undbx | `undbx <dbx file or directory> <outdir>` |
| unhide | Detects processes and TCP/UDP ports hidden by rootkits/LKMs | unhide | `sudo unhide brute; sudo unhide-tcp` |
| vinetto | Parses Windows Thumbs.db thumbnails and metadata | vinetto | `vinetto -o ./thumbs_out <Thumbs.db>` |
| xplico-webui-start | Starts the Xplico network forensics (pcap application data reconstruction) web service | xplico | `sudo xplico-webui-start` |
| xplico-webui-stop | Stops the Xplico service | xplico | `sudo xplico-webui-stop` |

---

Use only in penetration testing, CTF competitions, and security education scenarios that have written authorization.
