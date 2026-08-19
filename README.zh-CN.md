# kali-master

**Kali Linux 渗透测试 Skill for Claude Code** —— 让 Claude Code 在渗透测试、CTF、漏洞评估任务中**选对工具、给出准确命令、按标准流程推进**。

[![English](https://img.shields.io/badge/README-English-blue)](README.md) [![简体中文](https://img.shields.io/badge/README-简体中文-red)](README.zh-CN.md)

![CI](https://img.shields.io/github/actions/workflow/status/StanleyChanH/kaliMaster_skill/ci.yml?branch=main) ![tools](https://img.shields.io/badge/tools-470+-blue) ![references](https://img.shields.io/badge/references-13_domains-green) ![workflows](https://img.shields.io/badge/workflows-3_playbooks-orange) ![verified](https://img.shields.io/badge/commands-61_fixes_applied-brightgreen) ![license](https://img.shields.io/badge/license-MIT-lightgrey)

- **470+ 工具全覆盖**:数据逐页抓取自 [kali.org/tools](https://www.kali.org/tools/) 官方文档(16 个 ATT&CK 战术分类、337 条官方用法示例、完整 apt 安装信息)
- **13 个领域参考**:侦察 / 扫描 / Web / 利用 / 密码 / 无线 / MITM / AD 内网 / 隧道 / 提权 / 取证 / 逆向 / 报告
- **3 套实战 playbook**:授权渗透全流程、CTF 分题型手册、合规漏洞评估
- **渐进式加载**:入口仅 ~160 行常驻上下文,参考文档按任务路由按需读取,不影响普通编码任务的 token 开销
- **合规内建**:授权确认门(书面授权 / CTF / 自有资产 / 防御研究)是每次主动操作的先决步骤

## 安装

```bash
# 用户级(所有项目可用,推荐)
git clone https://github.com/StanleyChanH/kaliMaster_skill.git
mkdir -p ~/.claude/skills
cp -r kaliMaster_skill/kali-master ~/.claude/skills/

# 或项目级(仅当前项目)
mkdir -p .claude/skills && cp -r kaliMaster_skill/kali-master .claude/skills/
```

安装后重启 Claude Code 或新开会话即自动生效。

## 快速上手

安装后直接用自然语言,skill 会按任务自动路由到对应领域参考:

| 你说 | Claude 会做 |
|---|---|
| "对 10.10.10.5 做全面端口和服务扫描" | nmap/masscan 组合 + `-oA` 落盘 + 结果解读 |
| "这个 HTB 靶机开了 80 端口,帮我枚举" | whatweb → ffuf → nikto 链路 + CMS 识别 |
| "用 hashcat 破解这个 NTLM hash" | 识别模式 1000 → rockyou → 后台跑 + 进度查看 |
| "CTF 给了个 pcap" | tshark 过滤器套路 + 流提取 + 凭据嗅探 |
| "拿到 shell 了,怎么提权" | linpeas/winpeas 流程 + SUID/cron 检查清单 |
| "已知一组域凭据,下一步" | nxc 验证 → impacket 横向 → BloodHound 路径分析 |

## 结构

```
kali-master/                    # skill 本体(复制这个目录)
├── SKILL.md                    # 入口:授权确认 → 环境检测 → 任务路由 → 执行原则
├── references/                 # 领域详解(按需加载)
│   ├── 01-recon.md             # 侦察/OSINT · theHarvester amass subfinder sherlock…
│   ├── 02-scanning.md          # 扫描 · nmap masscan autorecon enum4linux OpenVAS…
│   ├── 03-web-testing.md       # Web · sqlmap ffuf nikto wpscan nuclei burpsuite…
│   ├── 04-exploitation.md      # 利用 · metasploit msfvenom searchsploit veil…
│   ├── 05-passwords.md         # 密码 · hashcat john hydra cewl seclists…
│   ├── 06-wireless.md          # 无线 · aircrack-ng 套件 wifite reaver hackrf…
│   ├── 07-network-attacks.md   # MITM/嗅探 · ettercap bettercap dsniff scapy…
│   ├── 08-ad-windows.md        # AD/内网 · impacket netexec BloodHound responder…
│   ├── 09-tunnels-c2.md        # 隧道 · chisel ligolo-ng sshuttle proxychains…
│   ├── 10-privesc.md           # 提权 · linpeas winpeas pspy + 检查清单
│   ├── 11-forensics.md         # 取证 · binwalk testdisk foremost steghide…
│   ├── 12-reversing.md         # 逆向 · ghidra radare2 gdb+gef jadx…
│   ├── 13-reporting-labs.md    # 报告/靶场 · dradis eyewitness DVWA juice-shop…
│   └── tool-index.md           # 470 工具全量索引(Grep 检索)
├── workflows/
│   ├── pentest-engagement.md   # 标准授权渗透测试全流程
│   ├── ctf.md                  # CTF 解题手册(Web/Pwn/Rev/Crypto/Forensics/Misc)
│   └── vuln-assessment.md      # 合规漏洞评估(只验证不利用)
└── scripts/
    └── env-check.sh            # 环境与工具可用性自检

build/                          # 数据构建与质检管线(可选,见 build/README.md)
```

## 质量保障

1. **数据真实性**:所有工具条目源自 kali.org 官方页面抓取解析(非模型记忆)
2. **独立验证**:16 份文档逐一经独立验证 agent 审查(命令参数真实性抽查、分片覆盖率核对)
3. **修复闭环**:验证发现的 61 处命令错误(过期参数、张冠李戴的选项、CLI 版本变更等)全部修复
4. **可回归质检**:`python build/integrity_check.py` 一键体检(结构/引用/覆盖/语法)

## 维护

数据与索引可从官网全量重建,见 [build/README.md](build/README.md)。

## 合规声明

本 skill 面向**已获授权**的渗透测试、CTF 竞赛、靶场练习与安全教学。SKILL.md 内置授权确认门,针对未授权第三方目标的请求会被拒绝。使用者应始终确保操作在书面授权范围内进行。

## License

[MIT](LICENSE) © 2026 StanleyChanH
