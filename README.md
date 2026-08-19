# kali-master

**Kali Linux Penetration Testing Skill for Claude Code** — lets Claude Code *pick the right tool, produce accurate commands, and follow standard methodology* across pentest, CTF, and vulnerability assessment work.

[![English](https://img.shields.io/badge/README-English-blue)](README.md) [![简体中文](https://img.shields.io/badge/README-简体中文-red)](README.zh-CN.md)

![CI](https://img.shields.io/github/actions/workflow/status/StanleyChanH/kaliMaster_skill/ci.yml?branch=main) ![tools](https://img.shields.io/badge/tools-470+-blue) ![references](https://img.shields.io/badge/references-13_domains-green) ![workflows](https://img.shields.io/badge/workflows-3_playbooks-orange) ![verified](https://img.shields.io/badge/commands-61_fixes_applied-brightgreen) ![license](https://img.shields.io/badge/license-MIT-lightgrey)

- **Full coverage of 470+ tools** — data scraped page-by-page from the official [kali.org/tools](https://www.kali.org/tools/) documentation (16 MITRE ATT&CK tactic categories, 337 official usage examples, complete apt install info)
- **13 domain references** — Recon / Scanning / Web / Exploitation / Passwords / Wireless / MITM / AD & Windows intranet / Tunneling / Privilege escalation / Forensics / Reversing / Reporting
- **3 workflow playbooks** — full authorized pentest engagement, CTF by category, and compliance-focused vulnerability assessment
- **Progressive loading** — the entry file is only ~160 lines resident in context; domain references load on demand per task, so ordinary coding tasks pay no token overhead
- **Compliance built-in** — an authorization gate (written authorization / CTF / own assets / defensive research) precedes every offensive action

## Installation

```bash
# User-level (available in all projects, recommended)
git clone https://github.com/StanleyChanH/kaliMaster_skill.git
mkdir -p ~/.claude/skills
cp -r kaliMaster_skill/kali-master ~/.claude/skills/

# Or project-level (current project only)
mkdir -p .claude/skills && cp -r kaliMaster_skill/kali-master .claude/skills/
```

Restart Claude Code (or open a new session) and the skill activates automatically.

## Quick Start

After installation, just talk naturally — the skill routes to the right domain reference per task:

| You say | Claude does |
|---|---|
| "Run a full port and service scan on 10.10.10.5" | nmap/masscan combo, `-oA` output files, result interpretation |
| "This HTB box has port 80 open, enumerate it" | whatweb → ffuf → nikto chain + CMS fingerprinting |
| "Crack this NTLM hash with hashcat" | identify mode 1000 → rockyou → background run + progress |
| "CTF gave me a pcap" | tshark filter patterns + stream extraction + credential sniffing |
| "Got a shell, how do I escalate?" | linpeas/winpeas flow + SUID/cron checklists |
| "I have a set of domain creds, what next?" | nxc validation → impacket lateral movement → BloodHound path analysis |

## Structure

```
kali-master/                    # the skill itself (copy this directory)
├── SKILL.md                    # entry: auth gate → env check → task routing → principles
├── references/                 # domain deep-dives (loaded on demand)
│   ├── 01-recon.md             # Recon/OSINT · theHarvester amass subfinder sherlock…
│   ├── 02-scanning.md          # Scanning · nmap masscan autorecon enum4linux OpenVAS…
│   ├── 03-web-testing.md       # Web · sqlmap ffuf nikto wpscan nuclei burpsuite…
│   ├── 04-exploitation.md      # Exploitation · metasploit msfvenom searchsploit veil…
│   ├── 05-passwords.md         # Passwords · hashcat john hydra cewl seclists…
│   ├── 06-wireless.md          # Wireless · aircrack-ng suite wifite reaver hackrf…
│   ├── 07-network-attacks.md   # MITM/sniffing · ettercap bettercap dsniff scapy…
│   ├── 08-ad-windows.md        # AD/intranet · impacket netexec BloodHound responder…
│   ├── 09-tunnels-c2.md        # Tunneling · chisel ligolo-ng sshuttle proxychains…
│   ├── 10-privesc.md           # Privesc · linpeas winpeas pspy + checklists
│   ├── 11-forensics.md         # Forensics · binwalk testdisk foremost steghide…
│   ├── 12-reversing.md         # Reversing · ghidra radare2 gdb+gef jadx…
│   ├── 13-reporting-labs.md    # Reporting/labs · dradis eyewitness DVWA juice-shop…
│   └── tool-index.md           # full index of all 470 tools (grep it, don't read it)
├── workflows/
│   ├── pentest-engagement.md   # standard authorized pentest methodology
│   ├── ctf.md                  # CTF playbook (Web/Pwn/Rev/Crypto/Forensics/Misc)
│   └── vuln-assessment.md      # compliance-focused vuln assessment (verify, don't exploit)
└── scripts/
    └── env-check.sh            # environment & tool availability self-check

build/                          # data build & QA pipeline (optional, see build/README.md)
```

## Quality Assurance

1. **Authentic data** — every tool entry comes from scraped official kali.org pages, not model memory
2. **Independent verification** — all 16 documents were reviewed by independent verifier agents (command/flag authenticity spot-checks, shard coverage cross-checks)
3. **Closed-loop fixes** — all 61 command errors found during verification (outdated flags, swapped options, CLI breaking changes) were applied and re-checked
4. **Repeatable QA** — `python build/integrity_check.py` runs a full health check (structure / references / coverage / syntax)

## Maintenance

Data and the tool index can be rebuilt from the official site — see [build/README.md](build/README.md).

## Legal / Compliance

This skill is intended for **authorized** penetration testing, CTF competitions, lab practice, and security education. SKILL.md contains a built-in authorization gate; requests targeting unauthorized third-party systems are refused. Always ensure your actions stay within written authorization.

## License

[MIT](LICENSE) © 2026 StanleyChanH
