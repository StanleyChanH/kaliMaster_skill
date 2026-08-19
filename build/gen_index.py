#!/usr/bin/env python
"""Generate tool-index.md: full 470-tool index from parsed data. Deterministic, no LLM."""
import json, pathlib, re

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / 'data'
OUT = HERE.parent / 'kali-master' / 'references' / 'tool-index.md'
OUT.parent.mkdir(parents=True, exist_ok=True)

parsed = json.loads((DATA / 'tools_parsed.json').read_text(encoding='utf-8'))

# domain per tool from shards
shard_dir = DATA / 'shards'
tool_domain = {}
for f in shard_dir.glob('*.json'):
    dom = f.stem
    for t in json.loads(f.read_text(encoding='utf-8')):
        tool_domain[t] = dom

DOMAIN_CN = {
    'recon': '侦察/OSINT', 'scanning': '网络扫描', 'web': 'Web 测试', 'exploit': '漏洞利用',
    'passwords': '密码攻击', 'wireless': '无线安全', 'network': '网络攻防', 'adwin': 'AD/Windows 内网',
    'tunnels': '隧道/C2', 'privesc': '提权', 'forensics': '取证/隐写', 'reversing': '逆向/Fuzz',
    'reports': '报告/靶场',
}

lines = [
    '# Kali 工具全量索引(470 工具)',
    '',
    '> **用途**:查找具体工具时读本文件。每行:工具名 | 所属领域 | 用途摘要 | 安装命令。',
    '> 详细用法进入对应领域文件(见文件名前缀)。',
    '',
]

for dom in sorted(set(tool_domain.values()), key=lambda d: list(DOMAIN_CN).index(d) if d in DOMAIN_CN else 99):
    tools = sorted([t for t, d in tool_domain.items() if d == dom])
    lines.append(f'## {DOMAIN_CN.get(dom, dom)}({dom})— {len(tools)} 个')
    lines.append('')
    lines.append('| 工具 | 用途 | 安装 |')
    lines.append('|---|---|---|')
    for t in tools:
        d = parsed[t]
        # clean description: cut at first root@kali / shell output, keep first sentence-ish
        desc = d['description'].replace('|', '/').replace('\n', ' ')
        desc = re.split(r'root@kali|\bUpdated on:|\bHomepage:|This package contains', desc)[0].strip()
        if len(desc) > 160:
            # try to cut at sentence boundary
            cut = desc[:160]
            for sep in ['. ', '? ']:
                p = cut.rfind(sep)
                if p > 40:
                    cut = cut[:p + 1]
                    break
            desc = cut
        # skip near-empty descriptions (dup of name)
        inst = next((p['install'] for p in d['packages'] if p.get('install')), None)
        inst_s = f'`sudo apt install {inst}`' if inst else '—'
        lines.append(f'| `{t}` | {desc} | {inst_s} |')
    lines.append('')

OUT.write_text('\n'.join(lines), encoding='utf-8')
print(f'Wrote {OUT} ({len(lines)} lines, {len(parsed)} tools)')
