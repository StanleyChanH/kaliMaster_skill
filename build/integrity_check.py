#!/usr/bin/env python
"""Integrity check for the kali-master skill.

Checks: file inventory, frontmatter, internal references, code-fence closure,
three-section structure of reference docs, junk markers, tool-index coverage,
and env-check.sh syntax.

Usage:
    python integrity_check.py                          # check repo copy only
    python integrity_check.py --installed <path>       # also diff against an
                                                      # installed copy (hashes)
"""
import argparse, hashlib, json, pathlib, re, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent / 'kali-master'

_ap = argparse.ArgumentParser()
_ap.add_argument('--installed', default=None, help='path to an installed copy to diff against')
_args, _ = _ap.parse_known_args()
DST = pathlib.Path(_args.installed) if _args.installed else None

issues = []

def norm(p, base):
    return str(p.relative_to(base)).replace(chr(92), '/')

# ===== 1. file inventory (+ optional installed-copy diff) =====
src_files = sorted(norm(p, SRC) for p in SRC.rglob('*') if p.is_file())
src_files = [f for f in src_files if not f.startswith('.omc')]  # plugin state, not ours
print(f'[1] repo files: {len(src_files)}')
if DST:
    dst_files = sorted(norm(p, DST) for p in DST.rglob('*') if p.is_file() and not norm(p, DST).startswith('.omc'))
    print(f'    installed files: {len(dst_files)}')
    if src_files != dst_files:
        issues.append(f"file list mismatch: repo-only={set(src_files)-set(dst_files)}, installed-only={set(dst_files)-set(src_files)}")
    else:
        mismatch = [f for f in src_files
                    if hashlib.md5((SRC/f).read_bytes()).hexdigest() != hashlib.md5((DST/f).read_bytes()).hexdigest()]
        if mismatch:
            issues.append(f'hash mismatch: {mismatch}')
        else:
            print('    repo == installed (per-file hashes)')

# ===== 2. SKILL.md frontmatter =====
skill = (SRC/'SKILL.md').read_text(encoding='utf-8')
m = re.match(r'^---\s*\n(.*?)\n---\s*\n', skill, re.S)
if not m:
    issues.append('SKILL.md frontmatter missing/malformed')
else:
    fm = m.group(1)
    if not re.search(r'^name:\s*[\w\-]+\s*$', fm, re.M): issues.append('frontmatter missing name')
    if not re.search(r'^description:', fm, re.M): issues.append('frontmatter missing description')
    print('[2] frontmatter: OK' if 'frontmatter' not in ' '.join(issues) else '[2] frontmatter: FAIL')

# ===== 3. internal references =====
all_md = list(SRC.rglob('*.md'))
broken = []
for p in all_md:
    for ref in re.findall(r'(?:references|workflows|scripts)/[A-Za-z0-9_\-]+\.(?:md|sh)', p.read_text(encoding='utf-8')):
        if not (SRC/ref).exists():
            broken.append(f'{p.name} -> {ref}')
print(f'[3] internal refs across {len(all_md)} md files:', 'OK' if not broken else broken)
if broken: issues.append(f'broken refs: {broken}')

# ===== 4. code fence closure =====
unclosed = [p.name for p in all_md
            if len(re.findall(r'^\s*```', p.read_text(encoding='utf-8'), re.M)) % 2]
print('[4] code fences:', 'OK' if not unclosed else unclosed)
if unclosed: issues.append(f'unclosed fences: {unclosed}')

# ===== 5. reference docs structure =====
struct = []
for p in sorted(list(SRC.glob('references/0*.md')) + list(SRC.glob('references/1*.md'))):
    t = p.read_text(encoding='utf-8')
    missing = [s for s in ('## 快速决策表', '## 核心工具详解', '## 其余工具速查') if s not in t]
    if missing: struct.append(f'{p.name} missing {missing}')
print('[5] 3-section structure of 13 reference docs:', 'OK' if not struct else struct)
issues.extend(struct)

# ===== 6. junk markers =====
junk = []
for p in all_md:
    t = p.read_text(encoding='utf-8')
    if re.search(r'TODO|FIXME', t): junk.append(f'{p.name}: TODO/FIXME')
    if re.search(r'^##\s*$', t, re.M): junk.append(f'{p.name}: empty section')
print('[6] junk markers:', 'OK' if not junk else junk)
if junk: issues.append(f'junk: {junk}')

# ===== 7. tool-index coverage vs shards =====
expected = set()
for f in (HERE/'data'/'shards').glob('*.json'):
    expected.update(json.loads(f.read_text(encoding='utf-8')).keys())
idx = (SRC/'references'/'tool-index.md').read_text(encoding='utf-8')
missing = [t for t in expected if f'`{t}`' not in idx]
row_names = [l.split('`')[1] for l in idx.splitlines() if l.startswith('| `')]
dupes = len(row_names) - len(set(row_names))
sections = len(re.findall(r'^## ', idx, re.M))
print(f'[7] tool-index: {len(set(row_names))}/{len(expected)} tools, dupes={dupes}, sections={sections}')
if missing: issues.append(f'index missing tools: {missing}')
if dupes: issues.append(f'index has {dupes} duplicated tool rows (generator regression?)')
if sections != 13: issues.append(f'index has {sections} domain sections, expected 13')

# ===== 8. env-check.sh syntax (git-bash if available, else bash) =====
bash = None
for cand in (r'C:/Program Files/Git/usr/bin/bash.exe', 'bash'):
    r = subprocess.run(['where' if sys.platform == 'win32' else 'which', cand],
                       capture_output=True, text=True) if '/' not in cand and '\\' not in cand else None
    if cand == 'bash' and (r and r.returncode == 0):
        bash = 'bash'
        break
    if pathlib.Path(cand).exists():
        bash = cand
        break
print('[8] env-check.sh syntax:', end=' ')
if bash:
    r = subprocess.run([bash, '-n', (SRC/'scripts'/'env-check.sh').as_posix()],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    if r.returncode != 0:
        issues.append(f'env-check.sh syntax error: {r.stderr.strip()[:200]}')
        print('FAIL')
    else:
        print('OK')
else:
    print('SKIPPED (no bash found)')

print()
if issues:
    print(f'=== {len(issues)} ISSUE(S) ===')
    for i in issues: print(' FAIL:', i)
    sys.exit(1)
print('=== ALL CHECKS PASSED ===')
