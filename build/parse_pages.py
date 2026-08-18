#!/usr/bin/env python
"""Parse Kali tool pages v3.
Structure discovered:
  <h1 id=tool-documentation>Tool Documentation:</h1>
    <h2 id=...>BIN Usage Example</h2>
      <p>prose explaining the command and flags</p>
      <pre><code>root@kali:~# ...</code></pre>
  <h1 id=packages-and-binaries>Packages and Binaries:</h1>
    <h3 id=b>binary</h3> <p><strong>desc</strong>...</p> <p>size/install</p>
"""
import json, pathlib, re, html as htmllib

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / 'data'
PAGES = DATA / 'pages'

def unesc(s):
    return htmllib.unescape(re.sub(r'\s+', ' ', s)).strip()

def strip_tags(s):
    return unesc(re.sub(r'<[^>]+>', ' ', s))

def parse_page(path):
    html = path.read_text(encoding='utf-8')
    tool = path.stem

    i_pkg = html.find('id=packages-and-binaries')
    i_pkg = html.find('>', i_pkg) if i_pkg > 0 else len(html)
    doc_zone = html[:i_pkg]
    pkg_zone = html[i_pkg:]

    tm = re.search(r'<title>([^<]+)</title>', html)
    title = unesc(tm.group(1)).replace(' | Kali Linux Tools', '') if tm else tool

    # usage examples: h2 sections, each = prose paragraphs + pre blocks interleaved
    usage = []
    for hm in re.finditer(r'<h2[^>]*>\s*([^<]{1,80}?)\s*Usage Example\s*</h2>(.*?)(?=<h2|<h1|\Z)', doc_zone, re.S):
        binary = unesc(hm.group(1))
        body = hm.group(2)
        # split into segments: paragraphs and pre blocks in order
        parts = []
        for pm in re.finditer(r'(<p[^>]*>.*?</p>)|(<pre[^>]*>.*?</pre>)', body, re.S):
            if pm.group(1):
                t = strip_tags(pm.group(1))
                if t and 'root@kali' not in t:
                    parts.append(('p', t[:600]))
            else:
                code = htmllib.unescape(re.sub(r'<[^>]+>', '', pm.group(2))).strip()
                if code:
                    parts.append(('code', code[:2500]))
        if parts:
            usage.append({'binary': binary, 'parts': parts[:12]})

    # packages
    packages = []
    for bm in re.finditer(r'<h3[^>]*id=[\'"]?([a-z0-9\-_.]+)[\'"]?[^>]*>([^<]{1,80})</h3>(.*?)(?=<h3|<h1|\Z)', pkg_zone, re.S):
        bin_name = unesc(bm.group(2))
        body = bm.group(3)
        descs = []
        for pm in re.finditer(r'<p[^>]*>(.*?)</p>', body, re.S):
            t = strip_tags(pm.group(1))
            if t and not re.match(r'^(Installed size|How to install|Dependencies)', t):
                descs.append(t)
            if len(descs) >= 2:
                break
        inst = re.search(r'sudo apt(?:-get)? install\s*<code>([a-z0-9\-+.:_]+)</code>', body) or \
               re.search(r'sudo apt(?:-get)? install\s*([a-z0-9\-+.:_]+)', body)
        size = re.search(r'Installed size:\s*(?:</?strong>\s*)*<code>([^<]+)</code>', body)
        packages.append({
            'binary': bin_name,
            'desc': ' '.join(descs)[:600],
            'install': inst.group(1) if inst else None,
            'size': size.group(1).strip() if size else None,
        })

    # fallback description: first package desc
    description = packages[0]['desc'] if packages else ''

    return {
        'tool': tool,
        'title': title,
        'description': description,
        'usage': usage[:15],
        'packages': packages[:20],
    }

out, errs = {}, []
for p in sorted(PAGES.glob('*.html')):
    try:
        out[p.stem] = parse_page(p)
    except Exception as e:
        errs.append((p.stem, str(e)[:80]))

(DATA / 'tools_parsed.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf-8')
print(f'Parsed {len(out)}, errors: {len(errs)}', errs[:5])

with_desc = sum(1 for d in out.values() if len(d['description']) > 50)
with_usage = sum(1 for d in out.values() if d['usage'])
n_examples = sum(len(u['parts']) for d in out.values() for u in d['usage'])
print(f'desc>50ch: {with_desc}, tools w/ usage: {with_usage}, total example blocks: {n_examples}')
for t in ['nmap', 'metasploit-framework', 'hashcat', 'hydra']:
    d = out.get(t)
    if d:
        print(f"  {t}: desc={len(d['description'])}ch usage_sections={len(d['usage'])} pkgs={len(d['packages'])}")
