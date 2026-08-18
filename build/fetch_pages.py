#!/usr/bin/env python
"""Fetch all Kali tool pages from www.kali.org/tools/<name>/ into data/pages/.

Two-pass logic: direct name lookup first, then known binary->package fallbacks.
Re-run safe: skips tools whose page is already on disk.

Usage:
    python fetch_pages.py            # fetch all (12 workers)
    python fetch_pages.py --force    # re-fetch even if cached
"""
import json, pathlib, re, sys, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / 'data'
PAGES = DATA / 'pages'
PAGES.mkdir(parents=True, exist_ok=True)

RAW_LIST = DATA / 'tools_raw_list.json'
RESULT_FILE = DATA / 'fetch_results.json'

# binary -> parent package page candidates on kali.org/tools/ (used when a
# binary name has no standalone page; keys are the *page name* we store under)
FALLBACKS = {
    'uniscan-gui': ['uniscan'],
    'gvm-start': ['gvm-tools', 'openvas', 'greenbone-security-assistant'],
    'gvm-stop': ['gvm-tools', 'openvas', 'greenbone-security-assistant'],
    'gvm-setup': ['gvm-tools', 'openvas', 'greenbone-security-assistant'],
    'gvm-check-setup': ['gvm-tools', 'openvas', 'greenbone-security-assistant'],
    'wcvs': ['wcvs'],
    'fang': ['fang'],
    'hackrf_info': ['hackrf'],
    'wash': ['reaver', 'wifite'],
    'ubertooth-util': ['ubertooth'],
    'gqrx': ['gqrx-kai', 'gnuradio'],
    'wixl': ['wixl'],
    'donut': ['donut'],
    'wmic': ['wmi-client'],
    'wmis': ['wmi-client'],
    'olefile': ['oletools'],
    'olevba': ['oletools'],
    'afl-fuzz': ['american-fuzzy-loph', 'afl++'],
    'generic_chunked': ['sfuzz'], 'generic_listen_tcp': ['sfuzz'],
    'generic_send_tcp': ['sfuzz'], 'generic_send_udp': ['sfuzz'],
    'clang': ['llvm-toolchain'], 'clang++': ['llvm-toolchain'],
    'edb': ['edb-debugger'],
    'cstool': ['capstone'],
    'cutter': ['rizin-cutter', 'cutter'],
    'recstudio': ['recstudio'], 'recstudio-cli': ['recstudio'],
    'd2j-dex2jar': ['dex2jar'],
    'searchsploit': ['exploitdb-papers', 'exploitdb'],
    'dns-rebind': ['dns-rebind'],
    'setoolkit': ['set', 'social-engineer-toolkit'],
    'gophish-start': ['gophish'], 'gophish-stop': ['gophish'],
    'jboss-linux': ['jboss'], 'jboss-win': ['jboss'],
    'evilgrade': ['evilgrade'],
    'beef-xss-start': ['beef-xss'], 'beef-xss-stop': ['beef-xss'],
    'peass': ['peass-ng'], 'linpeas': ['peass-ng'], 'winpeas': ['peass-ng'],
    'ftest': ['ftest'],
    'xfreerdp3': ['freerdp3', 'xfreerdp', 'freerdp2'],
    'exe2hex': ['exe2hexbat'],
    'maskgen': ['pack'], 'statsgen': ['pack'], 'policygen': ['pack'],
    'hydra-gtk': ['thc-hydra', 'hydra'],
    'rcrack': ['rainbowcrack'],
    'svcrack': ['sipvicious'], 'svcrash': ['sipvicious'], 'svreport': ['sipvicious'],
    'svwar': ['sipvicious'], 'svmap': ['sipvicious'],
    'mifare-classic-format': ['mfcuk', 'nfc-tools'],
    'nfc-list': ['libnfc-bin', 'nfc-tools'], 'nfc-mfclassic': ['libnfc-bin', 'nfc-tools'],
    'snmp-check': ['snmpcheck'],
    'arpspoof': ['dsniff'],
    'smbclient': ['smbclient'],
    'pspy-binaries': ['pspy'],
    'ass': ['ass'],
    'cdp': ['cdpsnarf'],
    'mdb-sql': ['mdbtools'],
    'mysql': ['mariadb-client'],
    'sidguess': ['sidguesser'],
    'bloodhound-python': ['bloodhound-ce-python', 'bloodhound'],
    'merge-router-config.pl': ['copy-router-config'],
    'ettercap-text-only': ['ettercap'],
    'dnscat': ['dnscat2'],
    'proxychains4': ['proxychains'],
    'adaptixclient': ['adaptixgh'], 'adaptixserver': ['adaptixgh'],
    'starkiller-start': ['starkiller', 'powershell-empire'],
    'starkiller-stop': ['starkiller', 'powershell-empire'],
    'readpst': ['libpst'],
    'photorec': ['testdisk'],
    'affcat': ['afflib-tools'],
    'dd_rescue': ['ddrescue'],
    'ewfacquire': ['libewf-tools'],
    'blkcalc': ['sleuthkit'], 'blkcat': ['sleuthkit'], 'blkls': ['sleuthkit'],
    'blkstat': ['sleuthkit'], 'fls': ['sleuthkit'], 'ffind': ['sleuthkit'],
    'fsstat': ['sleuthkit'], 'icat': ['sleuthkit'], 'ifind': ['sleuthkit'],
    'ils': ['sleuthkit'], 'img_cat': ['sleuthkit'], 'img_stat': ['sleuthkit'],
    'istat': ['sleuthkit'], 'jcat': ['sleuthkit'], 'jls': ['sleuthkit'],
    'mactime': ['sleuthkit'], 'mmcat': ['sleuthkit'], 'mmls': ['sleuthkit'],
    'mmstat': ['sleuthkit'], 'sigfind': ['sleuthkit'], 'sorter': ['sleuthkit'],
    'srch_strings': ['sleuthkit'], 'hfind': ['sleuthkit'],
    'tsk_comparedir': ['sleuthkit'], 'tsk_gettimes': ['sleuthkit'],
    'tsk_loaddb': ['sleuthkit'], 'tsk_recover': ['sleuthkit'],
    'grokevt-addlog': ['grokevt'], 'grokevt-builddb': ['grokevt'],
    'grokevt-findlogs': ['grokevt'], 'grokevt-parselog': ['grokevt'],
    'grokevt-ripdll': ['grokevt'],
    'bulk_extractor': ['bulk-extractor'],
    'dradis-start': ['dradis'], 'dradis-stop': ['dradis'],
    'faraday-start': ['faraday'], 'faraday-stop': ['faraday'],
    'xplico-webui-start': ['xplico'], 'xplico-webui-stop': ['xplico'],
    'redeye-start': ['redeye'], 'redeye-stop': ['redeye'],
    'juice-shop-start': ['juice-shop'], 'juice-shop-stop': ['juice-shop'],
    'defectdojo-start': ['defectdojo'], 'defectdojo-stop': ['defectdojo'],
    'dvwa-start': ['dvwa'], 'dvwa-stop': ['dvwa'],
    'portspoof-start': ['portspoof'], 'portspoof-stop': ['portspoof'],
    'thehive-start': ['thehive'], 'thehive-stop': ['thehive'],
    'pwsh': ['powershell'],
    'hexstrike_server': ['hexstrike'],
    'root-terminal': ['root-terminal'],
    'snapper-gui': ['snapper'],
    # first-pass extras
    'ncat': ['nmap'], 'nping': ['nmap'], 'ndiff': ['nmap'], 'zenmap': ['nmap'],
    'hydra': ['thc-hydra'],
    'msfvenom': ['metasploit-framework'], 'msf-nasm_shell': ['metasploit-framework'],
    'impacket-smbexec': ['impacket-scripts'], 'impacket-psexec': ['impacket-scripts'],
    'impacket-smbserver': ['impacket-scripts'], 'impacket-mssqlclient': ['impacket-scripts'],
    'ligolo-agent': ['ligolo-ng'], 'ligolo-proxy': ['ligolo-ng'],
    'ligolo-mp': ['ligolo-ng'], 'ligolo-mp-client': ['ligolo-ng'],
    'chisel-common-binaries': ['chisel'], 'ligolo-ng-common-binaries': ['ligolo-ng'],
    'sickle-pdk': ['sickle'], 'jadx-gui': ['jadx'], 'caido-cli': ['caido'],
    'ophcrack-cli': ['ophcrack'], 'dns2tcpc': ['dns2tcp'], 'dns2tcpd': ['dns2tcp'],
    'iodine-client-start': ['iodine'], 'rcracki_mt': ['rainbowcrack'],
    'evil-winrm-py': ['evil-winrm-py'], 'spiderfoot-cli': ['spiderfoot'],
}

def candidates(name):
    out = [name]
    if name != name.lower():
        out.append(name.lower())
    stripped = re.sub(r'\.(pl|sh|py|rb)$', '', name)
    if stripped not in out:
        out.append(stripped)
    out.extend(FALLBACKS.get(name, []))
    return out

def fetch(tool):
    for cand in candidates(tool):
        url = f'https://www.kali.org/tools/{cand}/'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urllib.request.urlopen(req, timeout=25) as r:
                html = r.read().decode('utf-8', 'ignore')
                if len(html) > 5000:  # real page, not a 404 stub
                    return tool, cand, html, None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            return tool, cand, None, f'HTTP {e.code}'
        except Exception as e:
            return tool, cand, None, str(e)[:100]
    return tool, None, None, 'all candidates 404'

def main():
    force = '--force' in sys.argv
    tools = json.loads(RAW_LIST.read_text(encoding='utf-8'))
    todo = [t for t in tools if force or not (PAGES / f'{t}.html').exists()]
    print(f'{len(tools)} tools total, {len(tools) - len(todo)} cached, fetching {len(todo)}')

    results, errors = {}, {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = {ex.submit(fetch, t): t for t in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            tool, cand, html, err = fut.result()
            if html:
                (PAGES / f'{tool}.html').write_text(html, encoding='utf-8')
                results[tool] = cand
            else:
                errors[tool] = err
            if i % 50 == 0:
                print(f'[{i}/{len(todo)}] ok={len(results)} fail={len(errors)}', flush=True)

    RESULT_FILE.write_text(json.dumps({'ok': results, 'errors': errors}, indent=1), encoding='utf-8')
    print(f'DONE: ok={len(results)} fail={len(errors)} (details: {RESULT_FILE.name})')
    if errors:
        print('Failed:', ', '.join(sorted(errors)[:20]), '...' if len(errors) > 20 else '')

if __name__ == '__main__':
    main()
