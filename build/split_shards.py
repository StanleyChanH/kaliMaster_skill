#!/usr/bin/env python
"""Split 470 parsed tools into per-domain JSON shards for skill authoring agents."""
import json, pathlib, re

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / 'data'
SHARDS = DATA / 'shards'
SHARDS.mkdir(parents=True, exist_ok=True)

parsed = json.loads((DATA / 'tools_parsed.json').read_text(encoding='utf-8'))

# Original ATT&CK category mapping (extracted from kali.org/tools listing)
cat_of = json.loads((DATA / 'attack_categories.json').read_text(encoding='utf-8'))

# Domain assignment: tool -> reference file (professional pentest domains, not raw ATT&CK)
DOMAIN = {
    'recon': '01-recon',
    'scanning': '02-scanning',
    'web': '03-web-testing',
    'exploit': '04-exploitation',
    'passwords': '05-passwords',
    'wireless': '06-wireless',
    'network': '07-network-attacks',
    'adwin': '08-ad-windows',
    'tunnels': '09-tunnels-c2',
    'privesc': '10-privesc',
    'forensics': '11-forensics',
    'reversing': '12-reversing',
    'reports': '13-reporting-labs',
}

# (pattern, domain) — matched in order against tool name; ATT&CK cat as fallback
ASSIGN = [
    # --- wireless / bt / sdr / nfc ---
    (r'aircrack|airgeddon|wifite|wifiphisher|bully|cowpatty|reaver|pixiewps|asleap|fern-wifi|wifi-honey|sparrow|kismet|wash|mdk4?$|sparrow-wifi|wifipumpkin', 'wireless'),
    (r'bluelog|bluesnarfer|btscanner|blueranger|spooftooph|ubertooth|crackle', 'wireless'),
    (r'hackrf|gnuradio|gqrx|chirp|rfcat', 'wireless'),
    (r'mfcuk|mfoc|mfterm|nfc|proxmark', 'wireless'),
    # --- passwords ---
    (r'hashcat|john|johnny|ophcrack|rcrack|crackle|fcrackzip|cmospwd|sipcrack|sucrack|truecrack|hashid|hash-identifier', 'passwords'),
    (r'hydra|medusa|ncrack|patator|crowbar|legba|sqldict|thc-pptp|cewl|crunch|bopscrk|rsmangler|twofi|maskgen|statsgen|policygen|wordlists|seclists', 'passwords'),
    (r'mimikatz|chntpw|creddump|samdump2|hashcat|hashid', 'passwords'),
    (r'trufflehog|gitxray|gitleaks', 'passwords'),
    # --- web ---
    (r'burpsuite|nikto|zap|wpscan|whatweb|dirb|dirbuster|dirsearch|gobuster|ffuf|feroxbuster|wfuzz|arjun|crlfuzz|joomscan|sstimap|tinja|wapiti|watobo|webscarab|skipfish|paros|davtest|subjack|wcvs|sqlmap|commix|jsql|sqlninja|sqlsus|xsser|beef|havij', 'web'),
    (r'nuclei|cve|nikto', 'web'),
    # --- scanning ---
    (r'nmap|masscan|unicornscan|autorecon|legion|zenmap|ike-scan|sctpscan|sslscan|sslyze|tlssled|nuclei|gvm|openvas', 'scanning'),
    (r'snmp-check|braa|onesixtyone|nbtscan|enum4linux|smtp-user-enum|apache-users|mxcheck|swaks|oscanner|tnscmd|sidguess', 'scanning'),
    (r'lynis', 'privesc'),
    # --- recon / osint ---
    (r'theharvester|sherlock|spiderfoot|metagoofil|maltego|recon-ng|subfinder|sublist3r|findomain|assetfinder|dmitry|dnsmap|dnsrecon|dnsenum|massdns|dnstracer|dnswalk|urlcrazy|photon|gospider|instaloader|linkedin2username|emailharvester|email2phone|tookie|finalrecon|uro|parsero|lbd|wpprobe|fierce|amass', 'recon'),
    # --- network attacks (mitm/sniff/spoof) ---
    (r'ettercap|bettercap|mitmproxy|mitm6|evilginx|sslsplit|sslsniff|ssldump|driftnet|dsniff|arpspoof|hexinject|netsniff|wireshark|tcpdump|tcpflow|scapy|darkstat|dnschef|hamstersidejack|ferret-sidejack|fiked|fluxion|sniffjoke|fragrouter|macchanger|yersinia|netdiscover|netmask|p0f|above|0trace|intrace|firewalk|tcpreplay|arpwatch|arping|hping3|fping|cdpsnarf|sara|wireshark', 'network'),
    (r'protos-sip|rtpbreak|rtpinsert|rtpmix|siparmyknife|sipp|sippts|sipsak|svcrash|svmap|svreport|svwar|voiphopper|ohrwurm|iaxflood|inviteflood|rtpflood|enumiax|svcrack|iax', 'network'),
    (r'cisco|cge|copy-router-config|merge-router-config|termineter', 'network'),
    (r'responder', 'adwin'),
    # --- ad / windows / lateral ---
    (r'crackmapexec|netexec|evil-winrm|impacket|smbmap|smbclient|passing-the-hash|rubeus|bloodhound|sharphound|azurehound|ldeep|bloodyad|krbrelayx|kerberoast|pth|wmi', 'adwin'),
    (r'xfreerdp|rdesktop|freerdp', 'adwin'),
    (r'powersploit|nishang|powershell|pwsh', 'adwin'),
    (r'pspy', 'privesc'),
    # --- tunnels / c2 ---
    (r'chisel|ligolo|proxychains|proxytunnel|ptunnel|pwnat|sshuttle|sslh|stunnel|udptunnel|dns2tcp|dnscat|iodine|miredo|socat|netcat|ncat|sbd|dbd|powercat|penelope|minicom', 'tunnels'),
    (r'metasploit|msfvenom|armitage|msfpc|cobalt|havoc|empire|starkiller|villain|hoaxshell|koadic|adaptix|shellnoob|donut|veil|shellter|backdoor-factory|exe2hex|cymothoa|weevely|webshells|webacoo|laudanum|phpggc', 'exploit'),
    (r'goshs|raven|cadaver', 'tunnels'),
    (r'dhcpig|goldeneye|slowhttptest|siege|t50|thc-ssl-dos|mdk', 'network'),
    # --- privesc ---
    (r'peass|linpeas|winpeas|unix-privesc|lynis', 'privesc'),
    # --- forensics ---
    (r'dc3dd|dcfldd|dd_rescue|guymager|ewfacquire|afflib|testdisk|photorec|foremost|scalpel|binwalk|bulk|magicrescue|myrescue|recoverdm|recoverjpeg|safecopy|scrounge|ext3grep|ext4magic|extundelete|autopsy|sleuthkit|fls$|icat|blk|tsk_|grokevt|mactime|hfind|sigfind|sorter|srch_strings|img_|istat|jcat|jls|mm|ffind|fsstat|ifind|ils|rifiuti|pasco|galleta|readpst|missidentify|reglookup|regripper|undbx|vinetto|hexwalk|hashdeep|ssdeep|chkrootkit|rkhunter|unhide|xplico|yara|pdfid|pdf-parser|readpe', 'forensics'),
    (r'steghide|stegosuite|stegsnow|outguess', 'forensics'),
    # --- reversing ---
    (r'ghidra|radare2|rizin|cutter|gdb|gef|edb|ollydbg|nasm|shellnoob|recstudio|cstool|capstone|apktool|jadx|jd-gui|dex2jar|bytecode-viewer|javasnoop|afl|sfuzz|bed|generic_|clusterd|pyinstaller|ollydbg', 'reversing'),
    (r'clang|code-oss', 'reversing'),
    # --- exploit / vuln ---
    (r'searchsploit|exploitdb|pompem|metasploit|msf|evilgrade|set|setoolkit|gophish|dns-rebind|jboss', 'exploit'),
    (r'heartleech|dsniff', 'exploit'),
    # --- reporting / labs / services ---
    (r'cherrytree|dradis|faraday|pipal|recordmydesktop|cutycapt|eyewitness|witnessme|obsidian|maltego|redeye|thehive|defectdojo| arsenal|kali-tweaks|gemini|shell-gpt|tailscale|snapper|root-terminal|hexstrike', 'reports'),
    (r'juice-shop|dvwa|portspoof', 'reports'),
    (r'-start$|-stop$', 'reports'),
]

def domain_of(tool):
    tl = tool.lower()
    for pat, dom in ASSIGN:
        if re.search(pat, tl):
            return dom
    cat = cat_of.get(tool, '')
    CM = {
        'Reconnaissance': 'recon', 'Discovery': 'scanning', 'Resource Development': 'reversing',
        'Initial Access': 'exploit', 'Execution': 'exploit', 'Persistence': 'exploit',
        'Privilege Escalation': 'privesc', 'Defense Evasion': 'exploit', 'Credential Access': 'passwords',
        'Lateral Movement': 'adwin', 'Collection': 'network', 'Command and Control': 'tunnels',
        'Exfiltration': 'tunnels', 'Impact': 'network', 'Forensics': 'forensics',
        'Services and Other Tools': 'reports',
    }
    return CM.get(cat, 'recon')

shards = {}
unassigned = []
for tool, data in parsed.items():
    d = domain_of(tool)
    # normalize: keep full record + original category
    data['attack_category'] = cat_of.get(tool, '')
    shards.setdefault(d, {})[tool] = data

for dom, tools in shards.items():
    (SHARDS / f'{dom}.json').write_text(json.dumps(tools, ensure_ascii=False, indent=1), encoding='utf-8')
    print(f'{dom}: {len(tools)} tools')

print('TOTAL:', sum(len(t) for t in shards.values()))
