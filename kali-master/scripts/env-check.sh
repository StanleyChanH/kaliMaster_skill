#!/usr/bin/env bash
# kali-master skill — 环境与工具可用性检测
# 用途:skill 加载后第一步自检,判断当前环境能跑哪类工具
# 用法:bash scripts/env-check.sh [--core|--full]

set -u

MODE="${1:--core}"

# ---------- 环境类型判断 ----------
echo "=== 环境检测 ==="
OS_ID=$(grep -m1 '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
KERNEL=$(uname -s)
WSL=0
if grep -qi microsoft /proc/version 2>/dev/null; then
  WSL=1
  echo "环境:WSL(Windows Subsystem for Linux)"
fi

if [ "$OS_ID" = "kali" ]; then
  echo "环境:Kali Linux $([ $WSL -eq 1 ] && echo '(WSL)' || echo '(原生)')"
  IS_KALI=1
elif [ "$KERNEL" = "Linux" ]; then
  echo "环境:通用 Linux(ID=$OS_ID)"
  IS_KALI=0
elif [ "$KERNEL" = "Darwin" ]; then
  echo "环境:macOS —— 无 Kali 工具链,主动扫描建议使用 Kali VM/容器"
  exit 0
else
  echo "环境:非 Linux"
  exit 0
fi

# root 检查
if [ "$(id -u)" -eq 0 ]; then
  echo "权限:root ✓"
else
  echo "权限:普通用户(主动扫描/原始套接字工具需要 sudo)"
fi

# ---------- 工具可用性 ----------
CORE_TOOLS="nmap curl whois dig sqlmap ffuf hydra searchsploit hashcat john netcat socat proxychains4"
WIRELESS_TOOLS="airmon-ng airodump-ng aircrack-ng bettercap kismet"
AD_TOOLS="impacket-psexec impacket-secretsdump nxc crackmapexec evil-winrm bloodhound-python responder"
FORENSIC_TOOLS="binwalk foremost testdisk photorec volatility3 sleuthkit strings"
RE_TOOLS="ghidraRun r2 rizin gdb jadx apktool"

check_group() {
  local label="$1"; shift
  local tools="$1"
  local have=0; local miss=0; local missing=""
  for t in $tools; do
    if command -v "$t" >/dev/null 2>&1; then
      have=$((have+1))
    else
      miss=$((miss+1)); missing="$missing $t"
    fi
  done
  echo "[$label] 可用 $have / $((have+miss))"
  [ -n "$missing" ] && echo "  缺失:$missing"
}

echo ""
echo "=== 核心工具($MODE)==="
check_group "core" "$CORE_TOOLS"

if [ "$MODE" = "--full" ]; then
  echo ""
  check_group "wireless" "$WIRELESS_TOOLS"
  check_group "ad/内网" "$AD_TOOLS"
  check_group "forensics" "$FORENSIC_TOOLS"
  check_group "reversing" "$RE_TOOLS"
fi

# ---------- 字典资源 ----------
echo ""
echo "=== 字典资源 ==="
for wl in /usr/share/wordlists/rockyou.txt /usr/share/seclists /usr/share/wordlists/dirb; do
  if [ -e "$wl" ]; then echo "✓ $wl"; else echo "✗ $wl(缺失)"; fi
done
if [ ! -e /usr/share/wordlists/rockyou.txt ] && [ -e /usr/share/wordlists/rockyou.txt.gz ]; then
  echo "  提示:运行 sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz 解压 rockyou"
fi
if [ ! -d /usr/share/seclists ]; then
  echo "  提示:sudo apt install seclists wordlists"
fi

# ---------- WSL 无线能力 ----------
if [ $WSL -eq 1 ]; then
  echo ""
  echo "=== WSL 限制提示 ==="
  echo "WSL1/WSL2 默认不支持:无线 monitor 模式、蓝牙直连、raw packet 注入。"
  echo "需要 aircrack/SDR/蓝牙时请使用 Kali 虚拟机(USB 网卡直通)。"
fi

echo ""
echo "完成。根据缺失工具:sudo apt install <包名>(包名见 references/tool-index.md)"
