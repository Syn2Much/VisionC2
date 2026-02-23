#!/bin/bash
# VisionC2 - Server Setup (run as root)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

[ "$(id -u)" -ne 0 ] && { echo "Run as root"; exit 1; }

# --- ulimit ---
ulimit -n 99999 2>/dev/null && ok "ulimit -n 99999"
sysctl -w fs.file-max=2097152 >/dev/null 2>&1 && ok "fs.file-max = 2097152"

grep -q 'nofile.*99999' /etc/security/limits.conf 2>/dev/null || {
    echo -e "*  soft nofile 99999\n*  hard nofile 99999\nroot soft nofile 99999\nroot hard nofile 99999" >> /etc/security/limits.conf
    ok "Persisted in limits.conf"
}

# --- Open port 443 ---
if command -v iptables &>/dev/null; then
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null && ok "Opened port 443 (tcp)"
fi
if command -v ufw &>/dev/null; then
    ufw allow 443/tcp >/dev/null 2>&1 && ok "ufw allow 443"
fi

# --- TCP buffer sizes ---
sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216" >/dev/null 2>&1
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216" >/dev/null 2>&1
sysctl -w net.core.somaxconn=65535 >/dev/null 2>&1
ok "TCP buffer sizes & backlog tuned"

echo -e "\n${GREEN}Done.${NC} Run: ${GREEN}ulimit -n 99999 && ./server${NC}"
