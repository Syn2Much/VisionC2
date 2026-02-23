#!/bin/bash
# ============================================================================
# VisionC2 - Bot Persistence Cleanup
# ============================================================================
# Removes ALL persistence artifacts created by the bot on the local machine.
# Run this as root if the bot was accidentally executed outside debug mode.
#
# What it removes:
#   1. Systemd service  (httpd-cache.service)
#   2. Hidden directory  (/var/lib/.httpd_cache)
#   3. Cron jobs         (.httpd_check.sh + all cross-compiled bot binary names)
#   4. rc.local entries  (lines referencing the bot binary)
#   5. Instance lock     (/tmp/.net_lock)
#   6. Speed cache       (/tmp/.net_metric)
#   7. Running processes (.httpd_worker + all cross-compiled bot binary names)
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
skip() { echo -e "${YELLOW}[-]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

# --- Must be root ---
if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root"
    exit 1
fi

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║${NC}   VisionC2 Bot Persistence Cleanup               ${RED}║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# --- Configurable values (must match config.go) ---
SERVICE_NAME="httpd-cache.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
HIDDEN_DIR="/var/lib/.httpd_cache"
SCRIPT_NAME=".httpd_check.sh"
BINARY_NAME=".httpd_worker"
RC_LOCAL="/etc/rc.local"
LOCK_FILE="/tmp/.net_lock"
SPEED_CACHE="/tmp/.net_metric"

# ============================
# 1. Kill running bot processes
# ============================
info "Checking for running bot processes..."

# Kill the persistence binary name
if pgrep -x "${BINARY_NAME}" > /dev/null 2>&1; then
    pkill -9 -x "${BINARY_NAME}" && ok "Killed running ${BINARY_NAME} processes"
else
    skip "No ${BINARY_NAME} processes found"
fi

# Kill anything launched from the hidden dir
if pgrep -f "${HIDDEN_DIR}" > /dev/null 2>&1; then
    pkill -9 -f "${HIDDEN_DIR}" && ok "Killed processes from ${HIDDEN_DIR}"
else
    skip "No processes running from ${HIDDEN_DIR}"
fi

# Kill all known cross-compiled bot binary names (from build.sh)
BOT_NAMES="kworkerd0 ethd0 mdsync1 ksnapd0 kswapd1 ip6addrd deferwqd devfreqd0 kintegrity0 biosd0 kpsmoused0 ttmswapd vredisd0 kvmirqd"
for bname in ${BOT_NAMES}; do
    if pgrep -x "${bname}" > /dev/null 2>&1; then
        pkill -9 -x "${bname}" && ok "Killed running ${bname} process"
    fi
done

# Kill any process running from a VisionC2 bins/ directory
if pgrep -f "VisionC2/bins/" > /dev/null 2>&1; then
    pkill -9 -f "VisionC2/bins/" && ok "Killed processes from VisionC2/bins/"
else
    skip "No processes running from VisionC2/bins/"
fi

# ============================
# 2. Remove systemd service
# ============================
info "Checking systemd service..."

if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl stop "${SERVICE_NAME}" 2>/dev/null && ok "Stopped ${SERVICE_NAME}"
else
    skip "${SERVICE_NAME} not active"
fi

if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl disable "${SERVICE_NAME}" 2>/dev/null && ok "Disabled ${SERVICE_NAME}"
else
    skip "${SERVICE_NAME} not enabled"
fi

if [ -f "${SERVICE_PATH}" ]; then
    rm -f "${SERVICE_PATH}" && ok "Removed ${SERVICE_PATH}"
    systemctl daemon-reload 2>/dev/null
else
    skip "${SERVICE_PATH} does not exist"
fi

# ============================
# 3. Remove hidden directory
# ============================
info "Checking hidden directory..."

if [ -d "${HIDDEN_DIR}" ]; then
    rm -rf "${HIDDEN_DIR}" && ok "Removed ${HIDDEN_DIR}"
else
    skip "${HIDDEN_DIR} does not exist"
fi

# ============================
# 4. Clean cron jobs
# ============================
info "Checking crontab for persistence entries..."

CRON_BEFORE=$(crontab -l 2>/dev/null || true)
if echo "${CRON_BEFORE}" | grep -q "${SCRIPT_NAME}"; then
    CRON_FILTERED=$(echo "${CRON_BEFORE}" | grep -v "${SCRIPT_NAME}")
    if [ -n "${CRON_FILTERED}" ]; then
        echo "${CRON_FILTERED}" | crontab - 2>/dev/null
    else
        crontab -r 2>/dev/null || true
    fi
    ok "Removed cron entries referencing ${SCRIPT_NAME}"
else
    skip "No cron entries found for ${SCRIPT_NAME}"
fi

# Also check for direct binary cron persistence (lazarus method — all known names)
CRON_NOW=$(crontab -l 2>/dev/null || true)
if echo "${CRON_NOW}" | grep -q "${BINARY_NAME}"; then
    CRON_FILTERED=$(echo "${CRON_NOW}" | grep -v "${BINARY_NAME}")
    if [ -n "${CRON_FILTERED}" ]; then
        echo "${CRON_FILTERED}" | crontab - 2>/dev/null
    else
        crontab -r 2>/dev/null || true
    fi
    ok "Removed cron entries referencing ${BINARY_NAME}"
else
    skip "No cron entries found for ${BINARY_NAME}"
fi

# Check for cron entries with cross-compiled bot binary names
for bname in ${BOT_NAMES}; do
    CRON_CUR=$(crontab -l 2>/dev/null || true)
    if echo "${CRON_CUR}" | grep -q "${bname}"; then
        CRON_FILTERED=$(echo "${CRON_CUR}" | grep -v "${bname}")
        if [ -n "${CRON_FILTERED}" ]; then
            echo "${CRON_FILTERED}" | crontab - 2>/dev/null
        else
            crontab -r 2>/dev/null || true
        fi
        ok "Removed cron entries referencing ${bname}"
    fi
done

# ============================
# 5. Clean rc.local
# ============================
info "Checking ${RC_LOCAL}..."

if [ -f "${RC_LOCAL}" ]; then
    if grep -q "${BINARY_NAME}\|${HIDDEN_DIR}" "${RC_LOCAL}" 2>/dev/null; then
        sed -i "/${BINARY_NAME}/d;/${HIDDEN_DIR//\//\\/}/d" "${RC_LOCAL}"
        ok "Cleaned bot entries from ${RC_LOCAL}"
    else
        skip "No bot entries in ${RC_LOCAL}"
    fi
else
    skip "${RC_LOCAL} does not exist"
fi

# ============================
# 6. Remove temp files
# ============================
info "Checking temp files..."

if [ -f "${LOCK_FILE}" ]; then
    rm -f "${LOCK_FILE}" && ok "Removed ${LOCK_FILE}"
else
    skip "${LOCK_FILE} does not exist"
fi

if [ -f "${SPEED_CACHE}" ]; then
    rm -f "${SPEED_CACHE}" && ok "Removed ${SPEED_CACHE}"
else
    skip "${SPEED_CACHE} does not exist"
fi

# ============================
# Done
# ============================
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Cleanup complete.${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
info "If the bot binary was copied elsewhere, remove it manually."
info "Check 'crontab -l' and 'systemctl list-units' to verify."
echo ""
