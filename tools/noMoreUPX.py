#!/usr/bin/env python3
"""
noMoreUPX! — build-time UPX signature stripper
Based on github.com/Syn2Much/upx-stripper, optimized for batch pipeline use.

Strips cosmetic/info UPX strings from packed binaries while preserving
the structural UPX! markers the decompressor stub needs at runtime.

Usage: python3 noMoreUPX.py <file> [file2 ...]
       python3 noMoreUPX.py --dir <directory>
"""
import os, sys, random

# Cosmetic strings safe to strip (decompressor doesn't use these)
UPX_STRINGS = [
    b"$Info: This file is packed with the UPX executable packer http://upx.sf.net $",
    b"$Id: UPX ",
    b"http://upx.sf.net",
    b"upx.sourceforge.net",
    b"upx.sf.net",
    b"github.com/upx/upx",
    b"the UPX Team",
    b"Copyright (C) 1996-",
    b"Markus Oberhumer",
    b"Laszlo Molnar",
    b"John F. Reiser",
    b"UPX 0.", b"UPX 1.", b"UPX 2.", b"UPX 3.", b"UPX 4.",
    b"UPX 5.", b"UPX 6.", b"UPX 7.", b"UPX 8.", b"UPX 9.",
    b"NRV 0x", b"NRV2B", b"NRV2D", b"NRV2E",
    b"UCL data compression",
]

def _pad(n):
    """Generate random padding that blends with binary data."""
    out = bytearray(n)
    for i in range(n):
        r = random.random()
        if r < 0.35:
            out[i] = 0x00
        elif r < 0.55:
            out[i] = random.choice([0x90, 0xCC, 0x00, 0xFF])
        else:
            out[i] = random.randint(0, 255)
    return bytes(out)

def strip_file(path):
    """Strip UPX cosmetic strings from a single binary. Returns count of replacements."""
    with open(path, "rb") as f:
        data = bytearray(f.read())
    total = 0
    for pat in UPX_STRINGS:
        while True:
            idx = data.find(pat)
            if idx == -1:
                break
            data[idx:idx+len(pat)] = _pad(len(pat))
            total += 1
    # Also wipe any remaining $Info:..$ or $Id:..$ blocks we missed
    import re
    for rx in [rb'\$Info:[^\$]{4,120}\$', rb'\$Id:[^\$]{4,120}\$']:
        for m in reversed(list(re.finditer(rx, bytes(data)))):
            data[m.start():m.end()] = _pad(m.end() - m.start())
            total += 1
    if total:
        with open(path, "wb") as f:
            f.write(data)
    return total

def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <file ...> | --dir <directory>", file=sys.stderr)
        sys.exit(1)
    files = []
    if sys.argv[1] == "--dir" and len(sys.argv) >= 3:
        d = sys.argv[2]
        for name in os.listdir(d):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                files.append(p)
    else:
        files = sys.argv[1:]

    total = 0
    for f in files:
        if not os.path.isfile(f):
            continue
        n = strip_file(f)
        if n:
            print(f"  {os.path.basename(f)}: {n} UPX signatures stripped")
            total += n
    if not total:
        print("  (no UPX signatures found)")

if __name__ == "__main__":
    main()
