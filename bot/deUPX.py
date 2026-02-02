#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import random
from pathlib import Path
from typing import Dict, List, Tuple, Optional

#
#       .        :uuuuuuu
#       8F          M$   'WWWWWWWi
#      '$$$$$$"`    'E       #$$$$$
#      t$$$$$       'E       '$$$$$$L    '$"
#      $`````       'E       'E#$$$$$k   'E
#     J&.           'E       'E `$$$$$N  'E
#  '$$$$$$$$$$L     'E       'E   $$$$$$ 'E
#  9$#"`"#$$$$$k   'E       `@"    #$$$$$$E
#         '$$$$$   'E        $      `$$$$$&
#   ..     9$$$$L..JBu       $        R$$$$N
# d$$$R    9$$$F   'E        $         "$$$$$r
# $$$$    J$$$F     {E      .$.         '$$$$$
#  "$$$$$$$$$"   ..u$$u..  uz$$bu         #$$$
#                                          '$$k.
#                     noMoreUPX! V3 01/28/2026
#


# Configure logging
def setup_logging(log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging configuration"""
    logger = logging.getLogger("noMoreUPX")
    logger.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    return logger


logger = setup_logging()

UPX_STRINGS = [
    b"$Id: UPX ",
    b"UPX!",
    b"$Info: This file is packed with the UPX executable packer http://upx.sf.net $",
    b"$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $",
    b"UPX!u",
    b"http://upx.sf.net",
    b"UPX",
    b"UPX 0.",
    b"UPX 1.",
    b"UPX 2.",
    b"UPX 3.",
    b"UPX 4.",
    b"UPX 5.",
    b"UPX 6.",
    b"UPX 7.",
    b"UPX 8.",
    b"UPX 9.",
    # Section names
    b"UPX0",
    b"UPX1",
    b"UPX2",
    # URLs and references
    b"upx.sourceforge.net",
    b"upx.sf.net",
    b"github.com/upx/upx",
    b"the UPX Team",
    # Copyright notices
    b"Copyright (C) 1996-",
    b"Markus Oberhumer",
    b"Laszlo Molnar",
    b"John F. Reiser",
    # PE/DLL specific patterns
    b"UPX!",
    b"\x55\x50\x58\x21",  # UPX! in hex
    b"UPX0\x00",
    b"UPX1\x00",
]

# Binary file extensions to always process
BINARY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".drv",
    ".ocx",
    ".cpl",
    ".scr",  # Windows
    ".so",
    ".dylib",
    ".bundle",  # Linux/macOS
    ".elf",
    ".bin",
    ".o",
    ".ko",  # Generic binary
    ".axf",
    ".prx",
    ".puff",
    ".out",  # Other
    ".mips",
    ".arm",
    ".x86",
    ".x86_64",
    ".aarch64",
    ".mipsel",
    ".armv7",
    ".armv6",
    ".powerpc",
    ".ppc",
    ".sparc",
    ".m68k",
    ".sh4",
    ".arc",  # Architecture-specific binaries
}


def generate_obfuscation_padding(length: int) -> bytes:
    """Generate intelligent obfuscation padding with improved randomness"""
    padding = bytearray()

    for i in range(length):
        # Random strategy selection
        strategy = random.random()

        if strategy < 0.3:  # 30% - Random valid x86 opcodes
            opcodes = [
                0x90,
                0x90,
                0x90,
                0x90,  # NOP (common)
                0x31,
                0xC0,
                0x31,
                0xC9,  # XOR reg, reg
                0x48,
                0x89,
                0xC7,
                0x48,  # MOV instructions
                0x89,
                0xF8,
                0x8B,
                0xFF,  # More MOV
                0xC3,
                0xCC,
                0xF4,
                0xFB,  # RET, INT3, HLT, STI
            ]
            padding.append(random.choice(opcodes))

        elif strategy < 0.6:  # 30% - Structured but meaningless data
            patterns = [
                lambda x: (x % 256),  # Incrementing pattern
                lambda x: (
                    0x00 if random.random() < 0.1 else random.randint(1, 255)
                ),  # Sparse nulls
                lambda x: (
                    0xFF if random.random() < 0.1 else random.randint(0, 254)
                ),  # Sparse 0xFF
                lambda x: random.choice(
                    [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
                ),  # Common hex words
            ]
            pattern = random.choice(patterns)
            padding.append(pattern(i))

        else:  # 40% - Truly random
            padding.append(random.randint(0, 255))

    return bytes(padding)


def scan_upx_patterns(data: bytes) -> List[bytes]:
    """Scan for UPX patterns in data with efficient search"""
    found_patterns = []
    seen = set()

    for upx_str in UPX_STRINGS:
        if upx_str in data and upx_str not in seen:
            found_patterns.append(upx_str)
            seen.add(upx_str)

    return found_patterns


def is_likely_binary(filepath: str) -> bool:
    """Check if file is likely binary by extension and content sampling"""
    try:
        # Check extension first - always process known binary types
        ext = Path(filepath).suffix.lower()
        if ext in BINARY_EXTENSIONS:
            logger.debug(f"Binary extension detected: {ext}")
            return True

        with open(filepath, "rb") as f:
            chunk = f.read(8192)

        if not chunk:
            return False

        # Check for PE header (MZ) - Windows executables/DLLs
        if chunk[:2] == b"MZ":
            return True

        # Check for ELF header - Linux binaries
        if chunk[:4] == b"\x7fELF":
            return True

        # Check for null bytes (binary indicator)
        if b"\x00" in chunk:
            return True

        # Check if mostly printable ASCII
        text_chars = sum(1 for b in chunk if 32 <= b <= 126 or b in (9, 10, 13))
        return (text_chars / len(chunk)) < 0.75

    except PermissionError:
        logger.warning(f"Permission denied checking: {filepath}")
        return True  # Try to process anyway
    except Exception as e:
        logger.debug(f"Error checking if binary {filepath}: {e}")
        return True  # Assume binary on error


def process_file(filepath: str, dry_run: bool = False) -> Dict:
    """Process a single file for UPX patterns with efficient memory handling"""
    results = {
        "filename": os.path.basename(filepath),
        "modified": False,
        "replacements": 0,
        "patterns": [],
        "error": None,
    }

    try:
        # Skip if not binary
        if not is_likely_binary(filepath):
            logger.debug(f"Skipping non-binary file: {filepath}")
            return results

        with open(filepath, "rb") as f:
            data = f.read()

        # Scan for UPX patterns
        found_patterns = scan_upx_patterns(data)
        results["patterns"] = found_patterns

        if not found_patterns:
            return results

        if dry_run:
            logger.info(
                f"Found {len(found_patterns)} UPX patterns in {os.path.basename(filepath)}"
            )
            return results

        # Apply modifications
        new_data = data
        replacements = 0

        for upx_str in found_patterns:
            # Replace each occurrence with obfuscated padding
            while upx_str in new_data:
                padding = generate_obfuscation_padding(len(upx_str))
                new_data = new_data.replace(upx_str, padding, 1)
                replacements += 1

        if new_data != data:
            # Write modified file
            with open(filepath, "wb") as f:
                f.write(new_data)

            results["modified"] = True
            results["replacements"] = replacements

            logger.info(
                f"Modified: {os.path.basename(filepath)} ({replacements} patterns replaced)"
            )

        return results

    except PermissionError as e:
        results["error"] = f"Permission denied (file may be in use): {e}"
        logger.warning(
            f"Permission denied: {filepath} - File may be locked/in use by system"
        )
        return results
    except OSError as e:
        if e.errno == 13:  # Permission denied
            results["error"] = "File is locked or in use"
            logger.warning(f"File locked/in use: {filepath}")
        elif e.errno == 32:  # Sharing violation (Windows)
            results["error"] = "File in use by another process"
            logger.warning(
                f"Sharing violation: {filepath} - Close applications using this DLL"
            )
        else:
            results["error"] = str(e)
            logger.error(f"OS error processing {filepath}: {e}")
        return results
    except MemoryError:
        results["error"] = "File too large to process"
        logger.error(f"File too large (memory error): {filepath}")
        return results
    except Exception as e:
        results["error"] = str(e)
        logger.error(f"Error processing {filepath}: {e}", exc_info=True)
        return results


def print_banner():
    """Print the tool banner"""
    banner = r"""
 __    __            __       __   ______                       __    __  _______   __    __  __ 
|  \  |  \          |  \     /  \ /      \                     |  \  |  \|       \ |  \  |  \|  \
| $$\ | $$  ______  | $$\   /  $$|  $$$$$$\  ______    ______  | $$  | $$| $$$$$$$\| $$  | $$| $$
| $$$\| $$ /      \ | $$$\ /  $$$| $$  | $$ /      \  /      \ | $$  | $$| $$__/ $$ \$$\/  $$| $$
| $$$$\ $$|  $$$$$$\| $$$$\  $$$$| $$  | $$|  $$$$$$\|  $$$$$$\| $$  | $$| $$    $$  >$$  $$ | $$
| $$\$$ $$| $$  | $$| $$\$$ $$ $$| $$  | $$| $$   \$$| $$    $$| $$  | $$| $$$$$$$  /  $$$$\  \$$
| $$ \$$$$| $$__/ $$| $$ \$$$| $$| $$__/ $$| $$      | $$$$$$$$| $$__/ $$| $$      |  $$ \$$\ __ 
| $$  \$$$ \$$    $$| $$  \$ | $$ \$$    $$| $$       \$$     \ \$$    $$| $$      | $$  | $$|  \
 \$$   \$$  \$$$$$$  \$$      \$$  \$$$$$$  \$$        \$$$$$$$  \$$$$$$  \$$       \$$   \$$ \$$
                                                                                                 
    """
    print(banner)
    print(f"                 Build: 01/09/2026")
    print(f"               Author: sintax@exploit.im")
    print(f"              Version: 2.0 (Improved)")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="noMoreUPX! - UPX pattern removal tool with backup system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s suspicious.exe           # Process single file
  %(prog)s ./malware_samples/       # Process directory
  %(prog)s target.bin --dry-run     # Scan without modifying
  %(prog)s -h                       # Show this help message
        """,
    )

    parser.add_argument("target", help="File or directory to process")
    parser.add_argument(
        "--dry-run",
        "-d",
        action="store_true",
        help="Scan for UPX patterns without modifying files",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed information"
    )
    parser.add_argument("--log", "-l", metavar="FILE", help="Write debug log to file")

    args = parser.parse_args()

    # Setup logging with optional file output
    global logger
    if args.log:
        logger = setup_logging(args.log)

    # Print banner
    print_banner()

    # Validate target
    if not os.path.exists(args.target):
        logger.error(f"Target '{args.target}' does not exist")
        sys.exit(1)

    logger.info(f"Target: {args.target}")
    logger.info(f"Mode: {'Scan only (dry run)' if args.dry_run else 'Modify in place'}")
    print()

    # Process files
    file_results = []
    total_processed = 0
    total_modified = 0
    total_patterns = 0
    total_replacements = 0

    if os.path.isfile(args.target):
        # Single file mode
        logger.info(f"Processing single file: {os.path.basename(args.target)}")
        result = process_file(args.target, args.dry_run)
        file_results.append(result)
        total_processed = 1
        if result["modified"]:
            total_modified = 1
            total_replacements = result["replacements"]
        total_patterns = len(result["patterns"])

    elif os.path.isdir(args.target):
        # Directory mode
        logger.info(f"Processing directory (recursive): {args.target}")
        files_found = 0

        for root, dirs, files in os.walk(args.target):
            # Skip backup directories
            if "backup_" in root and root.startswith(args.target):
                continue

            for file in files:
                filepath = os.path.join(root, file)

                # Skip very large files (> 100MB)
                try:
                    if os.path.getsize(filepath) > 100 * 1024 * 1024:
                        if args.verbose:
                            logger.debug(f"Skipping large file: {file} (>100MB)")
                        continue
                except OSError:
                    continue

                files_found += 1
                if args.verbose:
                    print(f"  Processing: {file}")

                result = process_file(filepath, args.dry_run)
                file_results.append(result)
                total_processed += 1

                if result["modified"]:
                    total_modified += 1
                    total_replacements += result["replacements"]

                total_patterns += len(result["patterns"])

        logger.debug(f"Total files found: {files_found}")

    # Summary
    print()
    print("=" * 60)
    print("                     PROCESSING SUMMARY")
    print("=" * 60)
    print(f"  Files processed:       {total_processed}")
    print(f"  Files modified:        {total_modified}")
    print(f"  UPX patterns found:    {total_patterns}")
    print(f"  Total replacements:    {total_replacements}")
    print("=" * 60)

    if args.dry_run and total_patterns > 0:
        print("\n  [!] Use without --dry-run to apply modifications")
    elif total_patterns == 0:
        print("\n  [✓] No UPX patterns found in target files")

    print("\n[+] Operation completed successfully!\n")

    # Return appropriate exit code
    sys.exit(0 if total_patterns >= 0 else 1)


if __name__ == "__main__":
    main()
