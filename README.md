
# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2](https://img.shields.io/badge/VisionNet-V1.7-red)
![Go](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**VisionC2** is a modern, Go based botnet framework focused on network stress testing. It includes enterprise-grade encryption (TLS 1.3 + HMAC + String Obfuscation), multi-architecture bot support (14+), remote shell, SOCKS5 proxying, and an interactive terminal user interface.

<p align="center">
<b>VisionC2 now features a complete Terminal User Interface built in BubbleTea</b>
</p>

![Animation(1)](https://github.com/user-attachments/assets/a1b48f12-ebb5-4582-8e6d-e61eb521ac10)

## Quick Start

### Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen
# Go 1.23+ required → https://go.dev/dl/
```

### Installation

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
python3 setup.py
```

### Starting the C2

**TUI Mode (recommended):**

```bash
cd cnc
./cnc
```

**Split Mode (telnet/multi-user):**

```bash
./cnc --split
# Then connect: nc <server-ip> <admin-port>
# Login trigger: spamtec
```

Bot binaries are automatically built to `bot/bins/`.

## Features

### Bot Capabilities

- **Layer 4**: UDP, TCP, SYN, ACK, GRE, DNS flood methods
- **Layer 7**: HTTP/HTTPS/TLS with HTTP/2 fingerprinting and Cloudflare UAM bypass (including CAPTCHA solving)
- **Remote Execution**: Interactive and fire-and-forget shell commands
- **SOCKS5 Proxy**: Turn any agent into a SOCKS5 proxy server

### Security & Stealth

- TLS 1.3 with perfect forward secrecy
- Multi-layer obfuscation (RC4, XOR, byte substitution, MD5)
- HMAC challenge-response authentication
- Anti-analysis & sandbox detection

### TUI Features

- Real-time bot management, visual attack builder, live shell access, and targeting filters
- Built-in SOCKS5 proxy manager (one-click per bot)
- Broadcast shell execution with architecture, RAM, and count filtering

### Performance

- Up to 30k–40k RPS / 2–6 Gbps (2-server baseline)
- 14+ architecture support (automated cross-compilation)
- Fully automated 5-minute setup

## Architecture

```
Admin Console ──TLS 1.3──► C2 Server
                            │
                     Bot Registry
                            ▲
                     TLS 1.3 │
                            │
                       Bot Agents (14+ arches)
```

**C2 Resolution Order** (highly resilient):

1. DoH TXT record
2. DNS TXT record
3. A record
4. Direct IP

## Configuration

After running the setup wizard, review `setup_config.txt` for:

- C2 address & ports
- Magic code & encryption keys
- Generated 4096-bit certificates

## Usage

- Bot port: **443** (TLS – fixed)
- Admin port: configurable (default 420)
- Full command reference: [`cnc/COMMANDS.md`](cnc/COMMANDS.md)

## Roadmap

### In Progress

- Enhanced daemonization & persistence
- Locker/killer (remove competing malware)

### Planned

- Auto-generated DGA fallback domains
- Self-replication / spreading
- Single-instance port takeover

See [CHANGELOG.md](CHANGELOG.md) for detailed history.

## Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND STRESS TESTING ONLY**

The authors are not responsible for any misuse, damage, or legal consequences arising from the use of this software. Use responsibly and legally.

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

## Support

- Documentation: [USAGE.md](USAGE.md)
- Issues & feature requests → GitHub Issues
- Contact: <dev@sinners.city>

---

This version is clean, professional, well-structured, and ready to be your main `README.md`. Let me know if you want a dark-mode friendly version, a version with screenshots, or further adjustments (e.g., remove certain sections).
