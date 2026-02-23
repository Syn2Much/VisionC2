
<div align="center">

# ☾℣☽ VisionC2

**Multi-arch botnet framework with layered encryption (TLS 1.3 transport + AES-128-CTR string encryption + split-XOR keying) — 14-arch cross-compiled agents, L4/L7 floods, interactive remote shells, SOCKS5 proxying, and full persistence — driven through a real-time Go TUI**  

![Go](https://img.shields.io/badge/Go-1.24.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)

[![Architecture](https://img.shields.io/badge/Full_Architecture-Documentation-blueviolet?style=for-the-badge)](Docs/ARCHITECTURE.md)
[![Changelog](https://img.shields.io/badge/Full_ChangeLog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)

![Animation](https://github.com/user-attachments/assets/1e0694e4-5714-4dcb-ad18-62a7c817c53e)

</div>

---

## Key Features

| | Feature | Description |
|---|---|---|
| 🤖 | **CNC** | Full-featured TUI control panel built with BubbleTea |
| 🔒 | **Communication** | Modern TLS 1.3 encrypted bot-to-server communication on port 443 (Indistinguishable from HTTPS traffic)|
| ⚔️ | **Attack Methods** | Layer 4 (network) and Layer 7 (application) |
| 🕵️ | **Evasion** | AES-128-CTR encrypted strings (zero sensitive plaintext in binary), 16-byte split XOR key, VM/sandbox/debugger detection (40+ signatures), 24-27h delayed exit on detection |
| 👻 | **Stealth** | Unix daemonization, single-instance enforcement, disguised process names, PID lock |
| ♻️ | **Persistence** | Systemd service + cron + rc.local, hidden directory with download script, auto-reinfection on reboot, cleanup tool included (`tools/cleanup.sh`) |
| 🧦 | **SOCKS5 Proxy** | Full SOCKS5 pivoting through bots, RFC 1929 username/password auth, runtime credential updates |
| 📡 | **C2 Resilience** | TXT/A records + direct IP, runtime C2 decryption |
| 💻 | **Cross-Platform** | 14 multi-arch targets + custom UPX packer |
| ⚡ | **Auto-Setup** | Python script automates config + build |

---

## Attack Methods

<details>
<summary><b>Layer 4 — Network/Transport</b></summary>

| Method | Description |
|---|---|
| **UDP Flood** | High-volume 1024-byte payload spam |
| **TCP Flood** | Connection table exhaustion |
| **SYN Flood** | SYN packets with randomized source ports (raw TCP) |
| **ACK Flood** | ACK packet flooding (raw TCP) |
| **GRE Flood** | GRE protocol (47) packets with max payload |
| **DNS Flood** | Randomized DNS query types (A, AAAA, MX, NS, etc.) |

</details>

<details>
<summary><b>Layer 7 — Application</b></summary>

| Method | Description |
|---|---|
| **HTTP Flood** | GET/POST with randomized headers + user-agents |
| **HTTPS/TLS Flood** | TLS handshake exhaustion + burst requests |
| **CF Bypass** | Cloudflare bypass via session/cookie reuse + fingerprinting |
| **Rapid Reset** | HTTP/2 exploit (CVE-2023-44487) with batched HEADERS + RST_STREAM |
| **Proxy Support** | Full proxy integration for all L7 methods (HTTP + SOCKS5) |

</details>

---

## Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    upx-ucl openssl git wget gcc python3 screen build-essential

# Install Go (1.24+ required)
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version  # verify installation
```

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Syn2Much/VisionC2.git
   cd VisionC2
   chmod +x setup.py tools/*.sh
   ```

2. **Run interactive setup**
   ```bash
   python3 setup.py
   ```
   The setup script will:
   - Generate 4096-bit TLS certificates
   - Create encryption keys and configuration
   - Cross-compile binaries for all supported architectures
   - Build the C2 server binary

3. **Output locations**

   | Output | Path |
   |---|---|
   | C2 Server | `./server` |
   | Agent Binaries | `./bins/` |
   | Configuration | `setup_config.txt` |

---

## Usage

### Starting the C2 Server

**Option 1: TUI Mode (Recommended)**
```bash
screen ./server
```
- Detach: `Ctrl + A` → `D`
- Reattach: `screen -r`

**Option 2: Telnet/Multi-User Mode**
```bash
screen ./server --split
nc your-server-ip 1337
```
- User database: `cnc/users.json`
- Login keyword: configured during setup

---

## Architecture

```text
Bot Binary
    │
    ▼
┌─────────────────────────────────────────┐
│      Runtime Decryption                 │
│  - AES-128-CTR decrypt all sensitive    │
│    strings from config.go hex blobs     │
│  - 16-byte key from split XOR functions │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│         Startup Sequence                │
│  - Daemonization (fork + setsid)        │
│  - Single-instance enforcement (PID)    │
│  - Sandbox/VM/debugger detection        │
│  - Persistence (systemd + cron + rc)    │
│  - Metadata caching                     │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│      C2 Resolution & Connection         │
│  - 5-layer C2 address decryption        │
│  - DNS Chain (DoH → UDP → A → Raw)     │
│  - TLS 1.3 Handshake                     │
│  - HMAC challenge/response auth         │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│        Command Loop & Execution         │
│  - Command dispatch                     │
│  - L4/L7 attacks (10+ methods)          │
│  - SOCKS5 proxy (RFC 1929 auth)         │
│  - Remote shell / broadcast shell       │
└─────────────────────────────────────────┘
```

---

## Project Structure

```
VisionC2/
├── setup.py                  # Interactive setup wizard
├── server                    # Compiled CNC binary
├── bot/                      # Bot agent
│   ├── main.go               # Entry point, main loop
│   ├── config.go             # All config vars + AES-encrypted sensitive strings
│   ├── connection.go         # TLS, DNS resolution, auth, C2 handler
│   ├── attacks.go            # L4/L7 DDoS methods + proxy support
│   ├── opsec.go              # AES-128-CTR, RC4, key derivation, sandbox detection
│   ├── persist.go            # Systemd, cron, rc.local persistence
│   └── socks.go              # SOCKS5 proxy with RFC 1929 auth
├── cnc/                      # CNC server
│   ├── main.go               # TLS listener, server entry
│   ├── cmd.go                # Command dispatch, help menus
│   ├── ui.go                 # Bubble Tea TUI
│   ├── connection.go         # Bot connection handler, auth, TLS config
│   ├── miscellaneous.go      # RBAC, user auth
│   └── certificates/         # TLS certs
├── tools/
│   ├── build.sh              # Cross-compile 14 architectures
│   ├── crypto.go             # AES-128-CTR encrypt/decrypt/verify CLI
│   ├── cleanup.sh            # Remove bot persistence from a machine
│   └── deUPX.py              # UPX signature stripper
├── bins/                     # Compiled bot binaries
└── Docs/                     # Architecture, commands, usage, changelog
```

---

## Documentation

| Document | Description |
|---|---|
| [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) | Full system architecture |
| [`CHANGELOG.md`](Docs/CHANGELOG.md) | Version history and changes |
| [`COMMANDS.md`](Docs/COMMANDS.md) | Command reference |
| [`USAGE.md`](Docs/USAGE.md) | Usage guide |

---

## Legal Disclaimer

> **FOR AUTHORIZED SECURITY RESEARCH AND EDUCATIONAL PURPOSES ONLY**
>
> This software is intended for authorized penetration testing, security research and education, and legitimate stress testing of owned systems.
>
> **Usage of this tool for attacking targets without prior mutual consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.**

---

## Author

**Syn2Much** — [dev@sinnners.city](mailto:dev@sinnners.city) · [@synacket](https://x.com/synacket)

---

<div align="center">
<sub>Maintained with ❤️ by Syn</sub>
</div>
