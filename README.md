
<div align="center">

# ☾℣☽ VisionC2

 > Vision is a Go-based C2 (TUI) and Agent with HMAC Auth, TLS 1.3 Comms, Layer 4/7 Attacks , Remote Shell, Reverse SOCKS5, and Advance Anti-Anaylsis and Obfuscation Techniques server over a Go TUI
> 
![Go](https://img.shields.io/badge/Go-1.23.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-009688?style=for-the-badge&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-GNU%20GPL-blue?style=for-the-badge&logo=go)

[![Architecture](https://img.shields.io/badge/Full_Architecture-Documentation-blueviolet?style=for-the-badge)](Docs/ARCHITECTURE.md)
[![Changelog](https://img.shields.io/badge/Full_ChangeLog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)

![Animation](https://github.com/user-attachments/assets/bab596ce-5269-42ca-ae97-cae26437ae41)
---

<br>
</div>


##  Key Features

| Category              | Feature                                                                 |
|-----------------------|-------------------------------------------------------------------------|
|  CNC                 | Full-featured interactive TUI control panel (BubbleTea)                             |
|  Communication      | Modern TLS 1.3 encrypted bot ↔ server communication                    |
|  Attack Methods      | Layer 4 (network) & Layer 7 (application) attack methods                |
|  Evasion            | Strong anti-analysis & sandbox evasion (HMAC/MD5 Auth, Proc Scan, Debugger Check)                                |
|  Stealth            | Full Unix daemonization + single-instance enforcement (Mirai Style)                 |
|  Persistent          | Automatic Cronjobs, startup service scripts, reinfect on device reboot             |
|  C2 Resilience      | Supports TXT Records, A Records, Direct IP. (No Plaintext/Bot Decrypts C2 at runtime)    |
|  Cross-Platform     | Multi-architecture bot binaries (14 targets out-of-the-box/ Custom UPX Packer included)             |
|  Auto-Setup         | Interactive Python Script to automate Config Setup and Build (updates source code)              |

##  Attack Methods

### Layer 4 (Network / Transport Layer)

| Method       | Protocol       | Description                                          |
|--------------|----------------|------------------------------------------------------|
| UDP Flood    | UDP            | High-volume 1024-byte payload spam                   |
| TCP Flood    | TCP            | Connection table exhaustion attack                   |
| SYN Flood    | Raw TCP        | SYN packets with randomized source ports             |
| ACK Flood    | Raw TCP        | ACK packet flooding                                  |
| GRE Flood    | GRE (47)       | GRE protocol packets with maximum payload            |
| DNS Flood    | UDP / DNS      | Randomized DNS query types (A, AAAA, MX, NS, etc.)   |

### Layer 7 (Application Layer)
| Method          | Description                                                  |
|-----------------|--------------------------------------------------------------|
| HTTP Flood      | GET/POST requests with randomized headers & user-agents      |
| HTTPS/TLS Flood | TLS handshake exhaustion + burst of full requests            |
| CF Bypass       | Cloudflare bypass via session/cookie reuse & fingerprinting  |
| Rapid Reset     | HTTP/2 CVE-2023-44487 — batched HEADERS+RST_STREAM framing  |
| Proxy Support   | Full proxy list integration for all L7 methods (HTTP/SOCKS5) |


##  Installation

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    upx-ucl openssl git wget gcc python3 screen build-essential
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
   - C2 Server: `./server`
   - Agent Binaries: `./bins/`
   - Configuration: `setup_config.txt`

##  Usage

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

##  Architecture

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

##  Documentation
- **Changelog**: [`Docs/CHANGELOG.md`](Docs/CHANGELOG.md)
- **Commands**: [`Docs/COMMANDS.md`](Docs/COMMANDS.md)
- **Usage**: [`Docs/USAGE.md`](Docs/USAGE.md)

## Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND EDUCATIONAL PURPOSES ONLY**

This software is intended for:
- Authorized penetration testing
- Security research and education
- Legitimate stress testing of owned systems

**Usage of this tool for attacking targets without prior mutual consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.**

## Author

**Syn2Much**

- Email: [dev@sinnners.city](mailto:dev@sinnners.city)
- X: [@synacket](https://x.com/synacket)
---
<div align="center">
<sub>Maintained with ❤️ by Syn</sub>
</div>
