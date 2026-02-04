
# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2](https://img.shields.io/badge/VisionC2-V1.7-red)
![Go](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

> **VisionC2** is a Go-based Command & Control framework for **network stress testing**, featuring a full-screen TUI CNC, TLS 1.3 encryption, 14+ architecture support, remote shell access, SOCKS5 proxying, and advanced Layer 4/7 testing capabilities.

---

## ✨ Features 

### 🤖 Bot Capabilities

* **Layer 4**: UDP, TCP, SYN, ACK, GRE, DNS flood methods
* **Layer 7**: HTTP / HTTPS / TLS with HTTP/2 fingerprinting and Cloudflare UAM bypass (including CAPTCHA solving)
* **Remote Execution**: Interactive and fire-and-forget shell commands
* **SOCKS5 Proxy**: Convert any agent into a SOCKS5 proxy server

### 🖥️ CNC & TUI

* Full-screen **TUI Command & Control**
* Real-time bot management & attack builder
* **Single-Agent Control** (interactive per-bot shell)
* **Broadcast Shell Execution** with architecture, RAM, and bot-count filtering
* **Built-in SOCKS5 Proxy Manager** (one-click per bot)

### 🛡️ Security & Stealth

* TLS 1.3 with Perfect Forward Secrecy
* HMAC challenge-response authentication
* Multi-layer obfuscation (RC4, XOR, byte substitution, MD5)
* Anti-analysis & sandbox detection

### ⚡ Performance & Scale

* **2 Servers** → **30k–40k RPS**
* **Layer 4 Throughput (2 servers)** → **2–6 Gbps**
* 14+ architectures with automated cross-compilation
* Fully automated ~5-minute setup

> *Performance depends on agent hardware and network conditions.*

---

## 🧠 Architecture Overview

```
Admin Console ──TLS 1.3──► C2 Server ◄──TLS 1.3── Bot Agents (14+ architectures)
```

### Bot Startup Flow

```
START → Sandbox Check ─[detected]─► EXIT(200)
          │
          ▼
    Persistence (rc.local + cron)
          │
          ▼
    C2 Resolution:
      Decrypt URL → DoH TXT → DNS TXT → A Record → Direct IP
          │
          ▼
    TLS Connect → HMAC Auth → Command Loop
```

### HMAC Challenge-Response

```
BOT                                    C2 SERVER
 │ ──── TLS Handshake ───────────────► │
 │ ◄─── AUTH_CHALLENGE:<random_32> ─── │
 │      Hash: Base64(MD5(challenge + MAGIC + challenge))
 │ ──── AUTH_RESPONSE:<hash> ────────► │
 │ ◄─── AUTH_SUCCESS ────────────────► │
 │ ──── ARCH|RAM|VERSION ────────────► │
 │ ◄═══ Command Loop ════════════════► │
```

### C2 URL Decryption (4-Layer)

```
Base64 Blob
 → Base64 Decode
 → XOR (derived key)
 → RC4
 → Byte Sub (ROL3, XOR 0xAA)
 → MD5 Verify
```

---

## 🧪 Demo

<p align="center">
  <b>TLS Bypass vs High-Density DSTAT Graph (6 servers)</b>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/52ffce78-eb92-4f7c-b34e-ba6ff227e416" alt="Demo Animation">
</p>

---

## 🚀 Quick Start

### Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen
# Go 1.23+ required → https://go.dev/dl/
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
cd cnc
./cnc
```

**Split / Multi-User Mode**

```bash
./cnc --split
# nc <server-ip> <admin-port>
```

Bot binaries are automatically built into `bot/bins/`.

---

## 🧬 Binary Layout & Architecture Support

Binaries are named to resemble system processes for operational blending:

| Binary    | Architecture | Description                |
| --------- | ------------ | -------------------------- |
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
* Locker / killer (removal of competing agents)

### Planned

* Auto-generated DGA fallback domains
* Self-replication & spreading
* Single-instance port takeover

---

## 📚 Documentation

| File              | Description                      |
| ----------------- | -------------------------------- |
| `USAGE.md`        | Setup, deployment, and TUI usage |
| `cnc/COMMANDS.md` | Full CNC command reference       |
| `CHANGELOG.md`    | Version history                  |

---

## ⚠️ Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND STRESS TESTING ONLY**

The authors assume no responsibility for misuse or legal consequences.

---

## 📜 License

MIT License — see `LICENSE`

---

## 🤝 Support

* GitHub Issues for bugs & feature requests
* Documentation in `USAGE.md`
* Contact: `dev@sinners.city`

---
