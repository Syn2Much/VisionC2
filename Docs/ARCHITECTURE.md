# 🏗️ VisionC2 — Architecture Documentation

> Complete technical breakdown of CNC server, bot agent, encryption, protocol flow, and build pipeline.

---

## 📋 Quick Navigation

### 🏗️ [CNC Server Architecture](#-cnc-server-architecture)
- [🎯 High-Level Overview](#-cnc-high-level-overview)
- [🔐 Authentication Protocol](#-cnc-authentication-protocol)  
- [🖥️ User Interface (TUI)](#️-cnc-user-interface-tui)
- [🌐 Web Panel (Tor)](#-cnc-web-panel-tor)
- [👥 Permission Model (RBAC)](#-cnc-permission-model-rbac)

### 🤖 [Bot Agent Architecture](#-bot-agent-architecture)
- [🔒 C2 Obfuscation & Encryption](#-bot-c2-obfuscation--encryption)
- [⚡ Attack Capabilities](#-bot-attack-capabilities)
- [🔄 Persistence Mechanisms](#-bot-persistence-mechanisms)
- [🛡️ Anti-Analysis & Sandbox Detection](#️-bot-anti-analysis--sandbox-detection)
- [🌐 SOCKS5 Proxy Architecture](#-bot-socks5-proxy-architecture)

### 🔧 [Build & Infrastructure](#-build--infrastructure)
- [📁 Project Structure](#-project-structure)
- [⚙️ Build Pipeline](#️-build-pipeline--cross-compilation)
- [🎛️ Setup Automation](#️-setup-automation)

---

## 🏗️ CNC Server Architecture

### 🎯 CNC High-Level Overview

```
     🎮 OPERATOR INTERFACES
     ┌─────────────────────────────────────────────┐
     │  🖥️ TUI    📡 Tor Panel    ⌨️ Telnet CLI   │
     │ (local)   (.onion WebSocket)  (--split)     │
     └─────────────────┬───────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │     🏗️ CNC SERVER (Go)      │
        │  ┌────────┬────────┬───────┐ │
        │  │ 🤖 Bot │ 🔐 TLS │ 👥 RBAC│ │
        │  │  Mgmt  │ Auth   │       │ │
        │  └────────┴────────┴───────┘ │
        │     🔒 TLS 1.2+ (port 443)   │
        └─────────────┬─────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
   🤖 Bot ARM    🤖 Bot x64    🤖 Bot MIPS
```

> **💡 Key Feature:** Three control interfaces — use any combination. The Tor panel enables full control without clearnet exposure.

**🎛️ Operating Modes:**
- **🖥️ TUI Mode** (default): Local Bubble Tea dashboard with real-time bot management
- **⌨️ Split Mode** (`--split`): Remote Telnet CLI on configurable port  
- **🌐 Web Mode** (`--web`): Tor hidden service with WebSocket-powered dashboard

---

### 🔐 CNC Authentication Protocol

> **📋 TL;DR:** Challenge-response using MD5 + shared secret. Bot must know the correct syncToken or connection is dropped.

```
     🤖 BOT                           🏗️ CNC
      │                               │
      │◄──── 🎲 AUTH_CHALLENGE ────────│ Random 32-char challenge
      │                               │
      │  🔐 response = Base64(MD5(     │ 
      │    challenge + syncToken +     │ Bot computes hash
      │    challenge                   │
      │  ))                           │
      │                               │
      │────── 📤 response ────────────►│ Send response
      │                               │
      │         🔍 CNC verifies        │ Same hash computation
      │                               │
      │◄──── ✅ AUTH_SUCCESS ──────────│ Success or disconnect
      │                               │
      │────── 📋 REGISTER ────────────►│ Bot registration data
      │                               │
      │◄═══════ 🔄 Command Loop ═══════►│ Enter main session
```

**🔑 Security Details:**
- **Sync Token**: 16-char random string (generated per campaign)
- **Build Tag**: Version string that must match exactly
- **Replay Protection**: Each challenge is unique

---

### 🖥️ CNC User Interface (TUI)

**📱 Bubble Tea Dashboard Views:**

| 🖥️ View | 🔑 Hotkey | 📝 Description |
|----------|-----------|----------------|
| **Dashboard** | `d` | Bot count, system stats, navigation menu |
| **Bot List** | `b` | Live table with actions (shell, persist, kill) |
| **Attack Builder** | `a` | Method picker, target form, launch controls |
| **Remote Shell** | `r` | Single-bot shell with history & scrolling |
| **Broadcast Shell** | `s` | Multi-bot shell with arch/RAM filters |
| **SOCKS Manager** | `p` | Proxy setup (relay/direct modes) |
| **Help** | `h` | Multi-section help guide |

> **⚡ Real-time Features:** Toast notifications, live bot updates, attack status, connection events

---

### 🌐 CNC Web Panel (Tor)

> **🔒 Security Note:** Tor-only access — no clearnet exposure. Generates `.onion` address on startup.

**🗂️ Dashboard Tabs:**

| 📋 Tab | 🔑 Key | 🎯 Purpose |
|--------|--------|------------|
| **🤖 Bots** | `1` | Live bot table, right-click for management popup |
| **💻 Shell** | `2` | WebSocket shell + file browser with shortcuts |
| **💥 Attack** | `3` | Attack launcher with confirmation dialogs |
| **🔌 SOCKS5** | `4` | Live proxy dashboard with SSE status updates |
| **📋 Tasks** | `5` | Auto-execute commands for new bot connections |
| **👥 Users** | `6` | User management (add/edit/remove, permissions) |

**🎮 Bot Management Popup:**
- 💻 Open shell session
- 🔌 Start/stop SOCKS5 proxy  
- 📊 View system info
- 🔄 Install persistence
- ☠️ Kill bot (self-destruct)

---

### 👥 CNC Permission Model (RBAC)

| 🏷️ Level | 💥 DDoS | 💻 Shell/SOCKS | 🎯 Targeting | 🔧 Bot Mgmt | 🗄️ DB Access |
|----------|---------|----------------|---------------|-------------|---------------|
| **Basic** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Pro** | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Admin** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Owner** | ✅ | ✅ | ✅ | ✅ | ✅ |

> **📁 Storage:** User credentials in `users.json` with expiry dates and permission levels.

---

## 🤖 Bot Agent Architecture

### 📋 Bot Lifecycle Overview

```
🤖 Bot Binary Executed
        │
        ▼
🔓 Decrypt Runtime Config ─── AES-128-CTR decrypt all strings
        │
        ▼  
👻 Daemonization ────────────── Fork, setsid, background process
        │
        ▼
🛡️ Sandbox Detection ────────── 40+ VM/analysis tool checks
        │
        ▼
🔐 Singleton Lock ───────────── PID file, kill old instance
        │
        ▼
🔄 Install Persistence ──────── rc.local + cron watchdog
        │
        ▼
🌐 Resolve C2 Address ────────── 6-layer decode + DNS lookup
        │
        ▼
🔄 Connect & Reconnect Loop ──── TLS connect, auth, command loop
```

> **💡 Key Point:** Sandbox detection runs BEFORE any file writes to avoid leaking IOCs to analysis tools.

---

### 🔒 Bot C2 Obfuscation & Encryption

> **📋 TL;DR:** C2 address never stored in plaintext. Goes through 6-layer encoding pipeline, decoded at runtime.

**🔐 6-Layer Encoding Pipeline:**

```
📍 Plaintext C2 ("192.168.1.1:443")
        │
        ▼
🔍 Layer 1: MD5 Checksum ────── Integrity verification
        │
        ▼
🔀 Layer 2: Byte Substitution ── XOR + bit rotation  
        │
        ▼
🔐 Layer 3: RC4 Encryption ───── Stream cipher
        │
        ▼
⚡ Layer 4: XOR Rotation ────── Rotating key XOR
        │
        ▼
📝 Layer 5: Base64 Encode ───── Safe string storage
        │
        ▼
🛡️ Layer 6: AES-128-CTR ─────── Final encryption layer
        │
        ▼
💾 Stored in Binary ─────────── As hex blob in config.go
```

**🔑 Runtime Decoding:**
1. **Stage 1**: AES decrypt (startup) → 5-layer blob
2. **Stage 2**: 5-layer decode (when needed) → plaintext C2

> **⚠️ Anti-Analysis:** All encryption keys split across 16 XOR functions with randomized constants per build.

---

### ⚡ Bot Attack Capabilities  

**🌐 Layer 4 (Network) Attacks:**

| 💥 Method | 🎯 Target | 📊 Technique |
|-----------|-----------|--------------|
| **UDP Flood** | Volume | 1024-byte payload spam |
| **TCP Flood** | Resources | Connection table exhaustion |
| **SYN Flood** | Resources | Raw SYN packets, random ports |
| **ACK Flood** | Firewall | Raw ACK packet spam |
| **GRE Flood** | Protocol | GRE tunnel packets |
| **DNS Flood** | Resolution | Random queries + reflection |

**🌍 Layer 7 (Application) Attacks:**

| 💥 Method | 🎯 Target | 🛠️ Features |
|-----------|-----------|-------------|
| **HTTP Flood** | Web servers | Random UA/referer, 4020 workers |
| **HTTPS Flood** | SSL/TLS | Handshake exhaustion + burst requests |
| **CF Bypass** | Cloudflare | Session persistence + fingerprinting |
| **Rapid Reset** | HTTP/2 | CVE-2023-44487 exploit |

> **🔌 Proxy Support:** All L7 attacks support HTTP/SOCKS5 proxies with automatic rotation.

**⚙️ Attack Control:**
- **Workers**: 2024 concurrent goroutines per attack
- **Duration**: Automatic timeout with context cancellation  
- **Control**: Start via `raichu()`, stop via `pikachu()` functions

---

### 🔄 Bot Persistence Mechanisms

**🚀 Automatic Persistence (Boot Sequence):**
- **📄 rc.local**: Append startup command to `/etc/rc.local`
- **⏰ Cron**: Install watchdog (`* * * * * pgrep || restart`)

**🔧 Full Persistence (`!persist` command):**
1. **📁 Hidden Directory**: Create disguised storage (e.g., `/var/lib/.httpd_cache/`)
2. **📜 Download Script**: Write persistence script for updates  
3. **⚙️ Systemd Service**: Install service with `Restart=always`
4. **⏰ Cron Backup**: Fallback watchdog via crontab

**💀 Self-Destruct (`!kill` command):**
1. Remove systemd service
2. Clean crontab entries  
3. Strip rc.local modifications
4. Delete hidden directories
5. Remove binary + lock file
6. Exit cleanly

> **🐛 Debug Mode:** When enabled, persistence functions only log actions without modifying system.

---

### 🛡️ Bot Anti-Analysis & Sandbox Detection

> **📋 TL;DR:** 40+ detection signatures check for VMs, analysis tools, and debuggers before any file I/O.

**🔍 Detection Methods:**

| 🎯 Type | 📊 Checks | 🚨 Triggers |
|---------|-----------|-------------|
| **VM Processes** | `/proc/*/cmdline` scan | vmware, vbox, qemu, cuckoo, joesandbox |
| **Analysis Tools** | 40+ tool paths | strace, gdb, ida, wireshark, yara, volatility |
| **Debugger Parent** | Parent process check | gdb, lldb, radare2, ghidra, frida |

**🚨 Detection Response:**
- Log specific trigger (debug mode)
- Sleep 24-27 hours (randomized) 
- Exit cleanly

> **🔐 Encrypted Signatures:** All detection lists are AES-128-CTR encrypted in the binary — no plaintext IOCs.

---

### 🌐 Bot SOCKS5 Proxy Architecture

**🔄 Two Proxy Modes:**

```
🔌 BACKCONNECT (Recommended):
User ──[SOCKS5]──▶ 🖥️ Relay Server ◀──[TLS]── 🤖 Bot ──▶ 🎯 Target
                   (disposable VPS)           (infected)

🔗 DIRECT:  
User ──[SOCKS5]──▶ 🤖 Bot:1080 ──▶ 🎯 Target
```

**⚙️ Key Components:**

| 🔧 Component | 🎯 Function | 📝 Description |
|--------------|-------------|----------------|
| **Backconnect** | `muddywater()` | Bot connects OUT to relay |
| **Direct** | `turmoil()` | Bot opens inbound SOCKS5 port |
| **Multi-Relay** | `cozyBear()` | Auto-reconnect + failover |
| **Data Channel** | `fancyBear()` | Per-session relay connection |
| **Protocol** | `trickbot()` | SOCKS5 v/username/IPv4/IPv6 |

> **🔥 Failover:** Bots rotate through relay list with exponential backoff (5s → 60s max).

**🔐 Authentication:**
- Username/password auth (RFC 1929) when credentials set
- Falls back to no-auth when credentials empty
- Runtime credential updates via `!socksauth`

---

## 🔧 Build & Infrastructure

### 📁 Project Structure

```
VisionC2/
├── 🐍 setup.py              # Interactive setup wizard
├── 🔧 server                # Compiled CNC binary  
├── 🔁 relay_server          # Compiled relay binary
├── 🤖 bot/                  # Bot agent source
│   ├── main.go              # Entry point + shell execution
│   ├── config.go            # Encrypted config blobs
│   ├── connection.go        # TLS + DNS + authentication  
│   ├── attacks.go           # DDoS methods + proxy support
│   ├── opsec.go             # Encryption + sandbox detection
│   ├── persist.go           # Persistence + self-destruct
│   └── socks.go             # SOCKS5 proxy + relay
├── 🏗️ cnc/                  # CNC server source
│   ├── main.go              # Server entry + TLS listener
│   ├── connection.go        # Bot auth + management
│   ├── cmd.go               # Command dispatch + sessions
│   ├── ui.go                # Bubble Tea TUI
│   ├── miscellaneous.go     # User auth + RBAC
│   └── users.json           # User credential database
├── 🔁 relay/                # SOCKS5 relay server
├── 🛠️ tools/                # Build + crypto + cleanup tools
├── 📦 bins/                 # Compiled bot binaries
└── 📚 Docs/                 # Documentation
```

---

### ⚙️ Build Pipeline & Cross-Compilation

**🎯 14 Linux Architectures:**

| 📦 Binary | 🏗️ Arch | 📝 Disguised Name |
|-----------|---------|------------------|
| ksoftirqd0 | x86 32-bit | Kernel thread name |
| kworker_u8 | x86_64 | Worker thread |  
| jbd2_sda1d | ARMv7 | Journaling daemon |
| bioset0 | ARMv5 | Block I/O thread |
| kblockd0 | ARMv6 | Block device daemon |
| rcuop_0 | ARM64 | RCU callback thread |
| kswapd0 | MIPS | Memory management |
| ecryptfsd | MIPS LE | Encryption daemon |
| xfsaild_sda | MIPS64 | XFS metadata daemon |
| scsi_tmf_0 | MIPS64 LE | SCSI task management |
| devfreq_wq | PPC64 | Device frequency work queue |
| zswap_shrinkd | PPC64 LE | Swap compression |
| edac_polld | s390x | Error detection daemon |
| cfg80211d | RISC-V 64 | WiFi config daemon |

**🔨 Build Process:**
1. **Cross-compile** with Go for each architecture
2. **Strip symbols** (`strip --strip-all`)  
3. **Pack with UPX** (custom zero-fingerprint fork)
4. **Output to** `bins/` directory

> **💡 Stealth:** All binary names mimic legitimate Linux kernel threads and system daemons.

---

### 🎛️ Setup Automation

**🐍 Interactive Setup Wizard (`setup.py`):**

**⚙️ Full Setup (Option 1):**
1. **🐛 Debug Mode** — Enable/disable verbose logging
2. **🌐 C2 Configuration** — Set IP/domain + admin port  
3. **🔐 Security Tokens** — Generate syncToken + buildTag + configSeed
4. **🔁 Relay Endpoints** — Configure backconnect SOCKS5 relays
5. **👤 SOCKS5 Credentials** — Set default proxy auth
6. **🔒 C2 Obfuscation** — 6-layer encoding + AES encryption
7. **🔑 Key Generation** — Fresh AES key + XOR byte randomization
8. **📝 Config Encryption** — Encrypt all sensitive strings
9. **🔐 TLS Certificates** — Generate 4096-bit RSA or use custom
10. **🔨 Build Binaries** — CNC + bots + relay server
11. **💾 Save Config** — Write setup summary

**🔄 Quick Options:**
- **Option 2**: Update C2 address only (keep tokens/certs)
- **Option 3**: Update relay endpoints + SOCKS5 credentials

> **💾 Output:** Binaries in `bins/`, certificates in `cnc/certificates/`, config summary in `setup_config.txt`

---

### 🏷️ Code Obfuscation (Naming Convention)

**🤖 Bot Functions — APT Groups:**

| 🏷️ Function Name | 🎯 Real Purpose |
|-----------------|----------------|
| `anonymousSudan` | C2 session handler |
| `gamaredon` | TLS connection |
| `sidewinder` | Shell execution |
| `blackEnergy` | Command dispatcher |
| `winnti` | Sandbox detection |
| `mustangPanda` | Bot ID generator |
| `dragonfly` | Full persistence |
| `nukeAndExit` | Self-destruct |
| `muddywater` | SOCKS5 backconnect |
| `stuxnet` | Daemonization |

**⚡ Attack Functions — Pokemon:**

| 🏷️ Function Name | 🎯 Real Purpose |
|-----------------|----------------|
| `pikachu` | Stop all attacks |
| `raichu` | Attack control |
| `snorlax` | UDP flood |
| `gengar` | DNS flood |
| `alakazam` | HTTP flood |
| `gyarados` | Cloudflare bypass |
| `giratina` | HTTP/2 Rapid Reset |

**🔐 Crypto Functions — Legendary Pokemon:**

| 🏷️ Function Name | 🎯 Real Purpose |
|-----------------|----------------|
| `dialga` | Main C2 resolver |
| `charizard` | Key derivation |
| `venusaur` | C2 address decoder |
| `garuda` | AES-128-CTR decrypt |

> **🎭 Purpose:** Makes static analysis harder by obscuring function purposes with themed naming.

---

## 🎯 Quick Reference

### 🚀 Getting Started
1. Run `python3 setup.py` → Full Setup
2. Start CNC: `./server` 
3. Deploy bots via `loader.sh`
4. Access via TUI, Telnet, or Tor panel

### ⚡ Key Commands
- **Shell**: `!shell <command>` 
- **Attack**: `!udp target.com 80 60`
- **SOCKS5**: `!socks` (backconnect) or `!socksd 1080` (direct)
- **Persistence**: `!persist`
- **Self-destruct**: `!kill`

### 📚 Documentation
- [`COMMANDS.md`](COMMANDS.md) — Command reference
- [`SETUP.md`](SETUP.md) — Installation guide  
- [`PROXY.md`](PROXY.md) — SOCKS5 relay deployment
- [`CHANGELOG.md`](CHANGELOG.md) — Version history

---

*🔧 Generated for VisionC2 — Author: **Syn2Much***
