# ☾℣☽ VisionC2 — Full Architecture Document

> Complete technical breakdown of encryption, obfuscation, protocol flow, persistence, attack capabilities, and build pipeline.

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [High-Level Architecture](#2-high-level-architecture)
3. [C2 Address Obfuscation & Encryption](#3-c2-address-obfuscation--encryption)
4. [TLS Transport Layer](#4-tls-transport-layer)
5. [Authentication Protocol](#5-authentication-protocol)
6. [Bot Lifecycle & Connection Flow](#6-bot-lifecycle--connection-flow)
7. [Command Dispatch & Routing](#7-command-dispatch--routing)
8. [Persistence Mechanisms](#8-persistence-mechanisms)
9. [Anti-Analysis & Sandbox Detection](#9-anti-analysis--sandbox-detection)
10. [Attack Capabilities](#10-attack-capabilities)
11. [SOCKS5 Proxy Pivoting](#11-socks5-proxy-pivoting)
12. [CNC Server Architecture](#12-cnc-server-architecture)
13. [User Permission Model (RBAC)](#13-user-permission-model-rbac)
14. [DNS Resolution Chain](#14-dns-resolution-chain)
15. [Build Pipeline & Cross-Compilation](#15-build-pipeline--cross-compilation)
16. [Setup Automation](#16-setup-automation)
17. [Naming Convention (Code Obfuscation)](#17-naming-convention-code-obfuscation)

---

## 1. Project Structure

```
VisionC2/
├── go.mod                  # Go module (Vision), Go 1.24
├── go.sum
├── setup.py                # Interactive setup wizard (Python 3)
├── server                  # Compiled CNC binary
├── bot/                    # Bot agent source
│   ├── main.go             # Entry point, config, shell exec, main loop
│   ├── connection.go       # TLS connection, DNS resolution, auth, C2 handler
│   ├── attacks.go          # L4/L7 DDoS attack methods + proxy support
│   ├── opsec.go            # Encryption, sandbox detection, bot ID generation
│   ├── persist.go          # Persistence mechanisms (cron, systemd, rc.local)
│   └── socks.go            # SOCKS5 proxy server implementation
├── cnc/                    # CNC server source
│   ├── main.go             # Server entry, TLS listener, user listener
│   ├── connection.go       # TLS config, bot auth handler, bot management
│   ├── cmd.go              # Command dispatch, user session handler, help menus
│   ├── ui.go               # Bubble Tea TUI (dashboard, bot list, attack builder)
│   ├── miscellaneous.go    # User auth, permissions (RBAC), utilities
│   ├── users.json          # User credential database
│   └── certificates/       # TLS certs (server.crt, server.key)
├── tools/
│   ├── build.sh            # Cross-compilation for 14 architectures
│   └── deUPX.py            # UPX signature stripper
├── bins/                   # Compiled bot binaries (output)
└── Docs/
    ├── ARCHITECTURE.md     # This document
    ├── COMMANDS.md          # TUI hotkey reference
    ├── USAGE.md             # Usage guide
    ├── CHANGELOG.md         # Version history
    └── LICENSE
```

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      OPERATOR                               │
│    ┌──────────────┐        ┌──────────────────────┐         │
│    │  Bubble Tea  │        │  Telnet CLI          │         │
│    │  TUI (local) │   OR   │  (--split mode)      │         │
│    └──────┬───────┘        └─────────┬────────────┘         │
│           │                          │                      │
│           ▼                          ▼                      │
│    ┌──────────────────────────────────────────┐              │
│    │           CNC SERVER (Go)                │              │
│    │  ┌──────────┐  ┌──────────┐  ┌────────┐ │              │
│    │  │ Bot Mgmt │  │ Auth/TLS │  │  RBAC  │ │              │
│    │  │          │  │          │  │        │ │              │
│    │  └──────────┘  └──────────┘  └────────┘ │              │
│    │         TLS 1.2+ on port 443             │              │
│    └──────────────────┬───────────────────────┘              │
│                       │                                     │
└───────────────────────┼─────────────────────────────────────┘
                        │ TLS 1.2/1.3 (port 443)
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ┌─────────┐    ┌─────────┐    ┌─────────┐
   │  Bot    │    │  Bot    │    │  Bot    │
   │ (ARM64) │    │ (amd64) │    │ (MIPS)  │
   └─────────┘    └─────────┘    └─────────┘
```

**Two operating modes:**

- **TUI Mode** (default): Local Bubble Tea terminal UI with dashboard, bot list, attack builder
- **Split Mode** (`--split`): Telnet-based CLI on configurable port for remote admin access

---

## 3. C2 Address Obfuscation & Encryption

The C2 address is never stored in plaintext in the binary. It goes through a **5-layer encoding pipeline** at build time (via `setup.py`) and is decoded at runtime by the bot.

### Encoding Pipeline (setup.py → stored in binary)

```
Plaintext C2 ("192.168.1.1:443")
        │
        ▼
┌─ Layer 1: MD5 Checksum ─────────────────────────┐
│  Append first 4 bytes of MD5(payload) for        │
│  integrity verification after decoding            │
└──────────────────────────────────────────────────┘
        │
        ▼
┌─ Layer 2: Byte Substitution ────────────────────┐
│  For each byte:                                   │
│    b ^= 0xAA                                      │
│    b = ROTATE_LEFT(b, 5)                          │
└──────────────────────────────────────────────────┘
        │
        ▼
┌─ Layer 3: RC4 Stream Cipher ────────────────────┐
│  Key = charizard(cryptSeed)                       │
│  Standard RC4 S-box initialization + keystream    │
└──────────────────────────────────────────────────┘
        │
        ▼
┌─ Layer 4: XOR with Rotating Key ────────────────┐
│  result[i] = data[i] ^ key[i % len(key)]         │
└──────────────────────────────────────────────────┘
        │
        ▼
┌─ Layer 5: Base64 Encode ────────────────────────┐
│  Standard Base64 encoding for safe string storage │
└──────────────────────────────────────────────────┘
        │
        ▼
Stored as `const gothTits = "EkAJ9ezFRv5F..."` in bot/main.go
```

### Decoding Pipeline (bot runtime — `venusaur()` in opsec.go)

Exact reverse of encoding:

1. **Base64 Decode** → raw bytes
2. **XOR with rotating key** → undo layer 4
3. **RC4 Decrypt** (symmetric, same function) → undo layer 3
4. **Reverse Byte Substitution** → `ROTATE_RIGHT(b, 3)` then `b ^= 0xAA`
5. **MD5 Checksum Verify** → validate integrity of decoded payload

### Key Derivation (`charizard()` in opsec.go)

```
cryptSeed (8-char hex, e.g., "292ae3aa")
    │
    ▼
MD5( seed + [mew()⊕mewtwo()⊕celebi()⊕jirachi()] + entropy )
    │
    │  Split key bytes (anti-static-analysis):
    │    mew()     = 0x31 ^ 0x64 = 0x55
    │    mewtwo()  = 0x72 ^ 0x17 = 0x65
    │    celebi()  = 0x93 ^ 0xC6 = 0x55
    │    jirachi() = 0xA4 ^ 0x81 = 0x25
    │
    │  Entropy bytes:
    │    [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
    │    XOR'd with position-based values: (len(seed) + i*17) & 0xFF
    │
    ▼
16-byte MD5 hash (used as RC4 key + XOR key)
```

---

## 4. TLS Transport Layer

All bot ↔ CNC communication is encrypted via TLS.

### CNC Server TLS Config (`connection.go`)

| Setting | Value |
|---------|-------|
| Min Version | TLS 1.2 |
| Curves | X25519, P-256 |
| Server Cipher Preference | Enabled |
| Cipher Suites | ECDHE+AES-256-GCM, ECDHE+ChaCha20, ECDHE+AES-128-GCM |
| TLS 1.3 | Auto-accepted (all TLS 1.3 ciphers are secure) |
| Certificate | 4096-bit RSA (self-signed or custom) |

### Bot TLS Config (`connection.go` → `gamaredon()`)

| Setting | Value |
|---------|-------|
| InsecureSkipVerify | `true` (self-signed certs) |
| Min Version | TLS 1.2 |
| Dial Timeout | 30 seconds |
| Handshake Timeout | 30 seconds |

### Validation Flow (CNC side — `validateTLSHandshake()`)

1. Assert connection is `*tls.Conn`
2. 10-second deadline for handshake (anti-slowloris)
3. Reject TLS < 1.2
4. Whitelist cipher suite check (skip for TLS 1.3)
5. Hand off to `handleBotConnection()` for authentication

---

## 5. Authentication Protocol

Challenge-response using **MD5 + shared secret (magicCode)**.

```
     BOT                                    CNC
      │                                      │
      │◄──── AUTH_CHALLENGE:<random_32>  ─────│  Step 1: CNC sends random challenge
      │                                      │
      │  response = Base64(MD5(              │
      │    challenge + magicCode + challenge  │  Step 2: Bot computes response
      │  ))                                  │
      │                                      │
      │──── <response>  ─────────────────────►│  Step 3: Bot sends response
      │                                      │
      │                    CNC computes same  │  Step 4: CNC verifies
      │                    hash and compares  │
      │                                      │
      │◄──── AUTH_SUCCESS  ──────────────────│  Step 5: Success (or disconnect)
      │                                      │
      │──── REGISTER:v3.8:botID:arch:ram:cpu►│  Step 6: Bot sends registration
      │                                      │
      │     CNC checks PROTOCOL_VERSION      │  Step 7: Version verification
      │                                      │
      │◄═══════ Command Loop ═══════════════►│  Step 8: Enter command loop
```

- **Magic Code**: 16-char random string shared between bot and CNC (generated per campaign by `setup.py`)
- **Protocol Version**: Random version string (e.g., `v3.8`) — must match exactly or connection is dropped
- **Bot ID** (`mustangPanda()`): First 8 chars of `MD5(hostname + MAC_address)` — persists across reboots

---

## 6. Bot Lifecycle & Connection Flow

### Startup Sequence (`main()` in bot/main.go)

```
Bot Binary Executed
        │
        ▼
┌─ winnti() ──────────────────────┐
│ Sandbox/VM detection            │
│ Check: vmware, vbox, qemu,     │
│   cuckoo, gdb, strace, etc.    │
│ If detected → exit(200)        │
└─────────────────────────────────┘
        │ (safe)
        ▼
┌─ fin7() ────────────────────────┐
│ rc.local persistence            │
│ Append to /etc/rc.local         │
└─────────────────────────────────┘
        │
        ▼
┌─ lazarus() ─────────────────────┐
│ Cron persistence                │
│ Install cron job (every minute) │
│ pgrep -x <name> || <exe> &     │
└─────────────────────────────────┘
        │
        ▼
┌─ dialga() ──────────────────────┐
│ Resolve C2 address              │
│ (See DNS Resolution Chain §14)  │
└─────────────────────────────────┘
        │
        ▼
┌─ Main Reconnection Loop ───────┐
│ forever:                        │
│   gamaredon() → TLS connect     │
│   anonymousSudan() → session    │
│   on disconnect:                │
│     sleep(fancyBear = 5s)       │
│     retry                       │
└─────────────────────────────────┘
```

### Session Handler (`anonymousSudan()`)

```
Connected via TLS
    │
    ├── Receive AUTH_CHALLENGE
    ├── Send hafnium(challenge, magicCode) response
    ├── Receive AUTH_SUCCESS
    ├── Send REGISTER:version:botID:arch:RAM:CPU
    │
    └── Command Loop (180s read timeout):
        ├── PING → respond PONG
        └── <command> → blackEnergy() dispatcher
```

### Keepalive & Cleanup

- **Bot side**: 180-second read timeout per command cycle
- **CNC side**: `pingHandler()` sends PING every 60s, bot responds PONG
- **Dead bot cleanup**: Background goroutine runs every 60s, removes bots with no PONG in 5 minutes
- **Reconnection**: Bot sleeps `fancyBear` (5s) then retries connection forever

---

## 7. Command Dispatch & Routing

### Bot-Side Dispatcher (`blackEnergy()` in attacks.go)

| Command | Function | Description |
|---------|----------|-------------|
| `!shell`, `!exec` | `sidewinder()` | Execute command, return output (Base64 encoded) |
| `!stream` | `machete()` | Stream output line-by-line in real-time |
| `!detach`, `!bg` | `oceanLotus()` | Execute in background (detached, no output) |
| `!stop` | `pikachu()` | Stop all running attacks (close stop channel) |
| `!udpflood` | `snorlax()` | UDP flood |
| `!tcpflood` | `gengar()` | TCP connection flood |
| `!http` | `alakazam()` / `alakazamProxy()` | HTTP POST flood (±proxy) |
| `!https`, `!tls` | `machamp()` / `machampProxy()` | HTTPS/TLS flood (±proxy) |
| `!cfbypass` | `gyarados()` / `gyaradosProxy()` | Cloudflare bypass flood (±proxy) |
| `!syn` | `dragonite()` | Raw SYN flood (requires CAP_NET_RAW) |
| `!ack` | `tyranitar()` | Raw ACK flood |
| `!gre` | `metagross()` | GRE protocol flood |
| `!dns` | `salamence()` | DNS query flood |
| `!persist` | `dragonfly()` | Full persistence setup |
| `!kill` | `os.Exit(0)` | Terminate bot |
| `!info` | — | Return hostname, arch, botID, OS |
| `!socks` | `muddywater()` | Start SOCKS5 proxy on given port |
| `!stopsocks` | `emotet()` | Stop SOCKS5 proxy |

### CNC-Side Command Routing

| Mode | Function | Description |
|------|----------|-------------|
| Broadcast | `sendToBots()` | Send to ALL authenticated bots |
| Filtered | `sendToFilteredBots()` | Send to bots matching arch/RAM/count filters |
| Targeted | `sendToBot()` | Send to specific bot by ID (full or prefix match) |
| TUI Target | `sendToSingleBot()` | Send to specific bot from TUI remote shell |

### Response Routing

Shell output from bots follows this path:

```
Bot executes !shell → sidewinder()
    │
    ▼
Base64 encode output → send "OUTPUT_B64: <encoded>\n"
    │
    ▼
CNC receives → handleBotConnection()
    │
    ├── Decode Base64
    ├── Forward to TUI (ShellOutputMsg) if TUI mode
    └── Forward to user (forwardBotResponseToUser) if split mode
        └── Uses commandOrigin map to route to correct user
```

---

## 8. Persistence Mechanisms

### On Startup (Automatic)

| Method | Function | Mechanism |
|--------|----------|-----------|
| rc.local | `fin7()` | Appends `<exe_path> # <random_name>` to `/etc/rc.local` |
| Cron | `lazarus()` | Installs `* * * * * pgrep -x <name> \|\| <exe> &` |

### On `!persist` Command (Full)

`dragonfly()` sets up comprehensive persistence:

1. **Hidden Directory**: Creates `/var/lib/.redis_helper/`
2. **Persistence Script**: Writes `.redis_script.sh` that downloads and runs the bot
3. **Systemd Service**: Creates `redis-helper.service` with `Restart=always`
4. **Cron Backup**: Installs cron job via `carbanak()` as fallback

```
/var/lib/.redis_helper/
├── .redis_script.sh      # Download + execute script
└── .redis_process         # Bot binary (disguised name)

/etc/systemd/system/
└── redis-helper.service   # Auto-restart systemd unit
```

All files are disguised as Redis system files to blend with legitimate services.

### Debug Mode

When `debugMode = true`, persistence functions **only log** what they would do — no actual file writes or system modifications. This prevents accidental persistence during development.

---

## 9. Anti-Analysis & Sandbox Detection

### `winnti()` — Sandbox Detection (opsec.go)

Three detection methods, checked at startup:

**1. VM Process Detection** — Scans `/proc/*/cmdline` for:

```
vmware, vbox, virtualbox, qemu, firejail, bubblewrap,
gvisor, kata, cuckoo, joesandbox, cape, any.run, hybrid-analysis
```

**2. Analysis Tool Detection** — Checks if these are running:

```
strace, ltrace, gdb, radare2, ghidra, ida, wireshark, tshark, tcpdump
```

**3. Debugger Parent Check** — Reads `/proc/<ppid>/cmdline` for:

```
gdb, strace, ltrace, radare2, rr
```

If any check triggers → `os.Exit(200)`

### Bot ID Generation (`mustangPanda()`)

```
botID = MD5(hostname + ":" + MAC_address)[:8]
```

Deterministic — same machine always generates same ID. Survives reboots. CNC deduplicates by closing old connection if same botID reconnects.

---

## 10. Attack Capabilities

### Layer 4 (Network)

| Method | Function | Protocol | Technique |
|--------|----------|----------|-----------|
| UDP Flood | `snorlax()` | UDP | 1024-byte payload spam via `net.Dial` |
| TCP Flood | `gengar()` | TCP | Connection + minimal HTTP data, table exhaustion |
| SYN Flood | `dragonite()` | Raw TCP | Raw SYN packets, random src ports, max payload (65535-40 bytes) |
| ACK Flood | `tyranitar()` | Raw TCP | Raw ACK packets, random seq/ack numbers |
| GRE Flood | `metagross()` | Raw GRE (proto 47) | GRE tunnel packets, max payload |
| DNS Flood | `salamence()` | UDP/DNS | Random queries (A/AAAA/MX/NS) with EDNS0 |

> SYN/ACK/GRE floods require `CAP_NET_RAW` or root for raw socket access.

### Layer 7 (Application)

| Method | Function | Technique |
|--------|----------|-----------|
| HTTP Flood | `alakazam()` / `alakazamProxy()` | POST requests, random UA/referer, 2024 workers |
| HTTPS/TLS Flood | `machamp()` / `machampProxy()` | TLS handshake + 10 requests per connection, raw HTTP over TLS |
| CF Bypass | `gyarados()` / `gyaradosProxy()` | Session management, cookie persistence, fake `__cf_bm` cookies |

### Concurrency

All attacks spawn `cozyBear` (default **2024**) goroutine workers.

### Proxy Support (L7 Only)

L7 methods support proxy rotation via `-pu <proxy_url>` flag:

```
!http target.com 443 60 -pu http://proxy-list.com/proxies.txt
```

- Bot fetches proxy list from URL directly
- Round-robin rotation via atomic counter (`persian()`)
- No validation — max speed (2s timeout, skip bad proxies)
- `meowstic()` creates per-proxy HTTP clients with aggressive timeouts

### Attack Control

- `raichu()` returns a stop channel, marks attack as running
- `pikachu()` closes the stop channel, all workers exit via `select`
- `!stop` command triggers `pikachu()`
- Each attack also respects `context.WithTimeout` for automatic expiry

---

## 11. SOCKS5 Proxy Pivoting

Full SOCKS5 proxy implementation for traffic tunneling through bots.

### Architecture

```
Operator → SOCKS5 Client → Bot (port X) → Target
```

| Component | Function | Description |
|-----------|----------|-------------|
| Start | `muddywater()` | Bind TCP listener on specified port, max 100 concurrent connections |
| Stop | `emotet()` | Close listener, mark inactive |
| Handler | `trickbot()` | SOCKS5 protocol: version negotiation → connect request → bidirectional relay |

### Supported SOCKS5 Features

- Address types: IPv4 (0x01), Domain (0x03), IPv6 (0x04)
- No authentication (method 0x00)
- CONNECT command (0x01)
- Bidirectional `io.Copy` relay with proper `CloseWrite` half-close

---

## 12. CNC Server Architecture

### Dual Listener Design

```
CNC Server
├── TLS Listener (0.0.0.0:443)     ← Bot connections
│   ├── validateTLSHandshake()
│   └── handleBotConnection()       ← Per-bot goroutine
│
└── Mode-dependent:
    ├── TUI Mode (default)           ← Bubble Tea local UI
    │   └── StartTUI()               ← Dashboard, bot list, attack builder
    │
    └── Split Mode (--split)         ← Plain TCP listener
        ├── Telnet negotiation
        ├── "spamtec" handshake
        └── handleRequest()          ← Per-user command loop
```

### Bot Connection Management

- `botConnections map[string]*BotConnection` — primary store (keyed by botID)
- `botConns []net.Conn` — legacy slice for backward compat
- `commandOrigin map[string]net.Conn` — routes bot responses to correct user
- All maps protected by `sync.RWMutex`

### TUI (Bubble Tea)

Views:

- **Dashboard**: Bot count, total RAM/CPU, uptime, menu navigation
- **Bot List**: Live table with ID, IP, arch, RAM, uptime; actions (shell, persist, kill)
- **Attack Builder**: Method selection, target/port/duration form, proxy URL, launch animation
- **Remote Shell**: Interactive single-bot shell with command history
- **Broadcast Shell**: Shell to all bots with arch/RAM/count filters
- **Socks Manager**: Start/stop SOCKS5 proxies on individual bots
- **Help**: Multi-section help guide

Toast notifications for connection/disconnection events and attack status.

---

## 13. User Permission Model (RBAC)

### Permission Levels (Low → High)

| Level | DDoS | Shell/SOCKS | Bot Targeting | Bot Management | Private/DB |
|-------|------|-------------|---------------|----------------|------------|
| Basic | ✅ | ❌ | ❌ | ❌ | ❌ |
| Pro | ✅ | ❌ | ✅ | ❌ | ❌ |
| Admin | ✅ | ✅ | ✅ | ✅ | ❌ |
| Owner | ✅ | ✅ | ✅ | ✅ | ✅ |

### User Storage (`users.json`)

```json
{
    "Username": "root",
    "Password": "randomPassword",
    "Expire": "3024-12-25T10:30:00.0-04:00",
    "Level": "Owner"
}
```

- First run auto-generates root user with random 12-char password
- Expiration date enforcement — expired users cannot log in
- 3 login attempts max before disconnect (brute force protection)

### Authentication Flow (Split Mode)

1. Client connects to admin port
2. Must send `spamtec` as first line (connection identifier)
3. Login banner rendered with ANSI art
4. Username/password prompt (password hidden with white-on-white text)
5. Up to 3 attempts, then lockout + disconnect

---

## 14. DNS Resolution Chain

The bot supports multiple C2 resolution methods for resilience. Handled by `dialga()`:

```
gothTits constant
    │
    ▼ venusaur() decode
    │
    ├── Is it IP:PORT format?
    │   └── YES → Use directly
    │
    ├── Is it a domain?
    │   │
    │   ├── Method 1: DoH TXT Record (palkia)
    │   │   Try: Cloudflare, Google, Quad9 DoH servers
    │   │   Look for: c2=IP:PORT, ip=IP:PORT, raw IP:PORT
    │   │   ✓ Encrypted DNS (bypasses local DNS monitoring)
    │   │
    │   ├── Method 2: UDP TXT Record (darkrai)
    │   │   Try: Cloudflare, Google, Quad9, OpenDNS (shuffled)
    │   │   Same TXT parsing as above
    │   │   ✓ Fallback if DoH blocked
    │   │
    │   ├── Method 3: A Record (rayquaza)
    │   │   Try: System resolver → DoH A record
    │   │   Append default port :443
    │   │   ✓ Simple domain → IP fallback
    │   │
    │   └── Method 4: Raw Value
    │       Return decoded string as-is (last resort)
```

### Supported TXT Record Formats

```
c2=192.168.1.1:443      ← Prefixed format
ip=192.168.1.1:443      ← Alternative prefix
192.168.1.1:443          ← Raw IP:PORT
192.168.1.1              ← Plain IP (appends :443)
```

---

## 15. Build Pipeline & Cross-Compilation

### `tools/build.sh`

Builds bot binaries for **14 Linux architectures**:

| Binary Name | Arch | GOARCH | GOARM |
|-------------|------|--------|-------|
| kworkerd0 | x86 32-bit | 386 | — |
| ethd0 | x86_64 | amd64 | — |
| mdsync1 | ARMv7 | arm | 7 |
| ksnapd0 | ARMv5 | arm | 5 |
| kswapd1 | ARMv6 | arm | 6 |
| ip6addrd | ARM64 | arm64 | — |
| deferwqd | MIPS | mips | — |
| devfreqd0 | MIPS LE | mipsle | — |
| kintegrity0 | MIPS64 | mips64 | — |
| biosd0 | MIPS64 LE | mips64le | — |
| kpsmoused0 | PPC64 | ppc64 | — |
| ttmswapd | PPC64 LE | ppc64le | — |
| vredisd0 | s390x | s390x | — |
| kvmirqd | RISC-V 64 | riscv64 | — |

Binary names are disguised as **kernel/system daemon processes** to blend with `ps` output.

### Build Flags

```bash
go build -trimpath -ldflags="-s -w -buildid=" -o <name> ./bot
```

| Flag | Purpose |
|------|---------|
| `-trimpath` | Remove local filesystem paths from binary |
| `-s` | Strip symbol table |
| `-w` | Strip DWARF debug info |
| `-buildid=` | Remove Go build ID |

### Post-Build Processing

1. **`strip --strip-all`** — Remove remaining symbols
2. **UPX compression** (`--best --lzma`) — Reduce binary size significantly
3. **`deUPX.py`** — Strip UPX signatures/magic bytes to evade UPX detection heuristics

---

## 16. Setup Automation

### `setup.py` — Interactive Setup Wizard

**Full Setup (Option 1):**

1. Configure debug mode (on/off)
2. Set C2 address (IP or domain) + admin port
3. Generate security tokens:
   - `magicCode` — 16-char random (letters, digits, symbols)
   - `protocolVersion` — Random format (e.g., `v3.8`, `proto42`, `r1.5-stable`)
   - `cryptSeed` — 8-char hex for encryption key derivation
4. Obfuscate C2 address (5-layer encoding) + verification
5. Generate TLS certificates (4096-bit RSA, self-signed) or use custom
6. Update source files via regex replacement:
   - `bot/main.go`: `gothTits`, `cryptSeed`, `magicCode`, `protocolVersion`, `debugMode`
   - `cnc/main.go`: `MAGIC_CODE`, `PROTOCOL_VERSION`, `USER_SERVER_PORT`
7. Build CNC server + bot binaries
8. Save configuration to `setup_config.txt`

**C2 URL Update (Option 2):**

- Reads existing config from source files
- Only updates C2 address (keeps magic code, protocol, certs)
- Re-obfuscates with existing `cryptSeed`
- Rebuilds bot binaries only

---

## 17. Naming Convention (Code Obfuscation)

All functions use APT group / Pokémon-themed names to make code harder to understand at a glance:

### Bot Functions — APT Groups

| Name | Real Purpose |
|------|-------------|
| `anonymousSudan` | C2 session handler |
| `gamaredon` | TLS connection establishment |
| `sidewinder` | Synchronous shell execution |
| `oceanLotus` | Detached/background execution |
| `machete` | Streaming shell execution |
| `blackEnergy` | Command dispatcher |
| `sandworm` | File append utility |
| `turla` | Random string generator |
| `kimsuky` | Random process name generator |
| `winnti` | Sandbox detection |
| `mustangPanda` | Bot ID generator |
| `hafnium` | Auth response generator |
| `carbanak` | Cron persistence |
| `dragonfly` | Full persistence suite |
| `fin7` | rc.local persistence |
| `lazarus` | Simple cron persistence |
| `muddywater` | SOCKS5 proxy start |
| `emotet` | SOCKS5 proxy stop |
| `trickbot` | SOCKS5 connection handler |

### Bot Functions — Pokémon (Attacks & Crypto)

| Name | Real Purpose |
|------|-------------|
| `charizard` | Key derivation (MD5) |
| `blastoise` | RC4 stream cipher |
| `venusaur` | Multi-layer C2 decoder |
| `pikachu` | Stop all attacks |
| `raichu` | Get attack stop channel |
| `snorlax` | UDP flood |
| `gengar` | TCP flood |
| `alakazam` | HTTP flood |
| `machamp` | HTTPS/TLS flood |
| `gyarados` | CF bypass flood |
| `dragonite` | SYN flood |
| `tyranitar` | ACK flood |
| `metagross` | GRE flood |
| `salamence` | DNS flood |
| `garchomp` | DNS query builder |
| `ditto` | Browser session struct |
| `zorua` / `zoruaWithProxy` | Session creator |
| `zoroark` | Cookie jar factory |
| `mimikyu` | Cookie jar implementation |
| `gastly` | CF challenge bypass |
| `eevee` | User-Agent list |
| `persian` | Proxy round-robin selector |
| `meowstic` | Proxy HTTP client creator |
| `lucario` | Target hostname resolver |
| `magikarp` | DoH response struct |

### DNS Resolution — Legendary Pokémon

| Name | Real Purpose |
|------|-------------|
| `dialga` | Main C2 resolver (orchestrator) |
| `palkia` | DoH TXT record lookup |
| `darkrai` | UDP TXT record lookup |
| `rayquaza` | A record fallback |
| `arceus` | Hostname validator |

### Key Derivation — Mythical Pokémon

| Name | Real Purpose |
|------|-------------|
| `mew` | Key byte 1 (0x55) |
| `mewtwo` | Key byte 2 (0x65) |
| `celebi` | Key byte 3 (0x55) |
| `jirachi` | Key byte 4 (0x25) |

### CNC Variables

| Name | Real Purpose |
|------|-------------|
| `fancyBear` | Reconnection delay (5s) |
| `cozyBear` | Worker count (2024) |
| `equationGroup` | Buffer size (256) |
| `lizardSquad` | DNS server list |
| `gothTits` | Obfuscated C2 address constant |

---

*Generated for VisionC2 — Author: Syn2Much*
