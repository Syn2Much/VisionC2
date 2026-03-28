# VisionC2 — Full Architecture Document
> Complete technical breakdown of CNC server, bot agent, encryption, protocol flow, and build pipeline.

---
## Table of Contents
### CNC Server Architecture
1. [CNC High-Level Architecture](#cnc-high-level-architecture)
2. [CNC Server Implementation](#cnc-server-implementation)
3. [CNC TLS Transport Layer](#cnc-tls-transport-layer)
4. [CNC Authentication Protocol](#cnc-authentication-protocol)
5. [CNC Command Dispatch & Routing](#cnc-command-dispatch--routing)
6. [CNC User Interface (TUI)](#cnc-user-interface-tui)
7. [CNC Web Panel (Tor)](#cnc-web-panel-tor)
8. [CNC User Permission Model (RBAC)](#cnc-user-permission-model-rbac)
9. [CNC Bot Connection Management](#cnc-bot-connection-management)

### Bot Agent Architecture
10. [Bot High-Level Architecture](#bot-high-level-architecture)
11. [Bot C2 Obfuscation & Encryption](#bot-c2-obfuscation--encryption)
12. [Bot TLS Transport Layer](#bot-tls-transport-layer)
13. [Bot Authentication Protocol](#bot-authentication-protocol)
14. [Bot Lifecycle & Connection Flow](#bot-lifecycle--connection-flow)
15. [Bot Attack Capabilities](#bot-attack-capabilities)
16. [Bot SOCKS5 Proxy & Relay Architecture](#bot-socks5-proxy--relay-architecture)
17. [Bot Persistence Mechanisms](#bot-persistence-mechanisms)
18. [Bot Anti-Analysis & Sandbox Detection](#bot-anti-analysis--sandbox-detection)
19. [Bot DNS Resolution Chain](#bot-dns-resolution-chain)

### Build & Infrastructure
20. [Project Structure](#project-structure)
21. [Build Pipeline & Cross-Compilation](#build-pipeline--cross-compilation)
22. [Setup Automation](#setup-automation)
23. [Naming Convention (Code Obfuscation)](#naming-convention-code-obfuscation)

---
## CNC Server Architecture

### CNC High-Level Architecture
```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                   OPERATOR                                   │
│  ┌──────────────┐   ┌──────────────────────┐   ┌─────────────────────────┐  │
│  │ Bubble Tea   │   │     Telnet CLI       │   │   Tor Web Panel         │  │
│  │   TUI        │   │   (--split mode)     │   │   (.onion WebSocket)    │  │
│  │ (local)      │   │                      │   │   (--web mode)          │  │
│  └──────┬───────┘   └─────────┬────────────┘   └────────────┬────────────┘  │
│         │                     │                              │               │
│         ▼                     ▼                              ▼               │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │                        CNC SERVER (Go)                               │   │
│  │  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌──────────────────────────┐   │   │
│  │  │ Bot Mgmt │ │ Auth/TLS │ │ RBAC   │ │ Embedded Tor Hidden Svc  │   │   │
│  │  │          │ │          │ │        │ │ (onion + WebSocket)      │   │   │
│  │  └──────────┘ └──────────┘ └────────┘ └──────────────────────────┘   │   │
│  │    TLS 1.2+ on port 443                                             │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                          │
└─────────────────────────────────┼──────────────────────────────────────────┘
                                  │ TLS 1.2/1.3 (port 443)
                    ┌─────────────┼───────────────┐
                    ▼             ▼               ▼
               ┌─────────┐   ┌─────────┐   ┌─────────┐
               │  Bot    │   │  Bot    │   │  Bot    │
               │ (ARM64) │   │ (amd64) │   │ (MIPS)  │
               └─────────┘   └─────────┘   └─────────┘
```

**Three Operating Modes:**
- **TUI Mode** (default): Local Bubble Tea terminal UI with dashboard, bot list, attack builder
- **Split Mode** (`--split`): Telnet-based CLI on configurable port for remote admin access
- **Web Mode** (`--web`): Tor hidden service serving a WebSocket-powered web dashboard over `.onion` -- no clearnet exposure

### CNC Server Implementation
**Multi-Listener Design:**
```
CNC Server
├── TLS Listener (0.0.0.0:443) ← Bot connections
│   ├── validateTLSHandshake()
│   └── handleBotConnection() ← Per-bot goroutine
│
└── Mode-dependent:
    ├── TUI Mode (default) ← Bubble Tea local UI
    │   └── StartTUI() ← Dashboard, bot list, attack builder
    │
    ├── Split Mode (--split) ← Plain TCP listener
    │   ├── Telnet negotiation
    │   ├── "spamtec" handshake
    │   └── handleRequest() ← Per-user command loop
    │
    └── Web Mode (--web) ← Embedded Tor hidden service
        ├── Tor bootstrap (tor.Start with embedded binary)
        ├── .onion address generation ← printed on startup
        ├── HTTP server on localhost (Tor-only, no clearnet)
        │   ├── Static assets (HTML/CSS/JS) via embed.FS
        │   └── WebSocket endpoint (/ws) ← operator shell + live events
        └── forwardBotOutputToWebShells() ← routes bot output to WS clients
```

### CNC TLS Transport Layer
| Setting | Value |
|---------|-------|
| Min Version | TLS 1.2 |
| Curves | X25519, P-256 |
| Server Cipher Preference | Enabled |
| Cipher Suites | ECDHE+AES-256-GCM, ECDHE+ChaCha20, ECDHE+AES-128-GCM |
| TLS 1.3 | Auto-accepted (all TLS 1.3 ciphers are secure) |
| Certificate | 4096-bit RSA (self-signed or custom) |

**Validation Flow (`validateTLSHandshake()`):**
1. Assert connection is `*tls.Conn`
2. 10-second deadline for handshake (anti-slowloris)
3. Reject TLS < 1.2
4. Whitelist cipher suite check (skip for TLS 1.3)
5. Hand off to `handleBotConnection()` for authentication

### CNC Authentication Protocol
Challenge-response using **MD5 + shared secret (syncToken)**.

```
     BOT                                  CNC
      │                                    │
      │◄──── AUTH_CHALLENGE:<random_32> ─────│ Step 1: CNC sends random challenge
      │                                    │
      │ response = Base64(MD5(             │
      │   challenge + syncToken + challenge│ Step 2: Bot computes response
      │ ))                                  │
      │                                    │
      │──── <response> ─────────────────────►│ Step 3: Bot sends response
      │                                    │
      │      CNC computes same             │ Step 4: CNC verifies
      │      hash and compares             │
      │                                    │
      │◄──── AUTH_SUCCESS ──────────────────│ Step 5: Success (or disconnect)
      │                                    │
      │──── REGISTER:v:botID:arch:ram:cpu:proc:uplink►│ Step 6: Bot sends registration
      │                                    │
      │      CNC checks buildTag           │ Step 7: Version verification
      │                                    │
      │◄═══════ Command Loop ═══════════════►│ Step 8: Enter command loop
```

- **Sync Token**: 16-char random string shared between bot and CNC (generated per campaign by `setup.py`)
- **Build Tag**: Random version string (e.g., `v3.8`) — must match exactly or connection is dropped

### CNC Command Dispatch & Routing
**Command Routing Methods:**
| Mode | Function | Description |
|------|----------|-------------|
| Broadcast | `sendToBots()` | Send to ALL authenticated bots |
| Filtered | `sendToFilteredBots()` | Send to bots matching arch/RAM/count filters |
| Targeted | `sendToBot()` | Send to specific bot by ID (full or prefix match) |
| TUI Target | `sendToSingleBot()` | Send to specific bot from TUI remote shell |

**Response Routing:**
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
    ├── Forward to user (forwardBotResponseToUser) if split mode
    │   └── Uses commandOrigin map to route to correct user
    └── Forward to Web Panel (forwardBotOutputToWebShells) if web mode
        └── Pushes output to all connected WebSocket clients via JSON message
```

### CNC User Interface (TUI)
**Bubble Tea Views:**
- **Dashboard**: Bot count, total RAM/CPU, uptime, menu navigation
- **Bot List**: Live table with ID, IP, arch, RAM, uptime; actions (shell, persist, kill)
- **Attack Builder**: Method selection, target/port/duration form, proxy URL, launch animation
- **Remote Shell**: Interactive single-bot shell with command history, scrollable output (500-line buffer, pgup/pgdown)
- **Broadcast Shell**: Shell to all bots with arch/RAM/count filters, shortcut tabs for post-exploitation
- **Socks Manager**: Three modes — quick start (relay), custom relay, direct listener
- **Help**: Multi-section help guide (9 sections)

**Features:**
- Toast notifications for connection/disconnection events
- Attack status updates
- Real-time bot list updates
- ANSI color support
- Confirmation prompts for dangerous commands (persist, reinstall, kill)

### CNC Web Panel (Tor)
The web panel provides a full-featured operator dashboard accessible exclusively via a Tor hidden service. No clearnet ports are opened -- the embedded Tor process generates a `.onion` address on startup and all traffic is routed through the Tor network.

**Transport:**
- Embedded Tor hidden service (`.onion`) -- no clearnet exposure
- WebSocket-powered remote shell for real-time bidirectional communication
- Static assets (HTML/CSS/JS) served via Go `embed.FS`

**Dashboard Tabs:**
| Tab | Key | Description |
|-----|-----|-------------|
| Bots | `1` | Live bot table with ID, IP, arch, RAM, CPU, uptime; double-click or right-click a row for bot management popup |
| Shell | `2` | WebSocket-powered remote shell with file browser, breadcrumb navigation, and post-exploit shortcut buttons |
| Attack | `3` | Attack launcher with method picker, target/port/duration form, and confirmation dialog |
| SOCKS5 | `4` | Live SOCKS5 dashboard with real-time SSE status updates for relay and direct proxy sessions |
| Tasks | `5` | Task manager for persistent auto-execute commands that run on bot connect |
| Users | `6` | User management panel (add, edit, remove, set permission level and expiry) |

**Bot Management Popup (double-click or right-click a bot row):**
- Open remote shell session
- Start / stop SOCKS5 proxy
- Assign bot to a group
- View bot info (arch, RAM, CPU, uptime, IP)
- Install full persistence (`!persist`)
- Kill bot (`!kill` -- self-destruct and cleanup)

**Activity Feed:**
- Real-time event stream showing bot join, leave, and command events
- Delivered to connected WebSocket clients as they occur

**Keyboard Shortcuts:**
| Key | Action |
|-----|--------|
| `1`-`6` | Switch between dashboard tabs |
| `/` | Focus search / filter bar |
| `?` | Show keyboard shortcut help overlay |

### CNC User Permission Model (RBAC)
**Permission Levels (Low → High):**
| Level | DDoS | Shell/SOCKS | Bot Targeting | Bot Management | Private/DB |
|-------|------|-------------|---------------|----------------|------------|
| Basic | yes | no | no | no | no |
| Pro   | yes | no | yes | no | no |
| Admin | yes | yes | yes | yes | no |
| Owner | yes | yes | yes | yes | yes |

**User Storage (`users.json`):**
```json
{
    "Username": "root",
    "Password": "randomPassword",
    "Expire": "3024-12-25T10:30:00.0-04:00",
    "Level": "Owner"
}
```

**Authentication Flow (Split Mode):**
1. Client connects to admin port
2. Must send `spamtec` as first line (connection identifier)
3. Login banner rendered with ANSI art
4. Username/password prompt (password hidden with white-on-white text)
5. Up to 3 attempts, then lockout + disconnect

### CNC Bot Connection Management
**Data Structures:**
- `botConnections map[string]*BotConnection` — primary store (keyed by botID)
- `commandOrigin map[string]net.Conn` — routes bot responses to correct user
- All maps protected by `sync.RWMutex`

**Keepalive & Cleanup:**
- `pingHandler()` sends PING every 60s to all bots
- Background goroutine runs every 60s, removes bots with no PONG in 5 minutes
- Dead bot cleanup with proper resource deallocation

---
## Bot Agent Architecture

### Bot High-Level Architecture
```
Bot Binary
    │
    ▼
┌─────────────────────────────────────────┐
│      Runtime Decryption                 │
│  - AES-128-CTR decrypt all sensitive    │
│    strings from config.go hex blobs     │
│  - Including rawServiceAddr →           │
│    serviceAddr (5-layer-encoded C2)     │
│  - 16-byte key from split XOR functions │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│         Startup Sequence                │
│  - Daemonization                        │
│  - Sandbox Detection (before any I/O)   │
│  - Single-instance enforcement (PID)    │
│  - Persistence Installation             │
│  - Metadata Caching                     │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│      C2 Resolution & Connection         │
│  - 6-layer C2 address decryption        │
│  - DNS Chain (DoH → UDP → A → Raw)     │
│  - TLS 1.3 Handshake                    │
│  - HMAC challenge/response auth         │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│        Command Loop & Execution         │
│  - Command Dispatch (blackEnergy)       │
│  - Attack Execution (10+ methods)       │
│  - SOCKS5 Proxy (direct + relay)        │
│  - Shell Command Execution              │
└─────────────────────────────────────────┘
```

### Bot C2 Obfuscation & Encryption
The C2 address is never stored in plaintext — or even in its intermediate 5-layer-encoded form — in the binary. It goes through a **6-layer encoding pipeline** at build time (via `setup.py`) and is decoded at runtime by the bot.

**Encoding Pipeline (`setup.py` → stored in binary):**
```
Plaintext C2 ("192.168.1.1:443")
        │
        ▼
┌─ Layer 1: MD5 Checksum ─────────────────────────┐
│ Append first 4 bytes of MD5(payload) for       │
│ integrity verification after decoding           │
└──────────────────────────────────────────────────┘
        │
        ▼
┌─ Layer 2: Byte Substitution ────────────────────┐
│ For each byte:                                  │
│   b ^= 0xAA                                     │
│   b = ROTATE_LEFT(b, 5)                         │
└──────────────────────────────────────────────────┘
        │
        ▼
┌─ Layer 3: RC4 Stream Cipher ────────────────────┐
│ Key = charizard(configSeed)                     │
│ Standard RC4 S-box initialization + keystream   │
└──────────────────────────────────────────────────┘
        │
        ▼
┌─ Layer 4: XOR with Rotating Key ────────────────┐
│ result[i] = data[i] ^ key[i % len(key)]         │
└──────────────────────────────────────────────────┘
        │
        ▼
┌─ Layer 5: Base64 Encode ────────────────────────┐
│ Standard Base64 encoding for safe string storage │
└──────────────────────────────────────────────────┘
        │
        ▼
┌─ Layer 6: AES-128-CTR Encryption ───────────────┐
│ aes_ctr_encrypt() using garuda key              │
│ (raw 16-byte XOR key, NOT the MD5-derived key)  │
│ Output: hex-encoded IV ‖ ciphertext             │
└──────────────────────────────────────────────────┘
        │
        ▼
Stored as `var rawServiceAddr, _ = hex.DecodeString("...")` in bot/config.go
```

**Decoding Pipeline (runtime):**

The bot decodes in two stages:

**Stage 1 — AES decrypt (`garuda()` in `opsec.go`, called by `initRuntimeConfig()`):**
1. **AES-128-CTR Decrypt** `rawServiceAddr` using raw 16-byte XOR key → recovers the base64-encoded 5-layer blob into `serviceAddr` variable

**Stage 2 — 5-layer decode (`venusaur()` in `opsec.go`, called by `dialga()`):**
1. **Base64 Decode** → raw bytes
2. **XOR with rotating key** → undo layer 4
3. **RC4 Decrypt** (symmetric, same function) → undo layer 3
4. **Reverse Byte Substitution** → `ROTATE_RIGHT(b, 3)` then `b ^= 0xAA`
5. **MD5 Checksum Verify** → validate integrity of decoded payload

This two-stage design means the AES outer layer is stripped uniformly alongside all other sensitive strings at startup, while the 5-layer inner decode only runs when the bot actually needs the C2 address.

**Key Derivation (`charizard()` in `opsec.go`):**
```
configSeed (8-char hex, e.g., "85fb7480")
    │
    ▼
MD5( seed + [16 XOR key bytes] + entropy )
    │
    │ 16 split key bytes (anti-static-analysis):
    │ mew()  mewtwo()  celebi()  jirachi()
    │ shaymin()  phione()  manaphy()  victini()
    │ keldeo()  meloetta()  genesect()  diancie()
    │ hoopa()  volcanion()  magearna()  marshadow()
    │
    │ Each function returns a single byte via XOR of two constants.
    │ XOR operands are randomised per build by setup.py.
    │
    │ Entropy bytes:
    │ [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
    │ XOR'd with position-based values: (len(seed) + i*17) & 0xFF
    │
    ▼
16-byte MD5 hash (used as RC4 key + XOR key for C2 address)
```

**Sensitive String & C2 Address Encryption (`garuda()` in `opsec.go`):**
```
Encrypted blob (hex-encoded IV‖ciphertext in config.go)
    │
    ▼
┌─ AES-128-CTR Decryption ──────────────────────┐
│ Key: raw 16 bytes from XOR byte functions     │
│ IV:  first 16 bytes of blob                   │
│ CT:  remaining bytes after IV                 │
│ Decrypt via AES-128-CTR stream cipher         │
└───────────────────────────────────────────────┘
    │
    ▼
Plaintext string (or null-separated slice)

initRuntimeConfig() decrypts ALL blobs at startup
before any other code references them, including:
  - rawServiceAddr → serviceAddr (5-layer-encoded C2 address)
  - rawSysMarkers, rawProcFilters, rawParentChecks
  - All persistence paths, service templates, daemon keys
  - Protocol strings, response messages, DNS servers
  - Process camouflage names, shell paths
```

**Crypto CLI Tool (`tools/crypto.go`):**
```
go run tools/crypto.go encrypt <string>            → hex blob
go run tools/crypto.go encrypt-slice <a> <b> ...   → hex blob (null-separated)
go run tools/crypto.go decrypt <hex>               → plaintext
go run tools/crypto.go decrypt-slice <hex>          → indexed list
go run tools/crypto.go generate                    → all blobs for config.go
go run tools/crypto.go verify                      → verify config.go blobs
go run tools/crypto.go resetconfig                 → reset key + blobs to zero-key state
```

### Bot TLS Transport Layer
| Setting | Value |
|---------|-------|
| InsecureSkipVerify | `true` (self-signed certs) |
| Min Version | TLS 1.2 |
| Dial Timeout | 30 seconds |
| Handshake Timeout | 30 seconds |
| Curve Preferences | X25519, P-256 |

**Function:** `gamaredon()` in `connection.go`

### Bot Authentication Protocol
**Response Generation (`hafnium()`):**
```go
response = base64.StdEncoding.EncodeToString(
    md5.Sum([]byte(challenge + syncToken + challenge))
)
```

**Bot Registration Format:**
```
REGISTER:<buildTag>:<botID>:<arch>:<RAM_MB>:<CPU_cores>:<procName>:<uplink_Mbps>
```

**Bot ID Generation (`mustangPanda()`):**
```
botID = MD5(hostname + ":" + MAC_address)[:8]
```
- Deterministic — same machine always generates same ID
- Survives reboots
- CNC deduplicates by closing old connection if same botID reconnects

### Bot Lifecycle & Connection Flow
**Startup Sequence (`main()` in `bot/main.go`):**
```
Bot Binary Executed
        │
        ▼
┌─ initRuntimeConfig() ─────────────┐
│ Decrypt all AES-128-CTR blobs     │
│ from config.go into runtime vars  │
│ Including: rawServiceAddr →       │
│   serviceAddr                     │
│ (must run before anything else)   │
└────────────────────────────────────┘
        │
        ▼
┌─ stuxnet() ─────────────────────┐
│ Full Unix daemonization         │
│ Fork, setsid, chdir /, umask 0  │
│ Redirect stdin/out/err → /dev/null│
│ Parent exits, child continues   │
│ (Skipped in debug mode)         │
└─────────────────────────────────┘
        │
        ▼
┌─ winnti() ──────────────────────┐
│ Sandbox/VM detection            │
│ 40+ analysis tool signatures    │
│ If detected → sleep 24-27h      │
│ then os.Exit(0)                 │
│ Runs BEFORE any /tmp writes     │
│ to avoid leaking IOCs to        │
│ sandboxes                       │
└─────────────────────────────────┘
        │ (safe)
        ▼
┌─ revilSingleInstance() ─────────┐
│ PID lock file                   │
│ Kill old instance if running    │
└─────────────────────────────────┘
        │
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
┌─ Pre-cache Metadata ────────────┐
│ cachedBotID = mustangPanda()    │
│ cachedArch = charmingKitten()   │
│ cachedRAM = revilMem()          │
│ cachedCPU = revilCPU()          │
│ cachedProc = revilProc()        │
│ cachedUplink = revilUplinkCached()│
│ (cached in pkg-level vars,      │
│ reused on every reconnect)      │
└─────────────────────────────────┘
        │
        ▼
┌─ dialga() ──────────────────────┐
│ Resolve C2 address              │
│ (See DNS Resolution Chain §18)  │
└─────────────────────────────────┘
        │
        ▼
┌─ Main Reconnection Loop ───────┐
│ forever:                       │
│   gamaredon() → TLS connect    │
│   anonymousSudan() → session   │
│   on disconnect:               │
│     sleep(retryFloor–retryCeil)│
│     (randomised 4–7s)          │
│     retry                      │
└─────────────────────────────────┘
```

**Session Handler (`anonymousSudan()`):**
```
Connected via TLS
    │
    ├── Receive AUTH_CHALLENGE
    ├── Send hafnium(challenge, syncToken) response
    ├── Receive AUTH_SUCCESS
    ├── Send REGISTER:buildTag:botID:arch:RAM:CPU:procName:uplink
    │
    └── Command Loop (180s read timeout):
        ├── PING → respond PONG
        └── <command> → blackEnergy() dispatcher
```

**Keepalive & Cleanup:**
- 180-second read timeout per command cycle
- Reconnection delay: randomised `retryFloor`–`retryCeil` (4–7 seconds)
- Automatic retry forever on disconnect

### Bot Attack Capabilities
**Layer 4 (Network) Attacks:**
| Method | Function | Protocol | Technique |
|--------|----------|----------|-----------|
| UDP Flood | `snorlax()` | UDP | 1024-byte payload spam via `net.Dial` |
| TCP Flood | `gengar()` | TCP | Connection + minimal HTTP data, table exhaustion |
| SYN Flood | `dragonite()` | Raw TCP | Raw SYN packets, random src ports, max payload |
| ACK Flood | `tyranitar()` | Raw TCP | Raw ACK packets, random seq/ack numbers |
| GRE Flood | `metagross()` | Raw GRE (proto 47) | GRE tunnel packets, max payload |
| DNS Flood | `salamence()` | UDP/DNS | Random queries (A/AAAA/MX/NS) with EDNS0 |

**Layer 7 (Application) Attacks:**
| Method | Function | Technique |
|--------|----------|-----------|
| HTTP Flood | `alakazam()` / `alakazamProxy()` | POST requests, random UA/referer, 4020 workers |
| HTTPS/TLS Flood | `machamp()` / `machampProxy()` | TLS handshake + 10 requests per connection |
| CF Bypass | `gyarados()` / `gyaradosProxy()` | Session management, cookie persistence, fake cookies |
| Rapid Reset | `giratina()` / `darkraiProxy()` | HTTP/2 CVE-2023-44487 — batched HEADERS+RST_STREAM |

**Concurrency & Control:**
- All attacks spawn `workerPool` (default **2024**) goroutine workers
- `raichu()` returns a stop channel, marks attack as running
- `pikachu()` closes the stop channel, all workers exit via `select`
- Each attack respects `context.WithTimeout` for automatic expiry

**Proxy Support (L7 Only):**
```
!http target.com 443 60 -pu http://proxy-list.com/proxies.txt
!rapidreset target.com 443 120 -pu http://proxy-list.com/proxies.txt
```
- Bot fetches proxy list from URL directly
- Round-robin rotation via atomic counter (`persian()`)
- No validation — max speed (2s timeout, skip bad proxies)
- `meowstic()` creates per-proxy HTTP clients with aggressive timeouts

### Bot SOCKS5 Proxy & Relay Architecture

VisionC2 supports two SOCKS5 modes: **backconnect relay** (primary) and **direct listener** (legacy).

**Backconnect Mode (Recommended):**
```
User ──[SOCKS5]──▶ Relay Server ◀──[backconnect TLS]── Bot ──▶ Target
                   (disposable VPS)                    (infected host)
```
- Bot connects **out** to the relay — never opens an inbound port
- Users connect to relay's SOCKS5 port with credentials
- C2 address is never exposed; relay is separate throwaway infrastructure
- If the relay gets burned, spin a new VPS without touching the C2

**Direct Mode:**
```
User ──[SOCKS5]──▶ Bot:1080 ──▶ Target
```
- Bot opens a SOCKS5 listener directly on a specified port
- Simpler, but exposes the bot's IP and requires an open port

**Components:**
| Component | Function | Description |
|-----------|----------|-------------|
| Backconnect start | `muddywater()` | Accepts relay list, connects out to relay via TLS |
| Direct start | `turmoil()` | Bind TCP listener on specified port, max 100 concurrent |
| Relay control loop | `cozyBear()` | Auto-reconnect, multi-relay rotation, exponential backoff |
| Data channel | `fancyBear()` | Per-session data connection to relay |
| Stop | `emotet()` | Close listener/relay connection, mark inactive |
| SOCKS5 handler | `trickbot()` | Protocol: version negotiation → connect → bidirectional relay |

**Multi-Relay Failover:**
1. Bots shuffle relay list on startup for load distribution
2. On disconnect, rotate to next relay (0.5–2s jitter)
3. After full rotation fails, exponential backoff: 5s → 10s → 20s → 40s → 60s (cap)
4. Auto-reconnect indefinitely until `!stopsocks` is issued

**Relay Protocol:**
```
Bot → Relay:   RELAY_AUTH:<key>:<botID>\n     (authenticate)
Relay → Bot:   RELAY_OK\n                     (accepted)
Relay → Bot:   RELAY_NEW:<sessionID>\n        (new SOCKS5 client waiting)
Bot → Relay:   RELAY_DATA:<sessionID>\n       (open data channel)
Bot → Relay:   RELAY_PING\n                   (keepalive, every 60s)
```

**Supported SOCKS5 Features:**
- Address types: IPv4 (0x01), Domain (0x03), IPv6 (0x04)
- Username/password authentication (method 0x02, RFC 1929) when `proxyUser`/`proxyPass` are set
- Falls back to no authentication (method 0x00) when credentials are empty
- Credentials updatable at runtime via `!socksauth <user> <pass>`
- CONNECT command (0x01)
- Bidirectional `io.Copy` relay with proper `CloseWrite` half-close

> Full relay deployment guide: [`PROXY.md`](PROXY.md)

### Bot Persistence Mechanisms
**Automatic Startup Persistence (runs during boot sequence):**
| Method | Function | Mechanism |
|--------|----------|-----------|
| rc.local | `fin7()` | Appends `<exe_path> # <random_name>` to `/etc/rc.local` |
| Cron | `lazarus()` | Installs `* * * * * pgrep -x <name> \|\| <exe> &` |

**Full Persistence (`!persist` command via `dragonfly()`):**
Sets up comprehensive persistence (all paths/names from encrypted config):
1. **Hidden Directory**: Creates storeDir (e.g., `/var/lib/.httpd_cache/`)
2. **Persistence Script**: Writes scriptLabel (e.g., `.httpd_check.sh`) that downloads and runs the bot
3. **Systemd Service**: Creates unitName (e.g., `httpd-cache.service`) with `Restart=always`
4. **Cron Backup**: Installs cron job via `carbanak()` as fallback

**Self-Destruct (`!kill` command via `nukeAndExit()`):**
1. Disables and removes systemd service
2. Strips persistence entries from crontab
3. Cleans rc.local
4. Removes hidden directory
5. Deletes lock file
6. Removes own binary
7. Exits

**Debug Mode:**
When `verboseLog = true`, persistence functions **only log** what they would do — no actual file writes or system modifications. This prevents accidental persistence during development.

### Bot Anti-Analysis & Sandbox Detection
**`winnti()` — Sandbox Detection (`opsec.go`):**
Three detection methods, checked at startup **before any file writes** (lock file, cache, etc.) to prevent leaking IOCs to sandbox analysis. All indicator lists are AES-128-CTR encrypted in `config.go` and decrypted at runtime by `initRuntimeConfig()` — no plaintext signatures in the binary.

**1. VM Process Detection** — Scans `/proc/*/cmdline` for:
```
vmware, vbox, virtualbox, qemu, firejail, bubblewrap,
gvisor, kata, cuckoo, joesandbox, cape, any.run, hybrid-analysis
```

**2. Analysis Tool Detection** — Checks 40+ tool paths including:
```
strace, ltrace, gdb, lldb, radare2, rizin, ghidra, ida, ida64,
wireshark, tshark, tcpdump, yara, ssdeep, binwalk, sysdig, bpftrace,
auditd, rkhunter, chkrootkit, clamdscan, volatility, ...
```

**3. Debugger Parent Check** — Reads `/proc/<ppid>/cmdline` for:
```
gdb, lldb, strace, ltrace, radare2, r2, rizin, rr, valgrind,
perf, ida, ida64, ghidra, sysdig, bpftrace, frida, frida-server
```

**Detection Response:**
If any check triggers → log the specific detection reason (in debug mode) → sleep **24–27 hours** (randomized jitter to outlast sandbox analysis windows), then `os.Exit(0)`.

### Bot DNS Resolution Chain
**`dialga()` — Main C2 Resolver:**
```
serviceAddr (decrypted from rawServiceAddr at startup)
    │
    ▼ venusaur() decode (5-layer inner decode)
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

**Supported TXT Record Formats:**
```
c2=192.168.1.1:443     ← Prefixed format
ip=192.168.1.1:443     ← Alternative prefix
192.168.1.1:443        ← Raw IP:PORT
192.168.1.1            ← Plain IP (appends :443)
```

---
## Build & Infrastructure

### Project Structure
```
VisionC2/
├── go.mod                 # Go module (Vision), Go 1.24
├── go.sum
├── setup.py              # Interactive setup wizard (Python 3)
├── server                # Compiled CNC binary
├── relay_server          # Compiled relay binary
├── bot/                  # Bot agent source
│   ├── main.go           # Entry point, shell exec, main loop
│   ├── config.go         # All config constants, encrypted blobs, initRuntimeConfig()
│   ├── connection.go     # TLS connection, DNS resolution, auth, C2 handler
│   ├── attacks.go        # L4/L7 DDoS attack methods + proxy support
│   ├── opsec.go          # Encryption (AES-128-CTR, RC4, key derivation), sandbox detection, bot ID, daemonization
│   ├── persist.go        # Persistence mechanisms (cron, systemd, rc.local) + nukeAndExit()
│   └── socks.go          # SOCKS5 proxy: direct listener + backconnect relay with multi-endpoint failover
├── cnc/                  # CNC server source
│   ├── main.go           # Server entry, TLS listener, user listener
│   ├── connection.go     # TLS config, bot auth handler, bot management
│   ├── cmd.go            # Command dispatch, user session handler, help menus
│   ├── ui.go             # Bubble Tea TUI (dashboard, bot list, attack builder, socks manager)
│   ├── miscellaneous.go  # User auth, permissions (RBAC), utilities
│   ├── users.json        # User credential database (0600 perms)
│   └── certificates/     # TLS certs (server.crt, server.key)
├── relay/                # Relay server source
│   └── main.go           # Backconnect SOCKS5 relay with TLS, stats, multi-bot support
├── tools/
│   ├── build.sh          # Cross-compilation for 14 architectures
│   ├── crypto.go         # Unified AES-128-CTR encrypt/decrypt/verify/resetconfig CLI tool
│   ├── cleanup.sh        # Remove bot persistence artifacts from a Linux machine
│   ├── fix_botkill.sh    # Server tuning (fd limits, TCP buffers, port 443)
│   └── upx              # m30w packer (custom UPX fork, zero fingerprint)
├── bins/                 # Compiled bot binaries (output)
└── Docs/
    ├── ARCHITECTURE.md   # This document
    ├── COMMANDS.md       # TUI hotkey reference
    ├── SETUP.md          # Setup guide
    ├── PROXY.md          # SOCKS5 relay deployment guide
    └── CHANGELOG.md      # Version history
```

### Build Pipeline & Cross-Compilation
**`tools/build.sh` — Builds for 14 Linux Architectures:**
| Binary Name | Arch | GOARCH | GOARM |
|-------------|------|--------|-------|
| ksoftirqd0 | x86 32-bit | 386 | — |
| kworker_u8 | x86_64 | amd64 | — |
| jbd2_sda1d | ARMv7 | arm | 7 |
| bioset0 | ARMv5 | arm | 5 |
| kblockd0 | ARMv6 | arm | 6 |
| rcuop_0 | ARM64 | arm64 | — |
| kswapd0 | MIPS | mips | — |
| ecryptfsd | MIPS LE | mipsle | — |
| xfsaild_sda | MIPS64 | mips64 | — |
| scsi_tmf_0 | MIPS64 LE | mips64le | — |
| devfreq_wq | PPC64 | ppc64 | — |
| zswap_shrinkd | PPC64 LE | ppc64le | — |
| edac_polld | s390x | s390x | — |
| cfg80211d | RISC-V 64 | riscv64 | — |

All binary names mimic legitimate Linux kernel thread and daemon process names to blend in on infected hosts.

**Build Flags:**
```bash
go build -trimpath -ldflags="-s -w -buildid=" -o <name> ./bot
```
| Flag | Purpose |
|------|---------|
| `-trimpath` | Remove local filesystem paths from binary |
| `-s` | Strip symbol table |
| `-w` | Strip DWARF debug info |
| `-buildid=` | Remove Go build ID |

**Post-Build Processing:**
1. **`strip --strip-all`** — Remove remaining symbols
2. **m30w packer** (`--best --lzma`) via bundled `tools/upx` — Compress with zero UPX fingerprint

### Setup Automation
**`setup.py` — Interactive Setup Wizard:**

**Full Setup (Option 1):**
1. Configure debug mode (on/off)
2. Set C2 address (IP or domain) + admin port
3. Generate security tokens:
   - `syncToken` — 16-char random (letters, digits, symbols)
   - `buildTag` — Random format (e.g., `v3.8`, `proto42`, `r1.5-stable`)
   - `configSeed` — 8-char hex for encryption key derivation
4. Configure relay endpoints (comma-separated `host:port` list, optional)
5. Configure SOCKS5 proxy credentials (default: `vision:vision`)
6. Obfuscate C2 address (5-layer encoding) + AES-128-CTR outer layer (6 total) + verification
7. Generate fresh random 16-byte AES key, patch XOR byte functions in `opsec.go`
8. Encrypt all sensitive string blobs and patch `config.go`
9. Generate TLS certificates (4096-bit RSA, self-signed) or use custom
10. Build CNC server + bot binaries + relay server
11. Save configuration to `setup_config.txt`

**C2 URL Update (Option 2):**
- Reads existing config from source files
- Only updates C2 address (keeps sync token, build tag, certs)
- Re-obfuscates with existing `configSeed`
- Rebuilds bot binaries + relay server

**Relay Endpoints Update (Option 3):**
- Shows current relay endpoints (decrypted from config)
- Update relay endpoint list (comma-separated)
- Update default SOCKS5 proxy credentials
- Re-encrypts config blobs with fresh AES key
- Rebuilds relay server + bot binaries

### Naming Convention (Code Obfuscation)
All functions use APT group / Pokemon-themed names to make code harder to understand at a glance.

**Bot Functions — APT Groups:**
| Name | Real Purpose |
|------|-------------|
| `anonymousSudan` | C2 session handler |
| `gamaredon` | TLS connection establishment |
| `sidewinder` | Synchronous shell execution |
| `oceanLotus` | Detached/background execution |
| `blackEnergy` | Command dispatcher |
| `winnti` | Sandbox detection |
| `mustangPanda` | Bot ID generator |
| `dragonfly` | Full persistence suite |
| `nukeAndExit` | Self-destruct + cleanup |
| `muddywater` | SOCKS5 backconnect start |
| `turmoil` | SOCKS5 direct listener start |
| `cozyBear` | Relay control loop |
| `fancyBear` | Per-session relay data channel |
| `emotet` | SOCKS5 shutdown |
| `trickbot` | SOCKS5 protocol handler |
| `stuxnet` | Unix daemonization |
| `revilSingleInstance` | PID-based singleton |
| `fin7` | rc.local persistence |
| `lazarus` | Cron persistence |
| `carbanak` | Cron persistence (script-based) |

**Bot Functions — Pokemon (Attacks):**
| Name | Real Purpose |
|------|-------------|
| `pikachu` | Stop all attacks |
| `raichu` | Get/set attack stop channel |
| `snorlax` | UDP flood |
| `gengar` | DNS flood |
| `dragonite` | SYN flood |
| `tyranitar` | ACK flood |
| `metagross` | GRE flood |
| `salamence` | TCP flood |
| `alakazam` | HTTP flood |
| `machamp` | HTTPS/TLS flood |
| `gyarados` | CF bypass flood |
| `giratina` | HTTP/2 Rapid Reset (CVE-2023-44487) |

**DNS Resolution — Legendary Pokemon:**
| Name | Real Purpose |
|------|-------------|
| `dialga` | Main C2 resolver (orchestrator) |
| `palkia` | DoH TXT record lookup |
| `darkrai` | UDP TXT record lookup |
| `rayquaza` | A record fallback |

**Key Derivation — Mythical Pokemon (16 bytes):**
| Name | Real Purpose |
|------|-------------|
| `mew` through `marshadow` | Key bytes 1–16 (XOR-obfuscated, randomised per build) |

**Crypto Functions — Pokemon:**
| Name | Real Purpose |
|------|-------------|
| `charizard` | Key derivation (MD5, for C2 address obfuscation) |
| `venusaur` | Multi-layer C2 address decoder |
| `blastoise` | RC4 stream cipher |
| `garuda` | AES-128-CTR decrypt (sensitive strings + C2 outer layer) |

**Config Variables (neutralised in v2.4.4):**
| Name | Real Purpose |
|------|-------------|
| `serviceAddr` | C2 address (AES-decrypted at runtime from `rawServiceAddr`) |
| `rawServiceAddr` | AES-128-CTR encrypted 6-layer C2 blob |
| `syncToken` | Shared auth secret (16-char random) |
| `buildTag` | Protocol version string (must match CNC) |
| `configSeed` | 8-char hex seed for key derivation |
| `verboseLog` | Debug mode flag |
| `workerPool` | Attack worker count (2024) |
| `bufferCap` | Buffer size (256) |
| `retryFloor` / `retryCeil` | Reconnection delay range (4–7s) |
| `proxyUser` / `proxyPass` | SOCKS5 proxy credentials |
| `maxSessions` | Max concurrent SOCKS5 connections |

---

*Generated for VisionC2 — Author: Syn2Much*
