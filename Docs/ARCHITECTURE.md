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
7. [CNC User Permission Model (RBAC)](#cnc-user-permission-model-rbac)
8. [CNC Bot Connection Management](#cnc-bot-connection-management)

### Bot Agent Architecture
9. [Bot High-Level Architecture](#bot-high-level-architecture)
10. [Bot C2 Obfuscation & Encryption](#bot-c2-obfuscation--encryption)
11. [Bot TLS Transport Layer](#bot-tls-transport-layer)
12. [Bot Authentication Protocol](#bot-authentication-protocol)
13. [Bot Lifecycle & Connection Flow](#bot-lifecycle--connection-flow)
14. [Bot Attack Capabilities](#bot-attack-capabilities)
15. [Bot SOCKS5 Proxy Pivoting](#bot-socks5-proxy-pivoting)
16. [Bot Persistence Mechanisms](#bot-persistence-mechanisms)
17. [Bot Anti-Analysis & Sandbox Detection](#bot-anti-analysis--sandbox-detection)
18. [Bot DNS Resolution Chain](#bot-dns-resolution-chain)

### Build & Infrastructure
19. [Project Structure](#project-structure)
20. [Build Pipeline & Cross-Compilation](#build-pipeline--cross-compilation)
21. [Setup Automation](#setup-automation)
22. [Naming Convention (Code Obfuscation)](#naming-convention-code-obfuscation)

---
## CNC Server Architecture

### CNC High-Level Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                          OPERATOR                           │
│  ┌──────────────┐         ┌──────────────────────┐         │
│  │ Bubble Tea   │         │     Telnet CLI       │         │
│  │   TUI        │   OR    │   (--split mode)     │         │
│  │ (local)      │         │                      │         │
│  └──────┬───────┘         └─────────┬────────────┘         │
│         │                           │                      │
│         ▼                           ▼                      │
│  ┌──────────────────────────────────────────┐              │
│  │          CNC SERVER (Go)                 │              │
│  │  ┌──────────┐ ┌──────────┐ ┌────────┐   │              │
│  │  │ Bot Mgmt │ │ Auth/TLS │ │ RBAC   │   │              │
│  │  │          │ │          │ │        │   │              │
│  │  └──────────┘ └──────────┘ └────────┘   │              │
│  │    TLS 1.2+ on port 443                 │              │
│  └──────────────────┬───────────────────────┘              │
│                     │                                      │
└─────────────────────┼──────────────────────────────────────┘
                      │ TLS 1.2/1.3 (port 443)
        ┌─────────────┼───────────────┐
        ▼             ▼               ▼
   ┌─────────┐   ┌─────────┐   ┌─────────┐
   │  Bot    │   │  Bot    │   │  Bot    │
   │ (ARM64) │   │ (amd64) │   │ (MIPS)  │
   └─────────┘   └─────────┘   └─────────┘
```

**Two Operating Modes:**
- **TUI Mode** (default): Local Bubble Tea terminal UI with dashboard, bot list, attack builder
- **Split Mode** (`--split`): Telnet-based CLI on configurable port for remote admin access

### CNC Server Implementation
**Dual Listener Design:**
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
    └── Split Mode (--split) ← Plain TCP listener
        ├── Telnet negotiation
        ├── "spamtec" handshake
        └── handleRequest() ← Per-user command loop
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
Challenge-response using **MD5 + shared secret (magicCode)**.

```
     BOT                                  CNC
      │                                    │
      │◄──── AUTH_CHALLENGE:<random_32> ─────│ Step 1: CNC sends random challenge
      │                                    │
      │ response = Base64(MD5(             │
      │   challenge + magicCode + challenge│ Step 2: Bot computes response
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
      │      CNC checks PROTOCOL_VERSION   │ Step 7: Version verification
      │                                    │
      │◄═══════ Command Loop ═══════════════►│ Step 8: Enter command loop
```

- **Magic Code**: 16-char random string shared between bot and CNC (generated per campaign by `setup.py`)
- **Protocol Version**: Random version string (e.g., `v3.8`) — must match exactly or connection is dropped

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
    └── Forward to user (forwardBotResponseToUser) if split mode
        └── Uses commandOrigin map to route to correct user
```

### CNC User Interface (TUI)
**Bubble Tea Views:**
- **Dashboard**: Bot count, total RAM/CPU, uptime, menu navigation
- **Bot List**: Live table with ID, IP, arch, RAM, uptime; actions (shell, persist, kill)
- **Attack Builder**: Method selection, target/port/duration form, proxy URL, launch animation
- **Remote Shell**: Interactive single-bot shell with command history
- **Broadcast Shell**: Shell to all bots with arch/RAM/count filters
- **Socks Manager**: Start/stop SOCKS5 proxies on individual bots
- **Help**: Multi-section help guide

**Features:**
- Toast notifications for connection/disconnection events
- Attack status updates
- Real-time bot list updates
- ANSI color support

### CNC User Permission Model (RBAC)
**Permission Levels (Low → High):**
| Level | DDoS | Shell/SOCKS | Bot Targeting | Bot Management | Private/DB |
|-------|------|-------------|---------------|----------------|------------|
| Basic | ✅ | ❌ | ❌ | ❌ | ❌ |
| Pro   | ✅ | ❌ | ✅ | ❌ | ❌ |
| Admin | ✅ | ✅ | ✅ | ✅ | ❌ |
| Owner | ✅ | ✅ | ✅ | ✅ | ✅ |

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
- `botConns []net.Conn` — legacy slice for backward compatibility
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
│  - AES-128-CTR decrypt C2 address      │
│    (encGothTits → gothTits)             │
│  - AES-128-CTR decrypt all sensitive    │
│    strings from config.go hex blobs     │
│  - 16-byte key from split XOR functions │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│         Startup Sequence                │
│  - Daemonization                        │
│  - Single-instance enforcement (PID)    │
│  - Sandbox Detection                    │
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
│  - SOCKS5 Proxy Server                  │
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
│ Key = charizard(cryptSeed)                      │
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
Stored as `var encGothTits, _ = hex.DecodeString("...")` in bot/config.go
```

**Decoding Pipeline (runtime):**

The bot decodes in two stages:

**Stage 1 — AES decrypt (`garuda()` in `opsec.go`, called by `initSensitiveStrings()`):**
1. **AES-128-CTR Decrypt** `encGothTits` using raw 16-byte XOR key → recovers the base64-encoded 5-layer blob into `gothTits` variable

**Stage 2 — 5-layer decode (`venusaur()` in `opsec.go`, called by `dialga()`):**
1. **Base64 Decode** → raw bytes
2. **XOR with rotating key** → undo layer 4
3. **RC4 Decrypt** (symmetric, same function) → undo layer 3
4. **Reverse Byte Substitution** → `ROTATE_RIGHT(b, 3)` then `b ^= 0xAA`
5. **MD5 Checksum Verify** → validate integrity of decoded payload

This two-stage design means the AES outer layer is stripped uniformly alongside all other sensitive strings at startup, while the 5-layer inner decode only runs when the bot actually needs the C2 address.

**Key Derivation (`charizard()` in `opsec.go`):**
```
cryptSeed (8-char hex, e.g., "85fb7480")
    │
    ▼
MD5( seed + [16 XOR key bytes] + entropy )
    │
    │ 16 split key bytes (anti-static-analysis):
    │ mew()=0xCC^0xA6  mewtwo()=0xC3^0x91  celebi()=0x79^0xC0  jirachi()=0x4F^0xAA
    │ shaymin()=0x51^0x80  phione()=0x75^0xD1  manaphy()=0x4B^0x7C  victini()=0x87^0x86
    │ keldeo()=0xFC^0x7C  meloetta()=0xD2^0x54  genesect()=0xE9^0xEC  diancie()=0x77^0xF1
    │ hoopa()=0x3B^0x4C  volcanion()=0x3C^0x9D  magearna()=0x6C^0x3C  marshadow()=0x97^0x33
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

initSensitiveStrings() decrypts ALL blobs at startup
before any other code references them, including:
  - encGothTits → gothTits (5-layer-encoded C2 address)
  - encVmIndicators, encAnalysisTools, encParentDebuggers
  - All persistence paths, service templates, daemon keys
```

**Crypto CLI Tool (`tools/crypto.go`):**
```
go run tools/crypto.go encrypt <string>            → hex blob
go run tools/crypto.go encrypt-slice <a> <b> ...   → hex blob (null-separated)
go run tools/crypto.go decrypt <hex>               → plaintext
go run tools/crypto.go decrypt-slice <hex>          → indexed list
go run tools/crypto.go generate                    → all blobs for config.go
go run tools/crypto.go verify                      → verify config.go blobs
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
    md5.Sum([]byte(challenge + magicCode + challenge))
)
```

**Bot Registration Format:**
```
REGISTER:<version>:<botID>:<arch>:<RAM_MB>:<CPU_cores>:<procName>:<uplink_Mbps>
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
┌─ initSensitiveStrings() ────────┐
│ Decrypt all AES-128-CTR blobs   │
│ from config.go into runtime vars│
│ Including: encGothTits → gothTits│
│ (must run before anything else) │
└─────────────────────────────────┘
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
┌─ revilSingleInstance() ─────────┐
│ PID lock file (/tmp/.net_lock)  │
│ Kill old instance if running    │
└─────────────────────────────────┘
        │
        ▼
┌─ winnti() ──────────────────────┐
│ Sandbox/VM detection            │
│ 30+ analysis tool signatures    │
│ If detected → sleep 24-27h      │
│ then os.Exit(0)                 │
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
│     sleep(fancyBear = 5s)      │
│     retry                      │
└─────────────────────────────────┘
```

**Session Handler (`anonymousSudan()`):**
```
Connected via TLS
    │
    ├── Receive AUTH_CHALLENGE
    ├── Send hafnium(challenge, magicCode) response
    ├── Receive AUTH_SUCCESS
    ├── Send REGISTER:version:botID:arch:RAM:CPU:procName:uplink
    │
    └── Command Loop (180s read timeout):
        ├── PING → respond PONG
        └── <command> → blackEnergy() dispatcher
```

**Keepalive & Cleanup:**
- 180-second read timeout per command cycle
- Reconnection delay: `fancyBear` (5 seconds)
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
| Rapid Reset | `arkrai()` / `darkraiProxy()` / `giratina()` | HTTP/2 CVE-2023-44487 — batched HEADERS+RST_STREAM |

**Concurrency & Control:**
- All attacks spawn `cozyBear` (default **2024**) goroutine workers
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

### Bot SOCKS5 Proxy Pivoting
**Full SOCKS5 Implementation for Traffic Tunneling:**
```
Operator → SOCKS5 Client → Bot (port X) → Target
```

**Components:**
| Component | Function | Description |
|-----------|----------|-------------|
| Start | `muddywater()` | Bind TCP listener on specified port, max 100 concurrent connections |
| Stop | `emotet()` | Close listener, mark inactive |
| Handler | `trickbot()` | SOCKS5 protocol: version negotiation → connect request → bidirectional relay |

**Supported SOCKS5 Features:**
- Address types: IPv4 (0x01), Domain (0x03), IPv6 (0x04)
- Username/password authentication (method 0x02, RFC 1929) when `socksUsername`/`socksPassword` are set in `config.go`
- Falls back to no authentication (method 0x00) when credentials are empty
- Credentials updatable at runtime via `!socksauth <user> <pass>`
- CONNECT command (0x01)
- Bidirectional `io.Copy` relay with proper `CloseWrite` half-close

### Bot Persistence Mechanisms
**Automatic Startup Persistence:**
| Method | Function | Mechanism |
|--------|----------|-----------|
| rc.local | `fin7()` | Appends `<exe_path> # <random_name>` to `/etc/rc.local` |
| Cron | `lazarus()` | Installs `* * * * * pgrep -x <name> \|\| <exe> &` |

**Full Persistence (`!persist` command via `dragonfly()`):**
Sets up comprehensive persistence (all paths/names from encrypted config):
1. **Hidden Directory**: Creates `/var/lib/.httpd_cache/`
2. **Persistence Script**: Writes `.httpd_check.sh` that downloads and runs the bot
3. **Systemd Service**: Creates `httpd-cache.service` with `Restart=always`
4. **Cron Backup**: Installs cron job via `carbanak()` as fallback

**File Structure:**
```
/var/lib/.httpd_cache/
├── .httpd_check.sh  # Download + execute script
└── .httpd_worker    # Bot binary (disguised name)
/etc/systemd/system/
└── httpd-cache.service # Auto-restart systemd unit
```

**Cleanup:** `tools/cleanup.sh` removes all persistence artifacts (run as root).

**Debug Mode:**
When `debugMode = true`, persistence functions **only log** what they would do — no actual file writes or system modifications. This prevents accidental persistence during development.

### Bot Anti-Analysis & Sandbox Detection
**`winnti()` — Sandbox Detection (`opsec.go`):**
Three detection methods, checked at startup. All indicator lists are AES-128-CTR encrypted in `config.go` and decrypted at runtime by `initSensitiveStrings()` — no plaintext signatures in the binary.

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
If any check triggers → sleep **24–27 hours** (randomized jitter to outlast sandbox analysis windows), then `os.Exit(0)`.

### Bot DNS Resolution Chain
**`dialga()` — Main C2 Resolver:**
```
gothTits (decrypted from encGothTits at startup)
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
├── bot/                  # Bot agent source
│   ├── main.go           # Entry point, shell exec, main loop
│   ├── config.go         # All tuneable constants, encrypted sensitive strings, initSensitiveStrings()
│   ├── connection.go     # TLS connection, DNS resolution, auth, C2 handler
│   ├── attacks.go        # L4/L7 DDoS attack methods + proxy support
│   ├── opsec.go          # Encryption (AES-128-CTR, RC4, key derivation), sandbox detection, bot ID, daemonization
│   ├── persist.go        # Persistence mechanisms (cron, systemd, rc.local)
│   └── socks.go          # SOCKS5 proxy server with username/password auth (RFC 1929)
├── cnc/                  # CNC server source
│   ├── main.go           # Server entry, TLS listener, user listener
│   ├── connection.go     # TLS config, bot auth handler, bot management
│   ├── cmd.go            # Command dispatch, user session handler, help menus
│   ├── ui.go             # Bubble Tea TUI (dashboard, bot list, attack builder)
│   ├── miscellaneous.go  # User auth, permissions (RBAC), utilities
│   ├── users.json        # User credential database
│   └── certificates/     # TLS certs (server.crt, server.key)
├── tools/
│   ├── build.sh          # Cross-compilation for 14 architectures
│   ├── crypto.go         # Unified AES-128-CTR encrypt/decrypt/verify CLI tool
│   ├── cleanup.sh        # Remove bot persistence artifacts from a Linux machine
│   └── deUPX.py          # UPX signature stripper
├── bins/                 # Compiled bot binaries (output)
└── Docs/
    ├── ARCHITECTURE.md   # This document
    ├── COMMANDS.md       # TUI hotkey reference
    ├── USAGE.md          # Usage guide
    ├── CHANGELOG.md      # Version history
    └── LICENSE
```

### Build Pipeline & Cross-Compilation
**`tools/build.sh` — Builds for 14 Linux Architectures:**
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
2. **UPX compression** (`--best --lzma`) — Reduce binary size significantly
3. **`deUPX.py`** — Strip UPX signatures/magic bytes to evade UPX detection heuristics

### Setup Automation
**`setup.py` — Interactive Setup Wizard:**

**Full Setup (Option 1):**
1. Configure debug mode (on/off)
2. Set C2 address (IP or domain) + admin port
3. Generate security tokens:
   - `magicCode` — 16-char random (letters, digits, symbols)
   - `protocolVersion` — Random format (e.g., `v3.8`, `proto42`, `r1.5-stable`)
   - `cryptSeed` — 8-char hex for encryption key derivation
4. Obfuscate C2 address (5-layer encoding) + AES-128-CTR outer layer (6 total) + verification
5. Generate TLS certificates (4096-bit RSA, self-signed) or use custom
6. Update source files via regex replacement:
   - `bot/config.go`: `encGothTits`, `cryptSeed`, `magicCode`, `protocolVersion`, `debugMode`
   - `cnc/main.go`: `MAGIC_CODE`, `PROTOCOL_VERSION`, `USER_SERVER_PORT`
7. Build CNC server + bot binaries
8. Save configuration to `setup_config.txt`

**C2 URL Update (Option 2):**
- Reads existing config from source files
- Only updates C2 address (keeps magic code, protocol, certs)
- Re-obfuscates with existing `cryptSeed`
- Rebuilds bot binaries only

### Naming Convention (Code Obfuscation)
All functions use APT group / Pokémon-themed names to make code harder to understand at a glance.

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
| `muddywater` | SOCKS5 proxy start |

**Bot Functions — Pokémon (Attacks & Crypto):**
| Name | Real Purpose |
|------|-------------|
| `charizard` | Key derivation (MD5) |
| `venusaur` | Multi-layer C2 decoder |
| `pikachu` | Stop all attacks |
| `snorlax` | UDP flood |
| `alakazam` | HTTP flood |
| `gyarados` | CF bypass flood |
| `dragonite` | SYN flood |

**DNS Resolution — Legendary Pokémon:**
| Name | Real Purpose |
|------|-------------|
| `dialga` | Main C2 resolver (orchestrator) |
| `palkia` | DoH TXT record lookup |
| `darkrai` | UDP TXT record lookup |
| `rayquaza` | A record fallback |

**Key Derivation — Mythical Pokémon (16 bytes):**
| Name | Real Purpose |
|------|-------------|
| `mew` | Key byte 1 (0xCC^0xA6) |
| `mewtwo` | Key byte 2 (0xC3^0x91) |
| `celebi` | Key byte 3 (0x79^0xC0) |
| `jirachi` | Key byte 4 (0x4F^0xAA) |
| `shaymin` | Key byte 5 (0x51^0x80) |
| `phione` | Key byte 6 (0x75^0xD1) |
| `manaphy` | Key byte 7 (0x4B^0x7C) |
| `victini` | Key byte 8 (0x87^0x86) |
| `keldeo` | Key byte 9 (0xFC^0x7C) |
| `meloetta` | Key byte 10 (0xD2^0x54) |
| `genesect` | Key byte 11 (0xE9^0xEC) |
| `diancie` | Key byte 12 (0x77^0xF1) |
| `hoopa` | Key byte 13 (0x3B^0x4C) |
| `volcanion` | Key byte 14 (0x3C^0x9D) |
| `magearna` | Key byte 15 (0x6C^0x3C) |
| `marshadow` | Key byte 16 (0x97^0x33) |

**Crypto Functions — Pokémon:**
| Name | Real Purpose |
|------|-------------|
| `charizard` | Key derivation (MD5, for C2 address obfuscation) |
| `venusaur` | Multi-layer C2 address decoder |
| `blastoise` | RC4 stream cipher |
| `garuda` | AES-128-CTR decrypt (sensitive strings + C2 outer layer) |

**CNC Variables:**
| Name | Real Purpose |
|------|-------------|
| `fancyBear` | Reconnection delay (5s) |
| `cozyBear` | Worker count (2024) |
| `equationGroup` | Buffer size (256) |
| `gothTits` | C2 address (AES-decrypted at runtime from `encGothTits`) |
| `encGothTits` | AES-128-CTR encrypted 6-layer C2 blob |

---

*Generated for VisionC2 — Author: Syn2Much*
