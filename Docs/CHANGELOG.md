
# VisionC2 Changelog

All notable changes to the VisionC2 project are documented in this file.

## [2.4.1] - 2026-02-20

### Changed
- **Reduced speed test payload from 1MB to 100KB** — faster connection setup with less bandwidth overhead

---

## [2.4] - 2026-02-19

### Added
- **SOCKS5 proxy authentication** (RFC 1929 username/password)
  - New `socksUsername` / `socksPassword` variables in `config.go`
  - Full method 0x02 negotiation in `socks.go` — clients must supply credentials when set
  - Leave both empty to fall back to unauthenticated access
  - `!socksauth <user> <pass>` command to update credentials at runtime from the TUI

- **`bot/config.go`** — centralised configuration file
  - All important constants and variables moved out of `main.go`, `socks.go`, `opsec.go`, `connection.go`, and `persist.go` into a single file
  - Sections: C2 connection, DNS, SOCKS5 proxy, paths, misc, sensitive strings, persistence paths & payloads
  - `setup.py` updated to read/write `config.go` instead of `main.go`

- **Persistence cleanup script** (`tools/cleanup.sh`)
  - Removes all bot persistence artifacts from a Linux machine
  - Covers: systemd service, hidden directory, cron jobs, rc.local entries, lock/cache files, running processes
  - All paths sourced from the same values in `config.go`

- **SOCKS5 Proxy section in TUI help menu**
  - New `writeSocksCommands()` section visible at Pro+ level
  - Shows `!socks`, `!stopsocks`, and `!socksauth` with usage
  - SOCKS commands removed from "Private Commands (Owner only)" section

### Changed
- **16-byte encryption key derivation** (was 4 bytes)
  - Expanded from 4 XOR byte functions to 16 (`mew` through `marshadow`) in `opsec.go`
  - `charizard()` now feeds all 16 bytes into the MD5 key derivation
  - `setup.py` `derive_key_py()` updated with matching 16 XOR pairs
  - All new randomised XOR operands — existing obfuscated C2 values must be regenerated via `setup.py`

- **Persistence strings extracted to `config.go`**
  - `persist.go` no longer contains any hardcoded paths, URLs, script templates, or service names
  - All values (`persistHiddenDir`, `persistPayloadURL`, `persistServiceName`, `persistScriptTemplate`, etc.) live in `config.go` as package-level variables

- **Sandbox/analysis detection strings extracted to `config.go`**
  - `vmIndicators`, `analysisTools`, and `parentDebuggers` moved from inline literals in `opsec.go` to `config.go`

- **AES-128-CTR encryption of all sensitive strings**
  - No plaintext sensitive data in the compiled binary — everything decrypted at runtime
  - Encrypted: `vmIndicators`, `analysisTools`, `parentDebuggers`, all persistence paths/names/templates, `daemonEnvKey`, `speedCachePath`, `instanceLockPath`
  - `persistPayloadURL` left unencrypted for easy per-deployment updates
  - New `garuda()` AES-128-CTR decrypt function in `opsec.go` (key = raw 16 XOR bytes)
  - New `initSensitiveStrings()` in `config.go` — called first in `main()` before any other code
  - Encrypted blobs stored as `hex.DecodeString(IV‖ciphertext)` at package level

- **Unified crypto tool** (`tools/crypto.go`)
  - Merged `encrypt_strings.go` and `verify_decrypt.go` into single CLI
  - Subcommands: `encrypt`, `encrypt-slice`, `decrypt`, `decrypt-slice`, `generate`, `verify`
  - Usage: `go run tools/crypto.go <command> [args...]`

---

## [2.3] - 2026-02

### Added
- **Comprehensive Help & Documentation menu** in the TUI
  - Expanded from 5 sections to 9: Quick Start, Navigation, Attacks, Bot Management, Shell Controls, SOCKS Proxy, Network & Security, Troubleshooting, About
  - New Quick Start guide with step-by-step onboarding
  - SOCKS Proxy section with controls, view modes, and usage examples
  - Network & Security section covering TLS, evasion, persistence, and architectures
  - Troubleshooting section with common issues and fixes
  - Expanded About page with project metadata, docs listing, and legal info
  - Page indicator and wider layout for better readability
  - Added Rapid Reset (`!rapidreset`) to the attack methods documentation

- **Broadcast shell — tabbed interface** with post-exploitation tooling
  - Two tabs: **Command**, **Shortcuts** (←/→ to switch)
  - **Shortcuts tab** — 10 pre-built post-exploitation actions (flush firewall, kill logging, clear history, kill EDR/monitors, disable cron, timestomp, DNS flush, kill sysmon, persist all, reinstall all)
  - Linux recon helpers omitted from broadcast (detached mode returns no output)
  - Scrollable list with cursor navigation, enter to execute

- **Broadcast confirmation gate** — all broadcast commands now require explicit `[y/n]` confirmation before sending
  - Shows exact target count: `⚠️ Broadcast to N bots: <command>`
  - Bot count reflects active filters (arch, RAM, max bots)
  - Applies to typed commands, shortcut selections, and `ctrl+p`/`ctrl+r` hotkeys
  - `countFilteredBots()` helper added to count matching bots without sending

- **Remote shell — Shortcuts & Linux helpers tabs**
  - Three tabs: **Shell**, **Shortcuts**, **Linux** (←/→ to switch)
  - Shortcuts tab provides the same 10 post-exploitation actions available in broadcast, targeting the single connected bot
  - Linux tab shows the same 14 recon helpers as broadcast, targeting the single connected bot
  - Enter executes the selected item and auto-switches to Shell tab to view output

### Changed
- **Broadcast shell runs fully detached** — commands sent as `!detach` instead of `!exec`, bots do not return output
  - Removed shell output area from broadcast view, replaced with command history and toast notifications
  - `ctrl+p`/`ctrl+r` routed through the same confirmation flow
- **`renderShortcutList`** refactored to standalone function with explicit cursor parameter, reused by both broadcast and remote shell views
- **Version bumped to V2.3** across TUI and changelog

---

## [2.2.1] - 2026-02

### Fixed

- **ARM/RISC-V build failure** — `syscall.Dup2` undefined on `linux/arm64` and `linux/riscv64`
  - Replaced with `syscall.Dup3(fd, fd2, 0)` which is available on all Linux architectures
    
- **`users.json` created in project root instead of `cnc/` directory**
  - Changed `USERS_FILE` to `"cnc/users.json"` so it resolves correctly when the binary is run from the project root
### Changed

- **Setup script usage output** updated with TUI and split mode instructions
  - `setup_config.txt` now documents both `./server` (TUI) and `./server --split` (multi-user telnet)
  - `print_summary()` quick start section shows both modes with admin login details    

## [2.2] - 2026-02

### Added

- **HTTP/2 Rapid Reset** attack method (`!rapidreset`) — CVE-2023-44487
  - Raw h2 framing via `golang.org/x/net/http2` + HPACK encoding
  - Batched HEADERS + RST_STREAM pairs (100 per flush) for maximum throughput
  - Automatic reconnection when stream IDs are exhausted
  - Full proxy CONNECT tunnel support (`-p` / `-pu` flags)
    
## [2.1] - 2026-02

### Added
- Full Unix daemonization of the bot process at startup
  - Re-execution with environment marker
  - Parent process exit and adoption by init (PID 1)
  - New session via `setsid()`, change directory to `/`, `umask(0)`
  - Redirection of stdin/stdout/stderr to `/dev/null`

### Changed
- Debug mode now skips daemonization to preserve logging (`deoxys()` output)

### Security / Anti-Analysis
- Significantly expanded sandbox and analysis environment detection
  - 30+ additional signatures for Unix analysis tools (debuggers, RE tools, network capture, malware sandboxes, syscall monitors, scanners, memory forensics)
  - Improved parent-process debugger checks (lldb, IDA, Ghidra, Frida, sysdig, bpftrace, …)
- Sandboxed environments now wait randomized **24–27 hours** before performing a clean `os.Exit(0)`
  - Evades short dynamic analysis timeouts
  - Avoids suspicious rapid-exit behavior

### Fixed
- **Registration timeout / disconnect issue**
  - Speed test no longer blocks the auth → register path
  - Bot metadata (ID, architecture, RAM, CPU cores, process name, uplink speed) is now pre-computed once in `main()` before entering the connection loop
  - `REGISTER` packet is sent immediately after `AUTH_SUCCESS`
  - CNC registration timeout increased from 20s → **25s**
  - Metadata cached in package-level variables and reused on reconnects

### Build
- `build.sh` now outputs binaries directly into `bins/` directory
- Removed unnecessary stale binary cleanup/move step

## [2.0] - 2026-02

### Added
- Persistent uplink speed test cache (`/tmp/.net_metric`)
  - Prevents redundant bandwidth tests on every reconnect
- Single-instance enforcement via PID-based lock file (`/tmp/.net_lock`)
  - New instance sends SIGTERM → SIGKILL to old process if present
  - Lock and cache files stored in `/tmp` — automatically cleaned on reboot

## [1.9] - 2026-02

### Added
- GeoIP country lookup at connection time (via ip-api.com, no local DB)
- Bot process name reporting (disguised name shown in TUI)
- In-memory uplink speed measurement (no disk writes)
- Extended `REGISTER` payload format:  
  `version:botID:arch:ram:cpu:procname:uplink`

### Changed
- Bot list in TUI now includes new columns: **GEO**, **PROCESS**, **UPLINK**
  - Country code highlighted in yellow
  - Process name in purple
  - Uplink speed in green

### Fixed
- UPX stripping process no longer corrupts binary structure (preserves UPX metadata)

## [1.8] - 2026-02

### Added
- Per-bot and total CPU core count tracking (displayed in stats bar)
- Proxy URL input field for Layer 7 attacks in TUI
- Cyberpunk-themed **Attack Center** interface

### Changed
- Proxy list fetching moved to bot-side (no CNC validation → higher RPS)
- Proxy rotation uses round-robin with 2-second per-proxy timeout

### Build & Tooling
- Improved file organization and modular structure
- Fixed UPX compression issues
- `setup.py` now places the server binary in project root as `server`
- More flexible certificate path handling
- Updated CNC login / header banners with cleaner design

## [1.7] - 2026-02

### Added
- Full interactive **Terminal User Interface (TUI)** – launched by default with `./cnc`
  - Real-time bot dashboard
  - Shell access to bots
  - Management commands
  - Consolidated **Attack Center** with live timers and progress
  - SOCKS5 proxy manager with status controls
  - Toast notifications
  - Connection history log

### Improved
- HTTP / Layer 7 attack performance: connection pooling + keep-alive
- Rewritten TUI-focused documentation (`USAGE.md`, `COMMANDS.md`)
- Smoother `setup.py` experience with clearer instructions

## [1.6] - 2026-02

### Added / Changed
- DNS resolution now prefers Cloudflare DoH over system resolver
- Bot persistence via cron-based auto-restart
- Parallel proxy validation before launching attacks
- Reduced status update traffic between bot and CNC

### UI
- Redesigned login screen with animations and lockout mechanism
- Split and streamlined command menus (`attack` / `methods`)

## [1.5] - 2026-01 / 02

### Build & Evasion
- Automatic UPX signature stripping (`deUPX.py`) integrated into `build.sh`

### Documentation
- Full function-level commenting of CNC and bot code
- Command reference moved to `cnc/COMMANDS.md`
- Setup summary printed at the end of `setup.py`

### Bot
- Added +50 User-Agents for better Layer 7 fingerprint diversity
- C2 domain resolution order:  
  DoH TXT → DNS TXT → A record → direct IP

## [1.4] - 2026-01

### Added
- Layer 7 proxy list support
  - Commands: `!http`, `!https`, `!tls`, `!cfbypass`
  - Supported formats: `ip:port`, `user:pass@ip:port`, `http://…`, `socks5://…`
  - Example:  
    ```
    !http target.com 443 60 -p https://example.com/proxies.txt
    ```

## [1.3] - 2026-01

### Added
- Total RAM reporting on bot registration
- Detailed debug logging (connection, TLS, auth, registration, commands)
- Stability improvements for Cloudflare / TLS bypass methods

## [1.2] - 2026-01

### Security
- Improved C2 address obfuscation (RC5 → RC4, XOR → RC4 → MD5 → Base64)

### Tooling
- Fully automated `setup.py` script
- Initial RCE and proxy support modules
- Early Cloudflare / TLS bypass functionality

## [1.1] - 2025-12

### Initial Release
- TLS 1.3 encrypted bot ↔ CNC communication
- Cross-compilation for 14 architectures:
  - `amd64`, `386`, `arm`, `arm64`, `mips`, `mipsle`, `mips64`, `mips64le`, …
- HMAC-based challenge-response authentication
