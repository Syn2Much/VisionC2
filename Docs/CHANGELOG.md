
# VisionC2 Changelog

All notable changes to the VisionC2 project are documented in this file.

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
