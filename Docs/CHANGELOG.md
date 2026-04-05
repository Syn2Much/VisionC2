
# VisionC2 Changelog

All notable changes to the VisionC2 project are documented in this file.

## [2.7.1] - 2026-04-05

### Changed
- **Attack wizard simplified** — removed dead "Options" step (always showed "No advanced options"); wizard is now 3 steps: Method → Target → Review

### Removed
- **`renderWizOpts()`** — unused function and all option-gathering code from attack wizard; no methods ever defined options

## [2.7.0] - 2026-03-30

### Changed
- **AES-128 → AES-256** — garuda() now uses a 32-byte key derived from 32 XOR byte functions (16 new pokemon added). All config blobs re-encrypted with AES-256-CTR. charizard() (venusaur C2 encoding) stays MD5 with first 16 key bytes for compatibility.
- **Sandbox detection trimmed** — procFilters reduced from 48 to 3 entries (chkrootkit, rkhunter only). parentChecks reduced from 17 to 3 (gdb, strace, frida only). Removed qemu from sysMarkers.
- **Tor panel: uplink speed column** — bot uplink (Mbps) added to /api/bots, bot table (sortable), and bot popup info.
- **Loader POSIX fix** — loader.sh rewritten for busybox/POSIX sh compatibility (removed bash arrays and local keyword).

## [2.6.5] - 2026-03-28

### Fixed
- **Tor web panel: shell output not delivered** — `forwardBotOutputToWebShells()` existed but was never called from the OUTPUT_B64 handler; bot shell output was silently dropped for all web panel sessions
- **Tor web panel: attack dispatcher sending `!attack undefined`** — API returned wrong field names (`name`/`description`/`layer` instead of `id`/`name`/`desc`/`category`), methods never populated into optgroups; command format was `!attack <method>` instead of `!<method>` which the bot expects
- **Tor web panel: stop attack sending `!stopattack`** — bot expects `!stop`, not `!stopattack`
- **Tor web panel: SOCKS status not updating** — no SSE `socks_update` events were ever broadcast; added `trackSocksState()` that intercepts `!socks`/`!stopsocks`/`!socksauth` commands from any source (HTTP API, WebSocket shell) and pushes live status via SSE
- **Tor web panel: activity tab empty** — `PushActivity()` was never called for bot join/leave events; added calls in `addBotConnection()` and both disconnect paths

### Added
- **Tor web panel re-enabled** — shell output routing fixed, attack dispatch fixed, SOCKS tracking wired up; removed WIP label and hardcoded disable
- **Baked relay endpoints in CNC** — `bakedRelayEndpoints` var patched by `setup.py`; new `/api/relays` endpoint returns them as JSON so SOCKS relay dropdowns auto-populate with all relays configured during setup
- **Baked proxy credentials in CNC** — `bakedProxyUser`/`bakedProxyPass` injected as JS globals into the dashboard; SOCKS launcher pre-fills default username/password from setup.py
- **SOCKS state on BotConnection** — `socksActive`, `socksRelay`, `socksUser` fields added to struct and `/api/bots` response; web panel shows live SOCKS status per bot
- **Post-exploit shortcuts in web shell** — Shortcuts button in shell action bar opens a popup menu with Quick Actions (persist, flush firewall, kill logging, kill monitors, etc.) and Recon helpers (system info, open ports, SUID binaries, SSH keys, credentials, etc.)
- **Bot join/leave activity events** — `PushActivity("join"/leave")` on bot connect and both disconnect paths; activity tab now shows live connection events

### Changed
- **Removed relay management tab** — relays are baked in via `setup.py`, not managed at runtime; removed tab button, panel HTML, relay CRUD JS, and API endpoints (`/api/relays` POST/DELETE, `/api/relay-api`, `/api/relay-stats`)
- **Launcher defaults to Tor web panel** — previously defaulted to TUI
- **Keyboard shortcuts renumbered** — 5=Tasks, 6=Users (was 5=Relays, 6=Tasks, 7=Users)
- **`setup.py` patches CNC** — `update_cnc_relay_endpoints()` and `update_cnc_proxy_credentials()` added; both full setup and relay-update flows now patch relay endpoints and proxy creds into `cnc/main.go` alongside the bot

### Documentation
- **README** — added Tor Web Panel navigation section, updated Architecture section
- **ARCHITECTURE.md** — updated to 3-way operator interface, added web panel section with transport/tabs/features, updated response routing diagram
- **COMMANDS.md** — added full Tor Web Panel reference covering all 6 tabs, bot popup, web shell, post-exploit shortcuts, SOCKS launcher, keyboard shortcuts; updated quick reference card

---

## [2.6.4] - 2026-03-27

### Fixed
- **m30w packer: stop renaming ELF linker symbols** — function names (`upx_main2`, `upxfd_create`, `get_upxfn_path`) are internal symbols resolved by the packer's linker. Renaming them broke i386, ARM, MIPS, and PPC64LE packing. These never appear in packed output. Now packs 11/14 architectures (s390x, MIPS64, MIPS64LE unsupported by UPX itself).

### Added
- **3-way C2 launcher** — interactive mode selector: TUI, Web Panel (Tor), Telnet. Any combination. Flags: `--tui`, `--web`, `--split`, `--daemon`.
- **Tor hidden service web panel** — `.onion` web dashboard with username/password login via `users.json` (no token, no space gate). WebSocket shell, bot management, attack control.
- **loader.sh** — architecture-detecting payload loader mapped to VisionC2 binary names.

---

## [2.6.3] - 2026-03-27

### Changed
- **Replaced stock UPX with m30w packer** — `tools/upx` is now a custom UPX fork with zero UPX fingerprint. All magic bytes, section names, ident strings, and stub metadata replaced at source level.
- **Removed `deUPX.py`** — no longer needed; m30w produces clean binaries at pack time.
- **Simplified `build.sh`** — removed post-pack signature stripping step.
- **Removed `deupx_binaries()` from `setup.py`** — obsolete.

---

## [2.6.2] - 2026-03-17

### Fixed
- **Sandbox detection now runs before /tmp writes** — `winnti()` moved before `revilSingleInstance()` in main loop so no lock/cache files are written to disk if a sandbox is detected. Prevents sandbox and similar tools from capturing tmp file names as IOCs.

### Changed
- **Lock/cache file paths hardened** — replaced obvious . Consider the old ones YARA'd.
- **Plaintext strings removed from crypto tool** — `cmdGenerate()` and `cmdVerify()` in `tools/crypto.go` no longer contain cleartext paths, IOC lists, or persistence strings. All blob management goes through `setup.py`.

## [2.6.1] - 2026-03-17

### Enhanced
- **Debug logging for sandbox detection** — `winnti()` now logs the specific reason for detection:
  - VM/sandbox process indicators: logs matched indicator, PID, and cmdline
  - Analysis tools: logs tool name and PIDs
  - Debugger parent process: logs parent PID, debugger name, and cmdline
- Sleep duration is now included in the sandbox-triggered exit log message

## [2.6.0] - 2026-03-15

### Added
- **Backconnect SOCKS5 relay server** (`relay/main.go`) — standalone binary that sits between SOCKS5 clients and bots
  - Bots connect OUT to the relay (backconnect TLS) — bot never opens a port
  - SOCKS5 clients connect to the relay's public port with username/password auth
  - Traffic flow: `User → Relay → Bot → Target` — C2 address never exposed
  - Relay is separate throwaway infrastructure; if burned, spin up a new VPS
  - Round-robin bot selection when multiple bots are connected
  - Built-in stats endpoint (`-stats 127.0.0.1:9090`): connected bots, session counts, bandwidth, auth failures
  - Auto-generated ephemeral TLS cert, or bring your own with `-cert`/`-keyfile`
  - Auth key baked in at build time by `setup.py` (matches bot `syncToken` / CNC `MAGIC_CODE`)

- **Multi-relay failover** — bots support unlimited relay endpoints with automatic rotation
  - Pre-configure endpoints in `setup.py` (comma-separated) or specify at runtime via `!socks`
  - Bots shuffle relay list on startup so they spread across relays
  - On disconnect, bot rotates to next relay with quick retry (0.5–2s jitter)
  - After full rotation fails, exponential backoff (5s → 60s cap)
  - Runtime override: `!socks r1:9001,r2:9001,r3:9001` — comma-separated, pre-configured endpoints appended as fallbacks

- **Direct SOCKS5 listener mode preserved** — `!socks <port>` opens a local listener on the bot (no relay needed)
  - Bot detects whether arg is a port number (direct) or host:port (backconnect)
  - `!socks 1080` → direct listener on `0.0.0.0:1080`
  - `!socks relay.com:9001` → backconnect to relay
  - `!socks` (no args) → use pre-configured relay endpoints

- **Default SOCKS5 proxy credentials** — baked into the bot binary at build time
  - Default: `vision:vision`, configurable in `setup.py`
  - Users connect with: `curl --socks5 relay:1080 -U user:pass http://target`
  - Can be changed at runtime via `!socksauth <user> <pass>`

- **Setup option 3: Relay Endpoints Update** — new menu option in `setup.py`
  - Add, change, or remove relay endpoints without touching C2/magic code/certs
  - Shows current relay endpoints (decrypted from config)
  - Update default proxy credentials
  - Rebuilds relay + bot binaries

- **Relay binary build** in `setup.py` — all 3 setup options now offer to build the relay server
  - `build_relay()` function with same hardening flags as bot/CNC (`-trimpath -ldflags="-s -w -buildid="`)
  - Output: `relay_server` in project root

- **`find_go()` helper** in `setup.py` — prefers `/usr/local/go/bin/go` over system PATH
  - Fixes build failures when system Go is outdated but `/usr/local/go` has the correct version
  - Used by `build_cnc()`, `build_relay()`, and `build.sh`

- **TUI SOCKS5 manager — three modes**
  - `[s]` Quick start — sends `!socks` immediately, uses pre-configured relay + default credentials
  - `[c]` Custom relay — input form for manual relay:port + credentials override
  - `[d]` Direct mode — input form for port number, opens local SOCKS5 listener on bot
  - `[x]` Stop — disconnect from relay or close listener
  - Table column changed from PORT to RELAY to show backconnect target

### Changed
- **SOCKS5 architecture rewritten** — bot no longer opens a local listener by default; backconnect via relay is the primary mode
  - `muddywater()` now accepts `[]string` (relay list) for backconnect mode
  - New `turmoil()` for direct listener mode (port-only arg)
  - `cozyBear()` — relay control loop with auto-reconnect and multi-relay rotation
  - `fancyBear()` — data channel per SOCKS5 session
  - `trickbot()` — SOCKS5 handler unchanged, works for both modes
  - `emotet()` — handles shutdown for both backconnect and direct modes
- **Go version requirement** — README install instructions updated from 1.23 to 1.24 (required by `miekg/dns` v1.1.72)
- **`build.sh`** — uses `$GO_BIN` variable, prefers `/usr/local/go/bin/go` over system PATH
- **CNC split mode help** — updated `!socks` help to show both direct and backconnect usage
- **TUI help section 5 (SOCKS)** — rewritten for backconnect architecture with relay setup instructions

---

## [2.5.0] - 2026-03-10

### Changed
- **Per-build random AES key** — every time `setup.py` runs, a fresh 16-byte AES-128-CTR key is randomly generated and baked into the binary. The old static key (readable in source) is gone. Two builds from the same source now produce binaries with completely different encrypted payloads, so reversing one tells you nothing about the next.
- **All sensitive strings encrypted in source** — the repo no longer ships plaintext protocol commands, persistence paths, DNS servers, attack fingerprints, or shell binary names. Everything is stored as AES-encrypted hex blobs even in the public source code, encrypted under a default zero key. `setup.py` replaces that with a real random key at build time. Running `strings` on either the source or the compiled binary gives you nothing useful.
- **~45 additional strings moved behind encryption** — protocol handshake strings (`AUTH_CHALLENGE`, `REGISTER`, `PING/PONG`, error formats), response messages, DoH server URLs, attack user-agents/referers/paths, Cloudflare bypass fingerprints, DNS flood domains, system binary names (`sh`, `bash`, `systemctl`, `crontab`, `pgrep`), `/proc/` paths, `/dev/null`, and process camouflage names are all now runtime-decrypted from encrypted blobs. Previously these were plaintext literals scattered across the source files — easy pickings for any analyst with `grep`.
- **`setup.py` handles all encryption automatically** — no need to manually run `tools/crypto.go` to generate blobs. The setup wizard reads the current key from `opsec.go`, decrypts existing blobs, generates a fresh random key, re-encrypts everything, and patches both `opsec.go` and `config.go` in one step. Works for both full setup (option 1) and C2 URL update (option 2).
- **`tools/crypto.go` stays usable** — `setup.py` patches its key array with the same random values it writes to `opsec.go`, so the tool works for manual encrypt/decrypt after a build. Shows a warning if the key is still all zeros (setup hasn't been run).
- **`derive_key_py()` and `garuda_key()` read dynamically from source** — no more hardcoded XOR pairs duplicated between Python and Go. `setup.py` parses the actual byte pairs from `opsec.go` at runtime, so they're always in sync.

---

## [2.4.6] - 2026-03-09

### Added
- **AUTH column in SOCKS5 Proxy Manager** — the active socks table now displays `user:pass` credentials for each proxy, so operators can see all proxy connection details at a glance
  - Proxies with credentials show `user:pass` in cyan
  - Active proxies with no auth show `(no auth)`
  - Inactive bots show `-`

### Changed
- **Attack method selector grouping** — moved SYN Flood, ACK Flood, GRE Flood, and DNS Amp from Layer 7 section to Layer 4 where they belong; removed duplicate L7 header

### Fixed
- **`setup.py` not patching C2 URL into bot binaries** — all `re.sub()` calls in `update_bot_main_go()` used stale variable names from before the v2.4.4 rename, so every regex silently matched nothing and the source was never updated; binaries kept the old hardcoded C2 address regardless of what was entered during setup
  - `encGothTits` → `rawServiceAddr`
  - `cryptSeed` → `configSeed`
  - `magicCode` → `syncToken`
  - `protocolVersion` → `buildTag`
- **`get_current_config()` reading wrong variable names** — "C2 URL Update Only" mode (option 2) failed to find existing config values for the same reason; fixed to match the renamed constants
- **`update_bot_debug_mode()` targeting non-existent variable** — regex looked for `debugMode` but config.go uses `verboseLog` since v2.4.4; debug mode toggle had no effect

---

## [2.4.5] - 2026-03-07

### Changed
- **Bundled UPX binary** — `tools/upx` now ships a static UPX 4.2.4 binary; `build.sh` uses it directly instead of relying on system-installed `upx-ucl` or `upx` packages
- **Removed `upx-ucl` from prerequisites** — no longer needed in `apt install`; README updated accordingly

---

## [2.4.4] - 2026-03-02

### Changed
- **Full config.go variable obfuscation** — renamed all 40+ variables and constants to neutral names that reveal nothing about intent
  - `debugMode` → `verboseLog`, `gothTits` → `serviceAddr`, `cryptSeed` → `configSeed`, `magicCode` → `syncToken`, `protocolVersion` → `buildTag`
  - `fancyBearMin/Max` → `retryFloor/retryCeil`, `lizardSquad` → `resolverPool`, `cozyBear` → `workerPool`, `equationGroup` → `bufferCap`
  - `socksUsername/Password` → `proxyUser/proxyPass`, `lazarusMax` → `maxSessions`
  - `daemonEnvKey` → `envLabel`, `speedCachePath` → `cacheLoc`, `instanceLockPath` → `lockLoc`
  - All `persist*` vars → `rcTarget`, `storeDir`, `scriptLabel`, `binLabel`, `unitPath`, `unitName`, `unitBody`, `tmplBody`, `schedExpr`, `fetchURL`
  - All `enc*` blobs → `raw*` equivalents (e.g. `encGothTits` → `rawServiceAddr`, `encVmIndicators` → `rawSysMarkers`)
  - `vmIndicators` → `sysMarkers`, `analysisTools` → `procFilters`, `parentDebuggers` → `parentChecks`
  - `initSensitiveStrings()` → `initRuntimeConfig()`
  - Updated all references across `main.go`, `connection.go`, `opsec.go`, `socks.go`, `persist.go`, `attacks.go`, and `tools/crypto.go`
  - Comments scrubbed of revealing terminology

### Added
- **SOCKS5 TUI auth fields** — socks manager input prompt now includes User and Pass fields alongside Port
  - `tab` cycles between Port / User / Pass fields
  - Password masked with `*` in the UI
  - Credentials sent via `!socksauth` after proxy starts
  - `SocksInfo` struct extended with `Username` and `Password` fields
- **Vision C2 manifest banner** in `bot/main.go` — ASCII art header with feature summary

## [2.4.3] - 2026-02-26

### Changed
- **6-layer C2 address encryption** — `gothTits` is now AES-128-CTR encrypted at rest and decrypted at runtime via `garuda()` before being passed to the 5-layer `venusaur()` decoder; the C2 address (and its 5-layer encoded form) no longer appears as plaintext anywhere in the binary
- `gothTits` changed from `const` to runtime-decrypted `var`, populated by `initSensitiveStrings()` alongside all other sensitive strings
- `setup.py` now AES-encrypts the obfuscated C2 blob using the `garuda` key before writing `encGothTits` to `config.go`
- Added `garuda_key()` and `aes_ctr_encrypt()` helpers to `setup.py`
- **New TUI dashboard banner** — replaced ASCII calligraphy banner with braille-art graphic

---

## [2.4.2] - 2026-02-23

### Fixed
- **Race condition: `ongoingAttacks` map** — added `sync.RWMutex` protection around all reads/writes in `cmd.go`, `ui.go`, and `miscellaneous.go`; prevents runtime panics from concurrent map access
- **Race condition: `clients` slice** — added `clientsLock sync.RWMutex` around all append/iteration of the global `clients` slice in `connection.go` and `miscellaneous.go`
- **Race condition: SOCKS5 credentials** — added `socksCredsMutex sync.RWMutex` to protect `socksUsername`/`socksPassword` writes (`!socksauth`) and reads (`trickbot`)
- **SOCKS5 buffer bounds** — added `ulen == 0` / `plen == 0` checks and tightened bounds validation in RFC 1929 sub-negotiation parsing (`socks.go`)
- **Insecure `users.json` permissions** — changed from `0777` to `0600` so credentials are only readable by the owner
- **Unclosed HTTP response bodies** — refactored `palkia()` and `rayquaza()` in `connection.go` to close `resp.Body` before branching, eliminating potential leaks on decode errors
- **Unprotected `proxyList` access** — replaced raw `proxyList[rand.Intn(...)]` in the HTTP/2 Rapid Reset attack with the already thread-safe `persian()` round-robin function
- **Ignored `strconv.Atoi` errors** — attack port and duration parsing now validates errors and rejects invalid/out-of-range values
- **Ignored `json.Unmarshal` error in `AuthUser`** — now checks and logs parse failures so corrupted `users.json` doesn't silently lock everyone out
- **Ignored `cmd.Run()` errors in persistence** — `carbanak`, `lazarus`, and `dragonfly` now check and log crontab/systemctl failures
- **Weak PRNG for auth challenges** — `randomChallenge()` now uses `crypto/rand` instead of `math/rand`, falling back only on error
- **`meowstic()` ignoring timeout parameter** — now uses the caller-provided timeout instead of hardcoded 2s
- **Cleanup script cron data loss** — `tools/cleanup.sh` cron removal now checks if `grep -v` output is non-empty before piping to `crontab -`; uses `crontab -r` when the filtered result would be empty
- **Regex metacharacter injection in `setup.py`** — all `re.sub()` replacements now use lambdas so special characters in magic codes or protocol versions (e.g. `$`, `^`, `+`) are written literally into Go source instead of being interpreted as regex syntax
- **Remote shell hotkeys sending OS commands instead of bot commands** — `!persist`, `!reinstall`, and any `!`-prefixed command are now sent directly to the bot instead of being wrapped with `!shell`, which caused them to be executed as literal OS shell commands that did nothing
- **TUI kill hotkey sending non-existent command** — TUI was sending `!lolnogtfo` (a CNC telnet command) directly to the bot which doesn't recognise it; now correctly sends `!kill`
- **`!kill` not removing persistence** — `!kill` previously just called `os.Exit(0)`, so persisted bots would respawn via cron/systemd/rc.local; now runs `nukeAndExit()` which disables the systemd service, strips cron entries, cleans rc.local, removes the hidden directory, deletes the lock file, and removes its own binary before exiting

### Changed
- **New Banners and UI elements** — Replaced old Banners for a more uniform feel 
- **Removed dead code** — deleted unused `bot` struct, `bots` slice, and legacy `botConns` slice from `cnc/main.go` and `cnc/connection.go`
- **`setup_config.txt` secured** — file now created with `0600` permissions; added to new `.gitignore`
- **Go version alignment** — README badge and install instructions updated from 1.23 to 1.24 to match `go.mod`
- **Ctrl+C works in debug mode** — removed `ignoreSignals()` call from `stuxnet()` when `debugMode` is true so the bot can be cleanly exited with Ctrl+C during development
- **Randomised reconnect delay** — bot reconnection delay changed from fixed 5s to random 4–7s (`fancyBearMin`/`fancyBearMax`) for traffic pattern variation
- **Scrollable remote shell output** — shell output in TUI now supports `pgup`/`pgdown` scrolling with 500-line buffer (was 50, no scroll); scroll indicator shows position; auto-scrolls to bottom on new output unless user has scrolled up
- **Shell clear resets scroll** — `ctrl+f` now also resets scroll offset to bottom

### Added
- **`.gitignore`** — new file covering `setup_config.txt`, `bins/`, `server`, `cnc/cnc`, and TLS certificates

---

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
- Persistent uplink speed test cache (`/tmp/.ICE-unix/.ICEauth`)
  - Prevents redundant bandwidth tests on every reconnect
- Single-instance enforcement via PID-based lock file (`/tmp/.font-unix/.font0-lock`)
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
