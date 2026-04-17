
# VisionC2 Changelog

All notable changes to the VisionC2 project are documented in this file.

## [2.9.1] - 2026-04-17

### Changed
- **Bot binary: `net/http` and `encoding/json` removed from core** — replaced with a minimal raw HTTP/1.1 client (`bot/rawhttp.go`) built on `net` + `crypto/tls` (already linked for C2 comms); DoH JSON responses parsed with lightweight string extractors instead of `encoding/json` + `reflect`; `revilUplink()`, `palkia()`, `rayquaza()`, and `fetchPayload()` all rewritten; attacks module still uses `net/http`/`encoding/json` when compiled with `withattacks` tag — core bot is completely free of both packages
- **Bot binary size reduced ~20-22% across all architectures** — packed MIPS/ARM binaries dropped from ~1.7MB to ~1.3MB; x86_64 from 1.9MB to 1.5MB; unpacked MIPS64 from 6.6MB to 5.1MB; savings come from eliminating the `net/http` dependency tree (HTTP/2, mime, multipart, compress/gzip, net/textproto) and `encoding/json` + `reflect`
- **HTTP/2 Rapid Reset (`!rapidreset`) is a raw implementation — no `x/net/http2`** — `giratina()` implements RFC 7540 framing (SETTINGS, HEADERS, RST_STREAM) and RFC 7541 HPACK static table encoding directly over `crypto/tls`; zero dependency on `golang.org/x/net/http2`; keeps the attack module free of the x/net module tree

## [2.9.0] - 2026-04-17

### Added
- **Go build tags for optional bot modules** — `attacks.go` tagged `//go:build withattacks`, `socks.go` tagged `//go:build withsocks`; compiler skips the file entirely when the tag is absent — zero attack or SOCKS code in the binary, not just disabled at runtime; stub files (`attacks_stub.go`, `socks_stub.go`) keep the bot compiling in all four configurations: full, attacks-only, socks-only, shell/management-only; shell-only binary is ~400KB smaller than full
- **`bot/dispatch.go`** — `blackEnergy` extracted into its own always-compiled file; delegates attack/SOCKS commands to `dispatchAttack()` / `dispatchSocks()` / `dispatchAttackStop()` which resolve to real implementation or no-op stub based on build tags
- **`bot/dns_codec.go`** — DNS wire-format helpers moved out of `attacks.go` into a dedicated always-compiled file (used by the C2 resolver in all builds)
- **`bot/caps.go`** — `botCaps()` returns the capability string (`"A"`, `"S"`, `"AS"`, `""`) from `hasAttacks`/`hasSocks` constants set by the active build tag files
- **Bot capability reporting in REGISTER** — bot appends `:<caps>` to REGISTER; CNC parses it and stores `attacksEnabled`/`socksEnabled` per `BotConnection`; bots without the field default to fully-enabled for backwards compatibility
- **Capability-filtered broadcast helpers** — `sendToAttackBots()` and `sendToSocksBots()` route only to bots with the respective flag; used by telnet CLI, TUI, and web panel
- **Capability enforcement on targeted sends** — web sidebar, `handleAPITasks`, telnet `!<botid>` syntax, and TUI socks view all check `attacksEnabled`/`socksEnabled` before sending; `trackSocksState` also skips bots where `socksEnabled == false` so the dashboard cannot show SOCKS active on an attack-only bot
- **Dashboard — Caps column** — bot table shows `ATK` (red) and/or `SOCKS` (blue) tags per bot; `-` when neither module is compiled in
- **API key panel shows attack-capable bot count** — `handleAPIMe` returns `getAttackBotCount()` for API-key sessions
- **`setup.py` — module selection prompt** — Full Setup, C2 Update, and new Module Update option all present a 4-choice menu (Full / Attacks only / SOCKS only / None); choice is converted to Go build tags and passed via `BOT_BUILD_TAGS` env var
- **`setup.py` option `[3]` — Module Update & Rebuild** — replaced the defunct Relay Endpoints Update (relays are runtime-managed since v2.8.7); presents the module menu and rebuilds bot binaries without touching C2, magic code, or certs
- **`setup.py` option `[4]` — Restore from `setup_config.txt`** — re-applies a saved campaign config after `git pull` or fresh clone; generates a fresh AES key, re-obfuscates C2 with stored crypt seed + new key, patches source, and rebuilds; old bots keep connecting because magic code and protocol version are unchanged
- **`setup_config.txt` saves proxy credentials and module flags** — `[Proxy]` and `[Modules]` sections added so a restore has everything needed to reproduce the exact build
- **`tools/build.sh` — `BOT_BUILD_TAGS` support** — all `go build` invocations read `$BOT_BUILD_TAGS` and pass `-tags` when set
- **Static binaries — `CGO_ENABLED=0` across all builds** — all 14 bot architectures, CNC, and relay now build with `CGO_ENABLED=0`; pure-Go net resolver, no libc dependency, runs on any Linux kernel regardless of glibc version or presence; resolves crashes on old routers and uClibc/musl systems

### Fixed
- **`trackSocksState` no longer marks non-SOCKS bots as active** — UI was showing SOCKS on for attack-only bots because the tracking function fired regardless of capability
- **TUI socks view guards capability** — shows a toast and aborts if selected bot lacks the SOCKS module
- **`BotInfo` struct carries capability flags** — `AttacksEnabled`/`SocksEnabled` populated from `BotConnection` on refresh
- **Theme picker syncs to actual active theme** — on first load the dropdown showed "Light" while the page was in dark mode; init now reads `data-theme` to set the correct value; `applyTheme()` also updates the picker on toggle

### Changed
- **Attack/SOCKS commands route to capable bots only** — `sendToAttackBots()`/`sendToSocksBots()` used in CLI, TUI, and web panel for all broadcast and targeted sends
- **Dashboard — confirm dialogs standardised** — `msKill()`, `popupKill()`, and stop-SOCKS actions now use the styled `showConfirm()` modal instead of the browser's native `confirm()`; new `confirmStopSocks(botID)` added
- **Dashboard — multi-select Start SOCKS filters by capability** — new `msCmdFiltered(cmd, capField)` skips bots without the module and reports skip count in the toast
- **Dashboard — SSE drop banner** — yellow slide-in banner appears after 3-second grace period when live connection is lost; disappears on reconnect
- **Dashboard — bot ID truncation** — `.bot-id-link` truncates at 130px with ellipsis; full ID shown on hover
- **Dashboard — bot count always visible** — filter count shows `"Y bots"` when no filter is active, `"X / Y bots"` when filtering; was hidden with no filter

## [2.8.8] - 2026-04-15

### Added
- **IP blacklist — auto-ban on repeated auth failures** — `connection.go` tracks consecutive auth failures per IP; after 3 failures the IP is banned for 1 hour and all subsequent connections are dropped silently before the TLS handshake completes; `[BLACKLIST]` log entry fires once on ban; ban expires and cleans up lazily on next connection attempt

### Changed
- **`tor_data/` moved into `cnc/`** — `getTorDataDir()` now prefers `cnc/tor_data` when the server is run from the project root (detects `cnc/` directory); falls back to next-to-binary for other run contexts; existing `tor_data/` migrated
- **`users.json` moved to `cnc/db/`** — canonical path is now `cnc/db/users.json` alongside `relays.json`; init checks legacy paths (`cnc/users.json`, `users.json`) first so existing deployments migrate automatically on next start
- **Project structure** — `relay/` moved to `cnc/relay/` (relay is CNC infrastructure); `loader.sh` moved to `tools/`; `setup.py` relay build path updated to `cnc/relay/`
- **Tab focus outline removed** — browser focus ring on tab click suppressed via `.tab:focus { outline: none }`
- **Command center target placeholder** updated to hint at bot ID targeting

## [2.8.7] - 2026-04-15

### Added
- **Relay stats push** — relay binary now accepts `-c2 <url>`, `-interval <s>`, and `-name <id>` flags; when `-c2` is set, a `pushStatsLoop()` goroutine POSTs live stats (active connections, total sessions, bytes up/down, failed sessions, connected bots, uptime) to the CNC `/api/relay-report` endpoint every `interval` seconds; authenticated via `X-Relay-Key` header
- **`/api/relay-report` endpoint (CNC)** — unauthenticated-to-relays POST endpoint that accepts stats payloads and caches them in memory per relay name; relays not seen in 90s are marked `Up: false`
- **`/api/relays/stats` endpoint (CNC)** — merges relay list from `relays.json` with latest cached stats; consumed by dashboard every 15s
- **`POST /api/relays` and `DELETE /api/relays`** — runtime add/remove relay endpoints; persisted to `cnc/db/relays.json`
- **Dashboard relay health cards** — SOCKS tab now shows a live card per relay: status dot, active connections, total sessions, bandwidth up/down, connected bots, uptime, last seen, and the exact `-c2` flag command to start the relay binary; updates every 15s
- **`cnc/db/` directory** — new JSON database folder for all runtime-managed state; starts with `relays.json`

### Changed
- **Relay endpoints no longer baked into bot binary** — `rawRelayEndpoints` encrypted blob and `relayEndpoints` var removed from `bot/config.go`; `!socks` now requires an explicit relay address or port — `!socks` with no args returns a usage error
- **`setup.py` relay prompt removed** — relay endpoints are no longer asked for or written during any setup option; option 3 updated to reflect dashboard management; summary output updated
- **`bakedRelayEndpoints` var removed from `cnc/main.go`** — replaced by `loadRelaysFromDisk()` / `saveRelaysToDisk()` backed by `cnc/db/relays.json`
- **PROXY.md fully rewritten** — reflects runtime relay management, new relay flags, stats push setup, dashboard instructions

## [2.8.6] - 2026-04-15

### Changed
- **`setup.py` option 1 — proxy credentials no longer prompted** — `proxyUser` and `proxyPass` are now auto-generated as random 12-character alphanumeric strings unique to each build; credentials are printed to stdout after generation so the operator can note them; eliminates a manual setup step without reducing security (was defaulting to `vision:vision`)

## [2.8.5] - 2026-04-15

### Added
- **`!persist [url]` runtime URL** — `!persist` now accepts an optional URL argument; the bot always tries to copy the running binary first and only falls back to fetching the URL if the binary is unreadable (deleted from disk, etc.); supports both ELF binaries and shell scripts
- **`!reinstall <url>`** — new command; fetches an ELF binary or shell script from the given URL, writes to a temp file, and `syscall.Exec`-replaces the current process image; script detection by `.sh` suffix or `#!` shebang (runs via bash); ELF exec'd directly
- **Dashboard — hover tooltips throughout the CNC** — `data-tooltip` CSS tooltips added to every action button, command chip, table header, nav control, and status indicator that benefits from contextual explanation; no prior knowledge of the bot fleet required

## [2.8.4] - 2026-04-15

### Added
- **Dashboard — page-wide bot detail sidebar** — left-clicking any bot row opens a full-height fixed panel on the right edge of the page (not clipped to the bots tab); contains all bot metadata and a complete single-target command surface: Shell, Start/Stop SOCKS, Persist, Reinstall, Set Group, Kill buttons plus a free-text command console with `!shell` / `!detach` / `!stream` / `!stopsocks` / `!persist` / `!reinstall` chips; right-click on a row opens the existing floating action popup
- **Dashboard — shell file browser opens at `/` on new sessions** — `shellWS.onopen` now sends `cd /` for fresh sessions so the file browser immediately populates with the full filesystem root (`/bin`, `/etc`, `/home`, `/lib`, `/root`, `/usr`, `/var`, …) without any manual navigation; restored sessions re-run `ls -laF` for the saved cwd instead

### Fixed
- **Dashboard — light mode broken after panel theme change** — `applyGlobalTheme` was setting inline CSS custom properties on `:root` which outranked `[data-theme="light"]` attribute-selector rules; `applyTheme` (sun/moon toggle) now calls `clearGlobalThemeVars()` first, removing all inline overrides before applying the data-theme attribute; added `light` and `dark` as named entries in the global theme picker so both are accessible from the dropdown as well as the toggle button
- **Dashboard — SSE connection dot always red** — `onerror` fires on every normal SSE reconnect cycle (server closing the keep-alive stream), immediately setting the indicator red even when `onopen` fires within milliseconds; added a 3-second debounce before going red so transient reconnects stay green and the dot only goes red during a sustained outage

## [2.8.3] - 2026-04-15

### Changed
- **`bot/persist.go` — `dragonfly()` no longer requires a download URL** — removed `fetchURL` plaintext config var, `tmplBody` / `scriptLabel` encrypted blobs, and the `carbanak()` cron helper entirely; `dragonfly()` now reads the running binary via `os.Executable()`, copies it into `storeDir/binLabel`, and writes a dynamically-built systemd unit pointing at the copy directly — no shell script, no remote fetch, nothing to store in config; `lazarus()` already handles the cron angle so `carbanak` was redundant

### Fixed
- **`bot/config.go` — `verboseLog` was `true` in source** — every deployed bot was printing `[DEBUG]` lines to stdout, leaking auth challenges, bot IDs, and C2 resolver hits; flipped to `false`
- **`bot/main.go` — `oceanLotus` never reaped detached children** — `exec.Cmd.Start()` with no `Wait()` causes every `!bg`/`!detach` command to leave a zombie process until the bot exits; added `go command.Wait()` after a successful `Start()` to reap each child
- **`bot/attacks.go` — `encodeDNSName` didn't clamp labels to 63 bytes** — DNS wire format reserves the top 2 bits of the length byte (`0xC0` = compression pointer); labels ≥ 64 bytes produced malformed packets and silently broken DNS floods; labels are now truncated to 63 bytes before encoding
- **`bot/attacks.go` / `bot/socks.go` — no `recover()` in any goroutine** — a single nil-deref or slice OOB in any of the 13+ attack workers would kill the entire bot process; added `guardedGo()` helper with `recover()` in `main.go` and wrapped all attack workers plus the SOCKS accept loop and per-client goroutines
- **`bot/main.go` — reconnect jitter could be zero** — `rand.Int63n(int64(2*time.Second))` can return 0, collapsing the retry delay to exactly `backoff`; added a 100ms floor so the jitter always produces a non-zero delta

## [2.8.2] - 2026-04-15

### Added
- **`/api/stats/bots` endpoint** — aggregate bot census for scripted monitoring: total bot count, per-arch / per-country / per-group distribution, uptime bucketing (`<1m`, `<1h`, `<1d`, `>=1d`), total RAM and CPU cores. Gated behind `requireWebAuth` like the rest of the `/api` surface
- **Relay `-h` usage output** — `flag.Usage` now prints a short description, all flags with defaults, two usage examples, and the plaintext-stats security warning; previously `./relay -h` dumped only the raw `flag.PrintDefaults()` list

### Changed
- **Relay TLS minimum is now 1.3** — `buildTLSConfig()` was hardcoding `MinVersion: tls.VersionTLS12` in both the loaded-cert and auto-generated paths; bumped to `tls.VersionTLS13` to match the hardened CNC config
- **CNC TLS now pins max version** — `loadTLSConfig()` sets `MaxVersion: tls.VersionTLS13` alongside the existing `MinVersion: tls.VersionTLS12` so the server never negotiates above 1.3 even on a mis-patched client
- **CNC missing-cert error is now actionable** — on startup without certs, prints the current working directory, every cert path that was tried, and a ready-to-run `openssl req` command to generate a self-signed pair. Previously printed just `make sure server.crt and server.key exist`
- **Relay `pickBot()` no longer holds nested locks** — round-robin counter is advanced before acquiring `botsMu.RLock()`; removes a potential deadlock vector if any future caller locks in the reverse order
- **Relay ephemeral cert lifetime dropped from 10 years to 1 year** — `NotAfter` now uses `365 * 24 * time.Hour`; matches the cert's intent (short-lived, regenerated on every start when no `-cert` is passed)
- **`tools/crypto.go` no longer panics on AES errors** — `encrypt()` / `aesEncrypt()` call sites used `panic(err)` on `aes.NewCipher` and `rand.Read` failures, producing goroutine stack traces in a CLI. Replaced with `log.Fatalf()` for a clean single-line error

## [2.8.1] - 2026-04-10

### Changed
- **Removed gopacket dependency** — TCP SYN/ACK flood (`dragonite`, `tyranitar`) and GRE flood (`metagross`) now use raw 20-byte header serialization via `encoding/binary` instead of `gopacket.SerializeLayers()`; eliminates ~300-500KB from binary
- **Removed miekg/dns dependency** — DNS flood (`salamence`) and C2 TXT resolution (`darkrai`) now use raw DNS wire format construction and parsing; `encodeDNSQuery()`, `parseDNSTXTResponse()`, `skipDNSName()` helpers handle query building and response extraction; eliminates ~50-100KB from binary
- **Replaced 546 hardcoded user-agents with 18 template-based generators** — `uaPool` stores format strings + version ranges; `randUA()` picks a random template and version at runtime via `fmt.Sprintf`; produces equivalent browser diversity at ~1/10 the binary cost; dropped all pre-2024 entries (IE/Trident, Chrome 37-45, Win NT 6.x, iPad OS 7/8)
- **UPX packer updated** — `tools/upx` replaced with fresh VPX build using unique hex magic 

### Fixed
- **Build script UPX packing broken** — `cp` creates files with 0000 permissions in sandboxed environments; UPX refused to pack with `IOException: file is write protected` and `CantPackException: file not executable`; added `chmod 755` on `.tmp` files before packing

### Removed
- **`github.com/google/gopacket`** — no longer a dependency (was only used for 3 L4 attack functions)
- **`github.com/miekg/dns`** — no longer a dependency (was only used for DNS flood + C2 resolution); also drops transitive deps `golang.org/x/mod`, `golang.org/x/sync`, `golang.org/x/tools`

### Binary Size
- Packed binaries (--lzma) now **1.7-2.1MB** across 11 supported architectures (down from 2.1-2.5MB)
- Unpacked stripped binaries reduced from ~7.5-8MB to ~6.0-6.7MB per architecture
- MIPS64, MIPS64LE, s390x remain unpacked (UPX does not support these ELF formats)

## [2.8.0] - 2026-04-06

### Added
- **Server-side permission enforcement** — all web API endpoints now check user level before allowing actions; `requireOwner` and `requireAdmin` middleware wrappers gate sensitive routes
- **Per-command authorization in `/api/command`** — shell commands (`!shell`, `!exec`, `!stream`, `!detach`) require Admin+; bot management (`!reinstall`, `!kill`, `!persist`, scanners, SOCKS) require Admin+; attacks validate method, maxtime, and concurrent limits against user record
- **Per-user API key system** — every user gets a unique 64-char hex API key auto-generated on creation; existing users backfilled on startup; `X-API-Key` header supported as alternative to cookie auth
- **`/api/auth/apikey` endpoint** — POST with `{"api_key": "..."}` to authenticate and receive a session cookie
- **`/api/me` endpoint** — returns current user's level, methods, limits, bot count, and running attacks
- **Stripped-down API panel** — API key sessions get a minimal customer-facing page with attack builder, bot count, limits display, and running attacks only; no shell, no user management, no scanners
- **Frontend RBAC** — dashboard fetches `/api/me` on load and hides unauthorized tabs/buttons (Users tab Owner-only, Relays/Tasks Admin+, shell/scanner/kill buttons Admin+)
- **Telnet attack validation** — telnet CLI now enforces user's allowed methods, maxtime, and concurrent attack limits (previously only checked `canUseDDoS` boolean)
- **Per-user attack tracking** — `attack` struct now includes `username` field for accurate concurrent limit enforcement across web and telnet

### Changed
- **`/api/users` route** — now gated by `requireOwner` (was `requireWebAuth`); only Owners can see, create, edit, or delete users
- **`/api/relays` and `/api/tasks` routes** — now gated by `requireAdmin`
- **`/ws/shell` route** — now gated by `requireAdmin` (was `requireWebAuth`)
- **Bot details in telnet** — Basic/Pro users now only see bot count, not full bot list with IDs/IPs
- **User GET response** — now includes `api_key` field (visible to Owner only since route is Owner-gated)
- **Bot targeting** — Basic users can only broadcast; Pro+ can target specific bots by ID

### Fixed
- **All users had Owner permissions** — `requireWebAuth` only checked session existence, never role; every authenticated user could access all commands, manage users, open shells regardless of configured level

## [2.7.1] - 2026-04-05

### Added
- **Live attacks panel** — attack tab now shows a real-time list of running attacks with method, target, progress bar, and countdown; polls `/api/attacks` every 2s; tracks attacks launched from both TUI and web panel
- **Task system** (`/api/tasks`) — create, list, and clear bot tasks from the Tor panel Tasks tab; tasks execute immediately and log to activity feed (replaces empty Armada stub)
- **Logout activity logging** — web panel logouts now appear in the activity tab alongside logins
- **Bot popup on single click** — clicking a bot row now opens the info sidebar (previously required right-click); double-click still opens shell

### Changed
- **File browser fixed** — `cd` into directories now works reliably; CNC chains `pwd && ls -laF` into a single atomic shell command via `---LS---` marker instead of racing two separate commands with a timeout; cwd extraction fixed to parse first line only from combined output
- **Attack wizard simplified** — removed dead "Options" step (always showed "No advanced options"); wizard is now 3 steps: Method → Target → Review
- **Bot reconnect backoff** — replaced fixed 4-7s retry with exponential backoff (4s → 8s → 16s → ... → 60s cap), resets on successful connect; reduces noisy traffic when C2 is down
- **Attack param validation** — port 0 now rejected (must be 1-65535), minimum duration enforced at 5 seconds
- **SOCKS5 buffer size** — increased from 513 to 514 bytes to prevent off-by-one on max-length username+password auth (255+255+3 = 513 needs index 513)
- **SSE/polling conflict** — polling now stops when SSE reconnects successfully instead of running both indefinitely
- **`/api/attacks` response** — now includes `elapsed` and `duration` fields for progress calculation
- **Attack tracking uses int keys** — `ongoingAttacks` map changed from `net.Conn` to `int` keys so both TUI and web panel attacks share the same tracker
- **OpenSSL config fix** — `setup.py` now sets `OPENSSL_CONF` to system config path, fixing cert generation failure on systems with musl-cross toolchains

### Removed
- **Deprecated `rand.Seed()` calls** — removed 6 occurrences in attacks.go; Go 1.20+ auto-seeds the global source
- **Dead Armada stubs** — removed 9 unused `loadTasks`/`loadUsers`/`scannerStart` etc. stub functions from app.js
- **`renderWizOpts()`** — unused wizard options function; no methods ever defined options
- **`!info` command** — removed from command dropdown, multi-select buttons, and task creator
- **Attack request counter** — removed unused `requestCount`/`atkRequestCount` atomic increments from L7 attack functions

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
