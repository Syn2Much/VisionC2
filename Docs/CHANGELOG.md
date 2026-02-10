
## ☾℣☽ VisionC2 Changelog

### v2.1 — Feb 2026

**Full Unix Daemonization**

* New Bot Process performs complete daemonization at startup

  * Re-exec with env marker, parent exit, init adoption
  * New session (`setsid`), `/` chdir, `umask(0)`
  * stdio redirected to `/dev/null`
* Debug safeguard: daemonization skipped in `debugMode` to preserve `deoxys()` logging


**Anti-Analysis Hardening**

* Expanded sandbox detection: 30+ additional Unix analysis tools (debuggers, RE, network capture, malware analysis, syscall monitoring, scanners, memory forensics)
* Enhanced parent-process debugger checks (incl. lldb, ida, ghidra, frida, sysdig, bpftrace)
* Sandbox behavior updated: randomized 24–27h sleep, then clean `os.Exit(0)`

  * Evades dynamic analysis timeouts
  * Avoids suspicious fast-exit signals

**Registration Timeout Fix**

* Fixed 20s disconnect caused by speed test blocking the auth→register path
  * Bot metadata (ID, arch, RAM, CPU, proc, uplink) now pre-computed once in `main()` before the connection loop
  * REGISTER sent instantly after AUTH_SUCCESS — no more timeout race
  * CNC registration timeout increased to 25s 
* Cached metadata stored in package-level vars, reused across reconnects

**Build Fix**

* `build.sh` now compiles directly into `bins/` (was building to project root then `mv`)
* Removed stale binary cleanup step — no longer needed


---

### v2.0 — Feb 2026

**Bot Single-Instance & Speed Cache**

* Persistent speed test cache (`/tmp/.net_metric`) — avoids re-running bandwidth test on every reconnect
* PID-based single-instance lock (`/tmp/.net_lock`) — new instance kills old via SIGTERM/SIGKILL and takes over
* Both files use `/tmp` namespace, auto-cleaned on reboot so stale state never persists

---

### v1.9 — Feb 2026

**Bot Metadata Expansion**

* GeoIP country lookup on bot connect (ip-api.com, no DB needed)
* Process name reporting (disguised binary name visible in TUI)
* Uplink speed measurement (in-memory bandwidth test, no files written)
* Extended REGISTER protocol: `version:botID:arch:ram:cpu:procname:uplink`

**TUI Bot List Overhaul**

* New columns: GEO, PROCESS, UPLINK
* Country code highlighted in yellow, process name in purple, uplink in green
* Fixed UPX stripping tool corrupting binaries (preserved structural UPX markers)
  
### v1.8 — Feb 2026

**Features**

* CPU core tracking (per bot + total in stats bar)
* TUI proxy URL field for L7 attacks
* Cyberpunk-themed Attack Center UI

**Proxy Optimizations**

* Bot-side proxy fetching (no CNC validation, max RPS)
* Round-robin rotation with 2s timeouts

**Build Fixes**

* Moved around some files for readability
* UPX compression fix
* Setup.py copies binary to project root as `server`
* Flexible cert paths (works from root or cnc dir)
* Update CNC with Prettier Banners
* Modular Bot/CNC file structure improved

---

### v1.7 — Feb 2026

**Full TUI Control Panel**

* Complete interactive terminal UI (default mode via `./cnc`)
* Real-time bot dashboard with shell access & management commands
* Consolidated Attack Center with live countdowns & progress
* SOCKS5 proxy manager with status controls
* Toast notifications & connection history logs

**Optimizations & Docs**

* HTTP/L7 improvements: connection pooling & keep-alive
* Rewritten documentation (USAGE.md, COMMANDS.md) for TUI
* Improved Setup.py flow and helper text

### v1.6 — Feb 2026

**Core Improvements**

* DNS: Prioritizes Cloudflare DoH over system DNS
* Persistence: Cron-based auto-restart on bot death
* Proxies: Validated in parallel before attacks
* Reduced bot-to-CNC status chatter

**UI Updates**

* Redesigned login screen with animations & lockout
* Streamlined command menus (`attack`/`methods` split)

---

### v1.5 — January 2026

#### 🔧 Build & Tooling

* **Automatic UPX Signature Stripping**

  * `deUPX.py` added and integrated into `build.sh`
  * Runs automatically post-setup to reduce static detection

#### 📚 Documentation

* **Full Code Documentation**

  * CNC and Bot functions fully commented
* **Command Reference**

  * Moved to `cnc/COMMANDS.md`
* **Setup Summary**

  * Configuration summary printed after setup

#### 🤖 Bot Enhancements

* **+50 User-Agents**

  * Expanded Layer 7 fingerprints
* **DoH-First C2 Resolution**

  * Resolution order: DoH TXT → DNS TXT → A → Direct IP

---

### v1.4 — January 2026

#### 🚀 Features

* **Proxy List Support (Layer 7)**

  * Commands: `!http`, `!https`, `!tls`, `!cfbypass`
  * Formats: `ip:port`, `ip:port:user:pass`, `http://`, `socks5://`
  * Example:

    ```
    !http target.com 443 60 -p https://example.com/proxies.txt
    ```

---

### v1.3 — January 2026

#### 🚀 Features

* **RAM Tracking**

  * Bots report total RAM on registration
* **Debug Logging**

  * Connection, TLS, auth, registration, command flow
* **CF / TLS Bypass Improvements**

  * Stability and reliability updates

---

### v1.2 — January 2026

#### 🔒 Security

* **C2 Address Obfuscation**

  * RC5 → RC4
  * XOR → RC4 → MD5 → Base64

#### 🛠️ Tooling

* **Automated `setup.py`**
* **RCE & Proxy Modules**
* **Early CF/TLS bypass support**

---

### v1.1 — December 2025

#### 🎉 Initial Release

* **TLS 1.3 Encrypted Communications**
* **14-Architecture Cross-Compilation**

  * amd64, 386, arm, arm64, mips, mipsle, mips64, mips64le
* **HMAC Challenge-Response Authentication**

---

## Version History Summary

| Version | Date     | Highlights                                          |
| ------- | -------- | --------------------------------------------------- |
| v2.2    | Feb 2026 | Expanded anti-analysis, benign sleep, file merge     |
| v2.1    | Feb 2026 | Full Unix daemonization, signal hardening            |
| v2.0    | Feb 2026 | Single-instance lock, speed cache                    |
| v1.9    | Feb 2026 | GeoIP, process name, uplink speed, TUI overhaul      |
| v1.8    | Feb 2026 | CPU tracking, proxy UI, build fixes                  |
| v1.7    | Feb 2026 | Full TUI panel, HTTP optimizations, consolidated UI  |
| v1.6    | Feb 2026 | DoH-first target resolve, persist fix, UI overhaul   |
| v1.5    | Feb 2026 | UPX stripping, docs, +50 user agents                 |
| v1.4    | Jan 2026 | Proxy support for Layer 7                            |
| v1.3    | Jan 2026 | RAM tracking, debug logging                          |
| v1.2    | Jan 2026 | RC4 obfuscation, setup automation                    |
| v1.1    | Dec 2025 | Initial release                                      |

---

---
