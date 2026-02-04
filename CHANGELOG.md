
## 📋 Changelog

All notable changes to **VisionC2** are documented below.

---

### v1.7 — February 2026

#### 🎨 Full TUI Control Panel (BubbleTea)

* **Complete Terminal User Interface**
  * Interactive dashboard with real-time bot stats and gradient ASCII banner
  * No telnet/netcat required — TUI is now the default mode
  * `./cnc` starts TUI, `./cnc --split` for legacy telnet mode

* **Bot Management View**
  * Real-time bot list with ID, IP, Architecture, RAM, and Uptime
  * Direct shell access to individual bots via `[enter]`
  * Bot commands: `[i]` Info, `[p]` Persist, `[r]` Reinstall, `[k]` Kill

* **Remote Shell**
  * Interactive shell session with single bot
  * Command history support
  * Hotkeys: `Ctrl+F` Clear, `Ctrl+P` Persist, `Ctrl+R` Reinstall

* **Broadcast Shell**
  * Execute commands on ALL bots simultaneously
  * Targeting filters:
    * `Ctrl+A` — Filter by architecture (amd64, arm64, mips, etc.)
    * `Ctrl+G` — Filter by minimum RAM
    * `Ctrl+B` — Limit max number of bots
  * Confirmation prompts for dangerous broadcast commands

* **Attack Center (Consolidated)**
  * Two-tab interface: `[⚡ Launch]` and `[📊 Ongoing]`
  * Interactive attack form with method picker
  * Live countdown timers and progress bars for ongoing attacks
  * `[s]` Stop all attacks from Ongoing tab
  * Auto-reset form fields after launching attack

* **SOCKS5 Manager**
  * View all bots with socks status (Active/Stopped/None)
  * `[s]` Start socks on selected bot (just enter port, binds to 0.0.0.0)
  * `[x]` Stop socks on selected bot
  * Three view modes: All Bots, Active Socks, Stopped

* **Connection Logs**
  * Full history of bot connects/disconnects
  * Filter by: All, Connections only, Disconnections only

* **Toast Notifications**
  * Non-blocking notifications for attack launches, stops, and actions
  * Auto-expire after 3-4 seconds

#### 🔧 HTTP/Layer 7 Optimizations

* **Connection Pooling & Keep-Alive**
  * Reuses TCP connections across requests
  * HTTP/2 multiplexing support
  * Configurable idle connection limits

* **Chunked Request Body**
  * Randomized chunk sizes (512B–2KB)
  * Delays between chunks to evade WAF detection

* **JA3 Fingerprint Randomization**
  * Randomized TLS cipher suites per connection
  * Mimics diverse browser fingerprints

* **Header Randomization**
  * Random order of HTTP headers
  * Varied Accept-Encoding, Accept-Language values

* **Realistic Request Patterns**
  * Random delays between requests (10-100ms)
  * Referrer chain simulation
  * Cookie persistence across requests

#### 📚 Documentation

* **USAGE.md Rewritten**
  * Full TUI documentation with view screenshots
  * Updated startup instructions (TUI default)
  * Hotkey reference for each view

* **COMMANDS.md Rewritten**
  * Complete TUI hotkey reference
  * Quick reference card
  * Split mode commands for backwards compatibility

* **README.md Updated**
  * TUI feature highlight at top
  * Updated Quick Start for TUI mode
  * Moved TUI from roadmap to "Recently Completed"

---

### v1.6 — February 2026

#### 🔧 Core Improvements

* **Target DNS Resolution Order Changed**
  * Cloudflare DoH now prioritized over system DNS for target resolution
  * System DNS now used as final fallback instead of first attempt
  * Improves reliability in environments with restricted local DNS

* **Cron-Based Persistence on Startup**
  * Adds cron job that checks every minute if bot is running
  * Automatically restarts bot if killed, until system reboot
  * Skips if cron entry already exists to avoid duplicates

* **Proxy Validation Before Attacks**
  * CNC validates all proxies in parallel against httpbin.org
  * Only working proxies sent to bots, all bots use same validated list

* **Reduced Bot-to-CNC Chatter**
  * Bots no longer send attack status messages back to CNC
  * Cleaner server logs, reduced bandwidth overhead, CNC already tracks attacks locally
  
#### 🎨 UI / UX

* **Login Screen Redesign**

  * Animated spinner, eye-themed UI, progress-based auth feedback
  * Success/failure banners and 3-attempt lockout screen
* **Command Menu Rework**

  * Split attack commands into `attack` / `methods`
  * Slimmed `help` menu with shortcut links
  * `?` now shows help + attack hints

---

### v1.5 — February 2026

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

| Version | Date     | Highlights                                         |
| ------- | -------- | ---------------------------------------------------|
| v1.7    | Feb 2026 | Full TUI panel, HTTP optimizations, consolidated UI|
| v1.6    | Feb 2026 | DoH-first target resolve, persist fix, UI overhaul |
| v1.5    | Feb 2026 | UPX stripping, docs, +50 user agents               |
| v1.4    | Jan 2026 | Proxy support for Layer 7                          |
| v1.3    | Jan 2026 | RAM tracking, debug logging                        |
| v1.2    | Jan 2026 | RC4 obfuscation, setup automation                  |
| v1.1    | Dec 2025 | Initial release                                    |

---

---
