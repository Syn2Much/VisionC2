## ☾℣☽ VisionC2 Changelog 

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

### v1.6 — Feb 2026
**Core Improvements**
* DNS: Prioritizes Cloudflare DoH over system DNS
* Persistence: Cron-based auto-restart on bot death
* Proxies: Validated in parallel before attacks
* Reduced bot-to-CNC status chatter

**UI Updates**
* Redesigned login screen with animations & lockout
* Streamlined command menus (`attack`/`methods` split)

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
