
## 📋 Changelog

All notable changes to **VisionC2** are documented in this file.

---

### v1.5 — February 2026

#### 🔧 Build & Tooling

* **Automatic UPX Signature Stripping**

  * Binary protection now runs automatically at the end of setup
  * Added `deUPX.py` for automated UPX pattern removal
  * Integrated into `build.sh` for seamless post-build obfuscation
  * Reduces static string analysis and signature-based detection 

#### 📚 Documentation

* **Comprehensive Code Comments**

  * Full developer documentation across CNC and Bot code
  * All CNC functions include detailed descriptions
  * All Bot functions documented with parameter explanations
* **Command Reference**

  * Moved to `cnc/COMMANDS.md`
  * Includes command usage, examples, and permission requirements
* **Setup Summary**

  * Setup wizard now prints a full configuration summary on completion

#### 🤖 Bot Enhancements

* **+50 Additional User-Agents**

  * Expanded Layer 7 fingerprint diversity
  * Improves HTTP-based attack effectiveness

---

### v1.4 — January 2026

#### 🚀 New Features

* **Proxy List Support for Layer 7 Attacks**

  * Supported commands: `!http`, `!https`, `!tls`, `!cfbypass`
  * Supports multiple proxy formats:

    * `ip:port`
    * `ip:port:user:pass`
    * `http://`, `socks5://`
  * Example usage:

    ```
    !http target.com 443 60 -p https://example.com/proxies.txt
    ```

---

### v1.3 — January 2026

#### 🚀 New Features

* **RAM Tracking**

  * Bots now report total system RAM during registration
  * Displayed in bot listings (e.g., `RAM: 4.0GB`)
* **Comprehensive Debug Logging**

  * TCP dial and connection attempts
  * TLS handshake and cipher suite details
  * Authentication challenge/response flow
  * Bot registration data
  * Command execution tracking
  * PING/PONG handling
* **CF / TLS Bypass Improvements**

  * Stability and reliability improvements for bypass-related commands

---

### v1.2 — January 2026

#### 🔒 Security Enhancements

* **C2 Address Obfuscation**

  * Encryption method changed from RC5 to RC4 for compatibility
  * 4-layer obfuscation:

    * XOR → RC4 → MD5 → Base64
  * Prevents static extraction of C2 addresses

#### 🛠️ Tooling & Modules

* **Automated `setup.py`**

  * Simplified initial configuration and rebuilds
* **RCE & Proxy Modules**

* **Early support for CF/TLS bypass methods**

---

### v1.1 — December 2025

#### 🎉 Initial Release

* **TLS 1.3 Encrypted Communications**

  * Perfect Forward Secrecy enabled
  * Modern cipher suites enforced
* **14-Architecture Cross-Compilation**

  * Linux: amd64, 386, arm, arm64, mips, mipsle, mips64, mips64le
  * Additional embedded targets
* **HMAC Challenge-Response Authentication**

  * Prevents unauthorized bot impersonation
  * Magic code validation

---

## Version History Summary

| Version | Date     | Highlights                                                   |
| ------- | -------- | ------------------------------------------------------------ |
| v1.5    | Feb 2026 | Auto UPX stripping, comprehensive code docs, +50 user agents |
| v1.4    | Jan 2026 | Proxy list support for Layer 7 attacks                       |
| v1.3    | Jan 2026 | RAM tracking, debug logging, UI updates, CF/TLS bypass       |
| v1.2    | Jan 2026 | RC4 obfuscation, automated setup, RCE & proxy modules        |
| v1.1    | Dec 2025 | Initial release — TLS 1.3, 14 architectures                  |

---

