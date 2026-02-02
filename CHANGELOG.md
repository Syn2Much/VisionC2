## 📋 Changelog
 
All notable changes to VisionC2 are documented in this file.
 
---
 
### v1.5 - February 2026
 
#### 🔧 Build & Tooling
* **Automatic UPX Signature Stripping** - Binary protection now runs automatically at the end of setup
  * Added `deUPX.py` tool for automating UPX pattern removal from compiled binaries
  * Integrated into `build.sh` for seamless binary obfuscation
  * Protects against binary string analysis and signature-based detection
 
#### 📚 Documentation
* **Comprehensive Code Comments** - Full developer documentation added
  * All CNC functions now include detailed comments and descriptions
  * All Bot functions documented with parameter explanations
  * Helps developers understand, debug, and extend the codebase
* **Command Reference** - Moved to separate `cnc/COMMANDS.md` file
  * Complete documentation for all CNC commands
  * Examples and permission requirements for each command
  * Quick reference card for common operations
* **Setup Summary** - Setup wizard now prints configuration summary after completion
 
#### 🎨 User Interface
* **Banner Update** - Version badge updated to V1.5
* **README Improvements** - Formatting consistency and clarity improvements
 
#### 🤖 Bot Enhancements
* **+50 Additional User-Agents** - Expanded Layer 7 attack fingerprinting
  * More diverse HTTP headers for better attack effectiveness
 
---
 
### v1.4 - January 31, 2026
 
#### 🚀 New Features
* **Proxy List Support for Layer 7 Attacks** - Route attacks through proxy lists
  * Supports `!http`, `!https`, `!tls`, and `!cfbypass` commands
  * Usage: `!http target.com 443 60 -p https://example.com/proxies.txt`
  * Accepts multiple proxy formats: `ip:port`, `ip:port:user:pass`, `http://`, `socks5://`
 
#### 📚 Documentation
* **Setup Wizard** - Changed from "recommended" to "required" for C2 encryption
* **WIP/TODO** - Updated roadmap with new planned features
* **Credentials** - Updated default credential documentation

#### 🐛 Bug Fixes
* **Type Mismatch** - Fixed type mismatch in RAM retrieval function
 
---
 
### v1.3 - January 29, 2026
 
#### 🚀 New Features
* **RAM Tracking** - Bots now report total system RAM on registration
  * RAM displayed in bot listings (e.g., `RAM: 4.0GB`)
  * Helps identify high-value targets in the botnet
* **Debug Logging** - Comprehensive debug logging for troubleshooting
  * Connection attempts and TCP dial status
  * TLS handshake with cipher suite info
  * Auth challenge/response flow
  * Bot registration details
  * Command execution tracking
  * PING/PONG handling
 
#### 🎨 User Interface
* **Banner Redesign** - Updated CNC banner with new eye logo

 
#### 📚 Documentation
* **C2 Resolution System** - Documented multi-method resolution
  * DNS TXT Record → DoH Lookup → A Record → Direct IP
* **Architecture Overview** - Added system architecture documentation
* **Performance Metrics** - Server performance benchmarks added
 
---
 
### v1.2 - January 28, 2026
 
#### 🔒 Security Enhancements
* **C2 Address Obfuscation** - Enhanced multi-layer encryption
  * Changed from RC5 to RC4 for improved compatibility
  * 4-layer obfuscation: XOR → RC4 → MD5 → Base64
  * Prevents static analysis of C2 addresses
 
---
 
### v1.1 - December 2025
 
#### 🎉 Initial Release
* **TLS 1.3 Encrypted Communications** - All bot-to-C2 traffic encrypted
  * Perfect forward secrecy enabled
  * Modern cipher suites only
* **14 Architecture Cross-Compilation** - Broad platform support
  * Linux: amd64, 386, arm, arm64, mips, mipsle, mips64, mips64le
  * And more embedded architectures
* **HMAC Challenge-Response Authentication** - Secure bot verification
  * Prevents unauthorized bot impersonation
  * Magic code validation
---
 
## Version History Summary
 
| Version | Date | Highlights |
|---------|------|------------|
| v1.5 | Feb 2026 | Auto UPX stripping, comprehensive code docs, +50 user agents |
| v1.4 | Jan 2026 | Proxy list support for L7 attacks |
| v1.3 | Jan 2026 | RAM tracking, debug logging, UI improvements |
| v1.2 | Jan 2026 | RC4 obfuscation, documentation updates |
| v1.1 | Dec 2025 | Initial release - TLS 1.3, 14 architectures, attack suite |
 
---
 
