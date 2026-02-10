
<div align="center">

# VisionC2

**Advanced, modular C2 framework** focused on evasion, performance, and wide attack protocol coverage.

**⚠️ This project is intended for authorized security research and red teaming only.**

![Vision C2](vision-banner.svg)
---
![Go](https://img.shields.io/badge/Go-1.23.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-009688?style=for-the-badge&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-4c1?style=for-the-badge)

<br>
</div>

## Features
- Modern TLS 1.3 encrypted communication
- Multi-architecture bot binaries (14 targets)
- Full-featured TUI control panel
- Layer 4 & Layer 7 attack methods
- Proxy support (HTTP/SOCKS5)
- Strong anti-analysis & sandbox evasion
- Unix daemonization & single-instance enforcement
- DoH-first C2 resolution
- UPX-aware build stripping

## ⚔️ Attack Methods

### Layer 4 (Network Layer)
| Method      | Protocol | Description                          |
|-------------|----------|--------------------------------------|
| UDP Flood   | UDP      | High-volume 1024-byte payload spam  |
| TCP Flood   | TCP      | Connection exhaustion attack        |
| SYN Flood   | Raw TCP  | SYN packets with random source ports|
| ACK Flood   | Raw TCP  | ACK packet flooding                 |
| GRE Flood   | GRE (47) | GRE protocol packets with max payload|
| DNS Flood   | UDP/DNS  | Random DNS query types (A/AAAA/MX/NS)|

### Layer 7 (Application Layer)
| Method          | Description                                  |
|-----------------|----------------------------------------------|
| HTTP Flood      | GET/POST requests with randomized headers    |
| HTTPS/TLS Flood | TLS handshake exhaustion with request bursts |
| CF Bypass       | CloudFlare bypass via session/cookie reuse  |
| Proxy Support   | All L7 methods support proxy list integration|

![Animation](https://github.com/user-attachments/assets/bab596ce-5269-42ca-ae97-cae26437ae41)
## 🚀 Installation

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    upx-ucl openssl git wget gcc python3 screen build-essential
```

### Quick Setup
1. **Clone the repository**
   ```bash
   git clone https://github.com/Syn2Much/VisionC2.git
   cd VisionC2
   chmod +x *
   ```

2. **Run interactive setup**
   ```bash
   python3 setup.py
   ```
   The setup script will:
   - Generate 4096-bit TLS certificates
   - Create encryption keys and configuration
   - Cross-compile binaries for all supported architectures
   - Build the C2 server binary

3. **Output locations**
   - C2 Server: `./server`
   - Agent Binaries: `./bins/`
   - Configuration: `setup_config.txt`

## 🖥️ Usage

### Starting the C2 Server
**Option 1: TUI Mode (Recommended)**
```bash
screen ./server
```
- Detach: `Ctrl + A` → `D`
- Reattach: `screen -r`

**Option 2: Telnet/Multi-User Mode**
```bash
screen ./server --split
nc your-server-ip 1337
```
- User database: `cnc/users.json`
- Default login keyword: `spamtec`

## 🏗️ Architecture

```text
Agent Startup Sequence
──────────────────────
1. Security Checks
   ├─ VM detection
   ├─ Sandbox analysis
   ├─ Debugger detection
   └─ Exit on positive detection

2. C2 Resolution
   ├─ Multi-layer address decryption
   └─ DNS fallback chain (TXT/A records, direct IP)

3. Secure Handshake
   ├─ TLS 1.2+ encrypted connection
   ├─ HMAC authentication
   └─ Registration payload submission

4. Command Loop
   └─ Encrypted bidirectional communication
```

## 📖 Documentation
- **Changelog**: [`Docs/CHANGELOG.md`](Docs/CHANGELOG.md)
- **Commands**: [`Docs/COMMANDS.md`](Docs/COMMANDS.md)
- **Usage**: [`Docs/USAGE.md`](Docs/USAGE.md)

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND EDUCATIONAL PURPOSES ONLY**

This software is intended for:
- Authorized penetration testing
- Security research and education
- Legitimate stress testing of owned systems

**Usage of this tool for attacking targets without prior mutual consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.**

## 👤 Author

**Syn**
- GitHub: [@syn2much](https://github.com/syn2much)
- Telegram: [@sinackrst](https://t.me/sinackrst)

---

<div align="center">
<sub>Maintained with ❤️ by Syn</sub>
</div>
