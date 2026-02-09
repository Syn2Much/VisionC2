
<div align="center">

# Vision C2

**Vision** is a Go-based Command & Control framework featuring one-click setup, TLS-secured communications, advanced obfuscation techniques, sandbox evasion, and cross-compiled agents for **14+ architectures**.

![Go](https://img.shields.io/badge/Go-1.23.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-009688?style=for-the-badge&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-4c1?style=for-the-badge)

<br>

![Dashboard Screenshot](https://github.com/user-attachments/assets/9c6d9ada-a8ff-499e-8445-8d8ea2409936)

</div>

## ✨ Features

### C2 Interface (TUI)
Built with BubbleTea for intuitive keyboard-controlled navigation:
- **Dashboard**: Real-time bot count, system resource monitoring (RAM/CPU), download speed, and uptime
- **Attack Builder**: Configurable attack methods with target and duration controls
- **Remote Shell**: Interactive shell access (broadcast and per-bot)
- **SOCKS5 Proxy**: Built-in proxy server management (per-bot)
- **Help System**: Integrated documentation and command reference

### Security & Obfuscation
- TLS 1.2+ encrypted communications
- Multi-layer C2 address obfuscation (Base64 → XOR → RC4 → checksum)
- Sandbox and VM detection evasion
- HMAC challenge/response authentication
- No plaintext C2 addresses in binaries

### Cross-Platform Support
- **14+ CPU architectures** via Go cross-compilation
- Native support for Linux, Windows, and macOS
- One-click setup and deployment

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
