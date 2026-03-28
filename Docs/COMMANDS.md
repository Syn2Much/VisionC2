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
| `!rapidreset` | HTTP/2 Rapid Reset (CVE-2023-44487) |

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
| `s` | Quick Start | Start proxy using pre-configured relay + default credentials |
| `c` | Custom Relay | Enter relay:port and credentials manually |
| `d` | Direct Mode | Enter port number, opens local SOCKS5 listener on bot |
| `x` | Stop Socks | Stop proxy on selected bot |
| `r` | Refresh | Update status |
| `q` | Back | Return to dashboard |

### SOCKS5 Modes

**Quick Start (`s`):** Sends `!socks` immediately — bot connects to pre-configured relay endpoints with default credentials.

**Custom Relay (`c`):** Input form for manual `relay:port` and optional credentials override.

**Direct Mode (`d`):** Input form for port number — bot opens a local SOCKS5 listener (no relay needed).

### SOCKS5 Authentication

The proxy supports username/password authentication (RFC 1929). Default credentials are set during `setup.py` (default: `vision:vision`) and baked into the bot binary.

- Update at runtime: `!socksauth <user> <pass>`
- Leave both empty to allow unauthenticated access

### Using the Proxy

After starting, connect via:

```bash
# Via relay (backconnect mode — recommended)
curl --socks5 relay.example.com:1080 -U vision:vision http://example.com

# Via direct mode (bot listener)
curl --socks5 BOT_IP:1080 -U vision:vision http://example.com

# Configure proxychains (add to /etc/proxychains4.conf)
socks5 relay.example.com 1080 vision vision
```

> Full relay deployment guide: [PROXY.md](PROXY.md)

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
| `!socks` | Start SOCKS5 via pre-configured relay endpoints |
| `!socks relay:port` | Backconnect to specific relay |
| `!socks r1:9001,r2:9001` | Multiple relays (comma-separated) |
| `!socks <port>` | Direct mode — open local listener on port |
| `!stopsocks` | Stop all proxies |
| `!socksauth <user> <pass>` | Update SOCKS5 proxy credentials |

---

## 🌐 Tor Web Panel

The web panel is a browser-based interface served over Tor (or clearnet). It provides full bot management, attack launching, SOCKS proxy control, and real-time event monitoring without requiring a terminal.

### Starting the Web Panel

```bash
# Start server with web panel enabled
./server --web

# Access via Tor onion address or configured clearnet endpoint
```

After login, you are presented with a tabbed interface. Switch tabs using the keyboard or by clicking.

### Authentication

The web panel uses session-based authentication. On first load you are redirected to a login page. Enter your VisionC2 username and password (same credentials as Split Mode).

### Tab Navigation

| Key | Tab | Description |
|-----|-----|-------------|
| `1` | Bots | Live bot table with multi-select |
| `2` | SOCKS | SOCKS5 proxy dashboard |
| `3` | Attack | Attack launcher with method config |
| `4` | Activity | Real-time event feed (SSE) |
| `5` | Tasks | Persistent auto-execute commands |
| `6` | Users | User management (add/edit/delete) |

### Global Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1`-`6` | Switch to tab |
| `/` | Focus search / filter bar |
| `?` | Toggle keyboard shortcuts help overlay |
| `Escape` | Close any open modal or overlay |

---

### Tab 1: Bots

Live table of all connected bots with real-time status updates.

#### Display Columns

| Column | Description |
|--------|-------------|
| Select | Checkbox for multi-select (bulk actions) |
| ID | Bot identifier |
| IP | Bot's IP address |
| Arch | CPU architecture (amd64, arm64, mips, etc.) |
| RAM | System memory |
| CPU | Processor info |
| Process | Running process name |
| Country | GeoIP country |
| Group | Assigned bot group |
| Uplink | Connection relay/uplink |
| Connected | Time the bot connected |
| Uptime | Duration since connection |
| Health | Live health indicator |

#### Interactions

| Action | Effect |
|--------|--------|
| Click a row | Open Bot Management Popup (see below) |
| Double-click a row | Open Web Shell directly |
| Check multiple rows | Select bots for bulk actions |
| Search bar (`/`) | Filter bots by any column value |

---

### Tab 2: SOCKS

Dashboard of active SOCKS5 proxies across all bots.

#### Display Columns

| Column | Description |
|--------|-------------|
| Status | Proxy running state |
| Relay | Connected relay endpoint |
| User | SOCKS auth username |
| Started | Time the proxy was started |

#### Interactions

| Action | Effect |
|--------|--------|
| Start button | Launch SOCKS proxy on the selected bot (opens SOCKS Launcher Modal) |
| Stop button | Terminate proxy on the selected bot |

---

### Tab 3: Attack

Interactive attack launcher with method-specific configuration.

#### Form Fields

| Field | Description |
|-------|-------------|
| Method | Dropdown selector grouped by UDP, TCP, and L3 categories |
| Target | IP address or hostname |
| Port | Target port |
| Duration | Attack duration in seconds |
| Bot Scope | Target all bots, selected bots, or by filter |
| Advanced Options | Method-specific parameters (populated per method) |

#### Buttons

| Button | Effect |
|--------|--------|
| Fire | Launch the configured attack (confirmation dialog shown) |
| Stop | Stop the currently running attack (confirmation dialog shown) |

---

### Tab 4: Activity

Live event feed updated in real time via Server-Sent Events (SSE).

#### Event Types

| Event | Description |
|-------|-------------|
| Bot Join | A new bot connected to the C2 |
| Bot Leave | A bot disconnected |
| Command Sent | A command was dispatched to one or more bots |

The feed auto-scrolls and requires no manual refresh.

---

### Tab 5: Tasks

Persistent commands that auto-execute on every bot join. Useful for maintaining consistent state across the fleet.

#### Fields

| Field | Description |
|-------|-------------|
| Command | The command to execute on join |
| Run Once | When enabled, prevents re-execution if the bot reconnects |

Tasks run automatically whenever a bot connects. Use the "Run Once" option for one-time setup commands that should not repeat on reconnect.

---

### Tab 6: Users

User account management panel.

#### Actions

| Action | Description |
|--------|-------------|
| Add User | Create a new user with username, password, permission level, and expiry date |
| Edit User | Modify an existing user's permissions or expiry |
| Delete User | Remove a user account |

---

### Bot Management Popup

Opened by clicking a bot row in the Bots tab. Shows detailed bot information and action buttons.

#### Bot Details Displayed

| Field | Description |
|-------|-------------|
| ID | Bot identifier |
| IP | IP address |
| Arch | CPU architecture |
| RAM | System memory |
| CPU | Processor info |
| Process | Running process name |
| Country | GeoIP country |
| Uplink | Connection relay |
| Connected | Connection timestamp |

#### Action Buttons

| Button | Effect |
|--------|--------|
| Shell | Open Web Shell to this bot |
| Start SOCKS | Launch SOCKS Launcher Modal for this bot |
| Stop SOCKS | Terminate running proxy on this bot |
| Group | Assign or change the bot's group |
| Info | Request `!info` from the bot |
| Persist | Send `!persist` to the bot |
| Reinstall | Send `!reinstall` to the bot |
| Kill | Send `!lolnogtfo` to the bot |

---

### Web Shell

Full remote shell session in a browser modal. WebSocket-powered for real-time interaction.

#### Interface Layout

| Element | Description |
|---------|-------------|
| Shell output area | Scrollable terminal output |
| Command input | Text input at the bottom for typing commands |
| File browser sidebar | Click-to-navigate directory tree |
| Breadcrumb path bar | Current working directory with clickable segments |
| Quick nav buttons | `/` (root), `~` (home), `..` (parent), `/tmp` |
| Bot info sidebar | Live details for the connected bot |

#### Multi-Tab Support

Multiple shell sessions can be open simultaneously. Each bot gets its own tab. Click tabs to switch between active shells.

#### Command Input Features

| Feature | Description |
|---------|-------------|
| `Enter` | Send command |
| `Up` / `Down` arrows | Cycle through command history |
| `Tab` (on `!` commands) | Tab completion |

#### Action Bar Buttons

| Button | Effect |
|--------|--------|
| Save History | Download the shell session output |
| Copy Output | Copy shell output to clipboard |
| Net Scan | Run a network scan from the bot |
| Shortcuts | Open Post-Exploit Shortcuts menu |
| SOCKS | Open SOCKS Launcher Modal for this bot |
| Clear | Clear the shell output |

#### Post-Exploit Shortcuts Menu

Accessed via the **Shortcuts** button in the action bar. Two categories:

**Quick Actions:**

| Shortcut | Description |
|----------|-------------|
| Persist All | Run persistence across all bots |
| Reinstall All | Force reinstall across all bots |
| Flush Firewall | Drop all firewall rules |
| Kill Logging | Stop logging daemons |
| Clear History | Wipe shell history files |
| Kill Monitors | Terminate monitoring processes |
| Disable Cron | Remove or disable cron jobs |
| Timestomp | Modify file timestamps |
| DNS Flush | Clear the DNS cache |
| Kill Sysmon | Terminate Sysmon process |

**Recon:**

| Shortcut | Description |
|----------|-------------|
| System Info | OS, hostname, kernel details |
| Network Info | Interfaces, routes, DNS |
| Open Ports | Listening ports and services |
| Users w/ Shell | Accounts with login shells |
| SUID Binaries | Find SUID/SGID executables |
| Writable Dirs | World-writable directories |
| Cron Jobs | Enumerate scheduled tasks |
| Docker/LXC | Detect containerization |
| SSH Keys | Find SSH keys and authorized_keys |
| Credentials | Search for credential files |
| Sudo Check | Enumerate sudo privileges |
| Proc Tree | Running process tree |
| Kernel Version | Kernel version and build info |
| Mount Points | Mounted filesystems |

---

### SOCKS Launcher Modal

Opened from the Bot Management Popup, the SOCKS tab, or the Web Shell action bar.

#### Mode Selector

| Mode | Description |
|------|-------------|
| Direct | Bot opens a local SOCKS5 listener on a specified port |
| Relay (Backconnect) | Bot connects back to a relay server (recommended) |

#### Form Fields

| Field | Description | Notes |
|-------|-------------|-------|
| Mode | Direct or Relay | Toggle at top of modal |
| Relay | Relay endpoint | Dropdown auto-populated from `setup.py` config; Relay mode only |
| Username | SOCKS auth username | Pre-filled from `setup.py` defaults |
| Password | SOCKS auth password | Pre-filled from `setup.py` defaults |
| Port | Listener port | Direct mode only |

---

### Global Web Panel Features

| Feature | Description |
|---------|-------------|
| Search/Filter | Filter the bot table by any field using the search bar (`/`) |
| Toast Notifications | Brief popup messages confirming actions or reporting errors |
| Real-Time Updates | All views update live via Server-Sent Events (SSE) — no manual refresh needed |
| Session Auth | Login session persists until logout or expiry |

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
├─────────────────────────────────────────────────────────────────┤
│ WEB PANEL                                                       │
│   1-6       Switch tabs       /        Focus search             │
│   ?         Help overlay      Esc      Close modal              │
│   Tabs: 1=Bots  2=SOCKS  3=Attack  4=Activity  5=Tasks  6=Users│
│   Web Shell: Up/Down history  Tab      Complete ! commands      │
│   Shortcuts button → Post-exploit quick actions & recon         │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Notes

- TUI requires minimum terminal size of 80x24
- All bot commands are logged server-side
- Dangerous commands (persist, reinstall, kill) require confirmation
- Dead bots are automatically cleaned up after 5 minutes
- Web panel updates in real time via SSE — no manual polling required
- Web shell sessions use WebSockets and persist until the modal is closed

---

*VisionC2 - ☾℣☽*
