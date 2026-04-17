package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// rawHTTPGet performs a minimal HTTP/1.1 GET over TLS (https) or plain TCP (http).
// Returns status code, response body bytes, and error.
// This replaces net/http for simple GET requests to avoid pulling in the
// massive net/http dependency tree (HTTP/2, mime, multipart, etc).
func rawHTTPGet(rawURL string, headers map[string]string, timeout time.Duration) (int, []byte, error) {
	useTLS := true
	host, path, port := "", "/", ""

	u := rawURL
	if strings.HasPrefix(u, "https://") {
		u = u[8:]
		port = "443"
	} else if strings.HasPrefix(u, "http://") {
		u = u[7:]
		useTLS = false
		port = "80"
	} else {
		return 0, nil, fmt.Errorf("unsupported scheme")
	}

	// Split host and path
	if idx := strings.Index(u, "/"); idx >= 0 {
		host = u[:idx]
		path = u[idx:]
	} else {
		host = u
	}

	// Extract explicit port from host
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}

	addr := net.JoinHostPort(host, port)

	var conn net.Conn
	var err error
	if useTLS {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Build request
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n"
	for k, v := range headers {
		req += k + ": " + v + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, nil, err
	}

	// Read full response
	raw, err := io.ReadAll(conn)
	if err != nil && len(raw) == 0 {
		return 0, nil, err
	}

	// Parse status line
	idx := strings.Index(string(raw), "\r\n")
	if idx < 0 {
		return 0, nil, fmt.Errorf("no status line")
	}
	statusLine := string(raw[:idx])
	// "HTTP/1.1 200 OK"
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return 0, nil, fmt.Errorf("bad status line")
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, fmt.Errorf("bad status code: %s", parts[1])
	}

	// Find body after \r\n\r\n
	hdrEnd := strings.Index(string(raw), "\r\n\r\n")
	if hdrEnd < 0 {
		return code, nil, nil
	}
	body := raw[hdrEnd+4:]

	// Handle chunked transfer-encoding
	hdrBlock := strings.ToLower(string(raw[:hdrEnd]))
	if strings.Contains(hdrBlock, "transfer-encoding: chunked") {
		body = decodeChunked(body)
	}

	return code, body, nil
}

// rawHTTPGetStream performs a minimal HTTP/1.1 GET and returns the body size
// read with timing info, for bandwidth measurement. Avoids buffering the
// entire body into memory.
func rawHTTPGetStream(rawURL string, timeout time.Duration) (totalBytes int64, elapsed float64, err error) {
	useTLS := true
	host, path, port := "", "/", ""

	u := rawURL
	if strings.HasPrefix(u, "https://") {
		u = u[8:]
		port = "443"
	} else if strings.HasPrefix(u, "http://") {
		u = u[7:]
		useTLS = false
		port = "80"
	} else {
		return 0, 0, fmt.Errorf("unsupported scheme")
	}

	if idx := strings.Index(u, "/"); idx >= 0 {
		host = u[:idx]
		path = u[idx:]
	} else {
		host = u
	}

	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}

	addr := net.JoinHostPort(host, port)

	var conn net.Conn
	if useTLS {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, 0, err
	}

	// Skip headers
	buf := make([]byte, 1)
	headerDone := false
	crlfCount := 0
	for !headerDone {
		n, err := conn.Read(buf)
		if n > 0 {
			totalBytes++ // count header bytes temporarily
			if buf[0] == '\r' || buf[0] == '\n' {
				crlfCount++
				if crlfCount == 4 {
					headerDone = true
				}
			} else {
				crlfCount = 0
			}
		}
		if err != nil {
			return 0, 0, err
		}
	}
	totalBytes = 0 // reset, only count body

	start := time.Now()
	readBuf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(readBuf)
		totalBytes += int64(n)
		if err != nil {
			break
		}
	}
	elapsed = time.Since(start).Seconds()
	return totalBytes, elapsed, nil
}

// decodeChunked decodes a chunked HTTP response body.
func decodeChunked(data []byte) []byte {
	var result []byte
	s := string(data)
	for {
		// Find chunk size line
		idx := strings.Index(s, "\r\n")
		if idx < 0 {
			break
		}
		sizeStr := strings.TrimSpace(s[:idx])
		if sizeStr == "" {
			break
		}
		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil || size == 0 {
			break
		}
		s = s[idx+2:]
		if int64(len(s)) < size {
			result = append(result, []byte(s)...)
			break
		}
		result = append(result, []byte(s[:size])...)
		s = s[size:]
		if strings.HasPrefix(s, "\r\n") {
			s = s[2:]
		}
	}
	return result
}

// extractJSONStringField extracts a string value for a given key from JSON.
// Handles: "key":"value" and "key": "value"
// This is a minimal parser to avoid importing encoding/json and reflect.
func extractJSONStringField(data, key string) string {
	search := "\"" + key + "\""
	idx := strings.Index(data, search)
	if idx < 0 {
		return ""
	}
	rest := data[idx+len(search):]
	// Skip : and whitespace
	rest = strings.TrimLeft(rest, ": \t\n\r")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// extractJSONIntField extracts an integer value for a given key from JSON.
// Handles: "key":123 and "key": 123
func extractJSONIntField(data, key string) (int, bool) {
	search := "\"" + key + "\""
	idx := strings.Index(data, search)
	if idx < 0 {
		return 0, false
	}
	rest := data[idx+len(search):]
	rest = strings.TrimLeft(rest, ": \t\n\r")
	// Read digits
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	v, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseDoHAnswers parses a DoH JSON response and returns (type, data) pairs.
// Handles the standard {"Answer":[{"type":N,"data":"..."},...]} format
// from Cloudflare, Google, Quad9 DoH endpoints.
func parseDoHAnswers(body string) (answers []struct{ Type int; Data string }) {
	// Find "Answer" array
	ansIdx := strings.Index(body, "\"Answer\"")
	if ansIdx < 0 {
		return nil
	}
	rest := body[ansIdx:]
	// Find opening [
	arrStart := strings.Index(rest, "[")
	if arrStart < 0 {
		return nil
	}
	rest = rest[arrStart:]
	// Find closing ]
	arrEnd := strings.Index(rest, "]")
	if arrEnd < 0 {
		return nil
	}
	arrBody := rest[1:arrEnd]

	// Split by }, { to get individual objects
	for len(arrBody) > 0 {
		objStart := strings.Index(arrBody, "{")
		if objStart < 0 {
			break
		}
		objEnd := strings.Index(arrBody[objStart:], "}")
		if objEnd < 0 {
			break
		}
		obj := arrBody[objStart : objStart+objEnd+1]
		arrBody = arrBody[objStart+objEnd+1:]

		typ, ok := extractJSONIntField(obj, "type")
		if !ok {
			continue
		}
		data := extractJSONStringField(obj, "data")
		answers = append(answers, struct{ Type int; Data string }{typ, data})
	}
	return answers
}
