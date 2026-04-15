package main

import (
	"context"
	"crypto"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil"
	ted25519 "github.com/cretz/bine/torutil/ed25519"
)

const onionKeyFile = "onion_key.pem"

// getTorDataDir returns an absolute path for the tor data directory.
// Prefers cnc/tor_data relative to CWD (when run from project root),
// then falls back to tor_data next to the binary (symlinks resolved).
func getTorDataDir() string {
	// Prefer cnc/tor_data when running from project root
	if _, err := os.Stat("cnc"); err == nil {
		abs, err := filepath.Abs("cnc/tor_data")
		if err == nil {
			return abs
		}
	}
	// Fallback: place next to the binary
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("/tmp", "tor_data")
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		real = exe
	}
	return filepath.Join(filepath.Dir(real), "tor_data")
}

// StartTorWebServer starts the web panel as a Tor hidden service (.onion)
// The onion key is persisted so the .onion address stays the same across restarts.
func StartTorWebServer(handler http.Handler) error {
	torDataDir := getTorDataDir()
	fmt.Println("[TOR] Starting Tor process... (this may take 30-60 seconds)")
	fmt.Printf("[TOR] Data directory: %s\n", torDataDir)

	// Ensure data directory exists
	if err := os.MkdirAll(torDataDir, 0700); err != nil {
		return fmt.Errorf("failed to create tor data dir: %w", err)
	}

	// Start embedded tor process
	t, err := tor.Start(context.Background(), &tor.StartConf{
		DataDir:     torDataDir,
		DebugWriter: nil,
	})
	if err != nil {
		return fmt.Errorf("failed to start tor (is 'tor' installed?): %w", err)
	}

	// Wait for tor to be ready
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer dialCancel()

	// Load or generate persistent onion key
	key, err := loadOrGenerateOnionKey()
	if err != nil {
		return fmt.Errorf("failed to load/generate onion key: %w", err)
	}

	// Create the hidden service - listen on port 80 externally (standard for .onion)
	onion, err := t.Listen(dialCtx, &tor.ListenConf{
		RemotePorts: []int{80},
		Key:         key,
		Version3:    true,
	})
	if err != nil {
		return fmt.Errorf("failed to create onion service: %w", err)
	}

	onionAddr := onion.ID + ".onion"
	fmt.Println("[TOR] ===================================================")
	fmt.Printf("[TOR]  Onion address: http://%s\n", onionAddr)
	fmt.Println("[TOR] ===================================================")
	fmt.Println("[TOR] Web panel is ONLY accessible via Tor Browser")

	// Save the onion address to a file for easy reference
	os.WriteFile(filepath.Join(torDataDir, "onion_address.txt"), []byte("http://"+onionAddr+"\n"), 0600)

	// Serve HTTP over the onion listener
	srv := &http.Server{
		Handler: handler,
	}
	return srv.Serve(onion)
}

// loadOrGenerateOnionKey loads a persisted ed25519 key or generates a new one.
// This keeps the .onion address stable across restarts.
func loadOrGenerateOnionKey() (crypto.PrivateKey, error) {
	keyPath := filepath.Join(getTorDataDir(), onionKeyFile)

	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "ED25519 PRIVATE KEY" {
			fmt.Println("[TOR] Loaded existing onion key (address will be the same)")
			// Reconstruct bine ed25519 key from raw bytes
			privKey := ted25519.PrivateKey(block.Bytes)
			return privKey, nil
		}
	}

	// Generate new key
	fmt.Println("[TOR] Generating new onion key pair...")
	keyPair, err := ted25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	privKey := keyPair.PrivateKey()

	// Log what the onion address will be
	onionAddr := torutil.OnionServiceIDFromV3PublicKey(keyPair.PublicKey())
	fmt.Printf("[TOR] New onion address will be: %s.onion\n", onionAddr)

	// Save raw key bytes for persistence
	pemBlock := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: privKey,
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		return nil, fmt.Errorf("failed to save onion key: %w", err)
	}

	return privKey, nil
}
