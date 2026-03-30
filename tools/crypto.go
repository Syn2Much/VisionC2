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
	"os"
	"regexp"
	"strings"
)

// Must match the XOR byte functions in bot/opsec.go
// Patched by setup.py at build time — all zeros until then
var key = []byte{
	0x10 ^ 0xF0, // mew         — patched by setup.py
	0xF4 ^ 0xF1, // mewtwo      — patched by setup.py
	0x2A ^ 0x99, // celebi      — patched by setup.py
	0x60 ^ 0x11, // jirachi     — patched by setup.py
	0xC9 ^ 0x05, // shaymin     — patched by setup.py
	0x40 ^ 0x88, // phione      — patched by setup.py
	0x08 ^ 0xCB, // manaphy     — patched by setup.py
	0x73 ^ 0x38, // victini     — patched by setup.py
	0x18 ^ 0xB9, // keldeo      — patched by setup.py
	0xF3 ^ 0x63, // meloetta    — patched by setup.py
	0x75 ^ 0x57, // genesect    — patched by setup.py
	0xF7 ^ 0x6E, // diancie     — patched by setup.py
	0x1C ^ 0x56, // hoopa       — patched by setup.py
	0xFD ^ 0xE5, // volcanion   — patched by setup.py
	0xED ^ 0xF2, // magearna    — patched by setup.py
	0xB3 ^ 0xE5, // marshadow   — patched by setup.py
	0xFC ^ 0x31, // zeraora     — patched by setup.py
	0x82 ^ 0x9B, // zarude      — patched by setup.py
	0x2F ^ 0xF8, // regieleki   — patched by setup.py
	0xA1 ^ 0xA0, // regidrago   — patched by setup.py
	0x77 ^ 0x28, // glastrier   — patched by setup.py
	0xB3 ^ 0x67, // spectrier   — patched by setup.py
	0xFF ^ 0x99, // calyrex     — patched by setup.py
	0x9B ^ 0x9B, // wyrdeer     — patched by setup.py
	0xEF ^ 0xBD, // kleavor     — patched by setup.py
	0x91 ^ 0x64, // ursaluna    — patched by setup.py
	0x09 ^ 0xBA, // basculegion — patched by setup.py
	0x78 ^ 0xE0, // sneasler    — patched by setup.py
	0x8C ^ 0x5F, // overqwil    — patched by setup.py
	0xB6 ^ 0xAE, // enamorus    — patched by setup.py
	0x62 ^ 0x85, // tinkaton    — patched by setup.py
	0x45 ^ 0x70, // annihilape  — patched by setup.py
}

// ============================================================================
// CORE ENCRYPT / DECRYPT
// ============================================================================

func encrypt(plaintext string) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
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
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
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
