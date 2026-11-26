package ui

import "github.com/charmbracelet/lipgloss"

// The colors of the text report. Each is an AdaptiveColor, so that lipgloss
// takes the shade for the background of the terminal: the light variants are
// darker, to stay readable on white.
var (
	accent  = lipgloss.AdaptiveColor{Light: "26", Dark: "39"}   // blue
	muted   = lipgloss.AdaptiveColor{Light: "240", Dark: "245"} // gray, for text of less weight
	text    = lipgloss.AdaptiveColor{Light: "235", Dark: "253"}
	green   = lipgloss.AdaptiveColor{Light: "28", Dark: "35"}
	yellow  = lipgloss.AdaptiveColor{Light: "130", Dark: "178"}
	orange  = lipgloss.AdaptiveColor{Light: "166", Dark: "208"}
	red     = lipgloss.AdaptiveColor{Light: "124", Dark: "167"}
	magenta = lipgloss.AdaptiveColor{Light: "90", Dark: "132"}
	cyan    = lipgloss.AdaptiveColor{Light: "31", Dark: "73"}
)

var (
	// Severity
	styleCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255")).Background(magenta)
	styleHigh     = lipgloss.NewStyle().Bold(true).Foreground(red)
	styleMedium   = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	styleLow      = lipgloss.NewStyle().Foreground(cyan)
	styleInfo     = lipgloss.NewStyle().Foreground(muted)

	// Text
	styleHeader    = lipgloss.NewStyle().Bold(true).Foreground(accent)
	styleSubHeader = lipgloss.NewStyle().Bold(true).Foreground(accent)
	styleSuccess   = lipgloss.NewStyle().Bold(true).Foreground(green)
	styleWarning   = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	styleDanger    = lipgloss.NewStyle().Bold(true).Foreground(red)
	styleMuted     = lipgloss.NewStyle().Foreground(muted)
	styleBold      = lipgloss.NewStyle().Bold(true).Foreground(text)
	styleText      = lipgloss.NewStyle().Foreground(text)
)

func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return styleCritical
	case "HIGH":
		return styleHigh
	case "MEDIUM":
		return styleMedium
	case "LOW":
		return styleLow
	}
	return styleInfo
}

// gradeStyle colors a grade from green for A to red for F. A grade that is
// not a letter, as for an incomplete analysis, takes the color of a warning.
func gradeStyle(grade string) lipgloss.Style {
	color := lipgloss.TerminalColor(yellow)
	switch grade {
	case "A", "B":
		color = green
	case "C":
		color = yellow
	case "D":
		color = orange
	case "F":
		color = red
	}
	return lipgloss.NewStyle().Bold(true).Foreground(color)
}
