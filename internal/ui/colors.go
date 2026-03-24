package ui

import "github.com/charmbracelet/lipgloss"

// ──────────────────────────────────────────────────────────────
// Color palette  —  balanced, readable, not garish.
//
// Base tones use the 256-color cube for consistency across terminals.
//   Accent (cyan):  "39"   — headings, structure
//   Muted:          "242"  — secondary text, borders, details
//   Faint:          "236"  — subtle rules, table chrome
//   Text:           "253"  — primary body text
//
// Semantic colors (kept muted / pastel-ish to avoid eye-burn):
//   Green:   "35"  (success, ACCEPT, FILTERED)
//   Yellow:  "178" (warning)
//   Red:     "167" (danger, DROP, EXPOSED)
//   Magenta: "132" (critical — subtle bg instead of neon)
//   Cyan:    "73"  (info / low severity)
// ──────────────────────────────────────────────────────────────

var (
	// ── Palette ──────────────────────────────────────────────
	accent  = lipgloss.Color("39")  // bright cyan-blue
	muted   = lipgloss.Color("242") // mid-gray
	faint   = lipgloss.Color("236") // dark gray
	text    = lipgloss.Color("253") // near-white
	green   = lipgloss.Color("35")  // teal-green
	yellow  = lipgloss.Color("178") // amber
	red     = lipgloss.Color("167") // soft red
	magenta = lipgloss.Color("132") // muted magenta
	cyan    = lipgloss.Color("73")  // steel-cyan

	// ── Severity ─────────────────────────────────────────────
	styleCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255")).Background(magenta)
	styleHigh     = lipgloss.NewStyle().Bold(true).Foreground(red)
	styleMedium   = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	styleLow      = lipgloss.NewStyle().Foreground(cyan)
	styleInfo     = lipgloss.NewStyle().Foreground(muted)

	// ── UI chrome ────────────────────────────────────────────
	styleHeader    = lipgloss.NewStyle().Bold(true).Foreground(accent)
	styleSubHeader = lipgloss.NewStyle().Bold(true).Foreground(accent)
	styleSuccess   = lipgloss.NewStyle().Bold(true).Foreground(green)
	styleWarning   = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	styleDanger    = lipgloss.NewStyle().Bold(true).Foreground(red)
	styleMuted     = lipgloss.NewStyle().Foreground(muted)
	styleFaint     = lipgloss.NewStyle().Foreground(faint)
	styleBold      = lipgloss.NewStyle().Bold(true).Foreground(text)
	styleText      = lipgloss.NewStyle().Foreground(text)

	// ── Rule targets ─────────────────────────────────────────
	styleAccept = lipgloss.NewStyle().Foreground(green)
	styleDrop   = lipgloss.NewStyle().Foreground(red)
	styleReject = lipgloss.NewStyle().Foreground(red)

	// ── Table ────────────────────────────────────────────────
	styleTableBorder = lipgloss.NewStyle().Foreground(faint)
	styleTableHeader = lipgloss.NewStyle().Bold(true).Foreground(muted)
	styleTableCell   = lipgloss.NewStyle().Foreground(text)

	// ── Grades ───────────────────────────────────────────────
	styleGradeA = lipgloss.NewStyle().Bold(true).Foreground(green)
	styleGradeB = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("71"))
	styleGradeC = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	styleGradeD = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
	styleGradeF = lipgloss.NewStyle().Bold(true).Foreground(red)
)

func severityStyle(s string) lipgloss.Style {
	switch s {
	case "CRITICAL":
		return styleCritical
	case "HIGH":
		return styleHigh
	case "MEDIUM":
		return styleMedium
	case "LOW":
		return styleLow
	default:
		return styleInfo
	}
}

func gradeStyle(grade string) lipgloss.Style {
	switch grade {
	case "A":
		return styleGradeA
	case "B":
		return styleGradeB
	case "C":
		return styleGradeC
	case "D":
		return styleGradeD
	default:
		return styleGradeF
	}
}

func gradeColor(grade string) lipgloss.Color {
	switch grade {
	case "A":
		return green
	case "B":
		return lipgloss.Color("71")
	case "C":
		return yellow
	case "D":
		return lipgloss.Color("208")
	default:
		return red
	}
}
