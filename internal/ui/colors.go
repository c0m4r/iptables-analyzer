package ui

import "github.com/charmbracelet/lipgloss"

// ──────────────────────────────────────────────────────────────
// Color palette  —  adaptive: Dark / Light terminal variants.
//
// Each entry is an AdaptiveColor{Light, Dark} so lipgloss picks
// the right shade automatically based on terminal background.
//
// Dark-bg tones (current default):
//   Accent:  "39"   bright cyan-blue
//   Muted:   "242"  mid-gray
//   Faint:   "236"  dark gray
//   Text:    "253"  near-white
//   Green:   "35"   teal-green
//   Yellow:  "178"  amber
//   Red:     "167"  soft red
//   Magenta: "132"  muted magenta
//   Cyan:    "73"   steel-cyan
//
// Light-bg counterparts (darker shades for readability on white):
//   Accent:  "26"   dark blue
//   Muted:   "240"  dark gray
//   Faint:   "246"  medium gray
//   Text:    "235"  near-black
//   Green:   "28"   dark green
//   Yellow:  "130"  dark amber
//   Red:     "124"  dark red
//   Magenta: "90"   dark purple
//   Cyan:    "31"   dark teal
// ──────────────────────────────────────────────────────────────

var (
	// ── Palette ──────────────────────────────────────────────
	accent  = lipgloss.AdaptiveColor{Light: "26", Dark: "39"}
	muted   = lipgloss.AdaptiveColor{Light: "240", Dark: "242"}
	faint   = lipgloss.AdaptiveColor{Light: "246", Dark: "236"}
	text    = lipgloss.AdaptiveColor{Light: "235", Dark: "253"}
	green   = lipgloss.AdaptiveColor{Light: "28", Dark: "35"}
	yellow  = lipgloss.AdaptiveColor{Light: "130", Dark: "178"}
	red     = lipgloss.AdaptiveColor{Light: "124", Dark: "167"}
	magenta = lipgloss.AdaptiveColor{Light: "90", Dark: "132"}
	cyan    = lipgloss.AdaptiveColor{Light: "31", Dark: "73"}

	// ── Severity ─────────────────────────────────────────────
	styleCritical = lipgloss.NewStyle().Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "255", Dark: "255"}).
			Background(magenta)
	styleHigh   = lipgloss.NewStyle().Bold(true).Foreground(red)
	styleMedium = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	styleLow    = lipgloss.NewStyle().Foreground(cyan)
	styleInfo   = lipgloss.NewStyle().Foreground(muted)

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
	styleGradeB = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "22", Dark: "71"})
	styleGradeC = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	styleGradeD = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "166", Dark: "208"})
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

func gradeColor(grade string) lipgloss.TerminalColor {
	switch grade {
	case "A":
		return green
	case "B":
		return lipgloss.AdaptiveColor{Light: "22", Dark: "71"}
	case "C":
		return yellow
	case "D":
		return lipgloss.AdaptiveColor{Light: "166", Dark: "208"}
	default:
		return red
	}
}
