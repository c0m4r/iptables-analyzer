// Package ui renders a report: as text for a terminal, as JSON and as a
// self-contained HTML page.
package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/report"
	"github.com/charmbracelet/lipgloss"
)

// TextOptions control the text report.
type TextOptions struct {
	// Width is the number of columns to wrap prose to; 0 uses the default.
	Width int
	// Verbose adds the notes, the listening sockets and the sandbox status.
	Verbose bool
	// Rules adds the rules of every chain.
	Rules bool
	// HTMLFile names the HTML report that was written in the same run.
	HTMLFile string
}

const (
	defaultWidth = 100
	minWidth     = 60
	// maxWidth keeps prose readable on very wide terminals.
	maxWidth = 120
)

// Prepare detects the color profile and the background of the terminal while
// the process can still use it freely, and returns the width to wrap to.
// Rendering may then run in the sandbox, where new terminal queries and file
// access are not available.
func Prepare(w io.Writer) int {
	renderer := lipgloss.DefaultRenderer()
	renderer.ColorProfile()
	renderer.HasDarkBackground()
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 0 {
		return clampWidth(columns)
	}
	if f, ok := w.(*os.File); ok {
		if columns := terminalWidth(f); columns > 0 {
			return clampWidth(columns)
		}
	}
	return defaultWidth
}

func clampWidth(width int) int {
	return max(minWidth, min(width, maxWidth))
}

// RenderJSON writes any part of a report as indented JSON.
func RenderJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// trackingWriter remembers the first write error, so that the renderer does
// not have to check every line.
type trackingWriter struct {
	writer io.Writer
	err    error
}

func (w *trackingWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.writer.Write(p)
	if err != nil {
		w.err = err
	}
	return n, err
}

// textReport renders one report.
type textReport struct {
	w     io.Writer
	rep   *report.Report
	opts  TextOptions
	width int
	// both is true when the report covers IPv4 and IPv6, so that findings
	// must say which family they are about.
	both bool
}

// RenderText writes the report for a terminal: the grade first, then what to
// fix, then the findings with their fixes, then what is reachable.
func RenderText(w io.Writer, rep *report.Report, opts TextOptions) error {
	tracked := &trackingWriter{writer: w}
	t := &textReport{w: tracked, rep: rep, opts: opts, width: opts.Width}
	if t.width == 0 {
		t.width = defaultWidth
	}
	t.width = clampWidth(t.width)
	t.both = analyzedFamilies(rep) > 1

	t.header()
	t.score()
	t.notes()
	t.fixFirst()
	t.findings()
	t.reachable()
	if opts.Verbose {
		t.services()
		t.sandbox()
	}
	if opts.Rules {
		t.rules()
	}
	t.footer()
	return tracked.err
}

// RenderScoreLine writes the score in a form that scripts can read: the
// points and the grade.
func RenderScoreLine(w io.Writer, rep *report.Report) error {
	_, err := fmt.Fprintf(w, "%d %s\n", rep.Score.Total, rep.Score.Grade)
	return err
}

// RenderSummaryLine writes one line with the grade and the number of
// findings of each severity.
func RenderSummaryLine(w io.Writer, rep *report.Report) error {
	_, err := fmt.Fprintf(w, "%d %s  %s\n", rep.Score.Total, rep.Score.Grade, countsText(rep.Counts, false))
	return err
}

func (t *textReport) line(format string, args ...any) {
	fmt.Fprintf(t.w, format+"\n", args...)
}

// wrap breaks prose into lines of at most width columns. It never breaks
// inside a word, so that addresses and rule text stay whole.
func wrap(s string, width int) []string {
	var lines []string
	for _, paragraph := range strings.Split(s, "\n") {
		current := ""
		for _, word := range strings.Fields(paragraph) {
			switch {
			case current == "":
				current = word
			case lipgloss.Width(current)+1+lipgloss.Width(word) > width:
				lines = append(lines, current)
				current = word
			default:
				current += " " + word
			}
		}
		lines = append(lines, current)
	}
	return lines
}

// prose writes wrapped text with an indent, in one style.
func (t *textReport) prose(indent string, style lipgloss.Style, s string) {
	for _, line := range wrap(s, t.width-len(indent)) {
		t.line("%s%s", indent, style.Render(line))
	}
}

func (t *textReport) section(title string) {
	t.line("")
	t.line("  %s", styleHeader.Render(title))
}

// header says what was analyzed.
func (t *textReport) header() {
	rep := t.rep
	t.line("%s %s", styleHeader.Render(rep.Tool.Name), styleMuted.Render("v"+rep.Tool.Version+" · "+sourceText(rep)+" · "+timeText(rep)))
	if len(rep.Inputs) > 0 {
		t.prose("", styleMuted, "inputs: "+strings.Join(rep.Inputs, ", "))
	}
	for _, family := range rep.Families {
		summary, warning := familySummary(family)
		if summary == "" {
			continue
		}
		name := "IPv" + strconv.Itoa(family.Version) + ":"
		if warning {
			t.line("%s %s", styleMuted.Render(name), styleDanger.Render(summary))
			continue
		}
		t.prose("", styleMuted, name+" "+summary)
	}
}

func countsText(counts report.Counts, styled bool) string {
	var parts []string
	add := func(n int, label string, style lipgloss.Style) {
		if n == 0 {
			return
		}
		part := strconv.Itoa(n) + " " + label
		if styled {
			part = style.Render(part)
		}
		parts = append(parts, part)
	}
	add(counts.Critical, "critical", styleCritical)
	add(counts.High, "high", styleHigh)
	add(counts.Medium, "medium", styleMedium)
	add(counts.Low, "low", styleLow)
	add(counts.Info, "info", styleInfo)
	if len(parts) == 0 {
		if styled {
			return styleSuccess.Render("no findings")
		}
		return "no findings"
	}
	separator := " · "
	if !styled {
		separator = ", "
	}
	return strings.Join(parts, separator)
}

// bar draws what a category keeps of its points. The two glyphs differ in
// shape, so the bar reads without color.
func bar(kept, maximum int) string {
	const cells = 10
	filled := 0
	if maximum > 0 {
		filled = (kept*cells + maximum/2) / maximum
	}
	color := green
	switch {
	case kept >= maximum:
	case kept*2 >= maximum:
		color = yellow
	default:
		color = red
	}
	// A style around nothing would still write its escape sequences.
	drawn := ""
	if filled > 0 {
		drawn = lipgloss.NewStyle().Foreground(color).Render(strings.Repeat("▰", filled))
	}
	if filled < cells {
		drawn += styleMuted.Render(strings.Repeat("▱", cells-filled))
	}
	return drawn
}

// score shows the grade, the counts and the parts of the score.
func (t *textReport) score() {
	score := t.rep.Score
	t.line("")
	grade := gradeStyle(score.Grade).Render("Grade " + score.Grade)
	t.line("  %s  %s    %s", grade, styleBold.Render(strconv.Itoa(score.Total)+"/100"), countsText(t.rep.Counts, true))
	if score.Cap != "" && score.Complete {
		t.prose("  ", styleWarning, strings.ToUpper(score.Cap[:1])+score.Cap[1:]+".")
	}
	if !score.Complete {
		t.prose("  ", styleWarning, "The grade is incomplete: "+strings.Join(score.Unassessed, ", ")+" could not be assessed.")
	}
	t.line("")
	// Two columns when they fit.
	cells := make([]string, len(score.Categories))
	for i, category := range score.Categories {
		kept := category.Max - category.Lost
		cells[i] = fmt.Sprintf("%-21s %s %s", category.Label, bar(kept, category.Max), styleMuted.Render(fmt.Sprintf("%2d/%d", kept, category.Max)))
	}
	if t.width >= 86 {
		half := (len(cells) + 1) / 2
		for i := 0; i < half; i++ {
			right := ""
			if i+half < len(cells) {
				right = cells[i+half]
			}
			t.line("  %s    %s", cells[i], right)
		}
		return
	}
	for _, cell := range cells {
		t.line("  %s", cell)
	}
}

// notes shows what the reader must know about the analysis. Without
// --verbose only the notes that change how to read the result are shown.
func (t *textReport) notes() {
	var lines []report.Note
	for _, note := range t.rep.Notes {
		if note.Kind == "incomplete" || t.opts.Verbose || note.Area != "services" || !t.rep.ServicesKnown {
			lines = append(lines, note)
		}
	}
	if len(lines) == 0 {
		return
	}
	t.line("")
	for _, note := range lines {
		mark, style := "note", styleMuted
		if note.Kind == "incomplete" {
			mark, style = "not assessed", styleWarning
		}
		t.prose("  ", style, mark+": "+note.Text)
	}
}

// fixFirst lists the findings to start with.
func (t *textReport) fixFirst() {
	top := fixFirst(t.rep)
	if len(top) == 0 {
		return
	}
	t.section("Fix first")
	for i, finding := range top {
		t.titleLine(fmt.Sprintf("    %d. %s", i+1, styleMuted.Render(fmt.Sprintf("%-*s", idWidth, finding.ID))), finding.Title, gainText(finding))
	}
}

// titleLine writes a title with a number at the right margin. A title that
// does not fit continues on the next lines.
func (t *textReport) titleLine(prefix, title, right string) {
	indent := strings.Repeat(" ", lipgloss.Width(prefix))
	lines := wrap(title, t.width-lipgloss.Width(prefix)-len(right)-2)
	for i, line := range lines {
		lead := indent
		if i == 0 {
			lead = prefix
		}
		if i == 0 && right != "" {
			gap := max(2, t.width-lipgloss.Width(prefix)-lipgloss.Width(line)-len(right))
			t.line("%s%s%s%s", lead, styleText.Render(line), strings.Repeat(" ", gap), styleMuted.Render(right))
			continue
		}
		t.line("%s%s", lead, styleText.Render(line))
	}
}

// findings lists what was found, the most severe first, each with the rules
// it is about and what to do.
func (t *textReport) findings() {
	shown := 0
	for _, finding := range t.rep.Findings {
		if finding.Severity > models.SeverityInfo || t.opts.Verbose {
			shown++
		}
	}
	if shown == 0 {
		if len(t.rep.Findings) == 0 {
			t.section("Findings")
			t.line("  %s", styleSuccess.Render("Nothing to report."))
		}
		return
	}
	t.section("Findings")
	for _, finding := range t.rep.Findings {
		if finding.Severity == models.SeverityInfo && !t.opts.Verbose {
			continue
		}
		t.finding(finding)
	}
}

// A finding starts with its severity and its number; the lines below are
// set under the title.
const (
	severityWidth = 9
	idWidth       = 5
)

var findingIndent = strings.Repeat(" ", 2+severityWidth+idWidth)

func (t *textReport) finding(finding report.Finding) {
	t.line("")
	severity := finding.Severity.String()
	label := severityStyle(severity).Render(severity) + strings.Repeat(" ", severityWidth-len(severity))
	title := finding.Title
	var tags []string
	if t.both && len(finding.Families) == 1 && !strings.Contains(title, familyNames(finding.Families)) {
		tags = append(tags, familyNames(finding.Families))
	}
	if finding.Certainty == models.CertaintyPossible {
		tags = append(tags, "possible")
	}
	if len(tags) > 0 {
		title += " (" + strings.Join(tags, ", ") + ")"
	}
	points := ""
	if finding.Points > 0 {
		points = "-" + strconv.Itoa(finding.Points)
	}
	t.titleLine("  "+label+styleMuted.Render(fmt.Sprintf("%-*s", idWidth, finding.ID)), title, points)
	t.prose(findingIndent, styleMuted, finding.Detail)

	limit := 3
	if t.opts.Verbose {
		limit = len(finding.Rules)
	}
	rules := finding.Rules
	if len(finding.Ports) > 1 && !t.opts.Verbose {
		// A finding about many ports names them; the list of translated
		// ports below has their rules.
		rules = nil
	}
	for i, rule := range rules {
		if i >= limit {
			t.line("%s%s", findingIndent, styleMuted.Render(fmt.Sprintf("... and %d more rules (-v)", len(rules)-limit)))
			break
		}
		where := rule.Table + "/" + rule.Chain + " #" + strconv.Itoa(rule.Num)
		if t.both {
			where = "IPv" + strconv.Itoa(rule.Family) + " " + where
		}
		t.line("%s%s  %s", findingIndent, styleLow.Render(where+":"), styleText.Render(rule.Spec))
		if len(rule.Path) > 1 {
			t.prose(findingIndent+"  ", styleMuted, "reached by "+strings.Join(rule.Path[:len(rule.Path)-1], " → "))
		}
	}
	if fix := finding.Fix; fix != nil {
		lines := wrap(fix.Summary, t.width-len(findingIndent)-5)
		for i, line := range lines {
			lead := "     "
			if i == 0 {
				lead = styleSuccess.Render("fix") + "  "
			}
			t.line("%s%s%s", findingIndent, lead, styleText.Render(line))
		}
		for _, step := range fix.Steps {
			t.prose(findingIndent+"     ", styleMuted, step.Text+":")
			// A command is not wrapped: it must stay one line to copy.
			t.line("%s       %s", findingIndent, styleText.Render(step.Command))
		}
	}
}

// reachable shows what other hosts can reach: the ports that INPUT accepts
// and the ports that are translated to other hosts.
func (t *textReport) reachable() {
	rep := t.rep
	entry := func(open report.OpenPort) string {
		name := "all ports that no rule names"
		if !open.Default {
			name = portRange(open.First, open.Last)
		}
		var qualifiers []string
		if len(open.Listeners) > 0 {
			name += " " + strings.Join(open.Listeners, "/")
		}
		if open.Condition != "" {
			qualifiers = append(qualifiers, open.Condition)
		}
		if open.Restriction != "" {
			qualifiers = append(qualifiers, open.Restriction)
		} else if open.Scope != models.ScopeExposed {
			qualifiers = append(qualifiers, scopeWords(open.Scope))
		}
		if len(open.Interfaces) > 0 {
			qualifiers = append(qualifiers, "on "+strings.Join(open.Interfaces, ", "))
		}
		if open.Certainty == models.CertaintyPossible {
			qualifiers = append(qualifiers, "possible")
		}
		if open.Public {
			qualifiers = append(qualifiers, "declared public")
		}
		if t.both && len(open.Families) == 1 {
			qualifiers = append(qualifiers, "IPv"+strconv.Itoa(open.Families[0])+" only")
		}
		if len(qualifiers) > 0 {
			name += " (" + strings.Join(qualifiers, ", ") + ")"
		}
		return name
	}
	block := func(title string, style lipgloss.Style, match func(report.OpenPort) bool) {
		byProtocol := map[string][]string{}
		for _, open := range rep.OpenPorts {
			if match(open) {
				byProtocol[open.Protocol] = append(byProtocol[open.Protocol], entry(open))
			}
		}
		if len(byProtocol) == 0 {
			return
		}
		t.section(title)
		for _, protocol := range []string{"tcp", "udp"} {
			entries := byProtocol[protocol]
			if len(entries) == 0 {
				continue
			}
			limit := 40
			if t.opts.Verbose || len(entries) <= limit {
				limit = len(entries)
			}
			joined := strings.Join(entries[:limit], " · ")
			if limit < len(entries) {
				joined += fmt.Sprintf(" · and %d more (-v)", len(entries)-limit)
			}
			lines := wrap(joined, t.width-9)
			for i, line := range lines {
				lead := "         "
				if i == 0 {
					lead = "    " + styleMuted.Render(fmt.Sprintf("%-5s", protocol))
				}
				t.line("%s%s", lead, style.Render(line))
			}
		}
	}

	any := func(open report.OpenPort) bool { return open.Scope == models.ScopeExposed }
	block("Open to any source", styleText, any)
	block("Open to restricted sources", styleMuted, func(open report.OpenPort) bool { return !any(open) })

	if len(rep.Forwards) > 0 {
		title := "Translated to other hosts"
		t.section(title)
		limit := 30
		if t.opts.Verbose || len(rep.Forwards) <= limit {
			limit = len(rep.Forwards)
		}
		for _, forward := range rep.Forwards[:limit] {
			host := forward.HostAddr
			if host != "" {
				host = bracket(host) + ":"
			}
			from := host + portRange(forward.HostPort, forward.HostPortEnd) + "/" + forward.Protocol
			to := bracket(forward.DestAddr) + ":" + portRange(forward.DestPort, forward.DestPortEnd)
			if forward.Bridge != "" {
				to += " (" + forward.Bridge + ")"
			}
			scope := scopeWords(forward.ForwardScope)
			if forward.Certainty == models.CertaintyPossible && forward.ForwardScope != "" {
				scope += ", possible"
			}
			if t.both {
				from = "IPv" + strconv.Itoa(forward.Family) + " " + from
			}
			style := styleText
			if forward.ForwardScope == "" {
				style = styleMuted
			}
			for i, line := range wrap(from+" → "+to+": "+scope, t.width-6) {
				lead := "      "
				if i == 0 {
					lead = "    "
				}
				t.line("%s%s", lead, style.Render(line))
			}
		}
		if limit < len(rep.Forwards) {
			t.line("    %s", styleMuted.Render(fmt.Sprintf("... and %d more (-v)", len(rep.Forwards)-limit)))
		}
		t.prose("    ", styleMuted, "These ports are translated in nat/PREROUTING and pass filter/FORWARD, not filter/INPUT.")
	}

	if len(rep.OpenPorts) == 0 && len(rep.Forwards) == 0 {
		analyzed := false
		for _, family := range rep.Families {
			analyzed = analyzed || family.Status == string(models.FamilyAnalyzed)
		}
		if analyzed {
			t.section("Open to other hosts")
			t.line("    %s", styleSuccess.Render("No port accepts new connections from other hosts."))
		}
	}
}

// services lists every listening socket with its status.
func (t *textReport) services() {
	if len(t.rep.Services) == 0 {
		return
	}
	t.section("Listening sockets")
	for _, svc := range t.rep.Services {
		address := svc.Address
		if svc.Device != "" {
			address += "%" + svc.Device
		}
		process := svc.Process
		if process == "" {
			process = "-"
		}
		status := string(svc.Status)
		style := styleMuted
		switch svc.Status {
		case models.ServiceReachable:
			status = string(svc.Scope)
			style = styleWarning
			if svc.Scope == models.ScopeExposed {
				style = styleDanger
			}
		case models.ServiceDocker:
			status = "DOCKER: " + string(svc.Scope)
			if svc.Scope == "" {
				status = "DOCKER: BLOCKED"
			}
		case models.ServiceFiltered, models.ServiceLocalhost:
			style = styleSuccess
		case models.ServiceNotAnalyzed:
			status = "NOT ANALYZED"
		}
		t.line("    %-5s %-6d %-24s %-18s %s", svc.Protocol, svc.Port, address, process, style.Render(status))
	}
}

// sandbox says how the process that read the input was confined.
func (t *textReport) sandbox() {
	status := t.rep.Sandbox
	if status == nil {
		return
	}
	t.section("Sandbox")
	summary, warning := sandboxSummary(status)
	style := styleMuted
	if warning {
		style = styleWarning
	}
	t.prose("    ", style, summary)
	for _, note := range status.Notes {
		t.prose("    ", styleWarning, note)
	}
}

// rules lists the rules of every chain as iptables-save prints them, with
// the findings that name them.
func (t *textReport) rules() {
	for _, ruleset := range t.rep.Rulesets {
		t.section("Rules, IPv" + strconv.Itoa(ruleset.Family))
		for _, table := range ruleset.Tables {
			for _, chain := range table.Chains {
				if len(chain.Rules) == 0 && !t.opts.Verbose {
					continue
				}
				head := table.Name + "/" + chain.Name
				detail := countNoun(len(chain.Rules), "rule")
				if chain.Policy != "" {
					detail = "policy " + chain.Policy + ", " + detail
				}
				if chain.Owner != "" {
					detail += ", " + chain.Owner
				}
				t.line("")
				t.line("    %s %s", styleSubHeader.Render(head), styleMuted.Render("("+detail+")"))
				for _, rule := range chain.Rules {
					spec := styleText.Render(rule.Spec)
					if len(rule.Findings) > 0 {
						spec += " " + styleWarning.Render("["+strings.Join(rule.Findings, " ")+"]")
					}
					t.line("    %s %s", styleMuted.Render(fmt.Sprintf("%4d", rule.Num)), spec)
				}
			}
		}
	}
}

// footer says what the report left out and how to get it.
func (t *textReport) footer() {
	rep := t.rep
	var hidden []string
	if !t.opts.Rules {
		rules := 0
		for _, family := range rep.Families {
			rules += family.Rules
		}
		if rules > 0 {
			hidden = append(hidden, countNoun(rules, "rule")+" (--rules)")
		}
	}
	if !t.opts.Verbose {
		var more []string
		if rep.Counts.Info > 0 {
			more = append(more, strconv.Itoa(rep.Counts.Info)+" info "+plural(rep.Counts.Info, "finding", "findings"))
		}
		if len(rep.Services) > 0 {
			more = append(more, countNoun(len(rep.Services), "listening socket"))
		}
		if len(more) > 0 {
			hidden = append(hidden, strings.Join(more, ", ")+" (-v)")
		}
	}
	if rep.Baseline != nil {
		hidden = append(hidden, "recommended baseline (--baseline)")
	}
	t.line("")
	if len(hidden) > 0 {
		t.prose("  ", styleMuted, "Not shown: "+strings.Join(hidden, " · "))
	}
	if t.opts.HTMLFile != "" {
		t.prose("  ", styleMuted, "Interactive report: "+t.opts.HTMLFile)
		return
	}
	t.prose("  ", styleMuted, "Interactive report: --html FILE · machine-readable: --json")
}
