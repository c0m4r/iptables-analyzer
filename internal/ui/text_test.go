package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/report"
	"github.com/charmbracelet/lipgloss"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRenderersReportOutputFailures(t *testing.T) {
	rep := fixtureReport(t, "basic.iptables-save", "", "services.txt")
	if RenderText(failingWriter{}, rep, TextOptions{}) == nil {
		t.Error("text renderer ignored the write failure")
	}
	if RenderHTML(failingWriter{}, rep) == nil {
		t.Error("HTML renderer ignored the write failure")
	}
	if RenderJSON(failingWriter{}, rep) == nil {
		t.Error("JSON renderer ignored the write failure")
	}
	if RenderScoreLine(failingWriter{}, rep) == nil || RenderSummaryLine(failingWriter{}, rep) == nil {
		t.Error("the one-line forms ignored the write failure")
	}
}

// The grade and what to fix come first; the rules and the baseline are not
// printed unless they are asked for (audit F1, F2).
func TestTextReportLeadsWithTheResult(t *testing.T) {
	rep := fixtureReport(t, "docker29.iptables-save", "docker29.ip6tables-save", "")
	text := renderText(t, rep, TextOptions{Width: 100})
	order := []string{"iptables-analyzer v1.2.3", "IPv4: 55 rules in 24 chains (docker)", "Grade F  65/100", "Grade limited to F",
		"Fix first", "Findings", "HIGH", "Open to any source", "Translated to other hosts", "Not shown:"}
	at := 0
	for _, wanted := range order {
		next := strings.Index(text[at:], wanted)
		if next < 0 {
			t.Fatalf("%q is missing, or not after what should come before it:\n%s", wanted, text)
		}
		at += next
	}
	for _, unwanted := range []string{"*filter", ":INPUT", "Recommended IPv4 baseline", "-A INPUT -i lo -j ACCEPT", "Sandbox", "Listening sockets"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("the report prints %q without being asked", unwanted)
		}
	}
	if !strings.Contains(text, "70 rules (--rules)") || !strings.Contains(text, "recommended baseline (--baseline)") || !strings.Contains(text, "--html FILE") {
		t.Errorf("the footer does not say what was left out:\n%s", text[strings.Index(text, "Not shown:"):])
	}
	if lines := strings.Count(text, "\n"); lines > 110 {
		t.Errorf("the report of a Docker host is %d lines long", lines)
	}
}

func TestFixFirstNamesTheFindingThatLiftsTheGrade(t *testing.T) {
	rep := fixtureReport(t, "docker29.iptables-save", "docker29.ip6tables-save", "")
	text := renderText(t, rep, TextOptions{Width: 100})
	start := strings.Index(text, "Fix first")
	end := strings.Index(text, "Findings")
	if start < 0 || end < start {
		t.Fatalf("no list of what to fix first:\n%s", text)
	}
	lines := strings.Split(strings.TrimSpace(text[start:end]), "\n")
	if len(lines) < 4 || !strings.Contains(lines[1], "1. F1   INPUT accepts new connections to any port") || !strings.HasSuffix(lines[1], "+15, grade B") {
		t.Fatalf("unexpected list:\n%s", strings.Join(lines, "\n"))
	}
	if !strings.Contains(lines[2], "2. F3   6 Docker published ports") || !strings.HasSuffix(lines[2], "+16") {
		t.Fatalf("the second entry must be the one with the most points: %s", lines[2])
	}

	// One finding to fix is no list.
	rep = fixtureReport(t, "ufw.iptables-save", "", "ufw-services.txt")
	if text := renderText(t, rep, TextOptions{Width: 100}); strings.Contains(text, "Fix first") {
		t.Errorf("a list for one finding:\n%s", text)
	}
}

func TestFindingShowsEvidenceAndFix(t *testing.T) {
	rep := fixtureReport(t, "ufw.iptables-save", "", "ufw-services.txt")
	text := renderText(t, rep, TextOptions{Width: 100})
	for _, wanted := range []string{
		"MEDIUM   F1   sshd is open to any source on 22/tcp",
		"filter/ufw-user-limit-accept #1:  -j ACCEPT",
		"reached by INPUT #2 → ufw-before-input #13 → ufw-user-input #3",
		"fix  ufw manages this rule",
		"ufw delete limit 22/tcp",
		"tcp  22 sshd (rate limit) · 80 nginx · 443 nginx",
		"Open to restricted sources",
		"5432 postgres (private networks)",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("missing %q in:\n%s", wanted, text)
		}
	}
	// One family was read: the findings do not repeat its name.
	if strings.Contains(text, "(IPv4)") || strings.Contains(text, "IPv4 filter/") {
		t.Errorf("the family is named although only one was analyzed:\n%s", text)
	}
	rep = fixtureReport(t, "docker29.iptables-save", "docker29.ip6tables-save", "")
	text = renderText(t, rep, TextOptions{Width: 100})
	if !strings.Contains(text, "(IPv4, possible)") || !strings.Contains(text, "IPv6 8443/tcp → [fd00:dead:beef::2]:443") {
		t.Errorf("with both families the report must say which one a line is about:\n%s", text)
	}
}

func TestVerboseAndRulesAddTheirParts(t *testing.T) {
	rep := fixtureReport(t, "ufw.iptables-save", "", "ufw-services.txt")
	plain := renderText(t, rep, TextOptions{Width: 100})
	if strings.Contains(plain, "INFO ") || strings.Contains(plain, "redis-server") || !strings.Contains(plain, "1 info finding, 7 listening sockets (-v)") {
		t.Errorf("default report:\n%s", plain)
	}
	verbose := renderText(t, rep, TextOptions{Width: 100, Verbose: true})
	for _, wanted := range []string{"INFO     F5   OUTPUT default policy is ACCEPT", "Listening sockets", "redis-server", "LOCALHOST", "Sandbox", "Landlock ABI 7 (filesystem, tcp)"} {
		if !strings.Contains(verbose, wanted) {
			t.Errorf("--verbose lacks %q", wanted)
		}
	}
	if strings.Contains(verbose, "(-v)") {
		t.Errorf("--verbose still points to -v")
	}
	rules := renderText(t, rep, TextOptions{Width: 100, Rules: true})
	for _, wanted := range []string{"Rules, IPv4", "filter/INPUT (policy DROP, 6 rules)", "   1 -j ufw-before-logging-input",
		"filter/ufw-user-input (6 rules, ufw)", "-p tcp -m tcp --dport 80 -j ACCEPT [F3]"} {
		if !strings.Contains(rules, wanted) {
			t.Errorf("--rules lacks %q", wanted)
		}
	}
	if strings.Contains(rules, "(--rules)") {
		t.Errorf("--rules still points to --rules")
	}
}

// Prose is wrapped to the width. Commands and rules stay on one line, so
// that they can be copied.
func TestTextIsWrappedToTheWidth(t *testing.T) {
	rep := fixtureReport(t, "docker29.iptables-save", "docker29.ip6tables-save", "")
	for _, width := range []int{60, 80, 100, 120} {
		text := renderText(t, rep, TextOptions{Width: width, Verbose: true})
		for _, line := range strings.Split(text, "\n") {
			if lipgloss.Width(line) <= width {
				continue
			}
			trimmed := strings.TrimSpace(line)
			command := strings.HasPrefix(trimmed, "iptables ") || strings.HasPrefix(trimmed, "ip6tables ") || strings.HasPrefix(trimmed, "ufw ")
			rule := strings.Contains(trimmed, " #") && strings.Contains(trimmed, ":  ")
			if !command && !rule {
				t.Errorf("width %d: line of %d columns: %q", width, lipgloss.Width(line), line)
			}
		}
	}
	// The width has limits in both directions.
	narrow := renderText(t, rep, TextOptions{Width: 10})
	if narrow != renderText(t, rep, TextOptions{Width: minWidth}) {
		t.Error("a width below the minimum is not raised to it")
	}
	if renderText(t, rep, TextOptions{Width: 500}) != renderText(t, rep, TextOptions{Width: maxWidth}) {
		t.Error("a width above the maximum is not lowered to it")
	}
	if renderText(t, rep, TextOptions{}) != renderText(t, rep, TextOptions{Width: defaultWidth}) {
		t.Error("no width does not mean the default width")
	}
}

func TestWrap(t *testing.T) {
	for _, c := range []struct {
		text  string
		width int
		want  []string
	}{
		{"one two three", 7, []string{"one two", "three"}},
		{"one two three", 100, []string{"one two three"}},
		{"a-very-long-word-that-does-not-fit short", 10, []string{"a-very-long-word-that-does-not-fit", "short"}},
		{"first\nsecond line", 100, []string{"first", "second line"}},
		{"", 10, []string{""}},
		{"  spaces   are   joined ", 100, []string{"spaces are joined"}},
	} {
		got := wrap(c.text, c.width)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("wrap(%q, %d) = %q, want %q", c.text, c.width, got, c.want)
		}
	}
}

func TestOneLineForms(t *testing.T) {
	rep := fixtureReport(t, "ufw.iptables-save", "", "ufw-services.txt")
	var score, summary strings.Builder
	if err := RenderScoreLine(&score, rep); err != nil || score.String() != "95 A\n" {
		t.Errorf("score line %q: %v", score.String(), err)
	}
	if err := RenderSummaryLine(&summary, rep); err != nil || summary.String() != "95 A  1 medium, 3 low, 1 info\n" {
		t.Errorf("summary line %q: %v", summary.String(), err)
	}
	clean := buildReport(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n"+
		"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A OUTPUT -o lo -j ACCEPT\nCOMMIT\n", "", "")
	summary.Reset()
	if err := RenderSummaryLine(&summary, clean); err != nil || summary.String() != "100 A  no findings\n" {
		t.Errorf("summary line %q: %v", summary.String(), err)
	}
	text := renderText(t, clean, TextOptions{})
	if !strings.Contains(text, "Nothing to report.") || !strings.Contains(text, "No port accepts new connections from other hosts.") {
		t.Errorf("a clean report must say so:\n%s", text)
	}
}

func TestIncompleteGradeIsExplained(t *testing.T) {
	rep := fixtureReport(t, "basic.iptables-save", "", "services.txt")
	rep.Notes = append(rep.Notes, report.Note{Kind: "incomplete", Area: "rules", Text: "IPv4: legacy tables are present."})
	rep.Score.Complete, rep.Score.Grade, rep.Score.Unassessed = false, "INCOMPLETE", []string{"rules that could not be read or evaluated in full"}
	text := renderText(t, rep, TextOptions{Width: 100})
	for _, wanted := range []string{"Grade INCOMPLETE", "The grade is incomplete: rules that could not be read or evaluated in full could not be assessed.",
		"not assessed: IPv4: legacy tables are present."} {
		if !strings.Contains(text, wanted) {
			t.Errorf("missing %q in:\n%s", wanted, text)
		}
	}
}

func TestHTMLFileIsNamedInTheFooter(t *testing.T) {
	rep := fixtureReport(t, "basic.iptables-save", "", "services.txt")
	text := renderText(t, rep, TextOptions{HTMLFile: "out/report.html"})
	if !strings.Contains(text, "Interactive report: out/report.html") || strings.Contains(text, "--html FILE") {
		t.Errorf("footer:\n%s", text[strings.LastIndex(text, "Not shown"):])
	}
}

func TestBarShowsTheShareThatIsKept(t *testing.T) {
	for _, c := range []struct{ kept, max, filled int }{{25, 25, 10}, {0, 25, 0}, {20, 25, 8}, {9, 25, 4}, {1, 25, 0}, {24, 25, 10}, {5, 10, 5}, {0, 0, 0}} {
		got := bar(c.kept, c.max)
		if strings.Count(got, "▰") != c.filled || strings.Count(got, "▰")+strings.Count(got, "▱") != 10 {
			t.Errorf("bar(%d, %d) = %q, want %d filled of 10", c.kept, c.max, got, c.filled)
		}
	}
}
