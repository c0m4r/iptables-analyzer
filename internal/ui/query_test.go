package ui

import (
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
	"github.com/c0m4r/iptables-analyzer/internal/report"
	"github.com/charmbracelet/lipgloss"
)

// traceOf follows a packet through a fixture.
func traceOf(t *testing.T, name, packet string) *report.TraceReport {
	t.Helper()
	rs, err := parser.Parse(fixture(t, name), models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := analyzer.ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	return report.NewTrace(analyzer.Trace(rs, nil, parsed), report.Options{Version: "1.2.3", Now: testTime, Inputs: []string{name}}, nil)
}

func renderTrace(t *testing.T, result *report.TraceReport, opts TextOptions) string {
	t.Helper()
	var out strings.Builder
	if err := RenderTrace(&out, result, opts); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestTraceShowsTheWayOfThePacket(t *testing.T) {
	text := renderTrace(t, traceOf(t, "router.iptables-save", "tcp 192.168.1.9 -> :80 in eth1"), TextOptions{})
	for _, want := range []string{
		"iptables-analyzer v1.2.3 · file analysis · 2026-11-25 12:00",
		"inputs: router.iptables-save",
		"Packet tcp 192.168.1.9 → this host, port 80 · in eth1 · new connection · IPv4",
		"nat/PREROUTING",
		"#4  -i eth1 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128  → REDIRECT",
		"→ new destination: this host, port 3128",
		"#9  -i eth1 -p tcp -m tcp --dport 3128 -j ACCEPT  → ACCEPT",
		"Verdict  ACCEPT by filter/INPUT #9",
		"This host receives the packet on port 3128, its new destination.",
		"The source port was not given",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the trace lacks %q:\n%s", want, text)
		}
	}

	// A packet that the rules drop, and one that a rule may accept.
	dropped := renderTrace(t, traceOf(t, "router.iptables-save", "tcp 203.0.113.5:40000 -> :22 in eth0"), TextOptions{})
	if !strings.Contains(dropped, "Verdict  DROP by the policy of filter/INPUT") || strings.Contains(dropped, "receives the packet") ||
		!strings.Contains(dropped, "tcp 203.0.113.5:40000 → this host, port 22") || strings.Contains(dropped, "The source port was not given") {
		t.Errorf("dropped packet:\n%s", dropped)
	}
	unsure := renderTrace(t, traceOf(t, "router.iptables-save", "tcp 203.0.113.5 -> :8443 in eth0"), TextOptions{})
	for _, want := range []string{"→ may match, not followed", "the egress interface is not known", "Verdict  DROP (not certain)",
		"When a rule that may match does match", "If filter/FORWARD #4 matches (the egress interface is not known): ACCEPT by filter/FORWARD #4.",
		"This host sends the packet on to 192.168.1.50, port 443, its new destination."} {
		if !strings.Contains(unsure, want) {
			t.Errorf("the uncertain trace lacks %q:\n%s", want, unsure)
		}
	}

	// Rules are never wrapped; everything else fits the width.
	narrow := renderTrace(t, traceOf(t, "k8s.iptables-save", "tcp 203.0.113.5 -> :30080 in eth0"), TextOptions{Width: 70})
	for _, line := range strings.Split(narrow, "\n") {
		if lipgloss.Width(line) > 70 && !strings.Contains(line, " -j ") && !strings.Contains(line, "--comment") {
			t.Errorf("line of %d columns: %q", lipgloss.Width(line), line)
		}
	}
	if !strings.Contains(narrow, "    → jump") || !strings.Contains(narrow, "the mark is now 0x4000") {
		t.Errorf("a long rule has what it does on the next line:\n%s", narrow)
	}
	if RenderTrace(failingWriter{}, traceOf(t, "basic.iptables-save", "tcp 203.0.113.5 -> :22"), TextOptions{}) == nil {
		t.Error("the trace renderer ignored the write failure")
	}
}

func TestDiffShowsWhatChanged(t *testing.T) {
	side := func(name, ss string) (*report.Report, *models.AnalysisResult) {
		rs, err := parser.Parse(fixture(t, name), models.IPv4)
		if err != nil {
			t.Fatal(err)
		}
		result := analyzer.Analyze(rs, nil)
		result.IPv4Only, result.IPv6Status = true, models.FamilyNotSupplied
		return report.Build(result, report.Options{Version: "1.2.3", Now: testTime, Inputs: []string{name}}), result
	}
	oldReport, oldResult := side("basic.iptables-save", "")
	newReport, newResult := side("router.iptables-save", "")
	diff := report.Compare(oldReport, newReport, oldResult, newResult)
	var out strings.Builder
	if err := RenderDiff(&out, diff, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"iptables-analyzer v1.2.3 · comparison · 2026-11-25 12:00",
		"old: basic.iptables-save (file analysis)", "new: router.iptables-save (file analysis)",
		"Grade A 93/100  →  Grade ", "New findings", "Findings that are gone", "Ports of this host",
		"IPv4 tcp 443           any source → closed",
		"Ports translated to other hosts", "new: IPv4 8443/tcp → 192.168.1.50:443: any source, possible",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the comparison lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "accepted by filter/INPUT") {
		t.Error("the details of the findings are for --verbose")
	}
	out.Reset()
	if err := RenderDiff(&out, diff, TextOptions{Verbose: true, Width: 80}); err != nil || !strings.Contains(out.String(), "accepted by filter/INPUT") {
		t.Errorf("--verbose adds the details: %v", err)
	}
	out.Reset()
	if err := RenderDiffLine(&out, diff); err != nil || !strings.HasPrefix(out.String(), "93 A -> ") || !strings.Contains(out.String(), "new finding") {
		t.Errorf("one line: %q %v", out.String(), err)
	}
	same := report.Compare(oldReport, oldReport, oldResult, oldResult)
	out.Reset()
	if err := RenderDiff(&out, same, TextOptions{}); err != nil || !strings.Contains(out.String(), "No difference.") || strings.Contains(out.String(), "New findings") {
		t.Errorf("no difference:\n%s", out.String())
	}
	if RenderDiff(failingWriter{}, diff, TextOptions{}) == nil || RenderDiffLine(failingWriter{}, diff) == nil {
		t.Error("the comparison renderer ignored the write failure")
	}
}

// The open ports name the local port that a redirect sends them to.
func TestTextReportShowsRedirectedPorts(t *testing.T) {
	text := renderText(t, fixtureReport(t, "router.iptables-save", "", "router-services.txt"), TextOptions{})
	for _, want := range []string{"80 → 3128 squid (on eth1)", "squid is open to any source on 80/tcp",
		"nat/PREROUTING #4:  -i eth1 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128", "8443/tcp → 192.168.1.50:443: any source, possible"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report lacks %q:\n%s", want, text)
		}
	}
	shared := renderText(t, fixtureReport(t, "k8s.iptables-save", "", "k8s-services.txt"), TextOptions{})
	if !strings.Contains(shared, "203.0.113.50:80/tcp → 10.244.0.10:8080, 10.244.0.11:8080: any source") {
		t.Errorf("a port that is shared among pods names them:\n%s", shared)
	}
}
