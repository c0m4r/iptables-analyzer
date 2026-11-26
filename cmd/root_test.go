package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
	"github.com/c0m4r/iptables-analyzer/internal/report"
	"github.com/c0m4r/iptables-analyzer/internal/sandbox"
	"github.com/c0m4r/iptables-analyzer/internal/services"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
)

var testTime = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func data(name string) string { return filepath.Join("..", "testdata", name) }

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// testDependencies collects real input but replaces the sandbox, which
// cannot be lifted, with one that does not confine the test process.
func testDependencies(root bool) commandDependencies {
	deps := defaultCommandDependencies()
	deps.isRoot = func() bool { return root }
	deps.sandbox = func(mode sandbox.Mode) (models.SandboxStatus, error) {
		return models.SandboxStatus{Mode: string(mode)}, nil
	}
	deps.now = func() time.Time { return testTime }
	// The tests must not read the facts of the machine that runs them.
	deps.collectFacts = func(*models.HostContext) loader.Facts { return loader.Facts{} }
	return deps
}

func newTestCommand(out *bytes.Buffer, root bool) *cobra.Command {
	command := newRootCommand(testDependencies(root))
	command.SetOut(out)
	command.SetErr(&bytes.Buffer{})
	return command
}

// run executes the command and returns what it printed.
func run(t *testing.T, deps commandDependencies, args ...string) (string, error) {
	t.Helper()
	lipgloss.SetColorProfile(termenv.Ascii)
	command := newRootCommand(deps)
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&bytes.Buffer{})
	// Without arguments cobra would read those of the test binary.
	command.SetArgs(append([]string{}, args...))
	err := command.Execute()
	return output.String(), err
}

func runReport(t *testing.T, deps commandDependencies, args ...string) report.Report {
	t.Helper()
	output, err := run(t, deps, append([]string{"--json"}, args...)...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(output), &rep); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, output)
	}
	return rep
}

func lost(rep report.Report, category string) int {
	for _, entry := range rep.Score.Categories {
		if entry.Key == category {
			return entry.Lost
		}
	}
	return -1
}

func family(rep report.Report, version int) report.Family {
	for _, entry := range rep.Families {
		if entry.Version == version {
			return entry
		}
	}
	return report.Family{}
}

func TestExplicitServicesFileFailuresAreFatal(t *testing.T) {
	if _, err := run(t, testDependencies(false), "-4", "--file", data("basic.iptables-save"),
		"--services-file", filepath.Join(t.TempDir(), "missing-services.txt"), "--json", "--score-only"); err == nil {
		t.Fatal("missing explicitly requested services file was not fatal")
	}
}

func TestMixedFamilyInventoryMarksExcludedStackNotAnalyzed(t *testing.T) {
	output, err := run(t, testDependencies(false), "-4", "--verbose", "--file", data("basic.iptables-save"), "--services-file", data("services.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "NOT ANALYZED") {
		t.Fatalf("excluded IPv6 services were not labeled NOT ANALYZED: %s", output)
	}
}

func TestMalformedServicesFileIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "services.txt")
	if err := os.WriteFile(path, []byte("this is not ss output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, testDependencies(false), "-4", "--file", data("basic.iptables-save"), "--services-file", path); err == nil {
		t.Fatal("malformed explicitly requested services file was not fatal")
	}
}

func TestCommandPropagatesOutputFailure(t *testing.T) {
	for _, mode := range [][]string{{"--json", "--score-only"}, {"--json"}, {"--score-only"}, {"--quiet"}, {}, {"--baseline"}} {
		command := newRootCommand(testDependencies(false))
		command.SetOut(errorWriter{})
		command.SetErr(&bytes.Buffer{})
		command.SetArgs(append([]string{"-4", "--file", data("basic.iptables-save")}, mode...))
		if err := command.Execute(); err == nil {
			t.Errorf("%v: the command ignored the output failure", mode)
		}
	}
}

func TestBaselineWithoutInputIsGeneric(t *testing.T) {
	text, err := run(t, testDependencies(false), "--baseline=6")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, "# Recommended IPv6 baseline") || strings.Contains(text, "IPv4 baseline") {
		t.Fatalf("--baseline=6 must print only the IPv6 file: %s", text)
	}
	if _, err := parser.Parse(text, models.IPv6); err != nil {
		t.Fatalf("printed baseline is not a valid rules file: %v", err)
	}
}

func TestBaselineAllPrintsBothFamiliesEvenWithIPv4Only(t *testing.T) {
	text, err := run(t, testDependencies(false), "-4", "--file", data("docker29.iptables-save"), "--baseline")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "IPv4 baseline") || !strings.Contains(text, "IPv6 baseline") || !strings.Contains(text, "DOCKER-USER") {
		t.Fatalf("expected both families with Docker awareness: %s", text)
	}
}

func TestInvalidOptionValuesAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"--baseline=5"},
		{"--fail-on", "severe"},
		{"--min-grade", "E"},
		{"--min-grade", "AB"},
		{"--public", "sctp/80"},
		{"--public", "tcp/99999"},
		{"-4", "-6"},
		{"-4", "--file6", "x"},
		{"-6", "--file", "x"},
		{"--sandbox", "maybe"},
	} {
		if _, err := run(t, testDependencies(false), append(args, data("basic.iptables-save"))...); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}

func TestJSONReportIncludesBaselineAndForwardedPorts(t *testing.T) {
	rep := runReport(t, testDependencies(false), "--file", data("docker29.iptables-save"), "--file6", data("docker29.ip6tables-save"))
	if rep.Baseline == nil || rep.Baseline.IPv4 == "" || rep.Baseline.IPv6 == "" || len(rep.Forwards) != 7 {
		t.Fatalf("JSON report is missing the baseline or the forwarded ports: %d ports", len(rep.Forwards))
	}
	if rep.SchemaVersion != report.SchemaVersion || rep.Mode != "file" || rep.Generated != "2026-11-25T12:00:00Z" || len(rep.Inputs) != 2 {
		t.Fatalf("header: %d %s %s %v", rep.SchemaVersion, rep.Mode, rep.Generated, rep.Inputs)
	}
	// The rules are in the JSON form only on request (audit F7).
	if rep.Rulesets != nil {
		t.Fatal("the rules are in the report without --rules")
	}
	rep = runReport(t, testDependencies(false), "--rules", "--file", data("docker29.iptables-save"))
	if len(rep.Rulesets) != 1 || len(rep.Rulesets[0].Tables) != 5 {
		t.Fatalf("--rules: %+v", rep.Rulesets)
	}
}

// liveDependencies simulates a root run whose tools print the given text.
func liveDependencies(v4, v6, ssTCP string) commandDependencies {
	deps := testDependencies(true)
	deps.readRules = func(cfg loader.Config) (loader.Sources, error) {
		var sources loader.Sources
		if !cfg.IPv6Only {
			sources.IPv4 = &loader.Source{Version: models.IPv4, Data: v4}
		}
		if !cfg.IPv4Only {
			sources.IPv6 = &loader.Source{Version: models.IPv6, Data: v6}
		}
		return sources, nil
	}
	deps.collectServices = func() services.Capture {
		return services.Capture{Outputs: []services.Output{{Proto: "tcp", Data: ssTCP}}}
	}
	deps.getHost = func() (*models.HostContext, error) { return nil, errors.New("no interfaces in tests") }
	return deps
}

const ssListenBoth = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
	"LISTEN 0      128          0.0.0.0:22        0.0.0.0:*     users:((\"sshd\",pid=812,fd=3))\n" +
	"LISTEN 0      128             [::]:22           [::]:*     users:((\"sshd\",pid=812,fd=4))\n"

func fixtureText(t *testing.T, name string) string {
	t.Helper()
	text, err := os.ReadFile(data(name))
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

// With the nf_tables backend ip6tables-save prints nothing when no IPv6 rule
// was ever added. Live analysis must report the open stack, not stop.
func TestLiveAnalysisOfFamilyWithoutRules(t *testing.T) {
	rep := runReport(t, liveDependencies(fixtureText(t, "basic.iptables-save"), "", ssListenBoth))
	if rep.Mode != "live" || family(rep, 4).Status != string(models.FamilyAnalyzed) || family(rep, 6).Status != string(models.FamilyNoRules) {
		t.Fatalf("mode %s, families %+v", rep.Mode, rep.Families)
	}
	if lost(rep, "ipv6") != 10 {
		t.Fatalf("an IPv6 stack without rules must be charged: -%d", lost(rep, "ipv6"))
	}
	exposedV6 := false
	for _, finding := range rep.Findings {
		if finding.Code == string(models.FindingExposedService) && len(finding.Ports) == 1 && finding.Ports[0] == "22/tcp" {
			for _, version := range finding.Families {
				exposedV6 = exposedV6 || version == 6
			}
		}
	}
	if !exposedV6 {
		t.Fatalf("sshd on an unfiltered IPv6 stack was not reported: %+v", rep.Findings)
	}

	// No rules at all: the host has no firewall.
	rep = runReport(t, liveDependencies("", "", ssListenBoth))
	if family(rep, 4).Status != string(models.FamilyNoRules) || family(rep, 6).Status != string(models.FamilyNoRules) || rep.Score.Grade != "F" {
		t.Fatalf("host without rules: %+v grade %s", rep.Families, rep.Score.Grade)
	}
}

func TestFileAnalysisDoesNotJudgeTheFamilyWithoutFile(t *testing.T) {
	rep := runReport(t, testDependencies(false), "--file", data("basic.iptables-save"))
	if family(rep, 6).Status != string(models.FamilyNotSupplied) || lost(rep, "ipv6") != 0 {
		t.Fatalf("a missing IPv6 file was treated as an IPv6 stack without rules: %+v, ipv6 -%d", rep.Families, lost(rep, "ipv6"))
	}
	said := false
	for _, note := range rep.Notes {
		said = said || (note.Kind == "scope" && strings.Contains(note.Text, "ip6tables-save"))
	}
	if !said {
		t.Fatalf("the report does not say that IPv6 was left out: %+v", rep.Notes)
	}
	for _, finding := range rep.Findings {
		for _, version := range finding.Families {
			if version == 6 {
				t.Fatalf("finding about a family that was not read: %s", finding.Title)
			}
		}
	}
}

func TestRulesThatSaveCannotPrintMakeTheResultIncomplete(t *testing.T) {
	dir := t.TempDir()
	incompatible := filepath.Join(dir, "nft.v4")
	if err := os.WriteFile(incompatible, []byte("# Table `filter' is incompatible, use 'nft' tool.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep := runReport(t, testDependencies(false), "-4", "--file", incompatible)
	if family(rep, 4).Status != string(models.FamilyUnreadable) || rep.Score.Complete || rep.Score.Grade != "INCOMPLETE" {
		t.Fatalf("native nftables rules were analyzed as absent: %+v grade %s", rep.Families, rep.Score.Grade)
	}
	incomplete := 0
	for _, note := range rep.Notes {
		if note.Kind == "incomplete" && note.Area == "rules" {
			incomplete++
		}
	}
	if incomplete != 1 {
		t.Fatalf("missing note about what was not assessed: %+v", rep.Notes)
	}

	legacy := filepath.Join(dir, "legacy.v4")
	warning := "# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n"
	if err := os.WriteFile(legacy, []byte(warning+fixtureText(t, "basic.iptables-save")), 0o600); err != nil {
		t.Fatal(err)
	}
	rep = runReport(t, testDependencies(false), "-4", "--file", legacy)
	if family(rep, 4).Status != string(models.FamilyAnalyzed) || rep.Score.Complete || rep.Score.Grade != "INCOMPLETE" {
		t.Fatalf("legacy tables warning was ignored: grade=%s", rep.Score.Grade)
	}
	// An incomplete grade does not reach any required grade.
	_, err := run(t, testDependencies(false), "-4", "--quiet", "--min-grade", "D", "--file", legacy)
	var threshold *thresholdError
	if !errors.As(err, &threshold) {
		t.Fatalf("--min-grade accepted an incomplete grade: %v", err)
	}
}

// Files can be named without saying what they hold (audit F8).
func TestFilesAreRecognizedByTheirContent(t *testing.T) {
	want := runReport(t, testDependencies(false), "--file", data("docker29.iptables-save"), "--file6", data("docker29.ip6tables-save"),
		"--services-file", data("services.txt"))
	for _, order := range [][]string{
		{"docker29.iptables-save", "docker29.ip6tables-save", "services.txt"},
		{"services.txt", "docker29.ip6tables-save", "docker29.iptables-save"},
	} {
		var args []string
		for _, name := range order {
			args = append(args, data(name))
		}
		got := runReport(t, testDependencies(false), args...)
		if got.Score.Total != want.Score.Total || len(got.Findings) != len(want.Findings) || !got.ServicesKnown ||
			family(got, 4).Rules != 55 || family(got, 6).Rules != 15 || len(got.Inputs) != 3 {
			t.Errorf("%v: total %d (want %d), %d findings (want %d), families %+v", order, got.Score.Total, want.Score.Total,
				len(got.Findings), len(want.Findings), got.Families)
		}
	}
	// A file can be combined with the options that name the kind.
	got := runReport(t, testDependencies(false), "--file6", data("docker29.ip6tables-save"), data("docker29.iptables-save"))
	if family(got, 4).Rules != 55 || family(got, 6).Rules != 15 {
		t.Errorf("file and option: %+v", got.Families)
	}

	dir := t.TempDir()
	other := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(other, []byte("remember to check the firewall\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"a file that is neither":      {other},
		"two files with IPv4 rules":   {data("basic.iptables-save"), data("ufw.iptables-save")},
		"two lists of sockets":        {data("basic.iptables-save"), data("services.txt"), data("ufw-services.txt")},
		"sockets without rules":       {data("services.txt")},
		"IPv6 rules with --ipv4-only": {"-4", data("docker29.ip6tables-save")},
		"IPv4 rules with --ipv6-only": {"-6", data("basic.iptables-save")},
		"a file that does not exist":  {filepath.Join(dir, "missing")},
		"sockets named twice":         {data("basic.iptables-save"), data("services.txt"), "--services-file", data("ufw-services.txt")},
	} {
		if _, err := run(t, testDependencies(false), args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClassifyInput(t *testing.T) {
	const filter = "*filter\n:INPUT DROP [0:0]\n"
	for name, c := range map[string]struct {
		data     string
		haveIPv4 bool
		want     inputKind
	}{
		"iptables-save header":          {"# Generated by iptables-save v1.8.10 on Mon\n" + filter + "COMMIT\n", false, inputRules4},
		"ip6tables-save header":         {"# Generated by ip6tables-save v1.8.10 on Mon\n" + filter + "COMMIT\n", false, inputRules6},
		"header wins over the rules":    {"# Generated by iptables-save v1.8.10\n" + filter + "-A INPUT -m comment --comment \"-s ::1\" -j ACCEPT\nCOMMIT\n", false, inputRules4},
		"first header wins":             {"# Generated by ip6tables-save\n# converted with iptables-save\n" + filter + "COMMIT\n", false, inputRules6},
		"IPv6 source":                   {filter + "-A INPUT -s fe80::/10 -j ACCEPT\nCOMMIT\n", false, inputRules6},
		"negated IPv6 destination":      {filter + "-A INPUT ! -d 2001:db8::1/128 -j DROP\nCOMMIT\n", false, inputRules6},
		"old negation":                  {filter + "-A INPUT -s ! 2001:db8::/32 -j DROP\nCOMMIT\n", false, inputRules6},
		"IPv4 source":                   {filter + "-A INPUT -s 10.0.0.0/8 -j ACCEPT\nCOMMIT\n", true, inputRules4},
		"ICMPv6":                        {filter + "-A INPUT -p ipv6-icmp -j ACCEPT\nCOMMIT\n", false, inputRules6},
		"ICMP":                          {filter + "-A INPUT -p icmp -j ACCEPT\nCOMMIT\n", true, inputRules4},
		"a colon in a comment is no v6": {filter + "-A INPUT -p tcp --dport 22 -m comment --comment \"a::b\" -j ACCEPT\nCOMMIT\n", false, inputRules4},
		"no sign, first file":           {filter + "-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n", false, inputRules4},
		"no sign, second file":          {filter + "-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n", true, inputRules6},
		"ss with a header":              {"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", false, inputServices},
		"ss -tln without the header":    {"LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", false, inputServices},
		"ss -tuln rows":                 {"udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\ntcp LISTEN 0 128 [::]:22 [::]:*\n", false, inputServices},
		"empty":                         {"", false, inputUnknown},
		"only comments":                 {"# nothing here\n", false, inputUnknown},
		"prose":                         {"this is a text file\n", false, inputUnknown},
		"rules and sockets in one file": {filter + "COMMIT\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", false, inputUnknown},
	} {
		if got := classifyInput(c.data, c.haveIPv4); got != c.want {
			t.Errorf("%s: kind %d, want %d", name, got, c.want)
		}
	}
}

// A completed analysis ends with status 0. A result below what --fail-on or
// --min-grade asks for ends with status 2, after the report (audit F9).
func TestThresholdsDecideTheExitStatus(t *testing.T) {
	rules := data("insecure.iptables-save") // grade F, high findings
	for name, c := range map[string]struct {
		args   []string
		status int
	}{
		"no threshold":                     {nil, 0},
		"--fail-on critical, none found":   {[]string{"--fail-on", "critical"}, 0},
		"--fail-on high":                   {[]string{"--fail-on", "high"}, 2},
		"--fail-on is not case sensitive":  {[]string{"--fail-on", "HIGH"}, 2},
		"--fail-on low":                    {[]string{"--fail-on", "low"}, 2},
		"--min-grade D":                    {[]string{"--min-grade", "D"}, 2},
		"--min-grade is not case sensitiv": {[]string{"--min-grade", "b"}, 2},
	} {
		output, err := run(t, testDependencies(false), append([]string{"--quiet", rules}, c.args...)...)
		var stderr bytes.Buffer
		if status := exitStatus(err, &stderr); status != c.status {
			t.Errorf("%s: status %d, want %d (%v)", name, status, c.status, err)
		}
		if !strings.HasPrefix(output, "70 F  ") {
			t.Errorf("%s: the result was not printed before the status: %q", name, output)
		}
		if c.status == 2 && !strings.HasPrefix(stderr.String(), "iptables-analyzer: ") {
			t.Errorf("%s: no reason on standard error: %q", name, stderr.String())
		}
	}
	// A good rule set passes.
	if _, err := run(t, testDependencies(false), "--quiet", "--min-grade", "A", "--fail-on", "high", data("ufw.iptables-save"), data("ufw-services.txt")); err != nil {
		t.Errorf("grade A with one medium finding failed: %v", err)
	}
	// An error is status 1.
	var stderr bytes.Buffer
	if status := exitStatus(errors.New("no rules"), &stderr); status != 1 || stderr.String() != "Error: no rules\n" {
		t.Errorf("error: status %d, %q", status, stderr.String())
	}
}

func TestOneLineOutputs(t *testing.T) {
	args := []string{data("ufw.iptables-save"), data("ufw-services.txt")}
	if output, err := run(t, testDependencies(false), append(args, "--score-only")...); err != nil || output != "95 A\n" {
		t.Errorf("--score-only: %q %v", output, err)
	}
	if output, err := run(t, testDependencies(false), append(args, "-q")...); err != nil || output != "95 A  1 medium, 3 low, 1 info\n" {
		t.Errorf("--quiet: %q %v", output, err)
	}
	output, err := run(t, testDependencies(false), append(args, "--score-only", "--json")...)
	var score report.Score
	if err != nil || json.Unmarshal([]byte(output), &score) != nil || score.Total != 95 || score.Grade != "A" || len(score.Categories) != 5 {
		t.Errorf("--score-only --json: %q %v", output, err)
	}
}

// Decision 7: ports that are public on purpose cost nothing.
func TestPublicPortsOption(t *testing.T) {
	args := []string{"--quiet", data("ufw.iptables-save"), data("ufw-services.txt")}
	output, err := run(t, testDependencies(false), append(args, "--public", "tcp/80,tcp/443")...)
	if err != nil || output != "97 A  1 medium, 1 low, 3 info\n" {
		t.Errorf("--public: %q %v", output, err)
	}
}

type memoryFile struct {
	bytes.Buffer
	truncated, closed bool
}

func (f *memoryFile) Truncate(size int64) error {
	f.truncated = true
	f.Buffer.Truncate(int(size))
	return nil
}

func (f *memoryFile) Close() error {
	f.closed = true
	return nil
}

// --html writes the page next to the usual report, in every output mode.
func TestHTMLReportIsWrittenNextToTheReport(t *testing.T) {
	for _, mode := range [][]string{{}, {"--json"}, {"--quiet"}, {"--score-only"}} {
		file := &memoryFile{}
		file.WriteString("an older and much longer report")
		deps := testDependencies(false)
		opened := ""
		deps.createFile = func(path string) (io.WriteCloser, error) {
			opened = path
			return file, nil
		}
		output, err := run(t, deps, append([]string{"--html", "out.html", data("ufw.iptables-save"), data("ufw-services.txt")}, mode...)...)
		if err != nil {
			t.Fatalf("%v: %v", mode, err)
		}
		page := file.String()
		if opened != "out.html" || !file.truncated || !file.closed || !strings.HasPrefix(page, "<!doctype html>") || !strings.HasSuffix(page, "</html>\n") {
			t.Fatalf("%v: opened %q, truncated %v, closed %v, page starts %q", mode, opened, file.truncated, file.closed, page[:min(len(page), 40)])
		}
		if !strings.Contains(page, "sshd is open to any source on 22/tcp") || !strings.Contains(page, `<b>A</b><small>95/100</small>`) {
			t.Errorf("%v: the page does not hold the report", mode)
		}
		if len(mode) == 0 && (!strings.Contains(output, "Interactive report: out.html") || strings.Contains(output, "--html FILE")) {
			t.Errorf("the text report does not name the page:\n%s", output[strings.LastIndex(output, "Not shown"):])
		}
		if len(mode) > 0 && strings.Contains(output, "out.html") {
			t.Errorf("%v: the name of the page is in the output: %q", mode, output)
		}
	}
	// A page that cannot be opened stops the run before any analysis.
	deps := testDependencies(false)
	deps.createFile = func(string) (io.WriteCloser, error) { return nil, errors.New("read-only file system") }
	if output, err := run(t, deps, "--html", "out.html", data("basic.iptables-save")); err == nil || output != "" {
		t.Errorf("a page that cannot be written was ignored: %q %v", output, err)
	}
	// The baseline is printed alone: no page is written with it.
	deps.createFile = func(string) (io.WriteCloser, error) {
		t.Error("a page was opened for --baseline")
		return &memoryFile{}, nil
	}
	if _, err := run(t, deps, "--html", "out.html", "--baseline", data("basic.iptables-save")); err != nil {
		t.Error(err)
	}
}

func TestHTMLReportFileIsCreatedSafely(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.v4")
	if err := os.WriteFile(rules, []byte(fixtureText(t, "basic.iptables-save")), 0o600); err != nil {
		t.Fatal(err)
	}
	// The page replaces an older one in full.
	page := filepath.Join(dir, "report.html")
	if err := os.WriteFile(page, []byte(strings.Repeat("old report ", 100000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, testDependencies(false), "--quiet", "--html", page, rules); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(page)
	if err != nil || !bytes.HasPrefix(written, []byte("<!doctype html>")) || !bytes.HasSuffix(written, []byte("</html>\n")) || bytes.Contains(written, []byte("old report")) {
		t.Fatalf("the page was not replaced in full: %v, %d bytes", err, len(written))
	}

	// An input file is never the page.
	before := fixtureText(t, "basic.iptables-save")
	for _, path := range []string{rules, filepath.Join(dir, ".", "rules.v4")} {
		if _, err := run(t, testDependencies(false), "--quiet", "--html", path, rules); err == nil || !strings.Contains(err.Error(), "input file") {
			t.Errorf("--html %s: %v", path, err)
		}
	}
	if after, _ := os.ReadFile(rules); string(after) != before {
		t.Fatal("the input file was overwritten")
	}

	// A symbolic link is not followed, and an analysis that fails leaves an
	// older page as it was.
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.html")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("no symbolic links here")
	}
	if _, err := run(t, testDependencies(false), "--quiet", "--html", link, rules); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("a symbolic link was followed: %v", err)
	}
	broken := filepath.Join(dir, "broken.v4")
	if err := os.WriteFile(broken, []byte("*filter\n-A INPUT --no-such-option\nCOMMIT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, testDependencies(false), "--quiet", "--html", target, "--file", broken); err == nil {
		t.Fatal("broken rules were accepted")
	}
	if kept, _ := os.ReadFile(target); string(kept) != "keep" {
		t.Fatalf("a failed run changed the older page: %q", kept)
	}
	if _, err := run(t, testDependencies(false), "--quiet", "--html", dir, rules); err == nil {
		t.Error("a directory was accepted as the page")
	}
}

func TestVersionAndUsage(t *testing.T) {
	output, err := run(t, testDependencies(false), "--version")
	if err != nil || !strings.HasPrefix(output, "iptables-analyzer v") {
		t.Errorf("--version: %q %v", output, err)
	}
	command := newRootCommand(testDependencies(false))
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{})
	if err := command.Execute(); err == nil || err.Error() != "no input specified" || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "iptables-analyzer rules.v4 rules.v6 ss.txt") {
		t.Errorf("no input: %v, stdout %q, stderr %q", err, stdout.String(), stderr.String())
	}
	usage := command.UsageString()
	for _, flag := range []string{"--html", "--rules", "--public", "--fail-on", "--min-grade", "--quiet", "--score-only", "--baseline", "--sandbox", "[FILE...]"} {
		if !strings.Contains(usage, flag) {
			t.Errorf("the usage does not name %s", flag)
		}
	}
}
