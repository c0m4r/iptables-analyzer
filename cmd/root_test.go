package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
	"github.com/c0m4r/iptables-analyzer/internal/sandbox"
	"github.com/c0m4r/iptables-analyzer/internal/services"
	"github.com/spf13/cobra"
)

func TestRootCommandRejectsPositionalArguments(t *testing.T) {
	if err := rootCmd.Args(rootCmd, []string{"rules.v4"}); err == nil {
		t.Fatal("expected positional argument error")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestExplicitServicesFileFailuresAreFatal(t *testing.T) {
	command := newRootCommand(testDependencies(false))
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{
		"-4", "--file", filepath.Join("..", "testdata", "basic.iptables-save"),
		"--services-file", filepath.Join(t.TempDir(), "missing-services.txt"), "--json", "--score-only",
	})
	if err := command.Execute(); err == nil {
		t.Fatal("missing explicitly requested services file was not fatal")
	}
}

func TestMixedFamilyInventoryMarksExcludedStackNotAnalyzed(t *testing.T) {
	command := newRootCommand(testDependencies(false))
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{
		"-4", "--no-color", "--file", filepath.Join("..", "testdata", "basic.iptables-save"),
		"--services-file", filepath.Join("..", "testdata", "services.txt"),
	})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte("NOT ANALYZED")) {
		t.Fatalf("excluded IPv6 services were not labeled NOT ANALYZED: %s", output.String())
	}
}

func TestMalformedServicesFileIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "services.txt")
	if err := os.WriteFile(path, []byte("this is not ss output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := newRootCommand(testDependencies(false))
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"-4", "--file", filepath.Join("..", "testdata", "basic.iptables-save"), "--services-file", path})
	if err := command.Execute(); err == nil {
		t.Fatal("malformed explicitly requested services file was not fatal")
	}
}

func TestCommandPropagatesOutputFailure(t *testing.T) {
	command := newRootCommand(testDependencies(false))
	command.SetOut(errorWriter{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"-4", "--file", filepath.Join("..", "testdata", "basic.iptables-save"), "--json", "--score-only"})
	if err := command.Execute(); err == nil {
		t.Fatal("command ignored output failure")
	}
}

// testDependencies collects real input but replaces the sandbox, which
// cannot be lifted, with one that does not confine the test process.
func testDependencies(root bool) commandDependencies {
	deps := defaultCommandDependencies()
	deps.isRoot = func() bool { return root }
	deps.sandbox = func(mode sandbox.Mode) (models.SandboxStatus, error) {
		return models.SandboxStatus{Mode: string(mode)}, nil
	}
	return deps
}

func newTestCommand(out *bytes.Buffer, root bool) *cobra.Command {
	command := newRootCommand(testDependencies(root))
	command.SetOut(out)
	command.SetErr(&bytes.Buffer{})
	return command
}

func TestBaselineWithoutInputIsGeneric(t *testing.T) {
	var output bytes.Buffer
	command := newTestCommand(&output, false)
	command.SetArgs([]string{"--baseline=6"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.HasPrefix(text, "# Recommended IPv6 baseline") || strings.Contains(text, "IPv4 baseline") {
		t.Fatalf("--baseline=6 must print only the IPv6 file: %s", text)
	}
	if _, err := parser.Parse(text, models.IPv6); err != nil {
		t.Fatalf("printed baseline is not a valid rules file: %v", err)
	}
}

func TestBaselineAllPrintsBothFamiliesEvenWithIPv4Only(t *testing.T) {
	var output bytes.Buffer
	command := newTestCommand(&output, false)
	command.SetArgs([]string{"-4", "--file", filepath.Join("..", "testdata", "docker29.iptables-save"), "--baseline"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "IPv4 baseline") || !strings.Contains(text, "IPv6 baseline") || !strings.Contains(text, "DOCKER-USER") {
		t.Fatalf("expected both families with Docker awareness: %s", text)
	}
}

func TestInvalidBaselineFamilyIsRejected(t *testing.T) {
	command := newTestCommand(&bytes.Buffer{}, false)
	command.SetArgs([]string{"--baseline=5"})
	if err := command.Execute(); err == nil {
		t.Fatal("invalid --baseline value was accepted")
	}
}

func TestJSONReportIncludesBaselineAndPublishedPorts(t *testing.T) {
	var output bytes.Buffer
	command := newTestCommand(&output, false)
	command.SetArgs([]string{"--json", "--file", filepath.Join("..", "testdata", "docker29.iptables-save"),
		"--file6", filepath.Join("..", "testdata", "docker29.ip6tables-save")})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var report models.AnalysisResult
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Baseline.IPv4 == "" || report.Baseline.IPv6 == "" || len(report.PublishedPorts) != 9 {
		t.Fatalf("JSON report is missing the baseline or published ports: %+v", report.PublishedPorts)
	}
}

func runReport(t *testing.T, deps commandDependencies, args ...string) models.AnalysisResult {
	t.Helper()
	command := newRootCommand(deps)
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&bytes.Buffer{})
	command.SetArgs(append([]string{"--json"}, args...))
	if err := command.Execute(); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	var report models.AnalysisResult
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, output.String())
	}
	return report
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

// With the nf_tables backend ip6tables-save prints nothing when no IPv6 rule
// was ever added. Live analysis must report the open stack, not stop.
func TestLiveAnalysisOfFamilyWithoutRules(t *testing.T) {
	v4, err := os.ReadFile(filepath.Join("..", "testdata", "basic.iptables-save"))
	if err != nil {
		t.Fatal(err)
	}
	report := runReport(t, liveDependencies(string(v4), "", ssListenBoth))
	if report.IPv4Status != models.FamilyAnalyzed || report.IPv6Status != models.FamilyNoRules {
		t.Fatalf("family status: IPv4=%s IPv6=%s", report.IPv4Status, report.IPv6Status)
	}
	if report.Score.Breakdown["ipv6"] != -10 {
		t.Fatalf("an IPv6 stack without rules must be charged: %+v", report.Score.Breakdown)
	}
	exposedV6 := false
	for _, finding := range report.ExposedServices {
		if finding.IPVersion == models.IPv6 && finding.Service.Port == 22 && finding.Scope == models.ScopeExposed {
			exposedV6 = true
		}
	}
	if !exposedV6 {
		t.Fatalf("sshd on an unfiltered IPv6 stack was not reported: %+v", report.ExposedServices)
	}

	// No rules at all: the host has no firewall.
	report = runReport(t, liveDependencies("", "", ssListenBoth))
	if report.IPv4Status != models.FamilyNoRules || report.IPv6Status != models.FamilyNoRules || len(report.ExposedServices) != 2 {
		t.Fatalf("host without rules: IPv4=%s IPv6=%s exposed=%d", report.IPv4Status, report.IPv6Status, len(report.ExposedServices))
	}
}

func TestFileAnalysisDoesNotJudgeTheFamilyWithoutFile(t *testing.T) {
	report := runReport(t, testDependencies(false), "--file", filepath.Join("..", "testdata", "basic.iptables-save"))
	if report.IPv6Status != models.FamilyNotSupplied || !report.IPv4Only || report.Score.Breakdown["ipv6"] != 0 {
		t.Fatalf("missing --file6 was treated as an IPv6 stack without rules: status=%s only=%v score=%+v",
			report.IPv6Status, report.IPv4Only, report.Score.Breakdown)
	}
	if len(report.Notes) != 1 || !strings.Contains(report.Notes[0], "--file6") {
		t.Fatalf("the report does not say that IPv6 was left out: %q", report.Notes)
	}
	for _, rec := range report.Recommendations {
		if strings.Contains(rec.Title, "IPv6") {
			t.Fatalf("recommendation about a family that was not read: %s", rec.Title)
		}
	}
}

func TestRulesThatSaveCannotPrintMakeTheResultIncomplete(t *testing.T) {
	dir := t.TempDir()
	incompatible := filepath.Join(dir, "nft.v4")
	if err := os.WriteFile(incompatible, []byte("# Table `filter' is incompatible, use 'nft' tool.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := runReport(t, testDependencies(false), "-4", "--file", incompatible)
	if report.IPv4Status != models.FamilyUnreadable || report.IPv4Rules != nil || report.Score.Complete {
		t.Fatalf("native nftables rules were analyzed as absent: status=%s complete=%v", report.IPv4Status, report.Score.Complete)
	}
	if len(report.Diagnostics) != 1 || report.Diagnostics[0].Area != "rules" {
		t.Fatalf("missing assessment note: %+v", report.Diagnostics)
	}

	basic, err := os.ReadFile(filepath.Join("..", "testdata", "basic.iptables-save"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "legacy.v4")
	warning := "# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n"
	if err := os.WriteFile(legacy, append([]byte(warning), basic...), 0o600); err != nil {
		t.Fatal(err)
	}
	report = runReport(t, testDependencies(false), "-4", "--file", legacy)
	if report.IPv4Status != models.FamilyAnalyzed || report.Score.Complete || report.Score.Grade != "INCOMPLETE" {
		t.Fatalf("legacy tables warning was ignored: grade=%s", report.Score.Grade)
	}
}
