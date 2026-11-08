package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
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
	command := NewRootCommand()
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
	command := NewRootCommand()
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
	command := NewRootCommand()
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"-4", "--file", filepath.Join("..", "testdata", "basic.iptables-save"), "--services-file", path})
	if err := command.Execute(); err == nil {
		t.Fatal("malformed explicitly requested services file was not fatal")
	}
}

func TestCommandPropagatesOutputFailure(t *testing.T) {
	command := NewRootCommand()
	command.SetOut(errorWriter{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"-4", "--file", filepath.Join("..", "testdata", "basic.iptables-save"), "--json", "--score-only"})
	if err := command.Execute(); err == nil {
		t.Fatal("command ignored output failure")
	}
}

func newTestCommand(out *bytes.Buffer, root bool) *cobra.Command {
	deps := defaultCommandDependencies()
	deps.isRoot = func() bool { return root }
	command := newRootCommand(deps)
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
