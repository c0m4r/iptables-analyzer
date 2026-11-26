package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/baseline"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
	"github.com/c0m4r/iptables-analyzer/internal/report"
	"github.com/c0m4r/iptables-analyzer/internal/services"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestMain(m *testing.M) {
	// The tests read the text as it is printed with --no-color.
	lipgloss.SetColorProfile(termenv.Ascii)
	os.Exit(m.Run())
}

var testTime = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func fixture(t testing.TB, name string) string {
	t.Helper()
	if name == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// buildReport analyzes rules text and builds the report, like the command
// does for files. ss is the text of ss output; empty means that no list of
// sockets was supplied.
func buildReport(t testing.TB, v4, v6, ss string) *report.Report {
	t.Helper()
	read := func(data string, version models.IPVersion) *models.Ruleset {
		if data == "" {
			return nil
		}
		rs, err := parser.Parse(data, version)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return rs
	}
	result := analyzer.Analyze(read(v4, models.IPv4), read(v6, models.IPv6))
	if v6 == "" {
		result.IPv4Only, result.IPv6Status = true, models.FamilyNotSupplied
		result.Notes = append(result.Notes, "IPv6 rules were not supplied: only IPv4 was analyzed.")
	}
	if ss != "" {
		svcs, err := services.ParseSSData(ss)
		if err != nil {
			t.Fatalf("ss: %v", err)
		}
		analyzer.CrossReferenceServices(result, svcs)
	}
	result.Sandbox = &models.SandboxStatus{Mode: "auto", Landlock: true, LandlockABI: 7, Restricted: []string{"filesystem", "tcp"}}
	return report.Build(result, report.Options{Version: "1.2.3", Now: testTime, Inputs: []string{"rules.v4"},
		Baseline: baseline.Generate(baseline.FromResult(result))})
}

func fixtureReport(t testing.TB, v4, v6, ss string) *report.Report {
	t.Helper()
	return buildReport(t, fixture(t, v4), fixture(t, v6), fixture(t, ss))
}

func renderText(t testing.TB, rep *report.Report, opts TextOptions) string {
	t.Helper()
	var out strings.Builder
	if err := RenderText(&out, rep, opts); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func renderHTML(t testing.TB, rep *report.Report) string {
	t.Helper()
	var out strings.Builder
	if err := RenderHTML(&out, rep); err != nil {
		t.Fatal(err)
	}
	return out.String()
}
