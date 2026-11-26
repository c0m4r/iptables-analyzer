package report

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
	"github.com/c0m4r/iptables-analyzer/internal/services"
)

var testTime = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func parse(t *testing.T, data string, version models.IPVersion) *models.Ruleset {
	t.Helper()
	if data == "" {
		return nil
	}
	rs, err := parser.Parse(data, version)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rs
}

// filterRules builds an IPv4 filter table with default-deny policies, the
// loopback and conntrack rules, and the given lines.
func filterRules(lines ...string) string {
	return "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n" +
		strings.Join(lines, "\n") + "\nCOMMIT\n"
}

// build analyzes rules and builds the report. ss holds rows of ss output
// without the header; nil means that no list of services was supplied.
func build(t *testing.T, v4, v6 string, ss []string, opts Options) *Report {
	t.Helper()
	result := analyzer.Analyze(parse(t, v4, models.IPv4), parse(t, v6, models.IPv6))
	if ss != nil {
		svcs, err := services.ParseSSData("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" + strings.Join(ss, "\n") + "\n")
		if err != nil {
			t.Fatalf("ss: %v", err)
		}
		analyzer.CrossReferenceServices(result, svcs)
	}
	if opts.Now.IsZero() {
		opts.Now = testTime
	}
	return Build(result, opts)
}

// analyzeLive analyzes rules as a live run does: empty text is the output of
// a save tool for a family in which no rule is loaded.
func analyzeLive(t *testing.T, v4, v6 string) *models.AnalysisResult {
	t.Helper()
	read := func(data string, version models.IPVersion) *models.Ruleset {
		if rs, empty := parser.ParseNoTables(data, version); empty {
			return rs
		}
		return parse(t, data, version)
	}
	return analyzer.Analyze(read(v4, models.IPv4), read(v6, models.IPv6))
}

func itoa(n int) string { return strconv.Itoa(n) }

func find(rep *Report, code string) []Finding {
	var found []Finding
	for _, finding := range rep.Findings {
		if finding.Code == code {
			found = append(found, finding)
		}
	}
	return found
}

func lost(rep *Report, category string) int {
	for _, c := range rep.Score.Categories {
		if c.Key == category {
			return c.Lost
		}
	}
	return -1
}

func TestDumpForReview(t *testing.T) {
	if os.Getenv("DUMP") == "" {
		t.Skip("set DUMP=1 to print reports")
	}
	for _, c := range []struct{ name, v4, v6, ss string }{
		{"basic", "basic.iptables-save", "", "services.txt"},
		{"ufw", "ufw.iptables-save", "", "ufw-services.txt"},
		{"docker29", "docker29.iptables-save", "docker29.ip6tables-save", ""},
		{"insecure", "insecure.iptables-save", "", ""},
	} {
		var ss []string
		if c.ss != "" {
			for _, line := range strings.Split(fixture(t, c.ss), "\n") {
				if line != "" && !strings.HasPrefix(line, "State") && !strings.HasPrefix(line, "Netid") {
					ss = append(ss, line)
				}
			}
		}
		v6 := ""
		if c.v6 != "" {
			v6 = fixture(t, c.v6)
		}
		rep := build(t, fixture(t, c.v4), v6, ss, Options{Version: "test"})
		t.Logf("==== %s: %d %s cap=%q counts=%+v", c.name, rep.Score.Total, rep.Score.Grade, rep.Score.Cap, rep.Counts)
		for _, cat := range rep.Score.Categories {
			t.Logf("   %-22s -%d/%d", cat.Label, cat.Lost, cat.Max)
		}
		for _, f := range rep.Findings {
			t.Logf("  %s %-8s %-9s %-8s -%d fam=%v %s", f.ID, f.Severity, f.Certainty, f.Category, f.Points, f.Families, f.Title)
			t.Logf("       %s", f.Detail)
			for _, r := range f.Rules {
				t.Logf("       rule[%s] v%d %s/%s #%d: %s path=%v", r.Role, r.Family, r.Table, r.Chain, r.Num, r.Spec, r.Path)
			}
			if f.Fix != nil {
				t.Logf("       fix: %s", f.Fix.Summary)
				for _, step := range f.Fix.Steps {
					t.Logf("         %s:\n           $ %s", step.Text, step.Command)
				}
			}
		}
		for _, n := range rep.Notes {
			t.Logf("  note[%s/%s] %s", n.Kind, n.Area, n.Text)
		}
		for _, p := range rep.OpenPorts {
			t.Logf("  open %v %s %d-%d %s %s cond=%q default=%v listeners=%v", p.Families, p.Protocol, p.First, p.Last, p.Scope, p.Certainty, p.Condition, p.Default, p.Listeners)
		}
	}
}
