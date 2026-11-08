package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

func TestRenderScoreUsesHundredPointCategoryTotal(t *testing.T) {
	if categoryMax["policy"]+categoryMax["exposure"]+categoryMax["shadow"]+
		categoryMax["hygiene"]+categoryMax["ipv6"] != 100 {
		t.Fatalf("category maxima must total 100: %+v", categoryMax)
	}
	var output bytes.Buffer
	renderScore(&output, models.ScoreResult{Total: 100, Grade: "A", Breakdown: map[string]int{}})
	if !strings.Contains(output.String(), "100/100") {
		t.Fatalf("missing score in output: %q", output.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRenderPropagatesOutputFailures(t *testing.T) {
	result := &models.AnalysisResult{Score: models.ScoreResult{Breakdown: map[string]int{}}}
	if err := Render(result, RenderOptions{JSON: true, Writer: failingWriter{}}); err == nil {
		t.Fatal("JSON write failure was ignored")
	}
	if err := Render(result, RenderOptions{Writer: failingWriter{}}); err == nil {
		t.Fatal("human-readable write failure was ignored")
	}
}

func TestExcludedServiceIsNotRenderedAsFiltered(t *testing.T) {
	service := models.ListeningService{Protocol: models.ProtoTCP, Address: "::", Port: 22, IsIPv6: true, Status: models.ServiceNotAnalyzed}
	status := getServiceStatus(service, &models.AnalysisResult{})
	if !strings.Contains(status, "NOT ANALYZED") {
		t.Fatalf("excluded service status was %q", status)
	}
}

func TestRuleTableRendersNegationsExtensionsGotoAndRawRule(t *testing.T) {
	rule := models.Rule{
		RuleNum: 1, Chain: "INPUT", Target: "CUSTOM", Goto: true, Protocol: models.ProtoTCP,
		SrcAddr: "0.0.0.0/0", DstAddr: "0.0.0.0/0", DstPort: "22", Fragment: true,
		States: []string{"NEW"}, Negations: map[string]bool{"protocol": true, "src": true, "dport": true, "state": true, "fragment": true},
		Matches: []models.MatchExt{{Module: "limit", Params: map[string]string{"--limit": "1/min"}, RawTokens: []string{"--limit", "1/min"}}},
		RawLine: "-A INPUT ! -p tcp ! -s 0.0.0.0/0 ! --dport 22 ! -f -g CUSTOM",
	}
	var output bytes.Buffer
	renderRuleTable(&output, &models.Chain{Name: "INPUT", Policy: "DROP", Rules: []models.Rule{rule}}, "filter", true)
	text := output.String()
	for _, wanted := range []string{"goto:CUSTOM", "!tcp", "!*", "!dpt:22", "!state:NEW", "!fragment", "-m limit --limit 1/min", "raw:"} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("rule rendering omitted %q: %s", wanted, text)
		}
	}
}

func TestIncompleteGradeIsNotWrapped(t *testing.T) {
	var output bytes.Buffer
	renderScore(&output, models.ScoreResult{Total: 60, Grade: "INCOMPLETE", Breakdown: map[string]int{}})
	if !strings.Contains(output.String(), "INCOMPLETE") {
		t.Fatalf("grade card wrapped INCOMPLETE: %q", output.String())
	}
}

func TestReportRendersDockerSectionsAndBaseline(t *testing.T) {
	result := &models.AnalysisResult{
		Score: models.ScoreResult{Breakdown: map[string]int{}},
		PublishedPorts: []models.PublishedPort{{
			IPVersion: models.IPv6, Protocol: models.ProtoTCP, HostPort: 8443, ContainerAddr: "fd00::2", ContainerPort: 443,
			Bridge: "br-0123456789ab", ForwardScope: models.ScopeExposed, Certainty: models.CertaintyDefinite,
		}},
		DockerBypasses: []models.DockerBypassFinding{{
			Code: models.FindingDockerIneffectiveRule, Severity: models.SeverityHigh, Reason: "rule never matches", Fix: "use --ctorigdstport",
		}},
		Baseline: models.Baseline{IPv4: "*filter\nCOMMIT\n", IPv6: "*filter\nCOMMIT\n", Notes: []string{"note"}},
	}
	var output bytes.Buffer
	if err := Render(result, RenderOptions{Writer: &output}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"Docker Published Ports", "[fd00::2]:443", "Docker: Ineffective Firewall Rules", "use --ctorigdstport",
		"Recommended Baseline (IPv4 + IPv6)", "baseline.v4", "baseline.v6"} {
		if !strings.Contains(text, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

func TestServiceTableShowsDockerPublishedStatus(t *testing.T) {
	result := &models.AnalysisResult{
		Services:       []models.ListeningService{{Protocol: models.ProtoTCP, Address: "0.0.0.0", Port: 8080, Process: "docker-proxy", IsWildcard: true, Status: models.ServiceDocker}},
		PublishedPorts: []models.PublishedPort{{IPVersion: models.IPv4, Protocol: models.ProtoTCP, HostPort: 8080, ForwardScope: models.ScopeExposed}},
	}
	var output bytes.Buffer
	renderServiceTable(&output, result)
	if !strings.Contains(output.String(), "DOCKER: EXPOSED") {
		t.Fatalf("published listener status missing: %s", output.String())
	}
}
