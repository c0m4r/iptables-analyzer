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
