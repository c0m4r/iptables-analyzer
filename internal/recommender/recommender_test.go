package recommender

import (
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
)

func TestDockerRecommendationMatchesOriginalPort(t *testing.T) {
	result := &models.AnalysisResult{DockerBypasses: []models.DockerBypassFinding{{
		NATRule:     models.Rule{Protocol: models.ProtoTCP, IPVersion: models.IPv4},
		ExposedPort: "8080", ContainerDest: "172.17.0.2:80", Severity: models.SeverityCritical,
	}}}
	recs := Generate(result)
	if len(recs) < 2 || !strings.Contains(recs[1].Detail, "--ctorigdstport 8080") {
		t.Fatalf("expected original-port conntrack recommendation, got %+v", recs)
	}
	if strings.Contains(recs[1].Detail, "--dport 8080") {
		t.Fatalf("recommendation incorrectly matches post-DNAT dport: %s", recs[1].Detail)
	}
}

func TestSSHReplacementPreservesOriginalRestrictions(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i wg0 -d 192.0.2.10/32 -p tcp --dport 22 -m comment --comment "VPN SSH" -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	recs := Generate(analyzer.Analyze(rs, nil))
	var detail string
	for _, rec := range recs {
		if strings.Contains(rec.Title, "rate limiting") {
			detail = rec.Detail
		}
	}
	for _, wanted := range []string{"iptables -R INPUT 2", "-i wg0", "-d 192.0.2.10/32", `--comment "VPN SSH"`} {
		if !strings.Contains(detail, wanted) {
			t.Fatalf("safe replacement lost %q: %s", wanted, detail)
		}
	}
	if strings.Contains(detail, "--ctstate NEW") {
		t.Fatalf("replacement invented a NEW-only restriction: %s", detail)
	}
}

func TestSSHReplacementIsWithheldWithoutEstablishedPath(t *testing.T) {
	rs, err := parser.Parse("*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n", models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	recs := Generate(analyzer.Analyze(rs, nil))
	for _, rec := range recs {
		if strings.Contains(rec.Title, "rate limiting") && strings.Contains(rec.Detail, "iptables -R") {
			t.Fatalf("unsafe ready-to-run replacement was generated: %s", rec.Detail)
		}
	}
}

func TestExposureRecommendationUsesAllowingChain(t *testing.T) {
	result := &models.AnalysisResult{ExposedServices: []models.ExposedServiceFinding{{
		IPVersion:    models.IPv4,
		Service:      models.ListeningService{Protocol: models.ProtoTCP, Port: 22, Process: "sshd"},
		AllowingRule: &models.Rule{Table: "filter", Chain: "SSH", RuleNum: 1},
		Scope:        models.ScopeExposed, Severity: models.SeverityHigh,
	}}}
	recs := Generate(result)
	var detail string
	for _, rec := range recs {
		if rec.Category == "exposure" {
			detail = rec.Detail
		}
	}
	if !strings.Contains(detail, "filter/SSH rule #1") || !strings.Contains(detail, "iptables -I SSH") {
		t.Fatalf("recommendation points to the wrong chain: %s", detail)
	}
}

func TestIPv6PolicyRecommendationUsesIP6Tables(t *testing.T) {
	result := &models.AnalysisResult{EffectiveIssues: []models.EffectivenessFinding{{
		Title: "INPUT default policy is ACCEPT", Chain: "INPUT", IPVersion: models.IPv6,
	}}}
	recs := Generate(result)
	if len(recs) == 0 || !strings.Contains(recs[0].Detail, "ip6tables -P INPUT DROP") {
		t.Fatalf("expected ip6tables recommendation, got %+v", recs)
	}
}
