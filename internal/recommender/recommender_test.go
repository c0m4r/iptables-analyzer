package recommender

import (
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
)

func TestDockerRecommendationMatchesOriginalPort(t *testing.T) {
	result := &models.AnalysisResult{IPv4Only: true, DockerBypasses: []models.DockerBypassFinding{{
		Code:        models.FindingDockerBypass,
		IPVersion:   models.IPv4,
		NATRule:     models.Rule{Protocol: models.ProtoTCP, IPVersion: models.IPv4},
		ExposedPort: "8080", ContainerDest: "172.17.0.2:80", Severity: models.SeverityCritical,
	}}}
	recs := Generate(result)
	if len(recs) < 2 || !strings.Contains(recs[1].Detail, "--ctorigdstport 8080 --ctdir ORIGINAL") {
		t.Fatalf("expected original-port conntrack recommendation, got %+v", recs)
	}
	if !strings.Contains(recs[1].Detail, "-I DOCKER-USER 1 ") || !strings.Contains(recs[1].Detail, "-I DOCKER-USER 2 ") {
		t.Fatalf("allow-before-drop ordering is not explicit: %s", recs[1].Detail)
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

func TestIneffectiveDockerUserRuleGetsConntrackReplacement(t *testing.T) {
	rule := models.Rule{Table: "filter", Chain: "DOCKER-USER", RuleNum: 1, Target: "DROP", Protocol: models.ProtoTCP, DstPort: "8080",
		RawLine: "-A DOCKER-USER -p tcp -m tcp --dport 8080 -j DROP", Negations: map[string]bool{}}
	recs := Generate(&models.AnalysisResult{IPv4Only: true, DockerBypasses: []models.DockerBypassFinding{{
		Code: models.FindingDockerIneffectiveRule, IPVersion: models.IPv4, Rule: &rule, Severity: models.SeverityHigh, Fix: "fix",
	}}})
	want := "iptables -R DOCKER-USER 1 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP"
	if len(recs) == 0 || !strings.Contains(recs[0].Detail, want) {
		t.Fatalf("expected replacement %q, got %+v", want, recs)
	}
}

func TestDirectRouteRecommendationUsesBridgeSubnet(t *testing.T) {
	v4, err := parser.Parse("*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\nCOMMIT\n", models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	recs := Generate(&models.AnalysisResult{IPv4Only: true, IPv4Rules: v4, DockerBypasses: []models.DockerBypassFinding{{
		Code: models.FindingDockerDirectRoute, IPVersion: models.IPv4, Bridge: "docker0", ContainerDest: "172.17.0.3:80",
		ExposedPort: "80", Severity: models.SeverityHigh, GatewayMode: "nat",
	}}})
	if len(recs) == 0 || !strings.Contains(recs[0].Detail, "iptables -t raw -I PREROUTING -d 172.17.0.0/16 ! -i docker0 -j DROP") ||
		!strings.Contains(recs[0].Detail, "! --ctstate DNAT -j DROP") {
		t.Fatalf("direct-routing recommendation is incomplete: %+v", recs)
	}
}

func TestRecommendationsAreOrderedBySeverity(t *testing.T) {
	recs := Generate(&models.AnalysisResult{IPv4Only: true, DockerBypasses: []models.DockerBypassFinding{
		{Code: models.FindingDockerPublished, IPVersion: models.IPv4, ExposedPort: "8080", Severity: models.SeverityMedium, NATRule: models.Rule{Protocol: models.ProtoTCP}},
		{Code: models.FindingDockerBypass, IPVersion: models.IPv4, ExposedPort: "3306", Severity: models.SeverityCritical, NATRule: models.Rule{Protocol: models.ProtoTCP}},
	}})
	for i := 1; i < len(recs); i++ {
		if recs[i].Severity > recs[i-1].Severity {
			t.Fatalf("recommendations are not ordered by severity: %+v", recs)
		}
	}
}

func TestSSHLimitedByPrecedingDropIsRecognized(t *testing.T) {
	rs, err := parser.Parse(`*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/min --hashlimit-mode srcip --hashlimit-name ssh -j DROP
-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
COMMIT
`, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range Generate(analyzer.Analyze(rs, nil)) {
		if strings.Contains(rec.Title, "rate limiting") {
			t.Fatalf("hashlimit DROP before the ACCEPT already limits SSH: %+v", rec)
		}
	}
}

func TestFragileRuleRecommendationMovesRuleIntoDockerUser(t *testing.T) {
	rule := models.Rule{Table: "filter", Chain: "FORWARD", RuleNum: 1, Target: "DROP", RawLine: "-A FORWARD -p tcp -m tcp --dport 80 -j DROP"}
	recs := Generate(&models.AnalysisResult{IPv4Only: true, DockerBypasses: []models.DockerBypassFinding{{
		Code: models.FindingDockerFragileRule, IPVersion: models.IPv4, Rule: &rule, Severity: models.SeverityMedium, Fix: "move it",
	}}})
	if len(recs) == 0 || !strings.Contains(recs[0].Detail, "iptables -I DOCKER-USER 1 -p tcp -m tcp --dport 80 -j DROP") ||
		!strings.Contains(recs[0].Detail, "iptables -D FORWARD 1") {
		t.Fatalf("expected move commands, got %+v", recs)
	}
}
