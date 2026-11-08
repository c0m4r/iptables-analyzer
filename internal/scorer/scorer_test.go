package scorer

import (
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
)

func parseRules(t *testing.T, data string) *models.Ruleset {
	t.Helper()
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestConditionalFinalDropDoesNotHideAcceptPolicy(t *testing.T) {
	rs := parseRules(t, `*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate INVALID -j DROP
COMMIT
`)
	score := Calculate(&models.AnalysisResult{IPv4Rules: rs, IPv4Only: true})
	if score.Breakdown["policy"] != -15 {
		t.Fatalf("expected INPUT policy deduction, got %+v", score.Breakdown)
	}
}

func TestPolicyFindingsAreNotDoubleCountedAsHygiene(t *testing.T) {
	rs := parseRules(t, `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`)
	result := analyzer.Analyze(rs, nil)
	result.IPv4Only = true
	score := Calculate(result)
	if score.Breakdown["policy"] != -25 || score.Breakdown["hygiene"] != 0 {
		t.Fatalf("unexpected breakdown: %+v", score.Breakdown)
	}
}

func TestIPv6OnlyUsesFullPolicyWeight(t *testing.T) {
	rs, err := parser.Parse(`*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`, models.IPv6)
	if err != nil {
		t.Fatal(err)
	}
	score := Calculate(&models.AnalysisResult{IPv6Rules: rs, IPv6Only: true})
	if score.Breakdown["policy"] != -25 || score.Breakdown["ipv6"] != 0 {
		t.Fatalf("unexpected IPv6-only breakdown: %+v", score.Breakdown)
	}
}

func TestScoreIsIncompleteWithoutServiceEvidence(t *testing.T) {
	rs := parseRules(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n")
	result := analyzer.Analyze(rs, nil)
	result.IPv4Only = true
	score := Calculate(result)
	if score.Complete || score.Grade != "INCOMPLETE" || len(score.Unassessed) == 0 {
		t.Fatalf("missing service evidence produced a complete score: %+v", score)
	}
	analyzer.CrossReferenceServices(result, nil)
	score = Calculate(result)
	if !score.Complete || score.Grade != "A" {
		t.Fatalf("valid empty inventory should produce a complete score: %+v", score)
	}
}

func TestExposureScoreCountsProtocolPortOnceAcrossFamilies(t *testing.T) {
	exposed := func(protocol models.Protocol, port int, family models.SocketFamily) models.ExposedServiceFinding {
		return models.ExposedServiceFinding{
			IPVersion: map[models.SocketFamily]models.IPVersion{
				models.SocketIPv4: models.IPv4,
				models.SocketIPv6: models.IPv6,
			}[family],
			Service: models.ListeningService{
				Protocol: protocol,
				Port:     port,
				Family:   family,
			},
			Scope: models.ScopeExposed,
		}
	}

	result := &models.AnalysisResult{
		IPv4Only:          true,
		ServiceAssessment: models.AssessmentComplete,
		ExposedServices: []models.ExposedServiceFinding{
			exposed(models.ProtoTCP, 8080, models.SocketIPv4),
			exposed(models.ProtoTCP, 8080, models.SocketIPv6),
			exposed(models.ProtoUDP, 8080, models.SocketIPv4),
			exposed(models.ProtoTCP, 22, models.SocketIPv4),
			exposed(models.ProtoTCP, 22, models.SocketIPv6),
		},
	}

	score := Calculate(result)
	// tcp/8080 (-2), udp/8080 (-2), and tcp/22 (-5). Address-family
	// duplicates are explanatory findings, not additional exposed ports.
	if score.Breakdown["exposure"] != -9 {
		t.Fatalf("dual-stack endpoints were double-counted: %+v", score.Breakdown)
	}
}

func TestDockerFindingsAreScoredByKind(t *testing.T) {
	result := &models.AnalysisResult{
		IPv4Only:          true,
		ServiceAssessment: models.AssessmentComplete,
		ExposedServices: []models.ExposedServiceFinding{{
			Service: models.ListeningService{Protocol: models.ProtoTCP, Port: 9000}, Scope: models.ScopeExposed,
		}},
		DockerBypasses: []models.DockerBypassFinding{
			{Code: models.FindingDockerPublished, Scope: models.ScopeExposed, ExposedPort: "9000-9002", NATRule: models.Rule{Protocol: models.ProtoTCP}},
			{Code: models.FindingDockerBypass, Severity: models.SeverityCritical},
			{Code: models.FindingDockerIneffectiveRule, Severity: models.SeverityHigh},
		},
	}
	score := Calculate(result)
	// 9000 is counted once across the listener and the published range: 3 ports × -2.
	if score.Breakdown["exposure"] != -6 {
		t.Fatalf("published ports must be charged as exposure, once per port: %+v", score.Breakdown)
	}
	if score.Breakdown["shadow"] != -17 {
		t.Fatalf("bypass (-12) and ineffective rule (-5) expected: %+v", score.Breakdown)
	}
}
