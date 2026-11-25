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
	result := analyzer.Analyze(rs, nil)
	result.IPv4Only = true
	score := Calculate(result)
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
	// INPUT -15; FORWARD -5 while nothing shows that the host routes packets.
	if score.Breakdown["policy"] != -20 || score.Breakdown["hygiene"] != 0 {
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
	result := analyzer.Analyze(nil, rs)
	result.IPv6Only = true
	score := Calculate(result)
	if score.Breakdown["policy"] != -20 || score.Breakdown["ipv6"] != 0 {
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

func analyzed(t *testing.T, data string) *models.AnalysisResult {
	t.Helper()
	result := analyzer.Analyze(parseRules(t, data), nil)
	result.IPv4Only = true
	analyzer.CrossReferenceServices(result, nil)
	return result
}

// Audit A1, E1: a firewall that accepts every connection cannot get a good
// grade, whatever the policy line says and whether or not something listens.
func TestAcceptAllRulesetIsGradedF(t *testing.T) {
	for name, data := range map[string]string{
		"rule under a DROP policy": "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n",
		"ACCEPT policy":            "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n",
	} {
		score := Calculate(analyzed(t, data))
		if score.Grade != "F" || score.Breakdown["policy"] != -15 || score.Cap == "" {
			t.Errorf("%s: grade %s, %+v, cap %q", name, score.Grade, score.Breakdown, score.Cap)
		}
	}
}

// Audit B2: an ACCEPT policy behind a final REJECT denies by default.
func TestFinalRejectUnderAcceptPolicyIsDefaultDeny(t *testing.T) {
	score := Calculate(analyzed(t, "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"+
		"-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -i lo -j ACCEPT\n"+
		"-A INPUT -j REJECT --reject-with icmp-host-prohibited\n-A FORWARD -j REJECT --reject-with icmp-host-prohibited\nCOMMIT\n"))
	if score.Total != 100 || score.Grade != "A" {
		t.Fatalf("classic RHEL layout: %d %s %+v", score.Total, score.Grade, score.Breakdown)
	}
}

// Audit A2: wide port ranges open to any source cost points without a
// listener, and a host that routes packets pays more for an open FORWARD.
func TestBroadAcceptAndRoutingAreScored(t *testing.T) {
	broad := Calculate(analyzed(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"+
		"-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"+
		"-A INPUT -p udp -m udp --dport 1024:65535 -j ACCEPT\nCOMMIT\n"))
	if broad.Breakdown["exposure"] != -10 {
		t.Errorf("wide UDP range: %+v", broad.Breakdown)
	}
	router := Calculate(analyzed(t, "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -o eth0 -j MASQUERADE\nCOMMIT\n"+
		"*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"+
		"-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\nCOMMIT\n"))
	if router.Breakdown["policy"] != -10 {
		t.Errorf("open FORWARD on a host that translates addresses: %+v", router.Breakdown)
	}
}

// Audit E2: a finding that is only possible costs half.
func TestPossibleFindingsCostHalf(t *testing.T) {
	result := &models.AnalysisResult{
		IPv4Only:          true,
		ServiceAssessment: models.AssessmentComplete,
		ExposedServices: []models.ExposedServiceFinding{
			{Service: models.ListeningService{Protocol: models.ProtoTCP, Port: 22}, Scope: models.ScopeExposed, Certainty: models.CertaintyPossible},
			{Service: models.ListeningService{Protocol: models.ProtoTCP, Port: 8080}, Scope: models.ScopeExposed, Certainty: models.CertaintyPossible},
			{Service: models.ListeningService{Protocol: models.ProtoUDP, Port: 68}, Scope: models.ScopeExposed, Condition: "source port 67"},
			{Service: models.ListeningService{Protocol: models.ProtoTCP, Port: 80}, Scope: models.ScopeRestricted},
		},
		DockerBypasses: []models.DockerBypassFinding{{Code: models.FindingDockerDirectRoute, Severity: models.SeverityHigh, Certainty: models.CertaintyPossible}},
	}
	score := Calculate(result)
	// 22: 3 (half of 5), 8080: 1 (half of 2), 68: 1 (source port), 80: 0 (not exposed).
	if score.Breakdown["exposure"] != -5 || score.Breakdown["shadow"] != -3 {
		t.Fatalf("unexpected breakdown: %+v", score.Breakdown)
	}
}
