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
