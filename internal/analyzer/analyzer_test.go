package analyzer

import (
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
)

func TestShadowDetection(t *testing.T) {
	data := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
-A INPUT -p tcp --dport 80 -j DROP
-A INPUT -p tcp --dport 3306 -j DROP
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	findings := DetectShadowedRules(rs)
	if len(findings) != 2 {
		t.Fatalf("expected 2 shadowed rules, got %d", len(findings))
	}

	// Both should be shadowed by rule #1 (ACCEPT all)
	for _, f := range findings {
		if f.ShadowingRule.RuleNum != 1 {
			t.Errorf("expected shadowing rule #1, got #%d", f.ShadowingRule.RuleNum)
		}
		if f.Severity != models.SeverityHigh {
			t.Errorf("expected HIGH severity (opposite actions), got %s", f.Severity.String())
		}
	}
}

func TestNoShadowForDifferentProtocols(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p udp --dport 80 -j ACCEPT
COMMIT
`
	rs, _ := parser.Parse(data, models.IPv4)
	findings := DetectShadowedRules(rs)
	if len(findings) != 0 {
		t.Errorf("expected 0 shadowed rules (different protocols), got %d", len(findings))
	}
}

func TestCIDRContains(t *testing.T) {
	tests := []struct {
		outer, inner string
		expected     bool
	}{
		{"10.0.0.0/8", "10.1.2.0/24", true},
		{"10.0.0.0/8", "192.168.1.0/24", false},
		{"0.0.0.0/0", "10.0.0.0/8", true},
		{"10.0.0.0/24", "10.0.0.0/16", false}, // inner is wider
		{"10.0.0.5/32", "10.0.0.5/32", true},
	}

	for _, tt := range tests {
		got := cidrContains(tt.outer, tt.inner)
		if got != tt.expected {
			t.Errorf("cidrContains(%s, %s) = %v, want %v", tt.outer, tt.inner, got, tt.expected)
		}
	}
}

func TestDockerBypassDetection(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -j DOCKER
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
-A INPUT -p tcp --dport 8080 -j DROP
-A DOCKER-USER -j RETURN
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	findings := DetectDockerBypasses(rs)

	// Should find the bypass: port 8080 blocked in INPUT but DNAT'd
	hasBypass := false
	for _, f := range findings {
		if f.ExposedPort == "8080" && f.Severity == models.SeverityCritical {
			hasBypass = true
		}
	}
	if !hasBypass {
		t.Errorf("expected to find CRITICAL Docker bypass for port 8080, findings: %+v", findings)
	}
}

func TestDeadRuleDetection(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`
	rs, _ := parser.Parse(data, models.IPv4)
	findings := CheckEffectiveness(rs)

	hasDeadRule := false
	for _, f := range findings {
		if f.Title == "Dead rule in filter/INPUT" {
			hasDeadRule = true
		}
	}
	if !hasDeadRule {
		t.Error("expected to find dead rule after catch-all DROP")
	}
}

func testService() models.ListeningService {
	return models.ListeningService{
		Protocol:   models.ProtoTCP,
		Address:    "0.0.0.0",
		Port:       8080,
		IsWildcard: true,
	}
}

func TestServiceExposureFollowsUserDefinedChain(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
:SERVICE - [0:0]
-A INPUT -p tcp --dport 8080 -j SERVICE
-A SERVICE -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Scope != models.ScopeExposed {
		t.Fatalf("expected custom-chain ACCEPT to expose service, got %+v", result.ExposedServices)
	}
}

func TestServiceExposureHonorsFirstTerminalRule(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 8080 -j DROP
-A INPUT -p tcp --dport 8080 -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 0 {
		t.Fatalf("expected earlier DROP to filter service, got %+v", result.ExposedServices)
	}
}

func TestDefaultAcceptIsNotHiddenByNarrowAllow(t *testing.T) {
	data := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 10.0.0.1/32 -p tcp --dport 8080 -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Scope != models.ScopeExposed {
		t.Fatalf("expected default ACCEPT exposure, got %+v", result.ExposedServices)
	}
}

func TestSourceRestrictionsAreClassified(t *testing.T) {
	tests := []struct {
		name   string
		source string
		scope  models.AccessScope
	}{
		{"host", "203.0.113.7/32", models.ScopeWhitelisted},
		{"private network", "10.0.0.0/8", models.ScopeLocalnet},
		{"public network", "203.0.113.0/24", models.ScopeExposed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := "*filter\n:INPUT DROP [0:0]\n-A INPUT -s " + tt.source + " -p tcp --dport 8080 -j ACCEPT\nCOMMIT\n"
			rs, err := parser.Parse(data, models.IPv4)
			if err != nil {
				t.Fatal(err)
			}
			result := Analyze(rs, nil)
			CrossReferenceServices(result, []models.ListeningService{testService()})
			if len(result.ExposedServices) != 1 || result.ExposedServices[0].Scope != tt.scope {
				t.Fatalf("expected %s, got %+v", tt.scope, result.ExposedServices)
			}
		})
	}
}

func TestDockerForwardRestrictionUsesTranslatedPort(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -j DOCKER
-A DOCKER -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
:DOCKER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER
-A DOCKER-USER -p tcp --dport 80 -j DROP
-A DOCKER-USER -j RETURN
-A DOCKER -d 172.17.0.2/32 -p tcp --dport 80 -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	if findings := DetectDockerBypasses(rs); len(findings) != 0 {
		t.Fatalf("expected translated port 80 block to restrict forwarding, got %+v", findings)
	}
}

func TestDockerIgnoresOutputOnlyDNAT(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	if findings := DetectDockerBypasses(rs); len(findings) != 0 {
		t.Fatalf("expected OUTPUT-only DNAT to be excluded, got %+v", findings)
	}
}

func TestDockerHonorsNATSourceRestriction(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -s 203.0.113.7/32 -j DOCKER
-A DOCKER -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	if findings := DetectDockerBypasses(rs); len(findings) != 0 {
		t.Fatalf("source-whitelisted DNAT must not be reported as unrestricted: %+v", findings)
	}
}

func TestDockerIgnoresLoopbackBoundDNAT(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -d 127.0.0.1/32 -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	if findings := DetectDockerBypasses(rs); len(findings) != 0 {
		t.Fatalf("loopback-bound DNAT must not be reported as externally exposed: %+v", findings)
	}
}

func TestBuiltinReturnAppliesPolicy(t *testing.T) {
	data := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 8080 -j RETURN
-A INPUT -p tcp --dport 8080 -j DROP
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 {
		t.Fatalf("expected RETURN to apply builtin ACCEPT policy, got %+v", result.ExposedServices)
	}
}

func TestGotoDoesNotResumeAtNextCallerRule(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
:CUSTOM - [0:0]
-A INPUT -p tcp --dport 8080 -g CUSTOM
-A INPUT -p tcp --dport 8080 -j ACCEPT
-A CUSTOM -j RETURN
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 0 {
		t.Fatalf("expected goto RETURN to apply INPUT policy, got %+v", result.ExposedServices)
	}
}

func TestNegatedSourceIsEvaluated(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
-A INPUT ! -s 10.0.0.0/8 -p tcp --dport 8080 -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Scope != models.ScopeExposed {
		t.Fatalf("expected public sources outside 10/8 to be exposed, got %+v", result.ExposedServices)
	}
}

func TestUnknownExtensionCannotProveShadowOrDeadRule(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
-A INPUT -m set --match-set allowed src -j ACCEPT
-A INPUT -p tcp --dport 80 -j DROP
-A INPUT -m statistic --mode random --probability 0.5 -j DROP
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	if findings := DetectShadowedRules(rs); len(findings) != 0 {
		t.Fatalf("unknown set match must not prove shadowing: %+v", findings)
	}
	for _, finding := range CheckEffectiveness(rs) {
		if finding.Title == "Dead rule in filter/INPUT" {
			t.Fatalf("probabilistic DROP must not make later rules dead: %+v", finding)
		}
	}
}
