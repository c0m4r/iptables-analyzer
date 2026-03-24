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
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
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
