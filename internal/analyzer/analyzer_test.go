package analyzer

import (
	"strings"
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
		name    string
		version models.IPVersion
		rules   string
		scope   models.AccessScope
	}{
		{"host", models.IPv4, "-A INPUT -s 203.0.113.7/32 -p tcp --dport 8080 -j ACCEPT", models.ScopeWhitelisted},
		{"private host", models.IPv4, "-A INPUT -s 192.168.88.10/32 -p tcp --dport 8080 -j ACCEPT", models.ScopeWhitelisted},
		{"private network", models.IPv4, "-A INPUT -s 10.0.0.0/8 -p tcp --dport 8080 -j ACCEPT", models.ScopeLocalnet},
		{"public network", models.IPv4, "-A INPUT -s 203.0.113.0/24 -p tcp --dport 8080 -j ACCEPT", models.ScopeSubnet},
		{"public network for all protocols", models.IPv4, "-A INPUT -s 203.0.113.0/24 -j ACCEPT", models.ScopeSubnet},
		{"public /16", models.IPv4, "-A INPUT -s 198.51.0.0/16 -p tcp --dport 8080 -j ACCEPT", models.ScopeSubnet},
		{"public /15", models.IPv4, "-A INPUT -s 198.50.0.0/15 -p tcp --dport 8080 -j ACCEPT", models.ScopeExposed},
		{"public network beside private one", models.IPv4, "-A INPUT -s 10.0.0.0/8 -j ACCEPT\n-A INPUT -s 203.0.113.0/24 -j ACCEPT", models.ScopeSubnet},
		{"public networks adding up beyond a /16", models.IPv4, "-A INPUT -s 198.51.0.0/16 -j ACCEPT\n-A INPUT -s 203.0.113.0/24 -j ACCEPT", models.ScopeExposed},
		{"any source", models.IPv4, "-A INPUT -s 0.0.0.0/0 -p tcp --dport 8080 -j ACCEPT", models.ScopeExposed},
		{"all but a private network", models.IPv4, "-A INPUT ! -s 10.0.0.0/8 -p tcp --dport 8080 -j ACCEPT", models.ScopeExposed},
		{"public network minus a host", models.IPv4, "-A INPUT -s 203.0.113.9/32 -j DROP\n-A INPUT -s 203.0.113.0/24 -j ACCEPT", models.ScopeSubnet},
		{"IPv6 site", models.IPv6, "-A INPUT -s 2001:db8:1::/48 -p tcp --dport 8080 -j ACCEPT", models.ScopeSubnet},
		{"IPv6 provider range", models.IPv6, "-A INPUT -s 2001:db8::/32 -p tcp --dport 8080 -j ACCEPT", models.ScopeExposed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := "*filter\n:INPUT DROP [0:0]\n" + tt.rules + "\nCOMMIT\n"
			rs, err := parser.Parse(data, tt.version)
			if err != nil {
				t.Fatal(err)
			}
			var result *models.AnalysisResult
			svc := testService()
			if tt.version == models.IPv6 {
				result = Analyze(nil, rs)
				svc.Address, svc.IsIPv6, svc.Family = "::", true, models.SocketIPv6
			} else {
				result = Analyze(rs, nil)
			}
			CrossReferenceServices(result, []models.ListeningService{svc})
			if len(result.ExposedServices) != 1 || result.ExposedServices[0].Scope != tt.scope {
				t.Fatalf("expected %s, got %+v", tt.scope, result.ExposedServices)
			}
			finding := result.ExposedServices[0]
			if tt.scope != models.ScopeExposed && (finding.Severity != models.SeverityLow || strings.Contains(finding.Reason, "from the network")) {
				t.Fatalf("source-restricted service reported as a network exposure: %+v", finding)
			}
		})
	}
}

func TestWorkSubnetAllowIsNotReportedAsExposure(t *testing.T) {
	data := "*filter\n:INPUT DROP [0:0]\n-A INPUT -s 203.0.113.0/24 -m comment --comment \"work subnet\" -j ACCEPT\nCOMMIT\n"
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	svc := testService()
	svc.Port, svc.Process = 22, "sshd"
	CrossReferenceServices(result, []models.ListeningService{svc})
	if len(result.ExposedServices) != 1 {
		t.Fatalf("expected one finding, got %+v", result.ExposedServices)
	}
	finding := result.ExposedServices[0]
	if finding.Scope != models.ScopeSubnet || finding.Severity != models.SeverityLow ||
		finding.AllowingRule == nil || finding.AllowingRule.RuleNum != 1 ||
		!strings.Contains(finding.Reason, "from specific public networks") {
		t.Fatalf("unexpected finding: %+v", finding)
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
	findings := DetectDockerBypasses(rs)
	if published := withCodes(findings, models.FindingDockerBypass, models.FindingDockerPublished); len(published) != 0 {
		t.Fatalf("source-whitelisted DNAT must not be reported as unrestricted: %+v", published)
	}
	// FORWARD ACCEPT without raw/PREROUTING protection still forwards packets
	// routed straight to the container address.
	if direct := withCodes(findings, models.FindingDockerDirectRoute); len(direct) != 1 || direct[0].Certainty != models.CertaintyPossible {
		t.Fatalf("expected a possible direct-routing finding, got %+v", findings)
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

func TestFragmentRuleCannotHideReachableServiceOrProveShadow(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
-A INPUT -f -j DROP
-A INPUT -p tcp --dport 8080 -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	// Unfragmented packets never match -f, so the ACCEPT path is definite.
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Certainty != models.CertaintyDefinite {
		t.Fatalf("fragment-only DROP hid reachable traffic: %+v", result.ExposedServices)
	}
	if len(result.ShadowedRules) != 0 {
		t.Fatalf("fragment-only rule proved shadowing: %+v", result.ShadowedRules)
	}
	for _, finding := range result.EffectiveIssues {
		if finding.Code == models.FindingDeadRule {
			t.Fatalf("fragment-only rule made later rule dead: %+v", finding)
		}
	}
}

func TestDualStackWildcardIsEvaluatedForIPv6(t *testing.T) {
	v4, err := parser.Parse("*filter\n:INPUT DROP [0:0]\nCOMMIT\n", models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	v6, err := parser.Parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", models.IPv6)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(v4, v6)
	CrossReferenceServices(result, []models.ListeningService{{
		Protocol: models.ProtoTCP, Address: "*", Port: 22, IsWildcard: true, Family: models.SocketDual,
	}})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].IPVersion != models.IPv6 {
		t.Fatalf("dual-stack wildcard did not reach IPv6 analysis: %+v", result.ExposedServices)
	}
}

func TestCrossReferenceDeduplicatesRepeatedListeners(t *testing.T) {
	v4, err := parser.Parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	v6, err := parser.Parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", models.IPv6)
	if err != nil {
		t.Fatal(err)
	}

	udp4 := models.ListeningService{
		Protocol: models.ProtoUDP, Address: "0.0.0.0", Port: 5353,
		Process: "kdeconnectd", PID: 1918, IsWildcard: true, Family: models.SocketIPv4,
	}
	udp6 := models.ListeningService{
		Protocol: models.ProtoUDP, Address: "::", Port: 5353,
		Process: "kdeconnectd", PID: 1918, IsIPv6: true, IsWildcard: true, Family: models.SocketIPv6,
	}
	result := Analyze(v4, v6)
	CrossReferenceServices(result, []models.ListeningService{udp4, udp6, udp4, udp6, udp6})

	if len(result.Services) != 2 {
		t.Fatalf("expected one logical listener per address family, got %+v", result.Services)
	}
	if len(result.ExposedServices) != 2 {
		t.Fatalf("expected one exposure finding per address family, got %+v", result.ExposedServices)
	}
	if result.ExposedServices[0].IPVersion != models.IPv4 || result.ExposedServices[1].IPVersion != models.IPv6 {
		t.Fatalf("expected distinct IPv4 and IPv6 findings, got %+v", result.ExposedServices)
	}
}

func TestCrossReferenceKeepsDifferentProcessesOnSharedListener(t *testing.T) {
	v4, err := parser.Parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	first := models.ListeningService{
		Protocol: models.ProtoUDP, Address: "0.0.0.0", Port: 5353,
		Process: "worker", PID: 100, IsWildcard: true, Family: models.SocketIPv4,
	}
	second := first
	second.PID = 101

	result := Analyze(v4, nil)
	CrossReferenceServices(result, []models.ListeningService{first, second})

	if len(result.Services) != 2 || len(result.ExposedServices) != 2 {
		t.Fatalf("listeners owned by different processes were merged: services=%+v findings=%+v", result.Services, result.ExposedServices)
	}
}

func TestAllowingRuleKeepsCustomChainIdentity(t *testing.T) {
	data := `*filter
:INPUT DROP [0:0]
:SSH - [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 8080 -j SSH
-A SSH -p tcp --dport 8080 -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].AllowingRule == nil {
		t.Fatalf("missing exposure: %+v", result.ExposedServices)
	}
	rule := result.ExposedServices[0].AllowingRule
	if rule.Chain != "SSH" || rule.RuleNum != 1 {
		t.Fatalf("wrong allowing-rule identity: %+v", rule)
	}
}

func TestDockerConntrackDNATStateAllowsNewTranslatedConnection(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -m conntrack --ctstate DNAT -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	if findings := DetectDockerBypasses(rs); len(findings) != 1 || findings[0].ExposedPort != "8080" {
		t.Fatalf("DNAT state was treated as excluding NEW: %+v", findings)
	}
}

func TestDockerPortRangeEvaluatesEveryPublishedPort(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 8080:8081 -j DNAT --to-destination 172.17.0.2
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -p tcp --dport 8080 -j DROP
-A FORWARD -p tcp --dport 8081 -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	findings := DetectDockerBypasses(rs)
	if len(findings) != 1 || findings[0].ExposedPort != "8081" {
		t.Fatalf("later exposed port in range was missed: %+v", findings)
	}
}

func TestParseDNATTargetDistinguishesBareIPv6(t *testing.T) {
	if host, port := ParseDNATTarget("2001:db8::2"); host != "2001:db8::2" || port != 0 {
		t.Fatalf("bare IPv6 address was split as a port: %q %d", host, port)
	}
	if host, port := ParseDNATTarget("[2001:db8::2]:80"); host != "2001:db8::2" || port != 80 {
		t.Fatalf("bracketed IPv6 target was not parsed: %q %d", host, port)
	}
}

func TestUnsupportedDNATProducesAssessmentDiagnostic(t *testing.T) {
	rs, err := parser.Parse("*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j DNAT --to-destination 172.17.0.2\nCOMMIT\n", models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(rs, nil)
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Area != "docker" {
		t.Fatalf("unsupported DNAT was silently omitted: %+v", result.Diagnostics)
	}
}

func TestNATTraversalHonorsConditionalReturn(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -j DOCKER
-A DOCKER -p tcp --dport 8080 -j RETURN
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
		t.Fatalf("unreachable DNAT after RETURN was reported: %+v", findings)
	}
}

func TestNATTraversalHonorsParentPredicates(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
:CUSTOM - [0:0]
-A PREROUTING -p udp --dport 8080 -j CUSTOM
-A CUSTOM -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
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
		t.Fatalf("conflicting parent and child predicates were reported: %+v", findings)
	}
}

func TestNATTraversalHonorsConflictingInterfaces(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
:CUSTOM - [0:0]
-A PREROUTING -i eth0 -j CUSTOM
-A CUSTOM -i eth1 -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
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
		t.Fatalf("conflicting interfaces were reported as reachable: %+v", findings)
	}
}

func TestNATGotoReturnDoesNotResumeCaller(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
:CUSTOM - [0:0]
-A PREROUTING -p tcp --dport 8080 -g CUSTOM
-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
-A CUSTOM -j RETURN
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
		t.Fatalf("goto RETURN incorrectly resumed the caller: %+v", findings)
	}
}

func TestDockerOriginalPortProtectionIsRecognized(t *testing.T) {
	data := `*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
:DOCKER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER
-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 -j DROP
-A DOCKER-USER -j RETURN
-A DOCKER -p tcp --dport 80 -j ACCEPT
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	findings := DetectDockerBypasses(rs)
	if published := withCodes(findings, models.FindingDockerBypass, models.FindingDockerPublished); len(published) != 0 {
		t.Fatalf("original-port protection was ignored: %+v", published)
	}
	// --ctorigdstport does not see packets routed directly to 172.17.0.2:80.
	direct := withCodes(findings, models.FindingDockerDirectRoute)
	if len(direct) != 1 || direct[0].Severity != models.SeverityHigh || direct[0].ContainerDest != "172.17.0.2:80" {
		t.Fatalf("expected direct routing to bypass the original-port restriction, got %+v", findings)
	}
}

func withCodes(findings []models.DockerBypassFinding, codes ...models.FindingCode) []models.DockerBypassFinding {
	var selected []models.DockerBypassFinding
	for _, finding := range findings {
		for _, code := range codes {
			if finding.Code == code {
				selected = append(selected, finding)
			}
		}
	}
	return selected
}

func TestStatefulMatchesDoNotProveShadowing(t *testing.T) {
	for _, match := range []string{
		"-m limit --limit 1/min --limit-burst 1",
		"-m statistic --mode random --probability 0.5",
	} {
		data := "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 80 " + match + " -j ACCEPT\n-A INPUT -p tcp --dport 80 " + match + " -j ACCEPT\nCOMMIT\n"
		rs, err := parser.Parse(data, models.IPv4)
		if err != nil {
			t.Fatal(err)
		}
		if findings := DetectShadowedRules(rs); len(findings) != 0 {
			t.Fatalf("stateful match %q proved shadowing: %+v", match, findings)
		}
	}
}

func TestPolicyAcceptedPrivateSourcesAreLocalnet(t *testing.T) {
	rs := parseRules(t, "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT ! -s 10.0.0.0/8 -j DROP\nCOMMIT\n", models.IPv4)
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Scope != models.ScopeLocalnet {
		t.Fatalf("sources accepted by the chain policy must keep their scope: %+v", result.ExposedServices)
	}
}

func TestRateLimitDropDoesNotMakeExposurePossible(t *testing.T) {
	rs := parseRules(t, `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -m tcp --dport 8080 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/min --hashlimit-mode srcip --hashlimit-name web -j DROP
-A INPUT -p tcp -m tcp --dport 8080 -m conntrack --ctstate NEW -j ACCEPT
COMMIT
`, models.IPv4)
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Certainty != models.CertaintyDefinite {
		t.Fatalf("traffic under the limit is definitely accepted: %+v", result.ExposedServices)
	}
}

func TestUndecidableAcceptIsPossible(t *testing.T) {
	rs := parseRules(t, "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 8080 -m set --match-set admins src -j ACCEPT\nCOMMIT\n", models.IPv4)
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Certainty != models.CertaintyPossible {
		t.Fatalf("an ipset-dependent accept is only possible: %+v", result.ExposedServices)
	}
}

func TestInterfaceRestrictedServiceIsDefinite(t *testing.T) {
	rs := parseRules(t, "*filter\n:INPUT DROP [0:0]\n-A INPUT -i eth0 -p tcp --dport 8080 -j ACCEPT\nCOMMIT\n", models.IPv4)
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 {
		t.Fatalf("expected an exposure via eth0, got %+v", result.ExposedServices)
	}
	finding := result.ExposedServices[0]
	if finding.Certainty != models.CertaintyDefinite || len(finding.Interfaces) != 1 || finding.Interfaces[0] != "eth0" {
		t.Fatalf("exposure should be definite and limited to eth0: %+v", finding)
	}
}

func TestInterfaceBlockLeavesOtherInterfacesPossible(t *testing.T) {
	rs := parseRules(t, "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -i eth0 -p tcp --dport 8080 -j DROP\nCOMMIT\n", models.IPv4)
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Certainty != models.CertaintyPossible {
		t.Fatalf("other interfaces may exist in saved rules: %+v", result.ExposedServices)
	}
	live := AnalyzeHost(rs, nil, &models.HostContext{Interfaces: []models.HostInterface{{Name: "lo"}, {Name: "eth0"}}})
	CrossReferenceServices(live, []models.ListeningService{testService()})
	if len(live.ExposedServices) != 0 {
		t.Fatalf("eth0 is the only external interface of the live host: %+v", live.ExposedServices)
	}
}

func TestLoopbackDestinationRuleDoesNotAdmitExternalTraffic(t *testing.T) {
	rs := parseRules(t, "*filter\n:INPUT DROP [0:0]\n-A INPUT -d 127.0.0.1/32 -j ACCEPT\nCOMMIT\n", models.IPv4)
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 0 {
		t.Fatalf("external packets cannot be addressed to loopback: %+v", result.ExposedServices)
	}
}

func TestBlockedLoopbackIsReported(t *testing.T) {
	rs := parseRules(t, "*filter\n:INPUT DROP [0:0]\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\nCOMMIT\n", models.IPv4)
	if !hasEffectiveness(CheckEffectiveness(rs), models.FindingMissingLoopback) {
		t.Fatal("expected the dropped loopback interface to be reported")
	}
	rs = parseRules(t, "*filter\n:INPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\nCOMMIT\n", models.IPv4)
	if hasEffectiveness(CheckEffectiveness(rs), models.FindingMissingLoopback) {
		t.Fatal("loopback accept was not recognized")
	}
}

func TestMissingConntrackWithDefaultDenyIsHigh(t *testing.T) {
	rs := parseRules(t, "*filter\n:INPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\nCOMMIT\n", models.IPv4)
	for _, finding := range CheckEffectiveness(rs) {
		if finding.Code == models.FindingMissingConntrack && finding.Severity != models.SeverityHigh {
			t.Fatalf("default deny without ESTABLISHED drops replies: %+v", finding)
		}
	}
}

func TestIPv6NeighborDiscoveryBlocked(t *testing.T) {
	blocked := parseRules(t, `*filter
:INPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p ipv6-icmp -m conntrack --ctstate NEW -j ACCEPT
COMMIT
`, models.IPv6)
	if !hasEffectiveness(CheckEffectiveness(blocked), models.FindingIPv6NDPBlocked) {
		t.Fatal("untracked neighbor discovery is not admitted by NEW or ESTABLISHED rules")
	}
	allowed := parseRules(t, `*filter
:INPUT DROP [0:0]
-A INPUT -p ipv6-icmp -j ACCEPT
COMMIT
`, models.IPv6)
	if hasEffectiveness(CheckEffectiveness(allowed), models.FindingIPv6NDPBlocked) {
		t.Fatal("a blanket ICMPv6 accept admits neighbor discovery")
	}
	typed := parseRules(t, `*filter
:INPUT DROP [0:0]
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT
COMMIT
`, models.IPv6)
	if hasEffectiveness(CheckEffectiveness(typed), models.FindingIPv6NDPBlocked) {
		t.Fatalf("typed neighbor discovery accepts were not recognized: %+v", CheckEffectiveness(typed))
	}
}

func TestMultipleConntrackMatchesAreAllEvaluated(t *testing.T) {
	rule := parseRules(t, "*filter\n:FORWARD DROP [0:0]\n-A FORWARD -m conntrack --ctstate NEW -m conntrack ! --ctstate DNAT -j DROP\nCOMMIT\n", models.IPv4).Tables["filter"].Chains["FORWARD"].Rules[0]
	if got := ruleMatchesQuery(&rule, packetQuery{Protocol: "tcp", State: "NEW", NATState: "DNAT"}); got != matchNo {
		t.Fatalf("DNATed connection matched ! --ctstate DNAT: %v", got)
	}
	if got := ruleMatchesQuery(&rule, packetQuery{Protocol: "tcp", State: "NEW", NATState: noNAT}); got != matchYes {
		t.Fatalf("untranslated NEW connection did not match: %v", got)
	}
	if got := ruleMatchesQuery(&rule, packetQuery{Protocol: "tcp", State: "ESTABLISHED", NATState: noNAT}); got != matchNo {
		t.Fatalf("ESTABLISHED matched --ctstate NEW: %v", got)
	}
}

func TestTargetOptionsDoNotCreateUncertainty(t *testing.T) {
	rs := parseRules(t, `*mangle
:FORWARD ACCEPT [0:0]
-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
COMMIT
*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 8080 -j LOG --log-prefix "in: "
-A INPUT -p tcp --dport 8080 -j ACCEPT
COMMIT
`, models.IPv4)
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Certainty != models.CertaintyDefinite {
		t.Fatalf("non-verdict targets must not add uncertainty: %+v", result.ExposedServices)
	}
}

func hasEffectiveness(findings []models.EffectivenessFinding, code models.FindingCode) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func TestQueueVerdictIsPossibleExposure(t *testing.T) {
	rs := parseRules(t, "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 1\nCOMMIT\n", models.IPv4)
	result := Analyze(rs, nil)
	CrossReferenceServices(result, []models.ListeningService{testService()})
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].Certainty != models.CertaintyPossible {
		t.Fatalf("userspace verdicts can accept: %+v", result.ExposedServices)
	}
}

func TestNotrackMakesStatefulChecksUncertain(t *testing.T) {
	rs := parseRules(t, `*raw
:PREROUTING ACCEPT [0:0]
-A PREROUTING -j CT --notrack
COMMIT
*filter
:INPUT DROP [0:0]
COMMIT
`, models.IPv6)
	// Untracked packets change conntrack state; a definite "dropped" claim is
	// not possible, so no neighbor-discovery finding may be produced.
	if hasEffectiveness(CheckEffectiveness(rs), models.FindingIPv6NDPBlocked) {
		t.Fatal("NOTRACK must make state-dependent conclusions uncertain")
	}
}
