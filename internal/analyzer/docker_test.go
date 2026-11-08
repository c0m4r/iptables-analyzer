package analyzer

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
)

// The docker29 fixtures are unmodified captures from Docker 29.9.3. Every
// variant below was also reproduced on that host: the expected verdict is the
// observed one (a probe container either reached the published port or timed out).

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func parseRules(t *testing.T, data string, version models.IPVersion) *models.Ruleset {
	t.Helper()
	rs, err := parser.Parse(data, version)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return rs
}

// insertRule adds line to table directly after the first line starting with after.
func insertRule(t *testing.T, data, table, after, line string) string {
	t.Helper()
	lines := strings.Split(data, "\n")
	current := ""
	for i, l := range lines {
		if strings.HasPrefix(l, "*") {
			current = l[1:]
		}
		if current == table && strings.HasPrefix(l, after) {
			out := append([]string{}, lines[:i+1]...)
			out = append(out, line)
			return strings.Join(append(out, lines[i+1:]...), "\n")
		}
	}
	t.Fatalf("anchor %q not found in table %s", after, table)
	return ""
}

func removeRule(t *testing.T, data, line string) string {
	t.Helper()
	if !strings.Contains(data, line+"\n") {
		t.Fatalf("rule %q not found", line)
	}
	return strings.Replace(data, line+"\n", "", 1)
}

func docker29(t *testing.T) string {
	return readFixture(t, "docker29.iptables-save")
}

func findingsFor(findings []models.DockerBypassFinding, code models.FindingCode, containerDest string) []models.DockerBypassFinding {
	var selected []models.DockerBypassFinding
	for _, finding := range findings {
		if finding.Code == code && (containerDest == "" || strings.Contains(finding.ContainerDest, containerDest)) {
			selected = append(selected, finding)
		}
	}
	return selected
}

func TestDocker29PublishedPortsAreDefiniteAndAttributedToBridges(t *testing.T) {
	analysis := AnalyzeDocker(parseRules(t, docker29(t), models.IPv4), nil)

	want := map[string]string{
		"8080": "docker0", "8082": "docker0", "9053": "docker0", "9000": "docker0", "9001": "docker0",
		"9002": "docker0", "8443": "br-7a3442937ee6", "8091": "br-982052ef0162",
	}
	if len(analysis.PublishedPorts) != len(want) {
		t.Fatalf("expected %d published ports, got %+v", len(want), analysis.PublishedPorts)
	}
	for _, mapping := range analysis.PublishedPorts {
		port := strconv.Itoa(mapping.HostPort)
		if want[port] != mapping.Bridge {
			t.Errorf("port %s: bridge %q, want %q", port, mapping.Bridge, want[port])
		}
		if mapping.Certainty != models.CertaintyDefinite || mapping.ForwardScope != models.ScopeExposed {
			t.Errorf("port %s: expected a definite exposure, got %+v", port, mapping)
		}
		if mapping.HostPort == 8081 {
			t.Errorf("loopback-only publication was treated as externally published: %+v", mapping)
		}
	}
	for _, mapping := range analysis.PublishedPorts {
		if mapping.HostPort == 8082 && mapping.HostAddr != "192.168.88.217" {
			t.Errorf("host-address binding was lost: %+v", mapping)
		}
	}

	// INPUT is ACCEPT in the capture: published ports are exposures, not bypasses.
	if bypasses := findingsFor(analysis.Findings, models.FindingDockerBypass, ""); len(bypasses) != 0 {
		t.Fatalf("open INPUT cannot be bypassed: %+v", bypasses)
	}
	published := findingsFor(analysis.Findings, models.FindingDockerPublished, "")
	if len(published) != 6 { // 9000-9002 is merged into one finding
		t.Fatalf("expected 6 published-port findings, got %+v", published)
	}
	for _, finding := range published {
		if finding.Certainty != models.CertaintyDefinite {
			t.Errorf("published port should be definite: %+v", finding)
		}
		if strings.HasPrefix(finding.Reason, "Possible") {
			t.Errorf("definite finding labelled possible: %s", finding.Reason)
		}
	}
	if merged := findingsFor(published, models.FindingDockerPublished, "172.17.0.6"); len(merged) != 1 || merged[0].ExposedPort != "9000-9002" {
		t.Fatalf("consecutive published ports were not merged: %+v", merged)
	}
}

func TestDocker29GatewayModesAreDetected(t *testing.T) {
	analysis := AnalyzeDocker(parseRules(t, docker29(t), models.IPv4), nil)
	direct := findingsFor(analysis.Findings, models.FindingDockerDirectRoute, "")
	if len(direct) != 2 {
		t.Fatalf("expected nat-unprotected and routed findings only, got %+v", direct)
	}
	byMode := map[string]models.DockerBypassFinding{}
	for _, finding := range direct {
		byMode[finding.GatewayMode] = finding
	}
	if open := byMode["nat-unprotected"]; open.Severity != models.SeverityHigh || open.ExposedPort != "all" || open.Bridge != "br-982052ef0162" {
		t.Errorf("nat-unprotected bridge must expose every container port: %+v", open)
	}
	if routed := byMode["routed"]; routed.Severity != models.SeverityMedium || routed.ContainerDest != "172.31.0.2:80" {
		t.Errorf("routed bridge must expose the published container port: %+v", routed)
	}
	// Docker 28+ raw/PREROUTING rules protect NAT-mode containers, including
	// the one published only on 127.0.0.1.
	for _, finding := range direct {
		if strings.Contains(finding.ContainerDest, "172.17.0.") {
			t.Errorf("raw-protected container reported as directly routable: %+v", finding)
		}
	}
}

func TestDocker29InputRuleIsBypassed(t *testing.T) {
	data := insertRule(t, docker29(t), "filter", ":DOCKER-USER", "-A INPUT -p tcp -m tcp --dport 8080 -j DROP")
	findings := AnalyzeDocker(parseRules(t, data, models.IPv4), nil).Findings
	bypass := findingsFor(findings, models.FindingDockerBypass, "172.17.0.2:80")
	if len(bypass) != 1 {
		t.Fatalf("expected one bypass of the INPUT block, got %+v", findings)
	}
	if bypass[0].Severity != models.SeverityCritical || bypass[0].Certainty != models.CertaintyDefinite || bypass[0].InputRule.RuleNum != 1 {
		t.Fatalf("explicit INPUT block bypass must be a definite CRITICAL citing the rule: %+v", bypass[0])
	}
}

func TestDocker29DefaultDenyPolicyIsBypassed(t *testing.T) {
	data := strings.Replace(docker29(t), ":INPUT ACCEPT [0:0]\n:FORWARD DROP", ":INPUT DROP [0:0]\n:FORWARD DROP", 1)
	findings := AnalyzeDocker(parseRules(t, data, models.IPv4), nil).Findings
	bypass := findingsFor(findings, models.FindingDockerBypass, "")
	if len(bypass) != 6 {
		t.Fatalf("every exposed published port bypasses a default-deny INPUT, got %+v", bypass)
	}
	for _, finding := range bypass {
		if finding.Severity != models.SeverityHigh || !strings.Contains(finding.Reason, "default-deny") {
			t.Errorf("policy-only bypass should be HIGH and name the policy: %+v", finding)
		}
	}
}

func TestDocker29IneffectiveDockerUserRules(t *testing.T) {
	tests := []struct {
		name string
		rule string
		port string
	}{
		{"pre-DNAT destination port", "-A DOCKER-USER -p tcp -m tcp --dport 8080 -j DROP", "8080/tcp"},
		{"pre-DNAT host address", "-A DOCKER-USER -d 192.168.88.217/32 -p tcp -j DROP", "8082/tcp"},
		{"local address type", "-A DOCKER-USER -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 8080 -j DROP", "8080/tcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := insertRule(t, docker29(t), "filter", "-A FORWARD -j DOCKER-USER", tt.rule)
			findings := AnalyzeDocker(parseRules(t, data, models.IPv4), nil).Findings
			ineffective := findingsFor(findings, models.FindingDockerIneffectiveRule, "")
			if len(ineffective) != 1 || ineffective[0].Rule == nil || ineffective[0].Rule.Chain != "DOCKER-USER" {
				t.Fatalf("expected the DOCKER-USER rule to be reported as ineffective, got %+v", findings)
			}
			if ineffective[0].ExposedPort != tt.port || ineffective[0].Certainty != models.CertaintyDefinite {
				t.Fatalf("wrong port or certainty: %+v", ineffective[0])
			}
		})
	}
}

func TestDocker29EffectiveRestrictionsProduceNoFinding(t *testing.T) {
	tests := []struct {
		name, table, after, rule string
	}{
		{"original port in DOCKER-USER", "filter", "-A FORWARD -j DOCKER-USER", "-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP"},
		{"container port in DOCKER-USER", "filter", "-A FORWARD -j DOCKER-USER", "-A DOCKER-USER -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j DROP"},
		{"raw PREROUTING", "raw", ":OUTPUT", "-A PREROUTING -p tcp -m tcp --dport 8080 -j DROP"},
		{"mangle PREROUTING", "mangle", ":POSTROUTING", "-A PREROUTING -p tcp -m tcp --dport 8080 -j DROP"},
		{"nat PREROUTING RETURN", "nat", ":DOCKER", "-A PREROUTING -p tcp -m tcp --dport 8080 -j RETURN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := insertRule(t, docker29(t), tt.table, tt.after, tt.rule)
			findings := AnalyzeDocker(parseRules(t, data, models.IPv4), nil).Findings
			for _, finding := range findings {
				if finding.ContainerDest == "172.17.0.2:80" || finding.ExposedPort == "8080" || finding.Code == models.FindingDockerIneffectiveRule {
					t.Fatalf("effective restriction reported as a problem: %+v", finding)
				}
			}
		})
	}
}

func TestDocker29ForwardRulesAfterDockerAreShadowed(t *testing.T) {
	data := insertRule(t, docker29(t), "filter", "-A FORWARD -j DOCKER-FORWARD", "-A FORWARD -p tcp -m tcp --dport 80 -j DROP")
	findings := AnalyzeDocker(parseRules(t, data, models.IPv4), nil).Findings
	shadowed := findingsFor(findings, models.FindingDockerShadowedRule, "")
	if len(shadowed) != 1 || shadowed[0].Rule.Chain != "FORWARD" || shadowed[0].Rule.RuleNum != 3 {
		t.Fatalf("expected FORWARD rule #3 to be shadowed by Docker, got %+v", findings)
	}
	if !strings.Contains(shadowed[0].ExposedPort, "8080/tcp") || strings.Contains(shadowed[0].ExposedPort, "9053") {
		t.Fatalf("only container port 80 traffic matches the rule: %+v", shadowed[0])
	}
}

func TestDocker29CatchAllForwardDropIsNotReportedAsShadowed(t *testing.T) {
	data := insertRule(t, docker29(t), "filter", "-A FORWARD -j DOCKER-FORWARD", "-A FORWARD -j DROP")
	findings := AnalyzeDocker(parseRules(t, data, models.IPv4), nil).Findings
	if shadowed := findingsFor(findings, models.FindingDockerShadowedRule, ""); len(shadowed) != 0 {
		t.Fatalf("a trailing catch-all DROP is the conventional FORWARD policy: %+v", shadowed)
	}
}

func TestDocker29RuleAboveDockerJumpIsFragile(t *testing.T) {
	data := strings.Replace(docker29(t), "-A FORWARD -j DOCKER-USER\n", "-A FORWARD -p tcp -m tcp --dport 80 -j DROP\n-A FORWARD -j DOCKER-USER\n", 1)
	analysis := AnalyzeDocker(parseRules(t, data, models.IPv4), nil)
	fragile := findingsFor(analysis.Findings, models.FindingDockerFragileRule, "")
	if len(fragile) != 1 || fragile[0].Rule.RuleNum != 1 {
		t.Fatalf("expected the rule above DOCKER-USER to be fragile, got %+v", analysis.Findings)
	}
	// It is effective today: container port 80 is blocked for all three bridges.
	for _, mapping := range analysis.PublishedPorts {
		if mapping.ContainerPort == 80 && mapping.ForwardScope != "" {
			t.Errorf("rule above Docker's jumps currently blocks %+v", mapping)
		}
	}
}

func TestDocker29MissingRawProtectionExposesLoopbackPublication(t *testing.T) {
	data := removeRule(t, docker29(t), "-A PREROUTING -d 172.17.0.3/32 ! -i docker0 -j DROP")
	findings := AnalyzeDocker(parseRules(t, data, models.IPv4), nil).Findings
	direct := findingsFor(findings, models.FindingDockerDirectRoute, "172.17.0.3:80")
	if len(direct) != 1 || direct[0].Severity != models.SeverityHigh || !strings.Contains(direct[0].Reason, "loopback (host port 8081)") {
		t.Fatalf("expected loopback-only publication to be reachable by direct routing, got %+v", findings)
	}
}

func TestDocker29DirectRoutingBypassesOriginalPortRestriction(t *testing.T) {
	data := removeRule(t, docker29(t), "-A PREROUTING -d 172.17.0.2/32 ! -i docker0 -j DROP")
	data = insertRule(t, data, "filter", "-A FORWARD -j DOCKER-USER", "-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP")
	findings := AnalyzeDocker(parseRules(t, data, models.IPv4), nil).Findings
	direct := findingsFor(findings, models.FindingDockerDirectRoute, "172.17.0.2:80")
	if len(direct) != 1 || direct[0].Severity != models.SeverityHigh || direct[0].Certainty != models.CertaintyPossible {
		t.Fatalf("expected the --ctorigdstport restriction to be bypassable, got %+v", findings)
	}
}

func TestDocker29NonDNATDropInDockerUserBlocksDirectRouting(t *testing.T) {
	data := removeRule(t, docker29(t), "-A PREROUTING -d 172.17.0.3/32 ! -i docker0 -j DROP")
	data = insertRule(t, data, "filter", "-A FORWARD -j DOCKER-USER",
		"-A DOCKER-USER -o docker0 ! -i docker0 -m conntrack --ctstate NEW -m conntrack ! --ctstate DNAT -j DROP")
	analysis := AnalyzeDocker(parseRules(t, data, models.IPv4), nil)
	if direct := findingsFor(analysis.Findings, models.FindingDockerDirectRoute, "172.17.0.3"); len(direct) != 0 {
		t.Fatalf("non-DNAT drop must block direct routing: %+v", direct)
	}
	for _, mapping := range analysis.PublishedPorts {
		if mapping.HostPort == 8080 && mapping.ForwardScope != models.ScopeExposed {
			t.Fatalf("published traffic is DNATed and must still pass: %+v", mapping)
		}
	}
}

func TestDocker29IPv6PublishedPort(t *testing.T) {
	analysis := AnalyzeDocker(parseRules(t, readFixture(t, "docker29.ip6tables-save"), models.IPv6), nil)
	if len(analysis.PublishedPorts) != 1 || analysis.PublishedPorts[0].ContainerAddr != "fd00:dead:beef::2" ||
		analysis.PublishedPorts[0].Bridge != "br-7a3442937ee6" || analysis.PublishedPorts[0].Certainty != models.CertaintyDefinite {
		t.Fatalf("unexpected IPv6 published ports: %+v", analysis.PublishedPorts)
	}
	published := findingsFor(analysis.Findings, models.FindingDockerPublished, "")
	if len(published) != 1 || published[0].ContainerDest != "[fd00:dead:beef::2]:443" {
		t.Fatalf("IPv6 destination must be bracketed: %+v", published)
	}
	if direct := findingsFor(analysis.Findings, models.FindingDockerDirectRoute, ""); len(direct) != 0 {
		t.Fatalf("raw-protected IPv6 container reported as routable: %+v", direct)
	}
}

func TestDockerIPv6GapWhenIp6tablesIsNotManaged(t *testing.T) {
	v4 := parseRules(t, docker29(t), models.IPv4)
	v6 := parseRules(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n", models.IPv6)
	if gaps := DockerIPv6Gaps(v4, v6); len(gaps) != 1 || gaps[0].Code != models.FindingDockerIPv6Unfiltered {
		t.Fatalf("expected an IPv6 forwarding gap, got %+v", gaps)
	}
	if gaps := DockerIPv6Gaps(v4, parseRules(t, readFixture(t, "docker29.ip6tables-save"), models.IPv6)); len(gaps) != 0 {
		t.Fatalf("Docker-managed ip6tables has no gap: %+v", gaps)
	}
	closed := parseRules(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n", models.IPv6)
	if gaps := DockerIPv6Gaps(v4, closed); len(gaps) != 0 {
		t.Fatalf("FORWARD DROP closes the gap: %+v", gaps)
	}
}

func TestDockerUserInterfaceRestriction(t *testing.T) {
	data := insertRule(t, docker29(t), "filter", "-A FORWARD -j DOCKER-USER",
		"-A DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP")
	rs := parseRules(t, data, models.IPv4)

	// Saved rules: other interfaces may exist.
	findings := findingsFor(AnalyzeDocker(rs, nil).Findings, models.FindingDockerPublished, "172.17.0.2:80")
	if len(findings) != 1 || findings[0].Certainty != models.CertaintyPossible ||
		strings.Join(findings[0].Interfaces, ",") != "other interfaces" {
		t.Fatalf("expected a possible exposure via unnamed interfaces, got %+v", findings)
	}

	// Live host with eth0 as the only external interface: fully restricted.
	only := &models.HostContext{Interfaces: []models.HostInterface{{Name: "lo"}, {Name: "eth0"}, {Name: "docker0"}}}
	if findings := findingsFor(AnalyzeDocker(rs, only).Findings, models.FindingDockerPublished, "172.17.0.2:80"); len(findings) != 0 {
		t.Fatalf("restriction covers every external interface: %+v", findings)
	}

	// Live host with a second uplink: definitely exposed through it.
	two := &models.HostContext{Interfaces: []models.HostInterface{{Name: "lo"}, {Name: "eth0"}, {Name: "wlan0"}}}
	findings = findingsFor(AnalyzeDocker(rs, two).Findings, models.FindingDockerPublished, "172.17.0.2:80")
	if len(findings) != 1 || findings[0].Certainty != models.CertaintyDefinite || strings.Join(findings[0].Interfaces, ",") != "wlan0" {
		t.Fatalf("expected a definite exposure via wlan0, got %+v", findings)
	}
}

func TestDockerUserOriginalSourceAllowlist(t *testing.T) {
	data := insertRule(t, docker29(t), "filter", "-A FORWARD -j DOCKER-USER",
		"-A DOCKER-USER -p tcp -m conntrack --ctorigsrc 10.0.0.0/8 --ctorigdstport 8080 --ctdir ORIGINAL -j RETURN\n"+
			"-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP")
	analysis := AnalyzeDocker(parseRules(t, data, models.IPv4), nil)
	for _, mapping := range analysis.PublishedPorts {
		if mapping.HostPort == 8080 && (mapping.ForwardScope != models.ScopeLocalnet || mapping.Certainty != models.CertaintyDefinite) {
			t.Fatalf("--ctorigsrc allowlist must limit the port to 10/8: %+v", mapping)
		}
	}
	if published := findingsFor(analysis.Findings, models.FindingDockerPublished, "172.17.0.2:80"); len(published) != 0 {
		t.Fatalf("allowlisted port reported as open to any source: %+v", published)
	}
}

func TestLegacyDockerLayoutIsDefinite(t *testing.T) {
	analysis := AnalyzeDocker(parseRules(t, readFixture(t, "docker.iptables-save"), models.IPv4), nil)
	bypass := findingsFor(analysis.Findings, models.FindingDockerBypass, "")
	if len(bypass) != 2 {
		t.Fatalf("expected two INPUT bypasses, got %+v", analysis.Findings)
	}
	for _, finding := range bypass {
		if finding.Severity != models.SeverityCritical || finding.Certainty != models.CertaintyDefinite {
			t.Errorf("legacy layout bypass should be definite CRITICAL: %+v", finding)
		}
	}
}

func TestPublishedListenerFollowsDockerPath(t *testing.T) {
	data := insertRule(t, docker29(t), "filter", ":DOCKER-USER", "-A INPUT -p tcp -m tcp --dport 8080 -j DROP")
	result := Analyze(parseRules(t, data, models.IPv4), nil)
	CrossReferenceServices(result, []models.ListeningService{{
		Protocol: models.ProtoTCP, Address: "0.0.0.0", Port: 8080, Process: "docker-proxy", IsWildcard: true, Family: models.SocketIPv4,
	}})
	if result.Services[0].Status != models.ServiceDocker {
		t.Fatalf("listener of a published port must follow the Docker path, got %s", result.Services[0].Status)
	}
	if len(result.ExposedServices) != 0 {
		t.Fatalf("published port must not be double-reported as an INPUT exposure: %+v", result.ExposedServices)
	}
}
