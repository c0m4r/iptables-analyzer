package analyzer

import (
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
	"github.com/c0m4r/iptables-analyzer/internal/services"
)

// The tests in this file reproduce the inputs of docs/audit-0.7.1.md.

// filterRules builds an IPv4 filter table with default-deny policies, the
// loopback and conntrack rules, and the given INPUT rules and extra lines.
func filterRules(lines ...string) string {
	return "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n" +
		strings.Join(lines, "\n") + "\nCOMMIT\n"
}

func mustParse(t *testing.T, data string, version models.IPVersion) *models.Ruleset {
	t.Helper()
	rs, err := parser.Parse(data, version)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rs
}

// analyzeWithServices analyzes IPv4 rules against ss rows (without header).
func analyzeWithServices(t *testing.T, rules string, ssRows ...string) *models.AnalysisResult {
	t.Helper()
	result := Analyze(mustParse(t, rules, models.IPv4), nil)
	svcs, err := services.ParseSSData("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" + strings.Join(ssRows, "\n") + "\n")
	if err != nil {
		t.Fatalf("ss: %v", err)
	}
	CrossReferenceServices(result, svcs)
	return result
}

func serviceStatus(t *testing.T, result *models.AnalysisResult, port int) models.ServiceStatus {
	t.Helper()
	for _, svc := range result.Services {
		if svc.Port == port {
			return svc.Status
		}
	}
	t.Fatalf("no service on port %d", port)
	return ""
}

func exposure(result *models.AnalysisResult, port int) *models.ExposedServiceFinding {
	for i := range result.ExposedServices {
		if result.ExposedServices[i].Service.Port == port {
			return &result.ExposedServices[i]
		}
	}
	return nil
}

// Audit B7: listeners that only guests behind a virtual bridge reach are not
// exposed to the network, and a device-bound socket is evaluated for its
// device alone.
func TestListenersOnGuestBridgesAreInternal(t *testing.T) {
	rules := "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:LIBVIRT_INP - [0:0]\n" +
		"-A INPUT -j LIBVIRT_INP\n-A INPUT -i lo -j ACCEPT\n" +
		"-A INPUT -i eth0 -p tcp -m tcp --dport 32400 -j ACCEPT\n" +
		"-A LIBVIRT_INP -i virbr0 -p udp -m udp --dport 53 -j ACCEPT\n" +
		"-A LIBVIRT_INP -i virbr0 -p tcp -m tcp --dport 53 -j ACCEPT\n" +
		"-A LIBVIRT_INP -i virbr0 -p udp -m udp --dport 67 -j ACCEPT\nCOMMIT\n"
	result := analyzeWithServices(t, rules,
		`udp UNCONN 0 0 0.0.0.0%virbr0:67 0.0.0.0:* users:(("dnsmasq",pid=1500,fd=3))`,
		`tcp LISTEN 0 32 192.168.122.1:53 0.0.0.0:* users:(("dnsmasq",pid=1500,fd=6))`,
		`tcp LISTEN 0 128 0.0.0.0:32400 0.0.0.0:* users:(("plex",pid=2000,fd=60))`)
	for _, port := range []int{67, 53} {
		if status := serviceStatus(t, result, port); status != models.ServiceInternal {
			t.Errorf("port %d behind virbr0: status %s, want INTERNAL", port, status)
		}
		if finding := exposure(result, port); finding != nil {
			t.Errorf("port %d behind virbr0 was reported as exposed: %s", port, finding.Reason)
		}
	}
	finding := exposure(result, 32400)
	if finding == nil || finding.Scope != models.ScopeExposed || strings.Join(finding.Interfaces, ",") != "eth0" {
		t.Fatalf("service allowed on eth0: %+v", finding)
	}
}

func TestDeviceBoundSocketIsEvaluatedForItsDevice(t *testing.T) {
	rules := filterRules(
		"-A INPUT -i eth1 -p udp -m udp --dport 5000 -j ACCEPT",
		"-A INPUT -i eth0 -p udp -m udp --dport 6000 -j ACCEPT")
	result := analyzeWithServices(t, rules,
		`udp UNCONN 0 0 0.0.0.0%eth0:5000 0.0.0.0:* users:(("a",pid=1,fd=3))`,
		`udp UNCONN 0 0 0.0.0.0%eth0:6000 0.0.0.0:* users:(("b",pid=2,fd=3))`,
		`udp UNCONN 0 0 0.0.0.0%lo:7000 0.0.0.0:* users:(("c",pid=3,fd=3))`)
	if status := serviceStatus(t, result, 5000); status != models.ServiceFiltered {
		t.Errorf("socket bound to eth0, port open on eth1 only: %s", status)
	}
	finding := exposure(result, 6000)
	if finding == nil || strings.Join(finding.Interfaces, ",") != "eth0" || finding.Certainty != models.CertaintyDefinite {
		t.Errorf("socket bound to eth0, port open on eth0: %+v", finding)
	}
	if status := serviceStatus(t, result, 7000); status != models.ServiceLocalhost {
		t.Errorf("socket bound to lo: %s", status)
	}
}

const sshListener = `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))`

// Audit B3: a source allowlist is not an exposure to any source.
func TestSourceAllowlistsAreNotExposedToAnySource(t *testing.T) {
	for _, tt := range []struct {
		rule        string
		scope       models.AccessScope
		restriction string
	}{
		{"-A INPUT -p tcp -m tcp --dport 22 -m iprange --src-range 192.168.1.10-192.168.1.20 -j ACCEPT", models.ScopeLocalnet, ""},
		{"-A INPUT -p tcp -m tcp --dport 22 -m iprange --src-range 203.0.113.10-203.0.113.20 -j ACCEPT", models.ScopeSubnet, ""},
		{"-A INPUT -p tcp -m tcp --dport 22 -m iprange --src-range 203.0.113.7-203.0.113.7 -j ACCEPT", models.ScopeWhitelisted, ""},
		{"-A INPUT -p tcp -m tcp --dport 22 -m set --match-set trusted src -j ACCEPT", models.ScopeRestricted, "ipset trusted"},
		{"-A INPUT -p tcp -m tcp --dport 22 -m mac --mac-source 00:11:22:33:44:55 -j ACCEPT", models.ScopeRestricted, "MAC address 00:11:22:33:44:55"},
		{"-A INPUT -p tcp -m tcp --dport 22 -m recent --rcheck --seconds 30 --name KNOCKED --mask 255.255.255.255 --rsource -j ACCEPT", models.ScopeRestricted, "recent list KNOCKED"},
		// The addresses already say more than the set does.
		{"-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -m set --match-set trusted src -j ACCEPT", models.ScopeLocalnet, ""},
	} {
		result := analyzeWithServices(t, filterRules(tt.rule), sshListener)
		finding := exposure(result, 22)
		if finding == nil {
			t.Errorf("%s: no finding", tt.rule)
			continue
		}
		if finding.Scope != tt.scope || finding.Certainty != models.CertaintyDefinite || finding.Severity != models.SeverityLow || finding.Restriction != tt.restriction {
			t.Errorf("%s:\n  scope=%s certainty=%s severity=%s restriction=%q\n  %s",
				tt.rule, finding.Scope, finding.Certainty, finding.Severity, finding.Restriction, finding.Reason)
		}
		if strings.Contains(finding.Reason, "from the network") {
			t.Errorf("%s: an allowlist was described as the network: %s", tt.rule, finding.Reason)
		}
	}
}

// Audit B4: an allowlist written as "drop what is not in the set" narrows the
// traffic that continues; a blocklist does not.
func TestNegatedSetDropNarrowsWhatFollows(t *testing.T) {
	allowlist := analyzeWithServices(t, filterRules(
		"-A INPUT -m set ! --match-set allowlist src -j DROP",
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"), sshListener)
	finding := exposure(allowlist, 22)
	if finding == nil || finding.Scope != models.ScopeRestricted || finding.Restriction != "ipset allowlist" || finding.Severity != models.SeverityLow {
		t.Fatalf("only members of the set pass the DROP rule: %+v", finding)
	}

	blocklist := analyzeWithServices(t, filterRules(
		"-A INPUT -m set --match-set blocklist src -j DROP",
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"), sshListener)
	finding = exposure(blocklist, 22)
	if finding == nil || finding.Scope != models.ScopeExposed || finding.Certainty != models.CertaintyDefinite || finding.Severity != models.SeverityHigh {
		t.Fatalf("a blocklist leaves the service exposed: %+v", finding)
	}

	// The same through a user chain that returns the trusted sources.
	chained := analyzeWithServices(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:GATE - [0:0]\n"+
		"-A INPUT -j GATE\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"+
		"-A GATE -m set --match-set trusted src -j RETURN\n-A GATE -j DROP\nCOMMIT\n", sshListener)
	finding = exposure(chained, 22)
	if finding == nil || finding.Scope != models.ScopeRestricted || finding.Restriction != "ipset trusted" {
		t.Fatalf("only the returned members of the set reach the ACCEPT rule: %+v", finding)
	}
}

// Audit B5: any source can pass a rate limit, and the packet that opens a
// connection is a SYN. Both exposures are certain.
func TestRateLimitsAndSynMatchesAreDefiniteExposure(t *testing.T) {
	for _, tt := range []struct {
		rule      string
		condition string
		severity  models.Severity
	}{
		{"-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 5 -j ACCEPT", "rate limit", models.SeverityMedium},
		{"-A INPUT -p tcp -m tcp --dport 22 -m connlimit --connlimit-upto 4 --connlimit-mask 32 --connlimit-saddr -j ACCEPT", "connection limit", models.SeverityMedium},
		{"-A INPUT -p tcp -m tcp --dport 22 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT", "", models.SeverityHigh},
		{"-A INPUT -p tcp -m tcp --dport 22 --tcp-flags SYN,RST SYN -m conntrack --ctstate NEW -j ACCEPT", "", models.SeverityHigh},
		{"-A INPUT -p tcp -m tcp --dport 22 -m time --timestart 08:00:00 --timestop 18:00:00 --datestop 2038-01-19T03:14:07 -j ACCEPT", "time window", models.SeverityHigh},
		{"-A INPUT -p tcp -m tcp --sport 1024:65535 --dport 22 -j ACCEPT", "", models.SeverityHigh},
		{"-A INPUT -p tcp -m pkttype --pkt-type unicast -m tcp --dport 22 -j ACCEPT", "", models.SeverityHigh},
	} {
		result := analyzeWithServices(t, filterRules(tt.rule), sshListener)
		finding := exposure(result, 22)
		if finding == nil || finding.Scope != models.ScopeExposed || finding.Certainty != models.CertaintyDefinite ||
			finding.Condition != tt.condition || finding.Severity != tt.severity {
			t.Errorf("%s:\n  %+v", tt.rule, finding)
		}
	}
	// A rule for packets that do not open a connection admits no client.
	for _, rule := range []string{
		"-A INPUT -p tcp -m tcp --dport 22 ! --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 22 --tcp-flags ALL FIN,PSH,URG -j ACCEPT",
		"-A INPUT -p tcp -m pkttype --pkt-type broadcast -m tcp --dport 22 -j ACCEPT",
	} {
		if result := analyzeWithServices(t, filterRules(rule), sshListener); serviceStatus(t, result, 22) != models.ServiceFiltered {
			t.Errorf("%s: %+v", rule, exposure(result, 22))
		}
	}
}

// Audit B6: a rule that requires a privileged source port, as for DHCP
// replies, is a low exposure of that one port.
func TestSourcePortRestrictedRuleIsLow(t *testing.T) {
	result := analyzeWithServices(t, filterRules("-A INPUT -p udp -m udp --sport 67 --dport 68 -j ACCEPT"),
		`udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("dhclient",pid=450,fd=6))`)
	finding := exposure(result, 68)
	if finding == nil || finding.Severity != models.SeverityLow || finding.Certainty != models.CertaintyDefinite || finding.Condition != "source port 67" {
		t.Fatalf("DHCP reply rule: %+v", finding)
	}
}

// A published port that DOCKER-USER limits to an ipset is not open to any
// source (the second half of audit B4).
func TestDockerUserSetAllowlistRestrictsPublishedPort(t *testing.T) {
	data := strings.Replace(readFixture(t, "docker.iptables-save"), "-A DOCKER-USER -j RETURN",
		"-A DOCKER-USER -m set ! --match-set trusted src -j DROP\n-A DOCKER-USER -j RETURN", 1)
	analysis := AnalyzeDocker(mustParse(t, data, models.IPv4), nil)
	if len(analysis.PublishedPorts) != 2 {
		t.Fatalf("expected two published ports, got %+v", analysis.PublishedPorts)
	}
	for _, port := range analysis.PublishedPorts {
		if port.ForwardScope != models.ScopeRestricted {
			t.Errorf("published port %d: forward scope %s, want RESTRICTED", port.HostPort, port.ForwardScope)
		}
	}
	for _, finding := range analysis.Findings {
		if finding.Scope == models.ScopeExposed {
			t.Errorf("finding claims any source: %s", finding.Reason)
		}
	}
}

func effectiveness(findings []models.EffectivenessFinding, code models.FindingCode, chain string) []models.EffectivenessFinding {
	var matching []models.EffectivenessFinding
	for _, finding := range findings {
		if finding.Code == code && (chain == "" || finding.Chain == chain) {
			matching = append(matching, finding)
		}
	}
	return matching
}

// Audit A1: what a chain does by default follows from its rules, not from
// its policy line.
func TestDefaultAcceptIsJudgedByEffect(t *testing.T) {
	acceptAll := CheckEffectiveness(mustParse(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n", models.IPv4))
	found := effectiveness(acceptAll, models.FindingPolicyAccept, "INPUT")
	if len(found) != 1 || found[0].Severity != models.SeverityHigh || !found[0].Unrestricted || found[0].Rule == nil || found[0].Rule.RuleNum != 1 {
		t.Fatalf("an accept-all rule under a DROP policy: %+v", found)
	}
	if len(effectiveness(acceptAll, models.FindingMissingConntrack, "")) != 0 {
		t.Fatal("a chain that accepts everything was said to drop replies")
	}

	// Audit B2: the classic layout with an ACCEPT policy and a final REJECT.
	rhel := CheckEffectiveness(mustParse(t, "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"+
		"-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -p icmp -j ACCEPT\n-A INPUT -i lo -j ACCEPT\n"+
		"-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT\n"+
		"-A INPUT -j REJECT --reject-with icmp-host-prohibited\n-A FORWARD -j REJECT --reject-with icmp-host-prohibited\nCOMMIT\n", models.IPv4))
	for _, finding := range rhel {
		if finding.Severity > models.SeverityInfo {
			t.Errorf("default deny by a final REJECT was reported: %s: %s", finding.Title, finding.Detail)
		}
	}

	// One protocol, or one interface, is not "every connection".
	tcpOnly := effectiveness(CheckEffectiveness(mustParse(t, filterRules("-A INPUT -p tcp -j ACCEPT"), models.IPv4)), models.FindingPolicyAccept, "INPUT")
	if len(tcpOnly) != 1 || tcpOnly[0].Unrestricted || !strings.Contains(tcpOnly[0].Title, "TCP") {
		t.Fatalf("accept of all TCP: %+v", tcpOnly)
	}
	trusted := CheckEffectiveness(mustParse(t, filterRules("-A INPUT -s 10.0.0.0/8 -j ACCEPT"), models.IPv4))
	if len(effectiveness(trusted, models.FindingPolicyAccept, "INPUT")) != 0 {
		t.Fatal("accepting everything from a private network is not a default accept for any source")
	}

	// A file without a filter table filters nothing; the report must say so.
	natOnly := effectiveness(CheckEffectiveness(mustParse(t, "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -o eth0 -j MASQUERADE\nCOMMIT\n", models.IPv4)), models.FindingPolicyAccept, "INPUT")
	if len(natOnly) != 1 || !strings.Contains(natOnly[0].Detail, "no filter table") {
		t.Fatalf("ruleset without a filter table: %+v", natOnly)
	}
}

// Audit A2: wide port ranges are a finding without any listener.
func TestBroadPortRangeIsReportedWithoutListeners(t *testing.T) {
	result := Analyze(mustParse(t, filterRules("-A INPUT -p udp -m udp --dport 1024:65535 -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 8000:8100 -j ACCEPT"), models.IPv4), nil)
	broad := effectiveness(result.EffectiveIssues, models.FindingBroadAccept, "")
	if len(broad) != 1 || broad[0].Severity != models.SeverityHigh || !strings.Contains(broad[0].Title, "64512 UDP ports") || broad[0].Rule == nil {
		t.Fatalf("wide UDP range: %+v", broad)
	}
	var ports []string
	for _, open := range result.OpenPorts {
		ports = append(ports, string(open.Protocol)+" "+portRangeText(open.First, open.Last)+" "+string(open.Scope))
	}
	if got := strings.Join(ports, "; "); got != "tcp 8000-8100 EXPOSED; udp 1024-65535 EXPOSED" {
		t.Fatalf("open ports: %s", got)
	}
}

// Audit B1 and D2: the rules of ufw are spread over its own chains.
func TestUFWRulesetIsJudgedThroughItsChains(t *testing.T) {
	result := Analyze(mustParse(t, readFixture(t, "ufw.iptables-save"), models.IPv4), nil)
	svcs, err := services.ParseSSData(readFixture(t, "ufw-services.txt"))
	if err != nil {
		t.Fatal(err)
	}
	CrossReferenceServices(result, svcs)
	for _, finding := range result.EffectiveIssues {
		if finding.Severity > models.SeverityInfo {
			t.Errorf("false finding on a ufw host: %s: %s", finding.Title, finding.Detail)
		}
	}
	if len(result.ShadowedRules) != 0 {
		t.Errorf("shadowed rules in the chains of ufw: %+v", result.ShadowedRules)
	}
	want := map[int]struct {
		scope     models.AccessScope
		severity  models.Severity
		condition string
	}{
		22:   {models.ScopeExposed, models.SeverityMedium, "rate limit"}, // ufw limit
		80:   {models.ScopeExposed, models.SeverityHigh, ""},
		443:  {models.ScopeExposed, models.SeverityHigh, ""},
		5432: {models.ScopeLocalnet, models.SeverityLow, ""},
		68:   {models.ScopeExposed, models.SeverityLow, "source port 67"}, // DHCP replies
	}
	if len(result.ExposedServices) != len(want) {
		t.Errorf("expected %d service findings, got %d", len(want), len(result.ExposedServices))
	}
	for _, finding := range result.ExposedServices {
		w, ok := want[finding.Service.Port]
		if !ok || finding.Scope != w.scope || finding.Severity != w.severity || finding.Condition != w.condition || finding.Certainty != models.CertaintyDefinite {
			t.Errorf("port %d: scope=%s severity=%s condition=%q certainty=%s", finding.Service.Port, finding.Scope, finding.Severity, finding.Condition, finding.Certainty)
		}
	}
	// Multicast rules of ufw (mDNS, SSDP) open nothing to a connecting host.
	for _, open := range result.OpenPorts {
		if open.First == 5353 || open.First == 1900 {
			t.Errorf("multicast-only rule listed as an open port: %+v", open)
		}
	}
}

// Audit B10: an address family that is turned off on purpose is one note.
func TestBlockedFamilyIsOneNote(t *testing.T) {
	findings := CheckEffectiveness(mustParse(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n", models.IPv6))
	if len(findings) != 1 || findings[0].Code != models.FindingFamilyBlocked || findings[0].Severity != models.SeverityInfo {
		t.Fatalf("blocked IPv6: %+v", findings)
	}
	// With one accepting rule the family is in use, and the checks apply.
	inUse := CheckEffectiveness(mustParse(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n", models.IPv6))
	if len(effectiveness(inUse, models.FindingIPv6NDPBlocked, "")) == 0 {
		t.Fatal("neighbor discovery check was skipped for a family that is in use")
	}
}

// Audit B13: a negated port predicate does not "allow port 22".
func TestUnusedPortFindingsNameThePortsThatAreOpen(t *testing.T) {
	result := analyzeWithServices(t, filterRules(
		"-A INPUT -s 10.0.0.0/8 -p tcp -m tcp ! --dport 22 -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 8443 -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"), sshListener)
	var reasons []string
	for _, finding := range result.UnusedRules {
		reasons = append(reasons, finding.Reason)
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "port 8443/tcp is open to any source by rule #4") {
		t.Fatalf("unused ports: %q", reasons)
	}
}

// Audit A7: the IPv6 rules must not be wider than the IPv4 rules.
func TestIPv6WiderThanIPv4IsReported(t *testing.T) {
	v4 := mustParse(t, filterRules(
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 3306 -j ACCEPT"), models.IPv4)
	v6 := mustParse(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\n"+
		"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -p ipv6-icmp -j ACCEPT\n"+
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT\n"+
		"-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT\nCOMMIT\n", models.IPv6)
	wider := effectiveness(Analyze(v4, v6).EffectiveIssues, models.FindingIPv6Wider, "")
	if len(wider) != 2 {
		t.Fatalf("expected a finding for the restricted and one for the filtered port: %+v", wider)
	}
	if wider[0].Severity != models.SeverityHigh || !strings.Contains(wider[0].Detail, "3306/tcp (localnet on IPv4)") || strings.Contains(wider[0].Detail, "22/tcp") {
		t.Errorf("port that IPv4 restricts: %+v", wider[0])
	}
	if wider[1].Severity != models.SeverityMedium || !strings.Contains(wider[1].Detail, "8080/tcp") {
		t.Errorf("port that IPv4 filters: %+v", wider[1])
	}
	// The same rules in both families: nothing to report.
	same := mustParse(t, strings.ReplaceAll(filterRules("-A INPUT -p ipv6-icmp -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A INPUT -s fc00::/7 -p tcp -m tcp --dport 3306 -j ACCEPT"), "10.0.0.0/8", "fc00::/7"), models.IPv6)
	if found := effectiveness(Analyze(v4, same).EffectiveIssues, models.FindingIPv6Wider, ""); len(found) != 0 {
		t.Fatalf("equal rules were reported: %+v", found)
	}
}
