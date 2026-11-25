package recommender

import (
	"os/exec"
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
		NATRule:     models.Rule{Table: "nat", Chain: "DOCKER", Protocol: models.ProtoTCP, IPVersion: models.IPv4},
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

// The SSH limiter is a rule in front of the accepting rule. It keeps the
// matches of that rule and counts each source by itself (audit D1): a global
// "-m limit" would let anyone use up the budget of all clients.
func TestSSHLimiterKeepsTheRestrictionsOfTheRule(t *testing.T) {
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
	for _, wanted := range []string{"iptables -I INPUT 2 ", "-i wg0", "-d 192.0.2.10/32", `--comment 'VPN SSH'`,
		"--ctstate NEW", "--hashlimit-mode srcip", "--hashlimit-above 10/min", "-j DROP"} {
		if !strings.Contains(detail, wanted) {
			t.Fatalf("limiter lacks %q: %s", wanted, detail)
		}
	}
	for _, unwanted := range []string{"iptables -R", "-m limit --limit", "-j ACCEPT"} {
		if strings.Contains(detail, unwanted) {
			t.Fatalf("limiter contains %q: %s", unwanted, detail)
		}
	}
}

func TestSSHLimiterIsNotRecommendedWhenOneExists(t *testing.T) {
	for name, rules := range map[string]string{
		"hashlimit DROP in front": "-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/min --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name ssh4-22 -j DROP\n" +
			"-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT\n",
		"limit on the ACCEPT": "-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 5 -j ACCEPT\n",
		"ufw limit": ":LIMIT - [0:0]\n:USER - [0:0]\n-A INPUT -j USER\n" +
			"-A USER -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource\n" +
			"-A USER -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 --name DEFAULT --mask 255.255.255.255 --rsource -j LIMIT\n" +
			"-A USER -p tcp -m tcp --dport 22 -j ACCEPT\n-A LIMIT -j REJECT --reject-with icmp-port-unreachable\n",
		"restricted to a network": "-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -j ACCEPT\n",
	} {
		chains, body := "", rules
		for strings.HasPrefix(body, ":") {
			line, rest, _ := strings.Cut(body, "\n")
			chains, body = chains+line+"\n", rest
		}
		rs, err := parser.Parse("*filter\n:INPUT DROP [0:0]\n"+chains+"-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"+body+"COMMIT\n", models.IPv4)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, rec := range Generate(analyzer.Analyze(rs, nil)) {
			if strings.Contains(rec.Title, "rate limiting") {
				t.Errorf("%s: a limiter was recommended: %s", name, rec.Detail)
			}
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
	result := &models.AnalysisResult{IPv6Status: models.FamilyAnalyzed, EffectiveIssues: []models.EffectivenessFinding{{
		Code: models.FindingPolicyAccept, Severity: models.SeverityHigh, Chain: "INPUT", IPVersion: models.IPv6,
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

// Comments, chain names and interface names in a ruleset can contain shell
// syntax. Copying a recommended command must not execute it.
func TestRecommendedCommandsQuoteRulesetValues(t *testing.T) {
	const payload = "$(touch /tmp/iptables-analyzer-pwned)`id`;reboot"
	data := `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:DOCKER-USER - [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -m comment --comment "` + payload + `" -j ACCEPT
-A DOCKER-USER -i "eth0;id" -p tcp -m tcp --dport 8080 -m comment --comment "` + payload + `" -j DROP
COMMIT
`
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	ssh := sshRulesWithoutRateLimit(analyzer.Analyze(rs, nil))
	if len(ssh) != 1 {
		t.Fatalf("expected the SSH rule, got %+v", ssh)
	}
	command, ok := sshLimiterCommand(ssh[0])
	if !ok {
		t.Fatal("expected an SSH limiter command")
	}
	docker := rs.Tables["filter"].Chains["DOCKER-USER"].Rules[0]
	rec := ineffectiveRuleRecommendation(models.DockerBypassFinding{
		Code: models.FindingDockerIneffectiveRule, IPVersion: models.IPv4, Rule: &docker, Fix: "fix",
	})
	if rec == nil {
		t.Fatal("expected a DOCKER-USER replacement")
	}
	replace := rec.Detail[strings.Index(rec.Detail, "iptables -R"):]

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell available")
	}
	for _, line := range []string{command, replace} {
		if !strings.Contains(line, "'"+payload+"'") {
			t.Errorf("payload is not single-quoted in %s", line)
		}
		// Let a shell split the command (printing, not running iptables).
		out, err := exec.Command(sh, "-c", `printf '%s\n' `+strings.TrimPrefix(line, "iptables ")).Output()
		if err != nil {
			t.Fatalf("shell rejected %s: %v", line, err)
		}
		if !strings.Contains(string(out), "\n"+payload+"\n") {
			t.Errorf("payload did not survive as one literal argument: %s", out)
		}
	}
	if !strings.Contains(replace, "-i 'eth0;id'") || !strings.Contains(replace, "--ctorigdstport 8080") {
		t.Errorf("interface name not quoted or port not rewritten: %s", replace)
	}
}

// Audit B8: a port forward of a router gets advice without Docker in it.
func TestPortForwardRecommendationDoesNotMentionDocker(t *testing.T) {
	recs := Generate(&models.AnalysisResult{IPv4Only: true, DockerBypasses: []models.DockerBypassFinding{{
		Code: models.FindingDockerPublished, IPVersion: models.IPv4, Severity: models.SeverityMedium,
		NATRule:     models.Rule{Table: "nat", Chain: "PREROUTING", RuleNum: 1, Protocol: models.ProtoTCP, IPVersion: models.IPv4},
		ExposedPort: "8443", ContainerDest: "192.168.1.50:443",
	}}})
	if len(recs) != 1 || !strings.Contains(recs[0].Title, "forwarded port 8443/tcp") || !strings.Contains(recs[0].Detail, "nat/PREROUTING rule #1") {
		t.Fatalf("expected one port-forward recommendation, got %+v", recs)
	}
	if text := recs[0].Title + recs[0].Detail; strings.Contains(text, "DOCKER") || strings.Contains(text, "docker") {
		t.Fatalf("advice for a port forward mentions Docker: %s", text)
	}
}
