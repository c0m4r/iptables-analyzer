package report

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// commands returns the commands of a fix, one on each line.
func commands(fix *Fix) string {
	if fix == nil {
		return ""
	}
	var lines []string
	for _, step := range fix.Steps {
		lines = append(lines, step.Command)
	}
	return strings.Join(lines, "\n")
}

// findingFor returns the finding about one port.
func findingFor(t *testing.T, rep *Report, port string) Finding {
	t.Helper()
	for _, finding := range rep.Findings {
		for _, name := range finding.Ports {
			if name == port {
				return finding
			}
		}
	}
	t.Fatalf("no finding about %s: %+v", port, rep.Findings)
	return Finding{}
}

// inputDefault returns the finding about what INPUT does with the ports
// that no rule names.
func inputDefault(t *testing.T, rep *Report) Finding {
	t.Helper()
	for _, finding := range find(rep, string(models.FindingPolicyAccept)) {
		if finding.key == "policy/INPUT" {
			return finding
		}
	}
	t.Fatalf("no finding about the default of INPUT: %+v", rep.Findings)
	return Finding{}
}

// handBuilt is a result for findings that are simpler to state than to get
// from rules.
func handBuilt(findings ...models.DockerBypassFinding) *models.AnalysisResult {
	return &models.AnalysisResult{IPv4Only: true, IPv4Status: models.FamilyAnalyzed, DockerBypasses: findings}
}

// The SSH limiter is a rule in front of the accepting rule. It keeps the
// matches of that rule and counts each source by itself (audit D1): a global
// "-m limit" would let anyone use up the budget of all clients.
func TestSSHLimiterKeepsTheRestrictionsOfTheRule(t *testing.T) {
	rep := build(t, "*filter\n:INPUT DROP [0:0]\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"+
		"-A INPUT -i wg0 -d 192.0.2.10/32 -p tcp --dport 22 -m comment --comment \"VPN SSH\" -j ACCEPT\nCOMMIT\n", "", nil, Options{})
	fix := findingFor(t, rep, "22/tcp").Fix
	if fix == nil || len(fix.Steps) != 2 {
		t.Fatalf("expected the two ways to limit SSH: %+v", fix)
	}
	replace, limiter := fix.Steps[0].Command, fix.Steps[1].Command
	for _, wanted := range []string{"iptables -I INPUT 2 ", "-i wg0", "-d 192.0.2.10/32", `--comment 'VPN SSH'`,
		"--ctstate NEW", "--hashlimit-mode srcip", "--hashlimit-above 10/min", "-j DROP"} {
		if !strings.Contains(limiter, wanted) {
			t.Errorf("limiter lacks %q: %s", wanted, limiter)
		}
	}
	for _, unwanted := range []string{"iptables -R", "-m limit --limit", "-j ACCEPT"} {
		if strings.Contains(limiter, unwanted) {
			t.Errorf("limiter contains %q: %s", unwanted, limiter)
		}
	}
	if !strings.HasPrefix(replace, "iptables -R INPUT 2 -s <trusted-cidr> -i wg0 ") || !strings.HasSuffix(replace, "-j ACCEPT") {
		t.Errorf("replacement for known clients: %s", replace)
	}
}

func TestSSHLimiterIsNotOfferedWhenOneExists(t *testing.T) {
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
		rep := build(t, "*filter\n:INPUT DROP [0:0]\n"+chains+"-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"+body+"COMMIT\n", "", nil, Options{})
		for _, finding := range rep.Findings {
			if text := commands(finding.Fix); strings.Contains(text, "hashlimit") {
				t.Errorf("%s: a limiter was offered: %s", name, text)
			}
			if finding.Severity >= models.SeverityHigh {
				t.Errorf("%s: limited or restricted SSH is reported as %s: %s", name, finding.Severity, finding.Title)
			}
		}
	}
}

// Comments, chain names and interface names in a ruleset can contain shell
// syntax. Copying a command of a fix must not execute it.
func TestFixCommandsQuoteRulesetValues(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell available")
	}
	marker := filepath.Join(t.TempDir(), "run")
	payload := "$(touch " + marker + ")`touch " + marker + "`;touch " + marker
	rules := "*nat\n:PREROUTING ACCEPT [0:0]\n:DOCKER - [0:0]\n-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER\n" +
		"-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80\nCOMMIT\n" +
		"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:DOCKER - [0:0]\n:DOCKER-USER - [0:0]\n:\"bad;chain\" - [0:0]\n" +
		"-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
		"-A INPUT -p tcp --dport 22 -m comment --comment \"" + payload + "\" -j ACCEPT\n" +
		"-A INPUT -p tcp --dport 9999 -m comment --comment \"" + payload + "\" -j ACCEPT\n" +
		"-A FORWARD -j DOCKER-USER\n-A FORWARD -o docker0 -j DOCKER\n" +
		"-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT\n" +
		"-A DOCKER-USER -i \"eth0;id\" -p tcp -m tcp --dport 8080 -m comment --comment \"" + payload + "\" -j DROP\n" +
		"COMMIT\n"
	rep := build(t, rules, "", []string{`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`}, Options{})

	checked, quoted := 0, 0
	for _, finding := range rep.Findings {
		if finding.Fix == nil {
			continue
		}
		for _, step := range finding.Fix.Steps {
			checked++
			// A placeholder makes the shell refuse the command; give it a value.
			line := strings.ReplaceAll(step.Command, "<trusted-cidr>", "192.0.2.0/24")
			// Let a shell split the command and print the words, not run them.
			out, err := exec.Command(sh, "-c", `printf '%s\n' `+line).Output()
			if err != nil {
				t.Fatalf("shell rejected %q: %v", line, err)
			}
			if strings.Contains(step.Command, "touch") {
				quoted++
				if !strings.Contains(step.Command, "'"+payload+"'") {
					t.Errorf("the comment is not quoted in: %s", step.Command)
				}
				if !strings.Contains(string(out), "\n"+payload+"\n") {
					t.Errorf("the comment did not stay one literal word: %s", out)
				}
			}
			if strings.Contains(step.Command, "eth0") && !strings.Contains(step.Command, "'eth0;id'") {
				t.Errorf("the interface name is not quoted in: %s", step.Command)
			}
		}
	}
	if checked < 4 || quoted < 3 {
		t.Fatalf("too few commands were checked (%d, %d with the comment): %+v", checked, quoted, rep.Findings)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a command ran text from the ruleset")
	}
}

func TestPublishedPortFixMatchesTheOriginalPort(t *testing.T) {
	rep := build(t, fixture(t, "docker29.iptables-save"), "", nil, Options{})
	fix := findingFor(t, rep, "8080/tcp").Fix
	text := commands(fix)
	for _, wanted := range []string{"iptables -I DOCKER-USER 1 ", "iptables -I DOCKER-USER 2 ", "--ctorigdstport 8080 --ctdir ORIGINAL", "-s <trusted-cidr> -j RETURN", "-j DROP"} {
		if !strings.Contains(text, wanted) {
			t.Errorf("fix lacks %q: %s", wanted, text)
		}
	}
	if strings.Contains(text, "--dport 8080") {
		t.Errorf("the fix matches the port after translation: %s", text)
	}
}

func TestIneffectiveDockerUserRuleGetsConntrackReplacement(t *testing.T) {
	rule := models.Rule{IPVersion: models.IPv4, Table: "filter", Chain: "DOCKER-USER", RuleNum: 1, Target: "DROP", Protocol: models.ProtoTCP, DstPort: "8080",
		RawLine: "-A DOCKER-USER -p tcp -m tcp --dport 8080 -j DROP", Negations: map[string]bool{}}
	rep := Build(handBuilt(models.DockerBypassFinding{
		Code: models.FindingDockerIneffectiveRule, IPVersion: models.IPv4, Rule: &rule, Severity: models.SeverityHigh, Fix: "fix",
	}), Options{Now: testTime})
	want := "iptables -R DOCKER-USER 1 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP"
	found := find(rep, string(models.FindingDockerIneffectiveRule))
	if len(found) != 1 || commands(found[0].Fix) != want {
		t.Fatalf("expected %q, got %+v", want, found)
	}
	if found[0].Category != "paths" || found[0].Points != 5 {
		t.Fatalf("category %s, -%d", found[0].Category, found[0].Points)
	}
}

func TestFragileRuleFixMovesTheRuleIntoDockerUser(t *testing.T) {
	rule := models.Rule{IPVersion: models.IPv4, Table: "filter", Chain: "FORWARD", RuleNum: 1, Target: "DROP", RawLine: "-A FORWARD -p tcp -m tcp --dport 80 -j DROP"}
	rep := Build(handBuilt(models.DockerBypassFinding{
		Code: models.FindingDockerFragileRule, IPVersion: models.IPv4, Rule: &rule, Severity: models.SeverityMedium, Fix: "move it",
	}), Options{Now: testTime})
	found := find(rep, string(models.FindingDockerFragileRule))
	if len(found) != 1 || commands(found[0].Fix) != "iptables -I DOCKER-USER 1 -p tcp -m tcp --dport 80 -j DROP\niptables -D FORWARD 1" {
		t.Fatalf("expected the two commands that move the rule, got %+v", found)
	}
}

func TestDirectRouteFixUsesTheSubnetOfTheBridge(t *testing.T) {
	result := handBuilt(models.DockerBypassFinding{
		Code: models.FindingDockerDirectRoute, IPVersion: models.IPv4, Bridge: "docker0", ContainerDest: "172.17.0.3:80",
		ExposedPort: "80", Severity: models.SeverityHigh, GatewayMode: "nat",
	})
	result.IPv4Rules = parse(t, "*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\nCOMMIT\n", models.IPv4)
	rep := Build(result, Options{Now: testTime})
	found := find(rep, string(models.FindingDockerDirectRoute))
	if len(found) != 1 {
		t.Fatalf("%+v", rep.Findings)
	}
	text := commands(found[0].Fix)
	if !strings.Contains(text, "iptables -t raw -I PREROUTING -d 172.17.0.0/16 ! -i docker0 -j DROP") || !strings.Contains(text, "! --ctstate DNAT -j DROP") {
		t.Fatalf("direct-routing fix is incomplete: %s", text)
	}
}

// Audit B8: a port forward of a router gets advice without Docker in it.
func TestPortForwardIsNotCalledDocker(t *testing.T) {
	rep := build(t, "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -i eth0 -p tcp -m tcp --dport 8443 -j DNAT --to-destination 192.168.1.50:443\nCOMMIT\n"+
		"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\n"+
		"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"+
		"-A FORWARD -d 192.168.1.50/32 -p tcp -m tcp --dport 443 -j ACCEPT\nCOMMIT\n", "", nil, Options{})
	finding := findingFor(t, rep, "8443/tcp")
	if finding.Title != "Forwarded port 8443/tcp is open to any source" || finding.Category != "exposure" {
		t.Fatalf("title %q, category %s", finding.Title, finding.Category)
	}
	text := finding.Title + finding.Detail + finding.Fix.Summary + commands(finding.Fix)
	if strings.Contains(strings.ToLower(text), "docker") {
		t.Fatalf("a port forward is described with Docker: %s", text)
	}
	if !strings.Contains(finding.Fix.Summary, "nat/PREROUTING rule #1") || !strings.Contains(finding.Fix.Summary, "--ctorigdstport 8443") {
		t.Fatalf("fix: %s", finding.Fix.Summary)
	}
	if len(rep.Forwards) != 1 || rep.Forwards[0].Docker || rep.Forwards[0].DestAddr != "192.168.1.50" || rep.Forwards[0].ForwardScope != models.ScopeExposed {
		t.Fatalf("forwarded ports: %+v", rep.Forwards)
	}
}

func TestPolicyFixUsesTheCommandOfTheFamily(t *testing.T) {
	rep := build(t, "", policies("ACCEPT", "ACCEPT")+"COMMIT\n", []string{}, Options{})
	text := ""
	for _, finding := range find(rep, string(models.FindingPolicyAccept)) {
		text += commands(finding.Fix) + "\n"
	}
	if !strings.Contains(text, "ip6tables -P INPUT DROP") || !strings.Contains(text, "ip6tables -P FORWARD DROP") || strings.Contains(text, "\niptables ") || strings.HasPrefix(text, "iptables ") {
		t.Fatalf("expected ip6tables commands only: %s", text)
	}
}

// A rule that accepts everything is deleted, not hidden behind a policy; in
// a chain that a program manages the report gives no command at all.
func TestCatchAllAcceptFix(t *testing.T) {
	rep := build(t, policies("DROP", "DROP")+"-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j ACCEPT\nCOMMIT\n", "", []string{}, Options{})
	if fix := inputDefault(t, rep).Fix; commands(fix) != "iptables -D INPUT 2" {
		t.Fatalf("expected the command that deletes the rule: %+v", fix)
	}
	rep = build(t, policies("DROP", "DROP")+":ufw-user-input - [0:0]\n-A INPUT -j ufw-user-input\n-A ufw-user-input -j ACCEPT\nCOMMIT\n", "", []string{}, Options{})
	if fix := inputDefault(t, rep).Fix; len(fix.Steps) != 0 || !strings.Contains(fix.Summary, "ufw") {
		t.Fatalf("a rule of ufw must be changed with ufw: %+v", fix)
	}
}

// Rules of ufw are changed with ufw: iptables commands would be lost at the
// next reload. A "ufw limit" rule is deleted as such.
func TestUFWRulesGetUFWCommands(t *testing.T) {
	var ss []string
	for _, line := range strings.Split(fixture(t, "ufw-services.txt"), "\n") {
		if line != "" && !strings.HasPrefix(line, "Netid") && !strings.HasPrefix(line, "State") {
			ss = append(ss, line)
		}
	}
	rep := build(t, fixture(t, "ufw.iptables-save"), "", ss, Options{})
	ssh, web := findingFor(t, rep, "22/tcp"), findingFor(t, rep, "80/tcp")
	if got := commands(ssh.Fix); got != "ufw allow from <trusted-cidr> to any port 22 proto tcp\nufw delete limit 22/tcp" {
		t.Errorf("SSH behind ufw limit: %s", got)
	}
	if got := commands(web.Fix); got != "ufw allow from <trusted-cidr> to any port 80 proto tcp\nufw delete allow 80/tcp" {
		t.Errorf("port 80: %s", got)
	}
	for _, finding := range rep.Findings {
		if strings.Contains(commands(finding.Fix), "iptables") {
			t.Errorf("%s: an iptables command for a chain of ufw: %s", finding.ID, commands(finding.Fix))
		}
	}
	// The rate limit of ufw keeps SSH from being a high finding (audit B5).
	if ssh.Severity != models.SeverityMedium || web.Severity != models.SeverityLow || rep.Score.Grade != "A" {
		t.Errorf("ssh %s, web %s, grade %s", ssh.Severity, web.Severity, rep.Score.Grade)
	}
	if len(ssh.Rules) != 1 || len(ssh.Rules[0].Path) != 4 || ssh.Rules[0].Path[0] != "INPUT #2" {
		t.Errorf("the finding does not show how the rule is reached: %+v", ssh.Rules)
	}
}

// Only a rule that opens exactly the unused port can be deleted for it.
func TestUnusedPortFix(t *testing.T) {
	rep := build(t, filterRules(
		"-A INPUT -p tcp --dport 8080 -j ACCEPT",
		"-A INPUT -p tcp -m multiport --dports 9000,9002 -j ACCEPT",
	), "", []string{}, Options{})
	unused := find(rep, string(models.FindingUnusedRule))
	if len(unused) != 3 {
		t.Fatalf("expected findings for 8080, 9000 and 9002: %+v", unused)
	}
	for _, finding := range unused {
		switch finding.Ports[0] {
		case "8080/tcp":
			if commands(finding.Fix) != "iptables -D INPUT 3" {
				t.Errorf("8080: %+v", finding.Fix)
			}
		case "9000/tcp", "9002/tcp":
			if len(finding.Fix.Steps) != 0 {
				t.Errorf("deleting the rule for one port would close the other too: %s", commands(finding.Fix))
			}
		default:
			t.Errorf("unexpected port %v", finding.Ports)
		}
		if finding.Severity != models.SeverityInfo || finding.Points != 0 {
			t.Errorf("%s: %s -%d", finding.Title, finding.Severity, finding.Points)
		}
	}
}
