package report

import (
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// natAndFilter builds rules of nat/PREROUTING in front of a filter table
// that denies by default.
func natAndFilter(nat []string, filter ...string) string {
	return "*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n" +
		strings.Join(nat, "\n") + "\nCOMMIT\n" + filterRules(filter...)
}

// A port that nat/PREROUTING redirects is a finding about the port that the
// clients use: its number tells what the service is to them (audit A6).
func TestRedirectedPortIsAFindingOfItsOwn(t *testing.T) {
	rules := natAndFilter([]string{"-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080"},
		"-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT")
	rep := build(t, rules, "", []string{`tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("node",pid=7,fd=3))`}, Options{})

	redirected := findingFor(t, rep, "80/tcp")
	if redirected.Title != "node is open to any source on 80/tcp" || redirected.Severity != models.SeverityLow || redirected.Points != 1 {
		t.Errorf("port 80 is a public port: %+v", redirected)
	}
	if !strings.Contains(redirected.Detail, "nat/PREROUTING rule #1 sends the port to local port 8080, where the service listens") ||
		!strings.Contains(redirected.Detail, "a rule for it decides about both ports") {
		t.Errorf("detail: %s", redirected.Detail)
	}
	if len(redirected.Rules) != 2 || redirected.Rules[0].Role != "redirects" || redirected.Rules[0].Table != "nat" || redirected.Rules[1].Role != "accepts" {
		t.Errorf("the finding names the redirect and the rule that accepts: %+v", redirected.Rules)
	}
	direct := findingFor(t, rep, "8080/tcp")
	if direct.Severity != models.SeverityMedium || direct.Points != 2 || len(direct.Rules) != 1 {
		t.Errorf("port 8080 is open by itself: %+v", direct)
	}
	if lost(rep, "exposure") != 3 {
		t.Errorf("the two ports cost 1 and 2 points, got %d", lost(rep, "exposure"))
	}

	var entry *OpenPort
	for i := range rep.OpenPorts {
		if rep.OpenPorts[i].First == 80 {
			entry = &rep.OpenPorts[i]
		}
	}
	if entry == nil || entry.Redirect == nil || entry.Redirect.First != 8080 || entry.Redirect.Last != 8080 || entry.Redirect.Address != "" ||
		len(entry.Redirect.Rules) != 1 || strings.Join(entry.Listeners, ",") != "node" {
		t.Fatalf("the table of open ports shows the redirect and the listener behind it: %+v", entry)
	}

	// Without a list of sockets the rules alone give the same two ports.
	rep = build(t, rules, "", nil, Options{})
	open := findingFor(t, rep, "80/tcp")
	if open.Code != "open_port" || !strings.Contains(open.Detail, "nat/PREROUTING rule #1 sends the port to local port 8080; accepted by filter/INPUT rule #3") {
		t.Errorf("rules only: %+v", open)
	}
}

func TestRedirectWithoutListenerIsNoted(t *testing.T) {
	rules := natAndFilter([]string{"-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080"},
		"-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT")
	rep := build(t, rules, "", []string{`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=7,fd=3))`}, Options{})
	unused := find(rep, string(models.FindingUnusedRule))
	var titles []string
	for _, finding := range unused {
		titles = append(titles, finding.Title)
	}
	got := strings.Join(titles, "; ")
	if !strings.Contains(got, "80/tcp is redirected to local port 8080, but nothing listens there") ||
		!strings.Contains(got, "8080/tcp is open, but nothing listens on it") {
		t.Errorf("unused ports: %s", got)
	}
}

// A translation that a rule makes for one address is named with it.
func TestPortOfOneAddressIsNamedWithIt(t *testing.T) {
	rules := natAndFilter([]string{"-A PREROUTING -d 192.0.2.10/32 -p tcp -m tcp --dport 2222 -j DNAT --to-destination 192.0.2.10:22"},
		"-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate DNAT -j ACCEPT")
	rep := build(t, rules, "", nil, Options{})
	finding := findingFor(t, rep, "2222/tcp")
	if finding.Title != "2222/tcp of 192.0.2.10 is open to any source" ||
		!strings.Contains(finding.Detail, "sends the port to local port 22 of 192.0.2.10") {
		t.Errorf("%s: %s", finding.Title, finding.Detail)
	}
	if len(rep.OpenPorts) != 1 || rep.OpenPorts[0].Address != "192.0.2.10" || rep.OpenPorts[0].Redirect == nil || rep.OpenPorts[0].Redirect.Address != "192.0.2.10" {
		t.Errorf("open ports: %+v", rep.OpenPorts)
	}
}

// The node ports of Kubernetes are forwarded ports. The pods of one service
// are one entry, and the fix is for the cluster, not for Docker (audit A5).
func TestKubernetesNodePortsAreForwardedPorts(t *testing.T) {
	rep := build(t, fixture(t, "k8s.iptables-save"), "", ssRows(t, "k8s-services.txt"), Options{})
	if !rep.Score.Complete {
		t.Fatalf("every translation is followed: %+v", rep.Notes)
	}
	if len(rep.Forwards) != 3 {
		t.Fatalf("two node ports and one address of a load balancer: %+v", rep.Forwards)
	}
	var web *Forward
	for i := range rep.Forwards {
		if rep.Forwards[i].HostPort == 30080 {
			web = &rep.Forwards[i]
		}
	}
	if web == nil || web.Docker || web.HostAddr != "" || web.ForwardScope != models.ScopeExposed || web.Certainty != models.CertaintyDefinite ||
		strings.Join(web.Destinations, " ") != "10.244.0.10:8080 10.244.0.11:8080" {
		t.Errorf("node port 30080 is shared by two pods: %+v", web)
	}
	if rep.Forwards[0].HostAddr != "203.0.113.50" || rep.Forwards[0].HostPort != 80 {
		t.Errorf("the address of the load balancer comes first: %+v", rep.Forwards[0])
	}

	ports := findingFor(t, rep, "30080/tcp")
	if ports.Title != "2 forwarded ports are open to any source" || strings.Contains(ports.Title+ports.Detail, "Docker") ||
		!strings.Contains(ports.Detail, "IPv4 30080/tcp to 10.244.0.10:8080, 10.244.0.11:8080; IPv4 30443/tcp to 10.244.0.12:8443") {
		t.Errorf("%s: %s", ports.Title, ports.Detail)
	}
	if ports.Fix == nil || !strings.Contains(ports.Fix.Summary, "kube-proxy") || strings.Contains(commands(ports.Fix), "DOCKER-USER") ||
		commands(ports.Fix) != "iptables -t raw -I PREROUTING -m addrtype --dst-type LOCAL -p tcp -m tcp --dport 30080 ! -s <trusted-cidr> -j DROP" {
		t.Errorf("fix: %+v", ports.Fix)
	}
	balancer := findingFor(t, rep, "80/tcp")
	if balancer.Title != "Forwarded port 80/tcp of 203.0.113.50 is open to any source" ||
		commands(balancer.Fix) != "iptables -t raw -I PREROUTING -d 203.0.113.50 -p tcp -m tcp --dport 80 ! -s <trusted-cidr> -j DROP" {
		t.Errorf("%s: %s", balancer.Title, commands(balancer.Fix))
	}
	// The default of FORWARD comes from the policy of the chain. A rule that
	// only may match (the mark of kube-proxy) is not its cause.
	for _, finding := range find(rep, string(models.FindingPolicyAccept)) {
		if finding.key == "policy/FORWARD" && (len(finding.Rules) != 0 || !strings.Contains(finding.Detail, "the policy of filter/FORWARD is ACCEPT")) {
			t.Errorf("FORWARD: %+v", finding)
		}
	}
	scope := 0
	for _, note := range rep.Notes {
		if note.Kind == "scope" && strings.Contains(note.Text, "4 cluster IP addresses") {
			scope++
		}
	}
	if scope != 1 {
		t.Errorf("the cluster addresses that were left out are named: %+v", rep.Notes)
	}
	if managers := strings.Join(rep.Families[0].Managers, ","); managers != "flannel,kubernetes" {
		t.Errorf("managers: %s", managers)
	}
}

// Many ports of one kind stay one finding that can be read.
func TestManyForwardedPortsAreAbbreviated(t *testing.T) {
	var nat []string
	// Every second port: ports that follow each other are one range.
	for port := 30000; port < 30080; port += 2 {
		nat = append(nat, "-A PREROUTING -p tcp -m tcp --dport "+itoa(port)+" -j DNAT --to-destination 10.0.0.5:"+itoa(port-20000))
	}
	rep := build(t, natAndFilter(nat, "-A FORWARD -d 10.0.0.5/32 -j ACCEPT"), "", nil, Options{})
	finding := findingFor(t, rep, "30000/tcp")
	if finding.Title != "40 forwarded ports are open to any source" || len(finding.Ports) != 40 ||
		!strings.Contains(finding.Detail, "and 28 more (see the list of translated ports)") || strings.Count(finding.Detail, " to 10.0.0.5:") != 12 {
		t.Errorf("%s: %s", finding.Title, finding.Detail)
	}
	if len(rep.Forwards) != 40 {
		t.Errorf("the list of translated ports has every port: %d", len(rep.Forwards))
	}
}

// Fixes on a host whose rules a program writes name that program.
func TestFixesNameTheProgramThatManagesTheRules(t *testing.T) {
	firewalld := build(t, fixture(t, "firewalld.iptables-save"), "", ssRows(t, "firewalld-services.txt"), Options{})
	ssh := findingFor(t, firewalld, "22/tcp")
	want := `firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="<trusted-cidr>" port port="22" protocol="tcp" accept'
firewall-cmd --permanent --zone=public --remove-port=22/tcp
firewall-cmd --reload`
	if commands(ssh.Fix) != want || strings.Contains(commands(ssh.Fix), "iptables") {
		t.Errorf("firewalld fix:\n%s", commands(ssh.Fix))
	}
	if managers := strings.Join(firewalld.Families[0].Managers, ","); managers != "firewalld" {
		t.Errorf("managers: %s", managers)
	}
	// An ACCEPT policy with a final REJECT denies by default.
	if lost(firewalld, "policy") != 0 {
		t.Errorf("firewalld denies by default: -%d", lost(firewalld, "policy"))
	}

	csf := filterRules("-A INPUT ! -i lo -j LOCALINPUT", "-A INPUT ! -i lo -p tcp -m conntrack --ctstate NEW -m tcp --dport 22 -j ACCEPT",
		"-A INPUT ! -i lo -p tcp -m conntrack --ctstate NEW -m tcp --dport 30000:30100 -j ACCEPT", "-A INPUT ! -i lo -j LOGDROPIN")
	csf = strings.Replace(csf, ":OUTPUT ACCEPT [0:0]\n", ":OUTPUT ACCEPT [0:0]\n:LOCALINPUT - [0:0]\n:LOGDROPIN - [0:0]\n", 1)
	csf = strings.Replace(csf, "COMMIT\n", "-A LOGDROPIN -j DROP\nCOMMIT\n", 1)
	rep := build(t, csf, "", nil, Options{})
	fix := findingFor(t, rep, "22/tcp").Fix
	if fix == nil || !strings.Contains(fix.Summary, "csf (ConfigServer Firewall)") || !strings.Contains(fix.Summary, "TCP_IN") ||
		commands(fix) != "echo 'tcp|in|d=22|s=<trusted-cidr>' >> /etc/csf/csf.allow\ncsf -r" {
		t.Errorf("csf fix: %+v", fix)
	}
	// For a range of ports the file format is not certain: no command.
	if ranged := findingFor(t, rep, "30000-30100/tcp").Fix; ranged == nil || len(ranged.Steps) != 0 || !strings.Contains(ranged.Summary, "csf") {
		t.Errorf("csf fix for a range: %+v", ranged)
	}

	shorewall := filterRules("-A INPUT -j net-fw", "-A net-fw -p tcp -m tcp --dport 22 -j ACCEPT")
	shorewall = strings.Replace(shorewall, ":OUTPUT ACCEPT [0:0]\n", ":OUTPUT ACCEPT [0:0]\n:net-fw - [0:0]\n:shorewall - [0:0]\n", 1)
	fix = findingFor(t, build(t, shorewall, "", nil, Options{}), "22/tcp").Fix
	if fix == nil || !strings.Contains(fix.Summary, "/etc/shorewall/rules") || commands(fix) != "shorewall check && shorewall reload" {
		t.Errorf("shorewall fix: %+v", fix)
	}

	// ufw sets the policies itself.
	ufw := strings.Replace(fixture(t, "ufw.iptables-save"), ":INPUT DROP", ":INPUT ACCEPT", 1)
	ufw = strings.Replace(ufw, "-A ufw-skip-to-policy-input -j DROP\n", "", 1)
	if policy := inputDefault(t, build(t, ufw, "", nil, Options{})); commands(policy.Fix) != "ufw default deny incoming" {
		t.Errorf("ufw policy fix: %+v", policy.Fix)
	}
}

// The limiter for SSH does not repeat a state match that the rule has.
func TestSSHLimiterDoesNotRepeatTheStateMatch(t *testing.T) {
	rep := build(t, fixture(t, "fail2ban.iptables-save"), "", ssRows(t, "fail2ban-services.txt"), Options{})
	fix := commands(findingFor(t, rep, "22/tcp").Fix)
	if strings.Count(fix, "--ctstate NEW") != 2 || !strings.Contains(fix, "--ctstate NEW -m hashlimit --hashlimit-above 10/min") {
		t.Errorf("limiter: %s", fix)
	}
}

func TestSnapshotModeIsNamed(t *testing.T) {
	rep := build(t, fixture(t, "basic.iptables-save"), "", nil, Options{Snapshot: true, Captured: "2026-11-25T04:46:00Z"})
	if rep.Mode != "snapshot" || rep.Captured != "2026-11-25T04:46:00Z" {
		t.Errorf("mode %s, captured %s", rep.Mode, rep.Captured)
	}
	if note := rep.Notes[len(rep.Notes)-1]; !strings.Contains(note.Text, "The snapshot holds no list of listening sockets") {
		t.Errorf("note: %s", note.Text)
	}
}

// Compare reports what the new input changes.
func TestCompare(t *testing.T) {
	before := filterRules("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 8000:8100 -j ACCEPT")
	after := natAndFilter([]string{"-A PREROUTING -p tcp -m tcp --dport 8443 -j DNAT --to-destination 10.0.0.5:443"},
		"-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 8000:8050 -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT", "-A FORWARD -d 10.0.0.5/32 -j ACCEPT")
	make := func(rules string) (*Report, *models.AnalysisResult) {
		result := analyzeLive(t, rules, "")
		result.IPv6Status = models.FamilyNotSupplied
		return Build(result, Options{Now: testTime}), result
	}
	oldReport, oldResult := make(before)
	newReport, newResult := make(after)
	diff := Compare(oldReport, newReport, oldResult, newResult)

	titles := func(findings []Finding) string {
		var list []string
		for _, finding := range findings {
			list = append(list, finding.Title)
		}
		return strings.Join(list, "; ")
	}
	if got := titles(diff.Added); got != "3306/tcp is open to any source; 8000-8050/tcp is open to any source; Forwarded port 8443/tcp is open to any source" {
		t.Errorf("added: %s", got)
	}
	if got := titles(diff.Removed); got != "22/tcp is open to any source; 8000-8100/tcp is open to any source" {
		t.Errorf("removed: %s", got)
	}
	var ports []string
	for _, port := range diff.Ports {
		ports = append(ports, port.Protocol+" "+itoa(port.First)+"-"+itoa(port.Last)+" "+string(port.Old.Scope)+">"+string(port.New.Scope))
	}
	if got := strings.Join(ports, "; "); got != "tcp 22-22 EXPOSED>LOCALNET; tcp 3306-3306 >EXPOSED; tcp 8051-8100 EXPOSED>" {
		t.Errorf("ports: %s", got)
	}
	if len(diff.Forwards) != 1 || diff.Forwards[0].Old != nil || diff.Forwards[0].New.HostPort != 8443 {
		t.Errorf("forwards: %+v", diff.Forwards)
	}
	if diff.Old.Score.Total == 0 || diff.New.Score.Total == 0 || diff.SchemaVersion != SchemaVersion {
		t.Errorf("header: %+v", diff)
	}

	// The same input twice has no difference; the reverse swaps the lists.
	same := Compare(oldReport, oldReport, oldResult, oldResult)
	if len(same.Added)+len(same.Removed)+len(same.Changed)+len(same.Ports)+len(same.Forwards) != 0 {
		t.Errorf("the same input differs: %+v", same)
	}
	back := Compare(newReport, oldReport, newResult, oldResult)
	if titles(back.Added) != titles(diff.Removed) || titles(back.Removed) != titles(diff.Added) || back.Forwards[0].New != nil {
		t.Errorf("reverse: added %s, removed %s", titles(back.Added), titles(back.Removed))
	}

	// A finding of both inputs whose severity differs is a changed finding.
	limited := filterRules("-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/min --hashlimit-mode srcip --hashlimit-name ssh -j DROP",
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 8000:8100 -j ACCEPT")
	limitedReport, limitedResult := make(limited)
	changed := Compare(oldReport, limitedReport, oldResult, limitedResult)
	if len(changed.Changed) != 1 || changed.Changed[0].Old.Severity != models.SeverityHigh || changed.Changed[0].New.Severity != models.SeverityMedium ||
		len(changed.Added)+len(changed.Removed) != 0 {
		t.Errorf("changed: %+v, added %s, removed %s", changed.Changed, titles(changed.Added), titles(changed.Removed))
	}
	// A family that only one input has is not compared.
	six, sixResult := Build(analyzeLive(t, before, before), Options{Now: testTime}), analyzeLive(t, before, before)
	if notes := Compare(oldReport, six, oldResult, sixResult).Notes; len(notes) != 1 || !strings.Contains(notes[0], "IPv6 rules are in the new input only") {
		t.Errorf("notes: %v", notes)
	}
}

// The commands of a fix are written for one port. A finding about several
// ports must say that, name the other ports, and say what changes for them:
// commands for the first port alone would leave the rest open.
func TestFixOfSeveralForwardedPortsNamesTheOthers(t *testing.T) {
	published := func(rep *Report) Finding {
		t.Helper()
		for _, finding := range find(rep, "docker_published_port") {
			if len(finding.Ports) > 1 {
				return finding
			}
		}
		t.Fatalf("no finding about several translated ports: %+v", rep.Findings)
		return Finding{}
	}

	// Docker: one port of one address, a UDP port, a range, and both families.
	docker := published(build(t, fixture(t, "docker29.iptables-save"), fixture(t, "docker29.ip6tables-save"), nil, Options{}))
	for _, want := range []string{
		"The commands below are for port 8080/tcp.",
		"For each of the other ports (8082/tcp of 192.168.88.217, 9053/udp, 9000-9002/tcp, 8091/tcp, 8443/tcp), run them again with its protocol and its port",
		"write a range of ports as FIRST:LAST",
		"For a port of one address, add --ctorigdst ADDRESS; for a port of all addresses, leave that match out.",
		"For IPv6, use ip6tables.",
	} {
		if !strings.Contains(docker.Fix.Summary, want) {
			t.Errorf("the Docker fix lacks %q:\n%s", want, docker.Fix.Summary)
		}
	}
	if got := commands(docker.Fix); !strings.Contains(got, "--ctorigdstport 8080 ") || strings.Contains(got, "--ctorigdst ") {
		t.Errorf("the commands are for the first port, which has no address:\n%s", got)
	}

	// One address family: no word about the other.
	docker = published(build(t, fixture(t, "docker29.iptables-save"), "", nil, Options{}))
	if strings.Contains(docker.Fix.Summary, "ip6tables") {
		t.Errorf("only IPv4 was analyzed:\n%s", docker.Fix.Summary)
	}

	// Kubernetes: node ports are ports of every address of the node.
	node := published(build(t, fixture(t, "k8s.iptables-save"), "", nil, Options{}))
	if !strings.Contains(node.Fix.Summary, "The command below is for port 30080/tcp. For each of the other ports (30443/tcp), run it again with its protocol and its port.") ||
		strings.Contains(node.Fix.Summary, "ADDRESS") || strings.Contains(node.Fix.Summary, "FIRST:LAST") {
		t.Errorf("the Kubernetes fix:\n%s", node.Fix.Summary)
	}

	// A node port together with a port of a load balancer address: the match
	// for the address type of the first does not fit the second.
	services := `*nat
:PREROUTING ACCEPT [0:0]
:KUBE-SERVICES - [0:0]
:KUBE-NODEPORTS - [0:0]
:KUBE-SEP-A - [0:0]
:KUBE-SEP-B - [0:0]
-A PREROUTING -j KUBE-SERVICES
-A KUBE-SERVICES -d 203.0.113.50/32 -p tcp -m tcp --dport 8081 -j KUBE-SEP-B
-A KUBE-SERVICES -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
-A KUBE-NODEPORTS -p tcp -m tcp --dport 30080 -j KUBE-SEP-A
-A KUBE-SEP-A -p tcp -m tcp -j DNAT --to-destination 10.244.0.10:8080
-A KUBE-SEP-B -p tcp -m tcp -j DNAT --to-destination 10.244.0.11:8080
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`
	mixed := published(build(t, services, "", nil, Options{}))
	if !strings.Contains(mixed.Fix.Summary, "Match a port of one address with -d ADDRESS, and a port of all addresses with -m addrtype --dst-type LOCAL.") {
		t.Errorf("a node port and a port of one address:\n%s\n%s", mixed.Fix.Summary, commands(mixed.Fix))
	}

	// Port forwards of the administrator have no commands; the text is about
	// all of them and names no rule of one.
	forwards := published(build(t, fixture(t, "router.iptables-save"), "", nil, Options{}))
	if !strings.HasPrefix(forwards.Fix.Summary, "Each of these ports is translated by its rule in nat/PREROUTING") ||
		strings.Contains(forwards.Fix.Summary, "rule #") || len(forwards.Fix.Steps) != 0 {
		t.Errorf("the fix for port forwards:\n%s", forwards.Fix.Summary)
	}
}
