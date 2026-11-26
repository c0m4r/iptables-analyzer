package report

import (
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

const noListeners = "" // an empty row list is a host on which nothing listens

func policies(input, forward string) string {
	return "*filter\n:INPUT " + input + " [0:0]\n:FORWARD " + forward + " [0:0]\n:OUTPUT ACCEPT [0:0]\n"
}

// Audit A1, E1: a firewall that accepts every connection cannot get a good
// grade, whatever the policy line says and whether or not something listens.
func TestAcceptAllRulesetIsGradedF(t *testing.T) {
	for name, data := range map[string]string{
		"rule under a DROP policy": policies("DROP", "DROP") + "-A INPUT -j ACCEPT\nCOMMIT\n",
		"ACCEPT policy":            policies("ACCEPT", "DROP") + "COMMIT\n",
	} {
		rep := build(t, data, "", []string{}, Options{})
		if rep.Score.Grade != "F" || lost(rep, "policy") != 15 || rep.Score.Cap == "" {
			t.Errorf("%s: grade %s, policy -%d, cap %q", name, rep.Score.Grade, lost(rep, "policy"), rep.Score.Cap)
		}
		if rep.Score.Total < 80 {
			t.Errorf("%s: the points alone give %d; the limit of the grade must explain the F", name, rep.Score.Total)
		}
	}
}

func TestConditionalFinalDropDoesNotHideAcceptPolicy(t *testing.T) {
	rep := build(t, policies("ACCEPT", "DROP")+"-A INPUT -m conntrack --ctstate INVALID -j DROP\nCOMMIT\n", "", []string{}, Options{})
	if lost(rep, "policy") != 15 {
		t.Fatalf("expected the INPUT policy deduction, got -%d", lost(rep, "policy"))
	}
}

func TestPolicyFindingsAreNotCountedAsHygieneToo(t *testing.T) {
	rep := build(t, policies("ACCEPT", "ACCEPT")+"COMMIT\n", "", []string{}, Options{})
	// INPUT -15; FORWARD -5 while nothing shows that the host routes packets.
	if lost(rep, "policy") != 20 {
		t.Fatalf("policy -%d", lost(rep, "policy"))
	}
	for _, finding := range rep.Findings {
		if finding.Code == string(models.FindingPolicyAccept) && finding.Category != "policy" {
			t.Fatalf("policy finding in category %s", finding.Category)
		}
	}
}

func TestIPv6AloneUsesThePolicyCategory(t *testing.T) {
	rep := build(t, "", policies("ACCEPT", "ACCEPT")+"COMMIT\n", []string{}, Options{})
	if lost(rep, "policy") != 20 || lost(rep, "ipv6") != 0 {
		t.Fatalf("policy -%d, ipv6 -%d", lost(rep, "policy"), lost(rep, "ipv6"))
	}
}

// Audit B2: an ACCEPT policy behind a final REJECT denies by default.
func TestFinalRejectUnderAcceptPolicyIsDefaultDeny(t *testing.T) {
	rep := build(t, policies("ACCEPT", "ACCEPT")+
		"-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -i lo -j ACCEPT\n"+
		"-A INPUT -j REJECT --reject-with icmp-host-prohibited\n-A FORWARD -j REJECT --reject-with icmp-host-prohibited\nCOMMIT\n", "", []string{}, Options{})
	if rep.Score.Total != 100 || rep.Score.Grade != "A" {
		t.Fatalf("classic RHEL layout: %d %s %+v", rep.Score.Total, rep.Score.Grade, rep.Findings)
	}
}

// Audit A2: wide port ranges open to any source cost points without a
// listener, and a host that routes packets pays more for an open FORWARD.
func TestBroadAcceptAndRoutingAreScored(t *testing.T) {
	broad := build(t, filterRules("-A INPUT -p udp -m udp --dport 1024:65535 -j ACCEPT"), "", []string{}, Options{})
	if lost(broad, "exposure") != 10 {
		t.Errorf("wide UDP range: exposure -%d", lost(broad, "exposure"))
	}
	router := build(t, "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -o eth0 -j MASQUERADE\nCOMMIT\n"+
		policies("DROP", "ACCEPT")+"-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\nCOMMIT\n", "", []string{}, Options{})
	if lost(router, "policy") != 10 {
		t.Errorf("open FORWARD on a host that translates addresses: policy -%d", lost(router, "policy"))
	}
}

// Audit E4: the rules alone give a complete grade. Without the listening
// sockets every open port counts as if a service uses it.
func TestGradeIsCompleteWithoutServices(t *testing.T) {
	rules := filterRules("-A INPUT -p tcp --dport 22 -j ACCEPT", "-A INPUT -p tcp --dport 8080 -j ACCEPT")
	rep := build(t, rules, "", nil, Options{})
	if !rep.Score.Complete || rep.Score.Grade == "INCOMPLETE" || rep.ServicesKnown {
		t.Fatalf("grade %s complete=%v services=%v", rep.Score.Grade, rep.Score.Complete, rep.ServicesKnown)
	}
	if lost(rep, "exposure") != 7 { // 22: 5, 8080: 2
		t.Fatalf("open ports must cost without listeners: exposure -%d", lost(rep, "exposure"))
	}
	if len(find(rep, "open_port")) != 2 || len(find(rep, string(models.FindingExposedService))) != 0 {
		t.Fatalf("expected two open_port findings: %+v", rep.Findings)
	}
	said := false
	for _, note := range rep.Notes {
		said = said || (note.Kind == "scope" && note.Area == "services")
	}
	if !said {
		t.Fatalf("the report does not say that no listeners were read: %+v", rep.Notes)
	}

	// With the listeners only the ports in use cost; the other is a note.
	rep = build(t, rules, "", []string{`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`}, Options{})
	if lost(rep, "exposure") != 5 || len(find(rep, string(models.FindingUnusedRule))) != 1 {
		t.Fatalf("with listeners: exposure -%d, findings %+v", lost(rep, "exposure"), rep.Findings)
	}
}

// A port costs by the kind of service that usually listens on it.
func TestExposureFollowsThePortRisk(t *testing.T) {
	rep := build(t, filterRules(
		"-A INPUT -p tcp --dport 3306 -j ACCEPT",
		"-A INPUT -p tcp --dport 8080 -j ACCEPT",
		"-A INPUT -p tcp --dport 443 -j ACCEPT",
	), "", nil, Options{})
	want := map[string]struct {
		severity models.Severity
		points   int
	}{"3306/tcp": {models.SeverityHigh, 5}, "8080/tcp": {models.SeverityMedium, 2}, "443/tcp": {models.SeverityLow, 1}}
	for _, finding := range find(rep, "open_port") {
		expected, ok := want[finding.Ports[0]]
		if !ok || finding.Severity != expected.severity || finding.Points != expected.points {
			t.Errorf("%s: %s -%d", finding.Ports[0], finding.Severity, finding.Points)
		}
		delete(want, finding.Ports[0])
	}
	if len(want) != 0 {
		t.Fatalf("missing findings: %v", want)
	}
}

// Decision 7: a port that is declared public is a note without points.
func TestPublicPortsCostNothing(t *testing.T) {
	rules := filterRules("-A INPUT -p tcp --dport 80 -j ACCEPT", "-A INPUT -p tcp --dport 443 -j ACCEPT", "-A INPUT -p tcp --dport 3306 -j ACCEPT")
	public, err := ParsePublic("tcp/80, 443/tcp")
	if err != nil {
		t.Fatal(err)
	}
	rep := build(t, rules, "", nil, Options{Public: public})
	if lost(rep, "exposure") != 5 {
		t.Fatalf("only 3306 may cost: exposure -%d", lost(rep, "exposure"))
	}
	for _, finding := range find(rep, "open_port") {
		public := finding.Ports[0] != "3306/tcp"
		if public != (finding.Severity == models.SeverityInfo && finding.Points == 0 && finding.Fix == nil) {
			t.Errorf("%s: %s -%d fix=%v", finding.Ports[0], finding.Severity, finding.Points, finding.Fix != nil)
		}
	}
	marked := 0
	for _, open := range rep.OpenPorts {
		if open.Public {
			marked++
		}
	}
	if marked != 2 {
		t.Fatalf("open ports marked public: %d", marked)
	}
}

func TestParsePublic(t *testing.T) {
	specs, err := ParsePublic("tcp/80,443/tcp, udp/53 ,8000-8100,")
	if err != nil || len(specs) != 4 {
		t.Fatalf("%v %+v", err, specs)
	}
	if specs[2] != (PortSpec{models.ProtoUDP, 53, 53}) || specs[3] != (PortSpec{models.ProtoTCP, 8000, 8100}) {
		t.Fatalf("%+v", specs)
	}
	for _, bad := range []string{"sctp/80", "tcp/0", "tcp/70000", "tcp/90-80", "http", "tcp/", "80/tcp/x"} {
		if _, err := ParsePublic(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// A service that listens on both address families is one finding and costs
// once.
func TestExposureCountsAPortOnceAcrossFamilies(t *testing.T) {
	rules := filterRules("-A INPUT -p tcp --dport 22 -j ACCEPT", "-A INPUT -p tcp --dport 8080 -j ACCEPT", "-A INPUT -p udp --dport 8080 -j ACCEPT")
	rep := build(t, rules, rules, []string{
		`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`,
		`tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))`,
		`tcp LISTEN 0 128 *:8080 *:* users:(("app",pid=2,fd=3))`,
		`udp UNCONN 0 0 0.0.0.0:8080 0.0.0.0:* users:(("app",pid=2,fd=4))`,
	}, Options{})
	// tcp/22 (-5), tcp/8080 (-2) and udp/8080 (-2).
	if lost(rep, "exposure") != 9 {
		t.Fatalf("exposure -%d: %+v", lost(rep, "exposure"), rep.Findings)
	}
	exposed := find(rep, string(models.FindingExposedService))
	if len(exposed) != 3 {
		t.Fatalf("expected three findings, got %d", len(exposed))
	}
	for _, finding := range exposed {
		if finding.Ports[0] == "22/tcp" && len(finding.Families) != 2 {
			t.Fatalf("sshd on both families must be one finding: %+v", finding.Families)
		}
	}
}

// Audit E2: a finding that is only possible costs half, rounded up.
func TestPossibleFindingsCostHalf(t *testing.T) {
	for points, want := range map[int]int{5: 3, 2: 1, 1: 1, 12: 6, 0: 0} {
		if got := weigh(points, models.CertaintyPossible); got != want {
			t.Errorf("weigh(%d) = %d, want %d", points, got, want)
		}
		if got := weigh(points, models.CertaintyDefinite); got != points {
			t.Errorf("a definite finding costs all of its %d points, got %d", points, got)
		}
	}
	// An ipset decides who reaches the port: the exposure is possible only
	// for the part that the set does not cover, which the report cannot see.
	rep := build(t, filterRules("-A INPUT -p tcp --dport 22 -m set ! --match-set blocked src -j ACCEPT"), "", nil, Options{})
	for _, finding := range rep.Findings {
		if finding.Certainty == models.CertaintyPossible && finding.Points > 3 {
			t.Errorf("possible finding with full points: %s -%d", finding.Title, finding.Points)
		}
	}
}

// A category cannot lose more than its maximum, and the gain of a finding
// says what its fix alone does to the score.
func TestCategoryLimitAndGain(t *testing.T) {
	var lines []string
	for _, port := range []string{"21", "23", "3306", "5432", "6379", "27017", "9200"} {
		lines = append(lines, "-A INPUT -p tcp --dport "+port+" -j ACCEPT")
	}
	rep := build(t, filterRules(lines...), "", nil, Options{})
	if lost(rep, "exposure") != 25 || rep.Score.Total != 75 {
		t.Fatalf("7 sensitive ports are 35 points, limited to 25: -%d, total %d", lost(rep, "exposure"), rep.Score.Total)
	}
	for _, finding := range find(rep, "open_port") {
		// 35 - 5 = 30 is still above the limit: one fix alone gains nothing.
		if finding.Points != 5 || finding.Gain != 0 || finding.GradeAfter != "" {
			t.Fatalf("%s: points %d gain %d after %q", finding.Title, finding.Points, finding.Gain, finding.GradeAfter)
		}
	}

	rep = build(t, filterRules(lines[:6]...), "", nil, Options{})
	for _, finding := range find(rep, "open_port") {
		// 30 points, limited to 25: one fix leaves 25, so it gains nothing.
		if finding.Gain != 0 {
			t.Fatalf("%s: gain %d", finding.Title, finding.Gain)
		}
	}
	rep = build(t, filterRules(lines[:2]...), "", nil, Options{})
	for _, finding := range find(rep, "open_port") {
		if finding.Gain != 5 || finding.GradeAfter != "" {
			t.Fatalf("%s: gain %d after %q (total %d)", finding.Title, finding.Gain, finding.GradeAfter, rep.Score.Total)
		}
	}
}

// The finding that limits the grade is the one whose fix gives a better
// grade, also when another finding costs more points.
func TestGradeAfterNamesTheFindingThatLimitsTheGrade(t *testing.T) {
	rep := build(t, fixture(t, "docker29.iptables-save"), fixture(t, "docker29.ip6tables-save"), nil, Options{})
	if rep.Score.Grade != "F" || rep.Score.Cap == "" {
		t.Fatalf("grade %s cap %q", rep.Score.Grade, rep.Score.Cap)
	}
	policy := find(rep, string(models.FindingPolicyAccept))
	var input *Finding
	for i := range policy {
		if policy[i].Points == 15 {
			input = &policy[i]
		}
	}
	if input == nil || input.Gain != 15 || input.GradeAfter != gradeFromScore(rep.Score.Total+15) {
		t.Fatalf("INPUT policy finding: %+v", input)
	}
	for _, finding := range rep.Findings {
		if finding.ID != input.ID && finding.GradeAfter != "" {
			t.Errorf("%s (%s) cannot lift the limit of the grade, but says grade %s", finding.ID, finding.Title, finding.GradeAfter)
		}
	}
}

func TestFindingsWithOneKeyCostOnce(t *testing.T) {
	findings := []Finding{
		{Category: "exposure", Points: 5, key: "port/22/tcp"},
		{Category: "exposure", Points: 3, key: "port/22/tcp"},
		{Category: "exposure", Points: 2},
		{Category: "policy", Points: 15, key: "policy/INPUT", ceiling: "F", ceilingReason: "INPUT accepts every new connection"},
		{Category: "policy", Points: 15, key: "policy/INPUT", ceiling: "D", ceilingReason: "IPv6 INPUT accepts every new connection"},
	}
	result := score(findings, nil)
	if result.Total != 100-7-15 || result.Grade != "F" || result.Cap != "grade limited to F: INPUT accepts every new connection" {
		t.Fatalf("%+v", result)
	}
	// The second charge for port 22 is covered by the first; the two policy
	// findings cover each other.
	wantGain := []int{2, 0, 2, 0, 0}
	wantAfter := []string{"", "", "", "D", ""}
	for i, finding := range findings {
		if finding.Gain != wantGain[i] || finding.GradeAfter != wantAfter[i] {
			t.Errorf("finding %d: gain %d, grade after %q; want %d, %q", i, finding.Gain, finding.GradeAfter, wantGain[i], wantAfter[i])
		}
	}
}

func TestIncompleteAnalysisHasNoGrade(t *testing.T) {
	findings := []Finding{{Category: "policy", Points: 15, ceiling: "F", ceilingReason: "x"}}
	result := score(findings, []Note{{Kind: "incomplete", Area: "docker", Text: "a port could not be followed"}, {Kind: "scope", Text: "IPv6 not supplied"}})
	if result.Complete || result.Grade != "INCOMPLETE" || len(result.Unassessed) != 1 || result.Total != 85 {
		t.Fatalf("%+v", result)
	}
	if findings[0].GradeAfter != "" {
		t.Fatalf("no grade to improve, but the finding says %q", findings[0].GradeAfter)
	}
}

func TestGrades(t *testing.T) {
	for total, grade := range map[int]string{100: "A", 90: "A", 89: "B", 80: "B", 79: "C", 70: "C", 69: "D", 50: "D", 49: "F", 0: "F"} {
		if got := gradeFromScore(total); got != grade {
			t.Errorf("%d: %s, want %s", total, got, grade)
		}
	}
}

// An address family without any rule is one finding that stands for the
// default-accept findings of that family.
func TestFamilyWithoutRulesIsOneFinding(t *testing.T) {
	result := analyzeLive(t, "", "")
	rep := Build(result, Options{Now: testTime, Live: true})
	none := find(rep, "no_rules")
	if len(none) != 2 || rep.Score.Grade != "F" || len(find(rep, string(models.FindingPolicyAccept))) != 0 {
		t.Fatalf("no rules at all: %d findings, grade %s: %+v", len(none), rep.Score.Grade, rep.Findings)
	}
	if lost(rep, "policy") != 25 || lost(rep, "ipv6") != 10 {
		t.Fatalf("policy -%d ipv6 -%d", lost(rep, "policy"), lost(rep, "ipv6"))
	}

	// IPv4 rules only; whether the open IPv6 stack limits the grade to F
	// depends on what is known about the addresses of the host.
	basic := fixture(t, "basic.iptables-save")
	for name, c := range map[string]struct {
		host     *models.HostContext
		grade    string
		severity models.Severity
	}{
		"addresses unknown": {nil, "D", models.SeverityHigh},
		"global address": {&models.HostContext{Interfaces: []models.HostInterface{{Name: "eth0", Up: true,
			Addrs: []string{"192.0.2.1/24", "2001:db8::1/64"}}}}, "F", models.SeverityHigh},
		"link-local only": {&models.HostContext{Interfaces: []models.HostInterface{{Name: "eth0", Up: true,
			Addrs: []string{"192.0.2.1/24", "fe80::1/64"}}}}, "", models.SeverityMedium},
	} {
		result := analyzeLive(t, basic, "")
		result.Host = c.host
		rep := Build(result, Options{Now: testTime, Live: true})
		none := find(rep, "no_rules")
		if len(none) != 1 || none[0].Severity != c.severity || none[0].ceiling != c.grade || none[0].Points != 10 {
			t.Errorf("%s: %+v", name, none)
		}
	}
}

func TestFindingsOfBothFamiliesAreJoined(t *testing.T) {
	rules := policies("ACCEPT", "DROP") + "COMMIT\n"
	rep := build(t, rules, rules, []string{}, Options{})
	policy := find(rep, string(models.FindingPolicyAccept))
	var input []Finding
	for _, finding := range policy {
		if finding.Points == 15 {
			input = append(input, finding)
		}
	}
	if len(input) != 1 || len(input[0].Families) != 2 || len(input[0].Fix.Steps) != 2 {
		t.Fatalf("expected one finding for both families with both commands: %+v", input)
	}
	if lost(rep, "policy") != 15 {
		t.Fatalf("policy -%d", lost(rep, "policy"))
	}
}

// Many ports of one kind are one finding, so that they do not bury the rest.
func TestManyOpenPortsAreOneFinding(t *testing.T) {
	var lines []string
	for port := 8101; port <= 8112; port++ {
		lines = append(lines, "-A INPUT -p tcp --dport "+itoa(port)+" -j ACCEPT")
	}
	lines = append(lines, "-A INPUT -p tcp --dport 22 -j ACCEPT")
	rep := build(t, filterRules(lines...), "", nil, Options{})
	open := find(rep, "open_port")
	if len(open) != 2 {
		t.Fatalf("expected the SSH finding and one joined finding, got %d: %+v", len(open), open)
	}
	for _, finding := range open {
		if finding.Severity != models.SeverityMedium {
			continue
		}
		if len(finding.Ports) != 12 || finding.Points != 24 {
			t.Fatalf("joined finding: %d ports, -%d", len(finding.Ports), finding.Points)
		}
		// The fix of one port does not fit the others.
		if finding.Fix == nil || len(finding.Fix.Steps) != 0 {
			t.Fatalf("joined finding carries the commands of one port: %+v", finding.Fix)
		}
	}
}

func TestFindingsAreOrderedAndNumbered(t *testing.T) {
	rep := build(t, fixture(t, "docker29.iptables-save"), fixture(t, "docker29.ip6tables-save"), nil, Options{})
	if len(rep.Findings) < 3 {
		t.Fatalf("too few findings: %d", len(rep.Findings))
	}
	counted := 0
	for i, finding := range rep.Findings {
		if finding.ID != "F"+itoa(i+1) {
			t.Fatalf("finding %d has the number %s", i, finding.ID)
		}
		if i > 0 && finding.Severity > rep.Findings[i-1].Severity {
			t.Fatalf("%s is more severe than the finding before it", finding.ID)
		}
		counted++
	}
	if total := rep.Counts.Critical + rep.Counts.High + rep.Counts.Medium + rep.Counts.Low + rep.Counts.Info; total != counted {
		t.Fatalf("counts %+v do not add up to %d findings", rep.Counts, counted)
	}
}

// Services on ports that no rule names are open because of one thing, the
// default of INPUT. They are one finding without a fix of its own, they cost
// their points, and the list of open ports names them.
func TestServicesOpenByDefaultAreOneFinding(t *testing.T) {
	rules := policies("ACCEPT", "DROP") + "-A INPUT -p tcp --dport 8443 -j ACCEPT\nCOMMIT\n"
	rep := build(t, rules, rules, []string{
		`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`,
		`tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))`,
		`tcp LISTEN 0 128 0.0.0.0:3306 0.0.0.0:* users:(("mysqld",pid=2,fd=3))`,
		`tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:(("app",pid=3,fd=3))`,
		`tcp LISTEN 0 128 127.0.0.1:6379 0.0.0.0:* users:(("redis",pid=4,fd=3))`,
	}, Options{})
	exposed := find(rep, string(models.FindingExposedService))
	if len(exposed) != 2 {
		t.Fatalf("expected one finding for the services that the default opens and one for the rule, got %+v", exposed)
	}
	joined, own := exposed[0], exposed[1]
	if joined.Title != "2 services are open to any source because INPUT accepts by default" || joined.Severity != models.SeverityHigh ||
		joined.Points != 10 || joined.Fix != nil || len(joined.Ports) != 2 || len(joined.Families) != 2 {
		t.Fatalf("joined finding: %+v", joined)
	}
	for _, wanted := range []string{"sshd on 22/tcp;", "mysqld on 3306/tcp (IPv4 only)", "Close the default first"} {
		if !strings.Contains(joined.Detail, wanted) {
			t.Errorf("detail lacks %q: %s", wanted, joined.Detail)
		}
	}
	// The port that a rule names is open because of that rule: its finding
	// has the fix for the rule.
	if own.Title != "app is open to any source on 8443/tcp" || own.Fix == nil || commands(own.Fix) != "iptables -R INPUT 1 -s <trusted-cidr> -p tcp --dport 8443 -j ACCEPT" {
		t.Fatalf("finding for the rule: %+v %s", own, commands(own.Fix))
	}
	if lost(rep, "exposure") != 12 || lost(rep, "policy") != 15 {
		t.Fatalf("exposure -%d, policy -%d", lost(rep, "exposure"), lost(rep, "policy"))
	}
	listed := map[string]bool{}
	for _, open := range rep.OpenPorts {
		if !open.Default {
			listed[portText(models.Protocol(open.Protocol), open.First, open.Last)+" "+strings.Join(open.Listeners, ",")] = true
		}
	}
	for _, wanted := range []string{"22/tcp sshd", "3306/tcp mysqld", "8443/tcp app"} {
		if !listed[wanted] {
			t.Errorf("the open ports do not list %s: %v", wanted, listed)
		}
	}
	if listed["6379/tcp redis"] {
		t.Errorf("a service on loopback is listed as open: %v", listed)
	}

	// One such service keeps its own title.
	rep = build(t, policies("ACCEPT", "DROP")+"COMMIT\n", "", []string{`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`}, Options{})
	exposed = find(rep, string(models.FindingExposedService))
	if len(exposed) != 1 || exposed[0].Title != "sshd is open to any source on 22/tcp" || exposed[0].Fix != nil ||
		!strings.Contains(exposed[0].Detail, "INPUT accepts it from any source by default") {
		t.Fatalf("%+v", exposed)
	}

	// A port that a rule opens for any source under a DROP policy is a
	// finding of its own, with its fix.
	rep = build(t, filterRules("-A INPUT -p tcp --dport 22 -j ACCEPT"), "", []string{`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`}, Options{})
	exposed = find(rep, string(models.FindingExposedService))
	if len(exposed) != 1 || exposed[0].Fix == nil || len(exposed[0].Fix.Steps) != 2 {
		t.Fatalf("%+v", exposed)
	}
}
