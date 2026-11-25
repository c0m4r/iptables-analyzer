package baseline

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
)

func TestBaselineAlwaysCoversBothFamilies(t *testing.T) {
	b := Generate(FromResult(&models.AnalysisResult{IPv4Only: true}))
	if !strings.Contains(b.IPv4, "*filter") || !strings.Contains(b.IPv6, "*filter") {
		t.Fatalf("both families must always be generated:\n%s\n%s", b.IPv4, b.IPv6)
	}
	if !strings.Contains(b.IPv6, "--icmpv6-type 135") || !strings.Contains(b.IPv6, "--icmpv6-type 136") {
		t.Fatalf("IPv6 baseline must keep neighbor discovery:\n%s", b.IPv6)
	}
	if strings.Contains(b.IPv4, "DOCKER-USER") {
		t.Fatalf("non-Docker baseline must not declare DOCKER-USER:\n%s", b.IPv4)
	}
}

// The baseline must itself pass the analyzer: no dropped loopback, no blocked
// neighbor discovery, default deny with SSH as the only open service.
func TestBaselinePassesItsOwnAnalysis(t *testing.T) {
	b := Generate(Options{})
	v4, err := parser.Parse(b.IPv4, models.IPv4)
	if err != nil {
		t.Fatalf("IPv4 baseline does not parse: %v", err)
	}
	v6, err := parser.Parse(b.IPv6, models.IPv6)
	if err != nil {
		t.Fatalf("IPv6 baseline does not parse: %v", err)
	}
	result := analyzer.Analyze(v4, v6)
	for _, finding := range result.EffectiveIssues {
		if finding.Severity >= models.SeverityMedium {
			t.Errorf("baseline triggers %s: %s", finding.Code, finding.Title)
		}
	}
	analyzer.CrossReferenceServices(result, []models.ListeningService{
		{Protocol: models.ProtoTCP, Address: "*", Port: 22, Process: "sshd", IsWildcard: true, Family: models.SocketDual},
		{Protocol: models.ProtoTCP, Address: "*", Port: 5432, Process: "postgres", IsWildcard: true, Family: models.SocketDual},
	})
	for _, exposure := range result.ExposedServices {
		if exposure.Service.Port != 22 {
			t.Errorf("baseline exposes %d: %+v", exposure.Service.Port, exposure)
		}
		if exposure.Certainty != models.CertaintyDefinite {
			t.Errorf("SSH reachability must be definite despite the rate limit: %+v", exposure)
		}
	}
	if len(result.ExposedServices) != 2 {
		t.Fatalf("SSH must stay reachable over IPv4 and IPv6: %+v", result.ExposedServices)
	}
}

func TestBaselineKeepsDetectedSSHPortAndListsServices(t *testing.T) {
	result := &models.AnalysisResult{Services: []models.ListeningService{
		{Protocol: models.ProtoTCP, Address: "0.0.0.0", Port: 2222, Process: "sshd", IsWildcard: true, Family: models.SocketIPv4},
		{Protocol: models.ProtoTCP, Address: "::", Port: 443, Process: "nginx", IsWildcard: true, IsIPv6: true, Family: models.SocketIPv6},
		{Protocol: models.ProtoTCP, Address: "127.0.0.1", Port: 5432, Process: "postgres", Status: models.ServiceLocalhost, Family: models.SocketIPv4},
	}}
	b := Generate(FromResult(result))
	if !strings.Contains(b.IPv4, "--dport 2222 -m conntrack --ctstate NEW -j ACCEPT") || strings.Contains(b.IPv4, "--dport 22 ") {
		t.Fatalf("detected SSH port must replace 22:\n%s", b.IPv4)
	}
	if !strings.Contains(b.IPv6, "# -A INPUT -p tcp -m tcp --dport 443") || strings.Contains(b.IPv4, "--dport 443") {
		t.Fatalf("IPv6-only listener must be suggested for IPv6 only:\n%s\n%s", b.IPv4, b.IPv6)
	}
	if strings.Contains(b.IPv4, "5432") {
		t.Fatalf("loopback listener must not be suggested:\n%s", b.IPv4)
	}
	if !strings.Contains(strings.Join(b.Notes, "\n"), "detected from the listening sshd") {
		t.Fatalf("notes must say where the SSH port came from: %v", b.Notes)
	}
}

func TestBaselineForDockerHostsRestrictsPublishedPorts(t *testing.T) {
	result := &models.AnalysisResult{
		IPv4Rules: mustParse(t, "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:DOCKER-USER - [0:0]\n:DOCKER - [0:0]\nCOMMIT\n"),
		PublishedPorts: []models.PublishedPort{{
			IPVersion: models.IPv4, Protocol: models.ProtoTCP, HostPort: 8080,
			ContainerAddr: "172.17.0.2", ContainerPort: 80, ForwardScope: models.ScopeExposed,
		}},
	}
	b := Generate(FromResult(result))
	if !strings.Contains(b.IPv4, ":DOCKER-USER - [0:0]") || !strings.Contains(b.IPv4, "-A DOCKER-USER -j RETURN") {
		t.Fatalf("Docker baseline must manage DOCKER-USER:\n%s", b.IPv4)
	}
	if !strings.Contains(b.IPv4, "--ctorigdstport 8080 --ctdir ORIGINAL -j DROP") {
		t.Fatalf("published port must be suggested with conntrack:\n%s", b.IPv4)
	}
	if !strings.Contains(strings.Join(b.Notes, "\n"), "always use --noflush") {
		t.Fatalf("Docker notes must warn about full restores: %v", b.Notes)
	}
}

func mustParse(t *testing.T, data string) *models.Ruleset {
	t.Helper()
	rs, err := parser.Parse(data, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func analyzeBaseline(t *testing.T, b models.Baseline) *models.AnalysisResult {
	t.Helper()
	v4, err := parser.Parse(b.IPv4, models.IPv4)
	if err != nil {
		t.Fatalf("IPv4 baseline does not parse: %v\n%s", err, b.IPv4)
	}
	v6, err := parser.Parse(b.IPv6, models.IPv6)
	if err != nil {
		t.Fatalf("IPv6 baseline does not parse: %v\n%s", err, b.IPv6)
	}
	result := analyzer.Analyze(v4, v6)
	analyzer.CrossReferenceServices(result, []models.ListeningService{
		{Protocol: models.ProtoTCP, Address: "*", Port: 22, Process: "sshd", IsWildcard: true, Family: models.SocketDual},
	})
	return result
}

// Audit B14: the tool must not object to the configuration it recommends.
func TestBaselineGetsNoHighFindingFromTheAnalyzer(t *testing.T) {
	result := analyzeBaseline(t, Generate(Options{}))
	for _, finding := range result.EffectiveIssues {
		if finding.Severity > models.SeverityInfo {
			t.Errorf("baseline triggers %s: %s", finding.Code, finding.Title)
		}
	}
	for _, exposure := range result.ExposedServices {
		if exposure.Severity > models.SeverityMedium || exposure.Condition != "rate limit" {
			t.Errorf("SSH of the baseline is rate limited per source: %+v", exposure)
		}
	}
	if len(result.UnusedRules) != 0 || len(result.ShadowedRules) != 0 {
		t.Errorf("baseline has unused or shadowed rules: %+v %+v", result.UnusedRules, result.ShadowedRules)
	}
}

// Audit D3: "-F INPUT" must not cut off the chains of other programs.
func TestBaselineKeepsJumpsToChainsOfOtherPrograms(t *testing.T) {
	rs := mustParse(t, "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:LIBVIRT_INP - [0:0]\n:f2b-sshd - [0:0]\n"+
		"-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n-A INPUT -j LIBVIRT_INP\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"+
		"-A LIBVIRT_INP -i virbr0 -p udp -m udp --dport 67 -j ACCEPT\n-A f2b-sshd -s 198.51.100.7/32 -j REJECT --reject-with icmp-port-unreachable\n"+
		"-A f2b-sshd -j RETURN\nCOMMIT\n")
	b := Generate(FromResult(&models.AnalysisResult{IPv4Rules: rs}))
	jail := strings.Index(b.IPv4, "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd")
	accept := strings.Index(b.IPv4, "--dport 22 -m conntrack --ctstate NEW -j ACCEPT")
	if jail < 0 || accept < 0 || jail > accept || !strings.Contains(b.IPv4, "-A INPUT -j LIBVIRT_INP") {
		t.Fatalf("jumps were lost or follow the SSH rule:\n%s", b.IPv4)
	}
	if strings.Contains(b.IPv6, "f2b-sshd") {
		t.Fatalf("IPv4 jumps must not appear in the IPv6 file:\n%s", b.IPv6)
	}
	if notes := strings.Join(b.Notes, "\n"); !strings.Contains(notes, "f2b-sshd, LIBVIRT_INP") {
		t.Fatalf("notes must name the kept chains: %s", notes)
	}
	// The result still parses and the kept jail is in front of the accept.
	if _, err := parser.Parse(strings.Replace(b.IPv4, ":OUTPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]\n:LIBVIRT_INP - [0:0]\n:f2b-sshd - [0:0]", 1), models.IPv4); err != nil {
		t.Fatalf("baseline with kept jumps does not parse: %v", err)
	}
}

func TestBaselineWarnsOnHostsManagedByUFW(t *testing.T) {
	rs := mustParse(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:ufw-before-input - [0:0]\n:ufw-user-input - [0:0]\n"+
		"-A INPUT -j ufw-before-input\n-A ufw-before-input -j ufw-user-input\n-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n")
	b := Generate(FromResult(&models.AnalysisResult{IPv4Rules: rs}))
	if strings.Contains(b.IPv4, "ufw-") {
		t.Fatalf("the chains of ufw hold its whole policy and must not be kept:\n%s", b.IPv4)
	}
	if notes := strings.Join(b.Notes, "\n"); !strings.Contains(notes, "ufw manages this firewall") {
		t.Fatalf("notes must advise against the baseline: %s", notes)
	}
}

func TestBaselineKeepsWhatItCannotKnow(t *testing.T) {
	// A router: FORWARD policy and rules are its own.
	router := mustParse(t, "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -o eth0 -j MASQUERADE\nCOMMIT\n"+
		"*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A FORWARD -i eth1 -o eth0 -j ACCEPT\nCOMMIT\n")
	b := Generate(FromResult(&models.AnalysisResult{IPv4Rules: router}))
	if !strings.Contains(b.IPv4, ":FORWARD ACCEPT [0:0]") || !strings.Contains(b.IPv6, ":FORWARD DROP [0:0]") {
		t.Fatalf("the FORWARD policy of a router must stay, for its family only:\n%s\n%s", b.IPv4, b.IPv6)
	}
	if notes := strings.Join(b.Notes, "\n"); !strings.Contains(notes, "IPv4 FORWARD keeps its policy (ACCEPT)") {
		t.Fatalf("notes must say that FORWARD is left alone: %s", notes)
	}

	// A Docker host: the rules of DOCKER-USER are replaced, so they are shown.
	docker := mustParse(t, "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:DOCKER-USER - [0:0]\n:DOCKER - [0:0]\n"+
		"-A DOCKER-USER -s 198.51.100.7/32 -j DROP\n-A DOCKER-USER -j RETURN\nCOMMIT\n")
	b = Generate(FromResult(&models.AnalysisResult{IPv4Rules: docker}))
	if !strings.Contains(b.IPv4, "# -A DOCKER-USER -s 198.51.100.7/32 -j DROP") || !strings.Contains(b.IPv4, ":FORWARD DROP [0:0]") {
		t.Fatalf("present DOCKER-USER rules must be listed as comments:\n%s", b.IPv4)
	}

	// A socket that only systemd holds may be sshd.
	b = Generate(FromResult(&models.AnalysisResult{Services: []models.ListeningService{
		{Protocol: models.ProtoTCP, Address: "*", Port: 2222, Process: "systemd", Processes: []string{"systemd"}, IsWildcard: true, Family: models.SocketDual},
		{Protocol: models.ProtoTCP, Address: "*", Port: 2022, Process: "sshd", Processes: []string{"systemd", "sshd"}, IsWildcard: true, Family: models.SocketDual},
	}}))
	if !strings.Contains(b.IPv4, "--dport 2022 -m conntrack --ctstate NEW -j ACCEPT") {
		t.Fatalf("a socket-activated sshd was not recognized:\n%s", b.IPv4)
	}
	if notes := strings.Join(b.Notes, "\n"); !strings.Contains(notes, "systemd holds TCP port 2222") {
		t.Fatalf("notes must mention the socket that only systemd holds: %s", notes)
	}
}

// The baseline is loaded by the real iptables-restore in a new network
// namespace. This needs unprivileged user namespaces and the iptables tools;
// the test is skipped where they are not available.
func TestBaselineLoadsWithRealIptablesRestore(t *testing.T) {
	if testing.Short() {
		t.Skip("runs external tools")
	}
	for _, tool := range []string{"unshare", "iptables", "iptables-restore", "ip6tables-restore", "iptables-save"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	if err := exec.Command("unshare", "-rn", "iptables", "-S").Run(); err != nil {
		t.Skipf("no network namespace with iptables is available: %v", err)
	}
	present := "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:f2b-sshd - [0:0]\n" +
		"-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n-A INPUT -p tcp -m tcp --dport 9999 -j ACCEPT\n" +
		"-A f2b-sshd -s 198.51.100.7/32 -j REJECT --reject-with icmp-port-unreachable\n-A f2b-sshd -j RETURN\nCOMMIT\n"
	b := Generate(FromResult(&models.AnalysisResult{IPv4Rules: mustParse(t, present)}))
	dir := t.TempDir()
	for name, data := range map[string]string{"present.v4": present, "baseline.v4": b.IPv4, "baseline.v6": b.IPv6} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := "set -e; cd \"$1\"; iptables-restore < present.v4; iptables-restore --noflush < baseline.v4; " +
		"ip6tables-restore --noflush < baseline.v6; iptables-save"
	out, err := exec.Command("unshare", "-rn", "sh", "-c", script, "sh", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("the baseline does not load: %v\n%s", err, out)
	}
	saved := string(out)
	for _, wanted := range []string{":INPUT DROP", "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd", "-A f2b-sshd -s 198.51.100.7/32"} {
		if !strings.Contains(saved, wanted) {
			t.Errorf("after the baseline, the rules lack %q:\n%s", wanted, saved)
		}
	}
	if strings.Contains(saved, "--dport 9999") {
		t.Errorf("the old INPUT rules were not replaced:\n%s", saved)
	}
	// What the kernel now holds must satisfy the analyzer as well.
	loaded, err := parser.Parse(saved, models.IPv4)
	if err != nil {
		t.Fatalf("saved rules do not parse: %v", err)
	}
	for _, finding := range analyzer.CheckEffectiveness(loaded) {
		if finding.Severity > models.SeverityInfo {
			t.Errorf("loaded baseline triggers %s: %s", finding.Code, finding.Detail)
		}
	}
}
