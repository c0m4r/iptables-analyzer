package baseline

import (
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
