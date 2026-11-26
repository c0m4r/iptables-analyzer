package analyzer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The tests in this file follow a packet through nat/PREROUTING. What they
// expect for REDIRECT and DNAT was observed with real packets between network
// namespaces; kernel_scenarios_linux_test.go repeats those observations when the tools
// are available.

// natRules builds a ruleset from rules of nat/PREROUTING and rules of the
// filter table. INPUT and FORWARD deny by default.
func natRules(nat []string, filter ...string) string {
	return "*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n" +
		strings.Join(nat, "\n") + "\nCOMMIT\n" +
		"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n" +
		strings.Join(filter, "\n") + "\nCOMMIT\n"
}

// openPorts returns the entries for one port.
func openPorts(result *models.AnalysisResult, protocol models.Protocol, port int) []models.OpenPort {
	var found []models.OpenPort
	for _, open := range result.OpenPorts {
		if open.Protocol == protocol && open.First <= port && port <= open.Last {
			found = append(found, open)
		}
	}
	return found
}

func published(result *models.AnalysisResult, protocol models.Protocol, port int) []models.PublishedPort {
	var found []models.PublishedPort
	for _, mapping := range result.PublishedPorts {
		if mapping.Protocol == protocol && mapping.HostPort <= port && port <= max(mapping.HostPort, mapping.HostPortEnd) {
			found = append(found, mapping)
		}
	}
	return found
}

func incomplete(result *models.AnalysisResult) []string {
	var messages []string
	for _, diagnostic := range result.Diagnostics {
		messages = append(messages, diagnostic.Area+": "+diagnostic.Message)
	}
	return messages
}

const listenerOn8080 = "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"proxy\",pid=7,fd=3))"

// Audit A6: a redirected port reaches the listener on the new port, and INPUT
// judges the packet by the new port.
func TestRedirectIsFollowedToTheLocalPort(t *testing.T) {
	rules := natRules([]string{"-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080"},
		"-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT")
	result := analyzeWithServices(t, rules, listenerOn8080)

	entries := openPorts(result, models.ProtoTCP, 80)
	if len(entries) != 1 {
		t.Fatalf("port 80: want one entry, got %+v", entries)
	}
	redirected := entries[0]
	if !redirected.Redirected() || redirected.LocalPort != 8080 || redirected.LocalPortEnd != 8080 || redirected.NATRule == nil ||
		redirected.Scope != models.ScopeExposed || redirected.Certainty != models.CertaintyDefinite {
		t.Errorf("port 80 must be open to any source through local port 8080: %+v", redirected)
	}
	if redirected.Rule == nil || redirected.Rule.DstPort != "8080" {
		t.Errorf("the rule for the new port accepts the redirected packet: %+v", redirected.Rule)
	}
	if direct := openPorts(result, models.ProtoTCP, 8080); len(direct) != 1 || direct[0].Redirected() {
		t.Errorf("port 8080 is open by itself too: %+v", direct)
	}

	var ways []int
	for _, finding := range result.ExposedServices {
		if finding.Service.Port != 8080 || finding.Scope != models.ScopeExposed {
			t.Errorf("unexpected finding: %+v", finding)
		}
		ways = append(ways, finding.ViaPort)
	}
	if fmt.Sprint(ways) != "[0 80]" {
		t.Errorf("the listener is reached at its own port and through port 80, got %v", ways)
	}
	if status := serviceStatus(t, result, 8080); status != models.ServiceReachable {
		t.Errorf("status %s", status)
	}
	if notes := incomplete(result); len(notes) != 0 {
		t.Errorf("a REDIRECT is followed and needs no note: %v", notes)
	}
	if len(result.UnusedRules) != 0 {
		t.Errorf("both ports are in use: %+v", result.UnusedRules)
	}
}

// A rule for the old port does not see the redirected packet.
func TestRedirectedPacketIsJudgedByTheNewPort(t *testing.T) {
	rules := natRules([]string{"-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080"},
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT")
	result := analyzeWithServices(t, rules, listenerOn8080)
	if entries := openPorts(result, models.ProtoTCP, 80); len(entries) != 0 {
		t.Errorf("INPUT sees port 8080, which no rule accepts: %+v", entries)
	}
	if status := serviceStatus(t, result, 8080); status != models.ServiceFiltered {
		t.Errorf("the listener must be filtered, got %s", status)
	}
}

// A rule can accept the redirected packets alone by their original port.
func TestRedirectAcceptedByOriginalPort(t *testing.T) {
	rules := natRules([]string{"-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080"},
		"-A INPUT -p tcp -m conntrack --ctorigdstport 80 -j ACCEPT")
	result := analyzeWithServices(t, rules, listenerOn8080)
	if entries := openPorts(result, models.ProtoTCP, 80); len(entries) != 1 || entries[0].LocalPort != 8080 {
		t.Errorf("port 80 is open through the redirect: %+v", entries)
	}
	if entries := openPorts(result, models.ProtoTCP, 8080); len(entries) != 0 {
		t.Errorf("a packet sent to port 8080 has no original port 80: %+v", entries)
	}
	if len(result.ExposedServices) != 1 || result.ExposedServices[0].ViaPort != 80 {
		t.Errorf("the listener is reached through port 80 only: %+v", result.ExposedServices)
	}
}

// Only the sources that the rule names are redirected; the others arrive at
// the port itself.
func TestRedirectForSomeSources(t *testing.T) {
	rules := natRules([]string{"-A PREROUTING -s 10.0.0.0/8 -p tcp -m tcp --dport 9000 -j REDIRECT --to-ports 3128"},
		"-A INPUT -p tcp -m tcp --dport 9000 -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 3128 -j ACCEPT")
	result := Analyze(mustParse(t, rules, models.IPv4), nil)
	entries := openPorts(result, models.ProtoTCP, 9000)
	if len(entries) != 2 {
		t.Fatalf("want the straight way and the redirect, got %+v", entries)
	}
	if entries[0].Redirected() || entries[0].Scope != models.ScopeExposed {
		t.Errorf("sources outside 10.0.0.0/8 arrive at port 9000: %+v", entries[0])
	}
	if !entries[1].Redirected() || entries[1].LocalPort != 3128 || entries[1].Scope != models.ScopeLocalnet {
		t.Errorf("10.0.0.0/8 arrives at port 3128: %+v", entries[1])
	}
}

// A redirect without a port and a redirect of every port keep the port.
func TestRedirectWithoutPortKeepsThePort(t *testing.T) {
	rules := natRules([]string{"-A PREROUTING -i eth1 -p tcp -j REDIRECT"},
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT")
	result := Analyze(mustParse(t, rules, models.IPv4), nil)
	for _, open := range result.OpenPorts {
		if open.Redirected() {
			t.Errorf("the port and the host stay the same: %+v", open)
		}
	}
	if entries := openPorts(result, models.ProtoTCP, 22); len(entries) == 0 {
		t.Error("port 22 is open")
	}
}

// A DNAT to the address that it matches changes the port only: INPUT decides.
func TestDNATToOwnAddressIsLocal(t *testing.T) {
	rules := natRules([]string{"-A PREROUTING -d 192.0.2.10/32 -p tcp -m tcp --dport 2222 -j DNAT --to-destination 192.0.2.10:22"},
		"-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate DNAT -j ACCEPT")
	result := Analyze(mustParse(t, rules, models.IPv4), nil)
	if len(result.PublishedPorts) != 0 {
		t.Errorf("the packet stays on this host: %+v", result.PublishedPorts)
	}
	entries := openPorts(result, models.ProtoTCP, 2222)
	if len(entries) != 1 || entries[0].Address != "192.0.2.10" || entries[0].LocalPort != 22 || entries[0].LocalAddr != "192.0.2.10" ||
		entries[0].Scope != models.ScopeExposed {
		t.Fatalf("port 2222 of 192.0.2.10 is open through local port 22: %+v", entries)
	}
	// A packet sent to port 22 itself is not translated, so the rule that
	// asks for the DNAT state refuses it.
	if entries := openPorts(result, models.ProtoTCP, 22); len(entries) != 0 {
		t.Errorf("port 22 is not open by itself: %+v", entries)
	}
}

// Packets for a loopback address are delivered only with route_localnet.
func TestDNATToLoopbackDependsOnRouteLocalnet(t *testing.T) {
	rules := natRules([]string{"-A PREROUTING -p tcp -m tcp --dport 2323 -j DNAT --to-destination 127.0.0.1:22"},
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT")
	result := Analyze(mustParse(t, rules, models.IPv4), nil)
	entries := openPorts(result, models.ProtoTCP, 2323)
	if len(entries) != 1 || entries[0].Certainty != models.CertaintyPossible || entries[0].LocalAddr != "127.0.0.1" {
		t.Fatalf("saved rules do not tell route_localnet, so the way is possible: %+v", entries)
	}
	if len(result.PublishedPorts) != 0 {
		t.Errorf("a loopback address is not another host: %+v", result.PublishedPorts)
	}

	v6 := natRules([]string{"-A PREROUTING -p tcp -m tcp --dport 2323 -j DNAT --to-destination [::1]:22"},
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT")
	result = Analyze(nil, mustParse(t, v6, models.IPv6))
	if entries := openPorts(result, models.ProtoTCP, 2323); len(entries) != 0 {
		t.Errorf("IPv6 has no route_localnet: %+v", entries)
	}
}

// kubeRules builds what kube-proxy writes for services with a NodePort: the
// port is matched in KUBE-NODEPORTS, and the DNAT rules are three chains on.
func kubeRules(services int) string {
	var chains, rules strings.Builder
	chains.WriteString(":KUBE-SERVICES - [0:0]\n:KUBE-NODEPORTS - [0:0]\n:KUBE-MARK-MASQ - [0:0]\n:KUBE-POSTROUTING - [0:0]\n")
	rules.WriteString("-A PREROUTING -m comment --comment \"kubernetes service portals\" -j KUBE-SERVICES\n")
	rules.WriteString("-A OUTPUT -m comment --comment \"kubernetes service portals\" -j KUBE-SERVICES\n")
	rules.WriteString("-A POSTROUTING -m comment --comment \"kubernetes postrouting rules\" -j KUBE-POSTROUTING\n")
	rules.WriteString("-A KUBE-MARK-MASQ -j MARK --set-xmark 0x4000/0x4000\n")
	rules.WriteString("-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN\n")
	rules.WriteString("-A KUBE-POSTROUTING -j MARK --set-xmark 0x4000/0x0\n")
	rules.WriteString("-A KUBE-POSTROUTING -m comment --comment \"kubernetes service traffic requiring SNAT\" -j MASQUERADE --random-fully\n")
	for i := 0; i < services; i++ {
		id := fmt.Sprintf("%016X", 0xA5A5000000000000+uint64(i))
		fmt.Fprintf(&chains, ":KUBE-EXT-%s - [0:0]\n:KUBE-SVC-%s - [0:0]\n", id, id)
		port, cluster := 30000+i, fmt.Sprintf("10.96.%d.%d", i/250, 1+i%250)
		fmt.Fprintf(&rules, "-A KUBE-NODEPORTS -p tcp -m comment --comment \"default/svc%d\" -m tcp --dport %d -j KUBE-EXT-%s\n", i, port, id)
		fmt.Fprintf(&rules, "-A KUBE-EXT-%s -m comment --comment \"masquerade traffic for default/svc%d external destinations\" -j KUBE-MARK-MASQ\n", id, i)
		fmt.Fprintf(&rules, "-A KUBE-EXT-%s -j KUBE-SVC-%s\n", id, id)
		fmt.Fprintf(&rules, "-A KUBE-SERVICES -d %s/32 -p tcp -m comment --comment \"default/svc%d cluster IP\" -m tcp --dport 80 -j KUBE-SVC-%s\n", cluster, i, id)
		fmt.Fprintf(&rules, "-A KUBE-SVC-%s ! -s 10.244.0.0/16 -d %s/32 -p tcp -m comment --comment \"default/svc%d cluster IP\" -m tcp --dport 80 -j KUBE-MARK-MASQ\n", id, cluster, i)
		for endpoint, probability := range []string{"0.33333333349", "0.50000000000", ""} {
			sep := fmt.Sprintf("%015X%d", 0xB5B000000000000+uint64(i), endpoint)
			pod := fmt.Sprintf("10.244.%d.%d", 1+endpoint, 2+i%250)
			fmt.Fprintf(&chains, ":KUBE-SEP-%s - [0:0]\n", sep)
			share := ""
			if probability != "" {
				share = " -m statistic --mode random --probability " + probability
			}
			fmt.Fprintf(&rules, "-A KUBE-SVC-%s -m comment --comment \"default/svc%d -> %s:8080\"%s -j KUBE-SEP-%s\n", id, i, pod, share, sep)
			fmt.Fprintf(&rules, "-A KUBE-SEP-%s -s %s/32 -m comment --comment \"default/svc%d\" -j KUBE-MARK-MASQ\n", sep, pod, i)
			fmt.Fprintf(&rules, "-A KUBE-SEP-%s -p tcp -m comment --comment \"default/svc%d\" -m tcp -j DNAT --to-destination %s:8080\n", sep, i, pod)
		}
	}
	rules.WriteString("-A KUBE-SERVICES -m comment --comment \"kubernetes service nodeports; NOTE: this must be the last rule in this chain\" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS\n")
	return "*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n" +
		chains.String() + rules.String() + "COMMIT\n" +
		"*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:KUBE-FORWARD - [0:0]\n" +
		"-A FORWARD -m comment --comment \"kubernetes forwarding rules\" -j KUBE-FORWARD\n" +
		"-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP\n" +
		"-A KUBE-FORWARD -m comment --comment \"kubernetes forwarding rules\" -m mark --mark 0x4000/0x4000 -j ACCEPT\n" +
		"-A KUBE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\nCOMMIT\n"
}

// Audit A5: a NodePort is followed to the DNAT rules of its endpoints.
func TestKubeNodePortsAreFollowedThroughServiceChains(t *testing.T) {
	result := Analyze(mustParse(t, kubeRules(3), models.IPv4), nil)
	if notes := incomplete(result); len(notes) != 0 {
		t.Fatalf("every translation can be followed: %v", notes)
	}
	for port := 30000; port < 30003; port++ {
		mappings := published(result, models.ProtoTCP, port)
		if len(mappings) != 3 {
			t.Fatalf("port %d: want its three endpoints, got %+v", port, mappings)
		}
		for _, mapping := range mappings {
			if mapping.HostAddr != "" || mapping.ContainerPort != 8080 || !strings.HasPrefix(mapping.ContainerAddr, "10.244.") ||
				mapping.ForwardScope != models.ScopeExposed || mapping.Certainty != models.CertaintyDefinite {
				t.Errorf("port %d: %+v", port, mapping)
			}
		}
	}
	if len(result.PublishedPorts) != 9 {
		t.Errorf("only the node ports are translated for the addresses of the node: %d mappings", len(result.PublishedPorts))
	}
	if len(result.Notes) != 1 || !strings.Contains(result.Notes[0], "3 cluster IP addresses") {
		t.Errorf("the cluster addresses that were left out must be named: %v", result.Notes)
	}
	for _, open := range result.OpenPorts {
		if open.First <= 30000 && 30000 <= open.Last && !open.Unnamed {
			t.Errorf("a node port goes to a pod, not to INPUT: %+v", open)
		}
	}
}

// The number of services must not change how the result reads.
func TestManyKubeServicesStayWithinTheBound(t *testing.T) {
	if testing.Short() {
		t.Skip("large ruleset")
	}
	result := Analyze(mustParse(t, kubeRules(200), models.IPv4), nil)
	if notes := incomplete(result); len(notes) != 0 {
		t.Fatalf("200 services: %v", notes)
	}
	if len(result.PublishedPorts) != 600 {
		t.Errorf("want 600 endpoints, got %d", len(result.PublishedPorts))
	}
}

// An address of a load balancer is evaluated by itself: the other addresses
// of the node keep the port.
func TestNamedDestinationIsEvaluatedByItself(t *testing.T) {
	rules := natRules([]string{
		":KUBE-SERVICES - [0:0]", ":KUBE-EXT-AAAA - [0:0]",
		"-A PREROUTING -j KUBE-SERVICES",
		"-A KUBE-SERVICES -d 203.0.113.50/32 -p tcp -m comment --comment \"default/web loadbalancer IP\" -m tcp --dport 80 -j KUBE-EXT-AAAA",
		"-A KUBE-EXT-AAAA -p tcp -m tcp -j DNAT --to-destination 10.244.1.7:8080",
	}, "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT", "-A FORWARD -d 10.244.0.0/16 -j ACCEPT")
	result := Analyze(mustParse(t, rules, models.IPv4), nil)
	mappings := published(result, models.ProtoTCP, 80)
	if len(mappings) != 1 || mappings[0].HostAddr != "203.0.113.50" || mappings[0].ContainerAddr != "10.244.1.7" ||
		mappings[0].ForwardScope != models.ScopeExposed || mappings[0].Certainty != models.CertaintyDefinite {
		t.Fatalf("port 80 of 203.0.113.50 goes to the pod: %+v", mappings)
	}
	entries := openPorts(result, models.ProtoTCP, 80)
	if len(entries) != 1 || entries[0].Redirected() || entries[0].Address != "" || entries[0].Certainty != models.CertaintyDefinite {
		t.Errorf("port 80 of the other addresses is open in INPUT: %+v", entries)
	}
}

// A port forward that names no port sends every port; FORWARD decides which
// of them arrive.
func TestForwardOfEveryPortIsJudgedByForward(t *testing.T) {
	rules := natRules([]string{"-A PREROUTING -i eth0 -j DNAT --to-destination 10.0.0.5"},
		"-A INPUT -i eth1 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-A FORWARD -d 10.0.0.5/32 -p tcp -m multiport --dports 80,443 -j ACCEPT")
	result := Analyze(mustParse(t, rules, models.IPv4), nil)
	if notes := incomplete(result); len(notes) != 0 {
		t.Fatalf("a DNAT without a port is followed: %v", notes)
	}
	var ports []string
	for _, mapping := range result.PublishedPorts {
		if mapping.ForwardScope == "" {
			continue
		}
		ports = append(ports, fmt.Sprintf("%s/%d", mapping.Protocol, mapping.HostPort))
		if mapping.ContainerAddr != "10.0.0.5" || mapping.ContainerPort != mapping.HostPort || strings.Join(mapping.Interfaces, ",") != "eth0" {
			t.Errorf("the port stays and the way exists on eth0 only: %+v", mapping)
		}
	}
	if fmt.Sprint(ports) != "[tcp/80 tcp/443]" {
		t.Errorf("FORWARD accepts ports 80 and 443 only, got %v", ports)
	}
	// Port 22 arrives at INPUT on eth1 only: eth0 sends it to 10.0.0.5.
	entries := openPorts(result, models.ProtoTCP, 22)
	if len(entries) != 1 || strings.Join(entries[0].Interfaces, ",") != "eth1" {
		t.Errorf("port 22: %+v", entries)
	}
}

func TestDNATWithoutPortAndProtocolIsFollowed(t *testing.T) {
	rs := mustParse(t, "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j DNAT --to-destination 172.17.0.2\nCOMMIT\n", models.IPv4)
	result := Analyze(rs, nil)
	if notes := incomplete(result); len(notes) != 0 {
		t.Fatalf("the translation is followed: %v", notes)
	}
	groups := GroupPublishedPorts(result.PublishedPorts)
	if len(groups) != 2 || groups[0].HostPort != 1 || groups[0].HostPortEnd != 65535 || groups[0].ContainerPortEnd != 65535 ||
		groups[0].Protocol != models.ProtoTCP || groups[1].Protocol != models.ProtoUDP {
		t.Fatalf("every port of both protocols goes to 172.17.0.2: %+v", groups)
	}
}

func TestTranslationsThatAreNotFollowedGiveNotes(t *testing.T) {
	rs := mustParse(t, "*nat\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"+
		"-A PREROUTING -d 198.51.100.0/24 -j NETMAP --to 10.1.0.0/24\n"+
		"-A PREROUTING -p tcp --dport 81 -j DNAT --to-destination bad:target:1\n"+
		"-A OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:9050\nCOMMIT\n", models.IPv4)
	notes := incomplete(Analyze(rs, nil))
	if len(notes) != 2 || !strings.HasPrefix(notes[0], "nat: ") || !strings.Contains(notes[0], "NETMAP") ||
		!strings.HasPrefix(notes[1], "docker: ") || !strings.Contains(notes[1], "rule #2") {
		t.Fatalf("want one note for NETMAP and one for the unreadable target, and none for OUTPUT: %v", notes)
	}
}

// Docker's ports go to containers; the survey of INPUT does not list them.
func TestTranslatedPortsAreNotOpenPortsOfTheHost(t *testing.T) {
	result := Analyze(parseRules(t, docker29(t), models.IPv4), nil)
	for _, port := range []int{8080, 8091, 8443, 9000, 9002} {
		if len(published(result, models.ProtoTCP, port)) != 1 {
			t.Errorf("port %d is published", port)
		}
		if entries := openPorts(result, models.ProtoTCP, port); len(entries) != 0 {
			t.Errorf("port %d goes to a container for every local address, INPUT does not see it: %+v", port, entries)
		}
	}
	// Port 8082 is published for one address; the other addresses keep it.
	if entries := openPorts(result, models.ProtoTCP, 8082); len(entries) != 1 || !entries[0].Unnamed {
		t.Errorf("port 8082 of the other addresses arrives at INPUT like any port: %+v", entries)
	}
}

// A rule that names an address of the host matches packets for that address.
// The addresses of the interfaces arrive as "address/length"; the host part
// must stay.
func TestRuleForOwnAddressMatchesOnLiveHost(t *testing.T) {
	rules := filterRules("-A INPUT -d 192.0.2.10/32 -p tcp -m tcp --dport 22 -j ACCEPT")
	host := &models.HostContext{Interfaces: []models.HostInterface{
		{Name: "lo", Addrs: []string{"127.0.0.1/8"}, Up: true},
		{Name: "eth0", Addrs: []string{"192.0.2.10/24"}, Up: true},
	}}
	result := AnalyzeHost(mustParse(t, rules, models.IPv4), nil, host)
	entries := openPorts(result, models.ProtoTCP, 22)
	if len(entries) != 1 || entries[0].Scope != models.ScopeExposed || entries[0].Certainty != models.CertaintyDefinite {
		t.Fatalf("port 22 of the only address of the host is open: %+v", entries)
	}
	trace := Trace(mustParse(t, rules, models.IPv4), host, models.Packet{
		Protocol: models.ProtoTCP, Source: "203.0.113.5", Destination: "192.0.2.10", Port: 22, In: "eth0", State: "NEW"})
	if trace.Verdict != "ACCEPT" || trace.Delivery != "local" || !trace.Certain {
		t.Errorf("the packet is for this host: %+v", trace)
	}
}

// The packet of --trace is read for both address families. TCP and UDP over
// IPv6 were refused once: only the ICMP protocols belong to one family.
func TestParsePacketReadsBothFamilies(t *testing.T) {
	for spec, want := range map[string]models.Packet{
		"tcp 203.0.113.5 -> :22 in eth0": {Protocol: "tcp", Source: "203.0.113.5", Port: 22, In: "eth0", State: "NEW"},
		"udp [2001:db8::5]:40000 -> [2001:db8::1]:53": {Protocol: "udp", Source: "2001:db8::5", SourcePort: 40000,
			Destination: "2001:db8::1", Port: 53, State: "NEW"},
		"tcp 2001:db8::5 -> :443 in eth0 state established": {Protocol: "tcp", Source: "2001:db8::5", Port: 443, In: "eth0", State: "ESTABLISHED"},
		"icmp 203.0.113.5 type 8":                           {Protocol: "icmp", Source: "203.0.113.5", State: "NEW", ICMPType: "8"},
		"icmpv6 2001:db8::5 type 128":                       {Protocol: "ipv6-icmp", Source: "2001:db8::5", State: "NEW", ICMPType: "128"},
		"tcp 10.1.2.3:5555 to 192.168.1.50:443 in eth1 out eth0": {Protocol: "tcp", Source: "10.1.2.3", SourcePort: 5555,
			Destination: "192.168.1.50", Port: 443, In: "eth1", Out: "eth0", State: "NEW"},
	} {
		got, err := ParsePacket(spec)
		if err != nil || got != want {
			t.Errorf("ParsePacket(%q) = %+v, %v; want %+v", spec, got, err, want)
		}
	}
	for _, spec := range []string{
		"", "tcp", "tcp 203.0.113.5", "sctp 203.0.113.5 -> :22", "tcp 203.0.113.5 -> :0", "tcp 203.0.113.5 -> :70000",
		"icmp 2001:db8::5 type 8", "icmpv6 203.0.113.5 type 128", "icmp 203.0.113.5 -> :22",
		"tcp 203.0.113.5 -> [2001:db8::1]:22", "tcp 203.0.113.5 -> :22 in", "tcp 203.0.113.5 -> :22 in eth0/1",
		"tcp 203.0.113.5 -> :22 in averyveryverylongname", "tcp 203.0.113.5 -> :22 state OPEN", "tcp fe80::1%eth0 -> :22",
	} {
		if packet, err := ParsePacket(spec); err == nil {
			t.Errorf("ParsePacket(%q) must be refused, got %+v", spec, packet)
		}
	}

	// A trace over IPv6 rules gives a verdict.
	rs := mustParse(t, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"+
		"-A INPUT -s 2001:db8:1::/48 -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n", models.IPv6)
	for source, want := range map[string]string{"2001:db8:1::5": "ACCEPT", "2001:db8:2::5": "DROP"} {
		packet, err := ParsePacket("tcp " + source + " -> :22 in eth0")
		if err != nil {
			t.Fatal(err)
		}
		if trace := Trace(rs, nil, packet); trace.Verdict != want || !trace.Certain || trace.Family != 6 {
			t.Errorf("%s: %s (certain %v, family %d), want %s", source, trace.Verdict, trace.Certain, trace.Family, want)
		}
	}
}
