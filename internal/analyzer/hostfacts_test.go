package analyzer

import (
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// With the contents of an ipset, a match against it is decided like -s.
func TestKnownIPSetIsEvaluated(t *testing.T) {
	rules := filterRules(
		"-A INPUT -m set --match-set banned src -j DROP",
		"-A INPUT -p tcp -m tcp --dport 22 -m set --match-set trusted src -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 443 -m set ! --match-set banned src -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 8080 -m set --match-set web src,dst -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 9090 -m set --match-set all src -j ACCEPT")
	host := &models.HostContext{IPSets: map[string]models.IPSet{
		"trusted": {Name: "trusted", Type: "hash:net", Family: "inet", Addresses: true, Entries: []string{"10.0.0.0/8", "198.51.100.7"}, Excluded: []string{"10.9.0.0/16"}},
		"banned":  {Name: "banned", Type: "hash:ip", Family: "inet", Addresses: true, Entries: []string{"203.0.113.66", "203.0.113.70-203.0.113.79"}},
		"web":     {Name: "web", Type: "hash:ip,port", Family: "inet"},
		"all":     {Name: "all", Type: "list:set", Members: []string{"trusted", "banned"}},
	}}
	rs := mustParse(t, rules, models.IPv4)
	result := AnalyzeHost(rs, nil, host)
	scope := func(port int) (models.AccessScope, string) {
		entries := openPorts(result, models.ProtoTCP, port)
		if len(entries) != 1 {
			t.Fatalf("port %d: %+v", port, entries)
		}
		return entries[0].Scope, entries[0].Restriction
	}
	// 10.0.0.0/8 is a range of private addresses; the single public address
	// in the set does not make it wider.
	if got, _ := scope(22); got != models.ScopeLocalnet {
		t.Errorf("port 22: %s, want LOCALNET", got)
	}
	// Everything but eleven banned addresses.
	if got, _ := scope(443); got != models.ScopeExposed {
		t.Errorf("port 443: %s, want EXPOSED", got)
	}
	// A set with ports is not decided by the source address.
	if got, restriction := scope(8080); got != models.ScopeRestricted || restriction != "ipset web" {
		t.Errorf("port 8080: %s %q, want RESTRICTED by ipset web", got, restriction)
	}
	if got, _ := scope(9090); got != models.ScopeLocalnet {
		t.Errorf("port 9090, a set of sets: %s, want LOCALNET", got)
	}

	for _, test := range []struct {
		source  string
		port    int
		verdict string
	}{
		{"10.1.2.3", 22, "ACCEPT"}, {"10.9.2.3", 22, "DROP"}, {"198.51.100.7", 22, "ACCEPT"}, {"198.51.100.8", 22, "DROP"},
		{"203.0.113.66", 443, "DROP"}, {"203.0.113.75", 443, "DROP"}, {"203.0.113.80", 443, "ACCEPT"},
	} {
		trace := Trace(rs, host, models.Packet{Protocol: models.ProtoTCP, Source: test.source, Port: test.port, In: "eth0", State: "NEW"})
		if trace.Verdict != test.verdict || !trace.Certain {
			t.Errorf("%s to port %d: %s (certain %v) by %s, want %s", test.source, test.port, trace.Verdict, trace.Certain, trace.DecidedBy, test.verdict)
		}
	}

	// Without the contents the same rules restrict to an unknown set.
	result = Analyze(rs, nil)
	if entries := openPorts(result, models.ProtoTCP, 22); len(entries) != 1 || entries[0].Scope != models.ScopeRestricted {
		t.Errorf("without the contents port 22 is restricted to an unknown set: %+v", entries)
	}
}

func TestForwardingSettingDecidesAboutForward(t *testing.T) {
	rules := "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp -m tcp --dport 8443 -j DNAT --to-destination 10.0.0.5:443\nCOMMIT\n" +
		"*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\n" +
		"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\nCOMMIT\n"
	rs := mustParse(t, rules, models.IPv4)
	forward := func(host *models.HostContext) (models.EffectivenessFinding, *models.AnalysisResult) {
		result := AnalyzeHost(rs, nil, host)
		found := effectiveness(result.EffectiveIssues, models.FindingPolicyAccept, "FORWARD")
		if len(found) != 1 {
			t.Fatalf("want one finding for FORWARD, got %+v", found)
		}
		return found[0], result
	}
	off, result := forward(&models.HostContext{Sysctls: map[string]string{"net.ipv4.ip_forward": "0"}})
	if off.Severity != models.SeverityInfo || !strings.Contains(off.Detail, "net.ipv4.ip_forward is 0") {
		t.Errorf("a host that does not route: %+v", off)
	}
	if len(result.PublishedPorts) != 0 || len(result.Notes) != 1 || !strings.Contains(result.Notes[0], "does not route packets") {
		t.Errorf("no port is sent to another host, and a note says so: %+v %v", result.PublishedPorts, result.Notes)
	}
	on, result := forward(&models.HostContext{Sysctls: map[string]string{"net.ipv4.ip_forward": "1"}})
	if on.Severity != models.SeverityHigh || !strings.Contains(on.Detail, "net.ipv4.ip_forward is 1") {
		t.Errorf("a host that routes: %+v", on)
	}
	if len(published(result, models.ProtoTCP, 8443)) != 1 {
		t.Errorf("the port forward is in use: %+v", result.PublishedPorts)
	}
	unknown, _ := forward(nil)
	if unknown.Severity != models.SeverityHigh || !strings.Contains(unknown.Detail, "The rules show") {
		t.Errorf("without the setting the rules tell: %+v", unknown)
	}
}

func TestRouteLocalnetSettingDecidesLoopbackDNAT(t *testing.T) {
	rules := natRules([]string{"-A PREROUTING -p tcp -m tcp --dport 2323 -j DNAT --to-destination 127.0.0.1:22"},
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT")
	rs := mustParse(t, rules, models.IPv4)
	host := func(all, own string) *models.HostContext {
		return &models.HostContext{
			Interfaces: []models.HostInterface{{Name: "lo", Addrs: []string{"127.0.0.1/8"}}, {Name: "eth0", Addrs: []string{"192.0.2.1/24"}, Up: true}},
			Sysctls:    map[string]string{"net.ipv4.conf.all.route_localnet": all, "net.ipv4.conf.eth0.route_localnet": own},
		}
	}
	if entries := openPorts(AnalyzeHost(rs, nil, host("0", "0")), models.ProtoTCP, 2323); len(entries) != 0 {
		t.Errorf("the kernel drops the packets: %+v", entries)
	}
	for _, settings := range [][2]string{{"1", "0"}, {"0", "1"}} {
		entries := openPorts(AnalyzeHost(rs, nil, host(settings[0], settings[1])), models.ProtoTCP, 2323)
		if len(entries) != 1 || entries[0].Certainty != models.CertaintyDefinite || entries[0].LocalAddr != "127.0.0.1" {
			t.Errorf("route_localnet %v: the port is open through 127.0.0.1:22: %+v", settings, entries)
		}
	}
}

func TestNativeNFTablesTablesMakeTheResultIncomplete(t *testing.T) {
	rs := mustParse(t, filterRules("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"), models.IPv4)
	host := &models.HostContext{NativeKnown: true, NativeTables: []models.NativeTable{
		{Family: "inet", Name: "firewalld", Hooks: []string{"forward", "input", "output", "prerouting"}},
		{Family: "ip6", Name: "only6", Hooks: []string{"input"}},
		{Family: "ip", Name: "counters", Hooks: []string{"output"}},
	}}
	notes := incomplete(AnalyzeHost(rs, nil, host))
	if len(notes) != 1 || !strings.Contains(notes[0], "nftables table inet firewalld has chains on the hooks forward, input and prerouting") ||
		!strings.Contains(notes[0], "nft list table inet firewalld") {
		t.Fatalf("want one note, for the table that filters incoming IPv4 packets: %v", notes)
	}
	if notes := incomplete(AnalyzeHost(rs, nil, &models.HostContext{NativeKnown: true})); len(notes) != 0 {
		t.Errorf("no native table, no note: %v", notes)
	}
}

// routerHost is a router with an uplink (eth0) and a local network (eth1).
func routerHost(filter string) *models.HostContext {
	host := &models.HostContext{
		Interfaces: []models.HostInterface{
			{Name: "lo", Addrs: []string{"127.0.0.1/8"}, Up: true},
			{Name: "eth0", Addrs: []string{"198.51.100.7/24"}, Up: true},
			{Name: "eth1", Addrs: []string{"192.168.1.1/24"}, Up: true},
		},
		Sysctls:     map[string]string{"net.ipv4.ip_forward": "1"},
		RoutesKnown: true,
		Routes: []models.Route{
			{Destination: "0.0.0.0/0", Devices: []string{"eth0"}, Metric: 100},
			{Destination: "198.51.100.0/24", Devices: []string{"eth0"}},
			{Destination: "192.168.1.0/24", Devices: []string{"eth1"}},
			{Destination: "10.20.0.0/16", Devices: []string{"eth1"}},
			{Destination: "10.99.0.0/16"}, // blackhole
			// A second default route with a higher metric is not the best one.
			{Destination: "0.0.0.0/0", Devices: []string{"eth1"}, Metric: 500},
		},
	}
	for _, name := range []string{"all", "default", "eth0", "eth1", "lo"} {
		host.Sysctls["net.ipv4.conf."+name+".rp_filter"] = filter
	}
	return host
}

// With the reverse-path filter in strict mode, only sources whose route
// leaves through an interface can arrive on it.
func TestReversePathFilterBoundsTheSourcesOfAnInterface(t *testing.T) {
	rules := filterRules(
		"-A INPUT -i eth1 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT")
	rs := mustParse(t, rules, models.IPv4)

	strict := AnalyzeHost(rs, nil, routerHost("1"))
	ssh := openPorts(strict, models.ProtoTCP, 22)
	if len(ssh) != 1 || ssh[0].Scope != models.ScopeLocalnet || ssh[0].Certainty != models.CertaintyDefinite || strings.Join(ssh[0].Interfaces, ",") != "eth1" {
		t.Errorf("port 22 on eth1 is open to the networks behind eth1 only: %+v", ssh)
	}
	if web := openPorts(strict, models.ProtoTCP, 80); len(web) != 1 || web[0].Scope != models.ScopeExposed {
		t.Errorf("port 80 is open to any source through the uplink: %+v", web)
	}
	said := false
	for _, note := range strict.Notes {
		said = said || strings.Contains(note, "arrive on eth1 to 10.20.0.0/16 and 192.168.1.0/24")
	}
	if !said {
		t.Errorf("the report must say what limits the sources: %v", strict.Notes)
	}

	for _, test := range []struct {
		filter, source, in, verdict string
	}{
		{"1", "192.168.1.50", "eth1", "ACCEPT"},
		{"1", "10.20.3.4", "eth1", "ACCEPT"},
		{"1", "203.0.113.5", "eth1", "DROP"},  // its route leaves through the uplink
		{"1", "192.168.1.50", "eth0", "DROP"}, // an address of the local network, forged on the uplink
		{"1", "10.99.1.1", "eth0", "DROP"},    // no way back at all
		{"2", "203.0.113.5", "eth1", "ACCEPT"},
		{"2", "10.99.1.1", "eth1", "DROP"},
		{"0", "203.0.113.5", "eth1", "ACCEPT"},
		{"0", "10.99.1.1", "eth1", "ACCEPT"},
	} {
		port := 22
		if test.in == "eth0" {
			port = 80
		}
		trace := Trace(rs, routerHost(test.filter), models.Packet{Protocol: models.ProtoTCP, Source: test.source, Destination: "192.168.1.1", Port: port, In: test.in, State: "NEW"})
		if trace.Verdict != test.verdict || !trace.Certain {
			t.Errorf("rp_filter %s, %s in %s: %s by %s, want %s", test.filter, test.source, test.in, trace.Verdict, trace.DecidedBy, test.verdict)
		}
		if test.verdict == "DROP" && !strings.Contains(trace.DecidedBy, "reverse-path filter") {
			t.Errorf("the trace must name the reverse-path filter: %s", trace.DecidedBy)
		}
	}

	// Without the filter, and without the routes, any source can arrive.
	for name, host := range map[string]*models.HostContext{"rp_filter 0": routerHost("0"), "no routes": {Interfaces: routerHost("1").Interfaces, Sysctls: routerHost("1").Sysctls}} {
		if ssh := openPorts(AnalyzeHost(rs, nil, host), models.ProtoTCP, 22); len(ssh) != 1 || ssh[0].Scope != models.ScopeExposed {
			t.Errorf("%s: port 22 on eth1 is open to any source: %+v", name, ssh)
		}
	}
}
