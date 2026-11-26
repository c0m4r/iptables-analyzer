//go:build linux

package analyzer

import (
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// kernelProbes builds probes of one protocol from every source to every
// port of one destination.
func kernelProbes(protocol string, sources []string, destination string, ports ...int) []kernelProbe {
	var probes []kernelProbe
	for _, source := range sources {
		for _, port := range ports {
			probes = append(probes, kernelProbe{Protocol: protocol, Source: source, Destination: destination, Port: port})
		}
	}
	return probes
}

// A host with one network of clients (eth0) and one network behind it (eth1).
var (
	kernelClients = []kernelNet{{Iface: "eth0", HostAddr: "192.0.2.1/24", Peers: []string{"192.0.2.2", "203.0.113.9", "10.1.2.3"}}}
	kernelInner   = []kernelNet{{Iface: "eth1", HostAddr: "10.8.0.1/24", Peers: []string{"10.8.0.2", "10.8.0.3"}}}
	kernelSources = []string{"192.0.2.2", "203.0.113.9", "10.1.2.3"}
)

func TestKernelRedirectAndDNAT(t *testing.T) {
	scenario := kernelScenario{
		Rules: natRules([]string{
			"-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080",
			"-A PREROUTING -p tcp -m tcp --dport 8443 -j DNAT --to-destination 10.8.0.2:443",
			"-A PREROUTING -p tcp -m tcp --dport 2222 -j DNAT --to-destination 192.0.2.1:22",
			"-A PREROUTING -p tcp -m tcp --dport 2323 -j DNAT --to-destination 127.0.0.1:22",
			"-A PREROUTING -s 203.0.113.0/24 -p tcp -m tcp --dport 9000 -j REDIRECT --to-ports 3128",
			"-A PREROUTING -p udp -m udp --dport 5353 -j REDIRECT --to-ports 53",
		},
			"-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT",
			"-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate DNAT -j ACCEPT",
			"-A INPUT -p tcp -m tcp --dport 9000 -j ACCEPT",
			"-A INPUT -p tcp -m conntrack --ctorigdstport 9000 -j ACCEPT",
			"-A INPUT -p udp -m udp --dport 53 -j ACCEPT",
			"-A INPUT -p tcp -m tcp --dport 25 -j REJECT --reject-with tcp-reset",
			"-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
			"-A FORWARD -d 10.8.0.2/32 -p tcp -m tcp --dport 443 -j ACCEPT"),
		Clients: kernelClients, Inner: kernelInner, Forward: true,
	}
	scenario.Probes = kernelProbes("tcp", kernelSources, "192.0.2.1", 22, 25, 80, 443, 2222, 2323, 3128, 8080, 8443, 9000)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", kernelSources, "192.0.2.1", 53, 5353)...)
	// Packets that the host routes on: straight to the host behind it.
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", kernelSources, "10.8.0.2", 80, 443, 8080)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", kernelSources, "10.8.0.3", 443)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}

	// With route_localnet the packets for 127.0.0.1 arrive.
	scenario.RouteLocalnet = true
	scenario.Probes = kernelProbes("tcp", kernelSources, "192.0.2.1", 2323, 22)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("route_localnet: %d of %d probes had a certain trace", certain, len(scenario.Probes))
	}

	// A host that does not route packets drops what it would have to send on.
	scenario.Forward = false
	scenario.Probes = append(kernelProbes("tcp", kernelSources, "192.0.2.1", 8443, 80), kernelProbes("tcp", kernelSources, "10.8.0.2", 443)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("no forwarding: %d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}

// kernelFilterRules use most of the matches and targets that the evaluation
// models, in user-defined chains with RETURN and goto.
const kernelFilterRules = `*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A PREROUTING -s 10.1.2.3/32 -p tcp -m tcp --dport 7001 -j DROP
-A PREROUTING -p tcp -m tcp --dport 7002 -j NOTRACK
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -p tcp -m tcp --dport 7003 -j MARK --set-xmark 0x10/0xff
-A PREROUTING -s 203.0.113.9/32 -p tcp -m tcp --dport 7005 -j MARK --set-xmark 0x20/0xff
-A INPUT -p tcp -m tcp --dport 7004 -j DROP
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:ADMIN - [0:0]
:LIMITED - [0:0]
:SERVICES - [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -s 203.0.113.9/32 -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ADMIN
-A INPUT -j SERVICES
-A INPUT -p tcp -m multiport --dports 6000:6010,6020 -m iprange --src-range 192.0.2.2-192.0.2.9 -j ACCEPT
-A INPUT -i eth9 -p tcp -m tcp --dport 6500 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 6501 -j ACCEPT
-A INPUT ! -i eth0 -p tcp -m tcp --dport 6502 -j ACCEPT
-A INPUT ! -s 10.0.0.0/8 -p tcp -m tcp --dport 6503 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 6504 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT
-A INPUT -p tcp -m tcp --dport 6505 -m conntrack --ctstate NEW -m limit --limit 30/min --limit-burst 20 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 6506 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 60/min --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name t6506 -j DROP
-A INPUT -p tcp -m tcp --dport 6506 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7001 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7002 -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7002 -m conntrack --ctstate UNTRACKED -j REJECT --reject-with tcp-reset
-A INPUT -p tcp -m mark --mark 0x10/0xff -j ACCEPT
-A INPUT -p tcp -m mark ! --mark 0x20/0xff -m tcp --dport 7005 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7004 -j ACCEPT
-A INPUT -p udp -m udp --dport 53 -j ACCEPT
-A INPUT -p udp -m udp --sport 1024:65535 --dport 123 -j ACCEPT
-A INPUT -p udp -m udp --sport 53 --dport 5300 -j ACCEPT
-A INPUT -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 6600 -j ACCEPT
-A INPUT -p tcp -m addrtype ! --dst-type LOCAL -m tcp --dport 6601 -j ACCEPT
-A INPUT -d 192.0.2.1/32 -p tcp -m tcp --dport 6602 -j ACCEPT
-A INPUT -d 192.0.2.99/32 -p tcp -m tcp --dport 6603 -j ACCEPT
-A INPUT -p tcp -m pkttype --pkt-type unicast -m tcp --dport 6604 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 6605 -m connlimit --connlimit-above 50 --connlimit-mask 32 --connlimit-saddr -j REJECT --reject-with tcp-reset
-A INPUT -p tcp -m tcp --dport 6605 -j ACCEPT
-A INPUT -p tcp -m tcp ! --dport 1:9999 -j ACCEPT
-A ADMIN -s 192.0.2.0/24 -j ACCEPT
-A ADMIN -s 10.1.2.3/32 -j RETURN
-A ADMIN -j DROP
-A LIMITED -s 203.0.113.0/24 -j ACCEPT
-A LIMITED -s 10.0.0.0/8 -j RETURN
-A SERVICES -p tcp -m tcp --dport 80 -j ACCEPT
-A SERVICES -p tcp -m tcp --dport 443 -g LIMITED
-A SERVICES -p tcp -m tcp --dport 443 -j ACCEPT
COMMIT
`

func TestKernelFilterRules(t *testing.T) {
	scenario := kernelScenario{
		Rules: kernelFilterRules,
		Clients: []kernelNet{
			{Iface: "eth0", HostAddr: "192.0.2.1/24", Peers: []string{"192.0.2.2", "192.0.2.77", "203.0.113.9", "10.1.2.3"}},
			{Iface: "eth1", HostAddr: "198.51.100.1/24", Peers: []string{"198.51.100.2", "10.5.5.5"}},
		},
	}
	tcp := []int{22, 80, 443, 5000, 6000, 6010, 6011, 6020, 6500, 6501, 6502, 6503, 6504, 6505, 6506, 6600, 6601, 6602, 6603, 6604, 6605,
		7001, 7002, 7003, 7004, 7005, 9999, 10000, 31337}
	scenario.Probes = kernelProbes("tcp", []string{"192.0.2.2", "192.0.2.77", "203.0.113.9", "10.1.2.3"}, "192.0.2.1", tcp...)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", []string{"198.51.100.2", "10.5.5.5"}, "198.51.100.1", tcp...)...)
	// The other address of the host, which is not on the interface of arrival.
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", []string{"198.51.100.2"}, "192.0.2.1", 80, 6602, 6501, 6502)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", []string{"192.0.2.2", "10.5.5.5"}, "192.0.2.1", 53, 123, 5300, 9)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}

// The fixture of a host that ufw manages: chains that call each other, a
// connection limit kept with the recent match, and logging rules.
func TestKernelUFWFixture(t *testing.T) {
	sources := []string{"10.0.0.9", "203.0.113.9", "192.168.7.7"}
	scenario := kernelScenario{
		Rules:   readFixture(t, "ufw.iptables-save"),
		Clients: []kernelNet{{Iface: "eth0", HostAddr: "10.0.0.5/24", Peers: sources}},
	}
	scenario.Probes = kernelProbes("tcp", sources, "10.0.0.5", 22, 80, 443, 5432, 139, 445, 6379, 8080)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", sources, "10.0.0.5", 53, 68, 137, 5353)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}

// The capture of a Docker 29 host: published ports in every gateway mode,
// the protection of container addresses in the raw table, and an internal
// network. The bridges are plain interfaces here, with a host behind each
// that has the addresses of the containers.
func TestKernelDocker29Fixture(t *testing.T) {
	sources := []string{"192.168.88.10", "203.0.113.9"}
	scenario := kernelScenario{
		Rules:   docker29(t),
		Forward: true,
		Clients: []kernelNet{{Iface: "eth0", HostAddr: "192.168.88.217/24", Peers: sources}},
		Inner: []kernelNet{
			{Iface: "docker0", HostAddr: "172.17.0.1/16", Peers: []string{"172.17.0.2", "172.17.0.3", "172.17.0.4", "172.17.0.5", "172.17.0.6"}},
			{Iface: "br-7a3442937ee6", HostAddr: "172.30.0.1/24", Peers: []string{"172.30.0.2"}},
			{Iface: "br-84b7b034b576", HostAddr: "172.31.0.1/24", Peers: []string{"172.31.0.2"}},
			{Iface: "br-982052ef0162", HostAddr: "172.29.0.1/24", Peers: []string{"172.29.0.2"}},
			{Iface: "br-1843f3e4f373", HostAddr: "172.28.0.1/24", Peers: []string{"172.28.0.2"}},
		},
	}
	scenario.Probes = kernelProbes("tcp", sources, "192.168.88.217", 22, 80, 8080, 8081, 8082, 8090, 8091, 8443, 9000, 9001, 9002, 9003)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", sources, "192.168.88.217", 9053, 53)...)
	// Packets that another host routes straight to a container.
	for _, direct := range []struct {
		addr  string
		ports []int
	}{
		{"172.17.0.2", []int{80}}, {"172.17.0.6", []int{9000}}, {"172.30.0.2", []int{443}},
		{"172.31.0.2", []int{80, 81}}, {"172.29.0.2", []int{80, 8080}}, {"172.28.0.2", []int{80}},
	} {
		scenario.Probes = append(scenario.Probes, kernelProbes("tcp", sources, direct.addr, direct.ports...)...)
	}
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}

// A node of a Kubernetes cluster: node ports that lead through the chains of
// kube-proxy to pods, an address of a load balancer, cluster addresses, and
// the mark that admits the translated packets in FORWARD.
func TestKernelKubernetesFixture(t *testing.T) {
	sources := []string{"192.168.49.9", "203.0.113.9"}
	scenario := kernelScenario{
		Rules:   readFixture(t, "k8s.iptables-save"),
		Forward: true,
		Clients: []kernelNet{{Iface: "eth0", HostAddr: "192.168.49.2/24", Peers: sources}},
		Inner:   []kernelNet{{Iface: "cni0", HostAddr: "10.244.0.1/24", Peers: []string{"10.244.0.2", "10.244.0.3", "10.244.0.10", "10.244.0.11", "10.244.0.12"}}},
	}
	scenario.Probes = kernelProbes("tcp", sources, "192.168.49.2", 22, 80, 6443, 8080, 10250, 30080, 30443, 30999)
	// The address of the load balancer and the cluster addresses are not
	// addresses of the node: the clients route them to it.
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", sources, "203.0.113.50", 80, 443)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", sources, "10.101.37.20", 80)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", sources, "10.107.201.9", 443, 80)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", sources, "10.96.0.10", 53)...)
	// Straight to a pod.
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", sources, "10.244.0.12", 8443, 22)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}

func TestKernelFail2banFixture(t *testing.T) {
	sources := []string{"192.0.2.44", "198.51.100.23", "203.0.113.66", "203.0.113.9"}
	scenario := kernelScenario{
		Rules:   readFixture(t, "fail2ban.iptables-save"),
		Clients: []kernelNet{{Iface: "eth0", HostAddr: "192.0.2.1/24", Peers: sources}},
	}
	scenario.Probes = kernelProbes("tcp", sources, "192.0.2.1", 22, 25, 80, 443, 8080)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}

// A host with virtual machines behind virbr0, one of which has a port of the
// host.
func TestKernelLibvirtFixture(t *testing.T) {
	sources := []string{"192.0.2.9", "203.0.113.9"}
	scenario := kernelScenario{
		Rules:   readFixture(t, "libvirt.iptables-save"),
		Forward: true,
		Clients: []kernelNet{{Iface: "eth0", HostAddr: "192.0.2.10/24", Peers: sources}},
		Inner:   []kernelNet{{Iface: "virbr0", HostAddr: "192.168.122.1/24", Peers: []string{"192.168.122.50", "192.168.122.51"}}},
	}
	scenario.Probes = kernelProbes("tcp", sources, "192.0.2.10", 22, 53, 67, 8022, 8080)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", sources, "192.0.2.10", 53, 67)...)
	// Straight to the guests, and to the address of the host on their bridge.
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", sources, "192.168.122.50", 22, 80)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", sources, "192.168.122.51", 22)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", sources, "192.168.122.1", 53, 22)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}

func TestKernelFirewalldFixture(t *testing.T) {
	sources := []string{"10.0.0.9", "203.0.113.9"}
	scenario := kernelScenario{
		Rules:   readFixture(t, "firewalld.iptables-save"),
		Clients: []kernelNet{{Iface: "eth0", HostAddr: "10.0.0.5/24", Peers: sources}},
	}
	scenario.Probes = kernelProbes("tcp", sources, "10.0.0.5", 22, 25, 80, 443, 5432, 8080)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", sources, "10.0.0.5", 53)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}

// A router between an uplink and a local network.
func TestKernelRouterFixture(t *testing.T) {
	uplink := []string{"198.51.100.9", "203.0.113.9", "192.0.2.77"}
	local := []string{"192.168.1.100"}
	scenario := kernelScenario{
		Rules:   readFixture(t, "router.iptables-save"),
		Forward: true,
		Clients: []kernelNet{
			{Iface: "eth0", HostAddr: "198.51.100.7/24", Peers: uplink},
			{Iface: "eth1", HostAddr: "192.168.1.1/24", Peers: local, Hosts: []string{"192.168.1.10", "192.168.1.20", "192.168.1.50"}},
		},
	}
	scenario.Probes = kernelProbes("tcp", uplink, "198.51.100.7", 22, 53, 80, 2222, 3128, 8443)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", uplink, "198.51.100.7", 53, 51820)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", local, "192.168.1.1", 22, 53, 80, 3128, 8443)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", local, "192.168.1.1", 53)...)
	// From the uplink straight to a host of the local network.
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", uplink, "192.168.1.50", 443, 22)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}

// The report advises to limit a node port in the raw table, in front of the
// translation of kube-proxy. The rule has the form that the fix gives.
func TestKernelNodePortFilterInRawTable(t *testing.T) {
	rules := "*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A PREROUTING -m addrtype --dst-type LOCAL -p tcp -m tcp --dport 30443 ! -s 192.168.49.0/24 -j DROP\n" +
		"-A PREROUTING -d 203.0.113.50 -p tcp -m tcp --dport 80 ! -s 192.168.49.0/24 -j DROP\nCOMMIT\n" +
		readFixture(t, "k8s.iptables-save")
	sources := []string{"192.168.49.9", "203.0.113.9"}
	scenario := kernelScenario{
		Rules:   rules,
		Forward: true,
		Clients: []kernelNet{{Iface: "eth0", HostAddr: "192.168.49.2/24", Peers: sources}},
		Inner:   []kernelNet{{Iface: "cni0", HostAddr: "10.244.0.1/24", Peers: []string{"10.244.0.10", "10.244.0.11", "10.244.0.12"}}},
	}
	scenario.Probes = kernelProbes("tcp", sources, "192.168.49.2", 30443, 30080)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", sources, "203.0.113.50", 80)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
	// The trace itself must say what the rule is for.
	rs := mustParse(t, rules, models.IPv4)
	for source, verdict := range map[string]string{"192.168.49.9": "ACCEPT", "203.0.113.9": "DROP"} {
		trace := Trace(rs, nil, models.Packet{Protocol: models.ProtoTCP, Source: source, Port: 30443, In: "eth0", State: "NEW"})
		if trace.Verdict != verdict {
			t.Errorf("node port from %s: %s, want %s", source, trace.Verdict, verdict)
		}
	}
}

// The reverse-path filter of the kernel refuses packets whose source has its
// route through another interface. The analysis takes the sources of an
// interface from the routes; here real packets with such sources show that
// the kernel does the same. One datagram is sent each time, because no
// answer can come back to a forged address.
func TestKernelReversePathFilter(t *testing.T) {
	rules := filterRules(
		"-A INPUT -p udp -m udp --dport 9000 -j ACCEPT",
		"-A INPUT -i eth1 -p udp -m udp --dport 9001 -j ACCEPT")
	clients := []kernelNet{
		{Iface: "eth0", HostAddr: "192.0.2.1/24", Peers: []string{"192.0.2.2", "203.0.113.9"}},
		// 192.0.2.77 has its route through eth0, and 203.0.113.200 has none.
		{Iface: "eth1", HostAddr: "198.51.100.1/24", Peers: []string{"198.51.100.2"}, Forged: []string{"192.0.2.77", "203.0.113.200"}},
	}
	for _, mode := range []string{"1", "2", "0"} {
		scenario := kernelScenario{Rules: rules, Clients: clients, RPFilter: mode}
		scenario.Probes = kernelProbes("udp1", []string{"192.0.2.2", "203.0.113.9"}, "192.0.2.1", 9000, 9001, 9002)
		scenario.Probes = append(scenario.Probes, kernelProbes("udp1", []string{"198.51.100.2", "192.0.2.77", "203.0.113.200"}, "198.51.100.1", 9000, 9001, 9002)...)
		if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
			t.Errorf("rp_filter %s: %d of %d probes had a certain trace", mode, certain, len(scenario.Probes))
		}
	}
}

// The same host with IPv6 addresses.
var (
	kernelClients6 = []kernelNet{{Iface: "eth0", HostAddr: "2001:db8:1::1/64", Peers: []string{"2001:db8:1::2", "2001:db8:9::9", "fd00:1::3"}}}
	kernelInner6   = []kernelNet{{Iface: "eth1", HostAddr: "2001:db8:8::1/64", Peers: []string{"2001:db8:8::2", "2001:db8:8::3"}}}
	kernelSources6 = []string{"2001:db8:1::2", "2001:db8:9::9", "fd00:1::3"}
)

// ip6tables: the translations and the filter rules of the IPv4 scenario.
// IPv6 has no route_localnet; what the kernel does with a DNAT to ::1 is
// what this test is for.
func TestKernelIPv6RedirectAndDNAT(t *testing.T) {
	scenario := kernelScenario{
		IPv6: true,
		Rules: natRules([]string{
			"-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080",
			"-A PREROUTING -p tcp -m tcp --dport 8443 -j DNAT --to-destination [2001:db8:8::2]:443",
			"-A PREROUTING -p tcp -m tcp --dport 2222 -j DNAT --to-destination [2001:db8:1::1]:22",
			"-A PREROUTING -p tcp -m tcp --dport 2323 -j DNAT --to-destination [::1]:22",
			"-A PREROUTING -s 2001:db8:9::/48 -p tcp -m tcp --dport 9000 -j REDIRECT --to-ports 3128",
			"-A PREROUTING -p udp -m udp --dport 5353 -j REDIRECT --to-ports 53",
			"-A PREROUTING -p udp -m udp --dport 5354 -j DNAT --to-destination [::1]:53",
			"-A PREROUTING -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 30080 -j DNAT --to-destination [2001:db8:8::3]:8080",
		},
			"-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT",
			"-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate DNAT -j ACCEPT",
			"-A INPUT -p tcp -m tcp --dport 9000 -j ACCEPT",
			"-A INPUT -p tcp -m conntrack --ctorigdstport 9000 -j ACCEPT",
			"-A INPUT -p udp -m udp --dport 53 -j ACCEPT",
			"-A INPUT -p tcp -m tcp --dport 25 -j REJECT --reject-with tcp-reset",
			"-A INPUT -s fd00::/8 -p tcp -m tcp --dport 5000 -j ACCEPT",
			"-A INPUT -d 2001:db8:1::1/128 -p tcp -m tcp --dport 5001 -j ACCEPT",
			"-A INPUT -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 5002 -j ACCEPT",
			"-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
			"-A FORWARD -d 2001:db8:8::2/128 -p tcp -m tcp --dport 443 -j ACCEPT",
			"-A FORWARD -d 2001:db8:8::3/128 -p tcp -m tcp --dport 8080 -m conntrack --ctorigdstport 30080 -j ACCEPT"),
		Clients: kernelClients6, Inner: kernelInner6, Forward: true,
	}
	scenario.Probes = kernelProbes("tcp", kernelSources6, "2001:db8:1::1", 22, 25, 80, 443, 2222, 2323, 3128, 5000, 5001, 5002, 8080, 8443, 9000, 30080)
	scenario.Probes = append(scenario.Probes, kernelProbes("udp", kernelSources6, "2001:db8:1::1", 53, 5353)...)
	// One datagram each, without a wait for an answer: does a socket of the
	// host receive it? This tells a packet that the kernel drops from one
	// whose answer is lost. Port 5353 arrives; port 5354, sent to ::1, does not.
	scenario.Probes = append(scenario.Probes, kernelProbes("udp1", kernelSources6[:1], "2001:db8:1::1", 5353, 5354)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", kernelSources6, "2001:db8:8::2", 80, 443, 8080)...)
	scenario.Probes = append(scenario.Probes, kernelProbes("tcp", kernelSources6, "2001:db8:8::3", 443, 8080)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("%d of %d probes had a certain trace", certain, len(scenario.Probes))
	}

	// A host that does not route packets drops what it would have to send on.
	scenario.Forward = false
	scenario.Probes = append(kernelProbes("tcp", kernelSources6, "2001:db8:1::1", 8443, 80, 30080), kernelProbes("tcp", kernelSources6, "2001:db8:8::2", 443)...)
	if certain := kernelCompare(t, scenario); certain != len(scenario.Probes) {
		t.Errorf("no forwarding: %d of %d probes had a certain trace", certain, len(scenario.Probes))
	}
}
