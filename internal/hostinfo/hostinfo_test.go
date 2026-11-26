package hostinfo

import (
	"reflect"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

const savedSets = `create trusted hash:net family inet hashsize 1024 maxelem 65536 bucketsize 12 initval 0x4b1d2c3a
add trusted 10.0.0.0/8
add trusted 10.9.0.0/16 nomatch
add trusted 203.0.113.7
create banned hash:ip family inet hashsize 1024 maxelem 65536 timeout 600 comment
add banned 198.51.100.23 timeout 432 comment "ssh nomatch brute force"
add banned 198.51.100.40-198.51.100.44
create blocks hash:ip family inet hashsize 1024 maxelem 65536 netmask 24
add blocks 192.0.2.0
create v6 hash:net family inet6 hashsize 1024 maxelem 65536
add v6 2001:db8::/32
create web hash:ip,port family inet hashsize 1024 maxelem 65536
add web 192.0.2.1,tcp:80
create both list:set size 8
add both trusted
add both banned
`

func TestParseIPSets(t *testing.T) {
	sets, err := ParseIPSets(savedSets)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]models.IPSet{
		"trusted": {Name: "trusted", Type: "hash:net", Family: "inet", Addresses: true,
			Entries: []string{"10.0.0.0/8", "203.0.113.7"}, Excluded: []string{"10.9.0.0/16"}},
		// A comment that holds the word nomatch does not exclude the entry.
		"banned": {Name: "banned", Type: "hash:ip", Family: "inet", Addresses: true,
			Entries: []string{"198.51.100.23", "198.51.100.40-198.51.100.44"}},
		// A set with a netmask stores networks of that size.
		"blocks": {Name: "blocks", Type: "hash:ip", Family: "inet", Addresses: true, Entries: []string{"192.0.2.0/24"}},
		"v6":     {Name: "v6", Type: "hash:net", Family: "inet6", Addresses: true, Entries: []string{"2001:db8::/32"}},
		// Entries with a port say nothing about a source address alone.
		"web":  {Name: "web", Type: "hash:ip,port", Family: "inet"},
		"both": {Name: "both", Type: "list:set", Members: []string{"trusted", "banned"}},
	}
	if !reflect.DeepEqual(sets, want) {
		t.Errorf("got  %+v\nwant %+v", sets, want)
	}
}

func TestParseIPSetsRefusesOtherInput(t *testing.T) {
	for _, text := range []string{
		"*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
		"add missing 10.0.0.1\n",
		"create a hash:ip\ncreate a hash:ip\n",
		"create a hash:ip\nadd a not-an-address\n",
		"create a hash:net\nadd a 10.0.0.9-10.0.0.1\n",
		"create a\n",
	} {
		if _, err := ParseIPSets(text); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	// Names are shown in the report: control characters must not pass.
	sets, err := ParseIPSets("create a\x1b[31m hash:ip\n")
	if err != nil {
		t.Fatal(err)
	}
	for name := range sets {
		if strings.ContainsRune(name, 0x1b) {
			t.Errorf("an escape character reached the name %q", name)
		}
	}
}

const listedChains = `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
	}
	chain DOCKER {
	}
}
table ip nat {
	chain PREROUTING {
		type nat hook prerouting priority dstnat; policy accept;
	}
}
table inet firewalld {
	chain mangle_PREROUTING {
		type filter hook prerouting priority mangle + 10; policy accept;
	}
	chain filter_INPUT {
		type filter hook input priority filter + 10; policy accept;
	}
	chain filter_FORWARD {
		type filter hook forward priority filter + 10; policy accept;
	}
	chain filter_IN_public {
	}
}
table ip6 mangle {
}
table inet f2b-table {
	chain f2b-chain {
		type filter hook input priority filter - 1; policy accept;
	}
}
table bridge filter {
	chain FORWARD {
		type filter hook forward priority filter; policy accept;
	}
}
table ip counters {
}
`

func TestParseNFTChains(t *testing.T) {
	want := []models.NativeTable{
		{Family: "inet", Name: "firewalld", Hooks: []string{"forward", "input", "prerouting"}},
		{Family: "inet", Name: "f2b-table", Hooks: []string{"input"}},
		{Family: "ip", Name: "counters"},
	}
	if got := ParseNFTChains(listedChains); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if got := ParseNFTChains(""); len(got) != 0 {
		t.Errorf("no output means no table: %+v", got)
	}
}

func TestSysctls(t *testing.T) {
	paths := SysctlPaths([]string{"eth0", "weird/name", "eth0.100", "..", ".", "../../etc", ""})
	if paths["net.ipv4.ip_forward"] != "/proc/sys/net/ipv4/ip_forward" ||
		paths["net.ipv4.conf.eth0.rp_filter"] != "/proc/sys/net/ipv4/conf/eth0/rp_filter" ||
		// A VLAN device has a dot in its name, and its settings are read.
		paths["net.ipv4.conf.eth0.100.rp_filter"] != "/proc/sys/net/ipv4/conf/eth0.100/rp_filter" {
		t.Errorf("missing paths: %v", paths)
	}
	for name, path := range paths {
		if strings.Contains(path, "weird") || strings.Contains(path, "etc") || strings.Contains(path, "..") || strings.Contains(path, "/./") || strings.Contains(path, "//") || strings.Contains(name, "/") {
			t.Errorf("a name of an interface that is no file name was used: %s %s", name, path)
		}
	}
	for raw, want := range map[string]string{"1\n": "1", " 0 ": "0", "2": "2"} {
		if got, ok := CleanSysctl(raw); !ok || got != want {
			t.Errorf("CleanSysctl(%q) = %q, %v", raw, got, ok)
		}
	}
	for _, raw := range []string{"", "yes", "1 2", "123456", "-1"} {
		if _, ok := CleanSysctl(raw); ok {
			t.Errorf("CleanSysctl accepted %q", raw)
		}
	}

	host := &models.HostContext{Sysctls: map[string]string{
		"net.ipv4.conf.all.rp_filter": "0", "net.ipv4.conf.eth0.rp_filter": "2", "net.ipv4.conf.eth1.rp_filter": "0",
		"net.ipv4.conf.all.route_localnet": "1", "net.ipv4.conf.eth0.route_localnet": "0",
	}}
	for _, test := range []struct{ name, iface, want string }{
		{"rp_filter", "eth0", "2"}, {"rp_filter", "eth1", "0"}, {"route_localnet", "eth0", "1"},
	} {
		if got, known := InterfaceSetting(host, test.name, test.iface); !known || got != test.want {
			t.Errorf("%s of %s = %q, %v; want %q", test.name, test.iface, got, known, test.want)
		}
	}
	if _, known := InterfaceSetting(host, "rp_filter", "eth9"); known {
		t.Error("the setting of an interface that was not read is not known")
	}
	if _, known := InterfaceSetting(nil, "rp_filter", "eth0"); known {
		t.Error("no host, no setting")
	}
}

func TestParseRoutes(t *testing.T) {
	routes, err := ParseRoutes(`default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100
192.0.2.0/24 dev eth0 proto kernel scope link src 192.0.2.10 metric 100
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
198.51.100.9 via 192.0.2.2 dev eth0
blackhole 10.99.0.0/16
unreachable 10.98.0.0/16 metric 1024
default proto static metric 200
	nexthop via 10.0.0.1 dev eth1 weight 1
	nexthop via 10.0.1.1 dev eth2 weight 1
`)
	if err != nil {
		t.Fatal(err)
	}
	want := []models.Route{
		{Destination: "0.0.0.0/0", Devices: []string{"eth0"}, Metric: 100},
		{Destination: "192.0.2.0/24", Devices: []string{"eth0"}, Metric: 100},
		{Destination: "172.17.0.0/16", Devices: []string{"docker0"}},
		{Destination: "198.51.100.9/32", Devices: []string{"eth0"}},
		{Destination: "10.99.0.0/16"},
		{Destination: "10.98.0.0/16", Metric: 1024},
		{Destination: "0.0.0.0/0", Devices: []string{"eth1", "eth2"}, Metric: 200},
	}
	if !reflect.DeepEqual(routes, want) {
		t.Errorf("got  %+v\nwant %+v", routes, want)
	}
	for _, bad := range []string{"this is no route\n", "\tnexthop via 10.0.0.1 dev eth1\n", "2001:db8::/32 dev eth0\n", "blackhole\n"} {
		if _, err := ParseRoutes(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if routes, err := ParseRoutes(""); err != nil || len(routes) != 0 {
		t.Errorf("a host without routes: %v %v", routes, err)
	}
}
