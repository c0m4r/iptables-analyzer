package hostinfo

import (
	"strings"
	"testing"
	"unicode"
)

// noControl fails when text that the report shows holds a character that a
// terminal interprets.
func noControl(t *testing.T, what, text string) {
	t.Helper()
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			t.Fatalf("%s holds the control character %U: %q", what, r, text)
		}
	}
}

// FuzzHostFacts reads arbitrary text as the output of the tools that tell
// about a host. The parsers must not panic, and every name that they return
// must be safe to print.
func FuzzHostFacts(f *testing.F) {
	f.Add(savedSets)
	f.Add(listedChains)
	f.Add("default via 192.0.2.1 dev eth0 metric 100\n192.0.2.0/24 dev eth0\nblackhole 10.0.0.0/8\n\tnexthop via 10.0.0.1 dev eth1\n")
	f.Add("create a\x1b[31m hash:ip\nadd a\x1b[31m 1.2.3.4 comment \"\u202e\"\n")
	f.Add("table inet \"x\x07y\" {\n\tchain c {\n\t\ttype filter hook input\x1b priority 0;\n")
	f.Fuzz(func(t *testing.T, text string) {
		if sets, err := ParseIPSets(text); err == nil {
			for name, set := range sets {
				noControl(t, "set name", name+set.Name+set.Type+set.Family)
				for _, entry := range append(append(append([]string{}, set.Entries...), set.Excluded...), set.Members...) {
					noControl(t, "set entry", entry)
				}
			}
		}
		for _, table := range ParseNFTChains(text) {
			noControl(t, "table", table.Family+table.Name+strings.Join(table.Hooks, ""))
		}
		if routes, err := ParseRoutes(text); err == nil {
			for _, route := range routes {
				noControl(t, "route", route.Destination+strings.Join(route.Devices, ""))
			}
		}
	})
}

// FuzzSnapshot reads arbitrary bytes as a snapshot file.
func FuzzSnapshot(f *testing.F) {
	f.Add([]byte(`{"format":"iptables-analyzer snapshot","version":1,"hostname":"h","interfaces":[{"name":"eth0","addrs":["192.0.2.1/24"],"up":true}],` +
		`"sysctls":{"net.ipv4.ip_forward":"1"},"iptables_save":{"data":"*filter\n:INPUT DROP [0:0]\nCOMMIT\n","warnings":["w"]},"ss":[{"proto":"tcp","data":""}]}`))
	f.Add([]byte(`{"format":"iptables-analyzer snapshot","version":1,"hostname":"\u001b[31m","created":"\u009b2J"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		snapshot, err := ParseSnapshot(data)
		if err != nil {
			return
		}
		host := snapshot.Host()
		noControl(t, "header", snapshot.Created+snapshot.Tool+host.Hostname)
		for _, iface := range host.Interfaces {
			noControl(t, "interface", iface.Name+strings.Join(iface.Addrs, ""))
		}
		for name, value := range host.Sysctls {
			noControl(t, "setting", name+value)
		}
		for _, rules := range []*SnapshotRules{snapshot.IPv4, snapshot.IPv6} {
			if rules != nil {
				noControl(t, "warning", strings.Join(rules.Warnings, ""))
			}
		}
	})
}
