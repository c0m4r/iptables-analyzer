package hostinfo

import (
	"bytes"
	"strings"
	"testing"
)

func TestSnapshotRoundTrip(t *testing.T) {
	chains := "table inet firewalld {\n}\n"
	original := &Snapshot{
		Created: "2026-11-25T04:46:00Z", Tool: "0.8.0", Live: true, Hostname: "web01",
		Interfaces: []SnapshotInterface{{Name: "eth0", Addrs: []string{"192.0.2.10/24", "2001:db8::10/64"}, Up: true}},
		Sysctls:    map[string]string{"net.ipv4.ip_forward": "1"},
		IPv4:       &SnapshotRules{Data: "*filter\n:INPUT DROP [0:0]\nCOMMIT\n", Warnings: []string{"iptables-legacy tables present"}},
		Sockets:    []SnapshotOutput{{Proto: "tcp", Data: "State Recv-Q\n"}},
		NFTChains:  &chains,
	}
	var file bytes.Buffer
	if err := original.Write(&file); err != nil {
		t.Fatal(err)
	}
	if !IsSnapshot(file.String()) {
		t.Fatalf("the file is not recognized:\n%s", file.String())
	}
	read, err := ParseSnapshot(file.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if read.Hostname != "web01" || !read.Live || read.IPv4 == nil || read.IPv4.Data != original.IPv4.Data || read.IPv6 != nil ||
		len(read.Sockets) != 1 || read.NFTChains == nil || *read.NFTChains != chains || read.IPSets != nil {
		t.Errorf("the snapshot changed: %+v", read)
	}
	host := read.Host()
	if len(host.Interfaces) != 1 || host.Interfaces[0].Name != "eth0" || len(host.Interfaces[0].Addrs) != 2 || !host.Interfaces[0].Up {
		t.Errorf("interfaces: %+v", host.Interfaces)
	}
	if on, known := host.Forwarding(4); !on || !known {
		t.Error("the forwarding setting was lost")
	}
}

func TestSnapshotInputIsNotTrusted(t *testing.T) {
	text := `{"format":"iptables-analyzer snapshot","version":1,"created":"now\u001b[31m","hostname":"host\u001b]0;x\u0007",
	 "interfaces":[{"name":"eth\u001b[0m","addrs":["192.0.2.1/24","not an address","fe80::1%eth0","10.0.0.1"],"up":true}],
	 "sysctls":{"net.ipv4.ip_forward":"1","net.ipv4.conf.all.rp_filter":"yes","kernel.hostname":"1","net.x":"99999999"},
	 "iptables_save":{"data":"","warnings":["warn\u001b[2J"]},"future_field":true}`
	snapshot, err := ParseSnapshot([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	host := snapshot.Host()
	for _, value := range []string{snapshot.Created, host.Hostname, host.Interfaces[0].Name, snapshot.IPv4.Warnings[0]} {
		if strings.ContainsRune(value, 0x1b) || strings.ContainsRune(value, 0x07) {
			t.Errorf("a control character passed: %q", value)
		}
	}
	if got := strings.Join(host.Interfaces[0].Addrs, " "); got != "192.0.2.1/24 10.0.0.1" {
		t.Errorf("addresses: %q", got)
	}
	if len(host.Sysctls) != 1 || host.Sysctls["net.ipv4.ip_forward"] != "1" {
		t.Errorf("only settings of the network with a small number as value are kept: %v", host.Sysctls)
	}

	for _, bad := range []string{
		`{"format":"something else","version":1}`,
		`{"format":"iptables-analyzer snapshot","version":2}`,
		`{"format":"iptables-analyzer snapshot","version":0}`,
		`{"format":"iptables-analyzer snapshot","version":1,"ss":[{"proto":"sctp","data":""}]}`,
		`*filter`,
	} {
		if _, err := ParseSnapshot([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	for _, other := range []string{"*filter\n:INPUT ACCEPT [0:0]\n", "", "{}", `{"format": "x"}`, "Netid State\n"} {
		if IsSnapshot(other) {
			t.Errorf("%q is no snapshot", other)
		}
	}
}
