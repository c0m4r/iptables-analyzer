package services

import "testing"

func TestParseSSData(t *testing.T) {
	data := `State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
UNCONN 0 0 [::]:53 [::]:* users:(("dns",pid=53,fd=4))
`
	services, err := ParseSSData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 2 {
		t.Fatalf("expected two services, got %+v", services)
	}
	if services[0].Port != 22 || !services[0].IsWildcard || services[0].Process != "sshd" {
		t.Fatalf("unexpected IPv4 service: %+v", services[0])
	}
	if services[1].Port != 53 || !services[1].IsIPv6 || !services[1].IsWildcard {
		t.Fatalf("unexpected IPv6 service: %+v", services[1])
	}
}

func TestParseAddressWithZone(t *testing.T) {
	addr, port := parseAddress("[fe80::1%eth0]:5353")
	if addr != "fe80::1%eth0" || port != 5353 {
		t.Fatalf("unexpected address %q:%d", addr, port)
	}
}

func TestWildcardSocketRetainsDualStackFamily(t *testing.T) {
	services, err := ParseSSData("State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 128 *:22 *:*\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].Address != "*" || services[0].Family != "dual" || !services[0].IsWildcard {
		t.Fatalf("wildcard family was lost: %+v", services)
	}
}

func TestParseSSDataRejectsMalformedInventory(t *testing.T) {
	if _, err := ParseSSData("this is not ss output\n"); err == nil {
		t.Fatal("expected malformed inventory error")
	}
	services, err := ParseSSData("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n")
	if err != nil || len(services) != 0 {
		t.Fatalf("valid empty inventory should succeed: services=%+v err=%v", services, err)
	}
}

func TestParseSSDataWithNetidColumn(t *testing.T) {
	data := `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
udp   UNCONN 0      0            0.0.0.0:5353      0.0.0.0:*    users:(("avahi-daemon",pid=4,fd=12))
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=9,fd=3))
`
	services, err := ParseSSData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 2 || services[0].Protocol != "udp" || services[1].Protocol != "tcp" || services[1].Process != "sshd" {
		t.Fatalf("ss -tulnp rows were misparsed: %+v", services)
	}
}
