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
