package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

func TestExplicitIPv6FileErrorIsFatal(t *testing.T) {
	_, _, err := Load(Config{IPv6File: filepath.Join(t.TempDir(), "missing.v6")})
	if err == nil {
		t.Fatal("expected an explicit IPv6 file error")
	}
}

func TestLoadIPv4File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.v4")
	data := []byte("*filter\n:INPUT DROP [0:0]\nCOMMIT\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ipv4, ipv6, err := Load(Config{IPv4File: path, IPv4Only: true})
	if err != nil {
		t.Fatal(err)
	}
	if ipv4 == nil || ipv4.IPVersion != models.IPv4 || ipv6 != nil {
		t.Fatalf("unexpected rulesets: ipv4=%+v ipv6=%+v", ipv4, ipv6)
	}
}
