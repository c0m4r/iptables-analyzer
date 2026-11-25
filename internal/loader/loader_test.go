package loader

import (
	"os"
	"path/filepath"
	"strings"
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

func TestHostListsLoopback(t *testing.T) {
	host, err := Host()
	if err != nil {
		t.Skipf("interfaces unavailable: %v", err)
	}
	for _, iface := range host.Interfaces {
		if iface.Name == "lo" || strings.HasPrefix(iface.Name, "lo") {
			return
		}
	}
	t.Fatalf("expected a loopback interface, got %+v", host.Interfaces)
}

// iptables-save prints nothing when no rules are loaded. That is a ruleset
// in which every chain accepts, not unreadable input.
func TestOutputWithoutTablesIsARulesetWithoutRules(t *testing.T) {
	dir := t.TempDir()
	v4 := filepath.Join(dir, "rules.v4")
	v6 := filepath.Join(dir, "rules.v6")
	if err := os.WriteFile(v4, []byte("*filter\n:INPUT DROP [0:0]\nCOMMIT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v6, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ipv4, ipv6, err := Load(Config{IPv4File: v4, IPv6File: v6})
	if err != nil {
		t.Fatalf("an empty rules file must not be an error: %v", err)
	}
	if len(ipv4.Tables) != 1 || ipv6 == nil || len(ipv6.Tables) != 0 || ipv6.IPVersion != models.IPv6 {
		t.Fatalf("unexpected rulesets: ipv4=%+v ipv6=%+v", ipv4, ipv6)
	}
}

func TestFamilyWithoutFileIsNotLoaded(t *testing.T) {
	v4 := filepath.Join(t.TempDir(), "rules.v4")
	if err := os.WriteFile(v4, []byte("*filter\n:INPUT DROP [0:0]\nCOMMIT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ipv4, ipv6, err := Load(Config{IPv4File: v4})
	if err != nil {
		t.Fatal(err)
	}
	if ipv4 == nil || ipv6 != nil {
		t.Fatalf("a family without a file must stay unknown, not empty: ipv4=%+v ipv6=%+v", ipv4, ipv6)
	}
}

func TestLiveWarningsReachTheRuleset(t *testing.T) {
	ipv4, _, err := Parse(Sources{IPv4: &Source{Version: models.IPv4, Data: "",
		Warnings: []string{"iptables-legacy tables present, use iptables-legacy-save to see them"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ipv4.Warnings) != 1 || len(ipv4.Tables) != 0 {
		t.Fatalf("warning of the live tool was lost: %+v", ipv4)
	}
}

func TestUnrecognizedInputIsStillAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.v4")
	if err := os.WriteFile(path, []byte("this is not iptables-save output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(Config{IPv4File: path, IPv4Only: true}); err == nil {
		t.Fatal("unrecognized input was accepted")
	}
}
