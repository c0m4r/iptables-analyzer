package analyzer

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
	"github.com/c0m4r/iptables-analyzer/internal/services"
)

// blocklistRules builds a ruleset with n single-address rules. As a jail it
// has the shape fail2ban creates (a chain for port 22 that rejects banned
// addresses); otherwise the addresses are dropped at the top of INPUT, as
// CSF and hand-maintained deny lists do.
func blocklistRules(n int, jail bool) string {
	var b strings.Builder
	b.WriteString("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:f2b-sshd - [0:0]\n")
	// A fixed multiplicative walk spreads the addresses without a random source.
	address := func(i int) string {
		v := uint32(i+1) * 2654435761
		return fmt.Sprintf("%d.%d.%d.%d", 1+v>>24%223, v>>16&255, v>>8&255, 1+v&127)
	}
	if jail {
		b.WriteString("-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n")
	} else {
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "-A INPUT -s %s/32 -j DROP\n", address(i))
		}
	}
	b.WriteString("-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n")
	for _, port := range []int{22, 80, 443} {
		fmt.Fprintf(&b, "-A INPUT -p tcp -m tcp --dport %d -j ACCEPT\n", port)
	}
	if jail {
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "-A f2b-sshd -s %s/32 -j REJECT --reject-with icmp-port-unreachable\n", address(i))
		}
		b.WriteString("-A f2b-sshd -j RETURN\n")
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

const blocklistListeners = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
	"LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n" +
	"LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=2,fd=6))\n" +
	"LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=2,fd=7))\n"

func analyzeBlocklist(tb testing.TB, n int, jail bool) *models.AnalysisResult {
	tb.Helper()
	rs, err := parser.Parse(blocklistRules(n, jail), models.IPv4)
	if err != nil {
		tb.Fatal(err)
	}
	svcs, err := services.ParseSSData(blocklistListeners)
	if err != nil {
		tb.Fatal(err)
	}
	result := Analyze(rs, nil)
	CrossReferenceServices(result, svcs)
	return result
}

// Audit C4: analysis time grew with the square of the number of blocked
// addresses; 3,000 took 30 seconds. The bound is generous for slow machines
// and still fails for quadratic behavior.
func TestLargeBlocklistsAreAnalyzedQuickly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	for _, jail := range []bool{true, false} {
		start := time.Now()
		result := analyzeBlocklist(t, 20000, jail)
		elapsed := time.Since(start)
		if len(result.ExposedServices) != 3 {
			t.Fatalf("jail=%v: expected three exposed services, got %d", jail, len(result.ExposedServices))
		}
		for _, finding := range result.ExposedServices {
			if finding.Scope != models.ScopeExposed || finding.Certainty != models.CertaintyDefinite {
				t.Errorf("jail=%v: a blocklist must leave the service exposed: %+v", jail, finding)
			}
		}
		if elapsed > 10*time.Second {
			t.Errorf("jail=%v: 20,000 blocked addresses took %s", jail, elapsed)
		}
	}
}

func BenchmarkBlocklistJail5000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		analyzeBlocklist(b, 5000, true)
	}
}

func BenchmarkBlocklistInput5000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		analyzeBlocklist(b, 5000, false)
	}
}
