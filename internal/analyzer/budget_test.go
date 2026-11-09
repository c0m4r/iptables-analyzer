package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
)

// jumpFanOut builds chains that each jump twice to the next one behind an
// undecidable mark match: exact evaluation needs 2^depth traversals.
func jumpFanOut(depth int) string {
	var b strings.Builder
	b.WriteString("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n")
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, ":C%d - [0:0]\n", i)
	}
	b.WriteString("-A INPUT -j C0\n-A FORWARD -j C0\n")
	for i := 0; i+1 < depth; i++ {
		fmt.Fprintf(&b, "-A C%d -m mark --mark 0x%x -j C%d\n-A C%d -j C%d\n", i, i+1, i+1, i, i+1)
	}
	fmt.Fprintf(&b, "-A C%d -p tcp --dport 22 -m mark --mark 0x99 -j ACCEPT\nCOMMIT\n", depth-1)
	b.WriteString("*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n:DOCKER - [0:0]\n")
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, ":N%d - [0:0]\n", i)
	}
	b.WriteString("-A PREROUTING -j N0\n")
	for i := 0; i+1 < depth; i++ {
		fmt.Fprintf(&b, "-A N%d -m mark --mark 0x%x -j N%d\n-A N%d -j N%d\n", i, i+1, i+1, i, i+1)
	}
	fmt.Fprintf(&b, "-A N%d -m addrtype --dst-type LOCAL -j DOCKER\n", depth-1)
	b.WriteString("-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\n")
	b.WriteString("-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80\nCOMMIT\n")
	return b.String()
}

func TestCraftedJumpFanOutIsBounded(t *testing.T) {
	saved := maxChainVisits
	maxChainVisits = 1 << 10
	defer func() { maxChainVisits = saved }()

	rs, err := parser.Parse(jumpFanOut(40), models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	result := AnalyzeHost(rs, nil, nil)
	CrossReferenceServices(result, []models.ListeningService{{
		Protocol: models.ProtoTCP, Address: "0.0.0.0", Port: 22, IsWildcard: true, Family: models.SocketIPv4, Process: "sshd",
	}})
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("bounded analysis took %s", elapsed)
	}
	areas := map[string]bool{}
	for _, diagnostic := range result.Diagnostics {
		if strings.Contains(diagnostic.Message, "too often to evaluate exactly") {
			areas[diagnostic.Area] = true
		}
	}
	if !areas["docker"] || !areas["services"] {
		t.Fatalf("expected limit diagnostics for docker and services, got %+v", result.Diagnostics)
	}
	if len(result.Services) != 1 || result.Services[0].Status == models.ServiceFiltered {
		t.Fatalf("a truncated evaluation must not claim that the listener is filtered: %+v", result.Services)
	}
}

func TestRealCapturesStayWithinTheBound(t *testing.T) {
	saved := maxChainVisits
	maxChainVisits = 1 << 12 // 20x what the captures need
	defer func() { maxChainVisits = saved }()
	for _, name := range []string{"docker29.iptables-save", "docker29.ip6tables-save", "docker.iptables-save"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		version := models.IPv4
		if strings.Contains(name, "ip6") {
			version = models.IPv6
		}
		rs, err := parser.Parse(string(data), version)
		if err != nil {
			t.Fatal(err)
		}
		var result *models.AnalysisResult
		if version == models.IPv4 {
			result = AnalyzeHost(rs, nil, nil)
		} else {
			result = AnalyzeHost(nil, rs, nil)
		}
		for _, diagnostic := range result.Diagnostics {
			if strings.Contains(diagnostic.Message, "too often") {
				t.Fatalf("%s hit the traversal bound: %s", name, diagnostic.Message)
			}
		}
	}
}
