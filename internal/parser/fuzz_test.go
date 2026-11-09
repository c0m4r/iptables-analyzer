package parser

import (
	"os"
	"path/filepath"
	"testing"
	"unicode"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

func addTestdataSeeds(f *testing.F, pattern string) {
	f.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", pattern))
	if err != nil {
		f.Fatal(err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(data))
	}
}

func hasControl(s string) bool {
	for _, r := range s {
		if r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			return true
		}
	}
	return false
}

// FuzzParse checks that arbitrary input never panics the parser and that no
// control character survives into rule text that is later displayed.
func FuzzParse(f *testing.F) {
	addTestdataSeeds(f, "*.iptables-save")
	addTestdataSeeds(f, "*.ip6tables-save")
	f.Add("*filter\n:INPUT DROP [0:0]\n-A INPUT -m comment --comment \"\x1b]52;c;aGk=\x07\" -j ACCEPT\nCOMMIT\n")
	f.Fuzz(func(t *testing.T, data string) {
		for _, version := range []models.IPVersion{models.IPv4, models.IPv6} {
			rs, _ := Parse(data, version)
			if rs == nil {
				t.Fatal("Parse returned no ruleset")
			}
			for name, table := range rs.Tables {
				if hasControl(name) {
					t.Fatalf("control character in table name %q", name)
				}
				for chainName, chain := range table.Chains {
					if hasControl(chainName) {
						t.Fatalf("control character in chain name %q", chainName)
					}
					for _, rule := range chain.Rules {
						if hasControl(rule.RawLine) || hasControl(rule.Comment) || hasControl(rule.InIface) {
							t.Fatalf("control character in rule %q", rule.RawLine)
						}
					}
				}
			}
		}
	})
}
