package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// FuzzAnalysis runs the whole command (parsing, analysis, recommendations,
// baseline, scoring and rendering) on arbitrary rules and ss output. It must
// not panic, and a --no-color report must not contain any character that a
// terminal interprets: input text can only reach it escaped.
func FuzzAnalysis(f *testing.F) {
	ss, err := os.ReadFile(filepath.Join("..", "testdata", "services.txt"))
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range []string{"basic.iptables-save", "docker.iptables-save", "docker29.iptables-save", "insecure.iptables-save"} {
		rules, err := os.ReadFile(filepath.Join("..", "testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(rules), string(ss))
	}
	f.Add("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -i \"\x1b[31m\" -p tcp --dport 22 -m comment --comment \"\u202e\x9b2J\" -j ACCEPT\nCOMMIT\n",
		"State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 1 0.0.0.0:22 0.0.0.0:* users:((\"\x1b]0;x\x07\",pid=1,fd=3))\n")
	f.Fuzz(func(t *testing.T, rules, ssData string) {
		deps := testDependencies(false)
		deps.readRules = func(loader.Config) (loader.Sources, error) {
			return loader.Sources{IPv4: &loader.Source{Version: models.IPv4, Data: rules}}, nil
		}
		deps.readServices = func(string) (string, error) { return ssData, nil }
		var out bytes.Buffer
		command := newRootCommand(deps)
		command.SetOut(&out)
		command.SetErr(&bytes.Buffer{})
		command.SetArgs([]string{"-4", "--no-color", "--verbose", "-f", "rules", "--services-file", "ss"})
		if err := command.Execute(); err != nil {
			return // malformed input is rejected, which is fine
		}
		report := out.String()
		if !utf8.ValidString(report) {
			t.Fatal("report is not valid UTF-8")
		}
		for _, r := range report {
			if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029') {
				t.Fatalf("report contains control character %U", r)
			}
		}
	})
}
