package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// FuzzAnalysis runs the whole command (parsing, analysis, the report with its
// fixes and its score, the baseline, and the text and HTML forms) on
// arbitrary rules and ss output. It must not panic, and a --no-color report
// must not contain any character that a terminal interprets: input text can
// only reach it escaped. The markup of the HTML form has its own fuzz target
// in internal/ui.
func FuzzAnalysis(f *testing.F) {
	ss, err := os.ReadFile(filepath.Join("..", "testdata", "services.txt"))
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range []string{"basic.iptables-save", "docker.iptables-save", "docker29.iptables-save", "insecure.iptables-save", "ufw.iptables-save",
		"k8s.iptables-save", "router.iptables-save", "libvirt.iptables-save", "firewalld.iptables-save", "fail2ban.iptables-save"} {
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
		page := &memoryFile{}
		deps.createFile = func(string) (io.WriteCloser, error) { return page, nil }
		var out bytes.Buffer
		command := newRootCommand(deps)
		command.SetOut(&out)
		command.SetErr(&bytes.Buffer{})
		command.SetArgs([]string{"-4", "--no-color", "--verbose", "--rules", "--html", "page", "-f", "rules", "--services-file", "ss"})
		if err := command.Execute(); err != nil {
			return // malformed input is rejected, which is fine
		}
		report := out.String()
		if !utf8.ValidString(report) || !utf8.Valid(page.Bytes()) {
			t.Fatal("report is not valid UTF-8")
		}
		if !bytes.HasSuffix(page.Bytes(), []byte("</html>\n")) {
			t.Fatal("the HTML report is not complete")
		}
		for _, r := range report {
			if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029') {
				t.Fatalf("report contains control character %U", r)
			}
		}
	})
}

// printable fails when text for a terminal holds a character that the
// terminal interprets.
func printable(t *testing.T, what, text string) {
	t.Helper()
	if !utf8.ValidString(text) {
		t.Fatalf("%s is not valid UTF-8", what)
	}
	for _, r := range text {
		if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029') {
			t.Fatalf("%s contains control character %U", what, r)
		}
	}
}

// FuzzQueries runs the two questions besides the report on arbitrary input:
// the way of a packet (--trace) through arbitrary rules, and the comparison
// (--diff) of arbitrary rules with a fixture. A file can also be a snapshot.
// Nothing may panic, and the text may not hold what a terminal interprets.
func FuzzQueries(f *testing.F) {
	for _, name := range []string{"ufw.iptables-save", "k8s.iptables-save", "router.iptables-save", "router.snapshot.json"} {
		rules, err := os.ReadFile(filepath.Join("..", "testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(rules), "tcp 203.0.113.5 -> :22 in eth0")
		f.Add(string(rules), "udp 10.1.2.3:53 -> 192.0.2.1:5353 in eth1 out eth0 state NEW")
	}
	f.Add("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i \"\x1b[31m\" -m comment --comment \"\u202e\x9b2J\" -j ACCEPT\n", "icmp 203.0.113.5 in \x1b[0m type 8")
	f.Add("*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp -j REDIRECT --to-ports 1\x07\nCOMMIT\n", "tcp [2001:db8::1]:1 -> [2001:db8::2]:2")
	base, err := os.ReadFile(filepath.Join("..", "testdata", "basic.iptables-save"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input, packet string) {
		deps := testDependencies(false)
		deps.readFile = func(path string) ([]byte, error) {
			if path == "base" {
				return base, nil
			}
			return []byte(input), nil
		}
		for _, args := range [][]string{
			{"--no-color", "--verbose", "--trace", packet, "input"},
			{"--no-color", "--verbose", "--diff", "base", "input"},
			{"--no-color", "--verbose", "--diff", "input", "base"},
		} {
			var out bytes.Buffer
			command := newRootCommand(deps)
			command.SetOut(&out)
			command.SetErr(&bytes.Buffer{})
			command.SetArgs(args)
			if err := command.Execute(); err != nil {
				var threshold *thresholdError
				if !errors.As(err, &threshold) {
					continue // input that is refused is fine
				}
			}
			printable(t, args[2], out.String())
		}
	})
}
