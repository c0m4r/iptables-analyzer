package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/report"
)

// writeTemp writes a file for one test and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func status(err error) int {
	return exitStatus(err, &bytes.Buffer{})
}

// --trace follows one packet instead of writing the report.
func TestTraceOption(t *testing.T) {
	ufw := []string{data("ufw.iptables-save"), data("ufw-services.txt")}
	text, err := run(t, testDependencies(false), append(ufw, "--trace", "tcp 203.0.113.5 -> :22 in eth0")...)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Packet", "tcp 203.0.113.5 → this host, port 22 · in eth0 · new connection · IPv4",
		"filter/INPUT", "ufw-user-input #3", "Verdict  ACCEPT by filter/ufw-user-limit-accept #1", "This host receives the packet on port 22."} {
		if !strings.Contains(text, want) {
			t.Errorf("the trace lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Grade") || strings.Contains(text, "Findings") {
		t.Errorf("the trace is printed alone, without the report:\n%s", text)
	}

	output, err := run(t, testDependencies(false), append(ufw, "--json", "--trace", "tcp 203.0.113.5 -> :5432")...)
	if err != nil {
		t.Fatal(err)
	}
	var result report.TraceReport
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	if result.SchemaVersion != report.SchemaVersion || result.Mode != "file" || len(result.Inputs) != 2 || result.Trace == nil ||
		result.Trace.Verdict != "DROP" || !result.Trace.Certain || result.Trace.Packet.Port != 5432 || len(result.Trace.Stages) == 0 {
		t.Errorf("JSON form of the trace: %s", output)
	}

	// --expect makes the trace a test of the rules.
	for name, c := range map[string]struct {
		args   []string
		status int
	}{
		"the verdict that is expected":        {[]string{"--trace", "tcp 203.0.113.5 -> :22", "--expect", "accept"}, 0},
		"case does not matter":                {[]string{"--trace", "tcp 203.0.113.5 -> :5432", "--expect", "DROP"}, 0},
		"another verdict":                     {[]string{"--trace", "tcp 203.0.113.5 -> :5432", "--expect", "accept"}, 2},
		"a source that the rule accepts":      {[]string{"--trace", "tcp 10.1.2.3 -> :5432", "--expect", "accept"}, 0},
		"--expect without --trace":            {[]string{"--expect", "drop"}, 1},
		"an unknown verdict":                  {[]string{"--trace", "tcp 203.0.113.5 -> :22", "--expect", "open"}, 1},
		"a packet without a port":             {[]string{"--trace", "tcp 203.0.113.5"}, 1},
		"an IPv6 packet without IPv6 rules":   {[]string{"--trace", "tcp 2001:db8::5 -> :22"}, 1},
		"a trace together with the HTML page": {[]string{"--trace", "tcp 203.0.113.5 -> :22", "--html", "x.html"}, 1},
		"a trace together with a threshold":   {[]string{"--trace", "tcp 203.0.113.5 -> :22", "--fail-on", "high"}, 1},
	} {
		_, err := run(t, testDependencies(false), append(append([]string{}, ufw...), c.args...)...)
		if got := status(err); got != c.status {
			t.Errorf("%s: status %d, want %d (%v)", name, got, c.status, err)
		}
	}

	// A verdict that depends on a rule that the packet does not decide is no
	// proof: the egress interface of the router is not known from its rules.
	_, err = run(t, testDependencies(false), data("router.iptables-save"), "--trace", "tcp 203.0.113.5 -> :8443 in eth0", "--expect", "drop")
	var threshold *thresholdError
	if !errors.As(err, &threshold) || !strings.Contains(err.Error(), "not certain") {
		t.Errorf("an uncertain verdict passed --expect: %v", err)
	}
	if _, err := run(t, testDependencies(false), data("router.iptables-save"),
		"--trace", "tcp 203.0.113.5 -> :8443 in eth0 out eth1", "--expect", "drop"); err == nil {
		t.Error("with the egress interface the router sends the packet on")
	}
}

// liveHost is a host with interfaces, kernel settings, a native nftables
// table and an ipset.
func liveHost(t *testing.T, rules string) commandDependencies {
	t.Helper()
	deps := liveDependencies(rules, "", ssListenBoth)
	deps.getHost = func() (*models.HostContext, error) {
		return &models.HostContext{Hostname: "web01", Interfaces: []models.HostInterface{
			{Name: "lo", Addrs: []string{"127.0.0.1/8", "::1/128"}, Up: true},
			{Name: "eth0", Addrs: []string{"192.0.2.10/24", "fe80::1/64"}, Up: true},
		}}, nil
	}
	deps.collectFacts = func(host *models.HostContext) loader.Facts {
		if host == nil || host.Hostname != "web01" {
			t.Error("the facts are read for the host whose interfaces were read")
		}
		return loader.Facts{
			Sysctls:   map[string]string{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"},
			NFTChains: "table inet custom {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n", HaveNFT: true,
			IPSets: "create trusted hash:net family inet\nadd trusted 10.0.0.0/8\n", HaveIPSets: true,
		}
	}
	return deps
}

const rulesWithSet = `*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -m set --match-set trusted src -j ACCEPT
COMMIT
`

// The facts about a live host reach the report, and a snapshot of the host
// gives the same report on another machine.
func TestSnapshotGivesTheReportOfTheLiveHost(t *testing.T) {
	file := &memoryFile{}
	deps := liveHost(t, rulesWithSet)
	deps.createFile = func(path string) (io.WriteCloser, error) {
		if path != "host.json" {
			t.Errorf("opened %q", path)
		}
		return file, nil
	}
	live := runReport(t, deps, "--snapshot", "host.json")
	if live.Mode != "live" || live.Host != "web01" {
		t.Fatalf("live report: %s %s", live.Mode, live.Host)
	}
	// What the facts tell: the set is evaluated, the native table makes the
	// result incomplete, and FORWARD has no effect without routing.
	if ssh := live.OpenPorts[0]; len(ssh.Families) != 1 || ssh.Families[0] != 4 || ssh.First != 22 || ssh.Scope != models.ScopeLocalnet || ssh.Restriction != "" {
		t.Errorf("the ipset was not evaluated: %+v", ssh)
	}
	incomplete, forward := 0, ""
	for _, note := range live.Notes {
		if note.Kind == "incomplete" && strings.Contains(note.Text, "nftables table inet custom") {
			incomplete++
		}
	}
	for _, finding := range live.Findings {
		if strings.Contains(finding.Title, "FORWARD") {
			forward = finding.Severity.String()
		}
	}
	if incomplete != 1 || live.Score.Complete || forward != "INFO" {
		t.Errorf("native table notes %d, complete %v, FORWARD finding %q", incomplete, live.Score.Complete, forward)
	}

	if !file.truncated || !file.closed || !strings.Contains(file.String(), `"format": "iptables-analyzer snapshot"`) {
		t.Fatalf("the snapshot was not written: %q", file.String()[:min(file.Len(), 80)])
	}
	path := writeTemp(t, "host.json", file.String())
	offline := runReport(t, testDependencies(false), path)
	if offline.Mode != "snapshot" || offline.Host != "web01" || offline.Captured != "2026-11-25T12:00:00Z" {
		t.Errorf("header of the snapshot report: %s %s %s", offline.Mode, offline.Host, offline.Captured)
	}
	// Only what names the input differs.
	offline.Mode, offline.Captured, offline.Inputs = live.Mode, live.Captured, live.Inputs
	if !reflect.DeepEqual(live, offline) {
		a, _ := json.MarshalIndent(live, "", " ")
		b, _ := json.MarshalIndent(offline, "", " ")
		t.Errorf("the report of the snapshot differs from that of the live host:\nlive:\n%s\nsnapshot:\n%s", a, b)
	}

	// The text header names the snapshot.
	text, err := run(t, testDependencies(false), path)
	if err != nil || !strings.Contains(text, "snapshot of web01 from 2026-11-25 12:00") {
		t.Errorf("text header: %v\n%s", err, text[:min(len(text), 200)])
	}
	// A family can be left out of a snapshot, and a packet can be traced in it.
	if rep := runReport(t, testDependencies(false), "-4", path); family(rep, 6).Status != string(models.FamilyExcluded) {
		t.Errorf("-4 with a snapshot: %+v", rep.Families)
	}
	if _, err := run(t, testDependencies(false), path, "--trace", "tcp 10.1.2.3 -> 192.0.2.10:22 in eth0", "--expect", "accept"); err != nil {
		t.Errorf("a member of the set is accepted: %v", err)
	}
	if _, err := run(t, testDependencies(false), path, "--trace", "tcp 203.0.113.5 -> 192.0.2.10:22 in eth0", "--expect", "drop"); err != nil {
		t.Errorf("another source is dropped: %v", err)
	}

	for name, args := range map[string][]string{
		"a snapshot with a rules file":      {path, data("basic.iptables-save")},
		"a snapshot with --file":            {path, "--file", data("basic.iptables-save")},
		"a snapshot with a list of sockets": {path, "--services-file", data("services.txt")},
		"a broken snapshot":                 {writeTemp(t, "bad.json", `{"format":"iptables-analyzer snapshot","version":99}`)},
		"a snapshot without rules":          {writeTemp(t, "empty.json", `{"format":"iptables-analyzer snapshot","version":1}`)},
		"the snapshot as its own output":    {path, "--snapshot", path},
	} {
		if _, err := run(t, testDependencies(false), args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A snapshot can be made from files as well. It keeps what they hold.
func TestSnapshotOfFiles(t *testing.T) {
	file := &memoryFile{}
	deps := testDependencies(false)
	deps.createFile = func(string) (io.WriteCloser, error) { return file, nil }
	args := []string{data("docker29.iptables-save"), data("docker29.ip6tables-save"), data("services.txt")}
	want := runReport(t, deps, append(args, "--snapshot", "s.json")...)
	got := runReport(t, testDependencies(false), writeTemp(t, "s.json", file.String()))
	if got.Mode != "snapshot" || got.Score.Total != want.Score.Total || len(got.Findings) != len(want.Findings) ||
		len(got.Services) != len(want.Services) || len(got.Forwards) != len(want.Forwards) {
		t.Errorf("the snapshot of the files gives another report: %d/%d points, %d/%d findings", got.Score.Total, want.Score.Total,
			len(got.Findings), len(want.Findings))
	}
}

// --ipset-file names the contents of the sets of saved rules.
func TestIPSetFileOption(t *testing.T) {
	rules := writeTemp(t, "rules.v4", rulesWithSet)
	without := runReport(t, testDependencies(false), rules)
	if len(without.OpenPorts) != 1 || without.OpenPorts[0].Scope != models.ScopeRestricted || without.OpenPorts[0].Restriction != "ipset trusted" {
		t.Fatalf("without the contents the port is restricted to an unknown set: %+v", without.OpenPorts)
	}
	sets := writeTemp(t, "sets.txt", "create trusted hash:net family inet hashsize 1024 maxelem 65536\nadd trusted 198.51.100.0/24\n")
	with := runReport(t, testDependencies(false), rules, "--ipset-file", sets)
	if len(with.OpenPorts) != 1 || with.OpenPorts[0].Scope != models.ScopeSubnet || len(with.Inputs) != 2 {
		t.Errorf("with the contents the port is open to the network of the set: %+v, inputs %v", with.OpenPorts, with.Inputs)
	}
	if _, err := run(t, testDependencies(false), rules, "--ipset-file", writeTemp(t, "bad.txt", "this is not ipset output\n")); err == nil ||
		!strings.Contains(err.Error(), "ipsets") {
		t.Errorf("a file that is no ipset output was accepted: %v", err)
	}
	if _, err := run(t, testDependencies(false), rules, "--ipset-file", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file was accepted")
	}
}

// The output of "iptables -S" is read like that of iptables-save.
func TestListingAsInput(t *testing.T) {
	listing := "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n" +
		"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
	rep := runReport(t, testDependencies(false), writeTemp(t, "listing.txt", listing))
	if family(rep, 4).Status != string(models.FamilyAnalyzed) || family(rep, 4).Rules != 3 || len(rep.OpenPorts) != 1 || rep.OpenPorts[0].First != 22 {
		t.Errorf("listing: %+v %+v", rep.Families, rep.OpenPorts)
	}
	six := runReport(t, testDependencies(false), writeTemp(t, "listing6.txt", strings.Replace(listing, "-i lo", "-s ::1/128 -i lo", 1)))
	if family(six, 6).Status != string(models.FamilyAnalyzed) || family(six, 4).Status != string(models.FamilyNotSupplied) {
		t.Errorf("a listing with an IPv6 address holds IPv6 rules: %+v", six.Families)
	}
}

// --diff says what a change of the rules changes.
func TestDiffOption(t *testing.T) {
	before := fixtureText(t, "basic.iptables-save")
	after := strings.Replace(before, "-A INPUT -p tcp --dport 80 -j ACCEPT\n",
		"-A INPUT -s 10.0.0.0/8 -p tcp --dport 80 -j ACCEPT\n-A INPUT -p tcp --dport 3306 -j ACCEPT\n", 1)
	oldFile, newFile := writeTemp(t, "old.v4", before), writeTemp(t, "new.v4", after)

	output, err := run(t, testDependencies(false), "--diff", "--json", oldFile, newFile)
	if err != nil {
		t.Fatal(err)
	}
	var diff report.Diff
	if err := json.Unmarshal([]byte(output), &diff); err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	titles := func(findings []report.Finding) string {
		var list []string
		for _, finding := range findings {
			list = append(list, finding.Title)
		}
		return strings.Join(list, "; ")
	}
	if got := titles(diff.Added); got != "3306/tcp is open to any source" {
		t.Errorf("new findings: %q", got)
	}
	if got := titles(diff.Removed); got != "80/tcp is open to any source" {
		t.Errorf("findings that are gone: %q", got)
	}
	if len(diff.Changed) != 0 || len(diff.Forwards) != 0 || len(diff.Old.Inputs) != 1 || len(diff.New.Inputs) != 1 {
		t.Errorf("changed %+v, forwards %+v", diff.Changed, diff.Forwards)
	}
	var ports []string
	for _, port := range diff.Ports {
		ports = append(ports, strings.Join([]string{port.Protocol, portRangeText(port.First, port.Last), string(port.Old.Scope), string(port.New.Scope)}, " "))
	}
	if got := strings.Join(ports, "; "); got != "tcp 80 EXPOSED LOCALNET; tcp 3306  EXPOSED" {
		t.Errorf("ports: %q", got)
	}

	text, err := run(t, testDependencies(false), "--diff", oldFile, newFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"comparison", "old: " + oldFile, "New findings", "3306/tcp is open to any source", "Findings that are gone",
		"any source → private networks", "closed → any source", "Grade A"} {
		if !strings.Contains(text, want) {
			t.Errorf("the comparison lacks %q:\n%s", want, text)
		}
	}
	line, err := run(t, testDependencies(false), "--diff", "--quiet", oldFile, newFile)
	if err != nil || !strings.HasSuffix(line, "1 new finding, 1 finding gone, 2 port ranges changed\n") {
		t.Errorf("--quiet: %q %v", line, err)
	}
	same, err := run(t, testDependencies(false), "--diff", "--quiet", oldFile, oldFile)
	if err != nil || !strings.HasSuffix(same, "no difference\n") {
		t.Errorf("the same input twice: %q %v", same, err)
	}

	// The thresholds judge what the new input adds.
	for name, c := range map[string]struct {
		args   []string
		status int
	}{
		"a new high finding":              {[]string{"--fail-on", "high", oldFile, newFile}, 2},
		"no new critical finding":         {[]string{"--fail-on", "critical", oldFile, newFile}, 0},
		"the findings of the old input":   {[]string{"--fail-on", "low", newFile, oldFile}, 2},
		"nothing new":                     {[]string{"--fail-on", "low", oldFile, oldFile}, 0},
		"the grade of the new input":      {[]string{"--min-grade", "A", oldFile, newFile}, 2},
		"one file":                        {[]string{oldFile}, 1},
		"three files":                     {[]string{oldFile, newFile, oldFile}, 1},
		"together with --html":            {[]string{"--html", "x.html", oldFile, newFile}, 1},
		"a file that is no rules file":    {[]string{oldFile, data("services.txt")}, 1},
		"a file that does not exist":      {[]string{oldFile, filepath.Join(t.TempDir(), "missing")}, 1},
		"together with --services-file":   {[]string{"--services-file", data("services.txt"), oldFile, newFile}, 1},
		"a snapshot against a rules file": {[]string{oldFile, newFile, "--quiet"}, 0},
	} {
		_, err := run(t, testDependencies(false), append([]string{"--diff"}, c.args...)...)
		if got := status(err); got != c.status {
			t.Errorf("%s: status %d, want %d (%v)", name, got, c.status, err)
		}
	}
}

func portRangeText(first, last int) string {
	if last > first {
		return strconv.Itoa(first) + "-" + strconv.Itoa(last)
	}
	return strconv.Itoa(first)
}
