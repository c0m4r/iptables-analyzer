package report

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// ssRows returns the rows of a saved ss output, without its header.
func ssRows(t *testing.T, name string) []string {
	t.Helper()
	var rows []string
	for _, line := range strings.Split(fixture(t, name), "\n") {
		if line != "" && !strings.HasPrefix(line, "Netid") && !strings.HasPrefix(line, "State") {
			rows = append(rows, line)
		}
	}
	return rows
}

// The JSON form is the documented interface for other programs: every key is
// lower case with underscores, and the values that are names are text.
func TestJSONForm(t *testing.T) {
	rep := build(t, fixture(t, "docker29.iptables-save"), fixture(t, "docker29.ip6tables-save"), ssRows(t, "services.txt"),
		Options{Version: "1.2.3", Inputs: []string{"rules.v4", "rules.v6", "ss.txt"}})
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "tool", "generated", "mode", "inputs", "families", "score", "counts", "findings",
		"open_ports", "forwarded_ports", "services_known", "services", "notes", "baseline", "rulesets"} {
		if key == "baseline" {
			continue // only when the caller supplies one
		}
		if _, ok := generic[key]; !ok {
			t.Errorf("the report has no %q", key)
		}
	}
	if generic["schema_version"] != float64(SchemaVersion) || generic["mode"] != "file" || generic["generated"] != "2026-11-25T12:00:00Z" {
		t.Errorf("header: %v %v %v", generic["schema_version"], generic["mode"], generic["generated"])
	}

	var walk func(path string, value any)
	walk = func(path string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				// The policies are keyed by the names of the chains.
				if !strings.HasSuffix(path, ".policies") {
					for _, r := range key {
						if !unicode.IsLower(r) && !unicode.IsDigit(r) && r != '_' {
							t.Errorf("%s.%s is not lower case with underscores", path, key)
							break
						}
					}
				}
				walk(path+"."+key, child)
			}
		case []any:
			for _, child := range typed {
				walk(path+"[]", child)
			}
		}
	}
	walk("", generic)

	findings := generic["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("no findings")
	}
	for _, entry := range findings {
		finding := entry.(map[string]any)
		severity, _ := finding["severity"].(string)
		if !strings.Contains("CRITICAL HIGH MEDIUM LOW INFO", severity) || severity == "" {
			t.Errorf("severity is %v, not a name", finding["severity"])
		}
		for _, key := range []string{"id", "code", "certainty", "category", "title", "detail", "points", "gain"} {
			if _, ok := finding[key]; !ok {
				t.Errorf("finding %v has no %q", finding["id"], key)
			}
		}
		for _, hidden := range []string{"key", "order", "ceiling"} {
			if _, ok := finding[hidden]; ok {
				t.Errorf("finding %v shows the internal field %q", finding["id"], hidden)
			}
		}
	}

	// The form can be read back.
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Findings) != len(rep.Findings) || back.Findings[0].Severity != rep.Findings[0].Severity {
		t.Fatalf("round trip lost findings")
	}
	if back.Score.Total != rep.Score.Total || back.Score.Grade != rep.Score.Grade {
		t.Fatalf("round trip changed the score")
	}
}

func TestHeaderDescribesTheInput(t *testing.T) {
	rep := build(t, fixture(t, "docker29.iptables-save"), fixture(t, "docker29.ip6tables-save"), nil, Options{Version: "1.2.3"})
	if rep.Tool.Name != "iptables-analyzer" || rep.Tool.Version != "1.2.3" || rep.Tool.URL == "" || len(rep.Families) != 2 {
		t.Fatalf("%+v %+v", rep.Tool, rep.Families)
	}
	v4 := rep.Families[0]
	if v4.Version != 4 || v4.Status != string(models.FamilyAnalyzed) || v4.Rules != 55 || v4.Chains != 24 || v4.Tables != 5 ||
		v4.Policies["INPUT"] != "ACCEPT" || v4.Policies["FORWARD"] != "DROP" || len(v4.Managers) != 1 || v4.Managers[0] != "docker" {
		t.Fatalf("IPv4: %+v", v4)
	}

	// A family that was not supplied is named, with nothing counted.
	result := analyzer.Analyze(parse(t, fixture(t, "ufw.iptables-save"), models.IPv4), nil)
	result.IPv6Status, result.IPv4Only = models.FamilyNotSupplied, true
	result.Host = &models.HostContext{Hostname: "gate"}
	rep = Build(result, Options{Now: testTime, Live: true})
	if rep.Mode != "live" || rep.Host != "gate" || rep.Families[1].Status != string(models.FamilyNotSupplied) || rep.Families[1].Rules != 0 {
		t.Fatalf("mode %s host %s families %+v", rep.Mode, rep.Host, rep.Families)
	}
	if got := rep.Families[0].Managers; len(got) != 1 || got[0] != "ufw" {
		t.Fatalf("managers: %v", got)
	}
	for _, finding := range rep.Findings {
		for _, family := range finding.Families {
			if family == 6 {
				t.Fatalf("finding about a family that was not read: %s", finding.Title)
			}
		}
	}
}

// The rule lists name the findings of each rule, so that a reader of the
// rules sees what is wrong with them.
func TestRulesNameTheirFindings(t *testing.T) {
	rep := build(t, fixture(t, "insecure.iptables-save"), "", nil, Options{})
	if len(rep.Rulesets) != 1 || rep.Rulesets[0].Family != 4 || rep.Rulesets[0].Tables[0].Name != "filter" {
		t.Fatalf("%+v", rep.Rulesets)
	}
	chains := rep.Rulesets[0].Tables[0].Chains
	if chains[0].Name != "INPUT" || chains[0].Policy != "ACCEPT" || len(chains[0].Rules) != 5 {
		t.Fatalf("first chain: %+v", chains[0])
	}
	byID := map[string]Finding{}
	for _, finding := range rep.Findings {
		byID[finding.ID] = finding
	}
	named := 0
	for _, rule := range chains[0].Rules {
		for _, id := range rule.Findings {
			named++
			found := false
			for _, ref := range byID[id].Rules {
				found = found || (ref.Chain == "INPUT" && ref.Num == rule.Num)
			}
			if !found {
				t.Errorf("rule #%d names %s, which does not name the rule", rule.Num, id)
			}
		}
	}
	if named < 3 {
		t.Fatalf("too few rules name a finding: %+v", chains[0].Rules)
	}
	if rule := chains[0].Rules[0]; rule.Spec != "-p tcp --dport 22 -j ACCEPT" || rule.Target != "ACCEPT" || rule.Jump {
		t.Fatalf("first rule: %+v", rule)
	}

	// Built-in chains come first, and a jump to a chain of the table is marked.
	rep = build(t, fixture(t, "ufw.iptables-save"), "", nil, Options{})
	chains = rep.Rulesets[0].Tables[0].Chains
	if chains[0].Name != "INPUT" || chains[1].Name != "FORWARD" || chains[2].Name != "OUTPUT" || chains[3].Policy != "" {
		t.Fatalf("order of chains: %s %s %s %s", chains[0].Name, chains[1].Name, chains[2].Name, chains[3].Name)
	}
	if !chains[0].Rules[0].Jump || chains[3].Owner != "ufw" {
		t.Fatalf("jump %v owner %q", chains[0].Rules[0].Jump, chains[3].Owner)
	}
}

func TestOpenPortsTable(t *testing.T) {
	rep := build(t, fixture(t, "ufw.iptables-save"), "", ssRows(t, "ufw-services.txt"), Options{})
	got := map[string]OpenPort{}
	for _, open := range rep.OpenPorts {
		got[portText(models.Protocol(open.Protocol), open.First, open.Last)] = open
	}
	if len(got) != 5 {
		t.Fatalf("expected five open ports: %+v", rep.OpenPorts)
	}
	if ssh := got["22/tcp"]; ssh.Scope != models.ScopeExposed || ssh.Condition != "rate limit" || len(ssh.Listeners) != 1 || ssh.Listeners[0] != "sshd" || len(ssh.Rules) != 1 {
		t.Errorf("22/tcp: %+v", ssh)
	}
	if db := got["5432/tcp"]; db.Scope != models.ScopeLocalnet || db.Listeners[0] != "postgres" {
		t.Errorf("5432/tcp: %+v", db)
	}
	if dhcp := got["68/udp"]; dhcp.Condition != "source port 67" || dhcp.Listeners[0] != "systemd-network" {
		t.Errorf("68/udp: %+v", dhcp)
	}

	// A chain that accepts by default is one entry for each protocol, and the
	// ports that a rule opens in the same way are not listed next to it.
	rep = build(t, policies("ACCEPT", "DROP")+"-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n", "", nil, Options{})
	defaults := 0
	for _, open := range rep.OpenPorts {
		if open.Default {
			defaults++
			if open.First != 0 || len(open.Rules) != 0 || open.Scope != models.ScopeExposed {
				t.Errorf("default entry: %+v", open)
			}
		}
	}
	if defaults != 2 {
		t.Fatalf("expected the default entries for tcp and udp: %+v", rep.OpenPorts)
	}

	// The same entry for both address families is one entry.
	rules := filterRules("-A INPUT -p tcp --dport 443 -j ACCEPT")
	rep = build(t, rules, rules, nil, Options{})
	if len(rep.OpenPorts) != 1 || len(rep.OpenPorts[0].Families) != 2 || len(rep.OpenPorts[0].Rules) != 2 {
		t.Fatalf("%+v", rep.OpenPorts)
	}
}

func TestServicesTable(t *testing.T) {
	rep := build(t, fixture(t, "ufw.iptables-save"), "", ssRows(t, "ufw-services.txt"), Options{})
	if !rep.ServicesKnown || len(rep.Services) != 7 {
		t.Fatalf("known=%v services=%d", rep.ServicesKnown, len(rep.Services))
	}
	for _, svc := range rep.Services {
		switch svc.Port {
		case 22, 80, 443:
			if svc.Status != models.ServiceReachable || svc.Scope != models.ScopeExposed {
				t.Errorf("%d: %s %s", svc.Port, svc.Status, svc.Scope)
			}
		case 5432:
			if svc.Status != models.ServiceReachable || svc.Scope != models.ScopeLocalnet {
				t.Errorf("5432: %s %s", svc.Status, svc.Scope)
			}
		case 6379, 53:
			if svc.Status != models.ServiceLocalhost || svc.Scope != "" {
				t.Errorf("%d: %s %s", svc.Port, svc.Status, svc.Scope)
			}
		}
	}
}

func TestNotesSayWhatTheAnalysisLeftOut(t *testing.T) {
	result := analyzer.Analyze(parse(t, fixture(t, "basic.iptables-save"), models.IPv4), nil)
	result.IPv6Status, result.IPv4Only = models.FamilyNotSupplied, true
	result.Notes = []string{"IPv6 rules were not supplied: only IPv4 was analyzed."}
	result.Diagnostics = append(result.Diagnostics, models.AssessmentDiagnostic{Area: "rules", Message: "legacy tables are present"})
	rep := Build(result, Options{Now: testTime})
	kinds := map[string]int{}
	for _, note := range rep.Notes {
		kinds[note.Kind]++
	}
	if kinds["incomplete"] != 1 || kinds["scope"] != 2 {
		t.Fatalf("notes: %+v", rep.Notes)
	}
	if rep.Score.Complete || rep.Score.Grade != "INCOMPLETE" || len(rep.Score.Unassessed) != 1 {
		t.Fatalf("score: %+v", rep.Score)
	}
}
