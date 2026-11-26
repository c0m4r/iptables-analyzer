package parser

import (
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The output of "iptables -S": no table line, policies as -P lines.
const filterListing = `-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N f2b-sshd
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -c 12 3456 -j ACCEPT
-A f2b-sshd -s 198.51.100.23/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -j RETURN
`

const natListing = `-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080
`

func TestParseListing(t *testing.T) {
	rs, err := Parse(filterListing, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	filter := rs.Tables["filter"]
	if len(rs.Tables) != 1 || filter == nil {
		t.Fatalf("a listing with INPUT, FORWARD and OUTPUT is the filter table: %v", rs.Tables)
	}
	if filter.Chains["INPUT"].Policy != "DROP" || filter.Chains["OUTPUT"].Policy != "ACCEPT" || filter.Chains["f2b-sshd"].Policy != "" {
		t.Errorf("policies: %+v", filter.Chains)
	}
	input := filter.Chains["INPUT"].Rules
	if len(input) != 4 || input[3].DstPort != "22" || input[3].Target != "ACCEPT" || input[0].Target != "f2b-sshd" {
		t.Errorf("rules of INPUT: %+v", input)
	}
	if len(filter.Chains["f2b-sshd"].Rules) != 2 {
		t.Errorf("rules of the user-defined chain: %+v", filter.Chains["f2b-sshd"].Rules)
	}
}

func TestParseListingsOfSeveralTables(t *testing.T) {
	raw := "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 7002 -j NOTRACK\n"
	mangle := "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n"
	security := "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
	rs, err := Parse(filterListing+natListing+raw+mangle+security, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"filter", "nat", "raw", "mangle", "security"} {
		if rs.Tables[name] == nil {
			t.Errorf("table %s is missing: %v", name, rs.Tables)
		}
	}
	if rules := rs.Tables["nat"].Chains["PREROUTING"].Rules; len(rules) != 1 || rules[0].Target != "REDIRECT" || rules[0].Table != "nat" {
		t.Errorf("nat rules: %+v", rules)
	}
	if len(rs.Tables["filter"].Chains["INPUT"].Rules) != 4 || len(rs.Tables["security"].Chains) != 3 {
		t.Error("the second table with INPUT, FORWARD and OUTPUT is the security table")
	}
}

func TestParseListingRefusesWhatIsNoTable(t *testing.T) {
	for name, text := range map[string]string{
		"rules without the policy lines": "-N f2b-sshd\n-A INPUT -j ACCEPT\n",
		"chains of no table":             "-P INPUT ACCEPT\n-P POSTROUTING ACCEPT\n",
		"a table without one chain":      "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n",
		"a policy twice":                 "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-N X\n-P INPUT DROP\n",
		"three filter tables":            strings.Repeat("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -j ACCEPT\n", 3),
		"an invalid policy":              "-P INPUT REJECT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
		"a table line after a listing":   "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -j ACCEPT\n*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n",
		"a rule of a missing chain":      "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A missing -j ACCEPT\n",
	} {
		if _, err := Parse(text, models.IPv4); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// iptables-restore also reads -N, -P and -I lines inside a table.
func TestParseRestoreCommands(t *testing.T) {
	rs, err := Parse(`*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-N SERVICES
-P INPUT DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -j SERVICES
-I INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-I INPUT 2 -p icmp -j ACCEPT
-I INPUT 5 -p tcp --dport 443 -j ACCEPT
-A SERVICES -p tcp --dport 22 -j ACCEPT
COMMIT
`, models.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	input := rs.Tables["filter"].Chains["INPUT"]
	if input.Policy != "DROP" {
		t.Errorf("-P must set the policy: %q", input.Policy)
	}
	var order []string
	for i, rule := range input.Rules {
		if rule.RuleNum != i+1 {
			t.Errorf("rule %d has the number %d", i+1, rule.RuleNum)
		}
		order = append(order, strings.TrimPrefix(rule.RawLine, "-A INPUT "))
	}
	want := "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT|-p icmp -j ACCEPT|-i lo -j ACCEPT|-j SERVICES|-p tcp --dport 443 -j ACCEPT"
	if got := strings.Join(order, "|"); got != want {
		t.Errorf("order of the rules:\n got %s\nwant %s", got, want)
	}
	for name, text := range map[string]string{
		"a rule number outside the chain": "*filter\n:INPUT ACCEPT [0:0]\n-I INPUT 3 -j ACCEPT\nCOMMIT\n",
		"a rule number of zero":           "*filter\n:INPUT ACCEPT [0:0]\n-I INPUT 0 -j ACCEPT\nCOMMIT\n",
		"a policy for a user chain":       "*filter\n:INPUT ACCEPT [0:0]\n:X - [0:0]\n-P X DROP\nCOMMIT\n",
		"a chain twice":                   "*filter\n:INPUT ACCEPT [0:0]\n-N X\n-N X\nCOMMIT\n",
		"a built-in chain as new chain":   "*filter\n:INPUT ACCEPT [0:0]\n-N FORWARD\nCOMMIT\n",
		"a deleted rule":                  "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\n-D INPUT 1\nCOMMIT\n",
	} {
		if _, err := Parse(text, models.IPv4); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
