package analyzer

import (
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// PortRisk says how much it matters that a port is open to any source. The
// classes follow what usually listens on a port, because the same rule
// "accept from anywhere" is the purpose of a web server and a defect for a
// database.
type PortRisk int

const (
	// RiskOrdinary: no usual meaning; open to any source is a medium finding.
	RiskOrdinary PortRisk = iota
	// RiskPublic: ports of services that are public by their purpose: web,
	// mail transfer and DNS.
	RiskPublic
	// RiskSensitive: remote administration, databases and queues, clear-text
	// and legacy protocols, file sharing and cluster control.
	RiskSensitive
)

var publicPorts = map[int]bool{25: true, 53: true, 80: true, 443: true, 465: true, 587: true, 993: true, 995: true}

var sensitivePorts = map[int]bool{
	// remote administration and control planes
	22: true, 23: true, 3389: true, 5900: true, 5901: true, 5902: true, 5903: true, 5985: true, 5986: true,
	2375: true, 2376: true, 2379: true, 2380: true, 6443: true, 8006: true, 10000: true, 10250: true,
	// databases, caches, queues, search
	1433: true, 1521: true, 3306: true, 5432: true, 5984: true, 6379: true, 7000: true, 7001: true,
	8086: true, 9042: true, 9200: true, 9300: true, 11211: true, 27017: true, 27018: true, 27019: true,
	2181: true, 4369: true, 5601: true, 5672: true, 8500: true, 9092: true, 15672: true,
	// clear-text and legacy protocols
	21: true, 69: true, 110: true, 143: true, 161: true, 389: true, 512: true, 513: true, 514: true, 623: true, 873: true,
	// file sharing, RPC, display
	111: true, 135: true, 137: true, 138: true, 139: true, 445: true, 2049: true, 3260: true, 6000: true,
}

// RiskOfPorts returns the class of a range of ports: sensitive when it holds
// a sensitive port, public when every port in it is public by purpose.
func RiskOfPorts(first, last int) PortRisk {
	if last < first {
		last = first
	}
	allPublic := true
	if last-first > 4096 {
		// A wide range: look the known ports up instead of walking the range.
		for port := range sensitivePorts {
			if port >= first && port <= last {
				return RiskSensitive
			}
		}
		return RiskOrdinary
	}
	for port := first; port <= last; port++ {
		if sensitivePorts[port] {
			return RiskSensitive
		}
		allPublic = allPublic && publicPorts[port]
	}
	if allPublic {
		return RiskPublic
	}
	return RiskOrdinary
}

// ExposureSeverity returns the severity of ports that are open to any
// source. A condition lowers it: a per-source rate limit slows guessing, and
// a rule for a given source port is the shape of replies (DHCP, DNS).
func ExposureSeverity(first, last int, condition string) models.Severity {
	severity := models.SeverityMedium
	switch RiskOfPorts(first, last) {
	case RiskSensitive:
		severity = models.SeverityHigh
	case RiskPublic:
		severity = models.SeverityLow
	}
	switch {
	case strings.HasPrefix(condition, "source port"):
		severity = models.SeverityLow
	case rateLimited(condition) && severity > models.SeverityMedium:
		severity = models.SeverityMedium
	}
	return severity
}

// RulePath returns the way from a built-in chain to a rule as steps
// "CHAIN #N": the jumps that lead to the chain of the rule, then the rule.
// A rule in a built-in chain is one step. When several ways exist it returns
// a shortest one, starting from the hook that the tables list first.
func RulePath(rs *models.Ruleset, rule *models.Rule) []string {
	last := rule.Chain + " #" + strconv.Itoa(rule.RuleNum)
	if rs == nil || rs.Tables[rule.Table] == nil {
		return []string{last}
	}
	table := rs.Tables[rule.Table]
	if chain := table.Chains[rule.Chain]; chain == nil || chain.Policy != "" {
		return []string{last}
	}
	type step struct {
		chain string
		via   string // "CHAIN #N" of the jump that led here
		from  int    // index of the previous step, -1 for a start
	}
	var queue []step
	seen := map[string]bool{}
	for _, name := range []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"} {
		if chain := table.Chains[name]; chain != nil && chain.Policy != "" {
			queue = append(queue, step{chain: name, from: -1})
			seen[name] = true
		}
	}
	for i := 0; i < len(queue); i++ {
		current := queue[i]
		if current.chain == rule.Chain {
			var path []string
			for at := i; at >= 0 && queue[at].via != ""; at = queue[at].from {
				path = append([]string{queue[at].via}, path...)
			}
			return append(path, last)
		}
		chain := table.Chains[current.chain]
		for r := range chain.Rules {
			target := chain.Rules[r].Target
			if _, isChain := table.Chains[target]; isChain && !seen[target] {
				seen[target] = true
				queue = append(queue, step{chain: target, via: current.chain + " #" + strconv.Itoa(chain.Rules[r].RuleNum), from: i})
			}
		}
	}
	return []string{last}
}
