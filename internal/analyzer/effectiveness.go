package analyzer

import (
	"net/netip"
	"strconv"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// CheckEffectiveness detects general effectiveness issues in the ruleset
func CheckEffectiveness(rs *models.Ruleset) []models.EffectivenessFinding {
	if rs == nil {
		return nil
	}

	var findings []models.EffectivenessFinding

	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return findings
	}

	// Check default policies
	findings = append(findings, checkPolicies(filterTable)...)

	// Check for dead rules (rules after a catch-all DROP/REJECT)
	for _, chainName := range sortedChainNames(filterTable) {
		chain := filterTable.Chains[chainName]
		findings = append(findings, checkDeadRules(chain, filterTable.Name)...)
	}

	// Check for missing conntrack optimization
	findings = append(findings, checkConntrack(filterTable)...)

	// Check for missing explicit final DROP in INPUT
	findings = append(findings, checkFinalDrop(filterTable)...)

	// Check that traffic the host itself depends on is not dropped
	findings = append(findings, checkLoopback(rs)...)
	if rs.IPVersion == models.IPv6 {
		findings = append(findings, checkNeighborDiscovery(rs)...)
	}
	for i := range findings {
		findings[i].IPVersion = rs.IPVersion
	}

	return findings
}

func checkPolicies(filterTable *models.Table) []models.EffectivenessFinding {
	var findings []models.EffectivenessFinding

	checks := []struct {
		chain    string
		severity models.Severity
		detail   string
	}{
		{"INPUT", models.SeverityHigh,
			"INPUT chain default policy is ACCEPT. All traffic not explicitly blocked will be allowed. " +
				"Consider changing to DROP and explicitly allowing needed traffic."},
		{"FORWARD", models.SeverityHigh,
			"FORWARD chain default policy is ACCEPT. All forwarded traffic (including Docker) will be allowed. " +
				"Consider changing to DROP."},
		{"OUTPUT", models.SeverityLow,
			"OUTPUT chain default policy is ACCEPT. All outbound traffic is allowed. " +
				"This is common but a stricter policy could limit data exfiltration."},
	}

	for _, c := range checks {
		chain, ok := filterTable.Chains[c.chain]
		if !ok {
			continue
		}
		if chain.Policy == "ACCEPT" {
			findings = append(findings, models.EffectivenessFinding{
				Code:      models.FindingPolicyAccept,
				Certainty: models.CertaintyDefinite,
				Title:     c.chain + " default policy is ACCEPT",
				Detail:    c.detail,
				Severity:  c.severity,
				Chain:     c.chain,
				Table:     "filter",
			})
		}
	}

	return findings
}

func checkDeadRules(chain *models.Chain, tableName string) []models.EffectivenessFinding {
	var findings []models.EffectivenessFinding

	catchAllIdx := -1
	for i, rule := range chain.Rules {
		if IsCatchAll(&rule) && rule.IsTerminal() {
			catchAllIdx = i
			break
		}
	}

	if catchAllIdx >= 0 && catchAllIdx < len(chain.Rules)-1 {
		for i := catchAllIdx + 1; i < len(chain.Rules); i++ {
			rule := chain.Rules[i]
			findings = append(findings, models.EffectivenessFinding{
				Code:      models.FindingDeadRule,
				Certainty: models.CertaintyDefinite,
				Title:     "Dead rule in " + tableName + "/" + chain.Name,
				Detail: "Rule #" + strconv.Itoa(rule.RuleNum) + " (" + rule.Summary() +
					") will never be reached because rule #" +
					strconv.Itoa(chain.Rules[catchAllIdx].RuleNum) +
					" catches all remaining traffic",
				Severity: models.SeverityMedium,
				Chain:    chain.Name,
				Table:    tableName,
			})
		}
	}

	return findings
}

// IsCatchAll returns true if a rule is known to match all traffic. Unknown or
// unsupported predicates make this return false rather than risking a false
// dead-rule or policy conclusion.
func IsCatchAll(rule *models.Rule) bool {
	if len(rule.Negations) > 0 {
		return false
	}
	if rule.Fragment {
		return false
	}
	if rule.Protocol != "" && rule.Protocol != models.ProtoAll {
		return false
	}
	if rule.SrcAddr != "" && rule.SrcAddr != "0.0.0.0/0" && rule.SrcAddr != "::/0" {
		return false
	}
	if rule.DstAddr != "" && rule.DstAddr != "0.0.0.0/0" && rule.DstAddr != "::/0" {
		return false
	}
	if rule.DstPort != "" || rule.SrcPort != "" {
		return false
	}
	if rule.InIface != "" || rule.OutIface != "" {
		return false
	}
	if len(rule.States) > 0 {
		return false
	}
	// Check for narrowing match extensions (e.g. recent --update, limit)
	if hasNarrowingMatches(rule.Matches) {
		return false
	}
	return true
}

// hasNarrowingMatches returns true if any match extension restricts which
// packets the rule applies to beyond protocol/addr/port/state.
func hasNarrowingMatches(exts []models.MatchExt) bool {
	for _, ext := range exts {
		if matchConstraintSignature(ext) != "" {
			return true
		}
	}
	return false
}

func checkConntrack(filterTable *models.Table) []models.EffectivenessFinding {
	var findings []models.EffectivenessFinding

	input, ok := filterTable.Chains["INPUT"]
	if !ok {
		return findings
	}

	hasConntrack := false
	conntrackPos := -1

	for i, rule := range input.Rules {
		if rule.IsAllow() && containsState(rule.States, "ESTABLISHED") {
			hasConntrack = true
			conntrackPos = i
			break
		}
	}

	if !hasConntrack && len(input.Rules) > 0 {
		finding := models.EffectivenessFinding{
			Code:      models.FindingMissingConntrack,
			Certainty: models.CertaintyDefinite,
			Title:     "No conntrack ESTABLISHED,RELATED rule in INPUT",
			Detail: "Adding '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' " +
				"early in the INPUT chain significantly improves performance by allowing " +
				"return traffic for established connections without checking all rules.",
			Severity: models.SeverityMedium,
			Chain:    "INPUT",
			Table:    "filter",
		}
		if defaultDeny(input) {
			finding.Severity = models.SeverityHigh
			finding.Detail = "INPUT denies by default but never accepts ESTABLISHED,RELATED traffic, so replies to the " +
				"host's own outbound connections (DNS, package updates, NTP) and related ICMP errors such as " +
				"fragmentation-needed are dropped unless individual rules allow them. Add " +
				"'-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' near the top of INPUT."
		}
		findings = append(findings, finding)
	} else if conntrackPos > 2 {
		// Conntrack rule should be near the top (after loopback accept typically)
		findings = append(findings, models.EffectivenessFinding{
			Code:      models.FindingLateConntrack,
			Certainty: models.CertaintyDefinite,
			Title:     "Conntrack rule is not near the top of INPUT chain",
			Detail: "The ESTABLISHED,RELATED rule is at position " + strconv.Itoa(conntrackPos+1) +
				" in INPUT. For optimal performance, place it within the first 2-3 rules " +
				"(after loopback accept).",
			Severity: models.SeverityLow,
			Chain:    "INPUT",
			Table:    "filter",
		})
	}

	return findings
}

func checkFinalDrop(filterTable *models.Table) []models.EffectivenessFinding {
	var findings []models.EffectivenessFinding

	input, ok := filterTable.Chains["INPUT"]
	if !ok {
		return findings
	}

	if input.Policy == "ACCEPT" && len(input.Rules) > 0 {
		// Check if the last rule is a catch-all DROP
		lastRule := input.Rules[len(input.Rules)-1]
		if !lastRule.IsBlock() || !IsCatchAll(&lastRule) {
			findings = append(findings, models.EffectivenessFinding{
				Code:      models.FindingMissingFinalDrop,
				Certainty: models.CertaintyDefinite,
				Title:     "No explicit DROP at end of INPUT chain with ACCEPT policy",
				Detail: "The INPUT chain has a default ACCEPT policy but no catch-all DROP rule at the end. " +
					"Any traffic not matching explicit rules will be accepted. " +
					"Either change the policy to DROP or add a final catch-all DROP rule.",
				Severity: models.SeverityHigh,
				Chain:    "INPUT",
				Table:    "filter",
			})
		}
	}

	return findings
}

// defaultDeny reports whether a built-in chain refuses unmatched traffic.
func defaultDeny(chain *models.Chain) bool {
	if chain.Policy == "DROP" {
		return true
	}
	if n := len(chain.Rules); n > 0 {
		last := chain.Rules[n-1]
		return last.IsBlock() && IsCatchAll(&last)
	}
	return false
}

// checkLoopback reports an INPUT path that definitely drops traffic on lo.
func checkLoopback(rs *models.Ruleset) []models.EffectivenessFinding {
	source := netip.MustParsePrefix("127.0.0.0/8")
	if rs.IPVersion == models.IPv6 {
		source = netip.MustParsePrefix("::1/128")
	}
	query := packetQuery{
		Protocol: models.ProtoTCP, DstPort: unlistedPort(rs), DstAddr: source.Addr().String(), DstType: "LOCAL",
		InIface: "lo", State: "NEW", NATState: noNAT, Direction: "ORIGINAL",
		OriginalDstAddr: source.Addr().String(), OriginalDstPort: unlistedPort(rs),
	}
	path := evaluatePath(rs, inputPath(query), []netip.Prefix{source})
	if len(path.Accepted) > 0 || path.Uncertain {
		return nil
	}
	return []models.EffectivenessFinding{{
		Code:      models.FindingMissingLoopback,
		Certainty: models.CertaintyDefinite,
		Title:     "Loopback traffic is dropped by INPUT",
		Detail: "New connections on the lo interface are refused. Local services that talk to each other over " +
			source.Addr().String() + " (databases, DNS stub resolvers, Docker's userland proxy) will fail. " +
			"Add '-A INPUT -i lo -j ACCEPT' as the first INPUT rule.",
		Severity: models.SeverityMedium,
		Chain:    "INPUT",
		Table:    "filter",
	}}
}

// checkNeighborDiscovery reports an IPv6 INPUT path that definitely drops
// Neighbor Discovery. ND messages are never conntrack-tracked (their state is
// UNTRACKED), so ESTABLISHED,RELATED and NEW rules do not admit them.
func checkNeighborDiscovery(rs *models.Ruleset) []models.EffectivenessFinding {
	ctx := newEvalContext(rs, inferDockerTopology(rs), nil)
	candidates := ingressCandidates(rs, ctx, nil)
	blocked := func(icmpType string) bool {
		for _, candidate := range candidates {
			query := packetQuery{
				Protocol: "ipv6-icmp", ICMPType: icmpType, HopLimit: 255, InIface: candidate.name,
				State: "UNTRACKED", NATState: noNAT, External: true, Ctx: ctx,
			}
			path := evaluatePath(rs, inputPath(query), []netip.Prefix{rootPrefix(models.IPv6)})
			if len(path.Accepted) > 0 || path.Uncertain {
				return false
			}
		}
		return true
	}
	var findings []models.EffectivenessFinding
	if blocked("135") || blocked("136") {
		findings = append(findings, models.EffectivenessFinding{
			Code:      models.FindingIPv6NDPBlocked,
			Certainty: models.CertaintyDefinite,
			Title:     "IPv6 Neighbor Discovery is dropped by INPUT",
			Detail: "ICMPv6 neighbor solicitations/advertisements (types 135/136) are refused. They are untracked by " +
				"conntrack, so ESTABLISHED,RELATED rules do not admit them, and without them the host cannot resolve " +
				"IPv6 neighbors: IPv6 connectivity breaks. Allow them explicitly, e.g. " +
				"'-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT' (and 136).",
			Severity: models.SeverityHigh,
			Chain:    "INPUT",
			Table:    "filter",
		})
	}
	if blocked("134") {
		findings = append(findings, models.EffectivenessFinding{
			Code:      models.FindingIPv6NDPBlocked,
			Certainty: models.CertaintyDefinite,
			Title:     "IPv6 Router Advertisements are dropped by INPUT",
			Detail: "ICMPv6 router advertisements (type 134) are refused. A host that configures IPv6 with SLAAC " +
				"loses its addresses and default route when they expire. Allow them with " +
				"'-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT' unless addressing is static.",
			Severity: models.SeverityMedium,
			Chain:    "INPUT",
			Table:    "filter",
		})
	}
	return findings
}

func containsState(states []string, target string) bool {
	for _, s := range states {
		if s == target {
			return true
		}
	}
	return false
}
