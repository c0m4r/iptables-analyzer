package analyzer

import (
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
	for _, chain := range filterTable.Chains {
		findings = append(findings, checkDeadRules(chain, filterTable.Name)...)
	}

	// Check for missing conntrack optimization
	findings = append(findings, checkConntrack(filterTable)...)

	// Check for missing explicit final DROP in INPUT
	findings = append(findings, checkFinalDrop(filterTable)...)

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
				Title:    c.chain + " default policy is ACCEPT",
				Detail:   c.detail,
				Severity: c.severity,
				Chain:    c.chain,
				Table:    "filter",
			})
		}
	}

	return findings
}

func checkDeadRules(chain *models.Chain, tableName string) []models.EffectivenessFinding {
	var findings []models.EffectivenessFinding

	catchAllIdx := -1
	for i, rule := range chain.Rules {
		if isCatchAll(&rule) && rule.IsTerminal() {
			catchAllIdx = i
			break
		}
	}

	if catchAllIdx >= 0 && catchAllIdx < len(chain.Rules)-1 {
		for i := catchAllIdx + 1; i < len(chain.Rules); i++ {
			rule := chain.Rules[i]
			findings = append(findings, models.EffectivenessFinding{
				Title: "Dead rule in " + tableName + "/" + chain.Name,
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

// isCatchAll returns true if a rule matches all traffic (no specific match criteria)
func isCatchAll(rule *models.Rule) bool {
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
		if !narrowingModules[ext.Module] {
			continue
		}
		nps := narrowingParams[ext.Module]
		for key := range ext.Params {
			if nps != nil && nps[key] {
				return true
			}
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
		findings = append(findings, models.EffectivenessFinding{
			Title: "No conntrack ESTABLISHED,RELATED rule in INPUT",
			Detail: "Adding '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' " +
				"early in the INPUT chain significantly improves performance by allowing " +
				"return traffic for established connections without checking all rules.",
			Severity: models.SeverityMedium,
			Chain:    "INPUT",
			Table:    "filter",
		})
	} else if conntrackPos > 2 {
		// Conntrack rule should be near the top (after loopback accept typically)
		findings = append(findings, models.EffectivenessFinding{
			Title: "Conntrack rule is not near the top of INPUT chain",
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
		if !lastRule.IsBlock() || !isCatchAll(&lastRule) {
			findings = append(findings, models.EffectivenessFinding{
				Title: "No explicit DROP at end of INPUT chain with ACCEPT policy",
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

func containsState(states []string, target string) bool {
	for _, s := range states {
		if s == target {
			return true
		}
	}
	return false
}
