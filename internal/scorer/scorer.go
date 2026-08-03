package scorer

import (
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// Calculate computes the security score based on analysis results
func Calculate(result *models.AnalysisResult) models.ScoreResult {
	score := 100
	breakdown := map[string]int{
		"policy":   0,
		"exposure": 0,
		"shadow":   0,
		"hygiene":  0,
		"ipv6":     0,
	}

	// Policy deductions (max -25). OUTPUT ACCEPT is reported as a low-severity
	// hardening opportunity, but is common and is not scored as a policy flaw.
	policyDeduct := 0
	policyRulesets := analyzedPolicyRulesets(result)
	policyDeduct += maxChainPolicyDeduction(policyRulesets, "INPUT", 15)
	policyDeduct += maxChainPolicyDeduction(policyRulesets, "FORWARD", 10)
	if policyDeduct > 25 {
		policyDeduct = 25
	}
	breakdown["policy"] = -policyDeduct
	score -= policyDeduct

	// Exposure deductions (max -25)
	// Only penalise truly EXPOSED services; LOCALNET/WHITELISTED have intentional restrictions.
	exposureDeduct := 0
	for _, svc := range result.ExposedServices {
		if svc.Scope != models.ScopeExposed {
			continue
		}
		if svc.Service.Port < 1024 {
			exposureDeduct += 5 // well-known port
		} else {
			exposureDeduct += 2 // high port
		}
	}
	if exposureDeduct > 25 {
		exposureDeduct = 25
	}
	breakdown["exposure"] = -exposureDeduct
	score -= exposureDeduct

	// Shadow/Docker bypass deductions (max -25)
	shadowDeduct := 0
	for _, bypass := range result.DockerBypasses {
		if bypass.Severity == models.SeverityCritical {
			shadowDeduct += 12
		} else {
			shadowDeduct += 5
		}
	}
	for _, shadow := range result.ShadowedRules {
		if shadow.Severity >= models.SeverityHigh {
			shadowDeduct += 5
		} else {
			shadowDeduct += 2
		}
	}
	if shadowDeduct > 25 {
		shadowDeduct = 25
	}
	breakdown["shadow"] = -shadowDeduct
	score -= shadowDeduct

	// Hygiene deductions (max -15)
	hygieneDeduct := 0
	for _, issue := range result.EffectiveIssues {
		// Policy findings are accounted for in the policy category. Avoid
		// charging for the same condition a second time as hygiene.
		if strings.Contains(issue.Title, "default policy is ACCEPT") ||
			issue.Title == "No explicit DROP at end of INPUT chain with ACCEPT policy" {
			continue
		}
		switch issue.Severity {
		case models.SeverityHigh:
			hygieneDeduct += 5
		case models.SeverityMedium:
			hygieneDeduct += 3
		case models.SeverityLow:
			hygieneDeduct += 1
		}
	}
	if hygieneDeduct > 15 {
		hygieneDeduct = 15
	}
	breakdown["hygiene"] = -hygieneDeduct
	score -= hygieneDeduct

	// IPv6 deductions (max -10); skip when only IPv4 was analyzed
	ipv6Deduct := 0
	if !result.IPv4Only {
		if result.IPv6Rules == nil || len(result.IPv6Rules.Tables) == 0 {
			ipv6Deduct += 10
		}
		if ipv6Deduct > 10 {
			ipv6Deduct = 10
		}
	}
	breakdown["ipv6"] = -ipv6Deduct
	score -= ipv6Deduct

	if score < 0 {
		score = 0
	}

	return models.ScoreResult{
		Total:     score,
		Breakdown: breakdown,
		Grade:     gradeFromScore(score),
	}
}

func analyzedPolicyRulesets(result *models.AnalysisResult) []*models.Ruleset {
	if result.IPv4Only {
		return []*models.Ruleset{result.IPv4Rules}
	}
	if result.IPv6Only {
		return []*models.Ruleset{result.IPv6Rules}
	}
	return []*models.Ruleset{result.IPv4Rules, result.IPv6Rules}
}

func maxChainPolicyDeduction(rulesets []*models.Ruleset, chainName string, deduction int) int {
	for _, ruleset := range rulesets {
		if ruleset != nil && len(ruleset.Tables) > 0 && checkChainPolicy(ruleset, chainName, deduction) > 0 {
			return deduction
		}
	}
	return 0
}

func checkChainPolicy(rs *models.Ruleset, chainName string, deduction int) int {
	if rs == nil {
		return 0 // stack was not analyzed; no penalty
	}
	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return deduction
	}
	chain, ok := filterTable.Chains[chainName]
	if !ok {
		return deduction
	}
	if chain.Policy == "ACCEPT" {
		// Check if there's a catch-all DROP at the end
		if len(chain.Rules) > 0 {
			last := chain.Rules[len(chain.Rules)-1]
			if last.IsBlock() && analyzer.IsCatchAll(&last) {
				return 0 // effectively DROP policy
			}
		}
		return deduction
	}
	return 0
}

func gradeFromScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}
