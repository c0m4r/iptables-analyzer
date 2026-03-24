package scorer

import (
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

	// Policy deductions (max -30)
	policyDeduct := 0
	policyDeduct += checkChainPolicy(result.IPv4Rules, "INPUT", 15)
	policyDeduct += checkChainPolicy(result.IPv4Rules, "FORWARD", 10)
	policyDeduct += checkChainPolicy(result.IPv4Rules, "OUTPUT", 5)
	if policyDeduct > 30 {
		policyDeduct = 30
	}
	breakdown["policy"] = -policyDeduct
	score -= policyDeduct

	// Exposure deductions (max -30)
	exposureDeduct := 0
	for _, svc := range result.ExposedServices {
		if svc.Service.Port < 1024 {
			exposureDeduct += 5 // well-known port
		} else {
			exposureDeduct += 2 // high port
		}
	}
	if exposureDeduct > 30 {
		exposureDeduct = 30
	}
	breakdown["exposure"] = -exposureDeduct
	score -= exposureDeduct

	// Shadow/Docker bypass deductions (max -20)
	shadowDeduct := 0
	for _, bypass := range result.DockerBypasses {
		if bypass.Severity == models.SeverityCritical {
			shadowDeduct += 10
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
	if shadowDeduct > 20 {
		shadowDeduct = 20
	}
	breakdown["shadow"] = -shadowDeduct
	score -= shadowDeduct

	// Hygiene deductions (max -15)
	hygieneDeduct := 0
	for _, issue := range result.EffectiveIssues {
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

	// IPv6 deductions (max -10)
	ipv6Deduct := 0
	if result.IPv6Rules == nil || len(result.IPv6Rules.Tables) == 0 {
		ipv6Deduct += 10
	} else {
		ipv6Deduct += checkChainPolicy(result.IPv6Rules, "INPUT", 5)
	}
	if ipv6Deduct > 10 {
		ipv6Deduct = 10
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

func checkChainPolicy(rs *models.Ruleset, chainName string, deduction int) int {
	if rs == nil {
		return deduction
	}
	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return deduction
	}
	chain, ok := filterTable.Chains[chainName]
	if !ok {
		return 0
	}
	if chain.Policy == "ACCEPT" {
		// Check if there's a catch-all DROP at the end
		if len(chain.Rules) > 0 {
			last := chain.Rules[len(chain.Rules)-1]
			if last.IsBlock() && isCatchAll(&last) {
				return 0 // effectively DROP policy
			}
		}
		return deduction
	}
	return 0
}

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
	return true
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
