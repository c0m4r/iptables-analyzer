package scorer

import (
	"strconv"
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

	// Exposure deductions (max -25). Findings retain one entry per reachable
	// address family so the report can explain each firewall path, but the score
	// is defined per exposed protocol/port. Do not charge a dual-stack endpoint
	// twice merely because both its IPv4 and IPv6 paths are reachable.
	exposureDeduct := 0
	type exposedEndpoint struct {
		protocol models.Protocol
		port     int
	}
	countedEndpoints := make(map[exposedEndpoint]struct{})
	charge := func(protocol models.Protocol, port int) {
		endpoint := exposedEndpoint{protocol: protocol, port: port}
		if _, counted := countedEndpoints[endpoint]; counted {
			return
		}
		countedEndpoints[endpoint] = struct{}{}
		if port < 1024 {
			exposureDeduct += 5 // well-known port
		} else {
			exposureDeduct += 2 // high port
		}
	}
	for _, svc := range result.ExposedServices {
		if svc.Scope == models.ScopeExposed {
			charge(svc.Service.Protocol, svc.Service.Port)
		}
	}
	// Docker-published ports that INPUT would also have allowed are
	// exposures, not bypasses. They are charged per host port like services.
	for _, finding := range result.DockerBypasses {
		if finding.Code != models.FindingDockerPublished || finding.Scope != models.ScopeExposed {
			continue
		}
		for _, port := range portList(finding.ExposedPort) {
			charge(finding.NATRule.Protocol, port)
		}
	}
	if exposureDeduct > 25 {
		exposureDeduct = 25
	}
	breakdown["exposure"] = -exposureDeduct
	score -= exposureDeduct

	// Shadow/Docker bypass deductions (max -25)
	shadowDeduct := 0
	ipv6Gap := false
	for _, finding := range result.DockerBypasses {
		switch finding.Code {
		case models.FindingDockerPublished:
			continue // charged as exposure
		case models.FindingDockerIPv6Unfiltered:
			ipv6Gap = true
			continue // charged in the IPv6 category
		}
		switch finding.Severity {
		case models.SeverityCritical:
			shadowDeduct += 12
		case models.SeverityHigh:
			shadowDeduct += 5
		case models.SeverityMedium:
			shadowDeduct += 2
		default:
			shadowDeduct++
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
		if issue.Code == models.FindingPolicyAccept || issue.Code == models.FindingMissingFinalDrop {
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
		if ipv6Gap {
			ipv6Deduct += 5
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

	complete := result.ServiceAssessment == models.AssessmentComplete && len(result.Diagnostics) == 0
	unassessed := []string{}
	if result.ServiceAssessment != models.AssessmentComplete {
		unassessed = append(unassessed, "listening-service exposure")
	}
	areas := map[string]bool{}
	for _, diagnostic := range result.Diagnostics {
		areas[diagnostic.Area] = true
	}
	if areas["docker"] {
		unassessed = append(unassessed, "one or more firewall translations")
	}
	if areas["services"] && result.ServiceAssessment == models.AssessmentComplete {
		unassessed = append(unassessed, "listening-service exposure")
	}
	grade := gradeFromScore(score)
	if !complete {
		grade = "INCOMPLETE"
	}
	return models.ScoreResult{
		Total:      score,
		Breakdown:  breakdown,
		Grade:      grade,
		Complete:   complete,
		Unassessed: unassessed,
	}
}

// portList expands "8080" or "9000-9002" into individual ports.
func portList(spec string) []int {
	low, high, isRange := strings.Cut(spec, "-")
	start, err := strconv.Atoi(low)
	if err != nil {
		return nil
	}
	end := start
	if isRange {
		if end, err = strconv.Atoi(high); err != nil || end < start {
			return []int{start}
		}
	}
	ports := make([]int, 0, end-start+1)
	for port := start; port <= end; port++ {
		ports = append(ports, port)
	}
	return ports
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
