package scorer

import (
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// Every deduction comes from a finding of the report. A finding that is
// only possible costs half.

// weigh returns the deduction for a finding of the given certainty.
func weigh(points int, certainty models.Certainty) int {
	if certainty == models.CertaintyPossible {
		return (points + 1) / 2
	}
	return points
}

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
	// ceiling is the best grade that the findings allow, whatever the points.
	ceiling, ceilingReason := "A", ""
	limit := func(grade, reason string) {
		if gradeRank(grade) > gradeRank(ceiling) {
			ceiling, ceilingReason = grade, reason
		}
	}

	// Policy deductions (max -25): INPUT or FORWARD accept the traffic that no
	// rule names. Each chain is charged once, with its worst family. An OUTPUT
	// chain that does not filter is common and is not scored.
	policy := map[string]int{}
	for _, issue := range result.EffectiveIssues {
		if issue.Code != models.FindingPolicyAccept {
			continue
		}
		points := 0
		switch {
		case issue.Chain == "INPUT":
			points = weigh(15, issue.Certainty)
			if issue.Unrestricted {
				limit("F", stackLabel(issue.IPVersion)+" INPUT accepts every new connection")
			} else {
				limit("D", stackLabel(issue.IPVersion)+" INPUT accepts connections to ports that no rule names")
			}
		case issue.Chain == "FORWARD" && issue.Severity >= models.SeverityHigh:
			points = weigh(10, issue.Certainty)
		case issue.Chain == "FORWARD":
			points = weigh(5, issue.Certainty)
		}
		policy[issue.Chain] = max(policy[issue.Chain], points)
	}
	policyDeduct := min(policy["INPUT"]+policy["FORWARD"], 25)
	breakdown["policy"] = -policyDeduct
	score -= policyDeduct

	// Exposure deductions (max -25). Findings retain one entry per reachable
	// address family so the report can explain each firewall path, but the score
	// is defined per exposed protocol/port. Do not charge a dual-stack endpoint
	// twice merely because both its IPv4 and IPv6 paths are reachable.
	type exposedEndpoint struct {
		protocol models.Protocol
		port     int
	}
	endpoints := make(map[exposedEndpoint]int)
	charge := func(protocol models.Protocol, port, points int) {
		endpoint := exposedEndpoint{protocol: protocol, port: port}
		endpoints[endpoint] = max(endpoints[endpoint], points)
	}
	for _, svc := range result.ExposedServices {
		if svc.Scope != models.ScopeExposed {
			continue
		}
		points := 2 // high port
		if svc.Service.Port < 1024 {
			points = 5 // well-known port
		}
		switch {
		case strings.HasPrefix(svc.Condition, "source port"):
			points = 1 // only for senders that choose that source port
		case strings.Contains(svc.Condition, "rate limit") || strings.Contains(svc.Condition, "connection limit"):
			points = min(points, 2)
		}
		charge(svc.Service.Protocol, svc.Service.Port, weigh(points, svc.Certainty))
	}
	// Docker-published ports that INPUT would also have allowed are
	// exposures, not bypasses. They are charged per host port like services.
	for _, finding := range result.DockerBypasses {
		if finding.Code != models.FindingDockerPublished || finding.Scope != models.ScopeExposed {
			continue
		}
		for _, port := range portList(finding.ExposedPort) {
			points := 2 // high port
			if port < 1024 {
				points = 5 // well-known port
			}
			charge(finding.NATRule.Protocol, port, weigh(points, finding.Certainty))
		}
	}
	exposureDeduct := 0
	for _, points := range endpoints {
		exposureDeduct += points
	}
	// A wide range of open ports exposes whatever listens there later.
	for _, issue := range result.EffectiveIssues {
		if issue.Code == models.FindingBroadAccept {
			exposureDeduct += weigh(10, issue.Certainty)
		}
	}
	exposureDeduct = min(exposureDeduct, 25)
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
		points := 1
		switch finding.Severity {
		case models.SeverityCritical:
			points = 12
			if finding.Certainty == models.CertaintyDefinite {
				limit("C", "a firewall rule is bypassed for every source")
			}
		case models.SeverityHigh:
			points = 5
		case models.SeverityMedium:
			points = 2
		}
		shadowDeduct += weigh(points, finding.Certainty)
	}
	for _, shadow := range result.ShadowedRules {
		if shadow.Severity >= models.SeverityHigh {
			shadowDeduct += 5
		} else {
			shadowDeduct += 2
		}
	}
	shadowDeduct = min(shadowDeduct, 25)
	breakdown["shadow"] = -shadowDeduct
	score -= shadowDeduct

	// Hygiene deductions (max -15) and the IPv6 findings among them
	hygieneDeduct, ipv6Deduct := 0, 0
	for _, issue := range result.EffectiveIssues {
		points := 0
		switch issue.Severity {
		case models.SeverityHigh:
			points = 5
		case models.SeverityMedium:
			points = 3
		case models.SeverityLow:
			points = 1
		}
		switch issue.Code {
		case models.FindingPolicyAccept, models.FindingBroadAccept:
			// charged above
		case models.FindingIPv6Wider:
			ipv6Deduct += weigh(points, issue.Certainty)
		default:
			hygieneDeduct += weigh(points, issue.Certainty)
		}
	}
	hygieneDeduct = min(hygieneDeduct, 15)
	breakdown["hygiene"] = -hygieneDeduct
	score -= hygieneDeduct

	// IPv6 deductions (max -10). An IPv6 stack without rules accepts
	// everything; a stack that was not read is not charged.
	if result.FamilyState(models.IPv6) == models.FamilyNoRules {
		ipv6Deduct += 10
	}
	if ipv6Gap {
		ipv6Deduct += 5
	}
	ipv6Deduct = min(ipv6Deduct, 10)
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
	if areas["nat"] {
		unassessed = append(unassessed, "ports redirected to local services")
	}
	if areas["rules"] {
		unassessed = append(unassessed, "rules that iptables-save does not show")
	}
	if areas["services"] && result.ServiceAssessment == models.AssessmentComplete {
		unassessed = append(unassessed, "listening-service exposure")
	}
	grade := gradeFromScore(score)
	scoreResult := models.ScoreResult{
		Total:      score,
		Breakdown:  breakdown,
		Complete:   complete,
		Unassessed: unassessed,
	}
	if gradeRank(ceiling) > gradeRank(grade) {
		grade = ceiling
		scoreResult.Cap = "grade limited to " + ceiling + ": " + ceilingReason
	}
	if !complete {
		grade = "INCOMPLETE"
	}
	scoreResult.Grade = grade
	return scoreResult
}

// gradeRank orders grades from best to worst.
func gradeRank(grade string) int {
	return strings.Index("ABCDF", grade)
}

func stackLabel(version models.IPVersion) string {
	if version == models.IPv6 {
		return "IPv6"
	}
	return "IPv4"
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
