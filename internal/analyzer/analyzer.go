package analyzer

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// Analyze runs all analysis on the rulesets
func Analyze(ipv4, ipv6 *models.Ruleset) *models.AnalysisResult {
	result := &models.AnalysisResult{
		IPv4Rules: ipv4,
		IPv6Rules: ipv6,
	}

	// Shadow detection
	result.ShadowedRules = append(result.ShadowedRules, DetectShadowedRules(ipv4)...)
	result.ShadowedRules = append(result.ShadowedRules, DetectShadowedRules(ipv6)...)

	// Docker NAT bypass detection
	result.DockerBypasses = append(result.DockerBypasses, DetectDockerBypasses(ipv4)...)
	result.DockerBypasses = append(result.DockerBypasses, DetectDockerBypasses(ipv6)...)

	// Effectiveness checks
	result.EffectiveIssues = append(result.EffectiveIssues, CheckEffectiveness(ipv4)...)
	result.EffectiveIssues = append(result.EffectiveIssues, CheckEffectiveness(ipv6)...)

	return result
}

// CrossReferenceServices cross-references firewall rules with listening services
func CrossReferenceServices(result *models.AnalysisResult, services []models.ListeningService) {
	result.Services = services

	for _, svc := range services {
		if !svc.IsWildcard {
			// Services bound to localhost aren't exposed
			if isLoopback(svc.Address) {
				continue
			}
		}

		// Check IPv4 / IPv6 rules; skip services for stacks that weren't analyzed
		if svc.IsIPv6 {
			if result.IPv6Rules == nil {
				continue
			}
			scope, allowRule := classifyPortScope(result.IPv6Rules, svc)
			if scope != "" {
				addServiceFinding(result, svc, allowRule, scope, "IPv6")
			}
		} else {
			if result.IPv4Rules == nil {
				continue
			}
			scope, allowRule := classifyPortScope(result.IPv4Rules, svc)
			if scope != "" {
				addServiceFinding(result, svc, allowRule, scope, "IPv4")
			}
		}
	}

	// Find unused rules (rules for ports with no listening service)
	findUnusedRules(result)
}

// addServiceFinding builds and appends an ExposedServiceFinding.
func addServiceFinding(result *models.AnalysisResult, svc models.ListeningService, allowRule *models.Rule, scope models.AccessScope, ipLabel string) {
	sev := models.SeverityHigh
	if svc.Port >= 1024 {
		sev = models.SeverityMedium
	}
	if scope != models.ScopeExposed {
		sev = models.SeverityLow
	}

	reason := "Service " + svc.Process + " listening on port " +
		strconv.Itoa(svc.Port) + "/" + string(svc.Protocol) +
		" (" + ipLabel + ") is accessible from the network"
	if allowRule != nil {
		reason += " (allowed by rule #" + strconv.Itoa(allowRule.RuleNum) + " in filter/INPUT)"
	} else {
		reason += " (allowed by default ACCEPT policy)"
	}

	result.ExposedServices = append(result.ExposedServices, models.ExposedServiceFinding{
		Service:      svc,
		AllowingRule: allowRule,
		Severity:     sev,
		Scope:        scope,
		Reason:       reason,
	})
}

// classifyPortScope evaluates filter/INPUT in rule order, including jumps and
// RETURN behavior. Returns ("", nil) when no source can reach the service.
func classifyPortScope(rs *models.Ruleset, svc models.ListeningService) (models.AccessScope, *models.Rule) {
	scope, allowRule, _ := evaluateAccess(rs, "INPUT", packetQuery{
		Protocol: svc.Protocol,
		DstPort:  svc.Port,
		DstAddr:  svc.Address,
		State:    "NEW",
		External: true,
	})
	return scope, allowRule
}

func portMatches(rulePort, servicePort string) bool {
	ranges := expandPorts(rulePort)
	sp, _ := strconv.Atoi(servicePort)
	if sp == 0 {
		return false
	}
	for _, r := range ranges {
		if sp >= r[0] && sp <= r[1] {
			return true
		}
	}
	return false
}

func findUnusedRules(result *models.AnalysisResult) {
	checkUnusedInRuleset(result, result.IPv4Rules)
	checkUnusedInRuleset(result, result.IPv6Rules)
}

func checkUnusedInRuleset(result *models.AnalysisResult, rs *models.Ruleset) {
	if rs == nil {
		return
	}

	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return
	}

	input, ok := filterTable.Chains["INPUT"]
	if !ok {
		return
	}

	for _, rule := range input.Rules {
		if !rule.IsAllow() || rule.DstPort == "" {
			continue
		}

		// Check if any service is listening on this port
		ports := expandPorts(rule.DstPort)
		found := false
		for _, portRange := range ports {
			for _, svc := range result.Services {
				if (rs.IPVersion == models.IPv6) != svc.IsIPv6 {
					continue
				}
				if svc.Port >= portRange[0] && svc.Port <= portRange[1] &&
					(rule.Protocol == "" || rule.Protocol == models.ProtoAll || rule.Protocol == svc.Protocol) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && len(ports) > 0 {
			result.UnusedRules = append(result.UnusedRules, models.UnusedRuleFinding{
				Rule: rule,
				Reason: "Rule #" + strconv.Itoa(rule.RuleNum) + " allows " +
					string(rule.Protocol) + " port(s) " + rule.DstPort +
					" but no matching service is listening",
			})
		}
	}
}

func isLoopback(addr string) bool {
	addr = strings.Split(addr, "%")[0]
	if prefix, err := netip.ParsePrefix(addr); err == nil {
		return prefix.Addr().IsLoopback()
	}
	parsed, err := netip.ParseAddr(addr)
	return err == nil && parsed.IsLoopback()
}
