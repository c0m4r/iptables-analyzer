package analyzer

import (
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

		// Check IPv4 rules
		if svc.IsIPv6 {
			exposed, allowRule := isPortExposed(result.IPv6Rules, svc)
			if exposed {
				sev := models.SeverityHigh
				if svc.Port >= 1024 {
					sev = models.SeverityMedium
				}
				reason := "Service " + svc.Process + " listening on port " +
					strconv.Itoa(svc.Port) + "/" + string(svc.Protocol) +
					" (IPv6) is accessible from the network"
				if allowRule != nil {
					reason += " (allowed by rule #" + strconv.Itoa(allowRule.RuleNum) + " in filter/INPUT)"
				} else {
					reason += " (allowed by default ACCEPT policy)"
				}
				result.ExposedServices = append(result.ExposedServices, models.ExposedServiceFinding{
					Service:      svc,
					AllowingRule: allowRule,
					Severity:     sev,
					Reason:       reason,
				})
			}
		} else {
			exposed, allowRule := isPortExposed(result.IPv4Rules, svc)
			if exposed {
				sev := models.SeverityHigh
				if svc.Port >= 1024 {
					sev = models.SeverityMedium
				}
				reason := "Service " + svc.Process + " listening on port " +
					strconv.Itoa(svc.Port) + "/" + string(svc.Protocol) +
					" (IPv4) is accessible from the network"
				if allowRule != nil {
					reason += " (allowed by rule #" + strconv.Itoa(allowRule.RuleNum) + " in filter/INPUT)"
				} else {
					reason += " (allowed by default ACCEPT policy)"
				}
				result.ExposedServices = append(result.ExposedServices, models.ExposedServiceFinding{
					Service:      svc,
					AllowingRule: allowRule,
					Severity:     sev,
					Reason:       reason,
				})
			}
		}
	}

	// Find unused rules (rules for ports with no listening service)
	findUnusedRules(result)
}

// isPortExposed checks if a service's port is accessible through the firewall
func isPortExposed(rs *models.Ruleset, svc models.ListeningService) (bool, *models.Rule) {
	if rs == nil {
		return true, nil // no ruleset means no firewall
	}

	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return true, nil
	}

	input, ok := filterTable.Chains["INPUT"]
	if !ok {
		return true, nil
	}

	// Walk rules in order, find first match
	for i := range input.Rules {
		rule := &input.Rules[i]
		if ruleMatchesService(rule, svc) {
			if rule.IsAllow() {
				return true, rule
			}
			if rule.IsBlock() {
				return false, nil
			}
			// Check if target is a jump to a user-defined chain
			if targetChain, ok := filterTable.Chains[rule.Target]; ok {
				if chainCanAccept(targetChain) {
					return true, rule
				}
				// Chain has no ACCEPT path - treat as non-matching and continue
				continue
			}
			// Non-terminal target (LOG, etc.) - continue checking
		}
	}

	// No rule matched - check default policy
	if input.Policy == "ACCEPT" || input.Policy == "" {
		return true, nil
	}
	return false, nil
}

// chainCanAccept returns true if a user-defined chain has any path that ACCEPTs.
// Used to detect exposure through rate-limiting chains like SSHBRUTE or ICMPFLOOD.
func chainCanAccept(chain *models.Chain) bool {
	for _, rule := range chain.Rules {
		if rule.IsAllow() {
			return true
		}
	}
	return chain.Policy == "ACCEPT"
}

func ruleMatchesService(rule *models.Rule, svc models.ListeningService) bool {
	// Protocol check
	if rule.Protocol != "" && rule.Protocol != models.ProtoAll && rule.Protocol != svc.Protocol {
		return false
	}

	// Port check
	if rule.DstPort != "" {
		svcPortStr := strconv.Itoa(svc.Port)
		if !portMatches(rule.DstPort, svcPortStr) {
			return false
		}
	}

	// Interface check - skip interface-specific rules for general exposure check
	if rule.InIface == "lo" {
		return false
	}

	// Source check - we're checking for "any source" exposure
	if rule.SrcAddr != "" && rule.SrcAddr != "0.0.0.0/0" && rule.SrcAddr != "::/0" {
		return false // rule only matches specific source, not "any"
	}

	// State check - only NEW connections matter for exposure.
	// Rules that only handle ESTABLISHED/RELATED cannot expose new connections.
	if len(rule.States) > 0 && !containsState(rule.States, "NEW") {
		return false
	}

	return true
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
		for _, portRange := range ports {
			for p := portRange[0]; p <= portRange[1]; p++ {
				found := false
				for _, svc := range result.Services {
					if svc.Port == p && (rule.Protocol == "" || rule.Protocol == models.ProtoAll || rule.Protocol == svc.Protocol) {
						found = true
						break
					}
				}
				if !found && p > 0 {
					result.UnusedRules = append(result.UnusedRules, models.UnusedRuleFinding{
						Rule: rule,
						Reason: "Rule #" + strconv.Itoa(rule.RuleNum) + " allows " +
							string(rule.Protocol) + " port " + strconv.Itoa(p) +
							" but no service is listening on that port",
					})
				}
			}
		}
	}
}

func isLoopback(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || strings.HasPrefix(addr, "127.")
}
