package analyzer

import (
	"net"
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

// classifyPortScope determines how accessible a service is through filter/INPUT.
//
// It scans all ACCEPT rules for the service's port and protocol, and classifies:
//   - ScopeWhitelisted  — only specific /32 hosts are allowed
//   - ScopeLocalnet     — only private RFC1918 ranges are allowed
//   - ScopeExposed      — any source can reach the service
//
// Port-specific ACCEPT rules (DstPort set) take precedence over broad rules
// (no DstPort) for determining scope, reflecting admin intent.
// Returns ("", nil) when the service is blocked.
func classifyPortScope(rs *models.Ruleset, svc models.ListeningService) (models.AccessScope, *models.Rule) {
	if rs == nil {
		return models.ScopeExposed, nil
	}

	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return models.ScopeExposed, nil
	}

	input, ok := filterTable.Chains["INPUT"]
	if !ok {
		return models.ScopeExposed, nil
	}

	svcPortStr := strconv.Itoa(svc.Port)

	var portSpecificScope models.AccessScope
	var portSpecificRule *models.Rule
	var broadScope models.AccessScope
	var broadRule *models.Rule

	for i := range input.Rules {
		rule := &input.Rules[i]

		// Skip loopback-only rules
		if rule.InIface == "lo" {
			continue
		}

		// Protocol filter
		if rule.Protocol != "" && rule.Protocol != models.ProtoAll && rule.Protocol != svc.Protocol {
			continue
		}

		// State filter — only NEW connections matter for exposure
		if len(rule.States) > 0 && !containsState(rule.States, "NEW") {
			continue
		}

		// Skip negated sources (too complex to classify reliably)
		if rule.Negations["src"] {
			continue
		}

		if !rule.IsAllow() {
			continue
		}

		if rule.DstPort != "" {
			// Port-specific rule
			if !portMatches(rule.DstPort, svcPortStr) {
				continue
			}
			scope := scopeForSource(rule.SrcAddr)
			if isScopeMorePermissive(scope, portSpecificScope) {
				portSpecificScope = scope
				portSpecificRule = rule
			}
		} else {
			// Broad rule — matches any port
			// Check for user-defined chain jumps
			if !rule.IsAllow() {
				if targetChain, ok := filterTable.Chains[rule.Target]; ok {
					if !chainCanAccept(targetChain) {
						continue
					}
				}
			}
			scope := scopeForSource(rule.SrcAddr)
			if isScopeMorePermissive(scope, broadScope) {
				broadScope = scope
				broadRule = rule
			}
		}
	}

	// Port-specific rules reflect the admin's intent for this service.
	// Prefer them over broad rules when present.
	if portSpecificRule != nil {
		return portSpecificScope, portSpecificRule
	}

	if broadRule != nil {
		return broadScope, broadRule
	}

	// No ACCEPT rule found — check default policy
	if input.Policy == "ACCEPT" || input.Policy == "" {
		return models.ScopeExposed, nil
	}
	return "", nil
}

// chainCanAccept returns true if a user-defined chain has any ACCEPT path.
func chainCanAccept(chain *models.Chain) bool {
	for _, rule := range chain.Rules {
		if rule.IsAllow() {
			return true
		}
	}
	return chain.Policy == "ACCEPT"
}

// scopeForSource classifies a source address into an access scope.
func scopeForSource(srcAddr string) models.AccessScope {
	if srcAddr == "" || srcAddr == "0.0.0.0/0" || srcAddr == "::/0" {
		return models.ScopeExposed
	}
	if isSpecificHost(srcAddr) {
		return models.ScopeWhitelisted
	}
	if isPrivateNetwork(srcAddr) {
		return models.ScopeLocalnet
	}
	return models.ScopeExposed // public IP range
}

// isScopeMorePermissive returns true when scope a is more permissive than b.
func isScopeMorePermissive(a, b models.AccessScope) bool {
	order := map[models.AccessScope]int{
		"":                      0,
		models.ScopeWhitelisted: 1,
		models.ScopeLocalnet:    2,
		models.ScopeExposed:     3,
	}
	return order[a] > order[b]
}

// isSpecificHost returns true for /32 (IPv4) or /128 (IPv6) addresses.
func isSpecificHost(addr string) bool {
	if strings.HasSuffix(addr, "/32") || strings.HasSuffix(addr, "/128") {
		return true
	}
	return !strings.Contains(addr, "/") // bare IP without CIDR
}

// isPrivateNetwork returns true when addr falls within RFC1918 / ULA ranges.
func isPrivateNetwork(addr string) bool {
	if !strings.Contains(addr, "/") {
		addr += "/32"
	}
	_, addrNet, err := net.ParseCIDR(addr)
	if err != nil {
		return false
	}
	for _, r := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10", // CGNAT (RFC 6598)
		"fc00::/7",      // IPv6 ULA
		"fe80::/10",     // IPv6 link-local
	} {
		_, privateNet, _ := net.ParseCIDR(r)
		if privateNet != nil && privateNet.Contains(addrNet.IP) {
			return true
		}
	}
	return false
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
