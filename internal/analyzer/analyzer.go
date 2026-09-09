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
		IPv4Rules:         ipv4,
		IPv6Rules:         ipv6,
		ServiceAssessment: models.AssessmentNotRequested,
	}

	// Shadow detection
	result.ShadowedRules = append(result.ShadowedRules, DetectShadowedRules(ipv4)...)
	result.ShadowedRules = append(result.ShadowedRules, DetectShadowedRules(ipv6)...)

	// Docker NAT bypass detection
	result.DockerBypasses = append(result.DockerBypasses, DetectDockerBypasses(ipv4)...)
	result.DockerBypasses = append(result.DockerBypasses, DetectDockerBypasses(ipv6)...)
	result.Diagnostics = append(result.Diagnostics, DockerAssessmentDiagnostics(ipv4)...)
	result.Diagnostics = append(result.Diagnostics, DockerAssessmentDiagnostics(ipv6)...)

	// Effectiveness checks
	result.EffectiveIssues = append(result.EffectiveIssues, CheckEffectiveness(ipv4)...)
	result.EffectiveIssues = append(result.EffectiveIssues, CheckEffectiveness(ipv6)...)

	return result
}

// CrossReferenceServices cross-references firewall rules with listening services
func CrossReferenceServices(result *models.AnalysisResult, services []models.ListeningService) {
	result.Services = deduplicateServices(services)
	result.ServiceAssessment = models.AssessmentComplete

	for i := range result.Services {
		svc := result.Services[i]
		if !svc.IsWildcard {
			// Services bound to localhost aren't exposed
			if isLoopback(svc.Address) {
				result.Services[i].Status = models.ServiceLocalhost
				continue
			}
		}

		families := []models.IPVersion{}
		switch svc.Family {
		case models.SocketDual:
			families = []models.IPVersion{models.IPv4, models.IPv6}
		case models.SocketIPv6:
			families = []models.IPVersion{models.IPv6}
		default:
			if svc.IsIPv6 {
				families = []models.IPVersion{models.IPv6}
			} else {
				families = []models.IPVersion{models.IPv4}
			}
		}
		assessed := false
		reachable := false
		for _, family := range families {
			rs := result.IPv4Rules
			label := "IPv4"
			evaluated := svc
			evaluated.Address = "0.0.0.0"
			evaluated.IsIPv6 = false
			evaluated.Family = models.SocketIPv4
			if family == models.IPv6 {
				rs = result.IPv6Rules
				label = "IPv6"
				evaluated.Address = "::"
				evaluated.IsIPv6 = true
				evaluated.Family = models.SocketIPv6
			}
			if rs == nil {
				continue
			}
			assessed = true
			scope, allowRule, certainty := classifyPortScope(rs, evaluated)
			if scope != "" {
				reachable = true
				addServiceFinding(result, evaluated, allowRule, scope, label, family, certainty)
			}
		}
		if !assessed {
			result.Services[i].Status = models.ServiceNotAnalyzed
		} else if reachable {
			result.Services[i].Status = models.ServiceReachable
		} else {
			result.Services[i].Status = models.ServiceFiltered
		}
	}

	// Find unused rules (rules for ports with no listening service)
	findUnusedRules(result)
}

// deduplicateServices collapses repeated socket rows without merging distinct
// address families or processes that happen to share a port. Tools such as ss
// can report one row per file descriptor when a process opens the same endpoint
// more than once; firewall reachability is identical for all of those rows.
func deduplicateServices(services []models.ListeningService) []models.ListeningService {
	type serviceKey struct {
		protocol   models.Protocol
		address    string
		port       int
		process    string
		pid        int
		isIPv6     bool
		isWildcard bool
		family     models.SocketFamily
	}

	unique := make([]models.ListeningService, 0, len(services))
	seen := make(map[serviceKey]struct{}, len(services))
	for _, svc := range services {
		key := serviceKey{
			protocol:   svc.Protocol,
			address:    svc.Address,
			port:       svc.Port,
			process:    svc.Process,
			pid:        svc.PID,
			isIPv6:     svc.IsIPv6,
			isWildcard: svc.IsWildcard,
			family:     svc.Family,
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, svc)
	}
	return unique
}

// addServiceFinding builds and appends an ExposedServiceFinding.
func addServiceFinding(result *models.AnalysisResult, svc models.ListeningService, allowRule *models.Rule, scope models.AccessScope, ipLabel string, ipVersion models.IPVersion, certainty models.Certainty) {
	sev := models.SeverityHigh
	if svc.Port >= 1024 {
		sev = models.SeverityMedium
	}
	if scope != models.ScopeExposed {
		sev = models.SeverityLow
	}

	reachability := "is accessible"
	if certainty == models.CertaintyPossible {
		reachability = "may be accessible"
	}
	reason := "Service " + svc.Process + " listening on port " +
		strconv.Itoa(svc.Port) + "/" + string(svc.Protocol) +
		" (" + ipLabel + ") " + reachability + " from the network"
	if allowRule != nil {
		reason += " (allowed by rule #" + strconv.Itoa(allowRule.RuleNum) + " in " +
			allowRule.Table + "/" + allowRule.Chain + ")"
	} else {
		reason += " (allowed by default ACCEPT policy)"
	}

	result.ExposedServices = append(result.ExposedServices, models.ExposedServiceFinding{
		Code:         models.FindingExposedService,
		Certainty:    certainty,
		IPVersion:    ipVersion,
		Service:      svc,
		AllowingRule: allowRule,
		Severity:     sev,
		Scope:        scope,
		Reason:       reason,
	})
}

// classifyPortScope evaluates filter/INPUT in rule order, including jumps and
// RETURN behavior. Returns ("", nil) when no source can reach the service.
func classifyPortScope(rs *models.Ruleset, svc models.ListeningService) (models.AccessScope, *models.Rule, models.Certainty) {
	scope, allowRule, _, certainty := evaluateAccessDetailed(rs, "INPUT", packetQuery{
		Protocol: svc.Protocol,
		DstPort:  svc.Port,
		DstAddr:  svc.Address,
		State:    "NEW",
		External: true,
	})
	return scope, allowRule, certainty
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
				familyMatches := (rs.IPVersion == models.IPv6 && (svc.Family == models.SocketIPv6 || svc.Family == models.SocketDual || svc.IsIPv6)) ||
					(rs.IPVersion == models.IPv4 && (svc.Family == models.SocketIPv4 || svc.Family == models.SocketDual || (!svc.IsIPv6 && svc.Family == "")))
				if !familyMatches {
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
				Code:      models.FindingUnusedRule,
				Certainty: models.CertaintyDefinite,
				Rule:      rule,
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
