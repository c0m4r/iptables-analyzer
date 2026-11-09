package analyzer

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// Analyze runs all analysis on the rulesets
func Analyze(ipv4, ipv6 *models.Ruleset) *models.AnalysisResult {
	return AnalyzeHost(ipv4, ipv6, nil)
}

// AnalyzeHost runs all analysis on the rulesets. host carries live facts such
// as the interface list; nil means they are unknown (saved rulesets).
func AnalyzeHost(ipv4, ipv6 *models.Ruleset, host *models.HostContext) *models.AnalysisResult {
	result := &models.AnalysisResult{
		IPv4Rules:         ipv4,
		IPv6Rules:         ipv6,
		Host:              host,
		ServiceAssessment: models.AssessmentNotRequested,
	}

	// Shadow detection
	result.ShadowedRules = append(result.ShadowedRules, DetectShadowedRules(ipv4)...)
	result.ShadowedRules = append(result.ShadowedRules, DetectShadowedRules(ipv6)...)

	// Docker packet-path analysis
	for _, rs := range []*models.Ruleset{ipv4, ipv6} {
		docker := AnalyzeDocker(rs, host)
		result.DockerBypasses = append(result.DockerBypasses, docker.Findings...)
		result.PublishedPorts = append(result.PublishedPorts, docker.PublishedPorts...)
		result.Diagnostics = append(result.Diagnostics, docker.Diagnostics...)
		result.Diagnostics = append(result.Diagnostics, DockerAssessmentDiagnostics(rs)...)
	}
	result.DockerBypasses = append(result.DockerBypasses, DockerIPv6Gaps(ipv4, ipv6)...)

	// Effectiveness checks
	result.EffectiveIssues = append(result.EffectiveIssues, CheckEffectiveness(ipv4)...)
	result.EffectiveIssues = append(result.EffectiveIssues, CheckEffectiveness(ipv6)...)

	return result
}

// CrossReferenceServices cross-references firewall rules with listening services
func CrossReferenceServices(result *models.AnalysisResult, services []models.ListeningService) {
	result.Services = deduplicateServices(services)
	result.ServiceAssessment = models.AssessmentComplete
	evaluators := map[*models.Ruleset]*inputEvaluator{}

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
		published := false
		for _, family := range families {
			rs := result.IPv4Rules
			label := "IPv4"
			evaluated := svc
			if svc.IsWildcard || svc.Family == models.SocketDual {
				evaluated.Address = "0.0.0.0"
			}
			evaluated.IsIPv6 = false
			evaluated.Family = models.SocketIPv4
			if family == models.IPv6 {
				rs = result.IPv6Rules
				label = "IPv6"
				if svc.IsWildcard || svc.Family == models.SocketDual {
					evaluated.Address = "::"
				}
				evaluated.IsIPv6 = true
				evaluated.Family = models.SocketIPv6
			}
			if rs == nil {
				continue
			}
			assessed = true
			if mapping := publishedMapping(result.PublishedPorts, family, evaluated); mapping != nil {
				// nat/PREROUTING translates this port before INPUT; the listener
				// (typically docker-proxy) is not what external clients reach.
				published = true
				if mapping.ForwardScope != "" {
					reachable = true
				}
				continue
			}
			evaluator := evaluators[rs]
			if evaluator == nil {
				evaluator = newInputEvaluator(rs, result.Host)
				evaluators[rs] = evaluator
			}
			exposure := evaluator.classify(evaluated)
			if exposure.scope != "" {
				reachable = true
				addServiceFinding(result, evaluated, exposure, label, family)
			}
		}
		switch {
		case !assessed:
			result.Services[i].Status = models.ServiceNotAnalyzed
		case published:
			result.Services[i].Status = models.ServiceDocker
		case reachable:
			result.Services[i].Status = models.ServiceReachable
		default:
			result.Services[i].Status = models.ServiceFiltered
		}
	}
	for _, rs := range []*models.Ruleset{result.IPv4Rules, result.IPv6Rules} {
		if evaluator := evaluators[rs]; evaluator != nil && evaluator.ctx.limitReached() {
			result.Diagnostics = append(result.Diagnostics, evaluationLimitDiagnostic(rs, "services"))
		}
	}

	// Find unused rules (rules for ports with no listening service)
	findUnusedRules(result)
}

// publishedMapping returns the Docker mapping that intercepts traffic for the
// listener before INPUT, if any. A mapping bound to one host address only
// intercepts a listener bound to that same address.
func publishedMapping(mappings []models.PublishedPort, family models.IPVersion, svc models.ListeningService) *models.PublishedPort {
	for i := range mappings {
		mapping := &mappings[i]
		if mapping.IPVersion != family || mapping.Protocol != svc.Protocol || mapping.HostPort != svc.Port {
			continue
		}
		if mapping.HostAddr == "" || mapping.HostAddr == svc.Address {
			return mapping
		}
	}
	return nil
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
func addServiceFinding(result *models.AnalysisResult, svc models.ListeningService, exposure serviceExposure, ipLabel string, ipVersion models.IPVersion) {
	sev := models.SeverityHigh
	if svc.Port >= 1024 {
		sev = models.SeverityMedium
	}
	audience := "the network"
	if exposure.scope != models.ScopeExposed {
		sev = models.SeverityLow
		audience = scopeAudience(exposure.scope)
	}

	reachability := "is accessible"
	if exposure.certainty == models.CertaintyPossible {
		reachability = "may be accessible"
	}
	process := svc.Process
	if process == "" {
		process = "(unknown process)"
	}
	reason := "Service " + process + " listening on port " +
		strconv.Itoa(svc.Port) + "/" + string(svc.Protocol) +
		" (" + ipLabel + ") " + reachability + " from " + audience
	if len(exposure.interfaces) > 0 {
		reason += " via " + strings.Join(exposure.interfaces, ", ")
	}
	if svc.Process == "docker-proxy" {
		reason += "; docker-proxy relays it to a container, so unlike DNATed traffic this path is filtered by INPUT"
	}
	if exposure.allowRule != nil {
		reason += " (allowed by rule #" + strconv.Itoa(exposure.allowRule.RuleNum) + " in " +
			exposure.allowRule.Table + "/" + exposure.allowRule.Chain + ")"
	} else {
		reason += " (allowed by default ACCEPT policy)"
	}

	result.ExposedServices = append(result.ExposedServices, models.ExposedServiceFinding{
		Code:         models.FindingExposedService,
		Certainty:    exposure.certainty,
		IPVersion:    ipVersion,
		Service:      svc,
		AllowingRule: exposure.allowRule,
		Severity:     sev,
		Scope:        exposure.scope,
		Interfaces:   exposure.interfaces,
		Reason:       reason,
	})
}

type serviceExposure struct {
	scope      models.AccessScope
	allowRule  *models.Rule
	certainty  models.Certainty
	interfaces []string
}

// inputEvaluator evaluates the local-delivery path (raw/PREROUTING through
// security/INPUT) of one ruleset for every candidate ingress interface.
type inputEvaluator struct {
	rs         *models.Ruleset
	ctx        *evalContext
	candidates []ingressCandidate
}

func newInputEvaluator(rs *models.Ruleset, host *models.HostContext) *inputEvaluator {
	ctx := newEvalContext(rs, inferDockerTopology(rs), host)
	return &inputEvaluator{rs: rs, ctx: ctx, candidates: ingressCandidates(rs, ctx, host)}
}

func (e *inputEvaluator) classify(svc models.ListeningService) serviceExposure {
	root := []netip.Prefix{rootPrefix(e.rs.IPVersion)}
	var best serviceExposure
	var selected []ingressCandidate
	uncertain := false
	for _, candidate := range e.candidates {
		query := packetQuery{
			Protocol:        svc.Protocol,
			DstPort:         svc.Port,
			DstAddr:         svc.Address,
			DstType:         "LOCAL",
			InIface:         candidate.name,
			State:           "NEW",
			NATState:        noNAT,
			OriginalDstAddr: svc.Address,
			OriginalDstPort: svc.Port,
			Direction:       "ORIGINAL",
			External:        true,
			Ctx:             e.ctx,
		}
		path := evaluatePath(e.rs, inputPath(query), root)
		scope, rule, certainty := path.classify()
		if scope == "" {
			continue
		}
		possible := certainty == models.CertaintyPossible
		switch {
		case scopeRank(scope) > scopeRank(best.scope):
			best = serviceExposure{scope: scope, allowRule: rule}
			selected = []ingressCandidate{candidate}
			uncertain = possible
		case scope == best.scope:
			selected = append(selected, candidate)
			uncertain = uncertain && possible
		}
	}
	if best.scope == "" {
		return best
	}
	best.certainty = models.CertaintyDefinite
	if uncertain || onlyAssumed(selected) {
		best.certainty = models.CertaintyPossible
	}
	best.interfaces = candidateLabels(selected, e.candidates)
	return best
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
