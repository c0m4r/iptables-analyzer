package analyzer

import (
	"fmt"
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
		Host:              host,
		ServiceAssessment: models.AssessmentNotRequested,
	}
	ipv4, result.IPv4Status = assessable(result, ipv4, models.IPv4)
	ipv6, result.IPv6Status = assessable(result, ipv6, models.IPv6)
	result.IPv4Rules, result.IPv6Rules = ipv4, ipv6

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

	// What the rules do by default, and which ports they open
	for _, rs := range []*models.Ruleset{ipv4, ipv6} {
		findings, open, diagnostics := checkEffectiveness(rs, host, result.PublishedPorts)
		result.EffectiveIssues = append(result.EffectiveIssues, findings...)
		result.OpenPorts = append(result.OpenPorts, open...)
		result.Diagnostics = append(result.Diagnostics, diagnostics...)
	}
	result.EffectiveIssues = append(result.EffectiveIssues, checkFamilyParity(result)...)

	return result
}

// assessable returns the ruleset to analyze for one family and its status,
// and records what iptables-save could not show. A family whose tables hold
// native nftables rules is not analyzed at all: treating the unseen rules as
// absent would report a filtered host as open.
func assessable(result *models.AnalysisResult, rs *models.Ruleset, version models.IPVersion) (*models.Ruleset, models.FamilyStatus) {
	if rs == nil {
		return nil, models.FamilyExcluded
	}
	stack := stackName(version)
	for _, warning := range rs.Warnings {
		result.Diagnostics = append(result.Diagnostics, models.AssessmentDiagnostic{Area: "rules", Message: fmt.Sprintf(
			"%s: %s. Packets pass both rule sets, so the real firewall can be stricter than this report", stack, warning)})
	}
	if len(rs.Unreadable) > 0 {
		result.Diagnostics = append(result.Diagnostics, models.AssessmentDiagnostic{Area: "rules", Message: fmt.Sprintf(
			"%s was not analyzed: table %s holds native nftables rules that iptables-save cannot print. Inspect them with 'nft list ruleset'",
			stack, strings.Join(rs.Unreadable, ", "))})
		return nil, models.FamilyUnreadable
	}
	if len(rs.Tables) == 0 {
		return rs, models.FamilyNoRules
	}
	return rs, models.FamilyAnalyzed
}

// CrossReferenceServices cross-references firewall rules with listening services
func CrossReferenceServices(result *models.AnalysisResult, services []models.ListeningService) {
	result.Services = deduplicateServices(services)
	result.ServiceAssessment = models.AssessmentComplete
	evaluators := map[*models.Ruleset]*inputEvaluator{}

	for i := range result.Services {
		svc := result.Services[i]
		// Services bound to localhost or to the loopback device aren't exposed
		if svc.Device == "lo" || (!svc.IsWildcard && isLoopback(svc.Address)) {
			result.Services[i].Status = models.ServiceLocalhost
			continue
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
		internal := false
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
			switch {
			case exposure.scope == "":
			case exposure.internal:
				internal = true
			default:
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
		case internal:
			result.Services[i].Status = models.ServiceInternal
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
		device     string
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
			device:     svc.Device,
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
	// How much an open port matters depends on what usually listens there.
	sev := ExposureSeverity(svc.Port, svc.Port, exposure.condition)
	audience := "the network"
	switch {
	case exposure.scope == models.ScopeRestricted:
		sev = models.SeverityLow
		audience = "sources that match " + exposure.restriction + " (not evaluated)"
	case exposure.scope != models.ScopeExposed:
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
	if exposure.condition != "" {
		reason += ", limited by: " + exposure.condition
	}
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
		Condition:    exposure.condition,
		Restriction:  exposure.restriction,
		Reason:       reason,
	})
}

// rateLimited reports whether a condition is a limit on the rate or the
// number of connections.
func rateLimited(condition string) bool {
	return strings.Contains(condition, "rate limit") || strings.Contains(condition, "connection limit")
}

type serviceExposure struct {
	scope       models.AccessScope
	allowRule   *models.Rule
	certainty   models.Certainty
	interfaces  []string
	internal    bool   // reachable only through guest bridges of this host
	condition   string // what a packet must meet, e.g. "rate limit"
	restriction string // what selects the sources of a RESTRICTED scope
}

// inputEvaluator evaluates the local-delivery path (raw/PREROUTING through
// security/INPUT) of one ruleset for every candidate ingress interface.
type inputEvaluator struct {
	rs         *models.Ruleset
	ctx        *evalContext
	candidates []ingressCandidate
	guests     []ingressCandidate
}

func newInputEvaluator(rs *models.Ruleset, host *models.HostContext) *inputEvaluator {
	ctx := newEvalContext(rs, inferDockerTopology(rs), host)
	return &inputEvaluator{rs: rs, ctx: ctx, candidates: ingressCandidates(rs, ctx, host), guests: guestCandidates(rs, ctx, host)}
}

// classify returns the widest exposure of a listener to other hosts. A
// listener that only guests of this host reach (through docker0, virbr0, ...)
// is reported as internal. A socket bound to a device is evaluated for that
// device alone.
func (e *inputEvaluator) classify(svc models.ListeningService) serviceExposure {
	external, guests, all := e.candidates, e.guests, e.candidates
	if svc.Device != "" {
		external, guests, all = onDevice(external, svc.Device), onDevice(guests, svc.Device), nil
		if len(external) == 0 && len(guests) == 0 {
			// The socket proves that the device exists, whatever the rules name.
			candidate := ingressCandidate{name: svc.Device}
			if isBridgeInterface(svc.Device, e.ctx) {
				guests = append(guests, candidate)
			} else {
				external = append(external, candidate)
			}
		}
	}
	exposure := e.classifyVia(svc, external, all)
	if exposure.scope != "" {
		return exposure
	}
	if internal := e.classifyVia(svc, guests, nil); internal.scope != "" {
		internal.internal = true
		return internal
	}
	return exposure
}

func onDevice(candidates []ingressCandidate, device string) []ingressCandidate {
	var result []ingressCandidate
	for _, candidate := range candidates {
		if candidate.name == device {
			result = append(result, candidate)
		}
	}
	return result
}

// newConnection is the first packet of a connection from another host to a
// local port. address is the local address, or the wildcard address.
func (e *inputEvaluator) newConnection(protocol models.Protocol, port int, address string) packetQuery {
	return packetQuery{
		Protocol:        protocol,
		DstPort:         port,
		DstAddr:         address,
		DstType:         "LOCAL",
		State:           "NEW",
		NATState:        noNAT,
		OriginalDstAddr: address,
		OriginalDstPort: port,
		Direction:       "ORIGINAL",
		External:        true,
		Ctx:             e.ctx,
	}
}

// classifyVia evaluates the listener for each given ingress interface.
func (e *inputEvaluator) classifyVia(svc models.ListeningService, candidates, all []ingressCandidate) serviceExposure {
	return e.classifyQuery(e.newConnection(svc.Protocol, svc.Port, svc.Address), candidates, all)
}

// classifyQuery evaluates a packet for each given ingress interface and
// returns the widest scope that accepts it. all is the full candidate list:
// an exposure through every one of them is reported without an interface list.
func (e *inputEvaluator) classifyQuery(base packetQuery, candidates, all []ingressCandidate) serviceExposure {
	root := rootSet(e.rs.IPVersion)
	var best serviceExposure
	var selected []ingressCandidate
	uncertain := false
	for _, candidate := range candidates {
		query := base
		query.InIface = candidate.name
		path := evaluatePath(e.rs, inputPath(query), root)
		class := path.classify()
		if class.scope == "" {
			continue
		}
		possible := class.certainty == models.CertaintyPossible
		switch {
		case scopeRank(class.scope) > scopeRank(best.scope):
			best = serviceExposure{scope: class.scope, allowRule: class.rule, condition: class.condition, restriction: class.restriction}
			selected = []ingressCandidate{candidate}
			uncertain = possible
		case class.scope == best.scope:
			selected = append(selected, candidate)
			uncertain = uncertain && possible
			if class.condition == "" {
				// Without a condition through this interface.
				best.condition = ""
			}
		}
	}
	if best.scope == "" {
		return best
	}
	best.certainty = models.CertaintyDefinite
	if uncertain || onlyAssumed(selected) {
		best.certainty = models.CertaintyPossible
	}
	best.interfaces = candidateLabels(selected, all)
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

// findUnusedRules reports ports that a rule opens although nothing listens
// on them. The ports come from the evaluation of the whole INPUT path, so
// rules in user chains count and rules that never match do not.
func findUnusedRules(result *models.AnalysisResult) {
	listening := func(open models.OpenPort) bool {
		for _, svc := range result.Services {
			if svc.Protocol != open.Protocol || svc.Port < open.First || svc.Port > open.Last {
				continue
			}
			switch {
			case svc.Family == models.SocketDual:
				return true
			case open.IPVersion == models.IPv6:
				if svc.Family == models.SocketIPv6 || svc.IsIPv6 {
					return true
				}
			case svc.Family == models.SocketIPv4 || (svc.Family == "" && !svc.IsIPv6):
				return true
			}
		}
		return false
	}
	for i := range result.OpenPorts {
		open := result.OpenPorts[i]
		// Ports that no rule names and wide ranges are findings of their own.
		// A rule for a given source port admits replies, not a service, and a
		// rule without a port was not written for this port.
		if open.Rule == nil || open.Unnamed || open.Last-open.First+1 >= broadPortCount ||
			open.Rule.SrcPort != "" || !namesPorts(open.Rule) || listening(open) {
			continue
		}
		audience := scopeAudience(open.Scope)
		if open.Scope == models.ScopeRestricted {
			audience = "sources that match " + open.Restriction
		}
		noun := "port"
		if open.Last > open.First {
			noun = "ports"
		}
		result.UnusedRules = append(result.UnusedRules, models.UnusedRuleFinding{
			Code:      models.FindingUnusedRule,
			Certainty: open.Certainty,
			IPVersion: open.IPVersion,
			Protocol:  open.Protocol,
			First:     open.First,
			Last:      open.Last,
			Scope:     open.Scope,
			Rule:      *open.Rule,
			Reason: fmt.Sprintf("%s %s %s/%s is open to %s by rule #%d in %s/%s, but nothing listens on it",
				stackName(open.IPVersion), noun, portRangeText(open.First, open.Last), open.Protocol, audience,
				open.Rule.RuleNum, open.Rule.Table, open.Rule.Chain),
		})
	}
}

// namesPorts reports whether a rule has a destination-port predicate.
func namesPorts(rule *models.Rule) bool {
	if rule.DstPort != "" {
		return true
	}
	for _, ext := range rule.Matches {
		if ext.Params["--ctorigdstport"] != "" || ext.Params["--ports"] != "" {
			return true
		}
	}
	return false
}

func isLoopback(addr string) bool {
	addr = strings.Split(addr, "%")[0]
	if prefix, err := netip.ParsePrefix(addr); err == nil {
		return prefix.Addr().IsLoopback()
	}
	parsed, err := netip.ParseAddr(addr)
	return err == nil && parsed.IsLoopback()
}
