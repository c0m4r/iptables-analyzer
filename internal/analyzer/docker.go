package analyzer

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
)

// DockerAnalysis is the result of analyzing Docker's packet paths for one
// address family.
type DockerAnalysis struct {
	Findings       []models.DockerBypassFinding
	PublishedPorts []models.PublishedPort
	Diagnostics    []models.AssessmentDiagnostic
	// Notes say what the analysis leaves out on purpose.
	Notes []string
}

// DetectDockerBypasses finds published ports that bypass filter/INPUT and are
// accepted on the translated path through filter/FORWARD.
func DetectDockerBypasses(rs *models.Ruleset) []models.DockerBypassFinding {
	return AnalyzeDocker(rs, nil).Findings
}

// AnalyzeDocker evaluates every port that nat/PREROUTING sends to another
// host, and every known container endpoint, along the Netfilter hooks a
// packet traverses:
//
//	raw/PREROUTING → mangle/PREROUTING → nat/PREROUTING (DNAT)
//	→ mangle/FORWARD → filter/FORWARD → security/FORWARD
//
// and compares the result with what mangle/INPUT, filter/INPUT and
// security/INPUT would have decided for the untranslated packet. The ports
// are those of Docker, of kube-proxy and of plain port forwards alike: they
// are found by following the packet, not by the form of a rule.
func AnalyzeDocker(rs *models.Ruleset, host *models.HostContext) DockerAnalysis {
	if rs == nil {
		return DockerAnalysis{}
	}
	// A host that does not route packets sends nothing to another host,
	// whatever the nat table and FORWARD say.
	if on, known := host.Forwarding(rs.IPVersion); known && !on {
		var analysis DockerAnalysis
		if forwardsPackets(rs) {
			analysis.Notes = append(analysis.Notes, fmt.Sprintf(
				"%s: this host does not route packets (%s is 0), so the rules that send ports to other hosts and the FORWARD chain have no effect now. They were not examined.",
				stackName(rs.IPVersion), forwardingSetting(rs.IPVersion)))
		}
		return analysis
	}
	eval := newInputEvaluator(rs, host)
	d := &dockerAnalyzer{rs: rs, topo: eval.topo, ctx: eval.ctx, host: host, candidates: eval.candidates, eval: eval,
		ruleFindings: map[string]*ruleFindingGroup{}}

	d.analyzePublishedPorts()
	d.analyzeDirectRouting()
	d.analyzeFragileOrder()

	var analysis DockerAnalysis
	analysis.PublishedPorts = d.published
	analysis.Findings = append(analysis.Findings, mergePortFindings(d.portFindings)...)
	analysis.Findings = append(analysis.Findings, d.flushRuleFindings()...)
	analysis.Findings = append(analysis.Findings, d.directFindings...)
	analysis.Findings = append(analysis.Findings, d.fragileFindings...)
	if d.ctx.limitReached() {
		analysis.Diagnostics = append(analysis.Diagnostics, evaluationLimitDiagnostic(rs, "docker"))
	}
	if n := eval.clusterIPs; n > 0 {
		analysis.Notes = append(analysis.Notes, fmt.Sprintf(
			"%s: %d cluster IP %s of Kubernetes services %s not examined. A cluster IP is no address of the node; "+
				"only hosts that route the service network through this node reach it.",
			stackName(rs.IPVersion), n, pluralWord(n, "address", "addresses"), pluralWord(n, "was", "were")))
	}
	return analysis
}

type dockerAnalyzer struct {
	rs         *models.Ruleset
	topo       *dockerTopology
	ctx        *evalContext
	host       *models.HostContext
	candidates []ingressCandidate
	eval       *inputEvaluator

	published       []models.PublishedPort
	publishedTo     map[string]bool      // container endpoints reached through a published port
	forwardAccepted map[string]labelSets // container endpoint -> sources accepted through published ports
	forwardRules    []*models.Rule
	loopbackOnly    map[string]string // container endpoint -> loopback host port
	portFindings    []portFinding
	ruleFindings    map[string]*ruleFindingGroup
	ruleOrder       []string
	directFindings  []models.DockerBypassFinding
	fragileFindings []models.DockerBypassFinding
}

type portFinding struct {
	finding          models.DockerBypassFinding
	explicit         bool
	protocol         models.Protocol
	hostPort         int
	hostPortEnd      int
	containerAddr    string
	containerPort    int
	containerPortEnd int
}

func endpointKey(protocol models.Protocol, addr string, port int) string {
	return string(protocol) + "|" + addr + "|" + strconv.Itoa(port)
}

// candidateOutcome is the evaluation of one published port for one ingress
// interface.
type candidateOutcome struct {
	candidate ingressCandidate
	forward   pathResult
	input     pathResult
	// bypass holds sources FORWARD accepts and INPUT refuses; definiteBypass
	// the subset established without undecidable predicates.
	bypass         []decisionSegment
	definiteBypass []decisionSegment
}

func (d *dockerAnalyzer) analyzePublishedPorts() {
	natTable := d.rs.Tables["nat"]
	if natTable == nil || natTable.Chains["PREROUTING"] == nil {
		return
	}
	d.forwardAccepted = map[string]labelSets{}
	d.publishedTo = map[string]bool{}
	d.loopbackOnly = map[string]string{}
	d.forwardRules = d.userForwardRules()
	d.noteDockerPublications(natTable)

	wildcard := "0.0.0.0"
	if d.rs.IPVersion == models.IPv6 {
		wildcard = "::"
	}
	for _, protocol := range []models.Protocol{models.ProtoTCP, models.ProtoUDP} {
		classes := d.eval.classes(protocol)
		for _, class := range classes {
			d.analyzeClass(protocol, wildcard, class)
		}
		// A translation that a rule makes for one local address only.
		for i := range d.eval.named {
			dest := &d.eval.named[i]
			for _, class := range classes {
				if dest.names(class) {
					d.analyzeClass(protocol, dest.addr.String(), class)
				}
			}
		}
	}
	sort.SliceStable(d.published, func(i, j int) bool {
		a, b := d.published[i], d.published[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.HostPort != b.HostPort {
			return a.HostPort < b.HostPort
		}
		return a.HostAddr < b.HostAddr
	})
	// A container port published on loopback and elsewhere is not loopback-only.
	for endpoint := range d.publishedTo {
		delete(d.loopbackOnly, endpoint)
	}
}

// noteDockerPublications records the container ports that DNAT rules with a
// port of their own name: those published on loopback only, which no packet
// from another host reaches, and all others. The analysis of packets routed
// straight to a container needs both.
func (d *dockerAnalyzer) noteDockerPublications(natTable *models.Table) {
	for _, dnat := range allDNATRules(natTable) {
		if dnat.DstPort == "" || dnat.DNATTarget == "" || dnat.Protocol == "" || dnat.Protocol == models.ProtoAll {
			continue
		}
		translation, err := parseDNATTranslation(dnat.DNATTarget)
		if err != nil {
			continue
		}
		if target, err := netip.ParseAddr(translation.Address); err != nil || target.IsLoopback() {
			continue
		}
		originalPorts := portsInSpec(dnat.DstPort)
		if len(originalPorts) == 0 || dnat.Negations["dport"] {
			continue
		}
		loopback := isLoopback(dnat.DstAddr) && !dnat.Negations["dst"]
		for _, hostPort := range originalPorts {
			containerPort := translatedPort(translation, originalPorts[0], hostPort)
			if containerPort == 0 {
				continue
			}
			endpoint := endpointKey(dnat.Protocol, translation.Address, containerPort)
			if !loopback {
				d.publishedTo[endpoint] = true
			} else if _, exists := d.loopbackOnly[endpoint]; !exists {
				d.loopbackOnly[endpoint] = strconv.Itoa(hostPort)
			}
		}
	}
}

// natEntry is the traffic of one ingress interface that a rule of
// nat/PREROUTING sends to another host.
type natEntry struct {
	candidate ingressCandidate
	original  packetQuery
	way       ingressWay
}

// analyzeClass follows a new connection to the ports of a class through
// PREROUTING for every ingress interface, and evaluates each translation to
// another host that it meets.
func (d *dockerAnalyzer) analyzeClass(protocol models.Protocol, address string, class portClass) {
	base := d.eval.newConnection(protocol, class.first, address)
	entries := map[*models.Rule][]natEntry{}
	var order []*models.Rule
	for _, candidate := range d.candidates {
		original := base
		original.InIface = candidate.name
		for _, way := range d.eval.ways(original, class) {
			if way.rule == nil || way.local {
				continue // INPUT decides: the survey of open ports covers it
			}
			if entries[way.rule] == nil {
				order = append(order, way.rule)
			}
			entries[way.rule] = append(entries[way.rule], natEntry{candidate: candidate, original: original, way: way})
		}
	}
	for _, rule := range order {
		d.analyzeMapping(protocol, address, class, rule, entries[rule])
	}
}

// maxEndpointPorts is the widest range of translated ports whose ports are
// noted one by one for the analysis of direct routing.
const maxEndpointPorts = 64

// mappingEndpoints returns the keys of the endpoints of a mapping.
func mappingEndpoints(mapping models.PublishedPort) []string {
	last := max(mapping.ContainerPort, mapping.ContainerPortEnd)
	if last-mapping.ContainerPort >= maxEndpointPorts {
		last = mapping.ContainerPort
	}
	var keys []string
	for port := mapping.ContainerPort; port <= last; port++ {
		keys = append(keys, endpointKey(mapping.Protocol, mapping.ContainerAddr, port))
	}
	return keys
}

func (d *dockerAnalyzer) analyzeMapping(protocol models.Protocol, address string, class portClass, rule *models.Rule, entries []natEntry) {
	target := entries[0].way.translation
	hostAddr := ""
	if !wildcardAddress(address) {
		hostAddr = address
	}
	mapping := models.PublishedPort{
		IPVersion:        d.rs.IPVersion,
		Protocol:         protocol,
		HostAddr:         hostAddr,
		HostPort:         class.first,
		HostPortEnd:      class.last,
		ContainerAddr:    target.addr,
		ContainerPort:    target.port,
		ContainerPortEnd: target.portEnd,
		Bridge:           d.topo.bridgeFor(target.addr),
		NATRule:          *rule,
		Certainty:        models.CertaintyDefinite,
	}

	var outcomes []candidateOutcome
	var forwardSegments, inputSegments []decisionSegment
	for _, entry := range entries {
		forward := d.eval.forward(entry.way)
		// What INPUT would decide for the same sources, had the port not been
		// translated.
		input := evaluatePath(d.rs, inputPath(entry.original)[2:], segmentsUnion(entry.way.entry, nil))
		outcome := candidateOutcome{candidate: entry.candidate, forward: forward, input: input}
		// A source bypasses INPUT when FORWARD accepts it and INPUT does not
		// accept it in full.
		var certain []decisionSegment
		for _, segment := range forward.Accepted {
			if !segment.Possible {
				certain = append(certain, segment)
			}
		}
		outcome.bypass = segmentsMinus(forward.Accepted, input.unconditionalSet())
		outcome.definiteBypass = segmentsMinus(certain, input.acceptedSet())
		outcomes = append(outcomes, outcome)
		forwardSegments = append(forwardSegments, forward.Accepted...)
		inputSegments = append(inputSegments, input.Accepted...)
		if len(forward.Accepted) > 0 {
			d.checkForwardRules(mapping, entry.original, entry.way.query, forward)
		}
	}
	endpoints := mappingEndpoints(mapping)
	for _, endpoint := range endpoints {
		d.publishedTo[endpoint] = true
	}
	if len(outcomes) == 0 {
		return
	}
	mapping.ForwardScope, _, _ = classifySegments(forwardSegments)
	mapping.InputScope, _, _ = classifySegments(inputSegments)
	var reachable []ingressCandidate
	definite := false
	for _, outcome := range outcomes {
		if len(outcome.forward.Accepted) > 0 {
			reachable = append(reachable, outcome.candidate)
		}
		if !outcome.forward.definiteSet().empty() && !outcome.candidate.assumed {
			definite = true
		}
	}
	if len(reachable) > 0 && !definite {
		mapping.Certainty = models.CertaintyPossible
	}
	mapping.Interfaces = candidateLabels(reachable, d.candidates)
	d.published = append(d.published, mapping)
	for _, endpoint := range endpoints {
		if d.forwardAccepted[endpoint] == nil {
			d.forwardAccepted[endpoint] = labelSets{}
		}
		d.forwardAccepted[endpoint].add(forwardSegments)
	}

	if finding, ok := d.classifyMapping(mapping, outcomes); ok {
		explicit := finding.Fix == "true"
		finding.Fix = ""
		d.portFindings = append(d.portFindings, portFinding{
			finding: finding, explicit: explicit, protocol: protocol,
			hostPort: mapping.HostPort, hostPortEnd: mapping.HostPortEnd, containerAddr: mapping.ContainerAddr,
			containerPort: mapping.ContainerPort, containerPortEnd: mapping.ContainerPortEnd,
		})
	}
}

// portRangeOf renders the ports first-last of a mapping.
func portRangeOf(first, last int) string {
	if last > first {
		return strconv.Itoa(first) + "-" + strconv.Itoa(last)
	}
	return strconv.Itoa(first)
}

// classifyMapping turns the per-interface outcomes of one published port into
// at most one finding: a bypass when filter/INPUT would have refused sources
// that FORWARD accepts, otherwise an exposure when FORWARD accepts everyone.
func (d *dockerAnalyzer) classifyMapping(mapping models.PublishedPort, outcomes []candidateOutcome) (models.DockerBypassFinding, bool) {
	type verdict struct {
		code      models.FindingCode
		severity  models.Severity
		scope     models.AccessScope
		inputRule *models.Rule
		explicit  bool
	}
	var best *verdict
	var selected []ingressCandidate
	uncertain := false
	for _, outcome := range outcomes {
		var current verdict
		possible := false
		bypass := outcome.definiteBypass
		if len(bypass) == 0 {
			bypass, possible = outcome.bypass, true
		}
		bypassScope, _, _ := classifySegments(bypass)
		inputRule, explicit := explicitInputRestriction(outcome.input, segmentsUnion(bypass, nil))
		forwardClass := outcome.forward.classify()
		forwardScope, forwardCertainty := forwardClass.scope, forwardClass.certainty
		switch {
		// A default-deny INPUT policy bypassed only for sources that the DNAT
		// itself restricts is the operator's own access control, not a bypass.
		// A port forward that the administrator wrote is meant to pass INPUT
		// by; it is a bypass only of an INPUT rule that names the port.
		case len(bypass) > 0 && (explicit || (bypassScope == models.ScopeExposed && dockerRule(&mapping.NATRule))):
			current = verdict{code: models.FindingDockerBypass, scope: bypassScope, inputRule: inputRule, explicit: explicit}
			if explicit && bypassScope == models.ScopeExposed {
				current.severity = models.SeverityCritical
			} else {
				current.severity = models.SeverityHigh
			}
		case forwardScope == models.ScopeExposed:
			current = verdict{code: models.FindingDockerPublished, scope: models.ScopeExposed, severity: models.SeverityMedium}
			if mapping.HostPort < 1024 {
				current.severity = models.SeverityHigh
			}
			possible = forwardCertainty == models.CertaintyPossible
		default:
			continue
		}
		switch {
		case best == nil || current.severity > best.severity:
			copied := current
			best = &copied
			selected = []ingressCandidate{outcome.candidate}
			uncertain = possible
		case current.severity == best.severity && current.code == best.code:
			selected = append(selected, outcome.candidate)
			uncertain = uncertain && possible
		}
	}
	if best == nil {
		return models.DockerBypassFinding{}, false
	}

	certainty := models.CertaintyDefinite
	if uncertain || onlyAssumed(selected) {
		certainty = models.CertaintyPossible
	}
	interfaces := candidateLabels(selected, d.candidates)
	port := portRangeOf(mapping.HostPort, mapping.HostPortEnd)
	dest := joinHostPort(mapping.ContainerAddr, portRangeOf(mapping.ContainerPort, mapping.ContainerPortEnd))
	finding := models.DockerBypassFinding{
		Code:          best.code,
		Certainty:     certainty,
		IPVersion:     mapping.IPVersion,
		NATRule:       mapping.NATRule,
		HostAddr:      mapping.HostAddr,
		ExposedPort:   port,
		ContainerDest: dest,
		Bridge:        mapping.Bridge,
		Scope:         best.scope,
		Interfaces:    interfaces,
		Severity:      best.severity,
	}
	if best.inputRule != nil {
		finding.InputRule = *best.inputRule
	}
	finding.Fix = strconv.FormatBool(best.explicit) // consumed by mergePortFindings
	return finding, true
}

// explicitInputRestriction reports the INPUT rule that refuses the bypassing
// sources. A refusal by a port- or source-specific rule, or a source-restricted
// allow, is explicit; a refusal only by the policy or a catch-all DROP is not.
func explicitInputRestriction(input pathResult, bypass addrSet) (*models.Rule, bool) {
	var fallback *models.Rule
	for _, segment := range input.Dropped {
		if segment.Rule == nil || !segment.Set.overlaps(bypass) {
			continue
		}
		if namesDestination(segment.Rule) {
			return segment.Rule, true
		}
		if fallback == nil {
			fallback = segment.Rule
		}
	}
	for _, segment := range input.Accepted {
		if segment.Rule != nil && namesDestination(segment.Rule) {
			return segment.Rule, true
		}
	}
	return fallback, false
}

// namesDestination reports whether a rule was written for a destination: it
// has a port or a destination-address predicate. A rule that only names
// sources or interfaces ("accept everything from the LAN", a blocklist entry)
// says nothing about one published port, so traffic that passes it by is not
// a bypass of an explicit restriction.
func namesDestination(rule *models.Rule) bool {
	if namesPorts(rule) {
		return true
	}
	return rule.DstAddr != "" && rule.DstAddr != "0.0.0.0/0" && rule.DstAddr != "::/0"
}

// dockerRule reports whether Docker wrote a NAT rule. Other DNAT rules are
// port forwards of the administrator, of kube-proxy or of libvirt.
func dockerRule(rule *models.Rule) bool {
	return strings.HasPrefix(rule.Chain, "DOCKER")
}

// IsDockerRule reports whether a NAT rule is in a chain that Docker manages.
func IsDockerRule(rule *models.Rule) bool {
	return rule != nil && dockerRule(rule)
}

func mappingReason(finding models.DockerBypassFinding, explicit, plural bool) string {
	stack := stackName(finding.IPVersion)
	noun, verb := "port", "is"
	if plural {
		noun, verb = "ports", "are"
	}
	via := ""
	if len(finding.Interfaces) > 0 {
		via = " via " + strings.Join(finding.Interfaces, ", ")
	}
	audience := scopeAudience(finding.Scope)
	nat := finding.NATRule.Table + "/" + finding.NATRule.Chain + " rule #" + strconv.Itoa(finding.NATRule.RuleNum)
	switch finding.Code {
	case models.FindingDockerBypass:
		if explicit && finding.InputRule.RuleNum > 0 {
			return fmt.Sprintf("%s %s %s/%s %s restricted by %s/%s rule #%d (%s), but %s DNATs the traffic to %s before INPUT is consulted; filter/FORWARD still accepts the refused sources (%s)%s.",
				stack, noun, finding.ExposedPort, finding.NATRule.Protocol, verb, finding.InputRule.Table, finding.InputRule.Chain,
				finding.InputRule.RuleNum, RuleSpec(&finding.InputRule), nat, finding.ContainerDest, audience, via)
		}
		return fmt.Sprintf("%s %s %s/%s would be refused by the default-deny filter/INPUT policy, but %s DNATs the traffic to %s and filter/FORWARD accepts it from %s%s.",
			stack, noun, finding.ExposedPort, finding.NATRule.Protocol, nat, finding.ContainerDest, audience, via)
	default:
		published := "published"
		if !dockerRule(&finding.NATRule) {
			published = "forwarded"
		}
		return fmt.Sprintf("%s %s %s/%s %s %s by %s to %s and accepted through filter/FORWARD from %s%s; host INPUT rules do not apply.",
			stack, noun, finding.ExposedPort, finding.NATRule.Protocol, verb, published, nat, finding.ContainerDest, audience, via)
	}
}

func scopeAudience(scope models.AccessScope) string {
	switch scope {
	case models.ScopeSubnet:
		return "specific public networks"
	case models.ScopeLocalnet:
		return "private networks"
	case models.ScopeWhitelisted:
		return "individual hosts"
	case models.ScopeRestricted:
		return "sources selected by a match that was not evaluated (ipset, MAC address)"
	}
	return "any source"
}

// forwardingSetting names the kernel setting that makes the host route
// packets of an address family.
func forwardingSetting(version models.IPVersion) string {
	if version == models.IPv6 {
		return "net.ipv6.conf.all.forwarding"
	}
	return "net.ipv4.ip_forward"
}

func stackName(version models.IPVersion) string {
	if version == models.IPv6 {
		return "IPv6"
	}
	return "IPv4"
}

// PublishedGroup is a run of published ports that Docker maps one-to-one onto
// consecutive container ports with identical verdicts.
type PublishedGroup struct {
	models.PublishedPort
	HostPortEnd      int
	ContainerPortEnd int
}

// GroupPublishedPorts merges consecutive mappings for display. Docker emits one
// rule per port of a published range, so -p 10000-20000 yields 10001 mappings.
func GroupPublishedPorts(ports []models.PublishedPort) []PublishedGroup {
	var groups []PublishedGroup
	for _, mapping := range ports {
		if n := len(groups); n > 0 {
			last := &groups[n-1]
			if last.IPVersion == mapping.IPVersion && last.Protocol == mapping.Protocol &&
				last.HostAddr == mapping.HostAddr && last.ContainerAddr == mapping.ContainerAddr &&
				last.Bridge == mapping.Bridge && last.ForwardScope == mapping.ForwardScope &&
				last.InputScope == mapping.InputScope && last.Certainty == mapping.Certainty &&
				mapping.HostPort == last.HostPortEnd+1 && mapping.ContainerPort == last.ContainerPortEnd+1 {
				last.HostPortEnd = max(mapping.HostPort, mapping.HostPortEnd)
				last.ContainerPortEnd = max(mapping.ContainerPort, mapping.ContainerPortEnd)
				continue
			}
		}
		groups = append(groups, PublishedGroup{PublishedPort: mapping,
			HostPortEnd: max(mapping.HostPort, mapping.HostPortEnd), ContainerPortEnd: max(mapping.ContainerPort, mapping.ContainerPortEnd)})
	}
	return groups
}

// mergePortFindings collapses findings for consecutive ports of one container
// (Docker emits one DNAT rule per port of a published range).
func mergePortFindings(findings []portFinding) []models.DockerBypassFinding {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.finding.IPVersion != b.finding.IPVersion {
			return a.finding.IPVersion < b.finding.IPVersion
		}
		if a.containerAddr != b.containerAddr {
			return a.containerAddr < b.containerAddr
		}
		if a.protocol != b.protocol {
			return a.protocol < b.protocol
		}
		return a.hostPort < b.hostPort
	})
	var merged []models.DockerBypassFinding
	for i := 0; i < len(findings); {
		j := i + 1
		for j < len(findings) && samePortGroup(findings[j-1], findings[j]) {
			j++
		}
		finding := findings[i].finding
		first, last := findings[i], findings[j-1]
		hostEnd, containerEnd := max(last.hostPort, last.hostPortEnd), max(last.containerPort, last.containerPortEnd)
		if hostEnd > first.hostPort {
			finding.ExposedPort = portRangeOf(first.hostPort, hostEnd)
			finding.ContainerDest = joinHostPort(first.containerAddr, portRangeOf(first.containerPort, containerEnd))
		}
		finding.Reason = mappingReason(finding, findings[i].explicit, hostEnd > first.hostPort)
		if finding.Certainty == models.CertaintyPossible {
			finding.Reason = "Possible path: " + finding.Reason
		}
		merged = append(merged, finding)
		i = j
	}
	return merged
}

func samePortGroup(a, b portFinding) bool {
	return a.finding.Code == b.finding.Code && a.finding.IPVersion == b.finding.IPVersion &&
		a.finding.Severity == b.finding.Severity && a.finding.Scope == b.finding.Scope &&
		a.finding.Certainty == b.finding.Certainty && a.protocol == b.protocol &&
		a.containerAddr == b.containerAddr && a.finding.InputRule.RuleNum == b.finding.InputRule.RuleNum &&
		strings.Join(a.finding.Interfaces, ",") == strings.Join(b.finding.Interfaces, ",") &&
		a.finding.NATRule.Chain == b.finding.NATRule.Chain && a.finding.HostAddr == b.finding.HostAddr &&
		b.hostPort == max(a.hostPort, a.hostPortEnd)+1 && b.containerPort == max(a.containerPort, a.containerPortEnd)+1
}

// ruleFindingGroup accumulates the published ports for which one user rule
// in the forwarding path is ineffective.
type ruleFindingGroup struct {
	finding models.DockerBypassFinding
	ports   []string
	dests   []string
}

// userForwardRules returns the DROP/REJECT rules that users control on the
// forwarding path: mangle/FORWARD, filter/FORWARD and every non-Docker chain
// reachable from it.
func (d *dockerAnalyzer) userForwardRules() []*models.Rule {
	var rules []*models.Rule
	visit := map[string]bool{}
	var walk func(table *models.Table, chainName string)
	walk = func(table *models.Table, chainName string) {
		key := table.Name + "/" + chainName
		chain := table.Chains[chainName]
		if chain == nil || visit[key] || dockerOwnedChain(chainName) {
			return
		}
		visit[key] = true
		for i := range chain.Rules {
			rule := &chain.Rules[i]
			if rule.IsBlock() {
				rules = append(rules, rule)
			}
			if _, isChain := table.Chains[rule.Target]; isChain {
				walk(table, rule.Target)
			}
		}
	}
	for _, tableName := range []string{"mangle", "filter"} {
		if table := d.rs.Tables[tableName]; table != nil {
			walk(table, "FORWARD")
		}
	}
	return rules
}

// checkForwardRules finds user DROP/REJECT rules that were evidently written
// for this published port but never take effect: rules that match the
// pre-DNAT destination, and rules that Docker's earlier ACCEPT shadows.
func (d *dockerAnalyzer) checkForwardRules(mapping models.PublishedPort, original, translated packetQuery, forward pathResult) {
	accepted := forward.acceptedSet()
	dropped := map[*models.Rule]bool{}
	for _, segment := range forward.Dropped {
		if segment.Rule != nil {
			dropped[segment.Rule] = true
		}
	}
	preDNAT := translated
	preDNAT.DstAddr = original.DstAddr
	preDNAT.DstPort = original.DstPort
	preDNAT.DstType = "LOCAL"
	for _, rule := range d.forwardRules {
		if !sourceMayMatch(accepted, rule, translated) {
			continue
		}
		afterDNAT := ruleMatchesQuery(rule, translated)
		switch {
		case afterDNAT == matchNo:
			beforeDNAT := ruleMatchesQuery(rule, preDNAT)
			if beforeDNAT == matchYes || (beforeDNAT == matchMaybe && rule.DstAddr == "") {
				d.addRuleFinding(rule, mapping, beforeDNAT == matchYes, true)
			}
		case afterDNAT == matchYes && !dropped[rule] && !IsCatchAll(rule):
			d.addRuleFinding(rule, mapping, true, false)
		}
	}
}

func (d *dockerAnalyzer) addRuleFinding(rule *models.Rule, mapping models.PublishedPort, definite, preDNAT bool) {
	key := fmt.Sprintf("%s/%s#%d|%t", rule.Table, rule.Chain, rule.RuleNum, preDNAT)
	port := portRangeOf(mapping.HostPort, mapping.HostPortEnd) + "/" + string(mapping.Protocol)
	dest := joinHostPort(mapping.ContainerAddr, portRangeOf(mapping.ContainerPort, mapping.ContainerPortEnd))
	group := d.ruleFindings[key]
	if group == nil {
		group = &ruleFindingGroup{finding: models.DockerBypassFinding{
			Code:      models.FindingDockerIneffectiveRule,
			Certainty: models.CertaintyPossible,
			IPVersion: d.rs.IPVersion,
			NATRule:   mapping.NATRule,
			Rule:      rule,
			Bridge:    mapping.Bridge,
			Severity:  models.SeverityHigh,
			Scope:     mapping.ForwardScope,
		}}
		if !preDNAT {
			group.finding.Code = models.FindingDockerShadowedRule
		}
		d.ruleFindings[key] = group
		d.ruleOrder = append(d.ruleOrder, key)
	}
	if definite {
		// One definite path is enough: the rule is ineffective for it.
		group.finding.Certainty = models.CertaintyDefinite
	}
	if !containsString(group.ports, port) {
		group.ports = append(group.ports, port)
		group.dests = append(group.dests, dest)
	}
}

func (d *dockerAnalyzer) flushRuleFindings() []models.DockerBypassFinding {
	var findings []models.DockerBypassFinding
	for _, key := range d.ruleOrder {
		group := d.ruleFindings[key]
		finding := group.finding
		rule := finding.Rule
		finding.ExposedPort = strings.Join(group.ports, ", ")
		finding.ContainerDest = strings.Join(group.dests, ", ")
		ports := abbreviateList(group.ports, 4)
		dests := abbreviateList(group.dests, 4)
		location := fmt.Sprintf("%s/%s rule #%d (%s)", rule.Table, rule.Chain, rule.RuleNum, RuleSpec(rule))
		if finding.Code == models.FindingDockerIneffectiveRule {
			finding.Reason = fmt.Sprintf("%s %s never matches published traffic for %s: Docker DNATs it to %s in nat/PREROUTING, so FORWARD sees the container address and port, not the published ones.",
				stackName(finding.IPVersion), location, ports, dests)
			finding.Fix = "Match the published port with -m conntrack --ctorigdstport <port> --ctdir ORIGINAL (and the host address with --ctorigdst) instead of --dport/-d."
		} else {
			finding.Reason = fmt.Sprintf("%s %s would block published traffic for %s (%s), but Docker's chains accept that traffic earlier in the FORWARD path, so this rule is never reached for it.",
				stackName(finding.IPVersion), location, ports, dests)
			finding.Fix = "Move the restriction into DOCKER-USER, which Docker evaluates before its own ACCEPT rules."
		}
		if finding.Certainty == models.CertaintyPossible {
			finding.Reason = "Possible path: " + finding.Reason
		}
		findings = append(findings, finding)
	}
	return findings
}

func abbreviateList(values []string, limit int) string {
	if len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return strings.Join(values[:limit], ", ") + fmt.Sprintf(" and %d more", len(values)-limit)
}

// joinHostPort renders addr:port with brackets for IPv6 addresses.
func joinHostPort(addr, port string) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]:" + port
	}
	return addr + ":" + port
}

// RuleSpec renders a rule's match and target specification as iptables-save
// prints it, without counters and the "-A CHAIN" prefix.
func RuleSpec(rule *models.Rule) string {
	raw := strings.TrimSpace(rule.RawLine)
	if strings.HasPrefix(raw, "[") {
		if end := strings.Index(raw, "]"); end >= 0 {
			raw = strings.TrimSpace(raw[end+1:])
		}
	}
	if prefix := "-A " + rule.Chain + " "; strings.HasPrefix(raw, prefix) {
		return strings.TrimPrefix(raw, prefix)
	}
	if raw == "" {
		return rule.Summary()
	}
	return raw
}

// RuleArgs returns a rule's match and target specification as the argument
// list iptables receives, without the quoting of iptables-save. Commands
// built from it must quote each argument (textsafe.ShellJoin): comments and
// names in a ruleset can contain shell syntax.
func RuleArgs(rule *models.Rule) []string {
	args, err := parser.Tokenize(RuleSpec(rule))
	if err != nil {
		return nil
	}
	return args
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// analyzeDirectRouting evaluates packets that are routed straight to a
// container address instead of a published host port. Docker 28+ drops them
// in raw/PREROUTING; older releases and the routed/nat-unprotected gateway
// modes forward them, which bypasses both INPUT and published-port rules
// that match --ctorigdstport.
func (d *dockerAnalyzer) analyzeDirectRouting() {
	if !d.topo.present {
		return
	}
	type endpoint struct {
		protocol models.Protocol
		addr     string
		port     int
		probe    bool // an arbitrary port no rule names
	}
	if d.loopbackOnly == nil {
		d.loopbackOnly = map[string]string{}
	}
	var endpoints []endpoint
	seen := map[string]bool{}
	add := func(e endpoint) {
		key := endpointKey(e.protocol, e.addr, e.port)
		if seen[key] {
			return
		}
		seen[key] = true
		endpoints = append(endpoints, e)
	}
	if filter := d.rs.Tables["filter"]; filter != nil && filter.Chains["DOCKER"] != nil {
		docker := filter.Chains["DOCKER"]
		for _, rule := range docker.Rules {
			prefix, ok := parsePrefix(rule.DstAddr)
			if rule.Target != "ACCEPT" || !ok || !prefix.IsSingleIP() || rule.Negations["dst"] ||
				rule.DstPort == "" || rule.Negations["dport"] || rule.Protocol == "" || rule.Protocol == models.ProtoAll {
				continue
			}
			for _, port := range portsInSpec(rule.DstPort) {
				add(endpoint{protocol: rule.Protocol, addr: prefix.Addr().String(), port: port})
			}
		}
	}
	for _, mapping := range d.published {
		last := max(mapping.ContainerPort, mapping.ContainerPortEnd)
		if last-mapping.ContainerPort >= maxEndpointPorts {
			last = mapping.ContainerPort
		}
		for port := mapping.ContainerPort; port <= last; port++ {
			add(endpoint{protocol: mapping.Protocol, addr: mapping.ContainerAddr, port: port})
		}
	}
	for key := range d.loopbackOnly {
		parts := strings.Split(key, "|")
		port, _ := strconv.Atoi(parts[2])
		add(endpoint{protocol: models.Protocol(parts[0]), addr: parts[1], port: port})
	}
	probePort := unlistedPort(d.rs)
	for addr, bridge := range d.topo.containerBridge {
		if d.topo.openBridges[bridge] != nil && (addr.Is6() == (d.rs.IPVersion == models.IPv6)) {
			add(endpoint{protocol: models.ProtoTCP, addr: addr.String(), port: probePort, probe: true})
		}
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].addr != endpoints[j].addr {
			return endpoints[i].addr < endpoints[j].addr
		}
		return endpoints[i].port < endpoints[j].port
	})

	reportedOpen := map[string]bool{}
	for _, e := range endpoints {
		addr, err := netip.ParseAddr(e.addr)
		if err != nil || addr.Is6() != (d.rs.IPVersion == models.IPv6) {
			continue
		}
		bridge := d.topo.bridgeFor(e.addr)
		var reachable []ingressCandidate
		var accepted []decisionSegment
		definitePath := false
		for _, candidate := range d.candidates {
			query := packetQuery{
				Protocol:        e.protocol,
				DstPort:         e.port,
				DstAddr:         e.addr,
				DstType:         "UNICAST",
				InIface:         candidate.name,
				OutIface:        bridge,
				State:           "NEW",
				NATState:        noNAT,
				OriginalDstAddr: e.addr,
				OriginalDstPort: e.port,
				Direction:       "ORIGINAL",
				External:        true,
				Ctx:             d.ctx,
			}
			sources, _ := d.eval.arriving(candidate.name)
			pre := evaluatePath(d.rs, preroutingPath(query), sources)
			forward := evaluatePath(d.rs, forwardPath(query), pre.acceptedSet())
			if len(forward.Accepted) == 0 {
				continue
			}
			reachable = append(reachable, candidate)
			accepted = append(accepted, forward.Accepted...)
			definitePath = definitePath || !forward.definiteSet().empty()
		}
		if len(reachable) == 0 {
			continue
		}
		key := endpointKey(e.protocol, e.addr, e.port)
		finding := models.DockerBypassFinding{
			Code:          models.FindingDockerDirectRoute,
			Certainty:     models.CertaintyPossible,
			IPVersion:     d.rs.IPVersion,
			ExposedPort:   strconv.Itoa(e.port),
			ContainerDest: joinHostPort(e.addr, strconv.Itoa(e.port)),
			Bridge:        bridge,
			Scope:         segmentsScope(accepted),
			Interfaces:    candidateLabels(reachable, d.candidates),
		}
		mode := d.topo.gatewayMode(bridge)
		finding.GatewayMode = mode
		route := "hosts that route " + e.addr + " via this host (for example on the same L2 segment)"
		switch {
		case e.probe:
			if reportedOpen[bridge] {
				continue
			}
			reportedOpen[bridge] = true
			finding.ExposedPort = "all"
			finding.ContainerDest = joinHostPort(e.addr, "*")
			finding.Severity = models.SeverityHigh
			finding.Reason = fmt.Sprintf("Every port of containers on bridge %s (gateway mode %s) is forwarded to %s, including ports that were never published; neither INPUT nor published-port rules apply.",
				bridgeLabel(bridge), mode, route)
			finding.Fix = "Use the default gateway mode \"nat\" for this network, or drop new non-DNAT connections into the bridge in DOCKER-USER."
		case d.loopbackOnly[key] != "":
			finding.Severity = models.SeverityHigh
			finding.Reason = fmt.Sprintf("%s/%s is published only on loopback (host port %s), but packets routed directly to the container address are forwarded from %s; raw/PREROUTING has no Docker direct-access protection for it.",
				finding.ContainerDest, e.protocol, d.loopbackOnly[key], route)
			finding.Fix = "Upgrade Docker to 28.0 or later, which drops direct-routed packets in raw/PREROUTING, or add that protection manually."
		case d.publishedTo[key]:
			extra := segmentsBeyond(accepted, d.forwardAccepted[key])
			if len(extra) == 0 {
				continue // already as reachable through the published port
			}
			finding.Scope = segmentsScope(extra)
			finding.Severity = models.SeverityHigh
			finding.Reason = fmt.Sprintf("Restrictions on the published port for %s/%s can be bypassed: packets routed directly to the container address are forwarded from %s, and rules matching --ctorigdstport do not see them.",
				finding.ContainerDest, e.protocol, route)
			finding.Fix = "Upgrade Docker to 28.0 or later, or drop new non-DNAT connections into the bridge in DOCKER-USER."
		case !d.topo.rawProtected[addr] && mode == "routed":
			finding.Severity = models.SeverityMedium
			finding.Reason = fmt.Sprintf("Container port %s/%s on bridge %s (gateway mode routed) is forwarded without NAT to %s; host INPUT rules do not apply to it.",
				finding.ContainerDest, e.protocol, bridgeLabel(bridge), route)
			finding.Fix = "Restrict the container port in DOCKER-USER (match -d " + e.addr + " --dport " + strconv.Itoa(e.port) + "), or use gateway mode nat."
		default:
			finding.Severity = models.SeverityMedium
			finding.Reason = fmt.Sprintf("Container port %s/%s is forwarded to %s without passing a published host port; host INPUT rules do not apply to it.",
				finding.ContainerDest, e.protocol, route)
			finding.Fix = "Restrict the container address in DOCKER-USER, or upgrade Docker to 28.0 or later."
		}
		if finding.Scope != models.ScopeExposed && finding.Severity > models.SeverityLow {
			finding.Severity--
		}
		if !definitePath {
			finding.Reason = "Possible path: " + finding.Reason
		}
		d.directFindings = append(d.directFindings, finding)
	}
}

func segmentsScope(segments []decisionSegment) models.AccessScope {
	scope, _, _ := classifySegments(segments)
	return scope
}

func bridgeLabel(bridge string) string {
	if bridge == "" {
		return "(unknown)"
	}
	return bridge
}

// unlistedPort returns a port that no destination-port predicate names, so
// that a probe for it represents "any other port".
func unlistedPort(rs *models.Ruleset) int {
	covered := func(port int) bool {
		for _, table := range rs.Tables {
			for _, chain := range table.Chains {
				for _, rule := range chain.Rules {
					if rule.DstPort != "" && portMatches(rule.DstPort, strconv.Itoa(port)) {
						return true
					}
				}
			}
		}
		return false
	}
	for _, port := range []int{47_391, 31_337, 2, 65_000} {
		if !covered(port) {
			return port
		}
	}
	return 47_391
}

// analyzeFragileOrder reports user rules placed in filter/FORWARD above
// Docker's jumps. dockerd re-inserts its jumps at the top of FORWARD when it
// starts, after which these rules no longer see container traffic first.
func (d *dockerAnalyzer) analyzeFragileOrder() {
	filter := d.rs.Tables["filter"]
	if !d.topo.present || filter == nil || filter.Chains["FORWARD"] == nil || filter.Chains["DOCKER-USER"] == nil {
		return
	}
	forward := filter.Chains["FORWARD"]
	jump := -1
	for i, rule := range forward.Rules {
		if rule.Target == "DOCKER-USER" || rule.Target == "DOCKER-FORWARD" {
			jump = i
			break
		}
	}
	for i := 0; i < jump; i++ {
		rule := &forward.Rules[i]
		if strings.HasPrefix(rule.Target, "DOCKER") {
			continue
		}
		d.fragileFindings = append(d.fragileFindings, models.DockerBypassFinding{
			Code:      models.FindingDockerFragileRule,
			Certainty: models.CertaintyPossible,
			IPVersion: d.rs.IPVersion,
			Rule:      rule,
			Severity:  models.SeverityMedium,
			Reason: fmt.Sprintf("%s filter/FORWARD rule #%d (%s) is above Docker's jump to %s. dockerd re-inserts its jumps at the top of FORWARD when it restarts, after which Docker accepts container traffic before this rule is evaluated.",
				stackName(d.rs.IPVersion), rule.RuleNum, RuleSpec(rule), forward.Rules[jump].Target),
			Fix: "Move the rule into DOCKER-USER, which Docker never reorders or flushes.",
		})
	}
}

// DockerIPv6Gaps reports IPv6 forwarding that Docker does not manage while it
// manages IPv4: with ip6tables integration disabled, IPv6-enabled container
// networks are routed without any Docker filtering.
func DockerIPv6Gaps(ipv4, ipv6 *models.Ruleset, host *models.HostContext) []models.DockerBypassFinding {
	if ipv4 == nil || ipv6 == nil || len(ipv6.Tables) == 0 {
		return nil
	}
	if on, known := host.Forwarding(models.IPv6); known && !on {
		return nil // the host routes no IPv6 packets to its containers
	}
	if !inferDockerTopology(ipv4).present || inferDockerTopology(ipv6).present {
		return nil
	}
	filter := ipv6.Tables["filter"]
	if filter == nil || filter.Chains["FORWARD"] == nil {
		return nil
	}
	forward := filter.Chains["FORWARD"]
	if forward.Policy != "ACCEPT" {
		return nil
	}
	if n := len(forward.Rules); n > 0 && forward.Rules[n-1].IsBlock() && IsCatchAll(&forward.Rules[n-1]) {
		return nil
	}
	return []models.DockerBypassFinding{{
		Code:      models.FindingDockerIPv6Unfiltered,
		Certainty: models.CertaintyPossible,
		IPVersion: models.IPv6,
		Severity:  models.SeverityHigh,
		Reason: "Docker manages iptables but not ip6tables, and the IPv6 filter/FORWARD policy is ACCEPT. " +
			"Any IPv6-enabled container network is routed to its globally addressable containers without filtering.",
		Fix: "Keep Docker's ip6tables integration enabled (\"ip6tables\": true in daemon.json, the default since Docker 27) and set ip6tables -P FORWARD DROP.",
	}}
}

// DockerAssessmentDiagnostics reports translations that cannot be followed,
// instead of leaving them out silently. Rules with the same gap are one note.
func DockerAssessmentDiagnostics(rs *models.Ruleset) []models.AssessmentDiagnostic {
	if rs == nil {
		return nil
	}
	type group struct {
		area      string
		reason    string
		locations []string
	}
	var groups []*group
	add := func(area, reason string, rule *models.Rule) {
		location := fmt.Sprintf("%s/%s rule #%d", rule.Table, rule.Chain, rule.RuleNum)
		for _, g := range groups {
			if g.reason == reason {
				g.locations = append(g.locations, location)
				return
			}
		}
		groups = append(groups, &group{area: area, reason: reason, locations: []string{location}})
	}
	// Only rules that a packet from another host can meet matter here.
	chains := preroutingChains(rs)
	keys := make([]string, 0, len(chains))
	for key := range chains {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		chain := chains[key]
		for i := range chain.Rules {
			rule := &chain.Rules[i]
			switch {
			case rule.Table == "nat" && rule.Target == "DNAT" && rule.DNATTarget == "":
				add("docker", "DNAT target is missing; the translation was not assessed", rule)
			case rule.Table == "nat" && rule.Target == "DNAT":
				translation, err := parseDNATTranslation(rule.DNATTarget)
				switch {
				case err != nil:
					add("docker", err.Error()+"; the translation was not assessed", rule)
				case translation.HasPort && translation.PortEnd > translation.PortStart && rule.DstPort != "" && !rule.Negations["dport"] &&
					translation.PortEnd-translation.PortStart+1 < len(portsInSpec(rule.DstPort)):
					add("docker", "translated port range is shorter than the original port range; part of the mapping was not assessed", rule)
				}
			case rule.Table == "nat" && rule.Target == "NETMAP":
				add("nat", "NETMAP maps a network of addresses to another one, which is not followed; the ports behind it were not assessed", rule)
			case rule.Table == "mangle" && rule.Target == "TPROXY":
				add("nat", "TPROXY hands the packets to a local proxy without changing them, which is not followed; "+
					"the proxy also receives the traffic that the rule matches", rule)
			}
		}
	}

	diagnostics := make([]models.AssessmentDiagnostic, 0, len(groups))
	for _, g := range groups {
		where := abbreviateList(g.locations, 3)
		if n := len(g.locations); n > 1 {
			where = fmt.Sprintf("%d rules (%s)", n, where)
		}
		diagnostics = append(diagnostics, models.AssessmentDiagnostic{Area: g.area,
			Message: fmt.Sprintf("IPv%d %s: %s", rs.IPVersion, where, g.reason)})
	}
	return diagnostics
}

func allDNATRules(table *models.Table) []models.Rule {
	var rules []models.Rule
	for _, chainName := range sortedChainNames(table) {
		for _, rule := range table.Chains[chainName].Rules {
			if rule.Target == "DNAT" {
				rules = append(rules, rule)
			}
		}
	}
	return rules
}

type dnatTranslation struct {
	Address   string
	PortStart int
	PortEnd   int
	HasPort   bool
}

func parseDNATTranslation(target string) (dnatTranslation, error) {
	if address, err := netip.ParseAddr(target); err == nil {
		return dnatTranslation{Address: address.String()}, nil
	}

	var host, portText string
	if strings.HasPrefix(target, "[") {
		close := strings.LastIndex(target, "]:")
		if close < 0 {
			if address, err := netip.ParseAddr(strings.Trim(target, "[]")); err == nil {
				return dnatTranslation{Address: address.String()}, nil
			}
			return dnatTranslation{}, fmt.Errorf("invalid bracketed DNAT target %q", target)
		}
		host = target[1:close]
		portText = target[close+2:]
	} else if strings.Count(target, ":") == 1 {
		host, portText, _ = strings.Cut(target, ":")
	} else {
		return dnatTranslation{}, fmt.Errorf("invalid or ambiguous DNAT target %q", target)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return dnatTranslation{}, fmt.Errorf("invalid DNAT address %q", host)
	}
	ports := portsInSpec(strings.ReplaceAll(portText, "-", ":"))
	if len(ports) == 0 {
		return dnatTranslation{}, fmt.Errorf("invalid DNAT port %q", portText)
	}
	return dnatTranslation{Address: address.String(), PortStart: ports[0], PortEnd: ports[len(ports)-1], HasPort: true}, nil
}

// ParseDNATTarget is retained for callers that need the first translated port.
// Bare IPv6 addresses are returned intact with port zero.
func ParseDNATTarget(target string) (string, int) {
	translation, err := parseDNATTranslation(target)
	if err != nil {
		return target, 0
	}
	return translation.Address, translation.PortStart
}

func translatedPort(translation dnatTranslation, firstOriginal, original int) int {
	if !translation.HasPort {
		return original
	}
	if translation.PortStart == translation.PortEnd {
		return translation.PortStart
	}
	translated := translation.PortStart + original - firstOriginal
	if translated > translation.PortEnd {
		return 0
	}
	return translated
}

func portsInSpec(spec string) []int {
	var ports []int
	for _, portRange := range expandPorts(spec) {
		start := max(1, portRange[0])
		end := min(65535, portRange[1])
		for port := start; port <= end; port++ {
			ports = append(ports, port)
		}
	}
	return ports
}
