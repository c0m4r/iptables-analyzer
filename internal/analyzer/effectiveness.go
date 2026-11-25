package analyzer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The checks in this file ask the evaluator what the ruleset does with a
// packet, instead of looking for a rule of a certain form in filter/INPUT.
// A conntrack rule in a chain of ufw, a final REJECT under an ACCEPT policy
// and a "-j ACCEPT" under a DROP policy are then judged by their effect.

// CheckEffectiveness reports conditions of one ruleset that defeat the
// firewall or break the host.
func CheckEffectiveness(rs *models.Ruleset) []models.EffectivenessFinding {
	findings, _, _ := checkEffectiveness(rs, nil, nil)
	return findings
}

func checkEffectiveness(rs *models.Ruleset, host *models.HostContext, published []models.PublishedPort) ([]models.EffectivenessFinding, []models.OpenPort, []models.AssessmentDiagnostic) {
	if rs == nil {
		return nil, nil, nil
	}
	var findings []models.EffectivenessFinding
	var open []models.OpenPort
	evaluator := newInputEvaluator(rs, host)

	if inputBlocked(rs) {
		findings = append(findings, models.EffectivenessFinding{
			Code:      models.FindingFamilyBlocked,
			Certainty: models.CertaintyDefinite,
			Title:     "INPUT accepts nothing",
			Detail: "The policy of filter/INPUT is DROP and no rule accepts a packet, so this address family is closed: " +
				"the host receives nothing over it, not even replies or loopback traffic. " +
				"That is a valid way to turn the family off.",
			Severity: models.SeverityInfo,
			Chain:    "INPUT",
			Table:    "filter",
		})
	} else {
		var defaults map[models.Protocol]serviceExposure
		open, defaults = surveyInput(evaluator, published)
		accepting := defaultAcceptFindings(rs, defaults)
		findings = append(findings, accepting...)
		findings = append(findings, broadAcceptFindings(open, defaults)...)
		if len(accepting) == 0 {
			findings = append(findings, checkReturnTraffic(evaluator)...)
		}
		findings = append(findings, checkLoopback(rs)...)
		if rs.IPVersion == models.IPv6 {
			findings = append(findings, checkNeighborDiscovery(rs)...)
		}
	}
	findings = append(findings, checkForwardDefault(evaluator)...)
	findings = append(findings, checkOutputPolicy(rs)...)
	for _, tableName := range sortedTableNames(rs) {
		table := rs.Tables[tableName]
		for _, chainName := range sortedChainNames(table) {
			findings = append(findings, checkDeadRules(table.Chains[chainName], table.Name)...)
		}
	}
	for i := range findings {
		findings[i].IPVersion = rs.IPVersion
	}

	var diagnostics []models.AssessmentDiagnostic
	if evaluator.ctx.limitReached() {
		diagnostics = append(diagnostics, evaluationLimitDiagnostic(rs, "rules"))
	}
	return findings, open, diagnostics
}

// inputChains returns the chains that a packet for a local socket can pass,
// keyed by "table/chain".
func inputChains(rs *models.Ruleset) map[string]*models.Chain {
	reached := map[string]*models.Chain{}
	var visit func(table *models.Table, name string)
	visit = func(table *models.Table, name string) {
		chain := table.Chains[name]
		key := table.Name + "/" + name
		if chain == nil || reached[key] != nil {
			return
		}
		reached[key] = chain
		for i := range chain.Rules {
			if _, isChain := table.Chains[chain.Rules[i].Target]; isChain {
				visit(table, chain.Rules[i].Target)
			}
		}
	}
	for _, stage := range inputPath(packetQuery{}) {
		if table := rs.Tables[stage.Table]; table != nil {
			visit(table, stage.Chain)
		}
	}
	return reached
}

// inputBlocked reports whether filter/INPUT cannot accept any packet: its
// policy is DROP and no chain it reaches has an accepting rule.
func inputBlocked(rs *models.Ruleset) bool {
	filter := rs.Tables["filter"]
	if filter == nil || filter.Chains["INPUT"] == nil || filter.Chains["INPUT"].Policy != "DROP" {
		return false
	}
	for key, chain := range inputChains(rs) {
		if !strings.HasPrefix(key, "filter/") {
			continue
		}
		for i := range chain.Rules {
			switch chain.Rules[i].Target {
			case "ACCEPT", "QUEUE", "NFQUEUE":
				return false
			}
		}
	}
	return true
}

// portClass is a range of destination ports that every rule on the way to a
// local socket treats alike.
type portClass struct {
	first, last int
	named       bool // some rule names these ports
}

// inputPortClasses divides the ports 1-65535 of one protocol at every
// boundary of a port predicate that can apply to it. Ports of published
// mappings are classes of their own.
func inputPortClasses(rs *models.Ruleset, protocol models.Protocol, extra map[int]bool) []portClass {
	starts := map[int]bool{1: true}
	var named [][2]int
	add := func(spec string) {
		if spec == "" {
			return
		}
		for _, r := range cachedPortRanges(spec) {
			lo, hi := max(r[0], 1), min(r[1], 65535)
			if lo > hi {
				continue
			}
			starts[lo] = true
			if hi < 65535 {
				starts[hi+1] = true
			}
			named = append(named, [2]int{lo, hi})
		}
	}
	for _, chain := range inputChains(rs) {
		for i := range chain.Rules {
			rule := &chain.Rules[i]
			// A rule for another protocol does not name ports of this one.
			if other := normalizeProtocol(rule.Protocol); other != "" && other != models.ProtoAll &&
				(other == protocol) == rule.Negations["protocol"] {
				continue
			}
			add(rule.DstPort)
			for _, ext := range rule.Matches {
				add(ext.Params["--ctorigdstport"])
				add(ext.Params["--ports"])
			}
		}
	}
	for port := range extra {
		if port >= 1 && port <= 65535 {
			starts[port] = true
			if port < 65535 {
				starts[port+1] = true
			}
		}
	}
	sorted := make([]int, 0, len(starts))
	for start := range starts {
		sorted = append(sorted, start)
	}
	sort.Ints(sorted)
	classes := make([]portClass, len(sorted))
	for i, start := range sorted {
		classes[i] = portClass{first: start, last: 65535}
		if i+1 < len(sorted) {
			classes[i].last = sorted[i+1] - 1
		}
		for _, r := range named {
			if r[0] <= start && start <= r[1] {
				classes[i].named = true
				break
			}
		}
	}
	return classes
}

// surveyInput evaluates a new connection to every class of ports and returns
// the ports that the firewall accepts, and what it does with ports that no
// rule names. No port predicate tells two unnamed ports apart, so one probe
// stands for all of them.
func surveyInput(e *inputEvaluator, published []models.PublishedPort) ([]models.OpenPort, map[models.Protocol]serviceExposure) {
	wildcard := "0.0.0.0"
	if e.rs.IPVersion == models.IPv6 {
		wildcard = "::"
	}
	// A port that nat/PREROUTING translates for every local address never
	// reaches INPUT; the published-port analysis covers it.
	translated := map[models.Protocol]map[int]bool{models.ProtoTCP: {}, models.ProtoUDP: {}}
	for _, mapping := range published {
		if mapping.IPVersion == e.rs.IPVersion && mapping.HostAddr == "" && translated[mapping.Protocol] != nil {
			translated[mapping.Protocol][mapping.HostPort] = true
		}
	}

	defaults := map[models.Protocol]serviceExposure{}
	var open []models.OpenPort
	for _, protocol := range []models.Protocol{models.ProtoTCP, models.ProtoUDP} {
		var unnamed *serviceExposure
		for _, class := range inputPortClasses(e.rs, protocol, translated[protocol]) {
			if translated[protocol][class.first] {
				continue
			}
			var exposure serviceExposure
			switch {
			case class.named:
				exposure = e.classifyQuery(e.newConnection(protocol, class.first, wildcard), e.candidates, e.candidates)
			case unnamed != nil:
				exposure = *unnamed
			default:
				exposure = e.classifyQuery(e.newConnection(protocol, class.first, wildcard), e.candidates, e.candidates)
				unnamed = &exposure
				defaults[protocol] = exposure
			}
			if exposure.scope == "" {
				continue
			}
			port := models.OpenPort{
				IPVersion: e.rs.IPVersion, Protocol: protocol, First: class.first, Last: class.last,
				Scope: exposure.scope, Certainty: exposure.certainty, Condition: exposure.condition,
				Restriction: exposure.restriction, Interfaces: exposure.interfaces, Rule: exposure.allowRule,
				Unnamed: !class.named,
			}
			if n := len(open); n > 0 && sameOpening(open[n-1], port) {
				open[n-1].Last = port.Last
				continue
			}
			open = append(open, port)
		}
	}
	return open, defaults
}

// sameOpening reports whether two port ranges are adjacent and open in the
// same way, so that they are one entry.
func sameOpening(a, b models.OpenPort) bool {
	return a.Protocol == b.Protocol && a.Last+1 == b.First && a.Scope == b.Scope && a.Certainty == b.Certainty &&
		a.Condition == b.Condition && a.Restriction == b.Restriction && a.Rule == b.Rule && a.Unnamed == b.Unnamed &&
		strings.Join(a.Interfaces, ",") == strings.Join(b.Interfaces, ",")
}

// defaultAcceptFindings reports that INPUT accepts new connections to ports
// that no rule names, from any source: the firewall does not deny by default.
func defaultAcceptFindings(rs *models.Ruleset, defaults map[models.Protocol]serviceExposure) []models.EffectivenessFinding {
	var protocols []models.Protocol
	for _, protocol := range []models.Protocol{models.ProtoTCP, models.ProtoUDP} {
		if defaults[protocol].scope == models.ScopeExposed {
			protocols = append(protocols, protocol)
		}
	}
	if len(protocols) == 0 {
		return nil
	}
	// The two protocols are one finding when the same thing accepts both.
	groups := [][]models.Protocol{protocols}
	if a, b := defaults[models.ProtoTCP], defaults[models.ProtoUDP]; len(protocols) == 2 &&
		(a.allowRule != b.allowRule || a.certainty != b.certainty || a.condition != b.condition ||
			strings.Join(a.interfaces, ",") != strings.Join(b.interfaces, ",")) {
		groups = [][]models.Protocol{{models.ProtoTCP}, {models.ProtoUDP}}
	}

	var findings []models.EffectivenessFinding
	for _, group := range groups {
		exposure := defaults[group[0]]
		what := "new connections"
		if len(group) == 1 {
			what = "new " + strings.ToUpper(string(group[0])) + " connections"
		}
		finding := models.EffectivenessFinding{
			Code:      models.FindingPolicyAccept,
			Certainty: exposure.certainty,
			Title:     "INPUT accepts " + what + " to any port",
			Severity:  models.SeverityHigh,
			Chain:     "INPUT",
			Table:     "filter",
			Rule:      exposure.allowRule,
			Unrestricted: len(group) == 2 && exposure.certainty == models.CertaintyDefinite &&
				exposure.condition == "" && len(exposure.interfaces) == 0,
		}
		verb := "accepts"
		if exposure.certainty == models.CertaintyPossible {
			finding.Title = "INPUT may accept " + what + " to any port"
			finding.Severity = models.SeverityMedium
			verb = "may accept"
		}
		switch {
		case len(rs.Tables) == 0:
			finding.Detail = "No rules are loaded for this address family, so nothing is filtered."
		case rs.Tables["filter"] == nil && exposure.allowRule == nil:
			finding.Detail = "The rules have no filter table, so nothing filters the traffic to the host."
		case exposure.allowRule != nil:
			finding.Detail = fmt.Sprintf("Rule #%d in %s/%s (%s) %s them from any source, whatever the policy of the chain is.",
				exposure.allowRule.RuleNum, exposure.allowRule.Table, exposure.allowRule.Chain, RuleSpec(exposure.allowRule), verb)
		default:
			finding.Detail = "No rule refuses them, and the policy of filter/INPUT is ACCEPT."
		}
		if exposure.condition != "" {
			finding.Detail += " The acceptance is limited by: " + exposure.condition + "."
		}
		if len(exposure.interfaces) > 0 {
			finding.Detail += " This holds for packets that arrive on " + strings.Join(exposure.interfaces, ", ") + "."
		}
		finding.Detail += " Every port that no rule names is open: a service that listens on one, now or later, is reachable at once."
		findings = append(findings, finding)
	}
	return findings
}

// broadPortCount is the number of ports from which an opening to any source
// is reported by itself. Single services and small ranges are reported with
// the services that listen on them.
const broadPortCount = 1024

// broadAcceptFindings reports wide ranges of named ports that are open to
// any source. Ports that no rule names are the default-accept finding, and
// a protocol with that finding needs no second one.
func broadAcceptFindings(open []models.OpenPort, defaults map[models.Protocol]serviceExposure) []models.EffectivenessFinding {
	var findings []models.EffectivenessFinding
	for _, protocol := range []models.Protocol{models.ProtoTCP, models.ProtoUDP} {
		if defaults[protocol].scope == models.ScopeExposed {
			continue
		}
		total := 0
		var ranges []string
		var rule *models.Rule
		certainty := models.CertaintyPossible
		for i := range open {
			port := &open[i]
			if port.Protocol != protocol || port.Scope != models.ScopeExposed || port.Unnamed {
				continue
			}
			total += port.Last - port.First + 1
			ranges = append(ranges, portRangeText(port.First, port.Last))
			if port.Certainty == models.CertaintyDefinite {
				certainty = models.CertaintyDefinite
			}
			if rule == nil || port.Last-port.First >= broadPortCount {
				rule = port.Rule
			}
		}
		if total < broadPortCount {
			continue
		}
		finding := models.EffectivenessFinding{
			Code:      models.FindingBroadAccept,
			Certainty: certainty,
			Title:     fmt.Sprintf("%d %s ports are open to any source", total, strings.ToUpper(string(protocol))),
			Detail: fmt.Sprintf("INPUT accepts new connections to %s ports %s from any source. "+
				"A rule this wide opens every service on those ports, also services that are started later.",
				strings.ToUpper(string(protocol)), abbreviateList(ranges, 6)),
			Severity: models.SeverityHigh,
			Chain:    "INPUT",
			Table:    "filter",
			Rule:     rule,
		}
		if rule != nil {
			finding.Detail += fmt.Sprintf(" Widest rule: #%d in %s/%s (%s).", rule.RuleNum, rule.Table, rule.Chain, RuleSpec(rule))
		}
		if certainty == models.CertaintyPossible {
			finding.Severity = models.SeverityMedium
		}
		findings = append(findings, finding)
	}
	return findings
}

func portRangeText(first, last int) string {
	if first == last {
		return strconv.Itoa(first)
	}
	return strconv.Itoa(first) + "-" + strconv.Itoa(last)
}

// checkReturnTraffic reports a default-deny INPUT that does not accept the
// packets of established connections.
func checkReturnTraffic(e *inputEvaluator) []models.EffectivenessFinding {
	wildcard := "0.0.0.0"
	if e.rs.IPVersion == models.IPv6 {
		wildcard = "::"
	}
	query := e.newConnection(models.ProtoTCP, unlistedPort(e.rs), wildcard)
	query.State = "ESTABLISHED"
	for _, candidate := range e.candidates {
		probe := query
		probe.InIface = candidate.name
		path := evaluatePath(e.rs, inputPath(probe), rootSet(e.rs.IPVersion))
		if len(path.Accepted) > 0 || path.Uncertain {
			return nil
		}
	}
	return []models.EffectivenessFinding{{
		Code:      models.FindingMissingConntrack,
		Certainty: models.CertaintyDefinite,
		Title:     "INPUT does not accept ESTABLISHED,RELATED traffic",
		Detail: "INPUT denies by default and no rule on its path accepts the packets of established connections, so replies to the " +
			"host's own outbound connections (DNS, package updates, NTP) and related ICMP errors such as " +
			"fragmentation-needed are dropped unless individual rules allow them. Add " +
			"'-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' near the top of INPUT.",
		Severity: models.SeverityHigh,
		Chain:    "INPUT",
		Table:    "filter",
	}}
}

// ForwardsPackets reports whether the rules show that the host routes
// packets for others: it translates addresses, or Docker manages it.
func ForwardsPackets(rs *models.Ruleset) bool {
	return rs != nil && forwardsPackets(rs)
}

func forwardsPackets(rs *models.Ruleset) bool {
	if inferDockerTopology(rs).present {
		return true
	}
	if nat := rs.Tables["nat"]; nat != nil {
		for _, chain := range nat.Chains {
			for i := range chain.Rules {
				switch chain.Rules[i].Target {
				case "DNAT", "SNAT", "MASQUERADE", "NETMAP":
					return true
				}
			}
		}
	}
	return false
}

// checkForwardDefault reports a FORWARD path that accepts a new connection
// which no rule names, whatever the interfaces are.
func checkForwardDefault(e *inputEvaluator) []models.EffectivenessFinding {
	rs := e.rs
	if filter := rs.Tables["filter"]; len(rs.Tables) > 0 && (filter == nil || filter.Chains["FORWARD"] == nil) {
		return nil // a file without the filter table says nothing about forwarding
	}
	port := unlistedPort(rs)
	var selected []ingressCandidate
	var rule *models.Rule
	definite := true
	for _, candidate := range e.candidates {
		query := packetQuery{
			Protocol: models.ProtoTCP, DstPort: port, DstType: "UNICAST", InIface: candidate.name,
			State: "NEW", NATState: noNAT, OriginalDstPort: port, Direction: "ORIGINAL", External: true, Ctx: e.ctx,
		}
		pre := evaluatePath(rs, preroutingPath(query), rootSet(rs.IPVersion))
		class := evaluatePath(rs, forwardPath(query), pre.acceptedSet()).classify()
		if class.scope != models.ScopeExposed || class.certainty != models.CertaintyDefinite {
			continue
		}
		selected = append(selected, candidate)
		definite = definite && !candidate.assumed
		if rule == nil {
			rule = class.rule
		}
	}
	if len(selected) == 0 {
		return nil
	}
	finding := models.EffectivenessFinding{
		Code:      models.FindingPolicyAccept,
		Certainty: models.CertaintyDefinite,
		Title:     "FORWARD accepts traffic that no rule names",
		Severity:  models.SeverityMedium,
		Chain:     "FORWARD",
		Table:     "filter",
		Rule:      rule,
	}
	switch {
	case len(rs.Tables) == 0:
		finding.Detail = "No rules are loaded for this address family."
	case rule != nil:
		finding.Detail = fmt.Sprintf("Rule #%d in %s/%s (%s) accepts it from any source to any destination.",
			rule.RuleNum, rule.Table, rule.Chain, RuleSpec(rule))
	default:
		finding.Detail = "No rule refuses it, and the policy of filter/FORWARD is ACCEPT."
	}
	if labels := candidateLabels(selected, e.candidates); len(labels) > 0 {
		finding.Detail += " This holds for packets that arrive on " + strings.Join(labels, ", ") + "."
	}
	if forwardsPackets(rs) {
		finding.Severity = models.SeverityHigh
		finding.Detail += " The rules show that this host routes packets (address translation or Docker), so other hosts can " +
			"send traffic through it to every network it reaches, including container and virtual networks."
	} else {
		finding.Detail += " This matters when IP forwarding is enabled (net.ipv4.ip_forward, net.ipv6.conf.all.forwarding): " +
			"the host then routes packets between its networks without a filter."
	}
	if !definite {
		finding.Certainty = models.CertaintyPossible
	}
	return []models.EffectivenessFinding{finding}
}

// checkOutputPolicy notes an OUTPUT chain that does not filter. That is the
// usual setup and no defect.
func checkOutputPolicy(rs *models.Ruleset) []models.EffectivenessFinding {
	filter := rs.Tables["filter"]
	if filter == nil || filter.Chains["OUTPUT"] == nil || filter.Chains["OUTPUT"].Policy != "ACCEPT" {
		return nil
	}
	return []models.EffectivenessFinding{{
		Code:      models.FindingPolicyAccept,
		Certainty: models.CertaintyDefinite,
		Title:     "OUTPUT default policy is ACCEPT",
		Detail: "All outbound traffic is allowed. This is the usual setup; an OUTPUT allowlist can limit what a " +
			"compromised service is able to reach.",
		Severity: models.SeverityInfo,
		Chain:    "OUTPUT",
		Table:    "filter",
	}}
}

// firstCatchAll returns the index of the first rule that ends the chain for
// every packet, or -1.
func firstCatchAll(chain *models.Chain) int {
	for i := range chain.Rules {
		if IsCatchAll(&chain.Rules[i]) && chain.Rules[i].IsTerminal() {
			return i
		}
	}
	return -1
}

// checkDeadRules reports the rules after a rule that ends the chain for every
// packet, as one finding for the chain.
func checkDeadRules(chain *models.Chain, tableName string) []models.EffectivenessFinding {
	catchAll := firstCatchAll(chain)
	if catchAll < 0 || catchAll == len(chain.Rules)-1 {
		return nil
	}
	ending := &chain.Rules[catchAll]
	dead := chain.Rules[catchAll+1:]
	// Rules with the opposite decision were meant to change what happens.
	opposite := 0
	for i := range dead {
		if (dead[i].IsBlock() || dead[i].IsAllow()) && (ending.IsBlock() || ending.IsAllow()) && dead[i].IsBlock() != ending.IsBlock() {
			opposite++
		}
	}
	numbers := "Rule #" + strconv.Itoa(dead[0].RuleNum) + " is"
	if len(dead) > 1 {
		numbers = fmt.Sprintf("Rules #%d-#%d (%d rules) are", dead[0].RuleNum, dead[len(dead)-1].RuleNum, len(dead))
	}
	finding := models.EffectivenessFinding{
		Code:      models.FindingDeadRule,
		Certainty: models.CertaintyDefinite,
		Title:     "Unreachable rules in " + tableName + "/" + chain.Name,
		Detail: fmt.Sprintf("%s never reached: rule #%d (%s) ends the chain for all traffic before.",
			numbers, ending.RuleNum, RuleSpec(ending)),
		Severity: models.SeverityMedium,
		Chain:    chain.Name,
		Table:    tableName,
		Rule:     ending,
	}
	if opposite > 0 {
		decision := "DROP or REJECT"
		if ending.IsBlock() {
			decision = "ACCEPT"
		}
		finding.Severity = models.SeverityHigh
		finding.Detail += fmt.Sprintf(" %d of them %s %s and %s no effect.", opposite,
			pluralWord(opposite, "is", "are"), decision, pluralWord(opposite, "has", "have"))
	}
	return []models.EffectivenessFinding{finding}
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// IsCatchAll returns true if a rule is known to match all traffic. Unknown or
// unsupported predicates make this return false rather than risking a false
// dead-rule or policy conclusion.
func IsCatchAll(rule *models.Rule) bool {
	if len(rule.Negations) > 0 {
		return false
	}
	if rule.Fragment {
		return false
	}
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
	if len(rule.States) > 0 {
		return false
	}
	// Check for narrowing match extensions (e.g. recent --update, limit)
	if hasNarrowingMatches(rule.Matches) {
		return false
	}
	return true
}

// hasNarrowingMatches returns true if any match extension restricts which
// packets the rule applies to beyond protocol/addr/port/state.
func hasNarrowingMatches(exts []models.MatchExt) bool {
	for _, ext := range exts {
		if matchConstraintSignature(ext) != "" {
			return true
		}
	}
	return false
}

// checkLoopback reports an INPUT path that definitely drops traffic on lo.
func checkLoopback(rs *models.Ruleset) []models.EffectivenessFinding {
	source := "127.0.0.0/8"
	if rs.IPVersion == models.IPv6 {
		source = "::1/128"
	}
	prefix, _ := parsePrefix(source)
	address := prefix.Addr().String()
	query := packetQuery{
		Protocol: models.ProtoTCP, DstPort: unlistedPort(rs), DstAddr: address, DstType: "LOCAL",
		InIface: "lo", State: "NEW", NATState: noNAT, Direction: "ORIGINAL",
		OriginalDstAddr: address, OriginalDstPort: unlistedPort(rs),
	}
	path := evaluatePath(rs, inputPath(query), setOfPrefix(prefix))
	if len(path.Accepted) > 0 || path.Uncertain {
		return nil
	}
	return []models.EffectivenessFinding{{
		Code:      models.FindingMissingLoopback,
		Certainty: models.CertaintyDefinite,
		Title:     "Loopback traffic is dropped by INPUT",
		Detail: "New connections on the lo interface are refused. Local services that talk to each other over " +
			address + " (databases, DNS stub resolvers, Docker's userland proxy) will fail. " +
			"Add '-A INPUT -i lo -j ACCEPT' as the first INPUT rule.",
		Severity: models.SeverityMedium,
		Chain:    "INPUT",
		Table:    "filter",
	}}
}

// checkNeighborDiscovery reports an IPv6 INPUT path that definitely drops
// Neighbor Discovery. ND messages are never conntrack-tracked (their state is
// UNTRACKED), so ESTABLISHED,RELATED and NEW rules do not admit them.
func checkNeighborDiscovery(rs *models.Ruleset) []models.EffectivenessFinding {
	ctx := newEvalContext(rs, inferDockerTopology(rs), nil)
	candidates := ingressCandidates(rs, ctx, nil)
	blocked := func(icmpType string) bool {
		for _, candidate := range candidates {
			query := packetQuery{
				Protocol: "ipv6-icmp", ICMPType: icmpType, HopLimit: 255, InIface: candidate.name,
				State: "UNTRACKED", NATState: noNAT, External: true, Ctx: ctx,
			}
			path := evaluatePath(rs, inputPath(query), rootSet(models.IPv6))
			if len(path.Accepted) > 0 || path.Uncertain {
				return false
			}
		}
		return true
	}
	var findings []models.EffectivenessFinding
	if blocked("135") || blocked("136") {
		findings = append(findings, models.EffectivenessFinding{
			Code:      models.FindingIPv6NDPBlocked,
			Certainty: models.CertaintyDefinite,
			Title:     "IPv6 Neighbor Discovery is dropped by INPUT",
			Detail: "ICMPv6 neighbor solicitations/advertisements (types 135/136) are refused. They are untracked by " +
				"conntrack, so ESTABLISHED,RELATED rules do not admit them, and without them the host cannot resolve " +
				"IPv6 neighbors: IPv6 connectivity breaks. Allow them explicitly, e.g. " +
				"'-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT' (and 136).",
			Severity: models.SeverityHigh,
			Chain:    "INPUT",
			Table:    "filter",
		})
	}
	if blocked("134") {
		findings = append(findings, models.EffectivenessFinding{
			Code:      models.FindingIPv6NDPBlocked,
			Certainty: models.CertaintyDefinite,
			Title:     "IPv6 Router Advertisements are dropped by INPUT",
			Detail: "ICMPv6 router advertisements (type 134) are refused. A host that configures IPv6 with SLAAC " +
				"loses its addresses and default route when they expire. Allow them with " +
				"'-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT' unless addressing is static.",
			Severity: models.SeverityMedium,
			Chain:    "INPUT",
			Table:    "filter",
		})
	}
	return findings
}

// checkFamilyParity reports ports that IPv6 opens to any source while IPv4
// restricts or filters them: the usual result of maintaining only the IPv4
// rules.
func checkFamilyParity(result *models.AnalysisResult) []models.EffectivenessFinding {
	if result.IPv4Status != models.FamilyAnalyzed || result.IPv6Status != models.FamilyAnalyzed {
		return nil
	}
	for _, finding := range result.EffectiveIssues {
		if finding.Chain == "INPUT" && (finding.Code == models.FindingPolicyAccept || finding.Code == models.FindingFamilyBlocked) {
			return nil // one family accepts or refuses everything; that finding says more
		}
	}
	// scope4 returns the IPv4 scope of one port.
	scope4 := func(protocol models.Protocol, port int) models.AccessScope {
		for _, open := range result.OpenPorts {
			if open.IPVersion == models.IPv4 && open.Protocol == protocol && open.First <= port && port <= open.Last {
				return open.Scope
			}
		}
		return ""
	}
	// IPv4 changes only at the boundaries of its own entries.
	cutsWithin := func(protocol models.Protocol, first, last int) []int {
		cuts := map[int]bool{first: true}
		for _, open := range result.OpenPorts {
			if open.IPVersion != models.IPv4 || open.Protocol != protocol {
				continue
			}
			for _, cut := range []int{open.First, open.Last + 1} {
				if cut > first && cut <= last {
					cuts[cut] = true
				}
			}
		}
		sorted := make([]int, 0, len(cuts))
		for cut := range cuts {
			sorted = append(sorted, cut)
		}
		sort.Ints(sorted)
		return sorted
	}

	var restricted, filtered []string
	for _, open := range result.OpenPorts {
		if open.IPVersion != models.IPv6 || open.Scope != models.ScopeExposed || open.Certainty != models.CertaintyDefinite {
			continue
		}
		cuts := cutsWithin(open.Protocol, open.First, open.Last)
		for i, start := range cuts {
			end := open.Last
			if i+1 < len(cuts) {
				end = cuts[i+1] - 1
			}
			text := portRangeText(start, end) + "/" + string(open.Protocol)
			switch scope := scope4(open.Protocol, start); {
			case scope == models.ScopeExposed:
			case scope == "":
				filtered = append(filtered, text)
			default:
				restricted = append(restricted, text+" ("+strings.ToLower(string(scope))+" on IPv4)")
			}
		}
	}
	var findings []models.EffectivenessFinding
	if len(restricted) > 0 {
		findings = append(findings, models.EffectivenessFinding{
			Code:      models.FindingIPv6Wider,
			Certainty: models.CertaintyDefinite,
			Title:     "IPv6 opens ports to any source that IPv4 restricts",
			Detail: "The IPv4 rules limit who may connect to " + abbreviateList(restricted, 8) +
				", but the IPv6 rules accept those ports from any source. A client that reaches the host over IPv6 passes the restriction.",
			Severity:  models.SeverityHigh,
			Chain:     "INPUT",
			Table:     "filter",
			IPVersion: models.IPv6,
		})
	}
	if len(filtered) > 0 {
		findings = append(findings, models.EffectivenessFinding{
			Code:      models.FindingIPv6Wider,
			Certainty: models.CertaintyDefinite,
			Title:     "IPv6 opens ports that IPv4 filters",
			Detail: "The IPv6 rules accept " + abbreviateList(filtered, 8) +
				" from any source, and the IPv4 rules do not accept these ports at all. Check that the IPv6 rules are intended.",
			Severity:  models.SeverityMedium,
			Chain:     "INPUT",
			Table:     "filter",
			IPVersion: models.IPv6,
		})
	}
	return findings
}

func containsState(states []string, target string) bool {
	for _, s := range states {
		if s == target {
			return true
		}
	}
	return false
}
