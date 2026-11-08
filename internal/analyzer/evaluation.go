package analyzer

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// otherInterface stands for an ingress interface that no rule names. Rules
// that name an interface are evaluated with that interface as a separate
// candidate, so an exact name never matches this placeholder.
const otherInterface = "\x00other"

// noNAT marks a connection that is known not to have been translated.
const noNAT = "NONE"

// packetQuery fixes the packet attributes known to an analysis. Empty interface
// and destination fields mean that multiple values are possible.
type packetQuery struct {
	Protocol        models.Protocol
	SrcPort         int
	DstPort         int
	DstAddr         string
	DstType         string // addrtype of the destination: LOCAL, UNICAST or "" when unknown
	InIface         string
	OutIface        string
	State           string
	NATState        string
	OriginalDstAddr string
	OriginalDstPort int
	Direction       string
	External        bool
	ICMPType        string // numeric ICMP/ICMPv6 type, "" when unknown
	HopLimit        int    // IPv6 hop limit, 0 when unknown
	Ctx             *evalContext
	Chain           string
	Hook            string
}

// evalContext carries ruleset-wide knowledge that individual predicates need,
// such as which interfaces Docker manages and which addresses are local.
type evalContext struct {
	bridges        map[string]bool
	containerAddrs map[netip.Addr]bool
	localAddrs     []netip.Addr
	localKnown     bool
	indexes        map[*models.Chain]*chainIndex
}

// chainIndex lists, per destination port, the rules of a chain that can match
// it. Docker emits one rule per published port, so large chains are common and
// a linear scan per evaluated packet would be quadratic.
type chainIndex struct {
	always []int         // rules without a positive, valid destination-port predicate
	byPort map[int][]int // rules whose destination-port predicate covers the port
}

func newChainIndex(chain *models.Chain) *chainIndex {
	index := &chainIndex{byPort: map[int][]int{}}
	for i := range chain.Rules {
		rule := &chain.Rules[i]
		ranges := cachedPortRanges(rule.DstPort)
		span := 0
		for _, r := range ranges {
			span += r[1] - r[0] + 1
		}
		if rule.DstPort == "" || rule.Negations["dport"] || len(ranges) == 0 || span > 1024 {
			index.always = append(index.always, i)
			continue
		}
		for _, r := range ranges {
			for port := r[0]; port <= r[1]; port++ {
				index.byPort[port] = append(index.byPort[port], i)
			}
		}
	}
	return index
}

// ruleOrder returns the indices of the rules of chain to evaluate for query,
// in chain order. Rules left out cannot match the query's destination port.
func ruleOrder(chain *models.Chain, query packetQuery) []int {
	if query.Ctx == nil || len(chain.Rules) < 32 || query.DstPort < 0 || query.DstPort > 65535 {
		order := make([]int, len(chain.Rules))
		for i := range order {
			order[i] = i
		}
		return order
	}
	if query.Ctx.indexes == nil {
		query.Ctx.indexes = map[*models.Chain]*chainIndex{}
	}
	index := query.Ctx.indexes[chain]
	if index == nil {
		index = newChainIndex(chain)
		query.Ctx.indexes[chain] = index
	}
	ports := index.byPort[query.DstPort]
	order := make([]int, 0, len(index.always)+len(ports))
	i, j := 0, 0
	for i < len(index.always) || j < len(ports) {
		if j >= len(ports) || (i < len(index.always) && index.always[i] < ports[j]) {
			order = append(order, index.always[i])
			i++
		} else {
			order = append(order, ports[j])
			j++
		}
	}
	return order
}

type matchCertainty uint8

const (
	matchNo matchCertainty = iota
	matchMaybe
	matchYes
)

func certaintyOf(matched bool) matchCertainty {
	if matched {
		return matchYes
	}
	return matchNo
}

// decisionSegment is a verdict for a source prefix. Possible marks a verdict
// that depends on a predicate the analysis cannot decide (for example a rate
// limit or an ipset) having matched; the branch where such a predicate does not
// match is evaluated as definite.
type decisionSegment struct {
	Prefix   netip.Prefix
	Rule     *models.Rule
	Possible bool
}

type chainEvaluation struct {
	Accepted  []decisionSegment
	Dropped   []decisionSegment
	Returned  []netip.Prefix
	Uncertain bool
}

func rootPrefix(version models.IPVersion) netip.Prefix {
	if version == models.IPv6 {
		return netip.MustParsePrefix("::/0")
	}
	return netip.MustParsePrefix("0.0.0.0/0")
}

// pathStage is one Netfilter hook traversal of a packet path. Stages are
// evaluated in order and only accepted sources continue to the next stage.
type pathStage struct {
	Table string
	Chain string
	Query packetQuery
}

type pathResult struct {
	Accepted  []decisionSegment
	Dropped   []decisionSegment
	Uncertain bool
}

func (r pathResult) acceptedPrefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(r.Accepted))
	for _, segment := range r.Accepted {
		prefixes = append(prefixes, segment.Prefix)
	}
	return normalizePrefixes(prefixes)
}

// definitePrefixes returns the sources accepted without relying on any
// undecidable predicate having matched.
func (r pathResult) definitePrefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(r.Accepted))
	for _, segment := range r.Accepted {
		if !segment.Possible {
			prefixes = append(prefixes, segment.Prefix)
		}
	}
	return normalizePrefixes(prefixes)
}

// classify returns the access scope of the accepted sources and whether that
// scope is established without relying on undecidable predicates.
func (r pathResult) classify() (models.AccessScope, *models.Rule, models.Certainty) {
	scope, rule := classifyAcceptedSources(r.Accepted)
	var definite []decisionSegment
	for _, segment := range r.Accepted {
		if !segment.Possible {
			definite = append(definite, segment)
		}
	}
	definiteScope, definiteRule := classifyAcceptedSources(definite)
	if definiteScope == scope {
		if definiteRule != nil || rule == nil {
			rule = definiteRule
		}
		return scope, rule, models.CertaintyDefinite
	}
	return scope, rule, models.CertaintyPossible
}

// evaluatePath evaluates a sequence of hook traversals. Absent tables and
// chains pass traffic unchanged, which matches the kernel when a table is not
// loaded. Accepted segments keep the most specific accepting rule seen.
func evaluatePath(rs *models.Ruleset, stages []pathStage, sources []netip.Prefix) pathResult {
	remaining := normalizePrefixes(sources)
	accepted := segmentsFor(remaining, nil)
	var result pathResult
	for _, stage := range stages {
		if len(remaining) == 0 {
			break
		}
		table := rs.Tables[stage.Table]
		if table == nil || table.Chains[stage.Chain] == nil {
			continue
		}
		query := stage.Query
		query.Chain = stage.Chain
		query.Hook = stage.Chain
		evaluation := evaluateChain(table, stage.Chain, remaining, query, map[string]bool{}, false)
		result.Uncertain = result.Uncertain || evaluation.Uncertain
		result.Dropped = append(result.Dropped, evaluation.Dropped...)
		// Built-in chains always end in a policy; anything returned from an
		// incomplete chain continues like an ACCEPT policy would.
		next := append(evaluation.Accepted, segmentsFor(evaluation.Returned, nil)...)
		accepted = inheritAttribution(next, accepted)
		remaining = make([]netip.Prefix, 0, len(accepted))
		for _, segment := range accepted {
			remaining = append(remaining, segment.Prefix)
		}
		remaining = normalizePrefixes(remaining)
	}
	result.Accepted = accepted
	return result
}

// inheritAttribution carries the accepting rule and the certainty of earlier
// stages into the segments of a later stage. A later acceptance is only
// definite when the source was definitely accepted before.
func inheritAttribution(next, previous []decisionSegment) []decisionSegment {
	for i := range next {
		containedDefinitely := false
		var rule *models.Rule
		for _, earlier := range previous {
			if earlier.Prefix.Bits() > next[i].Prefix.Bits() || !earlier.Prefix.Contains(next[i].Prefix.Addr()) {
				continue
			}
			if !earlier.Possible {
				containedDefinitely = true
			}
			if rule == nil && earlier.Rule != nil {
				rule = earlier.Rule
			}
		}
		if !containedDefinitely {
			next[i].Possible = true
		}
		if next[i].Rule == nil {
			next[i].Rule = rule
		}
	}
	return next
}

// inputPath returns the hook sequence of a packet delivered to a local socket.
func inputPath(query packetQuery) []pathStage {
	raw := query
	raw.State = "" // conntrack has not run yet in raw/PREROUTING
	return []pathStage{
		{Table: "raw", Chain: "PREROUTING", Query: raw},
		{Table: "mangle", Chain: "PREROUTING", Query: query},
		{Table: "mangle", Chain: "INPUT", Query: query},
		{Table: "filter", Chain: "INPUT", Query: query},
		{Table: "security", Chain: "INPUT", Query: query},
	}
}

// preroutingPath returns the hooks that see a packet before nat/PREROUTING.
func preroutingPath(query packetQuery) []pathStage {
	raw := query
	raw.State = ""
	return []pathStage{
		{Table: "raw", Chain: "PREROUTING", Query: raw},
		{Table: "mangle", Chain: "PREROUTING", Query: query},
	}
}

// forwardPath returns the hooks that see a routed packet after nat/PREROUTING.
func forwardPath(query packetQuery) []pathStage {
	return []pathStage{
		{Table: "mangle", Chain: "FORWARD", Query: query},
		{Table: "filter", Chain: "FORWARD", Query: query},
		{Table: "security", Chain: "FORWARD", Query: query},
	}
}

func evaluateChain(table *models.Table, chainName string, input []netip.Prefix, query packetQuery, path map[string]bool, possible bool) chainEvaluation {
	chain, ok := table.Chains[chainName]
	if !ok {
		return chainEvaluation{Returned: input}
	}
	if path[chainName] {
		// Kernel rule insertion normally prevents loops. If one is nevertheless
		// present in saved input, keep both outcomes possible instead of claiming
		// that traffic is filtered.
		return chainEvaluation{Accepted: possibleSegments(input, nil), Returned: input, Uncertain: true}
	}
	path[chainName] = true
	defer delete(path, chainName)

	remaining := normalizePrefixes(input)
	var result chainEvaluation
	for _, i := range ruleOrder(chain, query) {
		if len(remaining) == 0 {
			break
		}
		rule := &chain.Rules[i]
		// Non-source predicates are cheap and reject most rules of large
		// chains (one rule per published port), so test them first.
		certainty := ruleMatchesQuery(rule, query)
		if certainty == matchNo {
			continue
		}
		matched, unmatched, sourceKnown := splitBySource(remaining, rule, query)
		if len(matched) == 0 {
			continue
		}
		branchPossible := possible
		if certainty == matchMaybe || !sourceKnown {
			// The predicate can match some packets and miss others. Preserve the
			// non-matching branch while evaluating the matching branch as possible.
			unmatched = append(unmatched, matched...)
			result.Uncertain = true
			branchPossible = true
		}
		remaining = normalizePrefixes(unmatched)
		verdict := func(prefixes []netip.Prefix, rule *models.Rule) []decisionSegment {
			segments := segmentsFor(prefixes, rule)
			for i := range segments {
				segments[i].Possible = branchPossible
			}
			return segments
		}

		switch rule.Target {
		case "ACCEPT":
			result.Accepted = append(result.Accepted, verdict(matched, rule)...)
		case "DROP", "REJECT":
			result.Dropped = append(result.Dropped, verdict(matched, rule)...)
		case "RETURN":
			if chain.Policy == "ACCEPT" {
				result.Accepted = append(result.Accepted, verdict(matched, nil)...)
			} else if chain.Policy == "DROP" {
				result.Dropped = append(result.Dropped, verdict(matched, nil)...)
			} else {
				result.Returned = append(result.Returned, matched...)
			}
		default:
			if _, isChain := table.Chains[rule.Target]; isChain {
				childQuery := query
				childQuery.Chain = rule.Target
				child := evaluateChain(table, rule.Target, matched, childQuery, path, branchPossible)
				result.Accepted = append(result.Accepted, child.Accepted...)
				result.Dropped = append(result.Dropped, child.Dropped...)
				result.Uncertain = result.Uncertain || child.Uncertain
				if rule.Goto {
					if chain.Policy == "ACCEPT" {
						result.Accepted = append(result.Accepted, verdict(child.Returned, nil)...)
					} else if chain.Policy == "DROP" {
						result.Dropped = append(result.Dropped, verdict(child.Returned, nil)...)
					} else {
						result.Returned = append(result.Returned, child.Returned...)
					}
				} else {
					remaining = normalizePrefixes(append(remaining, child.Returned...))
				}
			} else if rule.Target == "QUEUE" || rule.Target == "NFQUEUE" {
				// Userspace decides the verdict. An ACCEPT outcome is possible.
				result.Accepted = append(result.Accepted, possibleSegments(matched, rule)...)
				remaining = normalizePrefixes(append(remaining, matched...))
			} else {
				if rule.Target == "NOTRACK" || (rule.Target == "CT" && containsToken(rule.TargetArgs, "--notrack")) {
					// Untracked packets no longer carry the NEW state assumed by
					// later conntrack predicates.
					result.Uncertain = true
				}
				// LOG, MARK and other non-verdict targets continue in this chain.
				remaining = normalizePrefixes(append(remaining, matched...))
			}
		}
	}

	final := segmentsFor(remaining, nil)
	for i := range final {
		final[i].Possible = possible
	}
	if chain.Policy == "ACCEPT" {
		result.Accepted = append(result.Accepted, final...)
	} else if chain.Policy == "DROP" {
		result.Dropped = append(result.Dropped, final...)
	} else {
		result.Returned = append(result.Returned, remaining...)
	}
	result.Returned = normalizePrefixes(result.Returned)
	return result
}

func possibleSegments(prefixes []netip.Prefix, rule *models.Rule) []decisionSegment {
	segments := segmentsFor(prefixes, rule)
	for i := range segments {
		segments[i].Possible = true
	}
	return segments
}

func segmentsFor(prefixes []netip.Prefix, rule *models.Rule) []decisionSegment {
	segments := make([]decisionSegment, 0, len(prefixes))
	for _, prefix := range prefixes {
		segments = append(segments, decisionSegment{Prefix: prefix, Rule: rule})
	}
	return segments
}

func normalizeProtocol(protocol models.Protocol) models.Protocol {
	switch protocol {
	case models.ProtoTCP, models.ProtoUDP, models.ProtoICMP, models.ProtoAll, "", "ipv6-icmp":
		return protocol
	}
	switch strings.ToLower(string(protocol)) {
	case "6":
		return models.ProtoTCP
	case "17":
		return models.ProtoUDP
	case "1":
		return models.ProtoICMP
	case "58", "icmpv6", "ipv6-icmp":
		return "ipv6-icmp"
	case "0":
		return models.ProtoAll
	}
	return models.Protocol(strings.ToLower(string(protocol)))
}

func ruleMatchesQuery(rule *models.Rule, query packetQuery) matchCertainty {
	certainty := matchYes
	combine := func(next matchCertainty) {
		if next < certainty {
			certainty = next
		}
	}

	protocol := normalizeProtocol(rule.Protocol)
	if protocol == "" || protocol == models.ProtoAll {
		if rule.Negations["protocol"] {
			return matchNo
		}
	} else {
		matched := protocol == normalizeProtocol(query.Protocol)
		if rule.Negations["protocol"] {
			matched = !matched
		}
		if !matched {
			return matchNo
		}
	}

	if rule.DstPort != "" {
		ranges := cachedPortRanges(rule.DstPort)
		if len(ranges) == 0 || query.DstPort < 0 || query.DstPort > 65535 {
			combine(matchMaybe)
		} else {
			matched := portInSpec(rule.DstPort, query.DstPort)
			if rule.Negations["dport"] {
				matched = !matched
			}
			if !matched {
				return matchNo
			}
		}
	}
	if rule.SrcPort != "" {
		if query.SrcPort < 1 || query.SrcPort > 65535 {
			combine(matchMaybe)
		} else {
			matched := portInSpec(rule.SrcPort, query.SrcPort)
			if rule.Negations["sport"] {
				matched = !matched
			}
			if !matched {
				return matchNo
			}
		}
	}
	if rule.Fragment {
		// The service and DNAT inventories do not establish whether a packet is
		// a later fragment. Preserve both branches for -f and ! -f.
		combine(matchMaybe)
	}

	combine(addressMatch(rule.DstAddr, query.DstAddr, rule.Negations["dst"], query))
	if certainty == matchNo {
		return matchNo
	}
	combine(interfaceMatch(rule.InIface, query, rule.Negations["in-iface"], true))
	if certainty == matchNo {
		return matchNo
	}
	combine(interfaceMatch(rule.OutIface, query, rule.Negations["out-iface"], false))
	if certainty == matchNo {
		return matchNo
	}

	if len(rule.States) > 0 && !hasStateExtension(rule.Matches) {
		combine(stateMatch(rule.States, rule.Negations["state"], query))
		if certainty == matchNo {
			return matchNo
		}
	}

	for _, ext := range rule.Matches {
		combine(extensionCertainty(ext, query))
		if certainty == matchNo {
			return matchNo
		}
	}
	return certainty
}

func hasStateExtension(matches []models.MatchExt) bool {
	for _, ext := range matches {
		if _, ok := ext.Params["--ctstate"]; ok {
			return true
		}
		if _, ok := ext.Params["--state"]; ok {
			return true
		}
	}
	return false
}

// stateMatch evaluates a conntrack state list. A packet carries its
// connection state and, when translated, the virtual DNAT/SNAT states.
func stateMatch(states []string, negated bool, query packetQuery) matchCertainty {
	matched := false
	known := false
	for _, state := range []string{query.State, query.NATState} {
		if state != "" {
			known = true
			matched = matched || containsState(states, state)
		}
	}
	if !known {
		return matchMaybe
	}
	if negated {
		matched = !matched
	}
	return certaintyOf(matched)
}

func addressMatch(ruleAddr, queryAddr string, negated bool, query packetQuery) matchCertainty {
	if ruleAddr == "" || ruleAddr == "0.0.0.0/0" || ruleAddr == "::/0" {
		if negated {
			return matchNo
		}
		return matchYes
	}
	prefix, ok := parsePrefix(ruleAddr)
	if !ok {
		return matchMaybe
	}
	if queryAddr == "" || queryAddr == "0.0.0.0" || queryAddr == "::" || queryAddr == "*" {
		if query.DstType == "LOCAL" {
			return applyNegation(localAddressMatch(prefix, query.Ctx), negated)
		}
		return matchMaybe
	}
	addr, err := netip.ParseAddr(strings.Split(queryAddr, "%")[0])
	if err != nil || prefix.Addr().Is4() != addr.Is4() {
		return matchMaybe
	}
	return applyNegation(certaintyOf(prefix.Contains(addr)), negated)
}

// localAddressMatch decides whether some local address falls in prefix when
// the exact local destination is unknown.
func localAddressMatch(prefix netip.Prefix, ctx *evalContext) matchCertainty {
	if ctx == nil {
		return matchMaybe
	}
	if ctx.localKnown {
		inside, outside := 0, 0
		for _, addr := range ctx.localAddrs {
			if addr.Is4() != prefix.Addr().Is4() {
				continue
			}
			if prefix.Contains(addr) {
				inside++
			} else {
				outside++
			}
		}
		switch {
		case inside == 0:
			return matchNo
		case outside == 0:
			return matchYes
		}
		return matchMaybe
	}
	if prefix.IsSingleIP() && ctx.containerAddrs[prefix.Addr()] {
		// A container address is routed to a bridge and is never local.
		return matchNo
	}
	if prefix.Addr().IsLoopback() && prefix.Bits() >= 8 {
		// Externally received packets addressed to loopback are martians.
		return matchNo
	}
	return matchMaybe
}

func containsToken(tokens []string, wanted string) bool {
	for _, token := range tokens {
		if token == wanted {
			return true
		}
	}
	return false
}

func applyNegation(certainty matchCertainty, negated bool) matchCertainty {
	if !negated || certainty == matchMaybe {
		return certainty
	}
	if certainty == matchYes {
		return matchNo
	}
	return matchYes
}

// interfaceMatch evaluates -i/-o. Externally received packets never arrive on
// loopback or on a Docker-managed bridge.
func interfaceMatch(ruleIface string, query packetQuery, negated, inbound bool) matchCertainty {
	if ruleIface == "" {
		return matchYes
	}
	queryIface := query.OutIface
	if inbound {
		queryIface = query.InIface
	}
	if queryIface == "" || queryIface == otherInterface {
		if inbound && query.External {
			if ruleIface == "lo" || isBridgeInterface(ruleIface, query.Ctx) {
				return applyNegation(matchNo, negated)
			}
			if queryIface == otherInterface && !strings.HasSuffix(ruleIface, "+") {
				return applyNegation(matchNo, negated)
			}
		}
		return matchMaybe
	}
	return applyNegation(certaintyOf(ifaceCovers(ruleIface, queryIface)), negated)
}

// isBridgeInterface reports whether name (or every interface a wildcard name
// covers) is a Docker-managed bridge or container veth.
func isBridgeInterface(name string, ctx *evalContext) bool {
	if ctx != nil && ctx.bridges[name] {
		return true
	}
	return dockerInterfaceName(name)
}

func dockerInterfaceName(name string) bool {
	switch name {
	case "docker0", "docker_gwbridge", "docker+", "br-+", "veth+":
		return true
	}
	if strings.HasPrefix(name, "veth") {
		return true
	}
	if strings.HasPrefix(name, "br-") && len(name) == 15 {
		for _, ch := range name[3:] {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				return false
			}
		}
		return true
	}
	return false
}

var icmpTypeNames = map[string]string{
	"echo-reply": "0", "pong": "0", "destination-unreachable": "3", "source-quench": "4",
	"redirect": "5", "echo-request": "8", "ping": "8", "router-advertisement": "9",
	"router-solicitation": "10", "time-exceeded": "11", "ttl-exceeded": "11",
	"parameter-problem": "12", "timestamp-request": "13", "timestamp-reply": "14",
}

var icmpv6TypeNames = map[string]string{
	"destination-unreachable": "1", "no-route": "1", "packet-too-big": "2",
	"time-exceeded": "3", "ttl-exceeded": "3", "parameter-problem": "4",
	"echo-request": "128", "ping": "128", "echo-reply": "129", "pong": "129",
	"router-solicitation": "133", "router-advertisement": "134",
	"neighbour-solicitation": "135", "neighbor-solicitation": "135",
	"neighbour-advertisement": "136", "neighbor-advertisement": "136", "redirect": "137",
}

func icmpTypeMatch(spec string, names map[string]string, query packetQuery, negated bool) matchCertainty {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "any" {
		return applyNegation(matchYes, negated)
	}
	if query.ICMPType == "" {
		return matchMaybe
	}
	if mapped, ok := names[spec]; ok {
		spec = mapped
	}
	typeText, code, hasCode := strings.Cut(spec, "/")
	if _, err := strconv.Atoi(typeText); err != nil {
		return matchMaybe
	}
	if hasCode && code != "" {
		// Codes are not part of the query; a matching type may still differ.
		if typeText != query.ICMPType {
			return applyNegation(matchNo, negated)
		}
		return matchMaybe
	}
	return applyNegation(certaintyOf(typeText == query.ICMPType), negated)
}

func addrTypeMatch(spec, actual string, negated bool) matchCertainty {
	if actual == "" {
		return matchMaybe
	}
	matched := false
	for _, value := range strings.Split(spec, ",") {
		if strings.EqualFold(strings.TrimSpace(value), actual) {
			matched = true
		}
	}
	return applyNegation(certaintyOf(matched), negated)
}

func extensionCertainty(ext models.MatchExt, query packetQuery) matchCertainty {
	modeled := modeledParams{}
	certainty := matchYes
	combine := func(next matchCertainty) bool {
		if next == matchNo {
			return false
		}
		if next == matchMaybe {
			certainty = matchMaybe
		}
		return true
	}
	switch ext.Module {
	case "comment":
		return matchYes
	case "tcp", "udp":
		modeled.add("--dport")
		modeled.add("--destination-port")
		modeled.add("--sport")
		modeled.add("--source-port")
		if _, ok := ext.Params["--syn"]; ok && ext.Module == "tcp" {
			modeled.add("--syn")
			if query.State == "NEW" && normalizeProtocol(query.Protocol) == models.ProtoTCP {
				if !combine(applyNegation(matchYes, ext.Negations["--syn"])) {
					return matchNo
				}
			} else {
				certainty = matchMaybe
			}
		}
	case "multiport":
		modeled.add("--dports")
		modeled.add("--destination-ports")
		modeled.add("--sports")
		modeled.add("--source-ports")
	case "conntrack", "state":
		for _, key := range []string{"--ctstate", "--state"} {
			if value, ok := ext.Params[key]; ok {
				modeled.add(key)
				if !combine(stateMatch(strings.Split(value, ","), ext.Negations[key], query)) {
					return matchNo
				}
			}
		}
		if value, ok := ext.Params["--ctorigdstport"]; ok {
			modeled.add("--ctorigdstport")
			if len(cachedPortRanges(value)) == 0 || query.OriginalDstPort == 0 {
				certainty = matchMaybe
			} else if !combine(applyNegation(certaintyOf(portInSpec(value, query.OriginalDstPort)), ext.Negations["--ctorigdstport"])) {
				return matchNo
			}
		}
		if value, ok := ext.Params["--ctorigdst"]; ok {
			modeled.add("--ctorigdst")
			original := query
			if query.NATState == "DNAT" {
				// The original destination of a DNATed connection was local.
				original.DstType = "LOCAL"
			}
			if !combine(addressMatch(value, query.OriginalDstAddr, ext.Negations["--ctorigdst"], original)) {
				return matchNo
			}
		}
		if _, ok := ext.Params["--ctorigsrc"]; ok && query.External && query.Direction == "ORIGINAL" {
			// Evaluated together with -s by splitBySource.
			modeled.add("--ctorigsrc")
		}
		if value, ok := ext.Params["--ctdir"]; ok {
			modeled.add("--ctdir")
			if query.Direction == "" {
				certainty = matchMaybe
			} else if strings.EqualFold(value, query.Direction) == ext.Negations["--ctdir"] {
				return matchNo
			}
		}
	case "addrtype":
		if value, ok := ext.Params["--dst-type"]; ok {
			modeled.add("--dst-type")
			if !combine(addrTypeMatch(value, query.DstType, ext.Negations["--dst-type"])) {
				return matchNo
			}
		}
		if value, ok := ext.Params["--src-type"]; ok {
			modeled.add("--src-type")
			actual := ""
			if query.External {
				actual = "UNICAST"
			}
			if !combine(addrTypeMatch(value, actual, ext.Negations["--src-type"])) {
				return matchNo
			}
		}
	case "icmp":
		if value, ok := ext.Params["--icmp-type"]; ok {
			modeled.add("--icmp-type")
			if !combine(icmpTypeMatch(value, icmpTypeNames, query, ext.Negations["--icmp-type"])) {
				return matchNo
			}
		}
	case "icmp6", "icmpv6":
		if value, ok := ext.Params["--icmpv6-type"]; ok {
			modeled.add("--icmpv6-type")
			if !combine(icmpTypeMatch(value, icmpv6TypeNames, query, ext.Negations["--icmpv6-type"])) {
				return matchNo
			}
		}
	case "hl":
		for key, compare := range map[string]func(int, int) bool{
			"--hl-eq": func(a, b int) bool { return a == b },
			"--hl-lt": func(a, b int) bool { return a < b },
			"--hl-gt": func(a, b int) bool { return a > b },
		} {
			value, ok := ext.Params[key]
			if !ok {
				continue
			}
			modeled.add(key)
			expected, err := strconv.Atoi(value)
			if err != nil || query.HopLimit == 0 {
				certainty = matchMaybe
			} else if !combine(applyNegation(certaintyOf(compare(query.HopLimit, expected)), ext.Negations[key])) {
				return matchNo
			}
		}
	default:
		// Module presence may itself constrain a match (for example socket), so
		// unknown modules remain indeterminate even when they have no options.
		return matchMaybe
	}

	for param := range ext.Params {
		if !modeled.has(param) {
			return matchMaybe
		}
	}
	return certainty
}

// modeledParams is a small allocation-free set of the options of one match
// extension that the evaluator understands.
type modeledParams struct {
	keys [8]string
	n    int
}

func (m *modeledParams) add(key string) {
	if m.n < len(m.keys) {
		m.keys[m.n] = key
		m.n++
	}
}

func (m *modeledParams) has(key string) bool {
	for i := 0; i < m.n; i++ {
		if m.keys[i] == key {
			return true
		}
	}
	return false
}

var portRangeCache sync.Map // port specification -> [][2]int

// cachedPortRanges memoizes expandPorts; rule specifications repeat for every
// evaluated packet.
func cachedPortRanges(spec string) [][2]int {
	if cached, ok := portRangeCache.Load(spec); ok {
		return cached.([][2]int)
	}
	ranges := expandPorts(spec)
	portRangeCache.Store(spec, ranges)
	return ranges
}

// portInSpec reports whether port lies in an iptables port specification.
func portInSpec(spec string, port int) bool {
	if port < 1 {
		return false
	}
	for _, r := range cachedPortRanges(spec) {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// sourcePredicate is one source-address restriction of a rule: -s or the
// conntrack original source, which equals -s for externally received packets.
type sourcePredicate struct {
	value   string
	negated bool
}

func sourcePredicates(rule *models.Rule, query packetQuery) []sourcePredicate {
	predicates := []sourcePredicate{{value: rule.SrcAddr, negated: rule.Negations["src"]}}
	if query.External && query.Direction == "ORIGINAL" {
		for _, ext := range rule.Matches {
			if ext.Module != "conntrack" {
				continue
			}
			if value, ok := ext.Params["--ctorigsrc"]; ok {
				predicates = append(predicates, sourcePredicate{value: value, negated: ext.Negations["--ctorigsrc"]})
			}
		}
	}
	return predicates
}

func splitBySource(input []netip.Prefix, rule *models.Rule, query packetQuery) (matched, unmatched []netip.Prefix, known bool) {
	matched = input
	known = true
	for _, predicate := range sourcePredicates(rule, query) {
		inside, outside, ok := splitByPrefix(matched, predicate.value, predicate.negated)
		if !ok {
			return input, input, false
		}
		matched = inside
		unmatched = append(unmatched, outside...)
	}
	return normalizePrefixes(matched), normalizePrefixes(unmatched), known
}

func splitByPrefix(input []netip.Prefix, source string, negated bool) (matched, unmatched []netip.Prefix, known bool) {
	if source == "" || source == "0.0.0.0/0" || source == "::/0" {
		if negated {
			return nil, input, true
		}
		return input, nil, true
	}
	predicate, ok := parsePrefix(source)
	if !ok {
		return input, input, false
	}
	for _, base := range input {
		intersection, overlaps := intersectPrefix(base, predicate)
		if overlaps {
			matched = append(matched, intersection)
			unmatched = append(unmatched, subtractPrefix(base, predicate)...)
		} else {
			unmatched = append(unmatched, base)
		}
	}
	if negated {
		matched, unmatched = unmatched, matched
	}
	return normalizePrefixes(matched), normalizePrefixes(unmatched), true
}

func parsePrefix(value string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func intersectPrefix(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Addr().Is4() != b.Addr().Is4() {
		return netip.Prefix{}, false
	}
	if a.Bits() <= b.Bits() && a.Contains(b.Addr()) {
		return b.Masked(), true
	}
	if b.Bits() <= a.Bits() && b.Contains(a.Addr()) {
		return a.Masked(), true
	}
	return netip.Prefix{}, false
}

func subtractPrefix(base, remove netip.Prefix) []netip.Prefix {
	if _, overlaps := intersectPrefix(base, remove); !overlaps {
		return []netip.Prefix{base}
	}
	if remove.Bits() <= base.Bits() && remove.Contains(base.Addr()) {
		return nil
	}
	if base.Bits() >= base.Addr().BitLen() {
		return nil
	}
	left, right := prefixChildren(base)
	result := subtractPrefix(left, remove)
	result = append(result, subtractPrefix(right, remove)...)
	return result
}

// subtractPrefixes returns the part of a that is not covered by b.
func subtractPrefixes(a, b []netip.Prefix) []netip.Prefix {
	result := normalizePrefixes(a)
	for _, remove := range b {
		var next []netip.Prefix
		for _, base := range result {
			next = append(next, subtractPrefix(base, remove)...)
		}
		result = normalizePrefixes(next)
	}
	return result
}

func prefixChildren(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	nextBits := prefix.Bits() + 1
	left := netip.PrefixFrom(prefix.Addr(), nextBits).Masked()
	bit := prefix.Bits()
	if prefix.Addr().Is4() {
		bytes := prefix.Addr().As4()
		bytes[bit/8] |= 1 << (7 - uint(bit%8))
		right := netip.PrefixFrom(netip.AddrFrom4(bytes), nextBits).Masked()
		return left, right
	}
	bytes := prefix.Addr().As16()
	bytes[bit/8] |= 1 << (7 - uint(bit%8))
	right := netip.PrefixFrom(netip.AddrFrom16(bytes), nextBits).Masked()
	return left, right
}

func normalizePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	seen := make(map[string]bool, len(prefixes))
	result := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		key := prefix.String()
		if !seen[key] {
			seen[key] = true
			result = append(result, prefix)
		}
	}
	return result
}

var restrictedSourcePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

func classifyAcceptedSources(accepted []decisionSegment) (models.AccessScope, *models.Rule) {
	if len(accepted) == 0 {
		return "", nil
	}
	// Track presence separately from attribution: segments accepted by a
	// chain policy have no rule.
	var whitelistRule, localRule, exposedRule *models.Rule
	local, exposed := false, false
	for _, segment := range accepted {
		prefix := segment.Prefix
		switch {
		case prefix.Bits() == prefix.Addr().BitLen():
			if whitelistRule == nil {
				whitelistRule = segment.Rule
			}
		case prefixIsRestricted(prefix):
			local = true
			if localRule == nil {
				localRule = segment.Rule
			}
		default:
			if !exposed || exposedRule == nil {
				exposedRule = segment.Rule
			}
			exposed = true
		}
	}
	if exposed {
		return models.ScopeExposed, exposedRule
	}
	if local {
		return models.ScopeLocalnet, localRule
	}
	return models.ScopeWhitelisted, whitelistRule
}

func classifyPrefixes(prefixes []netip.Prefix) models.AccessScope {
	scope, _ := classifyAcceptedSources(segmentsFor(prefixes, nil))
	return scope
}

func prefixIsRestricted(prefix netip.Prefix) bool {
	for _, restricted := range restrictedSourcePrefixes {
		if restricted.Addr().Is4() == prefix.Addr().Is4() &&
			restricted.Bits() <= prefix.Bits() && restricted.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// scopeRank orders access scopes from unreachable to unrestricted.
func scopeRank(scope models.AccessScope) int {
	switch scope {
	case models.ScopeExposed:
		return 3
	case models.ScopeLocalnet:
		return 2
	case models.ScopeWhitelisted:
		return 1
	}
	return 0
}
