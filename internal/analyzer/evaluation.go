package analyzer

import (
	"fmt"
	"net/netip"
	"sort"
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
	budget         *walkBudget
}

// maxChainVisits bounds the chain traversals of one evaluation context (one
// analysis of one ruleset). Every jump evaluates its target chain again, so
// chains that each jump to the next one twice grow exponentially with depth:
// a crafted 50-line ruleset would otherwise run for days. A real Docker 29
// host with several networks needs about 200 traversals; the bound leaves
// room for hosts with thousands of published ports and Kubernetes chains.
// Beyond it, traversals return the conservative answer used for loops.
// It is a variable only so that tests can lower it.
var maxChainVisits = 1 << 18

// walkBudget counts the chain traversals that remain.
type walkBudget struct {
	remaining int
	exhausted bool
}

func (b *walkBudget) spend() bool {
	if b.remaining <= 0 {
		b.exhausted = true
		return false
	}
	b.remaining--
	return true
}

// chainWalk is the state of one traversal: the chains on the current call
// path (to detect loops) and the budget shared with the evaluation context.
type chainWalk struct {
	path   map[string]bool
	budget *walkBudget
}

func newChainWalk(query packetQuery) *chainWalk {
	walk := &chainWalk{path: map[string]bool{}}
	if query.Ctx == nil {
		walk.budget = &walkBudget{remaining: maxChainVisits}
		return walk
	}
	if query.Ctx.budget == nil {
		query.Ctx.budget = &walkBudget{remaining: maxChainVisits}
	}
	walk.budget = query.Ctx.budget
	return walk
}

// limitReached reports whether evaluations in ctx were cut short.
func (ctx *evalContext) limitReached() bool {
	return ctx != nil && ctx.budget != nil && ctx.budget.exhausted
}

// evaluationLimitDiagnostic explains conservative results of a ruleset.
func evaluationLimitDiagnostic(rs *models.Ruleset, area string) models.AssessmentDiagnostic {
	return models.AssessmentDiagnostic{Area: area, Message: fmt.Sprintf(
		"IPv%d rule chains jump into each other too often to evaluate exactly (more than %d chain traversals); affected results are reported as possible", rs.IPVersion, maxChainVisits)}
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

// maybeKind tells why a rule may or may not match the packets of a query.
// The difference decides what the rule proves about exposure.
type maybeKind uint8

const (
	// kindUnknown: the outcome cannot be judged at all (packet marks,
	// extensions that are not modeled, facts that the query does not have).
	kindUnknown maybeKind = iota
	// kindConditional: every source can satisfy the undecided predicates: a
	// rate limit, a time window, the packet contents, a source port.
	kindConditional
	// kindNarrow: the undecided predicates hold only for an unknown subset of
	// the sources, such as the members of an ipset or one MAC address.
	kindNarrow
	// kindBroad: the undecided predicates hold for every source except an
	// unknown subset, such as a negated ipset match.
	kindBroad
)

// matchResult is the outcome of testing a rule against a query, without the
// source address. kind and label are set when certainty is matchMaybe.
type matchResult struct {
	certainty matchCertainty
	kind      maybeKind
	label     string
}

// matchState collects the predicates of one rule that the query cannot decide.
type matchState struct {
	unknown    bool
	conditions []string
	narrow     []string
	broad      []string
}

func (m *matchState) result() matchResult {
	switch {
	case m.unknown:
		return matchResult{certainty: matchMaybe, kind: kindUnknown}
	case len(m.narrow) > 0:
		return matchResult{certainty: matchMaybe, kind: kindNarrow, label: strings.Join(m.narrow, " and ")}
	case len(m.broad) > 0 && len(m.conditions) > 0:
		return matchResult{certainty: matchMaybe, kind: kindUnknown}
	case len(m.broad) > 0:
		return matchResult{certainty: matchMaybe, kind: kindBroad, label: strings.Join(m.broad, " and ")}
	case len(m.conditions) > 0:
		return matchResult{certainty: matchMaybe, kind: kindConditional, label: strings.Join(m.conditions, ", ")}
	}
	return matchResult{certainty: matchYes}
}

// flow is a part of the traffic of a query on its way through a chain.
type flow struct {
	set addrSet
	// possible: this traffic only exists if a predicate matched that the
	// analysis cannot judge.
	possible bool
	// narrowed: only an unknown subset of set is on this way; the text names
	// what selects it ("ipset trusted").
	narrowed string
	// condition: any source of set can be on this way, but only packets that
	// meet the named condition ("rate limit").
	condition string
}

func (f flow) with(set addrSet) flow {
	f.set = set
	return f
}

func joinLabels(a, b, separator string) string {
	switch {
	case a == "":
		return b
	case b == "" || a == b:
		return a
	}
	return a + separator + b
}

// addFlow adds traffic to a list of flows; flows with the same attributes
// are one flow.
func addFlow(flows []flow, f flow) []flow {
	if f.set.empty() {
		return flows
	}
	for i := range flows {
		if flows[i].possible == f.possible && flows[i].narrowed == f.narrowed && flows[i].condition == f.condition {
			flows[i].set = flows[i].set.union(f.set)
			return flows
		}
	}
	return append(flows, f)
}

// decisionSegment is a verdict for a set of sources. Possible marks a verdict
// that depends on a predicate the analysis cannot judge having matched.
// Narrowed and Condition qualify a verdict that is certain: it holds for an
// unknown subset of the sources, or for any source under a condition.
type decisionSegment struct {
	Set       addrSet
	Rule      *models.Rule
	Possible  bool
	Narrowed  string
	Condition string
}

type chainEvaluation struct {
	Accepted  []decisionSegment
	Dropped   []decisionSegment
	Returned  []flow
	Uncertain bool
}

func rootSet(version models.IPVersion) addrSet {
	if version == models.IPv6 {
		return setOfPrefix(netip.MustParsePrefix("::/0"))
	}
	return setOfPrefix(netip.MustParsePrefix("0.0.0.0/0"))
}

// segmentsUnion returns every source of the segments. Sorting all ranges
// once keeps this linear for chains with thousands of single-address rules.
func segmentsUnion(segments []decisionSegment, include func(decisionSegment) bool) addrSet {
	switch len(segments) {
	case 0:
		return addrSet{}
	case 1:
		if include == nil || include(segments[0]) {
			return segments[0].Set
		}
		return addrSet{}
	}
	var ranges []addrRange
	for _, segment := range segments {
		if include == nil || include(segment) {
			ranges = append(ranges, segment.Set.ranges()...)
		}
	}
	return normalizeRanges(ranges)
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

// acceptedSet returns every source that some rule or policy accepts.
func (r pathResult) acceptedSet() addrSet {
	return segmentsUnion(r.Accepted, nil)
}

// definiteSet returns the sources with an acceptance that does not depend on
// a predicate the analysis cannot judge. It includes sources of which only
// an unknown subset is accepted.
func (r pathResult) definiteSet() addrSet {
	return segmentsUnion(r.Accepted, func(segment decisionSegment) bool { return !segment.Possible })
}

// unconditionalSet returns the sources that are accepted in full and for
// certain: not possibly, and not only an unknown subset of them.
func (r pathResult) unconditionalSet() addrSet {
	return segmentsUnion(r.Accepted, func(segment decisionSegment) bool { return !segment.Possible && segment.Narrowed == "" })
}

// plainSet returns the sources that are accepted in full, certainly or
// possibly.
func (r pathResult) plainSet() addrSet {
	return segmentsUnion(r.Accepted, func(segment decisionSegment) bool { return segment.Narrowed == "" })
}

// exposureClass is the widest scope from which a path accepts traffic.
type exposureClass struct {
	scope     models.AccessScope
	rule      *models.Rule
	certainty models.Certainty
	// condition names what a packet must meet for this scope ("rate limit");
	// empty when some rule accepts the scope without a condition.
	condition string
	// restriction names what selects the sources of a RESTRICTED scope.
	restriction string
}

// classify returns the access scope of the accepted sources. The scope is
// definite when it does not rely on predicates that the analysis cannot judge.
func (r pathResult) classify() exposureClass {
	scope, rule, restriction := classifySegments(r.Accepted)
	result := exposureClass{scope: scope, rule: rule, certainty: models.CertaintyPossible, restriction: restriction}
	if scope == "" {
		return result
	}
	var definite, unconditional []decisionSegment
	condition := ""
	for _, segment := range r.Accepted {
		if segment.Possible {
			continue
		}
		definite = append(definite, segment)
		if segment.Condition == "" {
			unconditional = append(unconditional, segment)
		} else if condition == "" {
			condition = segment.Condition
		}
	}
	for _, tier := range []struct {
		segments  []decisionSegment
		condition string
	}{{unconditional, ""}, {definite, condition}} {
		tierScope, tierRule, tierRestriction := classifySegments(tier.segments)
		if tierScope != scope {
			continue
		}
		result.certainty, result.condition, result.restriction = models.CertaintyDefinite, tier.condition, tierRestriction
		if tierRule != nil || rule == nil {
			result.rule = tierRule
		}
		break
	}
	return result
}

// evaluatePath evaluates a sequence of hook traversals. Absent tables and
// chains pass traffic unchanged, which matches the kernel when a table is not
// loaded. Accepted segments keep the most specific accepting rule seen.
func evaluatePath(rs *models.Ruleset, stages []pathStage, sources addrSet) pathResult {
	remaining := sources
	var accepted []decisionSegment
	if !remaining.empty() {
		accepted = []decisionSegment{{Set: remaining}}
	}
	var result pathResult
	for _, stage := range stages {
		if remaining.empty() {
			break
		}
		table := rs.Tables[stage.Table]
		if table == nil || table.Chains[stage.Chain] == nil {
			continue
		}
		query := stage.Query
		query.Chain = stage.Chain
		query.Hook = stage.Chain
		evaluation := evaluateChain(table, stage.Chain, flow{set: remaining}, query, newChainWalk(query))
		result.Uncertain = result.Uncertain || evaluation.Uncertain
		result.Dropped = append(result.Dropped, evaluation.Dropped...)
		// Built-in chains always end in a policy; anything returned from an
		// incomplete chain continues like an ACCEPT policy would.
		next := evaluation.Accepted
		for _, returned := range evaluation.Returned {
			next = append(next, flowSegments(returned, nil)...)
		}
		accepted = inheritAttribution(next, accepted)
		remaining = segmentsUnion(accepted, nil)
	}
	result.Accepted = accepted
	return result
}

// segmentQuality orders the acceptances of one stage from the one that says
// most to the one that says least: complete and certain, under a condition,
// for an unknown subset, possible.
func segmentQuality(segment decisionSegment) int {
	switch {
	case segment.Possible:
		return 3
	case segment.Narrowed != "":
		return 2
	case segment.Condition != "":
		return 1
	}
	return 0
}

// inheritAttribution carries what earlier stages established into the
// segments of a later stage: a source is accepted by the path only as far as
// every stage accepted it. Where a source has more than one acceptance in an
// earlier stage, the one that says most counts. A segment that a policy
// accepted here keeps the rule of the earlier stage.
func inheritAttribution(next, previous []decisionSegment) []decisionSegment {
	ordered := make([]decisionSegment, len(previous))
	copy(ordered, previous)
	sort.SliceStable(ordered, func(i, j int) bool { return segmentQuality(ordered[i]) < segmentQuality(ordered[j]) })

	result := make([]decisionSegment, 0, len(next))
	for _, segment := range next {
		left := segment.Set
		for _, earlier := range ordered {
			if left.empty() {
				break
			}
			inside := left.intersect(earlier.Set)
			if inside.empty() {
				continue
			}
			part := decisionSegment{
				Set:       inside,
				Rule:      segment.Rule,
				Possible:  segment.Possible || earlier.Possible,
				Narrowed:  joinLabels(earlier.Narrowed, segment.Narrowed, " and "),
				Condition: joinLabels(earlier.Condition, segment.Condition, ", "),
			}
			if part.Rule == nil {
				part.Rule = earlier.Rule
			}
			result = append(result, part)
			left = left.subtract(inside)
		}
		if !left.empty() {
			// Not accepted by the earlier stage; cannot happen for the sources
			// that a stage hands on, so claim nothing certain about it.
			result = append(result, decisionSegment{Set: left, Rule: segment.Rule, Possible: true})
		}
	}
	return result
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

// evaluateChain follows the traffic of one flow through a chain and returns
// what the chain, and the chains it jumps to, decide for it.
func evaluateChain(table *models.Table, chainName string, input flow, query packetQuery, walk *chainWalk) chainEvaluation {
	chain, ok := table.Chains[chainName]
	if !ok {
		return chainEvaluation{Returned: addFlow(nil, input)}
	}
	if walk.path[chainName] || !walk.budget.spend() {
		// Kernel rule insertion normally prevents loops. If one is nevertheless
		// present in saved input, or the ruleset is too complex to finish, keep
		// both outcomes possible instead of claiming that traffic is filtered.
		possible := input
		possible.possible = true
		return chainEvaluation{Accepted: flowSegments(possible, nil), Returned: addFlow(nil, input), Uncertain: true}
	}
	walk.path[chainName] = true
	defer delete(walk.path, chainName)

	var result chainEvaluation
	// policy applies the chain policy to traffic that leaves the chain, or
	// hands it back to the caller of a user-defined chain.
	policy := func(f flow) {
		switch chain.Policy {
		case "ACCEPT":
			result.Accepted = append(result.Accepted, flowSegments(f, nil)...)
		case "DROP":
			result.Dropped = append(result.Dropped, flowSegments(f, nil)...)
		default:
			result.Returned = addFlow(result.Returned, f)
		}
	}

	flows := addFlow(nil, input)
	for _, i := range ruleOrder(chain, query) {
		if len(flows) == 0 {
			break
		}
		rule := &chain.Rules[i]
		_, isChain := table.Chains[rule.Target]
		verdict := isChain
		switch rule.Target {
		case "ACCEPT", "DROP", "REJECT", "RETURN", "QUEUE", "NFQUEUE":
			verdict = true
		}
		// Non-source predicates are cheap and reject most rules of large
		// chains (one rule per published port), so test them first.
		match := ruleMatch(rule, query)
		if match.certainty == matchNo {
			continue
		}
		if !verdict {
			// LOG, MARK and other non-verdict targets continue in this chain.
			if rule.Target == "NOTRACK" || (rule.Target == "CT" && containsToken(rule.TargetArgs, "--notrack")) {
				for _, f := range flows {
					if sourceMayMatch(f.set, rule, query) {
						// Untracked packets no longer carry the NEW state assumed
						// by later conntrack predicates.
						result.Uncertain = true
					}
				}
			}
			continue
		}

		var next []flow
		for _, f := range flows {
			matched, unmatched, sourceKnown := splitBySource(f.set, rule, query)
			if matched.empty() {
				next = addFlow(next, f)
				continue
			}
			// branch is the traffic that takes the action of the rule. The
			// sources that the rule does not name always continue; rest is the
			// matched traffic that continues as well, because an undecided
			// predicate did not hold for it.
			branch, rest := f.with(matched), flow{}
			switch {
			case match.certainty == matchYes && sourceKnown:
			case !sourceKnown || match.kind == kindUnknown:
				branch.possible = true
				rest = f.with(matched)
			case match.kind == kindConditional:
				branch.condition = joinLabels(f.condition, match.label, ", ")
				rest = f.with(matched)
			case match.kind == kindNarrow:
				// The rule takes an unknown subset; without knowing it, all of
				// the matched sources may still continue.
				branch.narrowed = joinLabels(f.narrowed, match.label, " and ")
				rest = f.with(matched)
			case match.kind == kindBroad:
				// The rule takes everything but an unknown subset, and only
				// that subset continues.
				rest = f.with(matched)
				rest.narrowed = joinLabels(f.narrowed, match.label, " and ")
			}
			if match.certainty != matchYes || !sourceKnown {
				result.Uncertain = true
			}

			switch {
			case rule.Target == "ACCEPT":
				result.Accepted = append(result.Accepted, flowSegments(branch, rule)...)
			case rule.Target == "DROP" || rule.Target == "REJECT":
				dropped := branch
				dropped.possible = dropped.possible || match.certainty != matchYes
				result.Dropped = append(result.Dropped, flowSegments(dropped, rule)...)
				if match.certainty == matchMaybe && match.kind == kindConditional && sourceKnown {
					// What passes a rule that drops the excess is limited by
					// the same condition.
					rest.condition = joinLabels(f.condition, match.label, ", ")
				}
			case rule.Target == "RETURN":
				policy(branch)
			case rule.Target == "QUEUE" || rule.Target == "NFQUEUE":
				// Userspace decides the verdict. An ACCEPT outcome is possible,
				// and the packet may also continue in this chain.
				queued := branch
				queued.possible = true
				result.Accepted = append(result.Accepted, flowSegments(queued, rule)...)
				rest = f.with(matched)
			default:
				childQuery := query
				childQuery.Chain = rule.Target
				child := evaluateChain(table, rule.Target, branch, childQuery, walk)
				result.Accepted = append(result.Accepted, child.Accepted...)
				result.Dropped = append(result.Dropped, child.Dropped...)
				result.Uncertain = result.Uncertain || child.Uncertain
				if match.certainty == matchMaybe && match.kind == kindConditional && sourceKnown &&
					len(child.Accepted) == 0 && len(child.Returned) == 0 {
					// The chain drops all of the excess, as "ufw limit" does.
					rest.condition = joinLabels(f.condition, match.label, ", ")
				}
				for _, returned := range child.Returned {
					if rule.Goto {
						policy(returned)
					} else {
						next = addFlow(next, returned)
					}
				}
			}
			next = addFlow(next, f.with(unmatched))
			next = addFlow(next, rest)
		}
		flows = reduceFlows(next)
	}

	for _, f := range flows {
		policy(f)
	}
	return result
}

// reduceFlows removes traffic that says nothing new: sources of a possible,
// narrowed or conditional flow that a flow without that reservation covers.
// What the rules decide for all packets of a source includes what they
// decide for some of them.
func reduceFlows(flows []flow) []flow {
	if len(flows) < 2 {
		return flows
	}
	covers := func(a, b flow) bool {
		return (!a.possible || b.possible) && (a.narrowed == "" || a.narrowed == b.narrowed) &&
			(a.condition == "" || a.condition == b.condition) &&
			(a.possible != b.possible || a.narrowed != b.narrowed || a.condition != b.condition)
	}
	reduced := flows[:0:0]
	for i, f := range flows {
		for j, other := range flows {
			if i != j && covers(other, f) {
				f.set = f.set.subtract(other.set)
			}
		}
		if !f.set.empty() {
			reduced = append(reduced, f)
		}
	}
	return reduced
}

// flowSegments returns the verdict of one rule (or of a policy when rule is
// nil) for a flow; an empty flow has no verdict.
func flowSegments(f flow, rule *models.Rule) []decisionSegment {
	if f.set.empty() {
		return nil
	}
	return []decisionSegment{{Set: f.set, Rule: rule, Possible: f.possible, Narrowed: f.narrowed, Condition: f.condition}}
}

// segments returns a plain verdict for a set of sources.
func segments(sources addrSet, rule *models.Rule, possible bool) []decisionSegment {
	return flowSegments(flow{set: sources, possible: possible}, rule)
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

// ruleMatchesQuery reports whether a rule matches the packets of a query,
// leaving the source address to splitBySource.
func ruleMatchesQuery(rule *models.Rule, query packetQuery) matchCertainty {
	return ruleMatch(rule, query).certainty
}

// ruleMatch is ruleMatchesQuery with the reason of an undecided outcome.
func ruleMatch(rule *models.Rule, query packetQuery) matchResult {
	var state matchState
	no := matchResult{certainty: matchNo}
	// decided records a predicate outcome and reports whether the rule can
	// still match.
	decided := func(certainty matchCertainty) bool {
		if certainty == matchMaybe {
			state.unknown = true
		}
		return certainty != matchNo
	}

	protocol := normalizeProtocol(rule.Protocol)
	if protocol == "" || protocol == models.ProtoAll {
		if rule.Negations["protocol"] {
			return no
		}
	} else {
		matched := protocol == normalizeProtocol(query.Protocol)
		if rule.Negations["protocol"] {
			matched = !matched
		}
		if !matched {
			return no
		}
	}

	if rule.DstPort != "" {
		ranges := cachedPortRanges(rule.DstPort)
		if len(ranges) == 0 || query.DstPort < 0 || query.DstPort > 65535 {
			state.unknown = true
		} else {
			matched := portInSpec(rule.DstPort, query.DstPort)
			if rule.Negations["dport"] {
				matched = !matched
			}
			if !matched {
				return no
			}
		}
	}
	if rule.SrcPort != "" && !sourcePortMatch(rule.SrcPort, rule.Negations["sport"], query, &state) {
		return no
	}
	if rule.Fragment {
		// The service and DNAT inventories do not establish whether a packet is
		// a later fragment. Preserve both branches for -f and ! -f.
		state.unknown = true
	}

	if !decided(addressMatch(rule.DstAddr, query.DstAddr, rule.Negations["dst"], query)) ||
		!decided(interfaceMatch(rule.InIface, query, rule.Negations["in-iface"], true)) ||
		!decided(interfaceMatch(rule.OutIface, query, rule.Negations["out-iface"], false)) {
		return no
	}
	if len(rule.States) > 0 && !hasStateExtension(rule.Matches) && !decided(stateMatch(rule.States, rule.Negations["state"], query)) {
		return no
	}
	for i := range rule.Matches {
		if !extensionMatch(&rule.Matches[i], query, &state) {
			return no
		}
	}
	return state.result()
}

// ordinarySourcePorts is the number of ports from 1024 up. A client that does
// nothing special sends from one of them.
const ordinarySourcePorts = 65536 - 1024

// sourcePortMatch evaluates a source-port predicate. The sender chooses the
// source port, so without a known port the predicate is a condition that
// every source can meet. A predicate that admits most ordinary client ports
// (--sport 1024:65535) is no condition at all.
func sourcePortMatch(spec string, negated bool, query packetQuery, state *matchState) bool {
	if query.SrcPort >= 1 && query.SrcPort <= 65535 {
		return portInSpec(spec, query.SrcPort) != negated
	}
	ranges := cachedPortRanges(spec)
	if len(ranges) == 0 {
		state.unknown = true
		return true
	}
	covered := 0
	for _, r := range ranges {
		if lo, hi := max(r[0], 1024), min(r[1], 65535); lo <= hi {
			covered += hi - lo + 1
		}
	}
	label := "source port " + spec
	if negated {
		covered = ordinarySourcePorts - covered
		label = "source port other than " + spec
	}
	if covered*2 < ordinarySourcePorts {
		state.conditions = append(state.conditions, label)
	}
	return true
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
	if first := prefix.Addr(); first.IsMulticast() || (first.Is4() && first.As4() == [4]byte{255, 255, 255, 255}) {
		// A connection to a service is addressed to one host. Multicast and
		// broadcast destinations (mDNS, SSDP, DHCP) are not local addresses.
		if multicastOnly(prefix) {
			return matchNo
		}
	}
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

// multicastOnly reports whether every address of the prefix is a multicast
// or the limited-broadcast address.
func multicastOnly(prefix netip.Prefix) bool {
	if prefix.Addr().Is4() {
		return prefix.Bits() >= 4 && (prefix.Addr().IsMulticast() || prefix.Bits() == 32)
	}
	return prefix.Bits() >= 8 && prefix.Addr().IsMulticast()
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
// covers) connects guests of this host, such as a Docker-managed bridge, a
// container veth or the bridge of a virtual network. Packets from other
// hosts do not arrive on it.
func isBridgeInterface(name string, ctx *evalContext) bool {
	if ctx != nil && ctx.bridges[name] {
		return true
	}
	return guestInterfaceName(name)
}

// guestInterfacePrefixes are the interface names that container and virtual
// machine managers give to their host-only bridges and links: libvirt, LXC,
// LXD, Incus, Podman, CNI plugins, Flannel, Calico and QEMU taps.
var guestInterfacePrefixes = []string{"virbr", "lxcbr", "lxdbr", "incusbr", "podman", "cni", "flannel", "cali", "vnet"}

func guestInterfaceName(name string) bool {
	if dockerInterfaceName(name) {
		return true
	}
	for _, prefix := range guestInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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

// tcpFlagBits maps the flag names of --tcp-flags to the bits of the TCP header.
var tcpFlagBits = map[string]int{"FIN": 1, "SYN": 2, "RST": 4, "PSH": 8, "ACK": 16, "URG": 32, "ALL": 63, "NONE": 0}

func tcpFlagMask(list string) (int, bool) {
	mask := 0
	for _, name := range strings.Split(list, ",") {
		bits, ok := tcpFlagBits[strings.ToUpper(strings.TrimSpace(name))]
		if !ok {
			return 0, false
		}
		mask |= bits
	}
	return mask, true
}

// synMatchesTCPFlags evaluates "--tcp-flags MASK COMPARE" for the packet that
// opens a connection, which has only SYN set.
func synMatchesTCPFlags(value string) (matched, ok bool) {
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return false, false
	}
	mask, okMask := tcpFlagMask(fields[0])
	compare, okCompare := tcpFlagMask(fields[1])
	if !okMask || !okCompare {
		return false, false
	}
	return tcpFlagBits["SYN"]&mask == compare, true
}

// extensionMatch evaluates one match extension. It returns false when the
// extension cannot match the query; predicates that the query does not
// decide are recorded in state with their kind.
func extensionMatch(ext *models.MatchExt, query packetQuery, state *matchState) bool {
	modeled := modeledParams{}
	decided := func(certainty matchCertainty) bool {
		if certainty == matchMaybe {
			state.unknown = true
		}
		return certainty != matchNo
	}
	// sourceSubset records a predicate that holds for an unknown subset of
	// the sources (or, negated, for all but that subset).
	sourceSubset := func(label string, negated bool) {
		if negated {
			state.broad = append(state.broad, label)
		} else {
			state.narrow = append(state.narrow, label)
		}
	}
	newTCP := query.State == "NEW" && normalizeProtocol(query.Protocol) == models.ProtoTCP

	switch ext.Module {
	case "comment":
		return true
	case "tcp", "udp":
		modeled.add("--dport")
		modeled.add("--destination-port")
		modeled.add("--sport")
		modeled.add("--source-port")
		if _, ok := ext.Params["--syn"]; ok && ext.Module == "tcp" {
			modeled.add("--syn")
			if !newTCP {
				state.unknown = true
			} else if ext.Negations["--syn"] {
				return false
			}
		}
		if value, ok := ext.Params["--tcp-flags"]; ok && ext.Module == "tcp" {
			// iptables-save prints --syn as "--tcp-flags FIN,SYN,RST,ACK SYN".
			modeled.add("--tcp-flags")
			if matched, readable := synMatchesTCPFlags(value); !newTCP || !readable {
				state.unknown = true
			} else if matched == ext.Negations["--tcp-flags"] {
				return false
			}
		}
	case "multiport":
		modeled.add("--dports")
		modeled.add("--destination-ports")
		modeled.add("--sports")
		modeled.add("--source-ports")
		if value, ok := ext.Params["--ports"]; ok {
			// Matches when the source port or the destination port is listed.
			modeled.add("--ports")
			negated := ext.Negations["--ports"]
			switch {
			case len(cachedPortRanges(value)) == 0 || query.DstPort < 1 || query.DstPort > 65535:
				state.unknown = true
			case portInSpec(value, query.DstPort):
				if negated {
					return false
				}
			default:
				if !sourcePortMatch(value, negated, query, state) {
					return false
				}
			}
		}
	case "conntrack", "state":
		for _, key := range []string{"--ctstate", "--state"} {
			if value, ok := ext.Params[key]; ok {
				modeled.add(key)
				if !decided(stateMatch(strings.Split(value, ","), ext.Negations[key], query)) {
					return false
				}
			}
		}
		if value, ok := ext.Params["--ctorigdstport"]; ok {
			modeled.add("--ctorigdstport")
			if len(cachedPortRanges(value)) == 0 || query.OriginalDstPort == 0 {
				state.unknown = true
			} else if portInSpec(value, query.OriginalDstPort) == ext.Negations["--ctorigdstport"] {
				return false
			}
		}
		if value, ok := ext.Params["--ctorigdst"]; ok {
			modeled.add("--ctorigdst")
			original := query
			if query.NATState == "DNAT" {
				// The original destination of a DNATed connection was local.
				original.DstType = "LOCAL"
			}
			if !decided(addressMatch(value, query.OriginalDstAddr, ext.Negations["--ctorigdst"], original)) {
				return false
			}
		}
		if _, ok := ext.Params["--ctorigsrc"]; ok && query.External && query.Direction == "ORIGINAL" {
			// Evaluated together with -s by splitBySource.
			modeled.add("--ctorigsrc")
		}
		if value, ok := ext.Params["--ctdir"]; ok {
			modeled.add("--ctdir")
			if query.Direction == "" {
				state.unknown = true
			} else if strings.EqualFold(value, query.Direction) == ext.Negations["--ctdir"] {
				return false
			}
		}
	case "addrtype":
		if value, ok := ext.Params["--dst-type"]; ok {
			modeled.add("--dst-type")
			if !decided(addrTypeMatch(value, query.DstType, ext.Negations["--dst-type"])) {
				return false
			}
		}
		if value, ok := ext.Params["--src-type"]; ok {
			modeled.add("--src-type")
			actual := ""
			if query.External {
				actual = "UNICAST"
			}
			if !decided(addrTypeMatch(value, actual, ext.Negations["--src-type"])) {
				return false
			}
		}
	case "icmp":
		if value, ok := ext.Params["--icmp-type"]; ok {
			modeled.add("--icmp-type")
			if !decided(icmpTypeMatch(value, icmpTypeNames, query, ext.Negations["--icmp-type"])) {
				return false
			}
		}
	case "icmp6", "icmpv6":
		if value, ok := ext.Params["--icmpv6-type"]; ok {
			modeled.add("--icmpv6-type")
			if !decided(icmpTypeMatch(value, icmpv6TypeNames, query, ext.Negations["--icmpv6-type"])) {
				return false
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
				state.unknown = true
			} else if compare(query.HopLimit, expected) == ext.Negations[key] {
				return false
			}
		}
	case "iprange":
		if _, ok := ext.Params["--src-range"]; ok {
			// Evaluated together with -s by splitBySource.
			modeled.add("--src-range")
		}
	case "pkttype":
		// A connection to a service, or to a published port, is unicast.
		if value, ok := ext.Params["--pkt-type"]; ok {
			modeled.add("--pkt-type")
			unicast := strings.EqualFold(value, "unicast") || strings.EqualFold(value, "host")
			if unicast == ext.Negations["--pkt-type"] {
				return false
			}
		}

	// Predicates that every source can meet: the rule decides for any source,
	// but not for every packet.
	case "limit", "hashlimit":
		state.conditions = append(state.conditions, "rate limit")
		return true
	case "connlimit":
		state.conditions = append(state.conditions, "connection limit")
		return true
	case "statistic":
		state.conditions = append(state.conditions, "random share of packets")
		return true
	case "time":
		state.conditions = append(state.conditions, "time window")
		return true
	case "length", "string", "u32", "tos", "dscp", "ecn", "tcpmss", "ttl":
		state.conditions = append(state.conditions, "packet contents ("+ext.Module+")")
		return true
	case "recent":
		// --set records the source and always matches. With a hit count the
		// list is a rate limit; without one it is a list of sources that
		// qualified earlier, as in port knocking.
		name := ext.Params["--name"]
		if name == "" {
			name = "DEFAULT"
		}
		for _, key := range []string{"--rcheck", "--update", "--remove"} {
			if _, ok := ext.Params[key]; !ok {
				continue
			}
			if _, limited := ext.Params["--hitcount"]; limited {
				state.conditions = append(state.conditions, "rate limit")
			} else {
				sourceSubset("recent list "+name, ext.Negations[key])
			}
			return true
		}
		if _, ok := ext.Params["--set"]; ok {
			return true
		}
		state.unknown = true
		return true

	// Predicates that hold for an unknown subset of the sources.
	case "set":
		value := strings.Fields(ext.Params["--match-set"])
		if len(ext.Params) != 1 || len(value) != 2 || !strings.HasPrefix(value[1], "src") {
			// A set of destinations or ports, or options that change the result.
			state.unknown = true
			return true
		}
		sourceSubset("ipset "+value[0], ext.Negations["--match-set"])
		return true
	case "mac":
		if value, ok := ext.Params["--mac-source"]; ok && len(ext.Params) == 1 {
			sourceSubset("MAC address "+value, ext.Negations["--mac-source"])
			return true
		}
		state.unknown = true
		return true
	case "geoip":
		for _, key := range []string{"--src-cc", "--source-country"} {
			if value, ok := ext.Params[key]; ok && len(ext.Params) == 1 {
				sourceSubset("GeoIP "+value, ext.Negations[key])
				return true
			}
		}
		state.unknown = true
		return true
	case "policy":
		// IPsec: "--pol ipsec" holds for traffic of authenticated peers only.
		if value, ok := ext.Params["--pol"]; ok && (value == "ipsec" || value == "none") {
			sourceSubset("IPsec peers", (value == "none") != ext.Negations["--pol"])
			return true
		}
		state.unknown = true
		return true
	case "rpfilter":
		// Without --invert it matches sources that pass the reverse-path test:
		// all but forged ones.
		_, invert := ext.Params["--invert"]
		sourceSubset("sources that fail the reverse-path filter", !invert)
		return true

	default:
		// Module presence may itself constrain a match (for example socket), so
		// unknown modules remain indeterminate even when they have no options.
		state.unknown = true
		return true
	}

	for param := range ext.Params {
		if !modeled.has(param) {
			state.unknown = true
		}
	}
	return true
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

// splitBySource divides sources into those the source predicates of a rule
// match and the rest. The predicates are -s, the conntrack original source
// (which equals -s for externally received packets) and iprange --src-range.
// known is false when a predicate cannot be read.
func splitBySource(input addrSet, rule *models.Rule, query packetQuery) (matched, unmatched addrSet, known bool) {
	matched, unmatched, known = splitByPrefix(input, rule.SrcAddr, rule.Negations["src"])
	if !known {
		return input, input, false
	}
	for i := range rule.Matches {
		ext := &rule.Matches[i]
		var inside, outside addrSet
		switch ext.Module {
		case "conntrack":
			value, ok := ext.Params["--ctorigsrc"]
			if !ok || !query.External || query.Direction != "ORIGINAL" {
				continue
			}
			if inside, outside, known = splitByPrefix(matched, value, ext.Negations["--ctorigsrc"]); !known {
				return input, input, false
			}
		case "iprange":
			value, ok := ext.Params["--src-range"]
			if !ok {
				continue
			}
			lo, hi, ok := parseAddrRange(value)
			if !ok {
				return input, input, false
			}
			inside, outside = matched.splitRange(lo, hi)
			if ext.Negations["--src-range"] {
				inside, outside = outside, inside
			}
		default:
			continue
		}
		matched = inside
		unmatched = unmatched.union(outside)
	}
	return matched, unmatched, true
}

// parseAddrRange reads "first-last" as iprange prints it.
func parseAddrRange(value string) (lo, hi netip.Addr, ok bool) {
	first, last, found := strings.Cut(value, "-")
	if !found {
		return lo, hi, false
	}
	lo, errLo := netip.ParseAddr(first)
	hi, errHi := netip.ParseAddr(last)
	if errLo != nil || errHi != nil || lo.Is4() != hi.Is4() || lo.Compare(hi) > 0 {
		return lo, hi, false
	}
	return lo, hi, true
}

// sourceMayMatch reports whether the source predicates of the rule can match
// a source of the set. For the usual single -s predicate it does not build
// the two halves of the split.
func sourceMayMatch(sources addrSet, rule *models.Rule, query packetQuery) bool {
	if len(rule.Matches) == 0 && !rule.Negations["src"] {
		if rule.SrcAddr == "" || rule.SrcAddr == "0.0.0.0/0" || rule.SrcAddr == "::/0" {
			return !sources.empty()
		}
		if prefix, ok := cachedPrefix(rule.SrcAddr); ok {
			return sources.overlapsPrefix(prefix)
		}
		return !sources.empty()
	}
	matched, _, _ := splitBySource(sources, rule, query)
	return !matched.empty()
}

func splitByPrefix(input addrSet, source string, negated bool) (matched, unmatched addrSet, known bool) {
	if source == "" || source == "0.0.0.0/0" || source == "::/0" {
		if negated {
			return addrSet{}, input, true
		}
		return input, addrSet{}, true
	}
	predicate, ok := cachedPrefix(source)
	if !ok {
		return input, input, false
	}
	matched, unmatched = input.split(predicate)
	if negated {
		matched, unmatched = unmatched, matched
	}
	return matched, unmatched, true
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

// restrictedSourcePrefixes are source ranges that are not the public Internet:
// private, shared, link-local and loopback addresses.
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

var restrictedSources = setOfPrefixes(restrictedSourcePrefixes)

// Public sources count as specific networks rather than the Internet while
// they add up to at most one prefix of this length: 65,536 IPv4 addresses or
// one IPv6 site. Wider ranges and complements such as "! -s 10.0.0.0/8" stay
// exposed.
const (
	subnetMinBitsIPv4 = 16
	subnetMinBitsIPv6 = 48
)

// classifySegments returns the access scope of accepted sources, the rule
// that best explains it and, for a RESTRICTED scope, what restricts it.
//
// A segment of which only an unknown subset is accepted (members of an
// ipset, one MAC address) is RESTRICTED, unless its sources are private
// networks or single hosts already.
func classifySegments(accepted []decisionSegment) (models.AccessScope, *models.Rule, string) {
	var plain []decisionSegment
	for _, segment := range accepted {
		if segment.Narrowed == "" {
			plain = append(plain, segment)
		}
	}
	scope, rule := classifyAcceptedSources(plain)
	restriction := ""
	if len(plain) == len(accepted) {
		return scope, rule, restriction
	}
	for _, segment := range accepted {
		if segment.Narrowed == "" {
			continue
		}
		own, _ := classifyAcceptedSources([]decisionSegment{segment})
		if scopeRank(own) > scopeRank(models.ScopeRestricted) {
			own = models.ScopeRestricted
		}
		if scopeRank(own) > scopeRank(scope) {
			scope, rule, restriction = own, segment.Rule, ""
			if own == models.ScopeRestricted {
				restriction = segment.Narrowed
			}
		}
	}
	return scope, rule, restriction
}

// classifyAcceptedSources returns the access scope of sources that are
// accepted in full and the rule that best explains it. The scope follows
// from the addresses alone, not from how the rules happened to divide them:
//
//   - EXPOSED: more public addresses than one /16 (IPv4) or /48 (IPv6),
//   - SUBNET: a range of public addresses within that limit,
//   - LOCALNET: ranges of private addresses only,
//   - WHITELISTED: single addresses only.
func classifyAcceptedSources(accepted []decisionSegment) (models.AccessScope, *models.Rule) {
	// Track presence separately from attribution: segments accepted by a
	// chain policy have no rule.
	var hostRule, localRule, subnetRule, exposedRule *models.Rule
	any, local, subnet := false, false, false
	var public, limit u128
	note := func(target **models.Rule, rule *models.Rule) {
		if *target == nil {
			*target = rule
		}
	}
	for _, segment := range accepted {
		for _, r := range segment.Set.ranges() {
			if !any {
				any = true
				limit = pow2(32 - subnetMinBitsIPv4)
				if r.lo.Is6() {
					limit = pow2(128 - subnetMinBitsIPv6)
				}
			}
			outside := r.subtractSet(restrictedSources)
			outsideSize := outside.size()
			if r.lo == r.hi {
				note(&hostRule, segment.Rule)
				continue
			}
			if outsideSize != r.size() {
				local = true
				note(&localRule, segment.Rule)
			}
			if !outside.empty() {
				subnet = true
				note(&subnetRule, segment.Rule)
				if limit.less(outsideSize) {
					note(&exposedRule, segment.Rule)
				}
			}
		}
	}
	// Count every public address once, however many rules accept it.
	if any {
		public = segmentsUnion(accepted, nil).subtract(restrictedSources).size()
	}
	switch {
	case !any:
		return "", nil
	case limit.less(public):
		// Many narrow allowlist entries can still add up to a wide audience.
		for _, rule := range []*models.Rule{exposedRule, subnetRule, hostRule} {
			if rule != nil {
				return models.ScopeExposed, rule
			}
		}
		return models.ScopeExposed, nil
	case subnet:
		return models.ScopeSubnet, subnetRule
	case local:
		return models.ScopeLocalnet, localRule
	}
	return models.ScopeWhitelisted, hostRule
}

// labelSets holds accepted sources by what narrows them; the key "" holds
// the sources that are accepted in full.
type labelSets map[string]addrSet

func (l labelSets) add(segments []decisionSegment) {
	for _, segment := range segments {
		l[segment.Narrowed] = l[segment.Narrowed].union(segment.Set)
	}
}

// segmentsBeyond returns the part of the segments that covered does not
// already accept: in full, or narrowed in the same way.
func segmentsBeyond(segments []decisionSegment, covered labelSets) []decisionSegment {
	var result []decisionSegment
	for _, segment := range segments {
		rest := segment.Set.subtract(covered[""])
		if segment.Narrowed != "" {
			rest = rest.subtract(covered[segment.Narrowed])
		}
		if !rest.empty() {
			segment.Set = rest
			result = append(result, segment)
		}
	}
	return result
}

// segmentsMinus returns the segments without the given sources.
func segmentsMinus(segments []decisionSegment, sources addrSet) []decisionSegment {
	return segmentsBeyond(segments, labelSets{"": sources})
}

func classifySet(sources addrSet) models.AccessScope {
	scope, _ := classifyAcceptedSources(segments(sources, nil, false))
	return scope
}

// scopeRank orders access scopes from unreachable to unrestricted.
func scopeRank(scope models.AccessScope) int {
	switch scope {
	case models.ScopeExposed:
		return 5
	case models.ScopeSubnet:
		return 4
	case models.ScopeRestricted:
		return 3
	case models.ScopeLocalnet:
		return 2
	case models.ScopeWhitelisted:
		return 1
	}
	return 0
}
