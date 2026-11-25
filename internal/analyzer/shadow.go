package analyzer

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// DetectShadowedRules finds rules that are shadowed by earlier rules in the same chain
func DetectShadowedRules(rs *models.Ruleset) []models.ShadowFinding {
	if rs == nil {
		return nil
	}

	var findings []models.ShadowFinding

	for _, tableName := range sortedTableNames(rs) {
		table := rs.Tables[tableName]
		for _, chainName := range sortedChainNames(table) {
			chain := table.Chains[chainName]
			findings = append(findings, detectShadowsInChain(chain, table.Name, rs.IPVersion)...)
		}
	}

	return findings
}

func detectShadowsInChain(chain *models.Chain, tableName string, ipVer models.IPVersion) []models.ShadowFinding {
	var findings []models.ShadowFinding
	rules := chain.Rules
	index := newShadowIndex(chain)
	// Rules after a rule that ends the chain for every packet are reported
	// together as unreachable (checkDeadRules), not one by one as shadowed.
	last := len(rules) - 1
	if catchAll := firstCatchAll(chain); catchAll >= 0 {
		last = catchAll
	}

	for j := 1; j <= last; j++ {
		for _, i := range index.candidates(&rules[j], j) {
			if isSuperset(&rules[i], &rules[j], ipVer) {
				sev := models.SeverityMedium
				// Higher severity if shadowed rule has opposite action
				if rules[i].IsBlock() != rules[j].IsBlock() {
					sev = models.SeverityHigh
				}
				findings = append(findings, models.ShadowFinding{
					Code:          models.FindingShadowedRule,
					Certainty:     models.CertaintyDefinite,
					ShadowingRule: rules[i],
					ShadowedRule:  rules[j],
					Reason: "Rule #" + strconv.Itoa(rules[j].RuleNum) + " in " +
						tableName + "/" + chain.Name +
						" is shadowed by rule #" + strconv.Itoa(rules[i].RuleNum) +
						" which matches all the same traffic",
					Severity: sev,
				})
				break // only report the first shadowing rule
			}
		}
	}

	return findings
}

// shadowIndex finds the rules of a chain that can cover a given rule without
// comparing every pair: a chain with thousands of rules (a blocklist, one
// rule per published port) would need millions of comparisons.
//
// A rule can only cover another when it is terminal and free of negations,
// when its source is "any" or contains the other source, and when its
// destination-port predicate contains the other ports.
type shadowIndex struct {
	chain     *models.Chain
	ports     *chainIndex
	eligible  []bool                 // terminal, without negation or fragment predicate
	anySource []int                  // eligible rules without a source predicate
	bySource  map[netip.Prefix][]int // eligible rules by their source prefix
	sources   []netip.Prefix         // parsed source of each rule; invalid when absent
}

func newShadowIndex(chain *models.Chain) *shadowIndex {
	index := &shadowIndex{
		chain:    chain,
		ports:    newChainIndex(chain),
		eligible: make([]bool, len(chain.Rules)),
		bySource: map[netip.Prefix][]int{},
		sources:  make([]netip.Prefix, len(chain.Rules)),
	}
	for i := range chain.Rules {
		rule := &chain.Rules[i]
		source, hasSource := netip.Prefix{}, false
		if rule.SrcAddr != "" && rule.SrcAddr != "0.0.0.0/0" && rule.SrcAddr != "::/0" {
			var ok bool
			if source, ok = cachedPrefix(rule.SrcAddr); !ok {
				continue // an unreadable source covers nothing and is covered by nothing
			}
			hasSource = true
			index.sources[i] = source
		}
		if !rule.IsTerminal() || len(rule.Negations) > 0 || rule.Fragment {
			continue
		}
		index.eligible[i] = true
		if hasSource {
			index.bySource[source] = append(index.bySource[source], i)
		} else {
			index.anySource = append(index.anySource, i)
		}
	}
	return index
}

// candidates returns, in chain order, the rules before position j that can
// cover rule b.
func (index *shadowIndex) candidates(b *models.Rule, j int) []int {
	if len(b.Negations) > 0 || b.Fragment {
		return nil
	}
	// Rules whose source is "any" or contains the source of b.
	lists := [][]int{index.anySource}
	if source := index.sources[j]; source.IsValid() {
		for bits := source.Bits(); bits >= 0; bits-- {
			if ancestor, err := source.Addr().Prefix(bits); err == nil {
				if list := index.bySource[ancestor]; len(list) > 0 {
					lists = append(lists, list)
				}
			}
		}
	} else if b.SrcAddr != "" && b.SrcAddr != "0.0.0.0/0" && b.SrcAddr != "::/0" {
		return nil
	}
	// Of those, the rules whose destination ports can contain the ports of b.
	port, indexed := 0, false
	if ranges := cachedPortRanges(b.DstPort); b.DstPort != "" && !b.Negations["dport"] && len(ranges) > 0 {
		port, indexed = ranges[0][0], true
	}
	var candidates []int
	for _, list := range lists {
		for _, i := range list {
			if i >= j {
				break
			}
			if ranges := cachedPortRanges(index.chain.Rules[i].DstPort); len(ranges) > 0 {
				if !indexed || !rangesContain(ranges, port) {
					continue // the rule names ports that b does not have
				}
			}
			candidates = append(candidates, i)
		}
	}
	if len(lists) > 1 {
		sort.Ints(candidates)
	}
	return candidates
}

func rangesContain(ranges [][2]int, port int) bool {
	for _, r := range ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

var prefixCache sync.Map // address or prefix text -> netip.Prefix, invalid when unreadable

// cachedPrefix memoizes parsePrefix: rule addresses are compared many times.
func cachedPrefix(value string) (netip.Prefix, bool) {
	if cached, ok := prefixCache.Load(value); ok {
		prefix := cached.(netip.Prefix)
		return prefix, prefix.IsValid()
	}
	prefix, ok := parsePrefix(value)
	if !ok {
		prefix = netip.Prefix{}
	}
	prefixCache.Store(value, prefix)
	return prefix, ok
}

// isSuperset returns true if rule A matches every packet that rule B matches
func isSuperset(a, b *models.Rule, ipVer models.IPVersion) bool {
	// Both must be in same chain (already guaranteed by caller)

	// Skip rules with negations - too complex to compare
	if len(a.Negations) > 0 || len(b.Negations) > 0 {
		return false
	}
	if a.Fragment || b.Fragment {
		return false
	}

	// Protocol check
	if !protocolCovers(a.Protocol, b.Protocol) {
		return false
	}

	// Source address
	anyAddr := "0.0.0.0/0"
	if ipVer == models.IPv6 {
		anyAddr = "::/0"
	}
	if !addrCovers(a.SrcAddr, b.SrcAddr, anyAddr) {
		return false
	}

	// Destination address
	if !addrCovers(a.DstAddr, b.DstAddr, anyAddr) {
		return false
	}

	// Ports
	if !portCovers(a.DstPort, b.DstPort) {
		return false
	}
	if !portCovers(a.SrcPort, b.SrcPort) {
		return false
	}

	// Interface
	if !ifaceCovers(a.InIface, b.InIface) {
		return false
	}
	if !ifaceCovers(a.OutIface, b.OutIface) {
		return false
	}

	// Conntrack state
	if !statesCovers(a.States, b.States) {
		return false
	}

	// Match extensions — if A has narrowing match modules (icmp type, recent,
	// limit, etc.) that B lacks or differs on, A doesn't cover B.
	if !matchExtsCovers(a.Matches, b.Matches) {
		return false
	}

	return true
}

func protocolCovers(a, b models.Protocol) bool {
	if a == "" || a == models.ProtoAll {
		return true
	}
	return a == b
}

func addrCovers(a, b, anyAddr string) bool {
	if a == "" || a == anyAddr {
		return true
	}
	if b == "" || b == anyAddr {
		return false // a is specific, b is any -> a doesn't cover b
	}
	return cidrContains(a, b)
}

func cidrContains(outer, inner string) bool {
	outerPrefix, ok := cachedPrefix(outer)
	if !ok {
		return false
	}
	innerPrefix, ok := cachedPrefix(inner)
	if !ok || outerPrefix.Addr().Is4() != innerPrefix.Addr().Is4() {
		return false // unreadable, or different address families
	}
	// Outer must have equal or shorter prefix (wider range)
	return outerPrefix.Bits() <= innerPrefix.Bits() && outerPrefix.Contains(innerPrefix.Addr())
}

func portCovers(a, b string) bool {
	if a == "" {
		return true // a matches any port
	}
	if b == "" {
		return false // a is specific, b is any
	}

	aPorts := cachedPortRanges(a)
	bPorts := cachedPortRanges(b)

	// All ports in b must be in a
	for _, bp := range bPorts {
		found := false
		for _, ap := range aPorts {
			if ap[0] <= bp[0] && ap[1] >= bp[1] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// expandPorts returns a list of [min,max] ranges
func expandPorts(spec string) [][2]int {
	var ranges [][2]int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, ":"); idx >= 0 {
			lo, hi := 0, 65535
			var err error
			if part[:idx] != "" {
				lo, err = strconv.Atoi(part[:idx])
				if err != nil {
					return nil
				}
			}
			if part[idx+1:] != "" {
				hi, err = strconv.Atoi(part[idx+1:])
				if err != nil {
					return nil
				}
			}
			if lo < 0 || hi > 65535 || lo > hi {
				return nil
			}
			ranges = append(ranges, [2]int{lo, hi})
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 0 || p > 65535 {
				return nil
			}
			ranges = append(ranges, [2]int{p, p})
		}
	}
	return ranges
}

func ifaceCovers(a, b string) bool {
	if a == "" {
		return true
	}
	if b == "" {
		return false
	}
	// Handle wildcard interfaces like "eth+" matching "eth0", "eth1"
	if strings.HasSuffix(a, "+") {
		return strings.HasPrefix(b, a[:len(a)-1])
	}
	return a == b
}

// narrowingParams lists per-module params that restrict the match scope.
// A module might have a param that only sets state (e.g. recent --set)
// rather than narrowing — those are tracked here so we can tell apart
// "recent --set" (non-narrowing) from "recent --update --seconds 300"
// (narrowing).
var narrowingParams = map[string]map[string]bool{
	"recent": {
		"--update": true, "--rcheck": true, "--seconds": true,
		"--hitcount": true, "--rttl": true,
	},
	"icmp6":    {"--icmpv6-type": true},
	"icmp":     {"--icmp-type": true},
	"limit":    {"--limit": true, "--limit-burst": true},
	"addrtype": {"--dst-type": true, "--src-type": true},
}

func matchExtsCovers(aExts, bExts []models.MatchExt) bool {
	bSignatures := make(map[string]int)
	for _, ext := range bExts {
		if signature := matchConstraintSignature(ext); signature != "" {
			bSignatures[signature]++
		}
	}
	for _, ext := range aExts {
		if statefulMatchModule(ext.Module) {
			return false
		}
		signature := matchConstraintSignature(ext)
		if signature == "" {
			continue
		}
		if bSignatures[signature] == 0 {
			return false
		}
		bSignatures[signature]--
	}
	return true
}

func statefulMatchModule(module string) bool {
	switch module {
	case "limit", "hashlimit", "statistic", "recent", "quota", "nth":
		return true
	default:
		return false
	}
}

// matchConstraintSignature returns a stable representation of match behavior
// that is not already modeled by Rule fields. Unknown extensions are treated
// as restrictive; equality is required before claiming one rule covers another.
func matchConstraintSignature(ext models.MatchExt) string {
	ignored := map[string]bool{}
	switch ext.Module {
	case "comment":
		return ""
	case "tcp", "udp":
		ignored["--dport"] = true
		ignored["--destination-port"] = true
		ignored["--sport"] = true
		ignored["--source-port"] = true
	case "multiport":
		ignored["--dports"] = true
		ignored["--destination-ports"] = true
		ignored["--sports"] = true
		ignored["--source-ports"] = true
	case "conntrack", "state":
		ignored["--ctstate"] = true
		ignored["--state"] = true
	case "recent":
		// --set only records the address and does not narrow the match.
		hasNarrowing := false
		for key := range ext.Params {
			if narrowingParams[ext.Module][key] {
				hasNarrowing = true
			}
		}
		if !hasNarrowing {
			return ""
		}
	}

	keys := make([]string, 0, len(ext.Params))
	for key := range ext.Params {
		if !ignored[key] {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		switch ext.Module {
		case "tcp", "udp", "multiport", "conntrack", "state":
			return ""
		}
	}
	if len(ext.RawTokens) > 0 {
		return ext.Module + "|" + strings.Join(ext.RawTokens, "\x1f")
	}
	sort.Strings(keys)
	var signature strings.Builder
	signature.WriteString(ext.Module)
	for _, key := range keys {
		signature.WriteString("|")
		if ext.Negations[key] {
			signature.WriteString("!")
		}
		signature.WriteString(key)
		signature.WriteString("=")
		signature.WriteString(ext.Params[key])
	}
	return signature.String()
}

func statesCovers(a, b []string) bool {
	if len(a) == 0 {
		return true // no state restriction covers everything
	}
	if len(b) == 0 {
		return false // a has restriction, b doesn't
	}
	aSet := make(map[string]bool)
	for _, s := range a {
		aSet[strings.TrimSpace(s)] = true
	}
	for _, s := range b {
		if !aSet[strings.TrimSpace(s)] {
			return false
		}
	}
	return true
}
