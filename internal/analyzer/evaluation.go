package analyzer

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// packetQuery fixes the packet attributes known to an analysis. Empty interface
// and destination fields mean that multiple values are possible.
type packetQuery struct {
	Protocol models.Protocol
	DstPort  int
	DstAddr  string
	InIface  string
	OutIface string
	State    string
	External bool
	Chain    string
	Hook     string
}

type matchCertainty uint8

const (
	matchNo matchCertainty = iota
	matchMaybe
	matchYes
)

type decisionSegment struct {
	Prefix netip.Prefix
	Rule   *models.Rule
}

type chainEvaluation struct {
	Accepted []decisionSegment
	Dropped  []decisionSegment
	Returned []netip.Prefix
}

func evaluateAccess(rs *models.Ruleset, chainName string, query packetQuery) (models.AccessScope, *models.Rule, *models.Rule) {
	return evaluateAccessFrom(rs, chainName, query, nil)
}

func evaluateAccessFrom(rs *models.Ruleset, chainName string, query packetQuery, sources []netip.Prefix) (models.AccessScope, *models.Rule, *models.Rule) {
	if rs == nil {
		return models.ScopeExposed, nil, nil
	}
	filter, ok := rs.Tables["filter"]
	if !ok {
		return models.ScopeExposed, nil, nil
	}
	if _, ok := filter.Chains[chainName]; !ok {
		return models.ScopeExposed, nil, nil
	}

	query.Chain = chainName
	query.Hook = chainName
	root := netip.MustParsePrefix("0.0.0.0/0")
	if rs.IPVersion == models.IPv6 {
		root = netip.MustParsePrefix("::/0")
	}
	if len(sources) == 0 {
		sources = []netip.Prefix{root}
	}
	result := evaluateChain(filter, chainName, sources, query, map[string]bool{})
	scope, allowRule := classifyAcceptedSources(result.Accepted)
	var dropRule *models.Rule
	if len(result.Dropped) > 0 {
		dropRule = result.Dropped[0].Rule
	}
	return scope, allowRule, dropRule
}

func evaluateChain(table *models.Table, chainName string, input []netip.Prefix, query packetQuery, path map[string]bool) chainEvaluation {
	chain, ok := table.Chains[chainName]
	if !ok {
		return chainEvaluation{Returned: input}
	}
	if path[chainName] {
		// Kernel rule insertion normally prevents loops. If one is nevertheless
		// present in saved input, keep both outcomes possible instead of claiming
		// that traffic is filtered.
		return chainEvaluation{Accepted: segmentsFor(input, nil), Returned: input}
	}
	path[chainName] = true
	defer delete(path, chainName)

	remaining := normalizePrefixes(input)
	var result chainEvaluation
	for i := range chain.Rules {
		if len(remaining) == 0 {
			break
		}
		rule := &chain.Rules[i]
		matched, unmatched, sourceKnown := splitBySource(remaining, rule)
		if len(matched) == 0 {
			continue
		}

		certainty := ruleMatchesQuery(rule, query)
		if certainty == matchNo {
			continue
		}
		if certainty == matchMaybe || !sourceKnown {
			// The predicate can match some packets and miss others. Preserve the
			// non-matching branch while evaluating the matching branch as possible.
			unmatched = append(unmatched, matched...)
		}
		remaining = normalizePrefixes(unmatched)

		switch rule.Target {
		case "ACCEPT":
			result.Accepted = append(result.Accepted, segmentsFor(matched, rule)...)
		case "DROP", "REJECT":
			result.Dropped = append(result.Dropped, segmentsFor(matched, rule)...)
		case "RETURN":
			if chain.Policy == "ACCEPT" {
				result.Accepted = append(result.Accepted, segmentsFor(matched, nil)...)
			} else if chain.Policy == "DROP" {
				result.Dropped = append(result.Dropped, segmentsFor(matched, nil)...)
			} else {
				result.Returned = append(result.Returned, matched...)
			}
		default:
			if _, isChain := table.Chains[rule.Target]; isChain {
				childQuery := query
				childQuery.Chain = rule.Target
				child := evaluateChain(table, rule.Target, matched, childQuery, path)
				result.Accepted = append(result.Accepted, child.Accepted...)
				result.Dropped = append(result.Dropped, child.Dropped...)
				if rule.Goto {
					if chain.Policy == "ACCEPT" {
						result.Accepted = append(result.Accepted, segmentsFor(child.Returned, nil)...)
					} else if chain.Policy == "DROP" {
						result.Dropped = append(result.Dropped, segmentsFor(child.Returned, nil)...)
					} else {
						result.Returned = append(result.Returned, child.Returned...)
					}
				} else {
					remaining = normalizePrefixes(append(remaining, child.Returned...))
				}
			} else if rule.Target == "QUEUE" || rule.Target == "NFQUEUE" {
				// Userspace decides the verdict. An ACCEPT outcome is possible.
				result.Accepted = append(result.Accepted, segmentsFor(matched, rule)...)
				remaining = normalizePrefixes(append(remaining, matched...))
			} else {
				// LOG, MARK and other non-verdict targets continue in this chain.
				remaining = normalizePrefixes(append(remaining, matched...))
			}
		}
	}

	if chain.Policy == "ACCEPT" {
		result.Accepted = append(result.Accepted, segmentsFor(remaining, nil)...)
	} else if chain.Policy == "DROP" {
		result.Dropped = append(result.Dropped, segmentsFor(remaining, nil)...)
	} else {
		result.Returned = append(result.Returned, remaining...)
	}
	result.Returned = normalizePrefixes(result.Returned)
	return result
}

func segmentsFor(prefixes []netip.Prefix, rule *models.Rule) []decisionSegment {
	segments := make([]decisionSegment, 0, len(prefixes))
	for _, prefix := range prefixes {
		segments = append(segments, decisionSegment{Prefix: prefix, Rule: rule})
	}
	return segments
}

func ruleMatchesQuery(rule *models.Rule, query packetQuery) matchCertainty {
	certainty := matchYes
	combine := func(next matchCertainty) {
		if next < certainty {
			certainty = next
		}
	}

	if rule.Protocol == "" || rule.Protocol == models.ProtoAll {
		if rule.Negations["protocol"] {
			return matchNo
		}
	} else {
		matched := rule.Protocol == query.Protocol
		if rule.Negations["protocol"] {
			matched = !matched
		}
		if !matched {
			return matchNo
		}
	}

	if rule.DstPort != "" {
		ranges := expandPorts(rule.DstPort)
		if len(ranges) == 0 || query.DstPort < 0 || query.DstPort > 65535 {
			combine(matchMaybe)
		} else {
			matched := portMatches(rule.DstPort, strconv.Itoa(query.DstPort))
			if rule.Negations["dport"] {
				matched = !matched
			}
			if !matched {
				return matchNo
			}
		}
	}
	if rule.SrcPort != "" {
		combine(matchMaybe)
	}

	combine(addressMatch(rule.DstAddr, query.DstAddr, rule.Negations["dst"]))
	if certainty == matchNo {
		return matchNo
	}
	combine(interfaceMatch(rule.InIface, query.InIface, rule.Negations["in-iface"], query.External))
	if certainty == matchNo {
		return matchNo
	}
	combine(interfaceMatch(rule.OutIface, query.OutIface, rule.Negations["out-iface"], false))
	if certainty == matchNo {
		return matchNo
	}

	if len(rule.States) > 0 && query.State != "" {
		matched := containsState(rule.States, query.State)
		if rule.Negations["state"] {
			matched = !matched
		}
		if !matched {
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

func addressMatch(ruleAddr, queryAddr string, negated bool) matchCertainty {
	if ruleAddr == "" || ruleAddr == "0.0.0.0/0" || ruleAddr == "::/0" {
		if negated {
			return matchNo
		}
		return matchYes
	}
	if queryAddr == "" || queryAddr == "0.0.0.0" || queryAddr == "::" || queryAddr == "*" {
		return matchMaybe
	}
	prefix, ok := parsePrefix(ruleAddr)
	addr, err := netip.ParseAddr(strings.Split(queryAddr, "%")[0])
	if !ok || err != nil || prefix.Addr().Is4() != addr.Is4() {
		return matchMaybe
	}
	matched := prefix.Contains(addr)
	if negated {
		matched = !matched
	}
	if matched {
		return matchYes
	}
	return matchNo
}

func interfaceMatch(ruleIface, queryIface string, negated, external bool) matchCertainty {
	if ruleIface == "" {
		return matchYes
	}
	if queryIface == "" {
		if external && ruleIface == "lo" {
			if negated {
				return matchYes
			}
			return matchNo
		}
		return matchMaybe
	}
	matched := ifaceCovers(ruleIface, queryIface)
	if negated {
		matched = !matched
	}
	if matched {
		return matchYes
	}
	return matchNo
}

func extensionCertainty(ext models.MatchExt, query packetQuery) matchCertainty {
	modeled := map[string]bool{}
	switch ext.Module {
	case "comment":
		return matchYes
	case "tcp", "udp":
		modeled["--dport"] = true
		modeled["--destination-port"] = true
		modeled["--sport"] = true
		modeled["--source-port"] = true
	case "multiport":
		modeled["--dports"] = true
		modeled["--destination-ports"] = true
		modeled["--sports"] = true
		modeled["--source-ports"] = true
	case "conntrack", "state":
		modeled["--ctstate"] = true
		modeled["--state"] = true
	case "addrtype":
		if dstType, ok := ext.Params["--dst-type"]; ok && strings.EqualFold(dstType, "LOCAL") && query.Hook == "INPUT" && !ext.Negations["--dst-type"] {
			modeled["--dst-type"] = true
		}
	default:
		// Module presence may itself constrain a match (for example socket), so
		// unknown modules remain indeterminate even when they have no options.
		return matchMaybe
	}

	for param := range ext.Params {
		if !modeled[param] {
			return matchMaybe
		}
	}
	return matchYes
}

func splitBySource(input []netip.Prefix, rule *models.Rule) (matched, unmatched []netip.Prefix, known bool) {
	source := rule.SrcAddr
	if source == "" || source == "0.0.0.0/0" || source == "::/0" {
		if rule.Negations["src"] {
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
	if rule.Negations["src"] {
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
	var whitelistRule, localRule, exposedRule *models.Rule
	for _, segment := range accepted {
		prefix := segment.Prefix
		if prefix.Bits() == prefix.Addr().BitLen() {
			if whitelistRule == nil {
				whitelistRule = segment.Rule
			}
			continue
		}
		if prefixIsRestricted(prefix) {
			if localRule == nil {
				localRule = segment.Rule
			}
			continue
		}
		exposedRule = segment.Rule
		break
	}
	if exposedRule != nil || hasExposedDefaultSegment(accepted) {
		return models.ScopeExposed, exposedRule
	}
	if localRule != nil {
		return models.ScopeLocalnet, localRule
	}
	return models.ScopeWhitelisted, whitelistRule
}

func hasExposedDefaultSegment(accepted []decisionSegment) bool {
	for _, segment := range accepted {
		if segment.Prefix.Bits() < segment.Prefix.Addr().BitLen() && !prefixIsRestricted(segment.Prefix) {
			return true
		}
	}
	return false
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
