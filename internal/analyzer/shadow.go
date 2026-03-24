package analyzer

import (
	"net"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// DetectShadowedRules finds rules that are shadowed by earlier rules in the same chain
func DetectShadowedRules(rs *models.Ruleset) []models.ShadowFinding {
	if rs == nil {
		return nil
	}

	var findings []models.ShadowFinding

	for _, table := range rs.Tables {
		for _, chain := range table.Chains {
			findings = append(findings, detectShadowsInChain(chain, table.Name, rs.IPVersion)...)
		}
	}

	return findings
}

func detectShadowsInChain(chain *models.Chain, tableName string, ipVer models.IPVersion) []models.ShadowFinding {
	var findings []models.ShadowFinding
	rules := chain.Rules

	for j := 1; j < len(rules); j++ {
		for i := 0; i < j; i++ {
			if !rules[i].IsTerminal() {
				continue
			}
			if isSuperset(&rules[i], &rules[j], ipVer) {
				sev := models.SeverityMedium
				// Higher severity if shadowed rule has opposite action
				if rules[i].IsBlock() != rules[j].IsBlock() {
					sev = models.SeverityHigh
				}
				findings = append(findings, models.ShadowFinding{
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

// isSuperset returns true if rule A matches every packet that rule B matches
func isSuperset(a, b *models.Rule, ipVer models.IPVersion) bool {
	// Both must be in same chain (already guaranteed by caller)

	// Skip rules with negations - too complex to compare
	if len(a.Negations) > 0 || len(b.Negations) > 0 {
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
	// Normalize: add /32 or /128 if missing
	if !strings.Contains(outer, "/") {
		outer += "/32"
	}
	if !strings.Contains(inner, "/") {
		inner += "/32"
	}

	_, outerNet, err := net.ParseCIDR(outer)
	if err != nil {
		return false
	}
	_, innerNet, err := net.ParseCIDR(inner)
	if err != nil {
		return false
	}

	onesOuter, bitsOuter := outerNet.Mask.Size()
	onesInner, bitsInner := innerNet.Mask.Size()

	if bitsOuter != bitsInner {
		return false // different address families
	}

	// Outer must have equal or shorter prefix (wider range)
	if onesOuter > onesInner {
		return false
	}

	return outerNet.Contains(innerNet.IP)
}

func portCovers(a, b string) bool {
	if a == "" {
		return true // a matches any port
	}
	if b == "" {
		return false // a is specific, b is any
	}

	aPorts := expandPorts(a)
	bPorts := expandPorts(b)

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
			lo, _ := strconv.Atoi(part[:idx])
			hi, _ := strconv.Atoi(part[idx+1:])
			ranges = append(ranges, [2]int{lo, hi})
		} else {
			p, _ := strconv.Atoi(part)
			if p > 0 {
				ranges = append(ranges, [2]int{p, p})
			}
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

// narrowingModules lists match modules whose parameters restrict which
// packets the rule applies to.  If rule A uses one of these, it can only
// shadow rule B if B uses the same module with compatible parameters.
var narrowingModules = map[string]bool{
	"icmp6":     true, // --icmpv6-type
	"icmp":      true, // --icmp-type
	"recent":    true, // --update --seconds --hitcount
	"limit":     true, // --limit --limit-burst
	"hashlimit": true,
	"string":    true,
	"u32":       true,
	"mark":      true,
	"owner":     true,
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
	"icmp6": {"--icmpv6-type": true},
	"icmp":  {"--icmp-type": true},
	"limit": {"--limit": true, "--limit-burst": true},
}

func matchExtsCovers(aExts, bExts []models.MatchExt) bool {
	// Index B's modules for quick lookup.
	bByMod := map[string]*models.MatchExt{}
	for i := range bExts {
		bByMod[bExts[i].Module] = &bExts[i]
	}

	for _, aExt := range aExts {
		if !narrowingModules[aExt.Module] {
			continue
		}
		// Check if this ext instance actually narrows (has narrowing params).
		hasNarrowing := false
		nps := narrowingParams[aExt.Module]
		for key := range aExt.Params {
			if nps != nil && nps[key] {
				hasNarrowing = true
				break
			}
		}
		if !hasNarrowing {
			continue // e.g. "recent --set" without --update is non-narrowing
		}
		// A narrows on this module — B must have the same module with same
		// narrowing params, otherwise A is more restrictive than B.
		bExt, ok := bByMod[aExt.Module]
		if !ok {
			return false // A restricts on a module B doesn't use
		}
		// Both have the module. Compare narrowing params — A covers B only
		// if every narrowing param in A has the same value in B.
		for key := range aExt.Params {
			if nps != nil && nps[key] {
				if bExt.Params[key] != aExt.Params[key] {
					return false
				}
			}
		}
	}

	// Also: if B has a narrowing module that A doesn't, then A IS wider
	// on that axis — that's fine, A still covers B. So we only need to
	// check A's modules (done above).

	return true
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
