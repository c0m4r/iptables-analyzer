package analyzer

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/hostinfo"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The functions in this file bring facts about the host into the analysis:
// the contents of ipsets, kernel settings, and nftables tables that
// iptables-save does not print. Live analysis and snapshots supply them.

// sourceSets returns the address sets of the ipsets that hold addresses of
// one family, by name. A set of sets is the union of its members; it is left
// out when one of them is not a set of addresses.
func sourceSets(host *models.HostContext, version models.IPVersion) map[string]addrSet {
	if host == nil || len(host.IPSets) == 0 {
		return nil
	}
	family := "inet"
	if version == models.IPv6 {
		family = "inet6"
	}
	sets := map[string]addrSet{}
	for name, set := range host.IPSets {
		if !set.Addresses || (set.Family != "" && set.Family != family) {
			continue
		}
		included := entryRanges(set.Entries, version)
		excluded := entryRanges(set.Excluded, version)
		sets[name] = normalizeRanges(included).subtract(normalizeRanges(excluded))
	}
	for name, set := range host.IPSets {
		if set.Type != "list:set" {
			continue
		}
		union, complete := addrSet{}, true
		for _, member := range set.Members {
			addresses, known := sets[member]
			if _, isList := host.IPSets[member]; !known && isList && host.IPSets[member].Addresses {
				continue // a set of the other address family holds nothing of this one
			}
			if !known {
				complete = false
				break
			}
			union = union.union(addresses)
		}
		if complete {
			sets[name] = union
		}
	}
	return sets
}

// entryRanges converts the entries of an ipset to ranges of one family.
func entryRanges(entries []string, version models.IPVersion) []addrRange {
	var ranges []addrRange
	for _, entry := range entries {
		var lo, hi netip.Addr
		if first, last, isRange := strings.Cut(entry, "-"); isRange {
			var errLo, errHi error
			lo, errLo = netip.ParseAddr(first)
			hi, errHi = netip.ParseAddr(last)
			if errLo != nil || errHi != nil || lo.Compare(hi) > 0 {
				continue
			}
		} else {
			prefix, ok := parsePrefix(entry)
			if !ok {
				continue
			}
			lo, hi = prefix.Addr(), lastAddr(prefix)
		}
		if lo.Is4() != hi.Is4() || lo.Is6() != (version == models.IPv6) || lo.Is4In6() {
			continue
		}
		ranges = append(ranges, addrRange{lo: lo, hi: hi})
	}
	return ranges
}

// knownSourceSet returns the addresses of the set that a "-m set" match
// tests the source address against, when its contents are known.
func knownSourceSet(ext *models.MatchExt, ctx *evalContext) (addrSet, bool) {
	if ctx == nil || ctx.sets == nil || ext.Module != "set" || len(ext.Params) != 1 {
		return addrSet{}, false
	}
	value := strings.Fields(ext.Params["--match-set"])
	// The first flag is the one that a set of addresses uses.
	if len(value) != 2 || strings.Split(value[1], ",")[0] != "src" {
		return addrSet{}, false
	}
	set, known := ctx.sets[value[0]]
	return set, known
}

// localnetRouted reports whether the host delivers packets from other hosts
// for 127.0.0.0/8 that arrive on an interface (route_localnet).
func (e *inputEvaluator) localnetRouted(iface string) (on, known bool) {
	if iface == otherInterface {
		iface = ""
	}
	value, known := hostinfo.InterfaceSetting(e.host, "route_localnet", iface)
	if !known {
		// When it is on for all interfaces, the one of the packet does not matter.
		if all, ok := e.host.Sysctl("net.ipv4.conf.all.route_localnet"); ok && all != "0" {
			return true, true
		}
		return false, false
	}
	return value != "0", true
}

// incomingHooks are the nftables hooks that a packet for this host, or one
// that it routes, passes.
var incomingHooks = map[string]bool{"ingress": true, "prerouting": true, "input": true, "forward": true}

// nativeTableDiagnostics reports nftables tables that iptables-save does not
// print and that filter incoming packets. A packet must pass the chains of
// every table on a hook, so such a table can only make the firewall
// stricter than this analysis says, or change destinations that it follows.
func nativeTableDiagnostics(result *models.AnalysisResult, host *models.HostContext) []models.AssessmentDiagnostic {
	if host == nil || !host.NativeKnown {
		return nil
	}
	var diagnostics []models.AssessmentDiagnostic
	for _, table := range host.NativeTables {
		switch table.Family {
		case "ip":
			if result.IPv4Rules == nil {
				continue
			}
		case "ip6":
			if result.IPv6Rules == nil {
				continue
			}
		}
		var hooks []string
		for _, hook := range table.Hooks {
			if incomingHooks[hook] {
				hooks = append(hooks, hook)
			}
		}
		if len(hooks) == 0 {
			continue
		}
		sort.Strings(hooks)
		name := table.Family + " " + table.Name
		diagnostics = append(diagnostics, models.AssessmentDiagnostic{Area: "rules", Message: fmt.Sprintf(
			"nftables table %s has chains on the %s %s. iptables-save does not print its rules, and packets pass them as well: "+
				"the real firewall can be stricter than this report. Read them with 'nft list table %s'",
			name, pluralWord(len(hooks), "hook", "hooks"), joinWords(hooks), name)})
	}
	return diagnostics
}

// joinWords renders "a", "a and b" or "a, b and c".
func joinWords(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// reversePaths holds what the routing table and the reverse-path filter of
// the kernel say about the sources of incoming packets.
type reversePaths struct {
	// via holds, for each interface, the sources whose best route leaves
	// through it; routed holds the sources that have a route at all.
	via    map[string]addrSet
	routed addrSet
}

// routedSources reads the routing table as the reverse-path filter does:
// the route with the longest prefix decides, and among routes for one
// destination the lowest metric.
func routedSources(host *models.HostContext) *reversePaths {
	if host == nil || !host.RoutesKnown {
		return nil
	}
	type entry struct {
		prefix netip.Prefix
		route  *models.Route
	}
	var entries []entry
	for i := range host.Routes {
		prefix, err := netip.ParsePrefix(host.Routes[i].Destination)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		entries = append(entries, entry{prefix.Masked(), &host.Routes[i]})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.prefix.Bits() != b.prefix.Bits() {
			return a.prefix.Bits() > b.prefix.Bits()
		}
		if a.prefix != b.prefix {
			return a.prefix.Addr().Less(b.prefix.Addr())
		}
		return a.route.Metric < b.route.Metric
	})
	paths := &reversePaths{via: map[string]addrSet{}}
	var assigned addrSet
	for i := 0; i < len(entries); {
		// The routes for one destination: those with the lowest metric count.
		j, devices := i, map[string]bool{}
		for ; j < len(entries) && entries[j].prefix == entries[i].prefix; j++ {
			if entries[j].route.Metric == entries[i].route.Metric {
				for _, device := range entries[j].route.Devices {
					devices[device] = true
				}
			}
		}
		network := setOfPrefix(entries[i].prefix)
		part := network.subtract(assigned)
		for device := range devices {
			paths.via[device] = paths.via[device].union(part)
		}
		if len(devices) > 0 {
			paths.routed = paths.routed.union(part)
		}
		assigned = assigned.union(network)
		i = j
	}
	return paths
}

// arriving returns the sources of the packets that the kernel accepts on an
// interface. With the reverse-path filter in strict mode (rp_filter 1) those
// are the sources whose route leaves through the interface; in loose mode
// (2) the sources that have a route. bounded is false when nothing limits
// the sources, or when the routes and the setting are not known.
func (e *inputEvaluator) arriving(iface string) (sources addrSet, bounded bool) {
	all := rootSet(e.rs.IPVersion)
	if e.rs.IPVersion != models.IPv4 || iface == "" || iface == otherInterface || iface == "lo" {
		return all, false
	}
	if !e.reverseRead {
		e.reverse, e.reverseRead = routedSources(e.host), true
	}
	if e.reverse == nil {
		return all, false
	}
	switch mode, known := hostinfo.InterfaceSetting(e.host, "rp_filter", iface); {
	case !known:
		return all, false
	case mode == "1":
		return e.reverse.via[iface], true
	case mode == "2":
		return e.reverse.routed, true
	}
	return all, false
}

// reversePathNotes says for which interfaces the reverse-path filter limits
// the sources, so that a narrow scope in the report can be understood.
func reversePathNotes(rs *models.Ruleset, host *models.HostContext) []string {
	if rs == nil || rs.IPVersion != models.IPv4 || host == nil || !host.RoutesKnown {
		return nil
	}
	e := newInputEvaluator(rs, host)
	var notes []string
	for _, candidate := range e.candidates {
		sources, bounded := e.arriving(candidate.name)
		if !bounded || sources.equal(rootSet(models.IPv4)) {
			continue
		}
		// The shorter of the two ways to say it: the networks that can
		// arrive, or all but the networks that cannot.
		list := func(set addrSet) []string {
			var networks []string
			for _, prefix := range set.prefixes() {
				networks = append(networks, prefix.String())
				if len(networks) == 5 {
					networks[4] = "more"
					break
				}
			}
			return networks
		}
		allowed, refused := sources.prefixes(), rootSet(models.IPv4).subtract(sources).prefixes()
		what := "to " + joinWords(list(sources))
		switch {
		case len(allowed) == 0:
			what = "to none"
		case len(refused) < len(allowed):
			what = "to all but " + joinWords(list(rootSet(models.IPv4).subtract(sources)))
		}
		setting, _ := hostinfo.InterfaceSetting(host, "rp_filter", candidate.name)
		notes = append(notes, fmt.Sprintf("IPv4: the reverse-path filter of the kernel (rp_filter is %s) limits the sources of packets that arrive on %s %s. "+
			"The scopes in this report take that into account.", setting, candidate.name, what))
	}
	return notes
}
