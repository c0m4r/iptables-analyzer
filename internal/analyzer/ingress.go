package analyzer

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The first packet of a connection from another host passes raw and mangle
// PREROUTING and then nat/PREROUTING, which can give it a new destination.
// The destination selects the hook that follows: INPUT for this host, FORWARD
// for another one. The functions in this file follow that way. The survey of
// open ports, the listening sockets and the translated ports all use them, so
// that a Docker published port, a NodePort of kube-proxy, a port forward and
// a REDIRECT are read by the same code.

// balancedShare is the condition of a rule that takes a random share of the
// packets. In the nat table that is load balancing: every source reaches one
// of the destinations, so it does not limit who reaches the port.
const balancedShare = "random share of packets"

// portClass is a range of destination ports that every rule treats alike.
type portClass struct {
	first, last int
	// named: a rule on the way to a local socket names these ports, so they
	// are evaluated by themselves.
	named bool
	// inputNamed: one of those rules is outside the nat table. A port that
	// only a rule of nat/PREROUTING names, and that the rule leaves alone,
	// arrives at INPUT like a port that no rule names.
	inputNamed bool
	// natNamed: a rule in raw, mangle or nat PREROUTING names these ports.
	// The ports that none of them names take the same way through those
	// hooks, so one traversal stands for all of them.
	natNamed bool
}

// reachableChains adds the chain and every chain that its rules jump to.
func reachableChains(table *models.Table, name string, reached map[string]*models.Chain) {
	chain := table.Chains[name]
	key := table.Name + "/" + name
	if chain == nil || reached[key] != nil {
		return
	}
	reached[key] = chain
	for i := range chain.Rules {
		if _, isChain := table.Chains[chain.Rules[i].Target]; isChain {
			reachableChains(table, chain.Rules[i].Target, reached)
		}
	}
}

// preroutingChains returns the chains that a packet from another host can
// pass before the routing decision, keyed by "table/chain".
func preroutingChains(rs *models.Ruleset) map[string]*models.Chain {
	reached := map[string]*models.Chain{}
	for _, name := range []string{"raw", "mangle", "nat"} {
		if table := rs.Tables[name]; table != nil {
			reachableChains(table, "PREROUTING", reached)
		}
	}
	return reached
}

// appliesTo reports whether a rule can match packets of the protocol.
func appliesTo(rule *models.Rule, protocol models.Protocol) bool {
	other := normalizeProtocol(rule.Protocol)
	if other == "" || other == models.ProtoAll {
		return !rule.Negations["protocol"]
	}
	return (other == protocol) != rule.Negations["protocol"]
}

// portSpecs returns the destination-port predicates of a rule.
func portSpecs(rule *models.Rule) []string {
	var specs []string
	if rule.DstPort != "" {
		specs = append(specs, rule.DstPort)
	}
	for _, ext := range rule.Matches {
		for _, key := range []string{"--ctorigdstport", "--ports"} {
			if value := ext.Params[key]; value != "" {
				specs = append(specs, value)
			}
		}
	}
	return specs
}

// maxSplitPorts bounds the ports of one rule that become classes of their
// own because the rule maps a range of ports to another range.
const maxSplitPorts = 4096

// classes divides the ports 1-65535 of one protocol at every boundary of a
// port predicate in the rules.
func (e *inputEvaluator) classes(protocol models.Protocol) []portClass {
	if cached, ok := e.classCache[protocol]; ok {
		return cached
	}
	starts := map[int]bool{1: true}
	cut := func(lo, hi int) bool {
		lo, hi = max(lo, 1), min(hi, 65535)
		if lo > hi {
			return false
		}
		starts[lo] = true
		if hi < 65535 {
			starts[hi+1] = true
		}
		return true
	}
	input, before := inputChains(e.rs), preroutingChains(e.rs)
	var named, inputNamed, natNamed [][2]int
	for _, table := range e.rs.Tables {
		for name, chain := range table.Chains {
			key := table.Name + "/" + name
			for i := range chain.Rules {
				rule := &chain.Rules[i]
				if !appliesTo(rule, protocol) {
					continue
				}
				for _, spec := range portSpecs(rule) {
					for _, r := range cachedPortRanges(spec) {
						if !cut(r[0], r[1]) {
							continue
						}
						ports := [2]int{max(r[0], 1), min(r[1], 65535)}
						if input[key] != nil {
							inputNamed = append(inputNamed, ports)
						}
						if before[key] != nil {
							natNamed = append(natNamed, ports)
						}
						if input[key] != nil || before[key] != nil {
							named = append(named, ports)
						}
					}
				}
				// A rule that maps a range of ports to another range gives every
				// port its own destination port.
				if translates(table, rule) && rangedTarget(rule) && rule.DstPort != "" && !rule.Negations["dport"] {
					if ports := portsInSpec(rule.DstPort); len(ports) <= maxSplitPorts {
						for _, port := range ports {
							cut(port, port)
						}
					}
				}
			}
		}
	}
	sorted := make([]int, 0, len(starts))
	for start := range starts {
		sorted = append(sorted, start)
	}
	sort.Ints(sorted)
	covered := func(ranges [][2]int) func(int) bool {
		sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
		// Merge the ranges, so that a class is found with one search.
		var merged [][2]int
		for _, r := range ranges {
			if n := len(merged); n > 0 && r[0] <= merged[n-1][1]+1 {
				merged[n-1][1] = max(merged[n-1][1], r[1])
				continue
			}
			merged = append(merged, r)
		}
		return func(port int) bool {
			i := sort.Search(len(merged), func(i int) bool { return merged[i][1] >= port })
			return i < len(merged) && merged[i][0] <= port
		}
	}
	isNamed, isInputNamed, isNATNamed := covered(named), covered(inputNamed), covered(natNamed)
	classes := make([]portClass, len(sorted))
	for i, start := range sorted {
		classes[i] = portClass{first: start, last: 65535, named: isNamed(start), inputNamed: isInputNamed(start), natNamed: isNATNamed(start)}
		if i+1 < len(sorted) {
			classes[i].last = sorted[i+1] - 1
		}
	}
	e.classCache[protocol] = classes
	return classes
}

// classOf returns the class that holds a port.
func (e *inputEvaluator) classOf(protocol models.Protocol, port int) portClass {
	classes := e.classes(protocol)
	i := sort.Search(len(classes), func(i int) bool { return classes[i].last >= port })
	if i < len(classes) && classes[i].first <= port {
		return classes[i]
	}
	return portClass{first: port, last: port, named: true, inputNamed: true, natNamed: true}
}

// rangedTarget reports whether a DNAT or REDIRECT rule names more than one
// new port.
func rangedTarget(rule *models.Rule) bool {
	switch rule.Target {
	case "DNAT":
		translation, err := parseDNATTranslation(rule.DNATTarget)
		return err == nil && translation.HasPort && translation.PortEnd > translation.PortStart
	case "REDIRECT":
		lo, hi, ok := redirectPorts(rule)
		return ok && hi > lo
	}
	return false
}

// redirectPorts returns the ports of "--to-ports N" or "--to-ports N-M".
// ok is false when the rule keeps the port.
func redirectPorts(rule *models.Rule) (lo, hi int, ok bool) {
	for i := 0; i+1 < len(rule.TargetArgs); i++ {
		if rule.TargetArgs[i] != "--to-ports" {
			continue
		}
		ports := portsInSpec(strings.ReplaceAll(rule.TargetArgs[i+1], "-", ":"))
		if len(ports) == 0 {
			return 0, 0, false
		}
		return ports[0], ports[len(ports)-1], true
	}
	return 0, 0, false
}

// namedDestination is a single address that rules of nat/PREROUTING name as
// the destination of a packet. The rules are evaluated for it by itself.
type namedDestination struct {
	addr netip.Addr
	// ranges holds the ports that the rules name together with the address;
	// all is true when one of them names no port.
	ranges [][2]int
	all    bool
}

func (d *namedDestination) names(class portClass) bool {
	if d.all {
		return true
	}
	for _, r := range d.ranges {
		if r[0] <= class.first && class.first <= r[1] {
			return true
		}
	}
	return false
}

// clusterPortal reports whether a rule of kube-proxy sends a cluster IP to
// its service. A cluster IP is no address of the node: only hosts that route
// the service network through this node reach it.
func clusterPortal(rule *models.Rule) bool {
	return rule.Chain == "KUBE-SERVICES" && strings.HasPrefix(rule.Target, "KUBE-SVC-")
}

// nameDestinations finds the single addresses that the rules of
// nat/PREROUTING name. All of them are kept in ctx.natNamed; those that can
// be an address of this host are returned for evaluation.
func (e *inputEvaluator) nameDestinations() {
	nat := e.rs.Tables["nat"]
	if nat == nil {
		return
	}
	chains := map[string]*models.Chain{}
	reachableChains(nat, "PREROUTING", chains)
	found := map[netip.Addr]*namedDestination{}
	skipped := map[netip.Addr]bool{}
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		chain := chains[name]
		for i := range chain.Rules {
			rule := &chain.Rules[i]
			prefix, ok := parsePrefix(rule.DstAddr)
			if !ok || !prefix.IsSingleIP() || rule.Negations["dst"] || prefix.Addr().Is6() != (e.rs.IPVersion == models.IPv6) {
				continue
			}
			addr := prefix.Addr()
			if e.ctx.natNamed == nil {
				e.ctx.natNamed = map[netip.Addr]bool{}
			}
			e.ctx.natNamed[addr] = true
			if clusterPortal(rule) {
				skipped[addr] = true
				e.clusterIPs++
			}
			dest := found[addr]
			if dest == nil {
				dest = &namedDestination{addr: addr}
				found[addr] = dest
			}
			if rule.DstPort == "" || rule.Negations["dport"] {
				dest.all = true
				continue
			}
			for _, r := range cachedPortRanges(rule.DstPort) {
				dest.ranges = append(dest.ranges, [2]int{r[0], r[1]})
			}
		}
	}
	for addr, dest := range found {
		// Packets from other hosts for a loopback address are dropped, and the
		// address of a container is not an address of this host.
		if skipped[addr] || addr.IsLoopback() || e.ctx.containerAddrs[addr] {
			continue
		}
		e.named = append(e.named, *dest)
	}
	sort.Slice(e.named, func(i, j int) bool { return e.named[i].addr.Less(e.named[j].addr) })
}

// egress returns the interface through which the host sends packets to an
// address: the bridge that the rules show for it, or the interface of the
// host whose network holds the address. It is empty when neither tells.
func (e *inputEvaluator) egress(address string) string {
	if bridge := e.topo.bridgeFor(address); bridge != "" {
		return bridge
	}
	addr, err := netip.ParseAddr(address)
	if err != nil || e.host == nil {
		return ""
	}
	best, bits := "", -1
	for _, iface := range e.host.Interfaces {
		for _, value := range iface.Addrs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				continue
			}
			if network := prefix.Masked(); network.Contains(addr) && network.Bits() > bits && network.Bits() < addr.BitLen() {
				best, bits = iface.Name, network.Bits()
			}
		}
	}
	return best
}

// isLocal reports whether an address is known to be one of this host.
func (e *inputEvaluator) isLocal(addr netip.Addr) (local, known bool) {
	if !e.ctx.localKnown {
		return false, false
	}
	for _, own := range e.ctx.localAddrs {
		if own == addr {
			return true, true
		}
	}
	return false, true
}

// wildcardAddress reports whether an address stands for every local address.
func wildcardAddress(address string) bool {
	switch address {
	case "", "0.0.0.0", "::", "*":
		return true
	}
	return false
}

// newConnection is the first packet of a connection from another host to a
// local port. address is the local address, or the wildcard address.
func (e *inputEvaluator) newConnection(protocol models.Protocol, port int, address string) packetQuery {
	query := packetQuery{
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
	if !wildcardAddress(address) {
		// An address that is known not to be one of this host is reached only
		// when another host routes it here.
		if addr, err := netip.ParseAddr(strings.Split(address, "%")[0]); err == nil {
			if local, known := e.isLocal(addr); known && !local {
				query.DstType = "UNICAST"
			}
		}
	}
	return query
}

// natBranch is a part of the traffic of a query behind nat/PREROUTING: the
// sources that one rule gives a new destination, or the sources that keep
// theirs.
type natBranch struct {
	rule     *models.Rule // the translating rule; nil when the destination stays
	segments []decisionSegment
}

// natKey identifies the traversals of PREROUTING that have the same result.
type natKey struct {
	protocol models.Protocol
	port     int // 0 for the ports that no rule in PREROUTING names
	dstAddr  string
	dstType  string
	iface    string
}

// prerouting follows a new connection through raw, mangle and nat PREROUTING
// and returns what is left of it, divided by what the nat table did.
func (e *inputEvaluator) prerouting(query packetQuery) []natBranch {
	key := natKey{protocol: normalizeProtocol(query.Protocol), dstAddr: query.DstAddr, dstType: query.DstType, iface: query.InIface}
	if e.classOf(key.protocol, query.DstPort).natNamed {
		key.port = query.DstPort
	}
	if cached, ok := e.natCache[key]; ok {
		return cached
	}
	branches := e.walkPrerouting(query)
	e.natCache[key] = branches
	return branches
}

func (e *inputEvaluator) walkPrerouting(query packetQuery) []natBranch {
	// The kernel tests the reverse path behind PREROUTING. It tests only the
	// source, which no rule changes, so the sources are limited from the start.
	sources, _ := e.arriving(query.InIface)
	pre := evaluatePath(e.rs, preroutingPath(query), sources)
	if len(pre.Accepted) == 0 {
		return nil
	}
	nat := e.rs.Tables["nat"]
	if nat == nil || nat.Chains["PREROUTING"] == nil {
		return []natBranch{{segments: pre.Accepted}}
	}
	natQuery := query
	natQuery.Chain, natQuery.Hook = "PREROUTING", "PREROUTING"
	// The addresses that the nat rules name are evaluated one by one, so the
	// wildcard address stands for the other local addresses here. That keeps
	// a translation for one address from being reported for all of them.
	natQuery.DstOther = wildcardAddress(query.DstAddr)
	evaluation := evaluateChain(nat, "PREROUTING", flow{set: pre.acceptedSet()}, natQuery, newChainWalk(natQuery))

	// A rule that accepts in the nat table ends the traversal of that table:
	// the packet keeps its destination, and the filter table judges it.
	var kept []decisionSegment
	for _, segment := range evaluation.Accepted {
		segment.Rule = nil
		kept = append(kept, segment)
	}
	for _, returned := range evaluation.Returned {
		kept = append(kept, flowSegments(returned, nil)...)
	}
	var branches []natBranch
	if kept = inheritAttribution(kept, pre.Accepted); len(kept) > 0 {
		branches = append(branches, natBranch{segments: kept})
	}
	position := map[*models.Rule]int{}
	for _, segment := range evaluation.Translated {
		rule := segment.Rule
		segment.Rule = nil
		segment.Condition = withoutLabel(segment.Condition, balancedShare)
		at, known := position[rule]
		if !known {
			at = len(branches)
			position[rule] = at
			branches = append(branches, natBranch{rule: rule})
		}
		branches[at].segments = append(branches[at].segments, segment)
	}
	for i := range branches {
		if branches[i].rule != nil {
			branches[i].segments = inheritAttribution(branches[i].segments, pre.Accepted)
		}
	}
	return branches
}

// withoutLabel removes one condition from a list of conditions.
func withoutLabel(conditions, label string) string {
	if !strings.Contains(conditions, label) {
		return conditions
	}
	var kept []string
	for _, condition := range strings.Split(conditions, ", ") {
		if condition != label {
			kept = append(kept, condition)
		}
	}
	return strings.Join(kept, ", ")
}

// translation is the new destination that a rule of nat/PREROUTING gives to
// the ports of a class.
type translation struct {
	// local: the new destination is this host, so INPUT judges the packet.
	local bool
	// addr is the new address. It is empty for REDIRECT, which uses the
	// address of the ingress interface.
	addr string
	// port and portEnd are the new ports of the first and the last port.
	port, portEnd int
	// keepsPort: the rule names no new port.
	keepsPort bool
	// uncertain: the packet is delivered only under a condition that the
	// rules do not show (route_localnet for a loopback destination).
	uncertain bool
}

// translate returns the new destination that rule gives to the ports of a
// class of the query. ok is false when the packets do not arrive anywhere
// that the analysis can follow.
func (e *inputEvaluator) translate(rule *models.Rule, query packetQuery, class portClass) (result translation, ok bool) {
	// mapped returns the new ports for a target that names the ports lo-hi.
	mapped := func(lo, hi int) (int, int, bool) {
		if lo == hi {
			return lo, lo, true
		}
		// A range: the ports of the rule are taken to map in order.
		first := class.first
		if rule.DstPort != "" && !rule.Negations["dport"] {
			if ports := portsInSpec(rule.DstPort); len(ports) > 0 {
				first = ports[0]
			}
		}
		port := lo + class.first - first
		if port < lo || port > hi {
			return 0, 0, false
		}
		return port, min(hi, port+class.last-class.first), true
	}
	result.port, result.portEnd, result.keepsPort = class.first, class.last, true
	switch rule.Target {
	case "REDIRECT":
		result.local = true
		if lo, hi, named := redirectPorts(rule); named {
			result.keepsPort = false
			if result.port, result.portEnd, ok = mapped(lo, hi); !ok {
				return result, false
			}
		}
		return result, true
	case "DNAT":
		target, err := parseDNATTranslation(rule.DNATTarget)
		if err != nil {
			return result, false
		}
		if target.HasPort {
			result.keepsPort = false
			if result.port, result.portEnd, ok = mapped(target.PortStart, target.PortEnd); !ok {
				return result, false
			}
		}
		addr, err := netip.ParseAddr(target.Address)
		if err != nil {
			return result, false
		}
		result.addr = addr.String()
		switch local, known := e.isLocal(addr); {
		case addr.IsLoopback():
			// The kernel drops packets from other hosts for a loopback address
			// unless route_localnet is set, which exists for IPv4 only.
			routed, settled := e.localnetRouted(query.InIface)
			if addr.Is6() || (settled && !routed) {
				return result, false
			}
			result.local, result.uncertain = true, !settled
		case known:
			result.local = local
		default:
			// Saved rules do not tell the addresses of the host. A rule that
			// sends an address to itself changes the port only.
			result.local = result.addr == strings.Split(query.DstAddr, "%")[0]
			if prefix, parsed := parsePrefix(rule.DstAddr); parsed && prefix.IsSingleIP() && !rule.Negations["dst"] {
				result.local = result.local || prefix.Addr() == addr
			}
		}
		return result, true
	}
	return result, false
}

// ingressWay is one way of the packets of a query behind PREROUTING.
type ingressWay struct {
	rule *models.Rule // the rule of nat/PREROUTING that translated them; nil when none did
	translation
	// entry holds the sources on this way, with what PREROUTING established.
	entry []decisionSegment
	// query is the packet as the next hook sees it.
	query packetQuery
}

// ways returns where the packets of a new connection go behind PREROUTING.
// class holds the ports that the query stands for.
func (e *inputEvaluator) ways(query packetQuery, class portClass) []ingressWay {
	var ways []ingressWay
	for _, branch := range e.prerouting(query) {
		if branch.rule == nil {
			ways = append(ways, ingressWay{
				translation: translation{local: query.DstType != "UNICAST", port: class.first, portEnd: class.last, keepsPort: true},
				entry:       branch.segments, query: query,
			})
			continue
		}
		target, ok := e.translate(branch.rule, query, class)
		if !ok {
			continue
		}
		way := ingressWay{rule: branch.rule, translation: target, entry: branch.segments, query: query}
		way.query.DstPort = target.port
		way.query.DstAddr = target.addr
		way.query.NATState = "DNAT"
		if target.local {
			way.query.DstType = "LOCAL"
		} else {
			way.query.DstType = "UNICAST"
			way.query.OutIface = e.egress(target.addr)
		}
		if target.uncertain {
			way.entry = make([]decisionSegment, len(branch.segments))
			for i, segment := range branch.segments {
				segment.Possible = true
				way.entry[i] = segment
			}
		}
		ways = append(ways, way)
	}
	return ways
}

// deliver returns what the chains of INPUT decide for a way that ends at
// this host.
func (e *inputEvaluator) deliver(way ingressWay) pathResult {
	return evaluatePathFrom(e.rs, inputPath(way.query)[2:], way.entry)
}

// forward returns what the chains of FORWARD decide for a way that leads to
// another host.
func (e *inputEvaluator) forward(way ingressWay) pathResult {
	return evaluatePathFrom(e.rs, forwardPath(way.query), way.entry)
}

// direct returns what the rules decide for the packets of a query that
// arrive at the port of the query itself: those that nat/PREROUTING leaves
// alone, and those whose new destination is the same port of this host.
func (e *inputEvaluator) direct(query packetQuery) pathResult {
	var result pathResult
	port := portClass{first: query.DstPort, last: query.DstPort}
	for _, way := range e.ways(query, port) {
		if !way.local || way.port != query.DstPort {
			continue
		}
		path := e.deliver(way)
		result.Accepted = append(result.Accepted, path.Accepted...)
		result.Dropped = append(result.Dropped, path.Dropped...)
		result.Uncertain = result.Uncertain || path.Uncertain
	}
	return result
}
