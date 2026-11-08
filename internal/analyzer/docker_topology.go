package analyzer

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// dockerTopology summarizes what a ruleset reveals about Docker networking.
// Everything is inferred from Docker's own rules so that saved rulesets can be
// analyzed without access to the host.
type dockerTopology struct {
	present         bool
	bridges         map[string]bool
	containerBridge map[netip.Addr]string
	subnetBridge    map[netip.Prefix]string
	rawProtected    map[netip.Addr]bool
	openBridges     map[string]*models.Rule // DOCKER: ! -i B -o B -j ACCEPT (gateway mode nat-unprotected)
	masqueraded     map[string]bool
	internal        map[string]bool
}

// DockerManaged reports whether Docker's iptables integration manages rs.
func DockerManaged(rs *models.Ruleset) bool {
	return inferDockerTopology(rs).present
}

// dockerOwnedChain reports whether Docker creates and rewrites the chain.
// DOCKER-USER is the only Docker chain reserved for user rules.
func dockerOwnedChain(name string) bool {
	return strings.HasPrefix(name, "DOCKER") && name != "DOCKER-USER"
}

func inferDockerTopology(rs *models.Ruleset) *dockerTopology {
	topo := &dockerTopology{
		bridges:         map[string]bool{},
		containerBridge: map[netip.Addr]string{},
		subnetBridge:    map[netip.Prefix]string{},
		rawProtected:    map[netip.Addr]bool{},
		openBridges:     map[string]*models.Rule{},
		masqueraded:     map[string]bool{},
		internal:        map[string]bool{},
	}
	if rs == nil {
		return topo
	}
	addBridge := func(name string) {
		if name != "" && name != "lo" && !strings.HasSuffix(name, "+") {
			topo.bridges[name] = true
		}
	}

	filter := rs.Tables["filter"]
	nat := rs.Tables["nat"]
	if filter != nil {
		for name, chain := range filter.Chains {
			if strings.HasPrefix(name, "DOCKER") {
				topo.present = true
			}
			if !dockerOwnedChain(name) {
				continue
			}
			for i := range chain.Rules {
				rule := &chain.Rules[i]
				addBridge(rule.InIface)
				addBridge(rule.OutIface)
			}
		}
	}
	if nat != nil {
		for name, chain := range nat.Chains {
			if !strings.HasPrefix(name, "DOCKER") {
				continue
			}
			topo.present = true
			for i := range chain.Rules {
				addBridge(chain.Rules[i].InIface)
			}
		}
		if postrouting := nat.Chains["POSTROUTING"]; postrouting != nil {
			for _, rule := range postrouting.Rules {
				if rule.Target != "MASQUERADE" || rule.OutIface == "" || !rule.Negations["out-iface"] || rule.SrcAddr == "" || rule.Negations["src"] {
					continue
				}
				if !topo.present && !dockerInterfaceName(rule.OutIface) {
					continue
				}
				if prefix, ok := parsePrefix(rule.SrcAddr); ok {
					addBridge(rule.OutIface)
					topo.subnetBridge[prefix] = rule.OutIface
					topo.masqueraded[rule.OutIface] = true
				}
			}
		}
	}
	for name := range topo.bridges {
		if !dockerInterfaceName(name) && !topo.present {
			delete(topo.bridges, name)
		}
	}

	if filter != nil {
		if docker := filter.Chains["DOCKER"]; docker != nil {
			for i := range docker.Rules {
				rule := &docker.Rules[i]
				if rule.OutIface == "" || rule.Negations["out-iface"] {
					continue
				}
				if prefix, ok := parsePrefix(rule.DstAddr); ok && prefix.IsSingleIP() && !rule.Negations["dst"] {
					topo.containerBridge[prefix.Addr()] = rule.OutIface
				}
				if rule.Target == "ACCEPT" && rule.InIface == rule.OutIface && rule.Negations["in-iface"] &&
					rule.DstAddr == "" && rule.DstPort == "" && (rule.Protocol == "" || rule.Protocol == models.ProtoAll) {
					topo.openBridges[rule.OutIface] = rule
				}
			}
		}
		if internal := filter.Chains["DOCKER-INTERNAL"]; internal != nil {
			for _, rule := range internal.Rules {
				if rule.OutIface != "" && rule.Negations["src"] {
					if prefix, ok := parsePrefix(rule.SrcAddr); ok {
						topo.subnetBridge[prefix] = rule.OutIface
						topo.internal[rule.OutIface] = true
					}
				}
			}
		}
	}

	if raw := rs.Tables["raw"]; raw != nil && raw.Chains["PREROUTING"] != nil {
		for _, rule := range raw.Chains["PREROUTING"].Rules {
			if rule.Target != "DROP" || !rule.Negations["in-iface"] || !topo.bridges[rule.InIface] || rule.Negations["dst"] {
				continue
			}
			if prefix, ok := parsePrefix(rule.DstAddr); ok && prefix.IsSingleIP() && rule.DstPort == "" {
				topo.containerBridge[prefix.Addr()] = rule.InIface
				topo.rawProtected[prefix.Addr()] = true
			}
		}
	}

	if nat != nil {
		for _, rule := range allDNATRules(nat) {
			translation, err := parseDNATTranslation(rule.DNATTarget)
			if err != nil {
				continue
			}
			addr, err := netip.ParseAddr(translation.Address)
			if err != nil || addr.IsLoopback() {
				continue
			}
			if _, known := topo.containerBridge[addr]; !known {
				topo.containerBridge[addr] = topo.bridgeForSubnet(addr)
			}
		}
	}
	return topo
}

func (t *dockerTopology) bridgeForSubnet(addr netip.Addr) string {
	best := ""
	bestBits := -1
	for prefix, bridge := range t.subnetBridge {
		if prefix.Contains(addr) && prefix.Bits() > bestBits {
			best, bestBits = bridge, prefix.Bits()
		}
	}
	return best
}

// bridgeFor returns the bridge that routes addr, or "" when unknown.
func (t *dockerTopology) bridgeFor(addr string) string {
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	if bridge := t.containerBridge[parsed]; bridge != "" {
		return bridge
	}
	return t.bridgeForSubnet(parsed)
}

// gatewayMode names the Docker bridge gateway mode suggested by the rules.
func (t *dockerTopology) gatewayMode(bridge string) string {
	switch {
	case t.internal[bridge]:
		return "internal"
	case t.openBridges[bridge] != nil:
		return "nat-unprotected"
	case !t.masqueraded[bridge]:
		return "routed"
	}
	return "nat"
}

func newEvalContext(rs *models.Ruleset, topo *dockerTopology, host *models.HostContext) *evalContext {
	ctx := &evalContext{bridges: map[string]bool{}, containerAddrs: map[netip.Addr]bool{}}
	for bridge := range topo.bridges {
		ctx.bridges[bridge] = true
	}
	for addr := range topo.containerBridge {
		ctx.containerAddrs[addr] = true
	}
	if host != nil && len(host.Interfaces) > 0 {
		ctx.localKnown = true
		for _, iface := range host.Interfaces {
			for _, value := range iface.Addrs {
				prefix, ok := parsePrefix(value)
				if !ok {
					continue
				}
				addr := prefix.Addr()
				if rs != nil && (rs.IPVersion == models.IPv6) != addr.Is6() {
					continue
				}
				ctx.localAddrs = append(ctx.localAddrs, addr)
			}
		}
	}
	return ctx
}

// ingressCandidate is one interface through which external traffic may arrive.
type ingressCandidate struct {
	name    string
	assumed bool // the interface's existence is not established by the input
}

func (c ingressCandidate) label() string {
	if c.name == otherInterface {
		return "other interfaces"
	}
	return c.name
}

// ingressCandidates lists the external interfaces to evaluate. In live mode
// the host's interfaces are used. For saved rules every interface a rule
// names is evaluated, plus one placeholder for interfaces no rule names.
func ingressCandidates(rs *models.Ruleset, ctx *evalContext, host *models.HostContext) []ingressCandidate {
	var candidates []ingressCandidate
	if host != nil && len(host.Interfaces) > 0 {
		for _, iface := range host.Interfaces {
			if iface.Name == "lo" || isBridgeInterface(iface.Name, ctx) {
				continue
			}
			candidates = append(candidates, ingressCandidate{name: iface.Name})
		}
		if len(candidates) > 0 {
			return candidates
		}
	}
	names := map[string]bool{}
	if rs != nil {
		for _, table := range rs.Tables {
			for _, chain := range table.Chains {
				for _, rule := range chain.Rules {
					name := rule.InIface
					if name == "" || name == "lo" || strings.HasSuffix(name, "+") || isBridgeInterface(name, ctx) {
						continue
					}
					names[name] = true
				}
			}
		}
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		candidates = append(candidates, ingressCandidate{name: name})
	}
	return append(candidates, ingressCandidate{name: otherInterface, assumed: len(sorted) > 0})
}

// candidateLabels renders the interfaces of a finding. A finding that holds
// for every candidate is reported without an interface list.
func candidateLabels(selected, all []ingressCandidate) []string {
	if len(selected) == len(all) {
		return nil
	}
	labels := make([]string, 0, len(selected))
	for _, candidate := range selected {
		labels = append(labels, candidate.label())
	}
	return labels
}

func onlyAssumed(selected []ingressCandidate) bool {
	if len(selected) == 0 {
		return false
	}
	for _, candidate := range selected {
		if !candidate.assumed {
			return false
		}
	}
	return true
}
