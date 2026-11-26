package report

import (
	"sort"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// openPorts lists the ports for which INPUT accepts new connections. Entries
// that are the same for IPv4 and IPv6 are one entry, and the ports that no
// rule names are one entry for each protocol, next to those of them on which
// a service listens.
func (b *builder) openPorts() []OpenPort {
	// What accepts the ports that no rule names, for each family and protocol.
	byDefault := map[stackProtocol]*models.OpenPort{}
	for i := range b.result.OpenPorts {
		if open := &b.result.OpenPorts[i]; open.Unnamed {
			byDefault[stackProtocol{open.IPVersion, open.Protocol}] = open
		}
	}
	ports := []OpenPort{}
	add := func(entry OpenPort) {
		for j := range ports {
			other := &ports[j]
			if other.Protocol != entry.Protocol || other.First != entry.First || other.Last != entry.Last ||
				other.Scope != entry.Scope || other.Certainty != entry.Certainty || other.Condition != entry.Condition ||
				other.Restriction != entry.Restriction || other.Default != entry.Default ||
				strings.Join(other.Interfaces, ",") != strings.Join(entry.Interfaces, ",") {
				continue
			}
			if !containsInt(other.Families, entry.Families[0]) {
				other.Families = append(other.Families, entry.Families[0])
				other.Rules = append(other.Rules, entry.Rules...)
			}
			for _, name := range entry.Listeners {
				if !containsString(other.Listeners, name) {
					other.Listeners = append(other.Listeners, name)
				}
			}
			return
		}
		ports = append(ports, entry)
	}
	for i := range b.result.OpenPorts {
		source := &b.result.OpenPorts[i]
		if usual := byDefault[stackProtocol{source.IPVersion, source.Protocol}]; usual != nil && !source.Unnamed &&
			sameRule(usual.Rule, source.Rule) && usual.Scope == source.Scope && usual.Certainty == source.Certainty &&
			usual.Condition == source.Condition && len(b.listeners(source)) == 0 {
			continue // open like every port that no rule names, and not in use: the default entry says it
		}
		entry := OpenPort{
			Families:    []int{int(source.IPVersion)},
			Protocol:    string(source.Protocol),
			First:       source.First,
			Last:        source.Last,
			Scope:       source.Scope,
			Certainty:   source.Certainty,
			Condition:   source.Condition,
			Restriction: source.Restriction,
			Interfaces:  source.Interfaces,
			Default:     source.Unnamed,
		}
		if source.Unnamed {
			// One probe stands for every port that no rule names.
			entry.First, entry.Last = 0, 0
		} else {
			entry.Public = b.declaredPublic(source.Protocol, source.First, source.Last)
			entry.Listeners = b.listeners(source)
		}
		if source.Rule != nil {
			entry.Rules = []RuleRef{b.ref(source.Rule, "accepts")}
		}
		add(entry)
	}
	// A service on a port that no rule names is reachable like the default
	// says. It gets its own entry, so that the list shows what is in use.
	for i := range b.result.ExposedServices {
		exposed := &b.result.ExposedServices[i]
		svc := exposed.Service
		named := false
		for j := range b.result.OpenPorts {
			open := &b.result.OpenPorts[j]
			named = named || (!open.Unnamed && open.IPVersion == exposed.IPVersion && open.Protocol == svc.Protocol &&
				open.First <= svc.Port && svc.Port <= open.Last)
		}
		if named {
			continue
		}
		name := svc.Process
		if name == "" {
			name = "unknown process"
		}
		entry := OpenPort{
			Families:   []int{int(exposed.IPVersion)},
			Protocol:   string(svc.Protocol),
			First:      svc.Port,
			Last:       svc.Port,
			Scope:      exposed.Scope,
			Certainty:  exposed.Certainty,
			Condition:  exposed.Condition,
			Interfaces: exposed.Interfaces,
			Listeners:  []string{name},
			Public:     b.declaredPublic(svc.Protocol, svc.Port, svc.Port),
		}
		if exposed.AllowingRule != nil {
			entry.Rules = []RuleRef{b.ref(exposed.AllowingRule, "accepts")}
		}
		add(entry)
	}
	sort.SliceStable(ports, func(i, j int) bool {
		a, c := ports[i], ports[j]
		if a.Protocol != c.Protocol {
			return a.Protocol < c.Protocol
		}
		if a.Default != c.Default {
			return !a.Default
		}
		return a.First < c.First
	})
	return ports
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// listeners names the processes that listen on the ports of an entry and
// that other hosts could reach there.
func (b *builder) listeners(open *models.OpenPort) []string {
	var names []string
	for _, svc := range b.result.Services {
		if svc.Protocol != open.Protocol || svc.Port < open.First || svc.Port > open.Last || svc.Status == models.ServiceLocalhost {
			continue
		}
		switch {
		case svc.Family == models.SocketDual:
		case open.IPVersion == models.IPv6:
			if svc.Family != models.SocketIPv6 && !svc.IsIPv6 {
				continue
			}
		case svc.Family == models.SocketIPv6 || svc.IsIPv6:
			continue
		}
		name := svc.Process
		if name == "" {
			name = "unknown process"
		}
		if !containsString(names, name) {
			names = append(names, name)
		}
	}
	return names
}

// forwards lists the ports that nat/PREROUTING translates to another host.
func (b *builder) forwards() []Forward {
	forwards := []Forward{}
	for _, group := range analyzer.GroupPublishedPorts(b.result.PublishedPorts) {
		rule := group.NATRule
		forwards = append(forwards, Forward{
			Family:       int(group.IPVersion),
			Protocol:     string(group.Protocol),
			HostAddr:     group.HostAddr,
			HostPort:     group.HostPort,
			HostPortEnd:  group.HostPortEnd,
			DestAddr:     group.ContainerAddr,
			DestPort:     group.ContainerPort,
			DestPortEnd:  group.ContainerPortEnd,
			Bridge:       group.Bridge,
			Docker:       analyzer.IsDockerRule(&rule),
			ForwardScope: group.ForwardScope,
			InputScope:   group.InputScope,
			Certainty:    group.Certainty,
			Interfaces:   group.Interfaces,
			Rule:         b.ref(&rule, "translates"),
		})
	}
	return forwards
}

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

// services lists the listening sockets with the widest scope that reaches
// each of them.
func (b *builder) services() []Service {
	services := []Service{}
	for _, svc := range b.result.Services {
		entry := Service{
			Protocol:  string(svc.Protocol),
			Address:   svc.Address,
			Device:    svc.Device,
			Port:      svc.Port,
			Process:   svc.Process,
			PID:       svc.PID,
			Processes: svc.Processes,
			Socket:    svc.Family,
			Status:    svc.Status,
		}
		switch svc.Status {
		case models.ServiceReachable:
			for _, exposed := range b.result.ExposedServices {
				found := exposed.Service
				sameAddress := svc.Address == found.Address
				if svc.Family == models.SocketDual || svc.IsWildcard {
					sameAddress = found.IsWildcard || found.Address == "0.0.0.0" || found.Address == "::"
				}
				if found.Port == svc.Port && found.Protocol == svc.Protocol && sameAddress && scopeRank(exposed.Scope) > scopeRank(entry.Scope) {
					entry.Scope = exposed.Scope
				}
			}
		case models.ServiceDocker:
			for _, mapping := range b.result.PublishedPorts {
				if mapping.Protocol == svc.Protocol && mapping.HostPort == svc.Port && scopeRank(mapping.ForwardScope) > scopeRank(entry.Scope) {
					entry.Scope = mapping.ForwardScope
				}
			}
		}
		services = append(services, entry)
	}
	return services
}

var tableOrder = map[string]int{"filter": 0, "nat": 1, "mangle": 2, "raw": 3, "security": 4}
var chainOrder = map[string]int{"PREROUTING": 0, "INPUT": 1, "FORWARD": 2, "OUTPUT": 3, "POSTROUTING": 4}

// rulesets returns the rules of the input for display, each with the
// findings that name it.
func (b *builder) rulesets(findings []Finding) []Ruleset {
	type ruleKey struct {
		family       int
		table, chain string
		num          int
	}
	named := map[ruleKey][]string{}
	for _, finding := range findings {
		for _, ref := range finding.Rules {
			key := ruleKey{ref.Family, ref.Table, ref.Chain, ref.Num}
			if !containsString(named[key], finding.ID) {
				named[key] = append(named[key], finding.ID)
			}
		}
	}

	var rulesets []Ruleset
	for _, version := range []models.IPVersion{models.IPv4, models.IPv6} {
		rs := b.ruleset(version)
		if rs == nil || len(rs.Tables) == 0 {
			continue
		}
		ruleset := Ruleset{Family: int(version)}
		tableNames := make([]string, 0, len(rs.Tables))
		for name := range rs.Tables {
			tableNames = append(tableNames, name)
		}
		sort.Slice(tableNames, func(i, j int) bool { return ordered(tableOrder, tableNames[i], tableNames[j]) })
		for _, tableName := range tableNames {
			source := rs.Tables[tableName]
			table := Table{Name: tableName}
			chainNames := make([]string, 0, len(source.Chains))
			for name := range source.Chains {
				chainNames = append(chainNames, name)
			}
			sort.Slice(chainNames, func(i, j int) bool {
				a, c := source.Chains[chainNames[i]], source.Chains[chainNames[j]]
				if (a.Policy != "") != (c.Policy != "") {
					return a.Policy != "" // built-in chains first
				}
				return ordered(chainOrder, chainNames[i], chainNames[j])
			})
			for _, chainName := range chainNames {
				chain := source.Chains[chainName]
				entry := Chain{Name: chainName, Policy: chain.Policy, Owner: chainOwner(chainName), Rules: make([]Rule, 0, len(chain.Rules))}
				for i := range chain.Rules {
					rule := &chain.Rules[i]
					_, jump := source.Chains[rule.Target]
					entry.Rules = append(entry.Rules, Rule{
						Num:      rule.RuleNum,
						Spec:     analyzer.RuleSpec(rule),
						Target:   rule.Target,
						Jump:     jump,
						Findings: named[ruleKey{int(version), tableName, chainName, rule.RuleNum}],
					})
				}
				table.Chains = append(table.Chains, entry)
			}
			ruleset.Tables = append(ruleset.Tables, table)
		}
		rulesets = append(rulesets, ruleset)
	}
	return rulesets
}

// ordered sorts names with a known position first, then by name.
func ordered(position map[string]int, a, b string) bool {
	pa, okA := position[a]
	pb, okB := position[b]
	switch {
	case okA && okB:
		return pa < pb
	case okA != okB:
		return okA
	}
	return a < b
}
