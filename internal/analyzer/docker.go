package analyzer

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// DetectDockerBypasses finds INPUT rules that are bypassed by Docker NAT rules
func DetectDockerBypasses(rs *models.Ruleset) []models.DockerBypassFinding {
	if rs == nil {
		return nil
	}

	var findings []models.DockerBypassFinding

	// Collect DNAT rules from nat table
	dnatRules := collectDNATRules(rs)
	if len(dnatRules) == 0 {
		return nil
	}

	// seen tracks (exposedPort → containerDest) pairs already reported
	seen := make(map[string]bool)

	for _, reachable := range dnatRules {
		dnat := reachable.Rule
		dnatPort := dnat.DstPort
		if dnatPort == "" {
			continue
		}
		containerDest := dnat.DNATTarget
		if containerDest == "" {
			continue
		}
		if isLoopback(dnat.DstAddr) {
			continue
		}

		containerIP, containerPort := ParseDNATTarget(containerDest)
		if containerPort == 0 {
			containerPort = firstPort(dnatPort)
		}
		if containerPort == 0 {
			continue
		}

		portKey := string(dnat.Protocol) + ":" + dnatPort + "→" + containerDest
		if seen[portKey] {
			continue
		}

		forwardScope, _, _ := evaluateAccessFrom(rs, "FORWARD", packetQuery{
			Protocol: dnat.Protocol,
			DstPort:  containerPort,
			DstAddr:  containerIP,
			State:    "NEW",
			External: true,
		}, reachable.Sources)
		if forwardScope != models.ScopeExposed {
			continue
		}

		hostPort := firstPort(dnatPort)
		inputScope, _, inputDrop := evaluateAccessFrom(rs, "INPUT", packetQuery{
			Protocol: dnat.Protocol,
			DstPort:  hostPort,
			DstAddr:  dnat.DstAddr,
			State:    "NEW",
			External: true,
		}, reachable.Sources)

		finding := models.DockerBypassFinding{
			NATRule:       dnat,
			ExposedPort:   dnatPort,
			ContainerDest: containerDest,
			Severity:      models.SeverityHigh,
			Reason: "Docker DNAT exposes port " + dnatPort + " -> " + containerDest +
				" to unrestricted sources through filter/FORWARD. Restrict the original " +
				"destination in DOCKER-USER with the conntrack match.",
		}
		if inputScope != models.ScopeExposed {
			finding.Severity = models.SeverityCritical
			finding.Reason = "Port " + dnatPort + " is restricted by filter/INPUT, but DNAT in " +
				dnat.Table + "/" + dnat.Chain + " redirects traffic to " + containerDest +
				" through FORWARD, where it remains reachable from unrestricted sources."
			if inputDrop != nil {
				finding.InputRule = *inputDrop
			}
		}
		findings = append(findings, finding)
		seen[portKey] = true
	}

	return findings
}

type reachableDNATRule struct {
	Rule    models.Rule
	Sources []netip.Prefix
}

func collectDNATRules(rs *models.Ruleset) []reachableDNATRule {
	var rules []reachableDNATRule

	natTable, ok := rs.Tables["nat"]
	if !ok {
		return rules
	}

	if _, ok := natTable.Chains["PREROUTING"]; !ok {
		return rules
	}
	root := netip.MustParsePrefix("0.0.0.0/0")
	if rs.IPVersion == models.IPv6 {
		root = netip.MustParsePrefix("::/0")
	}
	walkReachableNATChain(natTable, "PREROUTING", []netip.Prefix{root}, map[string]bool{}, &rules)

	return rules
}

func walkReachableNATChain(table *models.Table, chainName string, sources []netip.Prefix, path map[string]bool, rules *[]reachableDNATRule) {
	if path[chainName] {
		return
	}
	chain, ok := table.Chains[chainName]
	if !ok {
		return
	}
	path[chainName] = true
	defer delete(path, chainName)
	for _, rule := range chain.Rules {
		if (!rule.Negations["dst"] && isLoopback(rule.DstAddr)) ||
			(!rule.Negations["in-iface"] && rule.InIface == "lo") {
			continue
		}
		matchedSources, _, known := splitBySource(sources, &rule)
		if !known {
			matchedSources = sources
		}
		if len(matchedSources) == 0 {
			continue
		}
		if rule.Target == "DNAT" && rule.DNATTarget != "" {
			*rules = append(*rules, reachableDNATRule{Rule: rule, Sources: matchedSources})
		}
		if _, isChain := table.Chains[rule.Target]; isChain {
			walkReachableNATChain(table, rule.Target, matchedSources, path, rules)
		}
		if rule.IsTerminal() && IsCatchAll(&rule) {
			return
		}
	}
}

// ParseDNATTarget parses "ip:port" from --to-destination value
func ParseDNATTarget(target string) (string, int) {
	if host, portText, err := net.SplitHostPort(target); err == nil {
		port, _ := strconv.Atoi(strings.Split(portText, "-")[0])
		return host, port
	}
	parts := strings.Split(target, ":")
	if len(parts) >= 2 {
		port, _ := strconv.Atoi(strings.Split(parts[len(parts)-1], "-")[0])
		ip := strings.Trim(strings.Join(parts[:len(parts)-1], ":"), "[]")
		return ip, port
	}
	return target, 0
}

func firstPort(spec string) int {
	ranges := expandPorts(spec)
	if len(ranges) == 0 {
		return 0
	}
	return ranges[0][0]
}
