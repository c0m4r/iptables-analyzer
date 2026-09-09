package analyzer

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// DetectDockerBypasses finds published ports that bypass filter/INPUT and are
// accepted on the translated path through filter/FORWARD.
func DetectDockerBypasses(rs *models.Ruleset) []models.DockerBypassFinding {
	if rs == nil {
		return nil
	}
	natTable := rs.Tables["nat"]
	if natTable == nil || natTable.Chains["PREROUTING"] == nil {
		return nil
	}

	var findings []models.DockerBypassFinding
	seen := make(map[string]bool)
	for _, dnat := range allDNATRules(natTable) {
		if dnat.DstPort == "" || dnat.DNATTarget == "" || dnat.Protocol == "" ||
			dnat.Protocol == models.ProtoAll || isLoopback(dnat.DstAddr) {
			continue
		}
		translation, err := parseDNATTranslation(dnat.DNATTarget)
		if err != nil {
			continue
		}
		originalPorts := portsInSpec(dnat.DstPort)
		if len(originalPorts) == 0 {
			continue
		}
		firstOriginal := originalPorts[0]
		for _, hostPort := range originalPorts {
			sourcePort := 0
			if dnat.SrcPort != "" && !dnat.Negations["sport"] {
				sourcePorts := portsInSpec(dnat.SrcPort)
				if len(sourcePorts) == 1 {
					sourcePort = sourcePorts[0]
				}
			}
			query := packetQuery{
				Protocol:        dnat.Protocol,
				SrcPort:         sourcePort,
				DstPort:         hostPort,
				DstAddr:         dnat.DstAddr,
				InIface:         positiveValue(dnat.InIface, dnat.Negations["in-iface"]),
				OutIface:        positiveValue(dnat.OutIface, dnat.Negations["out-iface"]),
				State:           "NEW",
				OriginalDstAddr: dnat.DstAddr,
				OriginalDstPort: hostPort,
				Direction:       "ORIGINAL",
				External:        true,
				Hook:            "PREROUTING",
			}
			sources, natUncertain := sourcesReachingDNAT(rs, natTable, dnat, query)
			if len(sources) == 0 {
				continue
			}

			containerPort := translatedPort(translation, firstOriginal, hostPort)
			if containerPort == 0 {
				continue
			}
			forwardScope, _, _, forwardCertainty := evaluateAccessFromDetailed(rs, "FORWARD", packetQuery{
				Protocol:        dnat.Protocol,
				DstPort:         containerPort,
				DstAddr:         translation.Address,
				State:           "NEW",
				NATState:        "DNAT",
				OriginalDstAddr: dnat.DstAddr,
				OriginalDstPort: hostPort,
				Direction:       "ORIGINAL",
				External:        true,
			}, sources)
			if forwardScope != models.ScopeExposed {
				continue
			}

			key := string(dnat.Protocol) + ":" + strconv.Itoa(hostPort) + "→" + dnat.DNATTarget
			if seen[key] {
				continue
			}
			inputScope, _, inputDrop, inputCertainty := evaluateAccessFromDetailed(rs, "INPUT", packetQuery{
				Protocol: dnat.Protocol,
				DstPort:  hostPort,
				DstAddr:  dnat.DstAddr,
				State:    "NEW",
				External: true,
			}, sources)

			exposedPort := strconv.Itoa(hostPort)
			certainty := models.CertaintyDefinite
			if natUncertain || forwardCertainty == models.CertaintyPossible || inputCertainty == models.CertaintyPossible {
				certainty = models.CertaintyPossible
			}
			finding := models.DockerBypassFinding{
				Code:          models.FindingDockerBypass,
				Certainty:     certainty,
				NATRule:       dnat,
				ExposedPort:   exposedPort,
				ContainerDest: dnat.DNATTarget,
				Severity:      models.SeverityHigh,
				Reason: "Docker DNAT exposes port " + exposedPort + " -> " + dnat.DNATTarget +
					" to unrestricted sources through filter/FORWARD. Restrict the original " +
					"destination in DOCKER-USER with the conntrack match.",
			}
			if inputScope != models.ScopeExposed {
				finding.Severity = models.SeverityCritical
				finding.Reason = "Port " + exposedPort + " is restricted by filter/INPUT, but DNAT in " +
					dnat.Table + "/" + dnat.Chain + " redirects traffic to " + dnat.DNATTarget +
					" through FORWARD, where it remains reachable from unrestricted sources."
				if inputDrop != nil {
					finding.InputRule = *inputDrop
				}
			}
			if certainty == models.CertaintyPossible {
				finding.Reason = "Possible path: " + finding.Reason
			}
			findings = append(findings, finding)
			seen[key] = true
		}
	}
	return findings
}

func positiveValue(value string, negated bool) string {
	if negated || strings.HasSuffix(value, "+") {
		return ""
	}
	return value
}

// DockerAssessmentDiagnostics reports translations that cannot be evaluated
// completely instead of silently omitting them.
func DockerAssessmentDiagnostics(rs *models.Ruleset) []models.AssessmentDiagnostic {
	if rs == nil || rs.Tables["nat"] == nil {
		return nil
	}
	var diagnostics []models.AssessmentDiagnostic
	add := func(message string) {
		diagnostics = append(diagnostics, models.AssessmentDiagnostic{Area: "docker", Message: message})
	}
	for _, rule := range allDNATRules(rs.Tables["nat"]) {
		location := fmt.Sprintf("IPv%d nat/%s rule #%d", rs.IPVersion, rule.Chain, rule.RuleNum)
		switch {
		case rule.DstPort == "":
			add(location + ": DNAT has no destination-port predicate; published-port exposure was not assessed")
		case rule.Protocol == "" || rule.Protocol == models.ProtoAll:
			add(location + ": DNAT has no specific transport protocol; published-port exposure was not assessed")
		case len(portsInSpec(rule.DstPort)) == 0:
			add(location + ": DNAT has an invalid destination-port predicate; published-port exposure was not assessed")
		case rule.DNATTarget == "":
			add(location + ": DNAT target is missing; translation was not assessed")
		default:
			translation, err := parseDNATTranslation(rule.DNATTarget)
			if err != nil {
				add(location + ": " + err.Error())
			} else if translation.HasPort && translation.PortEnd > translation.PortStart &&
				translation.PortEnd-translation.PortStart+1 < len(portsInSpec(rule.DstPort)) {
				add(location + ": translated port range is shorter than the original port range; part of the mapping was not assessed")
			}
		}
	}
	return diagnostics
}

func allDNATRules(table *models.Table) []models.Rule {
	var rules []models.Rule
	for _, chainName := range sortedChainNames(table) {
		for _, rule := range table.Chains[chainName].Rules {
			if rule.Target == "DNAT" {
				rules = append(rules, rule)
			}
		}
	}
	return rules
}

type natWalkResult struct {
	Reached   []netip.Prefix
	Returned  []netip.Prefix
	Uncertain bool
}

func sourcesReachingDNAT(rs *models.Ruleset, table *models.Table, target models.Rule, query packetQuery) ([]netip.Prefix, bool) {
	root := netip.MustParsePrefix("0.0.0.0/0")
	if rs.IPVersion == models.IPv6 {
		root = netip.MustParsePrefix("::/0")
	}
	result := walkNATChain(table, "PREROUTING", []netip.Prefix{root}, target, query, map[string]bool{})
	return normalizePrefixes(result.Reached), result.Uncertain
}

func walkNATChain(table *models.Table, chainName string, input []netip.Prefix, target models.Rule, query packetQuery, path map[string]bool) natWalkResult {
	chain := table.Chains[chainName]
	if chain == nil || path[chainName] {
		return natWalkResult{}
	}
	path[chainName] = true
	defer delete(path, chainName)

	remaining := normalizePrefixes(input)
	var result natWalkResult
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
			unmatched = append(unmatched, matched...)
			result.Uncertain = true
		}
		remaining = normalizePrefixes(unmatched)

		if rule.Table == target.Table && rule.Chain == target.Chain && rule.RuleNum == target.RuleNum {
			result.Reached = append(result.Reached, matched...)
			continue
		}
		if _, isChain := table.Chains[rule.Target]; isChain {
			child := walkNATChain(table, rule.Target, matched, target, query, path)
			result.Reached = append(result.Reached, child.Reached...)
			result.Uncertain = result.Uncertain || child.Uncertain
			if !rule.Goto {
				remaining = normalizePrefixes(append(remaining, child.Returned...))
			}
			continue
		}
		switch rule.Target {
		case "RETURN":
			result.Returned = append(result.Returned, matched...)
		case "ACCEPT", "DROP", "REJECT", "DNAT", "REDIRECT":
			// These verdicts consume the matching branch in this hook.
		default:
			remaining = normalizePrefixes(append(remaining, matched...))
		}
	}
	result.Returned = normalizePrefixes(append(result.Returned, remaining...))
	return result
}

type dnatTranslation struct {
	Address   string
	PortStart int
	PortEnd   int
	HasPort   bool
}

func parseDNATTranslation(target string) (dnatTranslation, error) {
	if address, err := netip.ParseAddr(target); err == nil {
		return dnatTranslation{Address: address.String()}, nil
	}

	var host, portText string
	if strings.HasPrefix(target, "[") {
		close := strings.LastIndex(target, "]:")
		if close < 0 {
			return dnatTranslation{}, fmt.Errorf("invalid bracketed DNAT target %q", target)
		}
		host = target[1:close]
		portText = target[close+2:]
	} else if strings.Count(target, ":") == 1 {
		host, portText, _ = strings.Cut(target, ":")
	} else {
		return dnatTranslation{}, fmt.Errorf("invalid or ambiguous DNAT target %q", target)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return dnatTranslation{}, fmt.Errorf("invalid DNAT address %q", host)
	}
	ports := portsInSpec(strings.ReplaceAll(portText, "-", ":"))
	if len(ports) == 0 {
		return dnatTranslation{}, fmt.Errorf("invalid DNAT port %q", portText)
	}
	return dnatTranslation{Address: address.String(), PortStart: ports[0], PortEnd: ports[len(ports)-1], HasPort: true}, nil
}

// ParseDNATTarget is retained for callers that need the first translated port.
// Bare IPv6 addresses are returned intact with port zero.
func ParseDNATTarget(target string) (string, int) {
	translation, err := parseDNATTranslation(target)
	if err != nil {
		return target, 0
	}
	return translation.Address, translation.PortStart
}

func translatedPort(translation dnatTranslation, firstOriginal, original int) int {
	if !translation.HasPort {
		return original
	}
	if translation.PortStart == translation.PortEnd {
		return translation.PortStart
	}
	translated := translation.PortStart + original - firstOriginal
	if translated > translation.PortEnd {
		return 0
	}
	return translated
}

func portsInSpec(spec string) []int {
	var ports []int
	for _, portRange := range expandPorts(spec) {
		start := max(1, portRange[0])
		end := min(65535, portRange[1])
		for port := start; port <= end; port++ {
			ports = append(ports, port)
		}
	}
	return ports
}
