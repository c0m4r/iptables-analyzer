package analyzer

import (
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

	// Collect block rules from filter/INPUT
	inputBlocks := collectInputBlocks(rs)

	// Collect all filter/INPUT ACCEPT rules to check if ports are explicitly allowed
	// (we also flag DNAT ports that are exposed even without an INPUT block,
	//  since users might not realize Docker bypasses INPUT entirely)

	// seen tracks (exposedPort → containerDest) pairs already reported
	seen := make(map[string]bool)

	for _, dnat := range dnatRules {
		dnatPort := dnat.DstPort
		if dnatPort == "" {
			continue
		}
		containerDest := dnat.DNATTarget
		if containerDest == "" {
			continue
		}

		portKey := dnatPort + "→" + containerDest
		if seen[portKey] {
			continue
		}

		// Check 1: Is there an INPUT block for this port that is ineffective?
		// Report only the first matching block to avoid duplicate findings.
		foundBlock := false
		for _, block := range inputBlocks {
			if portsOverlap(dnatPort, block.DstPort) && protocolsOverlap(dnat.Protocol, block.Protocol) {
				findings = append(findings, models.DockerBypassFinding{
					InputRule:     block,
					NATRule:       dnat,
					ExposedPort:   dnatPort,
					ContainerDest: containerDest,
					Reason: "Port " + dnatPort + " is blocked in filter/INPUT, but Docker DNAT in " +
						dnat.Table + "/" + dnat.Chain + " redirects traffic to " + containerDest +
						". Traffic goes through PREROUTING->FORWARD, bypassing INPUT entirely.",
					Severity: models.SeverityCritical,
				})
				seen[portKey] = true
				foundBlock = true
				break
			}
		}

		// Check 2: Flag DNAT ports that have no FORWARD chain restriction
		if !foundBlock && !hasForwardBlock(rs, dnatPort, dnat.Protocol) {
			findings = append(findings, models.DockerBypassFinding{
				NATRule:       dnat,
				ExposedPort:   dnatPort,
				ContainerDest: containerDest,
				Reason: "Docker DNAT exposes port " + dnatPort + " -> " + containerDest +
					" with no restriction in the FORWARD chain. " +
					"Any source can reach this container port. " +
					"Use the DOCKER-USER chain to add restrictions.",
				Severity: models.SeverityHigh,
			})
			seen[portKey] = true
		}
	}

	return findings
}

func collectDNATRules(rs *models.Ruleset) []models.Rule {
	var rules []models.Rule

	natTable, ok := rs.Tables["nat"]
	if !ok {
		return rules
	}

	for _, chain := range natTable.Chains {
		for _, rule := range chain.Rules {
			if rule.Target == "DNAT" && rule.DNATTarget != "" {
				rules = append(rules, rule)
			}
		}
	}

	return rules
}

func collectInputBlocks(rs *models.Ruleset) []models.Rule {
	var rules []models.Rule

	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return rules
	}

	input, ok := filterTable.Chains["INPUT"]
	if !ok {
		return rules
	}

	for _, rule := range input.Rules {
		if rule.IsBlock() {
			rules = append(rules, rule)
		}
	}

	return rules
}

func hasForwardBlock(rs *models.Ruleset, port string, proto models.Protocol) bool {
	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return false
	}

	// Check FORWARD chain and DOCKER-USER chain
	chainsToCheck := []string{"FORWARD", "DOCKER-USER"}
	for _, chainName := range chainsToCheck {
		chain, ok := filterTable.Chains[chainName]
		if !ok {
			continue
		}
		for _, rule := range chain.Rules {
			if rule.IsBlock() && portsOverlap(port, rule.DstPort) && protocolsOverlap(proto, rule.Protocol) {
				return true
			}
		}
	}

	// Also check if FORWARD default policy is DROP and there's no blanket ACCEPT
	forward, ok := filterTable.Chains["FORWARD"]
	if ok && forward.Policy == "DROP" {
		// Check if there's a Docker ACCEPT that overrides it
		hasDockerAccept := false
		for _, rule := range forward.Rules {
			if rule.IsAllow() && (rule.Target == "ACCEPT" || rule.Target == "DOCKER") {
				// If it jumps to DOCKER chain or broadly accepts, Docker traffic may still pass
				if rule.OutIface != "" || rule.InIface != "" {
					hasDockerAccept = true
				}
			}
		}
		if !hasDockerAccept {
			return true
		}
	}

	return false
}

func portsOverlap(a, b string) bool {
	if a == "" || b == "" {
		// Empty means "any port" - if either is any, they overlap
		return true
	}

	aRanges := expandPorts(a)
	bRanges := expandPorts(b)

	for _, ar := range aRanges {
		for _, br := range bRanges {
			if ar[0] <= br[1] && ar[1] >= br[0] {
				return true
			}
		}
	}
	return false
}

func protocolsOverlap(a, b models.Protocol) bool {
	if a == "" || a == models.ProtoAll || b == "" || b == models.ProtoAll {
		return true
	}
	return a == b
}

// ParseDNATTarget parses "ip:port" from --to-destination value
func ParseDNATTarget(target string) (string, int) {
	parts := strings.Split(target, ":")
	if len(parts) >= 2 {
		port, _ := strconv.Atoi(parts[len(parts)-1])
		ip := strings.Join(parts[:len(parts)-1], ":")
		return ip, port
	}
	return target, 0
}
