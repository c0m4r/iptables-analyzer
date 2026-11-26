package report

import (
	"slices"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/textsafe"
)

// Commands in fixes are meant to be copied into a root shell. Every value
// taken from the analyzed ruleset (rule arguments, chain, interface and
// address names) is quoted with textsafe.ShellQuote, so a comment such as
// "$(curl ...)" stays an argument instead of running. Placeholders are in
// angle brackets, which a shell refuses instead of running a half-filled
// command.

const trusted = "<trusted-cidr>"

func shellQuote(value string) string { return textsafe.ShellQuote(value) }

// tableOption returns the -t option for tables other than filter.
func tableOption(table string) string {
	if table == "" || table == "filter" {
		return ""
	}
	return " -t " + textsafe.ShellQuote(table)
}

// policyFix says what to do about a chain that accepts by default.
func (b *builder) policyFix(issue *models.EffectivenessFinding) *Fix {
	if issue.Chain != "INPUT" && issue.Chain != "FORWARD" {
		return nil
	}
	command := firewallCommand(issue.IPVersion)
	if rule := issue.Rule; rule != nil {
		// A rule accepts everything; the policy is not what decides.
		fix := &Fix{Summary: "This rule accepts every packet that reaches it, so the rules after it and the policy of the chain decide nothing. " +
			"Add rules for the traffic that is needed, with a tested way back, then delete it."}
		if owner := b.owner(rule); owner != "" {
			fix.Summary += " The chain belongs to " + owner + ": make the change there."
			return fix
		}
		fix.Steps = []FixStep{{"Delete the rule that accepts everything",
			command + tableOption(rule.Table) + " -D " + shellQuote(rule.Chain) + " " + strconv.Itoa(rule.RuleNum)}}
		return fix
	}
	manager := b.manager(issue.IPVersion)
	if manager == "ufw" {
		// ufw sets the policies of the chains itself.
		direction := "incoming"
		if issue.Chain == "FORWARD" {
			direction = "routed"
		}
		return &Fix{
			Summary: "ufw manages this firewall: set the default with ufw, after the rules for the traffic that is needed are in place (ufw allow ...).",
			Steps:   []FixStep{{"Deny " + direction + " traffic by default", "ufw default deny " + direction}},
		}
	}
	if manager != "" {
		return &Fix{Summary: "The rules of this host are written by " + manager + ": set the default there. A policy set with " + command +
			" is lost when " + manager + " writes its rules again."}
	}
	if issue.Chain == "INPUT" {
		return &Fix{
			Summary: "Add rules for the traffic that is needed and test them, with a way back, then set the policy to DROP. " +
				"The recommended baseline (--baseline) is a complete rule set to start from.",
			Steps: []FixStep{{"Deny by default (" + stack(issue.IPVersion) + ")", command + " -P INPUT DROP"}},
		}
	}
	return &Fix{
		Summary: "Set the policy to DROP after the forwarding paths that are needed have rules.",
		Steps:   []FixStep{{"Deny forwarding by default (" + stack(issue.IPVersion) + ")", command + " -P FORWARD DROP"}},
	}
}

// exposureFix says how to limit a port that is open to any source. rule is
// the rule that accepts it, nil when the policy of the chain does. With
// limiter it also gives the rate limit for SSH that stays open.
func (b *builder) exposureFix(protocol models.Protocol, first, last int, rule *models.Rule, limiter bool) *Fix {
	if rule == nil {
		return &Fix{Summary: "No rule names this port: INPUT accepts it by default. Close the default first; then accept the port for its clients only."}
	}
	if owner := b.owner(rule); owner != "" {
		return managedExposureFix(owner, protocol, first, last, rule, limiter)
	}

	fix := &Fix{Summary: "If the clients are known, accept only their addresses."}
	if args := analyzer.RuleArgs(rule); len(args) > 0 && rule.SrcAddr == "" && namesPort(rule) {
		fix.Steps = []FixStep{{"Replace the rule with one for the known clients",
			firewallCommand(rule.IPVersion) + tableOption(rule.Table) + " -R " + shellQuote(rule.Chain) + " " +
				strconv.Itoa(rule.RuleNum) + " -s " + trusted + " " + textsafe.ShellJoin(args)}}
	}
	if limiter {
		if command, ok := sshLimiterCommand(rule); ok {
			fix.Summary += " If SSH must stay open to any source, limit new connections for each source: the limit counts every " +
				"source by itself, so one client cannot lock out the others, and it does not touch established sessions."
			fix.Steps = append(fix.Steps, FixStep{"Or drop the connections of a source that opens more than 10 a minute, in front of the rule", command})
		}
	}
	return fix
}

// namesPort reports whether a rule has a destination-port predicate. A rule
// without one accepts more than the port of the finding; replacing it would
// change all of that.
func namesPort(rule *models.Rule) bool {
	if rule.DstPort != "" {
		return true
	}
	for _, ext := range rule.Matches {
		if ext.Params["--ctorigdstport"] != "" || ext.Params["--ports"] != "" {
			return true
		}
	}
	return false
}

// sshLimiterCommand builds the rule that drops new connections of a source
// above 10 a minute, to be inserted in front of the accepting rule. It keeps
// every match of that rule, so that it limits the same traffic and nothing
// else.
func sshLimiterCommand(rule *models.Rule) (string, bool) {
	args := analyzer.RuleArgs(rule)
	targetAt := -1
	for i := 0; i+1 < len(args); i++ {
		if (args[i] == "-j" || args[i] == "--jump") && args[i+1] == "ACCEPT" {
			targetAt = i
		}
	}
	if targetAt < 0 {
		return "", false
	}
	name := "ssh" + strconv.Itoa(int(rule.IPVersion))
	limiter := args[:targetAt:targetAt]
	// The limit is for new connections. A rule that already matches their
	// state needs no second match for it.
	if !slices.Contains(limiter, "--ctstate") && !slices.Contains(limiter, "--state") {
		limiter = append(limiter, "-m", "conntrack", "--ctstate", "NEW")
	}
	limiter = append(limiter, "-m", "hashlimit", "--hashlimit-above", "10/min", "--hashlimit-burst", "20",
		"--hashlimit-mode", "srcip", "--hashlimit-name", name, "-j", "DROP")
	return firewallCommand(rule.IPVersion) + tableOption(rule.Table) + " -I " + shellQuote(rule.Chain) + " " +
		strconv.Itoa(rule.RuleNum) + " " + textsafe.ShellJoin(limiter), true
}

// publishedGroup describes a finding about several translated ports. The
// commands of its fix are written for one port, and the text says how they
// serve for the rest.
type publishedGroup struct {
	// others are the other ports, as the report names them: "8443/tcp", or
	// "8443/tcp of 192.0.2.10" for a port of one address of the host.
	others []string
	// someAddress and someWildcard say that the finding has a port of one
	// address, and a port of all addresses.
	someAddress, someWildcard bool
	// bothFamilies says that the finding is about IPv4 and IPv6.
	bothFamilies bool
}

// pattern says what to do about the ports and the address family that the
// commands of a fix do not name. commands and them are "The commands below
// are" and "them", or the singular; address says how the commands match the
// address of a port ("--ctorigdst ADDRESS") and wildcard how they match all
// addresses of the host ("" when they need no match for that).
func (g publishedGroup) pattern(finding *models.DockerBypassFinding, protocol models.Protocol, commands, them, address, wildcard string) string {
	text := ""
	if len(g.others) > 0 {
		port := finding.ExposedPort + "/" + string(protocol)
		if finding.HostAddr != "" {
			port += " of " + finding.HostAddr
		}
		text = " " + commands + " for port " + port + ". For each of the other ports (" + abbreviate(g.others, 8) +
			"), run " + them + " again with its protocol and its port"
		for _, other := range g.others {
			if port, _, _ := strings.Cut(other, "/"); strings.Contains(port, "-") {
				text += "; write a range of ports as FIRST:LAST"
				break
			}
		}
		text += "."
		switch {
		case g.someAddress && g.someWildcard && wildcard == "":
			text += " For a port of one address, add " + address + "; for a port of all addresses, leave that match out."
		case g.someAddress && g.someWildcard:
			text += " Match a port of one address with " + address + ", and a port of all addresses with " + wildcard + "."
		case g.someAddress:
			text += " Each port has its own address: use it in " + address + "."
		}
	}
	if g.bothFamilies {
		other, tool := "IPv6", "ip6tables"
		if finding.IPVersion == models.IPv6 {
			other, tool = "IPv4", "iptables"
		}
		text += " For " + other + ", use " + tool + "."
	}
	return text
}

// publishedFix says how to restrict a port that nat/PREROUTING translates.
// group is empty for a finding about one port.
func publishedFix(finding *models.DockerBypassFinding, protocol models.Protocol, group publishedGroup) *Fix {
	portSpec := strings.ReplaceAll(finding.ExposedPort, "-", ":")
	if chainOwner(finding.NATRule.Chain) == "kubernetes" {
		// kube-proxy rewrites its chains all the time. A rule in the raw
		// table sees the packet before the translation, with the port that
		// the client used.
		destination := "-m addrtype --dst-type LOCAL"
		if finding.HostAddr != "" {
			destination = "-d " + shellQuote(finding.HostAddr)
		}
		return &Fix{
			Summary: "kube-proxy writes this translation for a Service of type NodePort or LoadBalancer, and it writes its chains again all the time. " +
				"Limit the Service in the cluster: set spec.loadBalancerSourceRanges, use a NetworkPolicy for the pods, or use type ClusterIP " +
				"when the port needs no clients outside the cluster. To filter on the node, drop the port for other sources in the raw table, " +
				"which sees the packet before the translation." +
				group.pattern(finding, protocol, "The command below is", "it", "-d ADDRESS", "-m addrtype --dst-type LOCAL"),
			Steps: []FixStep{{"Drop port " + finding.ExposedPort + " for all but the known clients, in front of the translation",
				firewallCommand(finding.IPVersion) + " -t raw -I PREROUTING " + destination + " -p " + string(protocol) + " -m " + string(protocol) +
					" --dport " + portSpec + " ! -s " + trusted + " -j DROP"}},
		}
	}
	if !analyzer.IsDockerRule(&finding.NATRule) && len(group.others) > 0 {
		return &Fix{Summary: "Each of these ports is translated by its rule in nat/PREROUTING and then passes filter/FORWARD, not filter/INPUT. " +
			"If only known clients need a port, add their sources (-s " + trusted + ") to its rule or to the FORWARD rule that accepts its traffic. " +
			"In FORWARD the packet has the translated address and port; match the port that the clients use with " +
			"'-m conntrack --ctorigdstport PORT --ctdir ORIGINAL'."}
	}
	if !analyzer.IsDockerRule(&finding.NATRule) {
		// A port forward of the administrator: there is no DOCKER-USER chain.
		return &Fix{Summary: "The port is translated by " + ruleName(&finding.NATRule) + " and then passes filter/FORWARD, not filter/INPUT. " +
			"If only known clients need it, add their sources (-s " + trusted + ") to that rule or to the FORWARD rule that accepts the traffic. " +
			"In FORWARD the packet has the translated address and port; match the original port with " +
			"'-m conntrack --ctorigdstport " + portSpec + " --ctdir ORIGINAL'."}
	}
	command := firewallCommand(finding.IPVersion)
	args := []string{"-p", string(protocol), "-m", "conntrack"}
	if addr := finding.NATRule.DstAddr; addr != "" && !finding.NATRule.Negations["dst"] {
		args = append(args, "--ctorigdst", addr)
	}
	match := textsafe.ShellJoin(append(args, "--ctorigdstport", portSpec, "--ctdir", "ORIGINAL"))
	return &Fix{
		Summary: "Docker translates published ports in nat/PREROUTING, so they are forwarded and never reach filter/INPUT " +
			"(this includes INPUT rules of ufw or firewalld). Restrict them in DOCKER-USER, which runs before Docker's own rules " +
			"and which Docker never flushes. Packets are already translated there: match the published port with --ctorigdstport, not --dport. " +
			"A service that only local clients need can be published on loopback instead (docker run -p 127.0.0.1:" +
			strings.SplitN(finding.ExposedPort, "-", 2)[0] + ":<container-port>)." +
			group.pattern(finding, protocol, "The commands below are", "them", "--ctorigdst ADDRESS", ""),
		Steps: []FixStep{
			{"Allow the trusted sources of port " + finding.ExposedPort + " first", command + " -I DOCKER-USER 1 " + match + " -s " + trusted + " -j RETURN"},
			{"Then drop the rest of that port", command + " -I DOCKER-USER 2 " + match + " -j DROP"},
		},
	}
}

// ineffectiveRuleFix says how to make a rule on the forwarding path of Docker
// take effect.
func ineffectiveRuleFix(finding *models.DockerBypassFinding) *Fix {
	rule := finding.Rule
	command := firewallCommand(finding.IPVersion)
	args := analyzer.RuleArgs(rule)
	fix := &Fix{Summary: finding.Fix}
	switch {
	case len(args) == 0:
		// Without the rule's arguments no command can be built safely.
	case finding.Code == models.FindingDockerIneffectiveRule:
		replacement := args
		if !rule.Negations["dport"] {
			replacement = dportToOrigDstPort(replacement)
		}
		if rule.DstAddr != "" && !rule.Negations["dst"] {
			replacement = dstToOrigDst(replacement, rule.DstAddr)
		}
		changed := !slices.Equal(replacement, args)
		if changed && rule.Table == "filter" && rule.Chain == "DOCKER-USER" {
			fix.Steps = []FixStep{{"Replace the rule with one that matches the published port",
				command + " -R DOCKER-USER " + strconv.Itoa(rule.RuleNum) + " " + textsafe.ShellJoin(replacement)}}
		} else if changed {
			fix.Steps = []FixStep{{"Add the rule with the same intent to DOCKER-USER",
				command + " -I DOCKER-USER 1 " + textsafe.ShellJoin(replacement)}}
		}
	case rule.Table == "filter":
		fix.Steps = []FixStep{
			{"Add the rule to DOCKER-USER", command + " -I DOCKER-USER 1 " + textsafe.ShellJoin(args)},
			{"Delete it where it has no effect", command + " -D " + shellQuote(rule.Chain) + " " + strconv.Itoa(rule.RuleNum)},
		}
	}
	return fix
}

// fragileRuleFix moves a rule from above Docker's jumps into DOCKER-USER.
func fragileRuleFix(finding *models.DockerBypassFinding) *Fix {
	rule := finding.Rule
	command := firewallCommand(finding.IPVersion)
	fix := &Fix{Summary: finding.Fix}
	if args := analyzer.RuleArgs(rule); len(args) > 0 {
		fix.Steps = []FixStep{
			{"Add the rule to DOCKER-USER", command + " -I DOCKER-USER 1 " + textsafe.ShellJoin(args)},
			{"Delete it from FORWARD", command + " -D FORWARD " + strconv.Itoa(rule.RuleNum)},
		}
	}
	return fix
}

// directRouteFix says how to stop packets that are routed straight to a
// container address.
func (b *builder) directRouteFix(finding *models.DockerBypassFinding) *Fix {
	command := firewallCommand(finding.IPVersion)
	bridge := "<bridge>"
	if finding.Bridge != "" {
		bridge = shellQuote(finding.Bridge)
	}
	addr := finding.ContainerDest
	if i := strings.LastIndex(addr, ":"); i > 0 {
		addr = strings.Trim(addr[:i], "[]")
	}
	target := addr
	if subnet := b.bridgeSubnet(finding.IPVersion, finding.Bridge); subnet != "" {
		target = subnet
	}
	addr, target = shellQuote(addr), shellQuote(target)
	if finding.GatewayMode == "routed" {
		return &Fix{
			Summary: finding.Fix,
			Steps: []FixStep{{"Drop the container port for all but the trusted sources",
				command + " -I DOCKER-USER -o " + bridge + " -d " + addr + " -p tcp --dport " +
					shellQuote(finding.ExposedPort) + " ! -s " + trusted + " -j DROP"}},
		}
	}
	return &Fix{
		Summary: finding.Fix,
		Steps: []FixStep{
			{"Drop packets for the containers that do not arrive from their bridge (published ports keep working)",
				command + " -t raw -I PREROUTING -d " + target + " ! -i " + bridge + " -j DROP"},
			{"Or refuse new connections into the bridge that no published port translated",
				command + " -I DOCKER-USER -o " + bridge + " ! -i " + bridge + " -m conntrack --ctstate NEW -m conntrack ! --ctstate DNAT -j DROP"},
		},
	}
}

// bridgeSubnet returns the subnet Docker masquerades for bridge, if known.
func (b *builder) bridgeSubnet(version models.IPVersion, bridge string) string {
	rs := b.ruleset(version)
	if bridge == "" || rs == nil || rs.Tables["nat"] == nil || rs.Tables["nat"].Chains["POSTROUTING"] == nil {
		return ""
	}
	for _, rule := range rs.Tables["nat"].Chains["POSTROUTING"].Rules {
		if rule.Target == "MASQUERADE" && rule.OutIface == bridge && rule.Negations["out-iface"] && rule.SrcAddr != "" && !rule.Negations["src"] {
			return rule.SrcAddr
		}
	}
	return ""
}

// dportToOrigDstPort replaces "[-m tcp|udp] --dport N", which never matches
// in DOCKER-USER after DNAT, with a match on the original destination port.
func dportToOrigDstPort(args []string) []string {
	var result []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--dport" && i+1 < len(args) && isPortSpec(args[i+1]) {
			if n := len(result); n >= 2 && result[n-2] == "-m" && (result[n-1] == "tcp" || result[n-1] == "udp") {
				result = result[:n-2]
			}
			result = append(result, "-m", "conntrack", "--ctorigdstport", args[i+1], "--ctdir", "ORIGINAL")
			i++
			continue
		}
		result = append(result, args[i])
	}
	return result
}

// dstToOrigDst moves "-d addr" to a match on the original destination.
func dstToOrigDst(args []string, addr string) []string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "-d" || args[i+1] != addr || (i > 0 && args[i-1] == "!") {
			continue
		}
		result := slices.Concat(args[:i], args[i+2:])
		for j, arg := range result {
			if arg == "-j" || arg == "--jump" {
				return slices.Concat(result[:j], []string{"-m", "conntrack", "--ctorigdst", addr, "--ctdir", "ORIGINAL"}, result[j:])
			}
		}
		return args
	}
	return args
}

func isPortSpec(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && c != ':' {
			return false
		}
	}
	return true
}
