package recommender

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/textsafe"
)

// Commands in recommendations are meant to be copied into a root shell.
// Every value taken from the analyzed ruleset (rule arguments, chain,
// interface and address names) is quoted with textsafe.ShellQuote, so a
// comment such as "$(curl ...)" stays an argument instead of running.

// Generate produces security recommendations based on analysis results
func Generate(result *models.AnalysisResult) []models.Recommendation {
	var recs []models.Recommendation

	recs = append(recs, policyRecommendations(result)...)
	recs = append(recs, dockerRecommendations(result)...)
	recs = append(recs, exposureRecommendations(result)...)
	recs = append(recs, hygieneRecommendations(result)...)
	recs = append(recs, ipv6Recommendations(result)...)

	// Most severe first; generation order is kept within a severity.
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Severity > recs[j].Severity })
	return recs
}

func policyRecommendations(result *models.AnalysisResult) []models.Recommendation {
	var recs []models.Recommendation

	for _, issue := range result.EffectiveIssues {
		command := firewallCommand(issue.IPVersion)
		stack := stackLabel(issue.IPVersion)
		if issue.Chain == "INPUT" && (issue.Code == models.FindingPolicyAccept || issue.Title == "INPUT default policy is ACCEPT") {
			recs = append(recs, models.Recommendation{
				Title: "Set " + stack + " INPUT chain default policy to DROP",
				Detail: "Install and verify required allow rules first, with a tested rollback path, then change the INPUT policy to DROP. " +
					"The Recommended Baseline section contains a complete, reviewed rule set for both IPv4 and IPv6.\n" +
					"  Command: " + command + " -P INPUT DROP",
				Severity: models.SeverityHigh,
				Category: "policy",
			})
		}
		if issue.Chain == "FORWARD" && (issue.Code == models.FindingPolicyAccept || issue.Title == "FORWARD default policy is ACCEPT") {
			recs = append(recs, models.Recommendation{
				Title:    "Set " + stack + " FORWARD chain default policy to DROP",
				Detail:   "After verifying required forwarding paths, change the FORWARD policy to DROP.\n  Command: " + command + " -P FORWARD DROP",
				Severity: models.SeverityHigh,
				Category: "policy",
			})
		}
	}

	return recs
}

func dockerRecommendations(result *models.AnalysisResult) []models.Recommendation {
	var recs []models.Recommendation

	if len(result.DockerBypasses) == 0 {
		return recs
	}

	severity := models.SeverityLow
	published := false
	for _, finding := range result.DockerBypasses {
		if finding.Severity > severity {
			severity = finding.Severity
		}
		if finding.Code == models.FindingDockerBypass || finding.Code == models.FindingDockerPublished {
			published = true
		}
	}

	if published {
		recs = append(recs, models.Recommendation{
			Title: "Use the DOCKER-USER chain for container access control",
			Detail: "Docker DNATs published ports in nat/PREROUTING, so the traffic is forwarded and never reaches filter/INPUT " +
				"(this includes INPUT rules created by ufw or firewalld). DOCKER-USER is evaluated before Docker's own ACCEPT rules " +
				"and Docker never flushes it. Packets are already translated there: match the published port with " +
				"'-m conntrack --ctorigdstport <port> --ctdir ORIGINAL', not with --dport. If a service only needs local " +
				"access, publish it on loopback (-p 127.0.0.1:<port>:<container-port>) or set \"ip\": \"127.0.0.1\" in daemon.json.",
			Severity: severity,
			Category: "docker",
		})
	}

	for _, finding := range result.DockerBypasses {
		var rec *models.Recommendation
		switch finding.Code {
		case models.FindingDockerBypass, models.FindingDockerPublished:
			rec = publishedPortRecommendation(finding)
		case models.FindingDockerIneffectiveRule, models.FindingDockerShadowedRule:
			rec = ineffectiveRuleRecommendation(finding)
		case models.FindingDockerDirectRoute:
			rec = directRouteRecommendation(result, finding)
		case models.FindingDockerFragileRule:
			rec = fragileRuleRecommendation(finding)
		case models.FindingDockerIPv6Unfiltered:
			rec = &models.Recommendation{
				Title: "Let Docker manage ip6tables and deny IPv6 forwarding by default",
				Detail: finding.Fix + "\n" +
					"  ip6tables -P FORWARD DROP",
				Severity: finding.Severity,
				Category: "docker",
			}
		}
		if rec != nil {
			recs = append(recs, *rec)
		}
	}

	return recs
}

func publishedPortRecommendation(finding models.DockerBypassFinding) *models.Recommendation {
	protocol := string(finding.NATRule.Protocol)
	if protocol == "" || protocol == string(models.ProtoAll) {
		protocol = "tcp"
	}
	command := firewallCommand(finding.IPVersion)
	portSpec := strings.ReplaceAll(finding.ExposedPort, "-", ":")
	args := []string{"-p", protocol, "-m", "conntrack"}
	if addr := finding.NATRule.DstAddr; addr != "" && !finding.NATRule.Negations["dst"] {
		args = append(args, "--ctorigdst", addr)
	}
	match := textsafe.ShellJoin(append(args, "--ctorigdstport", portSpec, "--ctdir", "ORIGINAL"))
	var detail strings.Builder
	if finding.Code == models.FindingDockerBypass && finding.InputRule.RuleNum > 0 {
		detail.WriteString(finding.InputRule.Table + "/" + finding.InputRule.Chain + " rule #" +
			strconv.Itoa(finding.InputRule.RuleNum) + " never sees this traffic because it is DNATed first. ")
	} else if finding.Code == models.FindingDockerBypass {
		detail.WriteString("The default-deny INPUT policy never sees this traffic because it is DNATed first. ")
	}
	detail.WriteString("Allow trusted sources first, then drop the rest of the published port (insert positions keep the order):\n")
	detail.WriteString("  " + command + " -I DOCKER-USER 1 " + match + " -s <trusted-cidr> -j RETURN\n")
	detail.WriteString("  " + command + " -I DOCKER-USER 2 " + match + " -j DROP\n")
	detail.WriteString("Or, if only local clients need it, publish it on loopback: docker run -p 127.0.0.1:" +
		strings.SplitN(finding.ExposedPort, "-", 2)[0] + ":<container-port> ...")
	return &models.Recommendation{
		Title:    "Restrict " + stackLabel(finding.IPVersion) + " published port " + finding.ExposedPort + "/" + protocol + " (" + finding.ContainerDest + ") in DOCKER-USER",
		Detail:   detail.String(),
		Severity: finding.Severity,
		Category: "docker",
	}
}

func ineffectiveRuleRecommendation(finding models.DockerBypassFinding) *models.Recommendation {
	rule := finding.Rule
	if rule == nil {
		return nil
	}
	command := firewallCommand(finding.IPVersion)
	args := analyzer.RuleArgs(rule)
	location := rule.Table + "/" + rule.Chain + " rule #" + strconv.Itoa(rule.RuleNum)
	detail := finding.Fix
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
			detail += "\n  Replace it: " + command + " -R DOCKER-USER " + strconv.Itoa(rule.RuleNum) + " " + textsafe.ShellJoin(replacement)
		} else if changed {
			detail += "\n  Equivalent DOCKER-USER rule: " + command + " -I DOCKER-USER 1 " + textsafe.ShellJoin(replacement)
		}
	case rule.Table == "filter":
		detail += "\n  " + command + " -I DOCKER-USER 1 " + textsafe.ShellJoin(args) +
			"\n  " + command + " -D " + textsafe.ShellQuote(rule.Chain) + " " + strconv.Itoa(rule.RuleNum)
	}
	return &models.Recommendation{
		Title:    "Fix ineffective " + stackLabel(finding.IPVersion) + " " + location,
		Detail:   detail,
		Severity: finding.Severity,
		Category: "docker",
	}
}

func directRouteRecommendation(result *models.AnalysisResult, finding models.DockerBypassFinding) *models.Recommendation {
	command := firewallCommand(finding.IPVersion)
	bridge := "<bridge>"
	if finding.Bridge != "" {
		bridge = textsafe.ShellQuote(finding.Bridge)
	}
	addr := finding.ContainerDest
	if i := strings.LastIndex(addr, ":"); i > 0 {
		addr = strings.Trim(addr[:i], "[]")
	}
	target := addr
	if subnet := bridgeSubnet(result, finding.IPVersion, finding.Bridge); subnet != "" {
		target = subnet
	}
	addr, target = textsafe.ShellQuote(addr), textsafe.ShellQuote(target)
	detail := finding.Fix + "\n" +
		"  Drop packets addressed to the containers that do not arrive from their bridge (published ports are unaffected):\n" +
		"  " + command + " -t raw -I PREROUTING -d " + target + " ! -i " + bridge + " -j DROP\n" +
		"  Or refuse new connections into the bridge that were not DNATed by a published port:\n" +
		"  " + command + " -I DOCKER-USER -o " + bridge + " ! -i " + bridge + " -m conntrack --ctstate NEW -m conntrack ! --ctstate DNAT -j DROP"
	if finding.GatewayMode == "routed" {
		port := textsafe.ShellQuote(finding.ExposedPort)
		detail = finding.Fix + "\n" +
			"  " + command + " -I DOCKER-USER -o " + bridge + " -d " + addr + " -p tcp --dport " + port + " ! -s <trusted-cidr> -j DROP"
	}
	return &models.Recommendation{
		Title:    "Block direct routing to " + stackLabel(finding.IPVersion) + " container " + finding.ContainerDest,
		Detail:   detail,
		Severity: finding.Severity,
		Category: "docker",
	}
}

// bridgeSubnet returns the subnet Docker masquerades for bridge, if known.
func bridgeSubnet(result *models.AnalysisResult, version models.IPVersion, bridge string) string {
	rs := result.IPv4Rules
	if version == models.IPv6 {
		rs = result.IPv6Rules
	}
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

func fragileRuleRecommendation(finding models.DockerBypassFinding) *models.Recommendation {
	rule := finding.Rule
	if rule == nil {
		return nil
	}
	command := firewallCommand(finding.IPVersion)
	detail := finding.Fix
	if args := analyzer.RuleArgs(rule); len(args) > 0 {
		detail += "\n" +
			"  " + command + " -I DOCKER-USER 1 " + textsafe.ShellJoin(args) + "\n" +
			"  " + command + " -D FORWARD " + strconv.Itoa(rule.RuleNum)
	}
	return &models.Recommendation{
		Title:    "Move " + stackLabel(finding.IPVersion) + " filter/FORWARD rule #" + strconv.Itoa(rule.RuleNum) + " into DOCKER-USER",
		Detail:   detail,
		Severity: finding.Severity,
		Category: "docker",
	}
}

func exposureRecommendations(result *models.AnalysisResult) []models.Recommendation {
	var recs []models.Recommendation

	for _, exposed := range result.ExposedServices {
		// Only recommend restrictions for truly exposed services.
		// LOCALNET and WHITELISTED services already have source restrictions in place.
		if exposed.Scope != models.ScopeExposed {
			continue
		}
		svc := exposed.Service
		command := firewallCommand(exposed.IPVersion)
		chain := "INPUT"
		detail := svc.Process + " is listening on port " + strconv.Itoa(svc.Port) + "/" +
			string(svc.Protocol) + " and is accessible from unrestricted sources. "
		if exposed.AllowingRule != nil {
			chain = exposed.AllowingRule.Chain
			detail += "Replace or remove the permissive " + exposed.AllowingRule.Table + "/" +
				exposed.AllowingRule.Chain + " rule #" + strconv.Itoa(exposed.AllowingRule.RuleNum) +
				", then add a source-restricted rule and ensure unmatched traffic is dropped.\n"
		} else {
			detail += "Add a source-restricted allow rule, then ensure unmatched traffic is dropped by policy or a final rule.\n"
		}
		detail += "  Example allow: " + command + " -I " + textsafe.ShellQuote(chain) + " -p " + textsafe.ShellQuote(string(svc.Protocol)) +
			" --dport " + strconv.Itoa(svc.Port) + " -s <trusted-network> -j ACCEPT"
		recs = append(recs, models.Recommendation{
			Title:    "Restrict " + stackLabel(exposed.IPVersion) + " access to " + svc.Process + " on port " + strconv.Itoa(svc.Port) + "/" + string(svc.Protocol),
			Detail:   detail,
			Severity: exposed.Severity,
			Category: "exposure",
		})
	}

	return recs
}

func hygieneRecommendations(result *models.AnalysisResult) []models.Recommendation {
	var recs []models.Recommendation
	inputAcceptPolicy := map[models.IPVersion]bool{}
	for _, issue := range result.EffectiveIssues {
		if (issue.Code == models.FindingPolicyAccept && issue.Chain == "INPUT") || issue.Title == "INPUT default policy is ACCEPT" {
			inputAcceptPolicy[issue.IPVersion] = true
		}
	}

	for _, issue := range result.EffectiveIssues {
		command := firewallCommand(issue.IPVersion)
		stack := stackLabel(issue.IPVersion)
		switch {
		case issue.Code == models.FindingMissingConntrack || issue.Title == "No conntrack ESTABLISHED,RELATED rule in INPUT":
			recs = append(recs, models.Recommendation{
				Title:    "Add " + stack + " conntrack rule for established connections",
				Detail:   "Add an early rule to accept established/related connections for better performance:\n  " + command + " -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
				Severity: models.SeverityMedium,
				Category: "hygiene",
			})
		case issue.Code == models.FindingMissingFinalDrop || issue.Title == "No explicit DROP at end of INPUT chain with ACCEPT policy":
			if inputAcceptPolicy[issue.IPVersion] {
				continue // covered by the policy recommendation
			}
			recs = append(recs, models.Recommendation{
				Title:    "Add explicit " + stack + " DROP at end of INPUT or change policy",
				Detail:   "After verifying required allow rules and a rollback path, either change the INPUT policy to DROP or add a catch-all rule:\n  " + command + " -A INPUT -j DROP\n  Or: " + command + " -P INPUT DROP",
				Severity: models.SeverityHigh,
				Category: "hygiene",
			})
		}
	}

	// Check for SSH rate limiting on each analyzed stack.
	for _, rs := range []*models.Ruleset{result.IPv4Rules, result.IPv6Rules} {
		if sshRule := findSSHWithoutRateLimit(rs); sshRule != nil {
			detail := "Rate-limit the existing " + sshRule.Table + "/" + sshRule.Chain + " rule #" +
				strconv.Itoa(sshRule.RuleNum) + " while retaining all of its interface, address, port, state, and extension predicates."
			if command, safe := sshRateLimitCommand(rs, sshRule); safe {
				detail += " Verify that attempts which exceed the limit fall through to DROP:\n  " + command
			} else {
				detail += " No replacement command is generated because an effective ESTABLISHED,RELATED accept path was not proven; adding a limit directly could disrupt established sessions."
			}
			recs = append(recs, models.Recommendation{
				Title:    "Add rate limiting for " + stackLabel(rs.IPVersion) + " SSH",
				Detail:   detail,
				Severity: models.SeverityMedium,
				Category: "hygiene",
			})
		}
	}

	return recs
}

func firewallCommand(version models.IPVersion) string {
	if version == models.IPv6 {
		return "ip6tables"
	}
	return "iptables"
}

func stackLabel(version models.IPVersion) string {
	if version == models.IPv6 {
		return "IPv6"
	}
	return "IPv4"
}

func ipv6Recommendations(result *models.AnalysisResult) []models.Recommendation {
	var recs []models.Recommendation

	if !result.IPv4Only && (result.IPv6Rules == nil || len(result.IPv6Rules.Tables) == 0) {
		recs = append(recs, models.Recommendation{
			Title: "Configure IPv6 firewall rules",
			Detail: "No ip6tables rules detected. If IPv6 is enabled on this system, it may be completely unprotected: " +
				"hosts usually obtain global IPv6 addresses automatically, and IPv4 rules do not apply to them. " +
				"Apply the IPv6 part of the recommended baseline (see \"Recommended Baseline\" or --baseline 6); it keeps " +
				"the ICMPv6 neighbor discovery that IPv6 needs to work.",
			Severity: models.SeverityHigh,
			Category: "ipv6",
		})
	}

	return recs
}

func findSSHWithoutRateLimit(rs *models.Ruleset) *models.Rule {
	if rs == nil {
		return nil
	}
	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return nil
	}
	input, ok := filterTable.Chains["INPUT"]
	if !ok {
		return nil
	}

	limitedEarlier := false
	for i := range input.Rules {
		rule := &input.Rules[i]
		if rule.Protocol != models.ProtoTCP || rule.Negations["protocol"] || rule.DstPort != "22" || rule.Negations["dport"] {
			continue
		}
		// A preceding DROP with a rate-limiting match (hashlimit --hashlimit-above,
		// recent --update --hitcount) limits the ACCEPT that follows it.
		if rule.IsBlock() && hasRateLimit(rule) {
			limitedEarlier = true
			continue
		}
		if rule.IsAllow() && !hasRateLimit(rule) && !limitedEarlier {
			return rule
		}
	}
	return nil
}

func hasRateLimit(rule *models.Rule) bool {
	for _, m := range rule.Matches {
		if m.Module == "limit" || m.Module == "hashlimit" || m.Module == "recent" {
			return true
		}
	}
	return false
}

func sshRateLimitCommand(rs *models.Ruleset, rule *models.Rule) (string, bool) {
	matchesEstablished := len(rule.States) == 0 || rule.Negations["state"] ||
		contains(rule.States, "ESTABLISHED") || contains(rule.States, "RELATED")
	if matchesEstablished && !hasEstablishedAcceptBefore(rs, rule.RuleNum) {
		return "", false
	}
	if !overLimitTrafficIsBlocked(rs, rule) {
		return "", false
	}
	raw := strings.TrimSpace(rule.RawLine)
	if strings.HasPrefix(raw, "[") {
		if end := strings.Index(raw, "]"); end >= 0 {
			raw = strings.TrimSpace(raw[end+1:])
		}
	}
	prefix := "-A " + rule.Chain + " "
	if !strings.HasPrefix(raw, prefix) {
		return "", false
	}
	args := analyzer.RuleArgs(rule)
	targetAt := -1
	for i := 1; i+1 < len(args); i++ {
		if (args[i] == "-j" || args[i] == "--jump") && args[i+1] == "ACCEPT" {
			targetAt = i
		}
	}
	if targetAt < 0 {
		return "", false
	}
	limited := slices.Concat(args[:targetAt], []string{"-m", "limit", "--limit", "3/min", "--limit-burst", "5"}, args[targetAt:])
	return firewallCommand(rule.IPVersion) + " -R " + textsafe.ShellQuote(rule.Chain) + " " + strconv.Itoa(rule.RuleNum) + " " +
		textsafe.ShellJoin(limited), true
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

func overLimitTrafficIsBlocked(rs *models.Ruleset, candidate *models.Rule) bool {
	if rs == nil || rs.Tables["filter"] == nil || rs.Tables["filter"].Chains["INPUT"] == nil {
		return false
	}
	input := rs.Tables["filter"].Chains["INPUT"]
	for _, rule := range input.Rules {
		if rule.RuleNum <= candidate.RuleNum {
			continue
		}
		// A later allow might accept an over-limit attempt. Stay conservative
		// unless a definite catch-all block occurs first.
		if rule.IsAllow() && rulesMayOverlap(candidate, &rule) {
			return false
		}
		if rule.IsBlock() && isUnrestrictedExceptTarget(&rule) {
			return true
		}
	}
	return input.Policy == "DROP"
}

func rulesMayOverlap(a, b *models.Rule) bool {
	if !a.Negations["protocol"] && !b.Negations["protocol"] &&
		a.Protocol != "" && a.Protocol != models.ProtoAll &&
		b.Protocol != "" && b.Protocol != models.ProtoAll && a.Protocol != b.Protocol {
		return false
	}
	if !a.Negations["dport"] && !b.Negations["dport"] &&
		a.DstPort != "" && b.DstPort != "" && !portSpecsOverlap(a.DstPort, b.DstPort) {
		return false
	}
	if a.InIface != "" && b.InIface != "" && !a.Negations["in-iface"] && !b.Negations["in-iface"] &&
		!strings.HasSuffix(a.InIface, "+") && !strings.HasSuffix(b.InIface, "+") && a.InIface != b.InIface {
		return false
	}
	return true
}

func portSpecsOverlap(a, b string) bool {
	aRanges, aOK := recommendationPortRanges(a)
	bRanges, bOK := recommendationPortRanges(b)
	if !aOK || !bOK {
		return true
	}
	for _, ar := range aRanges {
		for _, br := range bRanges {
			if ar[0] <= br[1] && br[0] <= ar[1] {
				return true
			}
		}
	}
	return false
}

func recommendationPortRanges(spec string) ([][2]int, bool) {
	var ranges [][2]int
	for _, part := range strings.Split(spec, ",") {
		ends := strings.SplitN(strings.TrimSpace(part), ":", 2)
		lo, err := strconv.Atoi(ends[0])
		if err != nil || lo < 1 || lo > 65535 {
			return nil, false
		}
		hi := lo
		if len(ends) == 2 {
			hi, err = strconv.Atoi(ends[1])
			if err != nil || hi < lo || hi > 65535 {
				return nil, false
			}
		}
		ranges = append(ranges, [2]int{lo, hi})
	}
	return ranges, len(ranges) > 0
}

func hasEstablishedAcceptBefore(rs *models.Ruleset, before int) bool {
	if rs == nil || rs.Tables["filter"] == nil || rs.Tables["filter"].Chains["INPUT"] == nil {
		return false
	}
	for _, rule := range rs.Tables["filter"].Chains["INPUT"].Rules {
		if rule.RuleNum >= before {
			break
		}
		if !rule.IsAllow() || !contains(rule.States, "ESTABLISHED") || rule.Negations["state"] {
			continue
		}
		clone := rule
		clone.States = nil
		clone.Matches = withoutStateMatches(clone.Matches)
		if clone.IsAllow() && isUnrestrictedExceptTarget(&clone) {
			return true
		}
	}
	return false
}

func withoutStateMatches(matches []models.MatchExt) []models.MatchExt {
	var result []models.MatchExt
	for _, match := range matches {
		if match.Module != "conntrack" && match.Module != "state" {
			result = append(result, match)
		}
	}
	return result
}

func isUnrestrictedExceptTarget(rule *models.Rule) bool {
	return (rule.Protocol == "" || rule.Protocol == models.ProtoAll) && rule.SrcAddr == "" && rule.DstAddr == "" &&
		rule.SrcPort == "" && rule.DstPort == "" && rule.InIface == "" && rule.OutIface == "" &&
		!rule.Fragment && len(rule.Negations) == 0 && len(rule.Matches) == 0
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), wanted) {
			return true
		}
	}
	return false
}
