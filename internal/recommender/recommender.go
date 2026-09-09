package recommender

import (
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// Generate produces security recommendations based on analysis results
func Generate(result *models.AnalysisResult) []models.Recommendation {
	var recs []models.Recommendation

	recs = append(recs, policyRecommendations(result)...)
	recs = append(recs, dockerRecommendations(result)...)
	recs = append(recs, exposureRecommendations(result)...)
	recs = append(recs, hygieneRecommendations(result)...)
	recs = append(recs, ipv6Recommendations(result)...)

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
				Detail: "Install and verify required allow rules first, with a tested rollback path, then change the INPUT policy to DROP.\n" +
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

	severity := models.SeverityHigh
	for _, bypass := range result.DockerBypasses {
		if bypass.Severity == models.SeverityCritical {
			severity = models.SeverityCritical
			break
		}
	}

	// General Docker recommendation
	recs = append(recs, models.Recommendation{
		Title: "Use DOCKER-USER chain for container access control",
		Detail: "Docker manages the DOCKER chain directly. To restrict access to containerized services, " +
			"add reviewed rules to DOCKER-USER instead of INPUT. Packets are already DNATed there, " +
			"so match the published host port with conntrack --ctorigdstport or match the translated container tuple.",
		Severity: severity,
		Category: "docker",
	})

	for _, bypass := range result.DockerBypasses {
		protocol := string(bypass.NATRule.Protocol)
		if protocol == "" || protocol == string(models.ProtoAll) {
			protocol = "tcp"
		}
		command := firewallCommand(bypass.NATRule.IPVersion)
		detail := "Restrict the original published port before Docker's forwarding accept rules:\n" +
			"  " + command + " -I DOCKER-USER -i <external-interface> -p " + protocol +
			" -m conntrack --ctorigdstport " + bypass.ExposedPort + " -j DROP"
		if bypass.InputRule.RuleNum > 0 {
			detail = "The INPUT block at rule #" + strconv.Itoa(bypass.InputRule.RuleNum) +
				" does not see DNATed traffic. " + detail
		}
		recs = append(recs, models.Recommendation{
			Title:    "Restrict published port " + bypass.ExposedPort + " in DOCKER-USER",
			Detail:   detail,
			Severity: bypass.Severity,
			Category: "docker",
		})
	}

	return recs
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
		detail += "  Example allow: " + command + " -I " + chain + " -p " + string(svc.Protocol) + " --dport " +
			strconv.Itoa(svc.Port) + " -s <trusted-network> -j ACCEPT"
		recs = append(recs, models.Recommendation{
			Title:    "Restrict access to " + svc.Process + " on port " + strconv.Itoa(svc.Port),
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
			Detail: "No ip6tables rules detected. If IPv6 is enabled on this system, " +
				"it may be completely unprotected. Configure ip6tables rules to match your IPv4 policy, " +
				"or disable IPv6 if not needed:\n" +
				"  ip6tables -P INPUT DROP\n" +
				"  ip6tables -A INPUT -i lo -j ACCEPT\n" +
				"  ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
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

	for i := range input.Rules {
		rule := &input.Rules[i]
		if rule.IsAllow() && rule.Protocol == models.ProtoTCP && !rule.Negations["protocol"] &&
			rule.DstPort == "22" && !rule.Negations["dport"] {
			// Check if there's a limit match
			hasLimit := false
			for _, m := range rule.Matches {
				if m.Module == "limit" || m.Module == "hashlimit" || m.Module == "recent" {
					hasLimit = true
					break
				}
			}
			if !hasLimit {
				return rule
			}
		}
	}
	return nil
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
	body := strings.TrimPrefix(raw, prefix)
	targetAt := strings.LastIndex(body, " -j ACCEPT")
	if targetAt < 0 {
		targetAt = strings.LastIndex(body, " --jump ACCEPT")
	}
	if targetAt < 0 {
		return "", false
	}
	body = body[:targetAt] + " -m limit --limit 3/min --limit-burst 5" + body[targetAt:]
	return firewallCommand(rule.IPVersion) + " -R " + rule.Chain + " " + strconv.Itoa(rule.RuleNum) + " " + body, true
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
