package recommender

import (
	"strconv"

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
		if issue.Chain == "INPUT" && issue.Title == "INPUT default policy is ACCEPT" {
			recs = append(recs, models.Recommendation{
				Title: "Set " + stack + " INPUT chain default policy to DROP",
				Detail: "Install and verify required allow rules first, with a tested rollback path, then change the INPUT policy to DROP.\n" +
					"  Command: " + command + " -P INPUT DROP",
				Severity: models.SeverityHigh,
				Category: "policy",
			})
		}
		if issue.Chain == "FORWARD" && issue.Title == "FORWARD default policy is ACCEPT" {
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
		command := "iptables"
		if svc.IsIPv6 {
			command = "ip6tables"
		}
		detail := svc.Process + " is listening on port " + strconv.Itoa(svc.Port) + "/" +
			string(svc.Protocol) + " and is accessible from unrestricted sources. "
		if exposed.AllowingRule != nil {
			detail += "Replace or remove the permissive INPUT rule #" + strconv.Itoa(exposed.AllowingRule.RuleNum) +
				", then add a source-restricted rule and ensure unmatched traffic is dropped.\n"
		} else {
			detail += "Add a source-restricted allow rule, then ensure unmatched traffic is dropped by policy or a final rule.\n"
		}
		detail += "  Example allow: " + command + " -I INPUT -p " + string(svc.Protocol) + " --dport " +
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
		if issue.Title == "INPUT default policy is ACCEPT" {
			inputAcceptPolicy[issue.IPVersion] = true
		}
	}

	for _, issue := range result.EffectiveIssues {
		command := firewallCommand(issue.IPVersion)
		stack := stackLabel(issue.IPVersion)
		switch issue.Title {
		case "No conntrack ESTABLISHED,RELATED rule in INPUT":
			recs = append(recs, models.Recommendation{
				Title:    "Add " + stack + " conntrack rule for established connections",
				Detail:   "Add an early rule to accept established/related connections for better performance:\n  " + command + " -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
				Severity: models.SeverityMedium,
				Category: "hygiene",
			})
		case "No explicit DROP at end of INPUT chain with ACCEPT policy":
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

	// Check for SSH rate limiting
	if sshRule := findSSHWithoutRateLimit(result.IPv4Rules); sshRule != nil {
		recs = append(recs, models.Recommendation{
			Title: "Add rate limiting for SSH",
			Detail: "Replace unrestricted SSH ACCEPT rule #" + strconv.Itoa(sshRule.RuleNum) +
				" with a rate-limited rule, and verify that attempts which exceed the limit fall through to DROP:\n" +
				"  iptables -R INPUT " + strconv.Itoa(sshRule.RuleNum) +
				" -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 5 -j ACCEPT",
			Severity: models.SeverityMedium,
			Category: "hygiene",
		})
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
		if rule.IsAllow() && rule.Protocol == models.ProtoTCP && rule.DstPort == "22" &&
			(rule.SrcAddr == "" || rule.SrcAddr == "0.0.0.0/0") && !rule.Negations["src"] {
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
