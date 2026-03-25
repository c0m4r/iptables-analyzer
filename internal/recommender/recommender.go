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
		if issue.Chain == "INPUT" && issue.Title == "INPUT default policy is ACCEPT" {
			recs = append(recs, models.Recommendation{
				Title:    "Set INPUT chain default policy to DROP",
				Detail:   "Change the INPUT chain policy to DROP and explicitly allow needed services. This follows the principle of least privilege.\n  Command: iptables -P INPUT DROP",
				Severity: models.SeverityHigh,
				Category: "policy",
			})
		}
		if issue.Chain == "FORWARD" && issue.Title == "FORWARD default policy is ACCEPT" {
			recs = append(recs, models.Recommendation{
				Title:    "Set FORWARD chain default policy to DROP",
				Detail:   "Change the FORWARD chain policy to DROP. This is especially important with Docker, as it prevents unrestricted container traffic.\n  Command: iptables -P FORWARD DROP",
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

	// General Docker recommendation
	recs = append(recs, models.Recommendation{
		Title: "Use DOCKER-USER chain for container access control",
		Detail: "Docker manages the DOCKER chain directly. To restrict access to containerized services, " +
			"add rules to the DOCKER-USER chain instead of INPUT.\n" +
			"  Example: iptables -I DOCKER-USER -i eth0 -p tcp --dport 80 -j DROP\n" +
			"  This chain is processed before Docker's own rules and persists across container restarts.",
		Severity: models.SeverityCritical,
		Category: "docker",
	})

	for _, bypass := range result.DockerBypasses {
		if bypass.InputRule.RuleNum > 0 {
			recs = append(recs, models.Recommendation{
				Title: "Move port " + bypass.ExposedPort + " block from INPUT to DOCKER-USER",
				Detail: "The block on port " + bypass.ExposedPort + " in INPUT (rule #" +
					strconv.Itoa(bypass.InputRule.RuleNum) + ") is ineffective because Docker DNAT " +
					"bypasses INPUT. Move this rule to the DOCKER-USER chain:\n" +
					"  iptables -I DOCKER-USER -i eth0 -p tcp --dport " + bypass.ExposedPort + " -j DROP",
				Severity: models.SeverityCritical,
				Category: "docker",
			})
		}
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
		recs = append(recs, models.Recommendation{
			Title: "Restrict access to " + svc.Process + " on port " + strconv.Itoa(svc.Port),
			Detail: svc.Process + " is listening on port " + strconv.Itoa(svc.Port) + "/" +
				string(svc.Protocol) + " and is accessible from any source. " +
				"Consider restricting access to specific IP ranges:\n" +
				"  iptables -A INPUT -p " + string(svc.Protocol) + " --dport " +
				strconv.Itoa(svc.Port) + " -s <trusted-network> -j ACCEPT",
			Severity: exposed.Severity,
			Category: "exposure",
		})
	}

	return recs
}

func hygieneRecommendations(result *models.AnalysisResult) []models.Recommendation {
	var recs []models.Recommendation

	for _, issue := range result.EffectiveIssues {
		switch issue.Title {
		case "No conntrack ESTABLISHED,RELATED rule in INPUT":
			recs = append(recs, models.Recommendation{
				Title:    "Add conntrack rule for established connections",
				Detail:   "Add an early rule to accept established/related connections for better performance:\n  iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
				Severity: models.SeverityMedium,
				Category: "hygiene",
			})
		case "No explicit DROP at end of INPUT chain with ACCEPT policy":
			recs = append(recs, models.Recommendation{
				Title:    "Add explicit DROP at end of INPUT or change policy",
				Detail:   "Either change the INPUT policy to DROP or add a catch-all rule:\n  iptables -A INPUT -j DROP\n  Or: iptables -P INPUT DROP",
				Severity: models.SeverityHigh,
				Category: "hygiene",
			})
		}
	}

	// Check for SSH rate limiting
	if hasSSHWithoutRateLimit(result.IPv4Rules) {
		recs = append(recs, models.Recommendation{
			Title:    "Add rate limiting for SSH",
			Detail:   "SSH (port 22) is allowed without rate limiting. Add rate limiting to mitigate brute-force attacks:\n  iptables -I INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 5 -j ACCEPT",
			Severity: models.SeverityMedium,
			Category: "hygiene",
		})
	}

	return recs
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

func hasSSHWithoutRateLimit(rs *models.Ruleset) bool {
	if rs == nil {
		return false
	}
	filterTable, ok := rs.Tables["filter"]
	if !ok {
		return false
	}
	input, ok := filterTable.Chains["INPUT"]
	if !ok {
		return false
	}

	for _, rule := range input.Rules {
		if rule.IsAllow() && rule.Protocol == models.ProtoTCP && rule.DstPort == "22" {
			// Check if there's a limit match
			hasLimit := false
			for _, m := range rule.Matches {
				if m.Module == "limit" || m.Module == "hashlimit" || m.Module == "recent" {
					hasLimit = true
					break
				}
			}
			if !hasLimit {
				return true
			}
		}
	}
	return false
}
