package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/charmbracelet/lipgloss"
)

// ──────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────

// RenderOptions controls rendering behavior
type RenderOptions struct {
	NoColor  bool
	Verbose  bool
	JSON     bool
	LiveMode bool
	Version  string
}

// Render outputs the full analysis to stdout
func Render(result *models.AnalysisResult, opts RenderOptions) {
	if opts.JSON {
		renderJSON(result)
		return
	}

	w := os.Stdout

	renderBanner(w, opts.Version)
	renderHeader(w, opts)
	renderOverview(w, result)
	renderRules(w, result, opts.Verbose)
	renderFindingsAndRecommendations(w, result)
	if len(result.Services) > 0 {
		renderServiceTable(w, result)
	}
	renderScore(w, result.Score)
}

// RenderScoreOnly prints just the score
func RenderScoreOnly(result *models.AnalysisResult, opts RenderOptions) {
	if opts.JSON {
		renderJSON(result.Score)
		return
	}
	renderScore(os.Stdout, result.Score)
}

func renderJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// ──────────────────────────────────────────────────────────────
// Banner & header
// ──────────────────────────────────────────────────────────────

const repoURL = "https://github.com/c0m4r/iptables-analyzer"

func renderBanner(w io.Writer, version string) {
	art := strings.Join([]string{
		"╦╔═╗╔╦╗╔═╗╔╗ ╦  ╔═╗╔═╗  ╔═╗╔╗╔╔═╗╦  ╦ ╦╔═╗╔═╗╦═╗",
		"║╠═╝ ║ ╠═╣╠╩╗║  ║╣ ╚═╗  ╠═╣║║║╠═╣║  ╚╦╝╔═╝║╣ ╠╦╝",
		"╩╩   ╩ ╩ ╩╚═╝╩═╝╚═╝╚═╝  ╩ ╩╝╚╝╩ ╩╩═╝ ╩ ╚═╝╚═╝╩╚═",
	}, "\n")

	var meta string
	if version != "" {
		meta = styleMuted.Render("v"+version) + "  " + styleFaint.Render(repoURL)
	} else {
		meta = styleFaint.Render(repoURL)
	}

	content := lipgloss.NewStyle().Foreground(accent).Bold(true).Render(art) + "\n" + meta

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(faint).
		Padding(0, 3).
		Render(content)

	fmt.Fprintln(w, box)
	fmt.Fprintln(w)
}

func renderHeader(w io.Writer, opts RenderOptions) {
	mode := "file"
	if opts.LiveMode {
		mode = "live system"
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintln(w, styleMuted.Render(fmt.Sprintf("  mode: %s  │  %s", mode, ts)))
	fmt.Fprintln(w)
}

// ──────────────────────────────────────────────────────────────
// Section header — thin left accent + title + faint rule
// ──────────────────────────────────────────────────────────────

func renderSectionHeader(w io.Writer, title string) {
	titleRendered := styleHeader.Render(title)
	titleWidth := lipgloss.Width(titleRendered)
	fill := max(0, 68-titleWidth)
	fmt.Fprintf(w, "  %s %s\n\n", titleRendered, styleFaint.Render(strings.Repeat("─", fill)))
}

// ──────────────────────────────────────────────────────────────
// Overview
// ──────────────────────────────────────────────────────────────

func renderOverview(w io.Writer, result *models.AnalysisResult) {
	renderSectionHeader(w, "Overview")

	if result.IPv4Rules != nil {
		renderRulesetOverview(w, result.IPv4Rules, "IPv4")
	}
	if result.IPv6Rules != nil && len(result.IPv6Rules.Tables) > 0 {
		renderRulesetOverview(w, result.IPv6Rules, "IPv6")
	}

	fmt.Fprintln(w)

	exposedCount := countExposed(result)
	totalFindings := len(result.ShadowedRules) + len(result.DockerBypasses) +
		exposedCount + len(result.EffectiveIssues)

	if totalFindings == 0 {
		fmt.Fprintf(w, "  Findings:        %s\n", styleSuccess.Render("none"))
	} else {
		parts := []string{}
		if n := len(result.DockerBypasses); n > 0 {
			parts = append(parts, styleDanger.Render(fmt.Sprintf("%d docker bypasses", n)))
		}
		if n := len(result.ShadowedRules); n > 0 {
			parts = append(parts, styleWarning.Render(fmt.Sprintf("%d shadowed rules", n)))
		}
		if exposedCount > 0 {
			parts = append(parts, styleDanger.Render(fmt.Sprintf("%d exposed services", exposedCount)))
		}
		if n := len(result.EffectiveIssues); n > 0 {
			parts = append(parts, styleMuted.Render(fmt.Sprintf("%d effectiveness", n)))
		}
		summary := strings.Join(parts, styleFaint.Render(" · "))
		fmt.Fprintf(w, "  Findings:        %s  %s\n",
			styleWarning.Render(strconv.Itoa(totalFindings)), summary)
	}

	fmt.Fprintf(w, "  Recommendations: %s\n", styleMuted.Render(strconv.Itoa(len(result.Recommendations))))
	fmt.Fprintln(w)
}

func renderRulesetOverview(w io.Writer, rs *models.Ruleset, label string) {
	totalRules := 0
	totalChains := 0
	for _, table := range rs.Tables {
		for _, chain := range table.Chains {
			totalChains++
			totalRules += len(chain.Rules)
		}
	}

	fmt.Fprintf(w, "  %s  %s\n",
		styleBold.Render(label),
		styleMuted.Render(fmt.Sprintf("%d table · %d chains · %d rules", len(rs.Tables), totalChains, totalRules)),
	)

	if filterTable, ok := rs.Tables["filter"]; ok {
		var policies []string
		for _, name := range []string{"INPUT", "FORWARD", "OUTPUT"} {
			if chain, ok := filterTable.Chains[name]; ok {
				policy := chain.Policy
				if policy == "" {
					policy = "-"
				}
				label := styleMuted.Render(name + ":")
				var policyRendered string
				switch policy {
				case "DROP":
					policyRendered = styleSuccess.Render(policy)
				case "ACCEPT":
					policyRendered = styleWarning.Render(policy)
				default:
					policyRendered = styleMuted.Render(policy)
				}
				policies = append(policies, label+policyRendered)
			}
		}
		if len(policies) > 0 {
			fmt.Fprintf(w, "         %s\n", strings.Join(policies, "  "))
		}
	}
}

// ──────────────────────────────────────────────────────────────
// Firewall rules
// ──────────────────────────────────────────────────────────────

func renderRules(w io.Writer, result *models.AnalysisResult, verbose bool) {
	renderSectionHeader(w, "Firewall Rules")

	if result.IPv4Rules != nil {
		renderRulesetTables(w, result.IPv4Rules, "IPv4", verbose)
	}
	if result.IPv6Rules != nil && len(result.IPv6Rules.Tables) > 0 {
		renderRulesetTables(w, result.IPv6Rules, "IPv6", verbose)
	}
}

func renderRulesetTables(w io.Writer, rs *models.Ruleset, label string, verbose bool) {
	fmt.Fprintln(w, styleBold.Render("  ["+label+"]"))

	tableOrder := []string{"filter", "nat", "mangle", "raw"}
	shown := map[string]bool{}

	for _, tableName := range tableOrder {
		table, ok := rs.Tables[tableName]
		if !ok {
			continue
		}
		shown[tableName] = true
		renderTableChains(w, table, verbose)
	}

	for tableName, table := range rs.Tables {
		if shown[tableName] {
			continue
		}
		renderTableChains(w, table, verbose)
	}
}

func renderTableChains(w io.Writer, table *models.Table, verbose bool) {
	chainOrder := []string{"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}
	shown := map[string]bool{}

	for _, chainName := range chainOrder {
		chain, ok := table.Chains[chainName]
		if !ok {
			continue
		}
		shown[chainName] = true
		if verbose || len(chain.Rules) > 0 {
			renderRuleTable(w, chain, table.Name, verbose)
		}
	}

	for chainName, chain := range table.Chains {
		if shown[chainName] {
			continue
		}
		if verbose || len(chain.Rules) > 0 {
			renderRuleTable(w, chain, table.Name, verbose)
		}
	}
}

// ──────────────────────────────────────────────────────────────
// Score — categories + grade card side-by-side
// ──────────────────────────────────────────────────────────────

var categoryMax = map[string]int{
	"policy":   30,
	"exposure": 30,
	"shadow":   20,
	"hygiene":  15,
	"ipv6":     10,
}

func renderScore(w io.Writer, score models.ScoreResult) {
	renderSectionHeader(w, "Security Score")

	categories := []struct {
		name  string
		label string
	}{
		{"policy", "Policy"},
		{"exposure", "Exposure"},
		{"shadow", "Shadows/Bypasses"},
		{"hygiene", "Hygiene"},
		{"ipv6", "IPv6"},
	}

	var catLines []string
	for _, cat := range categories {
		deduct := score.Breakdown[cat.name]
		mx := categoryMax[cat.name]
		retained := mx + deduct
		if retained < 0 {
			retained = 0
		}
		bar := renderHealthBar(retained, mx)
		label := styleMuted.Render(fmt.Sprintf("  %-18s", cat.label))
		var valStyle lipgloss.Style
		switch {
		case retained >= mx:
			valStyle = styleSuccess
		case retained == 0:
			valStyle = styleDanger
		default:
			valStyle = styleWarning
		}
		catLines = append(catLines, fmt.Sprintf(
			"%s %s %s",
			label,
			bar,
			valStyle.Render(fmt.Sprintf("%2d/%d", retained, mx)),
		))
	}
	catsBlock := strings.Join(catLines, "\n")

	// Grade card
	gc := gradeColor(score.Grade)
	gs := gradeStyle(score.Grade)
	gradeCard := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(gc).
		Padding(0, 2).
		AlignHorizontal(lipgloss.Center).
		Width(12).
		Render(
			gs.Render(score.Grade) + "\n" +
				styleMuted.Render(strconv.Itoa(score.Total)+"/100"),
		)

	fmt.Fprintln(w, lipgloss.JoinHorizontal(lipgloss.Center, catsBlock, "  ", gradeCard))
	fmt.Fprintln(w)
}

func renderHealthBar(retained, mx int) string {
	const width = 20
	filled := 0
	if mx > 0 {
		filled = retained * width / mx
	}
	if filled > width {
		filled = width
	}
	empty := width - filled

	var barColor lipgloss.Color
	switch {
	case mx == 0 || retained >= mx:
		barColor = green
	case float64(retained)/float64(mx) >= 0.5:
		barColor = yellow
	default:
		barColor = red
	}

	return lipgloss.NewStyle().Foreground(barColor).Render(strings.Repeat("━", filled)) +
		styleFaint.Render(strings.Repeat("━", empty))
}

// ──────────────────────────────────────────────────────────────
// Findings & recommendations
// ──────────────────────────────────────────────────────────────

// shadowGroup bundles multiple shadowed rules under the same shadowing rule
type shadowGroup struct {
	shadowingRule models.Rule
	shadowedNums  []int
	shadowedChain string
	shadowedTable string
	severity      models.Severity
}

func groupShadowFindings(findings []models.ShadowFinding) []shadowGroup {
	type key struct {
		table, chain string
		ruleNum      int
	}
	groups := map[key]*shadowGroup{}
	var order []key

	for _, f := range findings {
		k := key{f.ShadowingRule.Table, f.ShadowingRule.Chain, f.ShadowingRule.RuleNum}
		if _, ok := groups[k]; !ok {
			groups[k] = &shadowGroup{
				shadowingRule: f.ShadowingRule,
				shadowedChain: f.ShadowedRule.Chain,
				shadowedTable: f.ShadowedRule.Table,
				severity:      f.Severity,
			}
			order = append(order, k)
		}
		g := groups[k]
		g.shadowedNums = append(g.shadowedNums, f.ShadowedRule.RuleNum)
		if f.Severity > g.severity {
			g.severity = f.Severity
		}
	}

	result := make([]shadowGroup, 0, len(order))
	for _, k := range order {
		result = append(result, *groups[k])
	}
	return result
}

func formatShadowedNums(nums []int) string {
	sort.Ints(nums)
	if len(nums) == 1 {
		return fmt.Sprintf("#%d", nums[0])
	}
	sequential := true
	for i := 1; i < len(nums); i++ {
		if nums[i] != nums[i-1]+1 {
			sequential = false
			break
		}
	}
	if sequential {
		return fmt.Sprintf("#%d–#%d", nums[0], nums[len(nums)-1])
	}
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = fmt.Sprintf("#%d", n)
	}
	return strings.Join(parts, ", ")
}

type effectKey struct{ title, detail string }

func deduplicateEffectivenessIssues(issues []models.EffectivenessFinding) []models.EffectivenessFinding {
	seen := map[effectKey]bool{}
	var result []models.EffectivenessFinding
	for _, iss := range issues {
		k := effectKey{iss.Title, iss.Detail}
		if !seen[k] {
			seen[k] = true
			result = append(result, iss)
		}
	}
	return result
}

func renderFindingsAndRecommendations(w io.Writer, result *models.AnalysisResult) {
	exposedOnlyCount := countExposed(result)
	totalFindings := len(result.ShadowedRules) + len(result.DockerBypasses) +
		exposedOnlyCount + len(result.EffectiveIssues) + len(result.UnusedRules)

	if totalFindings == 0 && len(result.Recommendations) == 0 {
		return
	}

	renderSectionHeader(w, "Issues & Recommendations")

	// Docker bypasses
	if len(result.DockerBypasses) > 0 {
		renderSubSection(w, "Docker NAT Bypasses", len(result.DockerBypasses))
		for _, f := range result.DockerBypasses {
			renderFindingRow(w, f.Severity.String(), f.Reason, "")
		}
		fmt.Fprintln(w)
	}

	// Shadowed rules (grouped)
	if len(result.ShadowedRules) > 0 {
		groups := groupShadowFindings(result.ShadowedRules)
		renderSubSection(w, "Shadowed Rules", len(result.ShadowedRules))
		for _, g := range groups {
			nums := formatShadowedNums(g.shadowedNums)
			var msg string
			if len(g.shadowedNums) == 1 {
				msg = fmt.Sprintf("Rule %s in %s/%s is shadowed by rule #%d",
					nums, g.shadowedTable, g.shadowedChain, g.shadowingRule.RuleNum)
			} else {
				msg = fmt.Sprintf("Rules %s in %s/%s (%d rules) shadowed by rule #%d",
					nums, g.shadowedTable, g.shadowedChain, len(g.shadowedNums), g.shadowingRule.RuleNum)
			}
			renderFindingRow(w, g.severity.String(), msg, "Shadowing rule: "+g.shadowingRule.Summary())
		}
		fmt.Fprintln(w)
	}

	// Exposed services (only truly EXPOSED scope — LOCALNET/WHITELISTED shown in service table)
	if exposedOnlyCount > 0 {
		renderSubSection(w, "Exposed Services", exposedOnlyCount)
		for _, f := range result.ExposedServices {
			if f.Scope == models.ScopeExposed {
				renderFindingRow(w, f.Severity.String(), f.Reason, "")
			}
		}
		fmt.Fprintln(w)
	}

	// Effectiveness issues
	deduped := deduplicateEffectivenessIssues(result.EffectiveIssues)
	if len(deduped) > 0 {
		renderSubSection(w, "Effectiveness Issues", len(deduped))
		for _, f := range deduped {
			renderFindingRow(w, f.Severity.String(), f.Title, f.Detail)
		}
		fmt.Fprintln(w)
	}

	// Unused rules
	if len(result.UnusedRules) > 0 {
		renderSubSection(w, "Unused Rules", len(result.UnusedRules))
		for _, f := range result.UnusedRules {
			renderFindingRow(w, "INFO", f.Reason, "")
		}
		fmt.Fprintln(w)
	}

	// Recommendations
	if len(result.Recommendations) > 0 {
		renderSubSection(w, "Recommendations", len(result.Recommendations))
		for i, rec := range result.Recommendations {
			ss := severityStyle(rec.Severity.String())
			badge := ss.Render("[" + rec.Severity.String() + "]")
			num := styleMuted.Render(fmt.Sprintf("%d.", i+1))
			fmt.Fprintf(w, "    %s %s %s\n", num, badge, styleText.Render(rec.Title))
			fmt.Fprintf(w, "       %s\n", styleMuted.Render(rec.Category))
			for _, line := range strings.Split(rec.Detail, "\n") {
				fmt.Fprintf(w, "       %s\n", styleMuted.Render(line))
			}
			fmt.Fprintln(w)
		}
	}
}

func renderSubSection(w io.Writer, title string, count int) {
	fmt.Fprintf(w, "  %s %s\n\n",
		styleSubHeader.Render(title),
		styleMuted.Render(fmt.Sprintf("(%d)", count)),
	)
}

var severityIcon = map[string]string{
	"CRITICAL": "✖",
	"HIGH":     "▲",
	"MEDIUM":   "●",
	"LOW":      "◇",
	"INFO":     "·",
}

func renderFindingRow(w io.Writer, severity, message, detail string) {
	ss := severityStyle(severity)
	icon := severityIcon[severity]
	if icon == "" {
		icon = "·"
	}
	fmt.Fprintf(w, "    %s %-8s %s\n",
		ss.Render(icon),
		ss.Render(severity),
		styleText.Render(message),
	)
	if detail != "" {
		fmt.Fprintf(w, "               %s\n", styleMuted.Render("↳ "+detail))
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// countExposed returns the number of findings with ScopeExposed (truly open services).
func countExposed(result *models.AnalysisResult) int {
	n := 0
	for _, f := range result.ExposedServices {
		if f.Scope == models.ScopeExposed {
			n++
		}
	}
	return n
}
