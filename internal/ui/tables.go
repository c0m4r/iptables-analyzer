package ui

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/charmbracelet/lipgloss"
	lgtable "github.com/charmbracelet/lipgloss/table"
)

// ──────────────────────────────────────────────────────────────
// Rule table  —  borderless, compact, indented under chain name
// ──────────────────────────────────────────────────────────────

func renderRuleTable(w io.Writer, chain *models.Chain, tableName string, verbose bool) {
	if len(chain.Rules) == 0 && !verbose {
		return
	}

	policyStr := chain.Policy
	if policyStr == "" {
		policyStr = "-"
	}

	// Chain header: "filter/INPUT  (policy: DROP)"
	var policyStyle lipgloss.Style
	switch policyStr {
	case "DROP":
		policyStyle = styleSuccess
	case "ACCEPT":
		policyStyle = styleWarning
	default:
		policyStyle = styleMuted
	}
	fmt.Fprintf(w, "  %s  %s\n",
		styleSubHeader.Render(tableName+"/"+chain.Name),
		styleMuted.Render("policy: ")+policyStyle.Render(policyStr),
	)

	if len(chain.Rules) == 0 {
		fmt.Fprintln(w, styleMuted.Render("    (no rules)"))
		fmt.Fprintln(w)
		return
	}

	rows := make([][]string, 0, len(chain.Rules))
	for _, rule := range chain.Rules {
		num := strconv.Itoa(rule.RuleNum)
		target := rule.Target
		if rule.Goto {
			target = "goto:" + target
		}
		proto := string(rule.Protocol)
		if proto == "" {
			proto = "all"
		}
		if rule.Negations["protocol"] {
			proto = "!" + proto
		}

		src := rule.SrcAddr
		if src == "" || src == "0.0.0.0/0" || src == "::/0" {
			src = "*"
		}
		if rule.Negations["src"] {
			src = "!" + src
		}

		dst := rule.DstAddr
		if dst == "" || dst == "0.0.0.0/0" || dst == "::/0" {
			dst = "*"
		}
		if rule.Negations["dst"] {
			dst = "!" + dst
		}

		port := formatPort(rule)
		opts := formatOptions(rule, verbose)

		var targetStr string
		switch target {
		case "ACCEPT":
			targetStr = styleAccept.Render(target)
		case "DROP":
			targetStr = styleDrop.Render(target)
		case "REJECT":
			targetStr = styleReject.Render(target)
		default:
			targetStr = styleMuted.Render(target)
		}

		rows = append(rows, []string{num, targetStr, proto, src, dst, port, opts})
	}

	t := lgtable.New().
		Border(lipgloss.HiddenBorder()).
		BorderHeader(true).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == lgtable.HeaderRow {
				return lipgloss.NewStyle().Foreground(muted).Padding(0, 1)
			}
			return lipgloss.NewStyle().Foreground(text).Padding(0, 1)
		}).
		Headers("#", "TARGET", "PROTO", "SRC", "DST", "PORT", "OPTIONS").
		Rows(rows...)

	fmt.Fprintln(w, indentBlock(t.String(), "    "))
	fmt.Fprintln(w)
}

// ──────────────────────────────────────────────────────────────
// Service table  —  rounded border, header separator
// ──────────────────────────────────────────────────────────────

func renderServiceTable(w io.Writer, result *models.AnalysisResult) {
	if len(result.Services) == 0 {
		return
	}

	renderSectionHeader(w, "Listening Services")

	rows := make([][]string, 0, len(result.Services))
	for _, svc := range result.Services {
		port := strconv.Itoa(svc.Port)
		proto := string(svc.Protocol)
		addr := svc.Address
		process := svc.Process
		if process == "" {
			process = "-"
		}
		pid := "-"
		if svc.PID > 0 {
			pid = strconv.Itoa(svc.PID)
		}
		status := getServiceStatus(svc, result)
		rows = append(rows, []string{port, proto, addr, process, pid, status})
	}

	t := lgtable.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(styleTableBorder).
		BorderRow(false).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == lgtable.HeaderRow {
				return lipgloss.NewStyle().Foreground(muted).Bold(true).Padding(0, 1)
			}
			return lipgloss.NewStyle().Foreground(text).Padding(0, 1)
		}).
		Headers("PORT", "PROTO", "ADDRESS", "PROCESS", "PID", "STATUS").
		Rows(rows...)

	fmt.Fprintln(w, indentBlock(t.String(), "  "))
	fmt.Fprintln(w)
}

func getServiceStatus(svc models.ListeningService, result *models.AnalysisResult) string {
	if svc.Status == models.ServiceLocalhost {
		return styleSuccess.Render("LOCALHOST")
	}
	if !svc.IsWildcard {
		if svc.Address == "127.0.0.1" || svc.Address == "::1" {
			return styleSuccess.Render("LOCALHOST")
		}
	}
	if svc.Status == models.ServiceNotAnalyzed {
		return styleMuted.Render("NOT ANALYZED")
	}
	if svc.Status == models.ServiceFiltered {
		return styleSuccess.Render("FILTERED")
	}
	if svc.Status == models.ServiceDocker {
		best := models.AccessScope("")
		for _, mapping := range result.PublishedPorts {
			if mapping.Protocol == svc.Protocol && mapping.HostPort == svc.Port && scopeRankUI(mapping.ForwardScope) > scopeRankUI(best) {
				best = mapping.ForwardScope
			}
		}
		if best == "" {
			return styleSuccess.Render("DOCKER: BLOCKED")
		}
		return styleDanger.Render("DOCKER: " + string(best))
	}

	best := models.AccessScope("")
	for _, exposed := range result.ExposedServices {
		if exposed.Service.Port == svc.Port &&
			exposed.Service.Protocol == svc.Protocol && serviceAddressesMatch(svc, exposed.Service) &&
			scopeRankUI(exposed.Scope) > scopeRankUI(best) {
			best = exposed.Scope
		}
	}
	switch best {
	case models.ScopeExposed:
		return styleDanger.Render("EXPOSED")
	case models.ScopeSubnet:
		return styleWarning.Render("SUBNET")
	case models.ScopeLocalnet:
		return styleWarning.Render("LOCALNET")
	case models.ScopeWhitelisted:
		return styleSuccess.Render("WHITELISTED")
	default:
		return styleMuted.Render("NOT ANALYZED")
	}
}

func serviceAddressesMatch(inventory, finding models.ListeningService) bool {
	if inventory.Family == models.SocketDual {
		return finding.IsWildcard
	}
	return inventory.Address == finding.Address
}

// ──────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────

func indentBlock(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}

func formatPort(rule models.Rule) string {
	parts := []string{}
	if rule.DstPort != "" {
		prefix := "dpt:"
		if rule.Negations["dport"] {
			prefix = "!dpt:"
		}
		parts = append(parts, prefix+rule.DstPort)
	}
	if rule.SrcPort != "" {
		prefix := "spt:"
		if rule.Negations["sport"] {
			prefix = "!spt:"
		}
		parts = append(parts, prefix+rule.SrcPort)
	}
	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	return ""
}

func formatOptions(rule models.Rule, verbose bool) string {
	var opts []string

	if rule.InIface != "" {
		prefix := "in:"
		if rule.Negations["in-iface"] {
			prefix = "!in:"
		}
		opts = append(opts, prefix+rule.InIface)
	}
	if rule.OutIface != "" {
		prefix := "out:"
		if rule.Negations["out-iface"] {
			prefix = "!out:"
		}
		opts = append(opts, prefix+rule.OutIface)
	}
	if len(rule.States) > 0 {
		prefix := "state:"
		if rule.Negations["state"] {
			prefix = "!state:"
		}
		opts = append(opts, prefix+strings.Join(rule.States, ","))
	}
	if rule.Fragment {
		fragment := "fragment"
		if rule.Negations["fragment"] {
			fragment = "!fragment"
		}
		opts = append(opts, fragment)
	}
	if rule.DNATTarget != "" {
		opts = append(opts, "to:"+rule.DNATTarget)
	}
	if rule.Comment != "" {
		opts = append(opts, "/* "+rule.Comment+" */")
	}
	for _, match := range rule.Matches {
		if match.Module == "comment" || isDisplayDuplicate(match) {
			continue
		}
		tokens := append([]string{"-m", match.Module}, match.RawTokens...)
		if match.Module == "raw" {
			tokens = append([]string{}, match.RawTokens...)
		}
		opts = append(opts, strings.Join(tokens, " "))
	}
	if verbose && rule.RawLine != "" {
		opts = append(opts, "raw: "+rule.RawLine)
	}

	return strings.Join(opts, " ")
}

func isDisplayDuplicate(match models.MatchExt) bool {
	for option := range match.Params {
		switch option {
		case "--dport", "--destination-port", "--sport", "--source-port", "--dports", "--destination-ports", "--sports", "--source-ports", "--ctstate", "--state", "--comment":
		default:
			return false
		}
	}
	switch match.Module {
	case "tcp", "udp", "multiport", "conntrack", "state":
		return true
	default:
		return false
	}
}

func scopeRankUI(scope models.AccessScope) int {
	switch scope {
	case models.ScopeExposed:
		return 4
	case models.ScopeSubnet:
		return 3
	case models.ScopeLocalnet:
		return 2
	case models.ScopeWhitelisted:
		return 1
	}
	return 0
}
