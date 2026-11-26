package ui

import (
	"sort"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/report"
)

// fixFirstCount is the number of findings that the reports name as the
// place to start.
const fixFirstCount = 3

// fixFirst returns the findings to start with: first those whose fix alone
// gives a better grade, then those that gain the most points. A report with
// one such finding needs no list.
func fixFirst(rep *report.Report) []report.Finding {
	var top []report.Finding
	for _, finding := range rep.Findings {
		// A port that is open by its purpose is not what to start with.
		if finding.Points > 0 && finding.Fix != nil && finding.Severity >= models.SeverityMedium {
			top = append(top, finding)
		}
	}
	if len(top) < 2 {
		return nil
	}
	rank := func(finding report.Finding) int {
		if finding.GradeAfter == "" {
			return len("ABCDF")
		}
		return strings.Index("ABCDF", finding.GradeAfter)
	}
	// The findings arrive ordered by severity, which decides between equals.
	sort.SliceStable(top, func(i, j int) bool {
		if rank(top[i]) != rank(top[j]) {
			return rank(top[i]) < rank(top[j])
		}
		if top[i].Gain != top[j].Gain {
			return top[i].Gain > top[j].Gain
		}
		return top[i].Points > top[j].Points
	})
	return top[:min(len(top), fixFirstCount)]
}

// gainText says what the fix of one finding does to the score.
func gainText(finding report.Finding) string {
	switch {
	case finding.GradeAfter != "" && finding.Gain > 0:
		return "+" + strconv.Itoa(finding.Gain) + ", grade " + finding.GradeAfter
	case finding.GradeAfter != "":
		return "grade " + finding.GradeAfter
	case finding.Gain > 0:
		return "+" + strconv.Itoa(finding.Gain)
	}
	return ""
}

// familyNames renders "IPv4" or "IPv4 and IPv6".
func familyNames(families []int) string {
	names := make([]string, len(families))
	for i, family := range families {
		names[i] = "IPv" + strconv.Itoa(family)
	}
	return strings.Join(names, " and ")
}

func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// scopeWords says who reaches a port.
func scopeWords(scope models.AccessScope) string {
	switch scope {
	case models.ScopeExposed:
		return "any source"
	case models.ScopeSubnet:
		return "specific public networks"
	case models.ScopeRestricted:
		return "sources that were not evaluated"
	case models.ScopeLocalnet:
		return "private networks"
	case models.ScopeWhitelisted:
		return "single hosts"
	}
	return "no source"
}

func portRange(first, last int) string {
	if last > first {
		return strconv.Itoa(first) + "-" + strconv.Itoa(last)
	}
	return strconv.Itoa(first)
}

// bracket puts an IPv6 address in brackets, for use in front of a port.
func bracket(addr string) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]"
	}
	return addr
}

// analyzedFamilies is the number of address families that the report covers.
func analyzedFamilies(rep *report.Report) int {
	covered := 0
	for _, family := range rep.Families {
		if family.Status == string(models.FamilyAnalyzed) || family.Status == string(models.FamilyNoRules) {
			covered++
		}
	}
	return covered
}

// familySummary describes one address family of the input in one line, and
// says whether the line is a warning.
func familySummary(family report.Family) (text string, warning bool) {
	switch family.Status {
	case string(models.FamilyAnalyzed):
		text = countNoun(family.Rules, "rule") + " in " + countNoun(family.Chains, "chain")
		if len(family.Managers) > 0 {
			text += " (" + strings.Join(family.Managers, ", ") + ")"
		}
		for _, chain := range []string{"INPUT", "FORWARD", "OUTPUT"} {
			if policy := family.Policies[chain]; policy != "" {
				text += " · " + chain + " " + policy
			}
		}
		return text, false
	case string(models.FamilyNoRules):
		return "no rules are loaded, all traffic is accepted", true
	case string(models.FamilyUnreadable):
		return "not analyzed, native nftables rules", true
	case string(models.FamilyNotSupplied):
		return "not supplied", false
	}
	return "", false
}

// sourceText says where the input came from.
func sourceText(rep *report.Report) string {
	if rep.Mode != "live" {
		return "file analysis"
	}
	if rep.Host != "" {
		return "live system " + rep.Host
	}
	return "live system"
}

// timeText renders the time of the report without seconds and zone.
func timeText(rep *report.Report) string {
	when := rep.Generated
	if len(when) >= 16 {
		when = strings.Replace(when[:16], "T", " ", 1)
	}
	return when
}

// sandboxSummary says how the process that read the input was confined.
func sandboxSummary(status *report.Sandbox) (text string, warning bool) {
	switch {
	case status.Mode == "off":
		return "off", true
	case status.Landlock:
		text = "Landlock ABI " + strconv.Itoa(status.LandlockABI) + " (" + strings.Join(status.Restricted, ", ") + ")"
		if status.PrivilegesDropped {
			text += ", root privileges dropped"
		}
		return text, false
	}
	return "Landlock is not available", true
}
