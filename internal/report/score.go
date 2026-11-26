package report

import "strings"

// categoryLimits are the parts of the score and the most that each can lose.
var categoryLimits = []Category{
	{Key: "policy", Label: "Policy", Max: 25},
	{Key: "exposure", Label: "Exposure", Max: 25},
	{Key: "paths", Label: "Shadows and bypasses", Max: 25},
	{Key: "hygiene", Label: "Hygiene", Max: 15},
	{Key: "ipv6", Label: "IPv6", Max: 10},
}

// grades are the grades from the best to the worst.
const grades = "ABCDF"

// tally holds the sums that the score is made of, in a form that also tells
// what one finding less would change.
type tally struct {
	// raw is what each category loses before its limit.
	raw map[string]int
	// top holds the two highest deductions among the findings of one key.
	// Findings with the same key are about one thing (a port on both address
	// families, a chain) and cost once, the highest of their points.
	top map[string][2]int
	// ceilings counts the findings that limit the grade, by the rank of the
	// limit.
	ceilings [len(grades)]int
}

func chargeKey(finding *Finding) string {
	return finding.Category + "|" + finding.key
}

func newTally(findings []Finding) *tally {
	t := &tally{raw: map[string]int{}, top: map[string][2]int{}}
	for i := range findings {
		finding := &findings[i]
		if finding.ceiling != "" {
			t.ceilings[gradeRank(finding.ceiling)]++
		}
		if finding.key == "" {
			t.raw[finding.Category] += finding.Points
			continue
		}
		top := t.top[chargeKey(finding)]
		switch {
		case finding.Points > top[0]:
			top = [2]int{finding.Points, top[0]}
		case finding.Points > top[1]:
			top[1] = finding.Points
		}
		t.top[chargeKey(finding)] = top
	}
	for key, top := range t.top {
		category, _, _ := strings.Cut(key, "|")
		t.raw[category] += top[0]
	}
	return t
}

// charge is what the finding adds to its category: all of its points, or
// what it costs more than the other findings with its key.
func (t *tally) charge(finding *Finding) int {
	if finding.key == "" {
		return finding.Points
	}
	top := t.top[chargeKey(finding)]
	if finding.Points == top[0] {
		return top[0] - top[1]
	}
	return 0
}

// ceilingWithout is the rank of the best grade that the findings allow when
// one finding with the given limit is left out; "" leaves none out.
func (t *tally) ceilingWithout(ceiling string) int {
	counts := t.ceilings
	if ceiling != "" {
		counts[gradeRank(ceiling)]--
	}
	for rank := len(counts) - 1; rank > 0; rank-- {
		if counts[rank] > 0 {
			return rank
		}
	}
	return 0
}

// score adds up the deductions of the findings and says what each finding
// costs. A category does not lose more than its maximum. A finding that
// leaves the host open by default also limits the grade, whatever the points.
func score(findings []Finding, notes []Note) Score {
	t := newTally(findings)
	result := Score{Total: 100, Complete: true}
	limits := map[string]int{}
	for _, category := range categoryLimits {
		limits[category.Key] = category.Max
		category.Lost = min(t.raw[category.Key], category.Max)
		result.Total -= category.Lost
		result.Categories = append(result.Categories, category)
	}
	result.Grade = gradeFromScore(result.Total)
	if ceiling := t.ceilingWithout(""); ceiling > gradeRank(result.Grade) {
		result.Grade = grades[ceiling : ceiling+1]
		for i := range findings {
			if findings[i].ceiling == result.Grade {
				result.Cap = "grade limited to " + result.Grade + ": " + findings[i].ceilingReason
				break
			}
		}
	}

	areas := map[string]string{
		"docker": "one or more translated ports",
		"nat":    "ports redirected to local services",
		"rules":  "rules that could not be read or evaluated in full",
	}
	seen := map[string]bool{}
	for _, note := range notes {
		if note.Kind != "incomplete" {
			continue
		}
		result.Complete = false
		label := areas[note.Area]
		if label == "" {
			label = note.Area
		}
		if !seen[label] {
			seen[label] = true
			result.Unassessed = append(result.Unassessed, label)
		}
	}

	for i := range findings {
		finding := &findings[i]
		raw, limit := t.raw[finding.Category], limits[finding.Category]
		finding.Gain = min(raw, limit) - min(raw-t.charge(finding), limit)
		if !result.Complete {
			continue // no grade to improve
		}
		after := max(gradeRank(gradeFromScore(result.Total+finding.Gain)), t.ceilingWithout(finding.ceiling))
		if after < gradeRank(result.Grade) {
			finding.GradeAfter = grades[after : after+1]
		}
	}
	if !result.Complete {
		result.Grade = "INCOMPLETE"
	}
	return result
}

// gradeRank orders grades from best to worst.
func gradeRank(grade string) int {
	return strings.Index(grades, grade)
}

func gradeFromScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}
