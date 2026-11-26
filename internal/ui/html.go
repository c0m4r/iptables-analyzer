package ui

import (
	"crypto/sha256"
	_ "embed" // the page is built from the embedded assets
	"encoding/base64"
	"html/template"
	"io"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/report"
)

// The HTML report is one file. Its style and its script are in the page, and
// the content security policy names both by their hash: the browser loads
// nothing from the network and runs no other script, also when text from the
// analyzed rules would get past the escaping of the template.
//
// Every value from the input goes through html/template into text or into
// the value of an attribute that holds text. Names of classes and anchors
// are never made from the input: they come from fixed lists and from counters.

//go:embed assets/report.css
var pageCSS string

//go:embed assets/report.js
var pageJS string

//go:embed assets/report.html
var pageBody string

var pageTemplate = template.Must(template.New("page").Parse(pageBody))

// pagePolicy is the content security policy of the page.
var pagePolicy = "default-src 'none'; style-src '" + sourceHash(pageCSS) + "'; script-src '" + sourceHash(pageJS) +
	"'; base-uri 'none'; form-action 'none'"

// sourceHash names an inline style or script in a content security policy.
func sourceHash(source string) string {
	sum := sha256.Sum256([]byte(source))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// RenderHTML writes the report as one self-contained HTML page.
func RenderHTML(w io.Writer, rep *report.Report) error {
	page := newHTMLPage(rep)
	out := &trackingWriter{writer: w}
	io.WriteString(out, "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"+
		"<meta http-equiv=\"Content-Security-Policy\" content=\""+pagePolicy+"\">\n"+
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"+
		"<meta name=\"referrer\" content=\"no-referrer\">\n"+
		"<meta name=\"color-scheme\" content=\"light dark\">\n"+
		"<title>"+template.HTMLEscapeString(page.Title)+"</title>\n"+
		"<style>"+pageCSS+"</style>\n</head>\n")
	if err := pageTemplate.Execute(out, page); err != nil {
		return err
	}
	io.WriteString(out, "<script>"+pageJS+"</script>\n</body>\n</html>\n")
	return out.err
}

type htmlPage struct {
	Title        string
	Tool         report.Tool
	Source, When string

	Grade, GradeClass string
	Total             int
	Chips             []htmlChip
	Warnings          []string
	Categories        []htmlCategory
	FixFirst          []htmlFirst
	Notes             []htmlNote
	Facts             []htmlFact

	Filters  []htmlFilter
	Findings []htmlFinding

	// ShowFamily is true when the report covers both address families.
	ShowFamily     bool
	ReachableCount int
	OpenPorts      []htmlOpenPort
	NoPorts        string
	Forwards       []htmlForward
	Services       []htmlService
	NoServices     string

	Rulesets  []htmlRuleset
	RuleCount int
	Baseline  *htmlBaseline
}

type htmlChip struct{ Class, Text string }

type htmlCategory struct {
	Label              string
	Kept, Max, Percent int
	Class              string
}

type htmlFirst struct{ Anchor, ID, Title, Gain string }

type htmlNote struct {
	Mark, Text string
	Incomplete bool
}

type htmlFact struct {
	Name, Text string
	Warning    bool
}

type htmlFilter struct {
	Severity, Label string
	Count           int
}

type htmlFinding struct {
	Anchor, ID, Severity, Title, Points string
	// Category names the part of the score that the points come from.
	Category         string
	Tags             []string
	Detail           []string
	Rules, MoreRules []htmlRef
	MoreLabel        string
	Fix              *htmlFix
	Open             bool
}

// htmlRef names a rule; Anchor is empty when the page does not show the rule.
type htmlRef struct{ Role, Where, Anchor, Spec, Path string }

type htmlFix struct {
	Summary string
	Steps   []htmlStep
}

type htmlStep struct{ ID, Text, Command string }

type htmlOpenPort struct {
	Protocol, Ports, Families string
	Sort                      int
	Public                    bool
	// Redirect names the local port that receives the connections, when
	// nat/PREROUTING sends them there; RedirectRules are the rules that do.
	Redirect              string
	RedirectRules         []htmlRef
	Scope, ScopeClass     string
	ScopeRank             int
	Qualifiers, Listeners string
	Rules                 []htmlRef
}

type htmlForward struct {
	Family, From, To, Bridge string
	Sort                     int
	Scope, ScopeClass        string
	ScopeRank                int
	Qualifiers               string
	Rule                     htmlRef
}

type htmlService struct {
	Protocol, Address, Process string
	Port                       int
	Status, StatusClass        string
	StatusRank                 int
}

type htmlRuleset struct {
	Family string
	Tables []htmlTable
}

type htmlTable struct {
	Name, Count string
	// Empty stands for the chains of a table that has no rules.
	Empty  string
	Chains []htmlChain
}

type htmlChain struct {
	Anchor                                         string
	Name, Policy, PolicyClass, Count, Owner, Named string
	Open                                           bool
	Rules                                          []htmlRule
}

// htmlRule is one rule, cut in front of its target. For a jump to a chain of
// the table, the target is a link: JumpLead, the name of the chain, JumpRest.
type htmlRule struct {
	Anchor                                  string
	Num                                     int
	Head, Tail, TailClass                   string
	JumpLead, JumpName, JumpRest, JumpChain string
	Findings                                []htmlBadge
}

type htmlBadge struct{ ID, Anchor string }

type htmlBaseline struct {
	Files []htmlFile
	Notes []string
}

type htmlFile struct{ Title, ID, Text string }

// ruleKey identifies a rule of the input.
type ruleKey struct {
	family       int
	table, chain string
	num          int
}

// htmlBuilder holds what the parts of the page need from each other.
type htmlBuilder struct {
	rep *report.Report
	// both is true when the report covers IPv4 and IPv6.
	both bool
	// ruleAnchors maps a rule to its anchor in the list of rules.
	ruleAnchors map[ruleKey]string
	// findingAnchors maps the number of a finding to its anchor.
	findingAnchors map[string]string
}

// shownRules is the number of rules that a finding shows before the rest is
// folded away.
const shownRules = 6

func newHTMLPage(rep *report.Report) *htmlPage {
	b := &htmlBuilder{rep: rep, both: analyzedFamilies(rep) > 1, ruleAnchors: map[ruleKey]string{}, findingAnchors: map[string]string{}}
	for i, finding := range rep.Findings {
		if _, known := b.findingAnchors[finding.ID]; !known {
			b.findingAnchors[finding.ID] = findingAnchor(i)
		}
	}
	page := &htmlPage{
		Tool:       rep.Tool,
		Source:     sourceText(rep),
		When:       timeText(rep),
		Grade:      rep.Score.Grade,
		GradeClass: "INCOMPLETE",
		Total:      rep.Score.Total,
		ShowFamily: b.both,
	}
	page.Title = "Firewall report"
	if rep.Host != "" {
		page.Title += ": " + rep.Host
	}
	page.Title += " · " + page.When
	if len(page.Grade) == 1 && strings.Contains("ABCDF", page.Grade) {
		page.GradeClass = page.Grade
	}
	// The rules come first: the other parts link to them.
	page.Rulesets, page.RuleCount = b.rulesets()
	b.summary(page)
	b.findings(page)
	b.reachable(page)
	if base := rep.Baseline; base != nil {
		page.Baseline = &htmlBaseline{Notes: base.Notes}
		if base.IPv4 != "" {
			page.Baseline.Files = append(page.Baseline.Files, htmlFile{"IPv4, for iptables-restore", "baseline-4", base.IPv4})
		}
		if base.IPv6 != "" {
			page.Baseline.Files = append(page.Baseline.Files, htmlFile{"IPv6, for ip6tables-restore", "baseline-6", base.IPv6})
		}
	}
	return page
}

// findingAnchor is the anchor of the finding at a position of the report. It
// comes from the position, so that it is unique whatever the report holds.
func findingAnchor(index int) string {
	return "f-" + strconv.Itoa(index+1)
}

var severityLabels = []struct {
	severity models.Severity
	label    string
}{
	{models.SeverityCritical, "Critical"},
	{models.SeverityHigh, "High"},
	{models.SeverityMedium, "Medium"},
	{models.SeverityLow, "Low"},
	{models.SeverityInfo, "Info"},
}

func severityCount(counts report.Counts, severity models.Severity) int {
	switch severity {
	case models.SeverityCritical:
		return counts.Critical
	case models.SeverityHigh:
		return counts.High
	case models.SeverityMedium:
		return counts.Medium
	case models.SeverityLow:
		return counts.Low
	}
	return counts.Info
}

func (b *htmlBuilder) summary(page *htmlPage) {
	rep := b.rep
	for _, entry := range severityLabels {
		if n := severityCount(rep.Counts, entry.severity); n > 0 {
			page.Chips = append(page.Chips, htmlChip{entry.severity.String(), strconv.Itoa(n) + " " + strings.ToLower(entry.label)})
			page.Filters = append(page.Filters, htmlFilter{entry.severity.String(), entry.label, n})
		}
	}
	if len(page.Chips) == 0 {
		page.Chips = []htmlChip{{"OK", "no findings"}}
	}
	score := rep.Score
	if score.Cap != "" && score.Complete {
		page.Warnings = append(page.Warnings, strings.ToUpper(score.Cap[:1])+score.Cap[1:]+".")
	}
	if !score.Complete {
		page.Warnings = append(page.Warnings, "The grade is incomplete: "+strings.Join(score.Unassessed, ", ")+" could not be assessed.")
	}
	for _, category := range score.Categories {
		kept := category.Max - category.Lost
		entry := htmlCategory{Label: category.Label, Kept: kept, Max: category.Max, Class: "poor"}
		if category.Max > 0 {
			entry.Percent = kept * 100 / category.Max
		}
		switch {
		case kept >= category.Max:
			entry.Class = "full"
		case kept*2 >= category.Max:
			entry.Class = "part"
		}
		page.Categories = append(page.Categories, entry)
	}
	for _, finding := range fixFirst(rep) {
		page.FixFirst = append(page.FixFirst, htmlFirst{b.findingAnchors[finding.ID], finding.ID, finding.Title, gainText(finding)})
	}
	for _, note := range rep.Notes {
		entry := htmlNote{Mark: "Note", Text: note.Text}
		if note.Kind == "incomplete" {
			entry.Mark, entry.Incomplete = "Not assessed", true
		}
		page.Notes = append(page.Notes, entry)
	}

	if len(rep.Inputs) > 0 {
		page.Facts = append(page.Facts, htmlFact{Name: "Input", Text: strings.Join(rep.Inputs, ", ")})
	} else if rep.Mode == "live" {
		page.Facts = append(page.Facts, htmlFact{Name: "Input", Text: "the loaded rules and the listening sockets of this host"})
	}
	for _, family := range rep.Families {
		if text, warning := familySummary(family); text != "" {
			page.Facts = append(page.Facts, htmlFact{"IPv" + strconv.Itoa(family.Version), text, warning})
		}
	}
	if status := rep.Sandbox; status != nil {
		text, warning := sandboxSummary(status)
		if len(status.Notes) > 0 {
			text += ". " + strings.Join(status.Notes, " ")
		}
		page.Facts = append(page.Facts, htmlFact{"Sandbox", text, warning})
	}
}

// ref makes the link to a rule of the input.
func (b *htmlBuilder) ref(rule report.RuleRef) htmlRef {
	where := rule.Table + "/" + rule.Chain + " #" + strconv.Itoa(rule.Num)
	if b.both {
		where = "IPv" + strconv.Itoa(rule.Family) + " " + where
	}
	ref := htmlRef{
		Role:   rule.Role,
		Where:  where,
		Anchor: b.ruleAnchors[ruleKey{rule.Family, rule.Table, rule.Chain, rule.Num}],
		Spec:   rule.Spec,
	}
	if len(rule.Path) > 1 {
		ref.Path = strings.Join(rule.Path[:len(rule.Path)-1], " → ")
	}
	return ref
}

func (b *htmlBuilder) findings(page *htmlPage) {
	for i, finding := range b.rep.Findings {
		entry := htmlFinding{
			Anchor:   findingAnchor(i),
			ID:       finding.ID,
			Severity: finding.Severity.String(),
			Title:    finding.Title,
			Detail:   strings.Split(finding.Detail, "\n"),
			Open:     finding.Severity >= models.SeverityMedium,
		}
		if b.both && len(finding.Families) == 1 && !strings.Contains(finding.Title, familyNames(finding.Families)) {
			entry.Tags = append(entry.Tags, familyNames(finding.Families))
		}
		if finding.Certainty == models.CertaintyPossible {
			entry.Tags = append(entry.Tags, "possible")
		}
		if finding.Points > 0 {
			entry.Points = "−" + strconv.Itoa(finding.Points)
			for _, category := range b.rep.Score.Categories {
				if category.Key == finding.Category {
					entry.Category = category.Label
				}
			}
		}
		for j, rule := range finding.Rules {
			if j < shownRules {
				entry.Rules = append(entry.Rules, b.ref(rule))
			} else {
				entry.MoreRules = append(entry.MoreRules, b.ref(rule))
			}
		}
		if n := len(entry.MoreRules); n > 0 {
			entry.MoreLabel = "and " + countNoun(n, "more rule")
		}
		if fix := finding.Fix; fix != nil {
			entry.Fix = &htmlFix{Summary: fix.Summary}
			for j, step := range fix.Steps {
				entry.Fix.Steps = append(entry.Fix.Steps, htmlStep{"c-" + strconv.Itoa(i+1) + "-" + strconv.Itoa(j+1), step.Text, step.Command})
			}
		}
		page.Findings = append(page.Findings, entry)
	}
}

// scopeClass returns the name of the style for a scope. It is one of a fixed
// list, whatever the value holds.
func scopeClass(scope models.AccessScope) string {
	switch scope {
	case models.ScopeExposed, models.ScopeSubnet, models.ScopeRestricted, models.ScopeLocalnet, models.ScopeWhitelisted:
		return string(scope)
	}
	return "BLOCKED"
}

// scopeOrder sorts scopes from the widest to the narrowest.
func scopeOrder(scope models.AccessScope) int {
	switch scope {
	case models.ScopeExposed:
		return 0
	case models.ScopeSubnet:
		return 1
	case models.ScopeRestricted:
		return 2
	case models.ScopeLocalnet:
		return 3
	case models.ScopeWhitelisted:
		return 4
	}
	return 5
}

func (b *htmlBuilder) reachable(page *htmlPage) {
	rep := b.rep
	for _, open := range rep.OpenPorts {
		entry := htmlOpenPort{
			Protocol:   open.Protocol,
			Ports:      openPortName(open),
			Sort:       open.First,
			Public:     open.Public,
			Families:   familyNames(open.Families),
			Scope:      scopeWords(open.Scope),
			ScopeClass: scopeClass(open.Scope),
			ScopeRank:  scopeOrder(open.Scope),
			Listeners:  strings.Join(open.Listeners, ", "),
		}
		if open.Default {
			entry.Ports, entry.Sort = "all that no rule names", 65536
		}
		if open.Redirect != nil {
			entry.Redirect = redirectName(open.Redirect)
			for _, rule := range open.Redirect.Rules {
				entry.RedirectRules = append(entry.RedirectRules, b.ref(rule))
			}
		}
		var qualifiers []string
		for _, text := range []string{open.Condition, open.Restriction} {
			if text != "" {
				qualifiers = append(qualifiers, text)
			}
		}
		if len(open.Interfaces) > 0 {
			qualifiers = append(qualifiers, "on "+strings.Join(open.Interfaces, ", "))
		}
		if open.Certainty == models.CertaintyPossible {
			qualifiers = append(qualifiers, "possible")
		}
		entry.Qualifiers = strings.Join(qualifiers, " · ")
		for _, rule := range open.Rules {
			entry.Rules = append(entry.Rules, b.ref(rule))
		}
		page.OpenPorts = append(page.OpenPorts, entry)
		if open.Scope == models.ScopeExposed {
			page.ReachableCount++
		}
	}
	page.NoPorts = "No port accepts new connections from other hosts."

	for _, forward := range rep.Forwards {
		host := forward.HostAddr
		if host != "" {
			host = bracket(host) + ":"
		}
		entry := htmlForward{
			Family:     "IPv" + strconv.Itoa(forward.Family),
			From:       host + portRange(forward.HostPort, forward.HostPortEnd) + "/" + forward.Protocol,
			To:         forwardDestination(forward),
			Bridge:     forward.Bridge,
			Sort:       forward.HostPort,
			Scope:      scopeWords(forward.ForwardScope),
			ScopeClass: scopeClass(forward.ForwardScope),
			ScopeRank:  scopeOrder(forward.ForwardScope),
			Rule:       b.ref(forward.Rule),
		}
		var qualifiers []string
		if len(forward.Interfaces) > 0 {
			qualifiers = append(qualifiers, "on "+strings.Join(forward.Interfaces, ", "))
		}
		if forward.Certainty == models.CertaintyPossible && forward.ForwardScope != "" {
			qualifiers = append(qualifiers, "possible")
		}
		entry.Qualifiers = strings.Join(qualifiers, " · ")
		page.Forwards = append(page.Forwards, entry)
		if forward.ForwardScope == models.ScopeExposed {
			page.ReachableCount++
		}
	}

	for _, svc := range rep.Services {
		entry := htmlService{Protocol: svc.Protocol, Address: svc.Address, Port: svc.Port, Process: svc.Process}
		if svc.Device != "" {
			entry.Address += "%" + svc.Device
		}
		if len(svc.Processes) > 1 {
			entry.Process = strings.Join(svc.Processes, ", ")
		}
		entry.Status, entry.StatusClass, entry.StatusRank = serviceStatus(svc)
		page.Services = append(page.Services, entry)
	}
	page.NoServices = "No list of listening sockets was read."
	if rep.ServicesKnown {
		page.NoServices = "Nothing listens on this host."
	}
}

// serviceStatus says who reaches a listening socket, with the name of its
// style and its place in the order from the widest to the narrowest.
func serviceStatus(svc report.Service) (text, class string, rank int) {
	switch svc.Status {
	case models.ServiceReachable:
		return "open to " + scopeWords(svc.Scope), scopeClass(svc.Scope), scopeOrder(svc.Scope)
	case models.ServiceDocker:
		if svc.Scope == "" {
			return "published by Docker, no source reaches it", "BLOCKED", 5
		}
		return "published by Docker, open to " + scopeWords(svc.Scope), scopeClass(svc.Scope), scopeOrder(svc.Scope)
	case models.ServiceInternal:
		return "guests of this host only", "INTERNAL", 6
	case models.ServiceFiltered:
		return "filtered", "FILTERED", 7
	case models.ServiceLocalhost:
		return "loopback only", "LOCALHOST", 8
	}
	return "not analyzed", "NONE", 9
}

// openChains is the number of rules up to which the page shows every chain
// unfolded. A longer rule set shows the built-in chains and the chains that
// findings name.
const openChains = 200

func (b *htmlBuilder) rulesets() ([]htmlRuleset, int) {
	total := 0
	for _, ruleset := range b.rep.Rulesets {
		for _, table := range ruleset.Tables {
			for _, chain := range table.Chains {
				total += len(chain.Rules)
			}
		}
	}
	var rulesets []htmlRuleset
	for _, ruleset := range b.rep.Rulesets {
		view := htmlRuleset{Family: "IPv" + strconv.Itoa(ruleset.Family)}
		for t, table := range ruleset.Tables {
			tableView := htmlTable{Name: table.Name}
			rules := 0
			// A rule can jump to a chain that comes later in the table.
			// The anchor of a chain comes from its position.
			chainAnchor := func(c int) string {
				return "ch" + strconv.Itoa(ruleset.Family) + "-" + strconv.Itoa(t+1) + "-" + strconv.Itoa(c+1)
			}
			chainAnchors := map[string]string{}
			for c, chain := range table.Chains {
				if _, known := chainAnchors[chain.Name]; !known {
					chainAnchors[chain.Name] = chainAnchor(c)
				}
			}
			for c, chain := range table.Chains {
				chainView := htmlChain{
					Anchor: chainAnchor(c),
					Name:   chain.Name,
					Policy: chain.Policy,
					Count:  countNoun(len(chain.Rules), "rule"),
					Owner:  chain.Owner,
					Rules:  make([]htmlRule, 0, len(chain.Rules)),
				}
				// Only the filter chains for incoming and forwarded packets
				// are expected to deny by default.
				chainView.PolicyClass = "NONE"
				if table.Name == "filter" && (chain.Name == "INPUT" || chain.Name == "FORWARD") {
					switch chain.Policy {
					case "ACCEPT":
						chainView.PolicyClass = "ACCEPT"
					case "DROP":
						chainView.PolicyClass = "DROP"
					}
				}
				named := map[string]bool{}
				for _, rule := range chain.Rules {
					anchor := "r" + strconv.Itoa(ruleset.Family) + "-" + strconv.Itoa(t+1) + "-" + strconv.Itoa(c+1) + "-" + strconv.Itoa(rule.Num)
					b.ruleAnchors[ruleKey{ruleset.Family, table.Name, chain.Name, rule.Num}] = anchor
					ruleView := htmlRule{Anchor: anchor, Num: rule.Num, TailClass: targetClass(rule)}
					ruleView.Head, ruleView.Tail = splitTarget(rule.Spec)
					// "-j NAME" or "-g NAME": the name becomes the link.
					if anchor := chainAnchors[rule.Target]; rule.Jump && anchor != "" && len(ruleView.Tail) > 3 &&
						strings.HasPrefix(ruleView.Tail[3:], rule.Target) {
						ruleView.JumpLead, ruleView.JumpName = ruleView.Tail[:3], rule.Target
						ruleView.JumpRest, ruleView.JumpChain = ruleView.Tail[3+len(rule.Target):], anchor
					}
					for _, id := range rule.Findings {
						named[id] = true
						ruleView.Findings = append(ruleView.Findings, htmlBadge{id, b.findingAnchors[id]})
					}
					chainView.Rules = append(chainView.Rules, ruleView)
				}
				if len(named) > 0 {
					chainView.Named = countNoun(len(named), "finding")
				}
				chainView.Open = len(chain.Rules) > 0 && (total <= openChains || chain.Policy != "" || len(named) > 0)
				rules += len(chain.Rules)
				tableView.Chains = append(tableView.Chains, chainView)
			}
			tableView.Count = countNoun(len(table.Chains), "chain") + ", " + countNoun(rules, "rule")
			if rules == 0 {
				var policies []string
				for _, chain := range table.Chains {
					if chain.Policy != "" {
						policies = append(policies, chain.Name+" "+chain.Policy)
					}
				}
				tableView.Empty = "No rules."
				if len(policies) > 0 {
					tableView.Empty += " Policies: " + strings.Join(policies, ", ") + "."
				}
			}
			view.Tables = append(view.Tables, tableView)
		}
		rulesets = append(rulesets, view)
	}
	return rulesets, total
}

// targetClass returns the name of the style for the target of a rule.
func targetClass(rule report.Rule) string {
	switch {
	case rule.Jump:
		return "jump"
	case rule.Target == "ACCEPT":
		return "ACCEPT"
	case rule.Target == "DROP" || rule.Target == "REJECT":
		return "DROP"
	}
	return "other"
}

// splitTarget cuts a rule in front of its target, so that the page can show
// the target in the color of what it does. iptables-save prints the target
// and its options last.
func splitTarget(spec string) (head, tail string) {
	at := max(strings.LastIndex(spec, " -j "), strings.LastIndex(spec, " -g "))
	switch {
	case at >= 0:
		return spec[:at+1], spec[at+1:]
	case strings.HasPrefix(spec, "-j ") || strings.HasPrefix(spec, "-g "):
		return "", spec
	}
	return spec, ""
}
