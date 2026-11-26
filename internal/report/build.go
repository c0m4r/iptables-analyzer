package report

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

const repoURL = "https://github.com/c0m4r/iptables-analyzer"

// Options carry what the report needs besides the analysis.
type Options struct {
	Version string
	Live    bool
	// Snapshot is true when the input is a snapshot of a host; Captured is
	// the time when the snapshot was taken.
	Snapshot bool
	Captured string
	Now      time.Time
	// Inputs names the files that were read, for the header of the report.
	Inputs []string
	// Public lists ports that are open to any source on purpose. They are
	// reported as notes and cost no points.
	Public []PortSpec
	// Baseline is the recommended firewall for the host.
	Baseline models.Baseline
}

type builder struct {
	result   *models.AnalysisResult
	opts     Options
	findings []Finding
	// managers holds the program that writes the filter table of each
	// address family, when its chains show one.
	managers map[models.IPVersion]string
}

// Build makes the report of an analysis.
func Build(result *models.AnalysisResult, opts Options) *Report {
	b := &builder{result: result, opts: opts}
	rep := &Report{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "iptables-analyzer", Version: opts.Version, URL: repoURL},
		Generated:     opts.Now.Format(time.RFC3339),
		Mode:          "file",
		Inputs:        opts.Inputs,
		ServicesKnown: result.ServiceAssessment == models.AssessmentComplete,
	}
	switch {
	case opts.Live:
		rep.Mode = "live"
	case opts.Snapshot:
		rep.Mode, rep.Captured = "snapshot", opts.Captured
	}
	if result.Host != nil {
		rep.Host = result.Host.Hostname
	}
	rep.Families = b.families()

	b.noRules()
	b.effectiveness()
	if rep.ServicesKnown {
		b.exposedServices()
		b.unusedPorts()
	} else {
		b.openPortFindings()
	}
	b.shadowedRules()
	b.translatedPorts()

	rep.Findings = b.finish()
	for _, finding := range rep.Findings {
		switch finding.Severity {
		case models.SeverityCritical:
			rep.Counts.Critical++
		case models.SeverityHigh:
			rep.Counts.High++
		case models.SeverityMedium:
			rep.Counts.Medium++
		case models.SeverityLow:
			rep.Counts.Low++
		default:
			rep.Counts.Info++
		}
	}
	rep.Notes = b.notes()
	rep.Score = score(rep.Findings, rep.Notes)
	rep.OpenPorts = b.openPorts()
	rep.Forwards = b.forwards()
	rep.Services = b.services()
	rep.Rulesets = b.rulesets(rep.Findings)
	if status := result.Sandbox; status != nil {
		rep.Sandbox = &Sandbox{Mode: status.Mode, Landlock: status.Landlock, LandlockABI: status.LandlockABI,
			Restricted: status.Restricted, PrivilegesDropped: status.PrivilegesDropped, Notes: status.Notes}
	}
	if opts.Baseline.IPv4 != "" || opts.Baseline.IPv6 != "" {
		rep.Baseline = &Baseline{IPv4: opts.Baseline.IPv4, IPv6: opts.Baseline.IPv6, Notes: opts.Baseline.Notes}
	}
	return rep
}

func (b *builder) ruleset(version models.IPVersion) *models.Ruleset {
	if version == models.IPv6 {
		return b.result.IPv6Rules
	}
	return b.result.IPv4Rules
}

func (b *builder) add(finding Finding) {
	finding.order = len(b.findings)
	b.findings = append(b.findings, finding)
}

// ref points to a rule, with the jumps that lead to it.
func (b *builder) ref(rule *models.Rule, role string) RuleRef {
	ref := RuleRef{Family: int(rule.IPVersion), Table: rule.Table, Chain: rule.Chain, Num: rule.RuleNum,
		Spec: analyzer.RuleSpec(rule), Role: role}
	if path := analyzer.RulePath(b.ruleset(rule.IPVersion), rule); len(path) > 1 {
		ref.Path = path
	}
	return ref
}

func ruleName(rule *models.Rule) string {
	return rule.Table + "/" + rule.Chain + " rule #" + strconv.Itoa(rule.RuleNum)
}

func stack(version models.IPVersion) string {
	if version == models.IPv6 {
		return "IPv6"
	}
	return "IPv4"
}

func firewallCommand(version models.IPVersion) string {
	if version == models.IPv6 {
		return "ip6tables"
	}
	return "iptables"
}

// families describes the input of each address family.
func (b *builder) families() []Family {
	var families []Family
	for _, version := range []models.IPVersion{models.IPv4, models.IPv6} {
		family := Family{Version: int(version), Status: string(b.result.FamilyState(version))}
		if rs := b.ruleset(version); rs != nil {
			family.Tables = len(rs.Tables)
			owners := map[string]bool{}
			if manager := b.manager(version); manager != "" {
				owners[manager] = true
			}
			for _, table := range rs.Tables {
				for name, chain := range table.Chains {
					family.Chains++
					family.Rules += len(chain.Rules)
					if owner := chainOwner(name); owner != "" {
						owners[owner] = true
					}
				}
			}
			if filter := rs.Tables["filter"]; filter != nil {
				family.Policies = map[string]string{}
				for _, name := range []string{"INPUT", "FORWARD", "OUTPUT"} {
					if chain := filter.Chains[name]; chain != nil {
						family.Policies[name] = chain.Policy
					}
				}
			}
			for owner := range owners {
				family.Managers = append(family.Managers, owner)
			}
			sort.Strings(family.Managers)
		}
		families = append(families, family)
	}
	return families
}

// ipv6InUse reports whether the host is known to have an IPv6 address
// beyond loopback and link-local ones. known is false for saved rules.
func (b *builder) ipv6InUse() (inUse, known bool) {
	host := b.result.Host
	if host == nil || len(host.Interfaces) == 0 {
		return false, false
	}
	for _, iface := range host.Interfaces {
		for _, value := range iface.Addrs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				continue
			}
			if addr := prefix.Addr(); addr.Is6() && !addr.Is4In6() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
				return true, true
			}
		}
	}
	return false, true
}

// noRules reports an address family for which nothing is loaded. It stands
// for the default-accept findings of that family, which say the same.
func (b *builder) noRules() {
	for _, version := range []models.IPVersion{models.IPv4, models.IPv6} {
		if b.result.FamilyState(version) != models.FamilyNoRules {
			continue
		}
		finding := Finding{
			Code:      "no_rules",
			Severity:  models.SeverityHigh,
			Certainty: models.CertaintyDefinite,
			Families:  []int{int(version)},
			Title:     "No " + stack(version) + " firewall rules are loaded",
			Fix: &Fix{
				Summary: "Load a rule set for " + stack(version) + ". The recommended baseline is a complete one; its notes say how to apply it with a way back.",
				Steps: []FixStep{{"Write the baseline for " + stack(version) + " to a file",
					fmt.Sprintf("iptables-analyzer --baseline=%d > baseline.v%d", version, version)}},
			},
		}
		if version == models.IPv4 {
			finding.Category, finding.Points, finding.key = "policy", 25, "policy/INPUT"
			finding.Detail = "iptables-save shows no tables for IPv4, so nothing is filtered: every port of the host is open, " +
				"and the host forwards packets without a filter when routing is on."
			finding.limit("F", "no IPv4 rules are loaded")
		} else {
			finding.Category, finding.Points = "ipv6", 10
			finding.Detail = "ip6tables-save shows no tables, and IPv4 rules do not filter IPv6. " +
				"Hosts usually get IPv6 addresses automatically; every service that listens on IPv6 is then open."
			switch inUse, known := b.ipv6InUse(); {
			case known && inUse:
				finding.Detail += " This host has an IPv6 address beyond the link-local one."
				finding.limit("F", "no IPv6 rules are loaded and the host has an IPv6 address")
			case known:
				finding.Severity = models.SeverityMedium
				finding.Detail += " This host has no IPv6 address beyond the link-local one at the moment."
			default:
				finding.limit("D", "no IPv6 rules are loaded")
			}
		}
		b.add(finding)
	}
}

// effectiveness converts the findings about what the chains do by default
// and about rules that break the host.
func (b *builder) effectiveness() {
	for i := range b.result.EffectiveIssues {
		issue := &b.result.EffectiveIssues[i]
		noRules := b.result.FamilyState(issue.IPVersion) == models.FamilyNoRules
		if noRules && issue.Code == models.FindingPolicyAccept {
			continue // said by the no_rules finding
		}
		finding := Finding{
			Code:      string(issue.Code),
			Severity:  issue.Severity,
			Certainty: issue.Certainty,
			Category:  "hygiene",
			Families:  []int{int(issue.IPVersion)},
			Title:     issue.Title,
			Detail:    issue.Detail,
		}
		if issue.Rule != nil {
			finding.Rules = []RuleRef{b.ref(issue.Rule, "causes")}
		}
		bySeverity := map[models.Severity]int{models.SeverityHigh: 5, models.SeverityMedium: 3, models.SeverityLow: 1}[issue.Severity]
		command := firewallCommand(issue.IPVersion)
		switch issue.Code {
		case models.FindingPolicyAccept:
			finding.Category = "policy"
			switch issue.Chain {
			case "INPUT":
				finding.Points, finding.key = 15, "policy/INPUT"
				b.limitForDefaultAccept(&finding, issue)
			case "FORWARD":
				finding.Points, finding.key = 5, "policy/FORWARD"
				switch {
				case issue.Severity >= models.SeverityHigh:
					finding.Points = 10
				case issue.Severity == models.SeverityInfo:
					finding.Points = 0 // the host does not route packets
				}
			}
			finding.Fix = b.policyFix(issue)
		case models.FindingBroadAccept:
			finding.Category, finding.Points = "exposure", 10
			finding.Fix = &Fix{Summary: "Replace the wide range with rules for the ports that services use, and add -s where the clients are known."}
		case models.FindingMissingConntrack:
			finding.Points = 5
			finding.Fix = &Fix{
				Summary: "Accept the packets of established and related connections near the top of INPUT.",
				Steps:   []FixStep{{"Accept established connections first", command + " -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"}},
			}
		case models.FindingMissingLoopback:
			finding.Points = bySeverity
			finding.Fix = &Fix{
				Summary: "Accept traffic on the loopback interface as the first rule of INPUT.",
				Steps:   []FixStep{{"Accept loopback traffic first", command + " -I INPUT 1 -i lo -j ACCEPT"}},
			}
		case models.FindingIPv6NDPBlocked:
			finding.Points = bySeverity
			types := []string{"135", "136"}
			if strings.Contains(issue.Title, "Router") {
				types = []string{"134"}
			}
			finding.Fix = &Fix{Summary: "Accept these ICMPv6 messages from the local link. A hop limit of 255 shows that no router forwarded the packet."}
			for _, icmpType := range types {
				finding.Fix.Steps = append(finding.Fix.Steps, FixStep{"Accept ICMPv6 type " + icmpType + " from the local link",
					"ip6tables -I INPUT 1 -p ipv6-icmp -m icmp6 --icmpv6-type " + icmpType + " -m hl --hl-eq 255 -j ACCEPT"})
			}
		case models.FindingDeadRule:
			finding.Points = bySeverity
			finding.Fix = &Fix{Summary: "Delete the rules that are never reached, or move those that must apply above the rule that ends the chain."}
		case models.FindingIPv6Wider:
			finding.Category, finding.Points = "ipv6", bySeverity
			finding.Fix = &Fix{Summary: "Give the ip6tables rules for these ports the sources of the iptables rules, or remove them when the service does not need IPv6."}
		case models.FindingFamilyBlocked:
			finding.Category = "policy"
		}
		finding.Points = weigh(finding.Points, issue.Certainty)
		b.add(finding)
	}
}

// limitForDefaultAccept lowers the best grade for an INPUT chain that does
// not deny by default. An IPv6 stack that may not be in use limits less than
// an IPv4 stack.
func (b *builder) limitForDefaultAccept(finding *Finding, issue *models.EffectivenessFinding) {
	name := stack(issue.IPVersion)
	if !issue.Unrestricted {
		finding.limit("D", name+" INPUT accepts connections to ports that no rule names")
		return
	}
	if issue.IPVersion == models.IPv6 {
		if inUse, known := b.ipv6InUse(); !known || !inUse {
			finding.limit("D", "IPv6 INPUT accepts every new connection")
			return
		}
	}
	finding.limit("F", name+" INPUT accepts every new connection")
}

// exposedServices reports listeners that any source can reach. A service
// that listens on both address families is one finding.
func (b *builder) exposedServices() {
	// A finding is about the port that other hosts connect to. That is the
	// port of the listener, or a port that nat/PREROUTING sends to it.
	type key struct {
		protocol models.Protocol
		port     int
		last     int
		process  string
	}
	groups := map[key][]*models.ExposedServiceFinding{}
	var order []key
	for i := range b.result.ExposedServices {
		exposed := &b.result.ExposedServices[i]
		if exposed.Scope != models.ScopeExposed {
			continue // the service table shows restricted scopes
		}
		k := key{exposed.Service.Protocol, exposed.Service.Port, exposed.Service.Port, exposed.Service.Process}
		if exposed.ViaPort != 0 {
			k.port, k.last = exposed.ViaPort, max(exposed.ViaPort, exposed.ViaPortEnd)
		}
		if groups[k] == nil {
			order = append(order, k)
		}
		groups[k] = append(groups[k], exposed)
	}
	defaults := b.defaultAccepts()
	var byDefault []Finding
	for _, k := range order {
		members := groups[k]
		condition := members[0].Condition
		certainty := models.CertaintyPossible
		var families []int
		var details []string
		var refs []RuleRef
		redirected := false
		viaDefault := !b.declaredPublic(k.protocol, k.port, k.last)
		for _, member := range members {
			usual := defaults[stackProtocol{member.IPVersion, k.protocol}]
			viaDefault = viaDefault && member.NATRule == nil && usual != nil && sameRule(usual.Rule, member.AllowingRule) && usual.Condition == member.Condition
			if member.Condition != condition {
				condition = "" // without a condition for one family
			}
			if member.Certainty == models.CertaintyDefinite {
				certainty = models.CertaintyDefinite
			}
			families = appendUnique(families, int(member.IPVersion))
			detail := stack(member.IPVersion) + ": "
			if member.NATRule != nil {
				redirected = true
				detail += fmt.Sprintf("%s sends the port to local port %d, where the service listens; ", ruleName(member.NATRule), member.Service.Port)
				refs = append(refs, b.ref(member.NATRule, "redirects"))
			}
			details = append(details, detail+b.acceptedBy(member.AllowingRule, member.Interfaces, member.Certainty)+".")
			if member.AllowingRule != nil {
				refs = append(refs, b.ref(member.AllowingRule, "accepts"))
			}
		}
		name := k.process
		if name == "" {
			name = "A service"
		}
		port := portText(k.protocol, k.port, k.last)
		finding := Finding{
			Code:      string(models.FindingExposedService),
			Severity:  analyzer.ExposureSeverity(k.port, k.last, condition),
			Certainty: certainty,
			Category:  "exposure",
			Families:  families,
			Title:     name + " is open to any source on " + port,
			Detail:    strings.Join(details, " "),
			Ports:     []string{port},
			Rules:     refs,
			Points:    weigh(exposurePoints(k.port, k.last, condition), certainty),
			key:       "port/" + port,
		}
		if redirected {
			finding.Detail += " INPUT sees the redirected packets with the new port, so a rule for it decides about both ports."
		}
		if condition != "" {
			finding.Detail += " Limited by: " + condition + "."
		}
		if k.process == "docker-proxy" {
			finding.Detail += " docker-proxy relays the port to a container; unlike translated traffic, this way passes INPUT."
		}
		if viaDefault {
			// Open like every port that no rule names: the finding about the
			// default of INPUT has the cause and the fix.
			finding.Detail = name + " on " + port
			if len(b.analyzedFamilies()) > 1 && len(families) == 1 {
				finding.Detail += " (" + stack(models.IPVersion(families[0])) + " only)"
			}
			byDefault = append(byDefault, finding)
			continue
		}
		switch {
		case b.declaredPublic(k.protocol, k.port, k.last):
			finding.Severity, finding.Points = models.SeverityInfo, 0
			finding.Title = name + " on " + port + " is public, as declared"
		case strings.HasPrefix(condition, "source port"):
			finding.Detail += " A rule of this form admits replies (DHCP, DNS): only a sender that uses that source port passes."
		default:
			ssh := k.protocol == models.ProtoTCP && (k.process == "sshd" || strings.HasPrefix(k.process, "sshd-") || k.port == 22)
			finding.Fix = b.exposureFix(k.protocol, k.port, k.last, members[0].AllowingRule, ssh && condition == "" && !redirected)
		}
		b.add(finding)
	}
	if len(byDefault) > 0 {
		b.add(joinDefaultExposure(byDefault))
	}
}

// stackProtocol names one protocol of one address family.
type stackProtocol struct {
	version  models.IPVersion
	protocol models.Protocol
}

// defaultAccepts returns what INPUT does with the ports that no rule names,
// where it accepts them from any source.
func (b *builder) defaultAccepts() map[stackProtocol]*models.OpenPort {
	defaults := map[stackProtocol]*models.OpenPort{}
	for i := range b.result.OpenPorts {
		if open := &b.result.OpenPorts[i]; open.Unnamed && open.Scope == models.ScopeExposed {
			defaults[stackProtocol{open.IPVersion, open.Protocol}] = open
		}
	}
	return defaults
}

// sameRule reports whether two rules are one rule of the input; two missing
// rules both stand for the policy of the chain.
func sameRule(a, b *models.Rule) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IPVersion == b.IPVersion && a.Table == b.Table && a.Chain == b.Chain && a.RuleNum == b.RuleNum
}

// analyzedFamilies lists the address families whose rules were analyzed.
func (b *builder) analyzedFamilies() []models.IPVersion {
	var families []models.IPVersion
	for _, version := range []models.IPVersion{models.IPv4, models.IPv6} {
		if state := b.result.FamilyState(version); state == models.FamilyAnalyzed || state == models.FamilyNoRules {
			families = append(families, version)
		}
	}
	return families
}

// joinDefaultExposure makes one finding of the services that are open only
// because INPUT accepts by default. Each of them costs its points, but they
// have one cause and one fix, which the finding about the default states.
func joinDefaultExposure(members []Finding) Finding {
	joined := Finding{
		Code:      string(models.FindingExposedService),
		Severity:  models.SeverityLow,
		Certainty: models.CertaintyPossible,
		Category:  "exposure",
	}
	var names []string
	for _, member := range members {
		joined.Severity = max(joined.Severity, member.Severity)
		if member.Certainty == models.CertaintyDefinite {
			joined.Certainty = models.CertaintyDefinite
		}
		joined.Families = appendUnique(joined.Families, member.Families...)
		joined.Ports = append(joined.Ports, member.Ports...)
		joined.Points += member.Points
		names = append(names, member.Detail)
	}
	sort.Ints(joined.Families)
	const advice = " Close the default first; then accept each port that must stay reachable, for its clients only."
	if len(members) == 1 {
		joined.Title = members[0].Title
		joined.Detail = "No rule names the port: INPUT accepts it from any source by default." + advice
		return joined
	}
	joined.Title = fmt.Sprintf("%d services are open to any source because INPUT accepts by default", len(members))
	joined.Detail = "No rule names their ports: " + strings.Join(names, "; ") + "." + advice
	return joined
}

// acceptedBy says what accepts a port.
func (b *builder) acceptedBy(rule *models.Rule, interfaces []string, certainty models.Certainty) string {
	text := "accepted by the policy of the chain, because no rule names the port"
	if rule != nil {
		text = "accepted by " + ruleName(rule)
	}
	if certainty == models.CertaintyPossible {
		text = "possibly " + text
	}
	if len(interfaces) > 0 {
		text += ", for packets that arrive on " + strings.Join(interfaces, ", ")
	}
	return text
}

// maxSingleFindings is the number of findings of one kind up to which each
// port is its own finding. Beyond it they are one finding with a list, so
// that a ruleset with hundreds of ports does not bury the other findings.
const maxSingleFindings = 8

// openPortFindings reports the ports that the rules open to any source when
// no list of listening services is known: the rules alone tell what a
// service on the port would be exposed to.
func (b *builder) openPortFindings() {
	type key struct {
		protocol    models.Protocol
		first, last int
		address     string
	}
	byDefault := b.defaultAccepts()
	groups := map[key][]*models.OpenPort{}
	var order []key
	for i := range b.result.OpenPorts {
		open := &b.result.OpenPorts[i]
		if open.Scope != models.ScopeExposed || open.Unnamed || open.Last-open.First+1 >= 1024 {
			continue // default accept and wide ranges are findings of their own
		}
		if usual := byDefault[stackProtocol{open.IPVersion, open.Protocol}]; usual != nil && sameRule(usual.Rule, open.Rule) && !open.Redirected() {
			continue // open like every port that no rule names: the default-accept finding says it
		}
		k := key{open.Protocol, open.First, open.Last, open.Address}
		if groups[k] == nil {
			order = append(order, k)
		}
		groups[k] = append(groups[k], open)
	}
	var found []Finding
	for _, k := range order {
		members := groups[k]
		condition := members[0].Condition
		certainty := models.CertaintyPossible
		var families []int
		var details []string
		var refs []RuleRef
		for _, member := range members {
			if member.Condition != condition {
				condition = ""
			}
			if member.Certainty == models.CertaintyDefinite {
				certainty = models.CertaintyDefinite
			}
			families = appendUnique(families, int(member.IPVersion))
			detail := stack(member.IPVersion) + ": "
			if member.Redirected() {
				detail += redirectText(member) + "; "
				refs = append(refs, b.ref(member.NATRule, "redirects"))
			}
			details = append(details, detail+b.acceptedBy(member.Rule, member.Interfaces, member.Certainty)+".")
			if member.Rule != nil {
				refs = append(refs, b.ref(member.Rule, "accepts"))
			}
		}
		port := portText(k.protocol, k.first, k.last)
		name := port
		if k.address != "" {
			name += " of " + k.address
		}
		finding := Finding{
			Code:      "open_port",
			Severity:  analyzer.ExposureSeverity(k.first, k.last, condition),
			Certainty: certainty,
			Category:  "exposure",
			Families:  families,
			Title:     name + " is open to any source",
			Detail:    strings.Join(details, " "),
			Ports:     []string{port},
			Rules:     refs,
			Points:    weigh(exposurePoints(k.first, k.last, condition), certainty),
			key:       "port/" + port,
		}
		if condition != "" {
			finding.Detail += " Limited by: " + condition + "."
		}
		switch {
		case b.declaredPublic(k.protocol, k.first, k.last):
			finding.Severity, finding.Points = models.SeverityInfo, 0
			finding.Title = name + " is public, as declared"
		case strings.HasPrefix(condition, "source port"):
			finding.Detail += " A rule of this form admits replies (DHCP, DNS): only a sender that uses that source port passes."
		default:
			finding.Fix = b.exposureFix(k.protocol, k.first, k.last, members[0].Rule, k.protocol == models.ProtoTCP && k.first == 22 && k.last == 22 && condition == "")
		}
		found = append(found, finding)
	}
	for _, finding := range b.joinMany(found, "ports are open to any source",
		"INPUT accepts new connections to these ports from any source.",
		"For each port: if the clients are known, give the rule that accepts it their addresses with -s; "+
			"delete the rule when the port is not needed. The rules are listed with the finding.") {
		b.add(finding)
	}
}

// redirectText says where nat/PREROUTING sends the ports of an entry.
func redirectText(open *models.OpenPort) string {
	target := "local port " + strconv.Itoa(open.LocalPort)
	if open.LocalPortEnd > open.LocalPort {
		target = "local ports " + strconv.Itoa(open.LocalPort) + "-" + strconv.Itoa(open.LocalPortEnd)
	}
	if open.LocalPort == open.First && open.LocalPortEnd == open.Last {
		target = "the same port"
	}
	if open.LocalAddr != "" {
		target += " of " + open.LocalAddr
	}
	return ruleName(open.NATRule) + " sends the port to " + target
}

// joinMany returns the findings as they are while they are few. More than
// maxSingleFindings of one severity become one finding that lists the ports.
// fix says what to do about all of them: the commands of one port do not fit
// the others.
func (b *builder) joinMany(findings []Finding, title, detail, fix string) []Finding {
	bySeverity := map[models.Severity][]Finding{}
	for _, finding := range findings {
		bySeverity[finding.Severity] = append(bySeverity[finding.Severity], finding)
	}
	var result []Finding
	for _, finding := range findings {
		group := bySeverity[finding.Severity]
		if len(group) <= maxSingleFindings {
			result = append(result, finding)
			continue
		}
		if group[0].Title != finding.Title {
			continue // joined with the first of its severity
		}
		joined := Finding{Code: finding.Code, Severity: finding.Severity, Certainty: models.CertaintyPossible, Category: finding.Category,
			Title: fmt.Sprintf("%d %s", len(group), title)}
		if finding.Fix != nil {
			joined.Fix = &Fix{Summary: fix}
		}
		for _, member := range group {
			joined.Families = appendUnique(joined.Families, member.Families...)
			joined.Ports = append(joined.Ports, member.Ports...)
			joined.Points += member.Points
			if member.Certainty == models.CertaintyDefinite {
				joined.Certainty = models.CertaintyDefinite
			}
			if len(joined.Rules) < 12 {
				joined.Rules = append(joined.Rules, member.Rules...)
			}
		}
		sort.Ints(joined.Families)
		joined.Detail = detail + " " + abbreviate(joined.Ports, 24) + "."
		result = append(result, joined)
	}
	return result
}

// unusedPorts notes ports that a rule opens although nothing listens there.
func (b *builder) unusedPorts() {
	var found []Finding
	for i := range b.result.UnusedRules {
		unused := &b.result.UnusedRules[i]
		port := portText(unused.Protocol, unused.First, unused.Last)
		rule := &unused.Rule
		finding := Finding{
			Code:      string(models.FindingUnusedRule),
			Severity:  models.SeverityInfo,
			Certainty: unused.Certainty,
			Category:  "hygiene",
			Families:  []int{int(unused.IPVersion)},
			Title:     port + " is open, but nothing listens on it",
			Detail: stack(unused.IPVersion) + ": " + ruleName(rule) + " accepts the port from " + audience(unused.Scope) +
				". A service that starts on it later is reachable at once.",
			Ports: []string{port},
			Rules: []RuleRef{b.ref(rule, "accepts")},
			Fix:   &Fix{Summary: "Remove the port from the rule if the service is gone."},
		}
		if unused.NATRule != nil {
			local := strconv.Itoa(unused.LocalPort)
			finding.Title = port + " is redirected to local port " + local + ", but nothing listens there"
			finding.Detail = stack(unused.IPVersion) + ": " + ruleName(unused.NATRule) + " sends the port to local port " + local + ", and " +
				ruleName(rule) + " accepts it from " + audience(unused.Scope) + ". A service that starts on port " + local + " later is reachable at once."
			finding.Rules = append([]RuleRef{b.ref(unused.NATRule, "redirects")}, finding.Rules...)
			finding.Fix = &Fix{Summary: "Delete the redirect and the rule that accepts its port if the service is gone."}
		}
		// Only a rule that opens exactly these ports can be deleted for them.
		if ranges := strings.ReplaceAll(rule.DstPort, ":", "-"); ranges == strings.TrimSuffix(port, "/"+string(unused.Protocol)) && b.owner(rule) == "" {
			finding.Fix = &Fix{
				Summary: "Delete the rule if the service is gone.",
				Steps: []FixStep{{"Delete the rule", firewallCommand(unused.IPVersion) + tableOption(rule.Table) + " -D " +
					shellQuote(rule.Chain) + " " + strconv.Itoa(rule.RuleNum)}},
			}
		}
		found = append(found, finding)
	}
	for _, finding := range b.joinMany(found, "open ports have no listener", "Rules accept these ports, but nothing listens on them.",
		"Remove a port from its rule, or delete the rule, when the service is gone.") {
		b.add(finding)
	}
}

func audience(scope models.AccessScope) string {
	switch scope {
	case models.ScopeSubnet:
		return "specific public networks"
	case models.ScopeLocalnet:
		return "private networks"
	case models.ScopeWhitelisted:
		return "single hosts"
	case models.ScopeRestricted:
		return "a set of sources that was not evaluated"
	}
	return "any source"
}

// shadowedRules reports rules that an earlier rule covers, one finding for
// each covering rule.
func (b *builder) shadowedRules() {
	type key struct {
		version      models.IPVersion
		table, chain string
		num          int
	}
	groups := map[key][]*models.ShadowFinding{}
	var order []key
	for i := range b.result.ShadowedRules {
		shadow := &b.result.ShadowedRules[i]
		rule := &shadow.ShadowingRule
		k := key{rule.IPVersion, rule.Table, rule.Chain, rule.RuleNum}
		if groups[k] == nil {
			order = append(order, k)
		}
		groups[k] = append(groups[k], shadow)
	}
	for _, k := range order {
		members := groups[k]
		covering := &members[0].ShadowingRule
		finding := Finding{
			Code:      string(models.FindingShadowedRule),
			Severity:  models.SeverityMedium,
			Certainty: models.CertaintyDefinite,
			Category:  "paths",
			Families:  []int{int(k.version)},
			Rules:     []RuleRef{b.ref(covering, "shadows")},
			Fix:       &Fix{Summary: "Move the rule above the one that covers it if it must apply, or delete it."},
		}
		var numbers []int
		opposite := 0
		for _, member := range members {
			numbers = append(numbers, member.ShadowedRule.RuleNum)
			if member.Severity >= models.SeverityHigh {
				finding.Severity = models.SeverityHigh
				finding.Points += 5
				opposite++
			} else {
				finding.Points += 2
			}
			if len(finding.Rules) < 9 {
				finding.Rules = append(finding.Rules, b.ref(&member.ShadowedRule, "shadowed"))
			}
		}
		where := k.table + "/" + k.chain
		if len(numbers) == 1 {
			finding.Title = fmt.Sprintf("Rule #%d in %s is shadowed by rule #%d", numbers[0], where, k.num)
		} else {
			finding.Title = fmt.Sprintf("%d rules in %s are shadowed by rule #%d", len(numbers), where, k.num)
		}
		finding.Detail = fmt.Sprintf("Rule #%d (%s) comes first and matches every packet that %s would match, so %s never applies.",
			k.num, analyzer.RuleSpec(covering), ruleNumbers(numbers), pronoun(len(numbers)))
		if opposite > 0 {
			finding.Detail += fmt.Sprintf(" %d of them %s the opposite decision.", opposite, plural(opposite, "has", "have"))
			if len(numbers) == 1 {
				finding.Detail = strings.Replace(finding.Detail, " 1 of them has the opposite decision.", " It has the opposite decision.", 1)
			}
		}
		b.add(finding)
	}
}

func ruleNumbers(numbers []int) string {
	sort.Ints(numbers)
	if len(numbers) == 1 {
		return "rule #" + strconv.Itoa(numbers[0])
	}
	sequential := true
	for i := 1; i < len(numbers); i++ {
		sequential = sequential && numbers[i] == numbers[i-1]+1
	}
	if sequential {
		return fmt.Sprintf("rules #%d-#%d", numbers[0], numbers[len(numbers)-1])
	}
	parts := make([]string, len(numbers))
	for i, number := range numbers {
		parts[i] = "#" + strconv.Itoa(number)
	}
	return "rules " + abbreviate(parts, 10)
}

func pronoun(n int) string {
	if n == 1 {
		return "it"
	}
	return "they"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// translatedPorts reports the findings about ports that nat/PREROUTING
// translates: Docker published ports and port forwards.
func (b *builder) translatedPorts() {
	type openKey struct {
		docker    bool
		severity  models.Severity
		certainty models.Certainty
	}
	open := map[openKey]*Finding{}
	var openOrder []openKey
	seenPort := map[string]bool{}
	// example holds, for each group, the port for which the fix is written,
	// and what the fix must say about the other ports.
	type openExample struct {
		source   *models.DockerBypassFinding
		protocol models.Protocol
		names    []string
		group    publishedGroup
	}
	examples := map[openKey]*openExample{}
	// destinations holds, for each group, its ports with their destinations.
	type portDestinations struct {
		port  string
		dests []string
	}
	destinations := map[openKey][]*portDestinations{}

	for i := range b.result.DockerBypasses {
		source := &b.result.DockerBypasses[i]
		docker := analyzer.IsDockerRule(&source.NATRule)
		protocol := source.NATRule.Protocol
		if protocol == "" || protocol == models.ProtoAll {
			protocol = models.ProtoTCP
		}
		detail := strings.TrimPrefix(source.Reason, "Possible path: ")
		finding := Finding{
			Code:      string(source.Code),
			Severity:  source.Severity,
			Certainty: source.Certainty,
			Category:  "paths",
			Families:  []int{int(source.IPVersion)},
			Detail:    detail,
		}
		bySeverity := map[models.Severity]int{models.SeverityCritical: 12, models.SeverityHigh: 5, models.SeverityMedium: 2}[source.Severity]
		if bySeverity == 0 {
			bySeverity = 1
		}
		finding.Points = weigh(bySeverity, source.Certainty)

		switch source.Code {
		case models.FindingDockerPublished:
			// Open, as INPUT would have allowed too: an exposure. Ports of one
			// kind are one finding.
			first, last, ok := parsePortRange(source.ExposedPort)
			if !ok {
				continue
			}
			port := portText(protocol, first, last)
			severity := analyzer.ExposureSeverity(first, last, "")
			points := 0
			for p := first; p <= last && p-first < 4096; p++ {
				points += weigh(exposurePoints(p, p, ""), source.Certainty)
			}
			if b.declaredPublic(protocol, first, last) {
				severity, points = models.SeverityInfo, 0
			}
			k := openKey{docker, severity, source.Certainty}
			group := open[k]
			if group == nil {
				group = &Finding{Code: string(source.Code), Severity: severity, Certainty: source.Certainty, Category: "exposure"}
				examples[k] = &openExample{source: source, protocol: protocol}
				open[k] = group
				openOrder = append(openOrder, k)
			}
			group.Families = appendUnique(group.Families, int(source.IPVersion))
			if !seenPort[port] {
				seenPort[port] = true
				group.Ports = append(group.Ports, port)
				group.Points += points
			}
			// The endpoints of one port (a Kubernetes service) are one entry.
			name := stack(source.IPVersion) + " " + port
			if source.HostAddr != "" {
				name += " of " + source.HostAddr
			}
			example := examples[k]
			if _, own, _ := strings.Cut(name, " "); !containsString(example.names, own) {
				example.names = append(example.names, own)
			}
			example.group.someAddress = example.group.someAddress || source.HostAddr != ""
			example.group.someWildcard = example.group.someWildcard || source.HostAddr == ""
			dest := source.ContainerDest
			if len(source.Interfaces) > 0 {
				dest += " (via " + strings.Join(source.Interfaces, ", ") + ")"
			}
			entries := destinations[k]
			if n := len(entries); n > 0 && entries[n-1].port == name {
				entries[n-1].dests = append(entries[n-1].dests, dest)
			} else {
				destinations[k] = append(entries, &portDestinations{port: name, dests: []string{dest}})
			}
			if len(group.Rules) < 12 {
				group.Rules = append(group.Rules, b.ref(&source.NATRule, "translates"))
			}
			continue

		case models.FindingDockerBypass:
			port := source.ExposedPort + "/" + string(protocol)
			finding.Ports = []string{port}
			kind := "published"
			if !docker {
				kind = "forwarded"
			}
			if source.InputRule.RuleNum > 0 && !analyzer.IsCatchAll(&source.InputRule) {
				finding.Title = fmt.Sprintf("%s does not protect %s port %s", ruleName(&source.InputRule), kind, port)
				finding.Rules = append(finding.Rules, b.ref(&source.InputRule, "bypassed"))
			} else {
				finding.Title = fmt.Sprintf("%s port %s passes the default deny of INPUT", strings.ToUpper(kind[:1])+kind[1:], port)
			}
			finding.Rules = append(finding.Rules, b.ref(&source.NATRule, "translates"))
			finding.Fix = publishedFix(source, protocol, publishedGroup{})
			if source.Severity == models.SeverityCritical && source.Certainty == models.CertaintyDefinite {
				finding.limit("C", "a published port passes an INPUT rule that names it, for every source")
			}

		case models.FindingDockerIneffectiveRule, models.FindingDockerShadowedRule, models.FindingDockerFragileRule:
			if source.Rule == nil {
				continue
			}
			switch source.Code {
			case models.FindingDockerIneffectiveRule:
				finding.Title = ruleName(source.Rule) + " never matches published traffic"
				finding.Fix = ineffectiveRuleFix(source)
			case models.FindingDockerShadowedRule:
				finding.Title = ruleName(source.Rule) + " comes after Docker's ACCEPT rules"
				finding.Fix = ineffectiveRuleFix(source)
			default:
				finding.Title = ruleName(source.Rule) + " is above Docker's jumps, which dockerd moves"
				finding.Fix = fragileRuleFix(source)
			}
			finding.Rules = []RuleRef{b.ref(source.Rule, "ineffective")}

		case models.FindingDockerDirectRoute:
			if source.ExposedPort == "all" {
				finding.Title = "All ports of the containers on " + bridgeName(source.Bridge) + " are reachable by direct routing"
			} else {
				finding.Title = "Container port " + source.ContainerDest + " is reachable by direct routing"
			}
			finding.Fix = b.directRouteFix(source)

		case models.FindingDockerIPv6Unfiltered:
			finding.Category = "ipv6"
			finding.Points = 5
			finding.Title = "Docker does not filter IPv6 forwarding"
			finding.Fix = &Fix{Summary: source.Fix, Steps: []FixStep{{"Deny IPv6 forwarding by default", "ip6tables -P FORWARD DROP"}}}
		default:
			continue
		}
		b.add(finding)
	}

	for _, k := range openOrder {
		group := open[k]
		kind, where := "Docker published", "Docker translates these ports to containers, and filter/FORWARD accepts them from any source; the rules of filter/INPUT do not apply: "
		if !k.docker {
			kind, where = "Forwarded", "nat/PREROUTING translates these ports to another host, and filter/FORWARD accepts them from any source; the rules of filter/INPUT do not apply: "
		}
		sort.Ints(group.Families)
		if k.severity > models.SeverityInfo {
			// The fix is written for the first port and names the others.
			example := examples[k]
			example.group.others = example.names[1:]
			example.group.bothFamilies = len(group.Families) > 1
			group.Fix = publishedFix(example.source, example.protocol, example.group)
		}
		if len(group.Ports) == 1 {
			// The entry names the port with its address, when it has one.
			name := group.Ports[0]
			if entries := destinations[k]; len(entries) > 0 {
				_, name, _ = strings.Cut(entries[0].port, " ")
			}
			group.Title = kind + " port " + name + " is open to any source"
		} else {
			group.Title = fmt.Sprintf("%d %s ports are open to any source", len(group.Ports), strings.ToLower(kind[:1])+kind[1:])
			if k.docker {
				group.Title = fmt.Sprintf("%d Docker published ports are open to any source", len(group.Ports))
			}
		}
		if k.severity == models.SeverityInfo {
			group.Title = strings.Replace(group.Title, "open to any source", "public, as declared", 1)
		}
		var entries []string
		for _, entry := range destinations[k] {
			entries = append(entries, entry.port+" to "+abbreviate(entry.dests, 4))
		}
		const shown = 12
		group.Detail = where + strings.Join(entries[:min(len(entries), shown)], "; ")
		if more := len(entries) - shown; more > 0 {
			group.Detail += fmt.Sprintf("; and %d more (see the list of translated ports)", more)
		}
		group.Detail += "."
		b.add(*group)
	}
}

func bridgeName(bridge string) string {
	if bridge == "" {
		return "a bridge"
	}
	return "bridge " + bridge
}

func appendUnique(list []int, values ...int) []int {
	for _, value := range values {
		found := false
		for _, existing := range list {
			found = found || existing == value
		}
		if !found {
			list = append(list, value)
		}
	}
	return list
}

func abbreviate(values []string, limit int) string {
	if len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return strings.Join(values[:limit], ", ") + fmt.Sprintf(" and %d more", len(values)-limit)
}

// finish joins findings that say the same about both address families,
// orders them and numbers them.
func (b *builder) finish() []Finding {
	var merged []Finding
	for _, finding := range b.findings {
		joined := false
		for i := range merged {
			other := &merged[i]
			if other.Code != finding.Code || other.Title != finding.Title || other.Detail != finding.Detail ||
				other.Severity != finding.Severity || other.Certainty != finding.Certainty || other.key != finding.key ||
				len(other.Families) != 1 || len(finding.Families) != 1 || other.Families[0] == finding.Families[0] {
				continue
			}
			other.Families = appendUnique(other.Families, finding.Families...)
			sort.Ints(other.Families)
			other.Rules = append(other.Rules, finding.Rules...)
			other.Points = max(other.Points, finding.Points)
			if finding.ceiling != "" {
				other.limit(finding.ceiling, finding.ceilingReason)
			}
			if other.Fix != nil && finding.Fix != nil {
				for _, step := range finding.Fix.Steps {
					known := false
					for _, existing := range other.Fix.Steps {
						known = known || existing.Command == step.Command
					}
					if !known {
						other.Fix.Steps = append(other.Fix.Steps, step)
					}
				}
			}
			joined = true
			break
		}
		if !joined {
			merged = append(merged, finding)
		}
	}
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].Severity != merged[j].Severity {
			return merged[i].Severity > merged[j].Severity
		}
		if merged[i].Points != merged[j].Points {
			return merged[i].Points > merged[j].Points
		}
		return merged[i].order < merged[j].order
	})
	for i := range merged {
		merged[i].ID = "F" + strconv.Itoa(i+1)
	}
	return merged
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// notes lists what the reader must know about the analysis itself.
func (b *builder) notes() []Note {
	notes := []Note{}
	for _, diagnostic := range b.result.Diagnostics {
		kind := "incomplete"
		if diagnostic.Area == "services" {
			// The rules are judged without the listeners.
			kind = "scope"
		}
		notes = append(notes, Note{Kind: kind, Area: diagnostic.Area, Text: diagnostic.Message})
	}
	for _, note := range b.result.Notes {
		notes = append(notes, Note{Kind: "scope", Text: note})
	}
	if b.result.ServiceAssessment != models.AssessmentComplete {
		hint := "Add the output of \"ss -tulnp\" as another file to tell used ports from unused ones."
		switch {
		case b.opts.Live:
			hint = "The listening sockets could not be read."
		case b.opts.Snapshot:
			hint = "The snapshot holds no list of listening sockets."
		}
		notes = append(notes, Note{Kind: "scope", Area: "services",
			Text: "No list of listening sockets was read, so every open port is judged as if a service uses it. " + hint})
	}
	return notes
}
