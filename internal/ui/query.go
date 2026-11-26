package ui

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/report"
)

// This file renders the answers to the two questions that the command
// answers besides the report: what the rules do with one packet (--trace),
// and what a change of the rules changes (--diff).

// packetText describes a packet in one line.
func packetText(packet models.Packet, family int) string {
	source := packet.Source
	if packet.SourcePort != 0 {
		source = bracket(source) + ":" + strconv.Itoa(packet.SourcePort)
	}
	destination := "this host"
	if packet.Destination != "" {
		destination = packet.Destination
	}
	if packet.Port != 0 {
		destination += ", port " + strconv.Itoa(packet.Port)
	}
	protocol := string(packet.Protocol)
	if packet.ICMPType != "" {
		protocol += " type " + packet.ICMPType
	}
	parts := []string{protocol + " " + source + " → " + destination}
	if packet.In != "" {
		parts = append(parts, "in "+packet.In)
	}
	if packet.Out != "" {
		parts = append(parts, "out "+packet.Out)
	}
	state := "new connection"
	if packet.State != "NEW" {
		state = "state " + packet.State
	}
	return strings.Join(append(parts, state, "IPv"+strconv.Itoa(family)), " · ")
}

// deliveryText says where an accepted packet arrives.
func deliveryText(delivery, destination string, port int, packet models.Packet) string {
	where := ""
	if port != 0 {
		where = "port " + strconv.Itoa(port)
	}
	switch delivery {
	case "local":
		text := "This host receives the packet"
		if where != "" {
			text += " on " + where
		}
		if destination != "" && destination != packet.Destination {
			text += " of " + destination
		}
		if port != packet.Port || (destination != "" && destination != packet.Destination) {
			text += ", its new destination"
		}
		return text + "."
	case "forward":
		text := "This host sends the packet on to " + destination
		if where != "" {
			text += ", " + where
		}
		if destination != packet.Destination || port != packet.Port {
			text += ", its new destination"
		}
		return text + "."
	}
	return ""
}

// RenderTrace writes the way of one packet through the rules.
func RenderTrace(w io.Writer, result *report.TraceReport, opts TextOptions) error {
	tracked := &trackingWriter{writer: w}
	width := opts.Width
	if width == 0 {
		width = defaultWidth
	}
	t := &textReport{w: tracked, opts: opts, width: clampWidth(width)}
	trace := result.Trace
	header := &report.Report{Mode: result.Mode, Host: result.Host, Captured: result.Captured, Generated: result.Generated}
	t.line("%s %s", styleHeader.Render(result.Tool.Name), styleMuted.Render("v"+result.Tool.Version+" · "+sourceText(header)+" · "+timeText(header)))
	if len(result.Inputs) > 0 {
		t.prose("", styleMuted, "inputs: "+strings.Join(result.Inputs, ", "))
	}
	t.line("")
	t.prose("  ", styleText, "Packet   "+packetText(trace.Packet, trace.Family))

	for _, stage := range trace.Stages {
		if len(stage.Steps) == 0 {
			// A hook without a rule for the packet needs one line.
			t.line("")
			t.line("  %s  %s", styleSubHeader.Render(stage.Table+"/"+stage.Chain), styleMuted.Render("→ "+stage.Result))
			continue
		}
		t.line("")
		t.line("  %s", styleSubHeader.Render(stage.Table+"/"+stage.Chain))
		for _, step := range stage.Steps {
			where := "#" + strconv.Itoa(step.Num)
			if step.Depth > 0 {
				where = step.Chain + " " + where
			}
			action := step.Action
			style := styleText
			if step.Match == "maybe" {
				action, style = "may match, not followed", styleMuted
			}
			indent := "    " + strings.Repeat("  ", step.Depth)
			// A rule is not wrapped. What it does goes on the next line when
			// the rule fills the line.
			if len(indent)+len(where)+len(step.Spec)+len(action)+8 <= t.width {
				t.line("%s%s  %s  %s", indent, styleLow.Render(where), style.Render(step.Spec), styleBold.Render("→ "+action))
			} else {
				t.line("%s%s  %s", indent, styleLow.Render(where), style.Render(step.Spec))
				t.line("%s    %s", indent, styleBold.Render("→ "+action))
			}
			if step.Note != "" {
				t.prose(indent+"    ", styleMuted, step.Note)
			}
		}
		if stage.Result != "" {
			t.prose("    ", styleMuted, "→ "+stage.Result)
		}
	}
	if len(trace.Stages) == 0 {
		t.line("")
		t.prose("  ", styleMuted, "No table on the way of the packet is loaded.")
	}

	t.line("")
	verdict := trace.Verdict
	if !trace.Certain && verdict != "UNDECIDED" {
		verdict += " (not certain)"
	}
	t.line("  %s  %s", styleHeader.Render("Verdict"), styleBold.Render(verdict)+styleMuted.Render(" by "+trace.DecidedBy))
	if text := deliveryText(trace.Delivery, trace.Destination, trace.Port, trace.Packet); text != "" && trace.Verdict == "ACCEPT" {
		t.prose("           ", styleText, text)
	}
	if !trace.Certain {
		t.prose("           ", styleWarning, "A rule that may match leads to another verdict. The packet alone does not decide it; see below.")
	}
	if len(trace.Alternatives) > 0 {
		t.section("When a rule that may match does match")
		for _, other := range trace.Alternatives {
			text := "If " + other.If + ": " + other.Verdict + " by " + other.DecidedBy + "."
			if delivery := deliveryText(other.Delivery, other.Destination, other.Port, trace.Packet); delivery != "" && other.Verdict == "ACCEPT" {
				text += " " + delivery
			}
			t.bullet(text)
		}
	}
	if len(trace.Assumptions) > 0 {
		t.section("Taken for granted")
		for _, assumption := range trace.Assumptions {
			t.bullet(assumption)
		}
	}
	return tracked.err
}

// bullet writes one wrapped item of a list.
func (t *textReport) bullet(text string) {
	for i, line := range wrap(text, t.width-6) {
		lead := "      "
		if i == 0 {
			lead = "    · "
		}
		t.line("%s%s", lead, styleMuted.Render(line))
	}
}

// stateWords says from where a port is reached.
func stateWords(state report.PortState) string {
	if state.Scope == "" {
		return "closed"
	}
	text := scopeWords(state.Scope)
	var qualifiers []string
	if state.LocalPort != 0 {
		qualifiers = append(qualifiers, "to local port "+strconv.Itoa(state.LocalPort))
	}
	if state.Condition != "" {
		qualifiers = append(qualifiers, state.Condition)
	}
	if state.Certainty == models.CertaintyPossible {
		qualifiers = append(qualifiers, "possible")
	}
	if len(qualifiers) > 0 {
		text += " (" + strings.Join(qualifiers, ", ") + ")"
	}
	return text
}

// forwardText describes a port that is sent to another host.
func forwardText(forward *report.Forward) string {
	host := forward.HostAddr
	if host != "" {
		host = bracket(host) + ":"
	}
	scope := scopeWords(forward.ForwardScope)
	if forward.Certainty == models.CertaintyPossible && forward.ForwardScope != "" {
		scope += ", possible"
	}
	return fmt.Sprintf("IPv%d %s%s/%s → %s: %s", forward.Family, host, portRange(forward.HostPort, forward.HostPortEnd),
		forward.Protocol, forwardDestination(*forward), scope)
}

func sideText(side report.DiffSide) string {
	header := &report.Report{Mode: side.Mode, Host: side.Host, Captured: side.Captured}
	text := sourceText(header)
	if len(side.Inputs) > 0 {
		text = strings.Join(side.Inputs, ", ") + " (" + text + ")"
	}
	return text
}

func scoreText(score report.Score) string {
	return "Grade " + score.Grade + " " + strconv.Itoa(score.Total) + "/100"
}

// diffSummary counts what differs.
func diffSummary(diff *report.Diff) string {
	var parts []string
	add := func(n int, one, many string) {
		if n > 0 {
			parts = append(parts, strconv.Itoa(n)+" "+plural(n, one, many))
		}
	}
	add(len(diff.Added), "new finding", "new findings")
	add(len(diff.Removed), "finding gone", "findings gone")
	add(len(diff.Changed), "finding changed", "findings changed")
	add(len(diff.Ports), "port range changed", "port ranges changed")
	add(len(diff.Forwards), "translated port changed", "translated ports changed")
	if len(parts) == 0 {
		return "no difference"
	}
	return strings.Join(parts, ", ")
}

// RenderDiffLine writes the comparison as one line.
func RenderDiffLine(w io.Writer, diff *report.Diff) error {
	_, err := fmt.Fprintf(w, "%d %s -> %d %s  %s\n", diff.Old.Score.Total, diff.Old.Score.Grade,
		diff.New.Score.Total, diff.New.Score.Grade, diffSummary(diff))
	return err
}

// RenderDiff writes what the new input changes: the grade, the findings and
// the ports.
func RenderDiff(w io.Writer, diff *report.Diff, opts TextOptions) error {
	tracked := &trackingWriter{writer: w}
	width := opts.Width
	if width == 0 {
		width = defaultWidth
	}
	t := &textReport{w: tracked, opts: opts, width: clampWidth(width)}
	when := &report.Report{Generated: diff.Generated}
	t.line("%s %s", styleHeader.Render(diff.Tool.Name), styleMuted.Render("v"+diff.Tool.Version+" · comparison · "+timeText(when)))
	t.prose("", styleMuted, "old: "+sideText(diff.Old))
	t.prose("", styleMuted, "new: "+sideText(diff.New))

	t.line("")
	change := diff.New.Score.Total - diff.Old.Score.Total
	points := "the same points"
	if change != 0 {
		points = fmt.Sprintf("%+d points", change)
	}
	t.line("  %s  →  %s    %s", gradeStyle(diff.Old.Score.Grade).Render(scoreText(diff.Old.Score)),
		gradeStyle(diff.New.Score.Grade).Render(scoreText(diff.New.Score)), styleMuted.Render(points))
	t.prose("  ", styleText, strings.ToUpper(diffSummary(diff)[:1])+diffSummary(diff)[1:]+".")
	for _, note := range diff.Notes {
		t.prose("  ", styleMuted, "note: "+note)
	}

	finding := func(finding report.Finding, was string) {
		severity := finding.Severity.String()
		label := severityStyle(severity).Render(severity) + strings.Repeat(" ", severityWidth-len(severity))
		title := finding.Title
		if finding.Certainty == models.CertaintyPossible {
			title += " (possible)"
		}
		if was != "" {
			title += " (" + was + ")"
		}
		points := ""
		if finding.Points > 0 {
			points = "-" + strconv.Itoa(finding.Points)
		}
		t.titleLine("    "+label, title, points)
		if opts.Verbose {
			t.prose(strings.Repeat(" ", 4+severityWidth), styleMuted, finding.Detail)
		}
	}
	if len(diff.Added) > 0 {
		t.section("New findings")
		for _, added := range diff.Added {
			finding(added, "")
		}
	}
	if len(diff.Changed) > 0 {
		t.section("Changed findings")
		for _, changed := range diff.Changed {
			var was []string
			if changed.Old.Severity != changed.New.Severity {
				was = append(was, "was "+changed.Old.Severity.String())
			}
			if changed.Old.Certainty != changed.New.Certainty {
				was = append(was, "was "+strings.ToLower(string(changed.Old.Certainty)))
			}
			if changed.Old.Points != changed.New.Points {
				was = append(was, fmt.Sprintf("was -%d", changed.Old.Points))
			}
			if familyNames(changed.Old.Families) != familyNames(changed.New.Families) {
				was = append(was, "was "+familyNames(changed.Old.Families))
			}
			finding(changed.New, strings.Join(was, ", "))
		}
	}
	if len(diff.Removed) > 0 {
		t.section("Findings that are gone")
		for _, removed := range diff.Removed {
			finding(removed, "")
		}
	}

	if len(diff.Ports) > 0 {
		t.section("Ports of this host")
		limit := 40
		if opts.Verbose || len(diff.Ports) <= limit {
			limit = len(diff.Ports)
		}
		for _, port := range diff.Ports[:limit] {
			name := portRange(port.First, port.Last)
			if port.Address != "" {
				name = bracket(port.Address) + ":" + name
			}
			style := styleText
			if port.New.Scope == "" {
				style = styleSuccess
			} else if port.New.Scope == models.ScopeExposed {
				style = styleWarning
			}
			t.line("    %s %s", styleMuted.Render(fmt.Sprintf("IPv%d %-3s %-13s", port.Family, port.Protocol, name)),
				style.Render(stateWords(port.Old)+" → "+stateWords(port.New)))
		}
		if limit < len(diff.Ports) {
			t.line("    %s", styleMuted.Render(fmt.Sprintf("... and %d more (-v)", len(diff.Ports)-limit)))
		}
	}
	if len(diff.Forwards) > 0 {
		t.section("Ports translated to other hosts")
		for _, forward := range diff.Forwards {
			switch {
			case forward.Old == nil:
				t.prose("    ", styleWarning, "new: "+forwardText(forward.New))
			case forward.New == nil:
				t.prose("    ", styleSuccess, "gone: "+forwardText(forward.Old))
			default:
				t.prose("    ", styleText, "was: "+forwardText(forward.Old))
				t.prose("    ", styleText, "now: "+forwardText(forward.New))
			}
		}
	}
	t.line("")
	return tracked.err
}
