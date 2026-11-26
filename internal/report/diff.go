package report

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// TraceReport is the result of --trace: the way of one packet through the
// rules.
type TraceReport struct {
	SchemaVersion int           `json:"schema_version"`
	Tool          Tool          `json:"tool"`
	Generated     string        `json:"generated"`
	Mode          string        `json:"mode"`
	Host          string        `json:"host,omitempty"`
	Captured      string        `json:"captured,omitempty"`
	Inputs        []string      `json:"inputs,omitempty"`
	Trace         *models.Trace `json:"trace"`
}

func modeOf(opts Options) string {
	switch {
	case opts.Live:
		return "live"
	case opts.Snapshot:
		return "snapshot"
	}
	return "file"
}

// NewTrace puts a trace together with what it was made from.
func NewTrace(trace *models.Trace, opts Options, host *models.HostContext) *TraceReport {
	result := &TraceReport{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "iptables-analyzer", Version: opts.Version, URL: repoURL},
		Generated:     opts.Now.Format(time.RFC3339),
		Mode:          modeOf(opts),
		Inputs:        opts.Inputs,
		Trace:         trace,
	}
	if opts.Snapshot {
		result.Captured = opts.Captured
	}
	if host != nil {
		result.Host = host.Hostname
	}
	return result
}

// Diff is the result of --diff: what the new input changes.
type Diff struct {
	SchemaVersion int      `json:"schema_version"`
	Tool          Tool     `json:"tool"`
	Generated     string   `json:"generated"`
	Old           DiffSide `json:"old"`
	New           DiffSide `json:"new"`
	// Added are the findings that only the new input has, and Removed those
	// that only the old one has. Changed are findings of both whose
	// severity, certainty, points or address families differ.
	Added   []Finding       `json:"added"`
	Removed []Finding       `json:"removed"`
	Changed []FindingChange `json:"changed"`
	// Ports lists the ports of the host itself whose sources differ.
	Ports []PortChange `json:"ports"`
	// Forwards lists the ports that are sent to other hosts and differ.
	Forwards []ForwardChange `json:"forwarded_ports"`
	// Notes say what could not be compared.
	Notes []string `json:"notes,omitempty"`
}

// DiffSide describes one of the two inputs.
type DiffSide struct {
	Mode     string   `json:"mode"`
	Host     string   `json:"host,omitempty"`
	Captured string   `json:"captured,omitempty"`
	Inputs   []string `json:"inputs,omitempty"`
	Families []Family `json:"families"`
	Score    Score    `json:"score"`
	Counts   Counts   `json:"counts"`
}

// FindingChange is a finding that both inputs have, in its two forms.
type FindingChange struct {
	Old Finding `json:"old"`
	New Finding `json:"new"`
}

// PortState says from where a port of the host is reached.
type PortState struct {
	// Scope is empty for a port that no source reaches.
	Scope     models.AccessScope `json:"scope,omitempty"`
	Certainty models.Certainty   `json:"certainty,omitempty"`
	Condition string             `json:"condition,omitempty"`
	// LocalPort is the local port that receives the connections when
	// nat/PREROUTING sends all of the ports to one port.
	LocalPort int `json:"local_port,omitempty"`
}

// PortChange is a range of ports of the host whose state differs.
type PortChange struct {
	Family   int    `json:"family"`
	Protocol string `json:"protocol"`
	// Address is set for ports of one local address.
	Address string    `json:"address,omitempty"`
	First   int       `json:"first"`
	Last    int       `json:"last"`
	Old     PortState `json:"old"`
	New     PortState `json:"new"`
}

// ForwardChange is a port that is sent to another host and differs. Old is
// missing for a port that only the new input sends on, and New for one that
// it sends on no more.
type ForwardChange struct {
	Old *Forward `json:"old,omitempty"`
	New *Forward `json:"new,omitempty"`
}

func side(rep *Report) DiffSide {
	return DiffSide{Mode: rep.Mode, Host: rep.Host, Captured: rep.Captured, Inputs: rep.Inputs, Families: rep.Families,
		Score: rep.Score, Counts: rep.Counts}
}

// identity names a finding in a way that does not depend on its place in
// the report.
func identity(finding *Finding) string {
	if finding.key != "" {
		return finding.Code + "|" + finding.key
	}
	return finding.Code + "|" + finding.Title
}

// Compare says what the new input changes: findings, the ports of the host
// and the ports that it sends to other hosts.
func Compare(oldReport, newReport *Report, oldResult, newResult *models.AnalysisResult) *Diff {
	diff := &Diff{
		SchemaVersion: SchemaVersion, Tool: newReport.Tool, Generated: newReport.Generated,
		Old: side(oldReport), New: side(newReport),
		Added: []Finding{}, Removed: []Finding{}, Changed: []FindingChange{}, Ports: []PortChange{}, Forwards: []ForwardChange{},
	}

	// Findings, matched by what they are about.
	before := map[string][]*Finding{}
	for i := range oldReport.Findings {
		finding := &oldReport.Findings[i]
		before[identity(finding)] = append(before[identity(finding)], finding)
	}
	for i := range newReport.Findings {
		finding := &newReport.Findings[i]
		same := before[identity(finding)]
		if len(same) == 0 {
			diff.Added = append(diff.Added, *finding)
			continue
		}
		previous := same[0]
		before[identity(finding)] = same[1:]
		if previous.Severity != finding.Severity || previous.Certainty != finding.Certainty || previous.Points != finding.Points ||
			!sameInts(previous.Families, finding.Families) {
			diff.Changed = append(diff.Changed, FindingChange{Old: *previous, New: *finding})
		}
	}
	for i := range oldReport.Findings {
		finding := &oldReport.Findings[i]
		for _, left := range before[identity(finding)] {
			if left == finding {
				diff.Removed = append(diff.Removed, *finding)
			}
		}
	}

	for _, version := range []models.IPVersion{models.IPv4, models.IPv6} {
		was, is := covered(oldResult, version), covered(newResult, version)
		switch {
		case was && is:
			diff.Ports = append(diff.Ports, portChanges(version, oldResult.OpenPorts, newResult.OpenPorts)...)
		case was:
			diff.Notes = append(diff.Notes, stack(version)+" rules are in the old input only: the ports and findings of "+stack(version)+" are not comparable.")
		case is:
			diff.Notes = append(diff.Notes, stack(version)+" rules are in the new input only: the ports and findings of "+stack(version)+" are not comparable.")
		}
	}
	diff.Forwards = forwardChanges(oldReport.Forwards, newReport.Forwards)
	if oldReport.ServicesKnown != newReport.ServicesKnown {
		diff.Notes = append(diff.Notes, "Only one of the inputs has a list of listening sockets, so findings about services and about open ports stand for each other.")
	}
	return diff
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// covered reports whether the rules of a family were read.
func covered(result *models.AnalysisResult, version models.IPVersion) bool {
	state := result.FamilyState(version)
	return state == models.FamilyAnalyzed || state == models.FamilyNoRules
}

// portChanges compares the open ports of one address family.
func portChanges(version models.IPVersion, before, after []models.OpenPort) []PortChange {
	type group struct {
		protocol models.Protocol
		address  string
	}
	entries := map[group][2][]*models.OpenPort{}
	var order []group
	add := func(list []models.OpenPort, which int) {
		for i := range list {
			open := &list[i]
			if open.IPVersion != version {
				continue
			}
			key := group{open.Protocol, open.Address}
			pair, known := entries[key]
			if !known {
				order = append(order, key)
			}
			pair[which] = append(pair[which], open)
			entries[key] = pair
		}
	}
	add(before, 0)
	add(after, 1)
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].protocol != order[j].protocol {
			return order[i].protocol < order[j].protocol
		}
		return order[i].address < order[j].address
	})

	// state returns the widest way on which a port is reached.
	state := func(list []*models.OpenPort, port int) PortState {
		var best PortState
		for _, open := range list {
			if port < open.First || port > open.Last || scopeRank(open.Scope) <= scopeRank(best.Scope) {
				continue
			}
			best = PortState{Scope: open.Scope, Certainty: open.Certainty, Condition: open.Condition}
			if open.Redirected() && open.LocalPort == open.LocalPortEnd {
				best.LocalPort = open.LocalPort
			}
		}
		return best
	}
	var changes []PortChange
	for _, key := range order {
		pair := entries[key]
		cuts := map[int]bool{1: true}
		for _, list := range pair {
			for _, open := range list {
				cuts[open.First] = true
				if open.Last < 65535 {
					cuts[open.Last+1] = true
				}
			}
		}
		starts := make([]int, 0, len(cuts))
		for cut := range cuts {
			starts = append(starts, cut)
		}
		sort.Ints(starts)
		first := len(changes)
		for i, start := range starts {
			end := 65535
			if i+1 < len(starts) {
				end = starts[i+1] - 1
			}
			was, is := state(pair[0], start), state(pair[1], start)
			if was == is {
				continue
			}
			if n := len(changes); n > first && changes[n-1].Last+1 == start && changes[n-1].Old == was && changes[n-1].New == is {
				changes[n-1].Last = end
				continue
			}
			changes = append(changes, PortChange{Family: int(version), Protocol: string(key.protocol), Address: key.address,
				First: start, Last: end, Old: was, New: is})
		}
	}
	return changes
}

// forwardChanges compares the ports that are sent to other hosts.
func forwardChanges(before, after []Forward) []ForwardChange {
	key := func(forward *Forward) string {
		return strings.Join([]string{strconv.Itoa(forward.Family), forward.Protocol, forward.HostAddr, strconv.Itoa(forward.HostPort), strconv.Itoa(forward.HostPortEnd)}, "|")
	}
	previous := map[string]*Forward{}
	for i := range before {
		previous[key(&before[i])] = &before[i]
	}
	changes := []ForwardChange{}
	seen := map[string]bool{}
	for i := range after {
		forward := &after[i]
		seen[key(forward)] = true
		was := previous[key(forward)]
		switch {
		case was == nil:
			changes = append(changes, ForwardChange{New: forward})
		case was.DestAddr != forward.DestAddr || was.DestPort != forward.DestPort || was.DestPortEnd != forward.DestPortEnd ||
			was.ForwardScope != forward.ForwardScope || was.Certainty != forward.Certainty ||
			strings.Join(was.Destinations, ",") != strings.Join(forward.Destinations, ",") ||
			strings.Join(was.Interfaces, ",") != strings.Join(forward.Interfaces, ","):
			changes = append(changes, ForwardChange{Old: was, New: forward})
		}
	}
	for i := range before {
		if !seen[key(&before[i])] {
			changes = append(changes, ForwardChange{Old: &before[i]})
		}
	}
	return changes
}
