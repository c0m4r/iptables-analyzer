package analyzer

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/c0m4r/iptables-analyzer/internal/hostinfo"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The trace follows one packet through the rules, like the TRACE target of
// the kernel does for a real packet. It uses the predicates of the symbolic
// evaluation, and it knows more: the packet has one source address, and the
// marks that rules set on the way are known. A test compares its verdicts
// with those of the kernel for real packets (kernel_linux_test.go).

// assumedSourcePort is the source port of a packet whose port was not given:
// a port from the range that clients send from.
const assumedSourcePort = 54321

// maxTraceRules bounds the rules that one trace reads. Saved rules can hold
// chains that jump into each other, which the kernel would refuse to load.
const maxTraceRules = 1 << 20

// ParsePacket reads the description of a packet:
//
//	PROTOCOL SOURCE[:PORT] [-> [DESTINATION]:PORT] [in IFACE] [out IFACE] [state STATE] [type N]
//
// for example "tcp 203.0.113.5 -> :22 in eth0". A destination without an
// address is an address of this host. An IPv6 address with a port is written
// in brackets.
func ParsePacket(spec string) (models.Packet, error) {
	packet := models.Packet{State: "NEW"}
	fields := strings.Fields(spec)
	if len(fields) < 2 {
		return packet, fmt.Errorf("a packet needs a protocol and a source address, for example: tcp 203.0.113.5 -> :22 in eth0")
	}
	switch protocol := strings.ToLower(fields[0]); protocol {
	case "tcp", "udp", "icmp":
		packet.Protocol = models.Protocol(protocol)
	case "icmpv6", "icmp6", "ipv6-icmp":
		packet.Protocol = "ipv6-icmp"
	default:
		return packet, fmt.Errorf("protocol %q: use tcp, udp, icmp or icmpv6", fields[0])
	}
	source, port, hasPort, err := splitEndpoint(fields[1])
	if err != nil || source == "" {
		return packet, fmt.Errorf("source %q: give an address, with a port as ADDRESS:PORT or [ADDRESS]:PORT", fields[1])
	}
	packet.Source = source
	if hasPort {
		packet.SourcePort = port
	}
	rest := fields[2:]
	if len(rest) > 0 && (rest[0] == "->" || rest[0] == "to") {
		if len(rest) < 2 {
			return packet, fmt.Errorf("%q needs a destination", rest[0])
		}
		destination, port, hasPort, err := splitEndpoint(rest[1])
		if err != nil {
			return packet, fmt.Errorf("destination %q: give :PORT, ADDRESS:PORT or [ADDRESS]:PORT", rest[1])
		}
		packet.Destination = destination
		if hasPort {
			packet.Port = port
		}
		rest = rest[2:]
	}
	if len(rest)%2 != 0 {
		return packet, fmt.Errorf("%q needs a value", rest[len(rest)-1])
	}
	for i := 0; i < len(rest); i += 2 {
		value := rest[i+1]
		switch rest[i] {
		case "in", "out":
			// The name is printed and compared with the rules: it must be
			// what the kernel accepts as the name of an interface.
			if len(value) > 15 || strings.ContainsAny(value, "/:") || strings.IndexFunc(value, func(r rune) bool {
				return unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar
			}) >= 0 {
				return packet, fmt.Errorf("%q is not the name of an interface", value)
			}
			if rest[i] == "in" {
				packet.In = value
			} else {
				packet.Out = value
			}
		case "state":
			packet.State = strings.ToUpper(value)
			switch packet.State {
			case "NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED":
			default:
				return packet, fmt.Errorf("state %q: use NEW, ESTABLISHED, RELATED, INVALID or UNTRACKED", value)
			}
		case "type":
			if _, err := strconv.Atoi(value); err != nil {
				return packet, fmt.Errorf("type %q: give the number of the ICMP type", value)
			}
			packet.ICMPType = value
		default:
			return packet, fmt.Errorf("unknown word %q: use in, out, state or type", rest[i])
		}
	}
	tcpOrUDP := packet.Protocol == models.ProtoTCP || packet.Protocol == models.ProtoUDP
	switch {
	case tcpOrUDP && (packet.Port < 1 || packet.Port > 65535):
		return packet, fmt.Errorf("a %s packet needs a destination port, for example: -> :22", packet.Protocol)
	case !tcpOrUDP && (packet.Port != 0 || packet.SourcePort != 0):
		return packet, fmt.Errorf("an ICMP packet has no port")
	}
	src, _ := netip.ParseAddr(packet.Source)
	if packet.Destination != "" {
		if dst, _ := netip.ParseAddr(packet.Destination); dst.Is4() != src.Is4() {
			return packet, fmt.Errorf("source and destination are of different address families")
		}
	}
	if (packet.Protocol == "ipv6-icmp" && src.Is4()) || (packet.Protocol == models.ProtoICMP && !src.Is4()) {
		return packet, fmt.Errorf("protocol %s does not go with the address %s", fields[0], packet.Source)
	}
	return packet, nil
}

// splitEndpoint reads ":PORT", "ADDRESS", "ADDRESS:PORT" and "[ADDRESS]:PORT".
func splitEndpoint(text string) (address string, port int, hasPort bool, err error) {
	portText := ""
	switch {
	case strings.HasPrefix(text, "["):
		end := strings.Index(text, "]")
		if end < 0 {
			return "", 0, false, fmt.Errorf("unterminated bracket")
		}
		address = text[1:end]
		if after := text[end+1:]; after != "" {
			if !strings.HasPrefix(after, ":") {
				return "", 0, false, fmt.Errorf("unexpected text after the bracket")
			}
			portText, hasPort = after[1:], true
		}
	case strings.Count(text, ":") == 1:
		address, portText, _ = strings.Cut(text, ":")
		hasPort = true
	default:
		address = text // an IPv4 address, or an IPv6 address without a port
	}
	if address != "" {
		parsed, err := netip.ParseAddr(address)
		if err != nil || parsed.Zone() != "" {
			return "", 0, false, fmt.Errorf("invalid address")
		}
		address = parsed.String()
	}
	if hasPort {
		if port, err = strconv.Atoi(portText); err != nil || port < 1 || port > 65535 {
			return "", 0, false, fmt.Errorf("invalid port")
		}
	}
	return address, port, hasPort, nil
}

// PacketVersion returns the address family of a packet.
func PacketVersion(packet models.Packet) models.IPVersion {
	if addr, err := netip.ParseAddr(packet.Source); err == nil && !addr.Is4() {
		return models.IPv6
	}
	return models.IPv4
}

// traceOutcome is how a packet leaves a chain.
type traceOutcome int

const (
	traceContinues  traceOutcome = iota // no rule decided
	traceAccepted                       // ACCEPT
	traceDropped                        // DROP
	traceRejected                       // REJECT
	traceTranslated                     // a new destination
	traceUnknown                        // handed to a program, or not followed
)

// maxTraceRuns bounds the ways through the rules that one trace follows
// when rules may or may not match.
const maxTraceRuns = 48

// decision is a rule whose match the packet alone does not decide.
type decision struct {
	rule *models.Rule
	note string
}

type tracer struct {
	eval   *inputEvaluator
	source addrSet
	query  packetQuery
	trace  *models.Trace
	stage  *models.TraceStage
	path   map[string]bool
	budget int
	// by names the rule or policy that decided the last hook.
	by string
	// nat is the rule that translated the destination.
	nat *models.Rule
	// forced holds the rules that this run takes as matching although the
	// packet does not decide them; open collects the others that it met.
	forced map[*models.Rule]bool
	open   []decision
	// unsettled: the kernel may drop the packet for a reason that the input
	// does not tell (route_localnet).
	unsettled string
	// The marks of the packet and of its connection. They are unknown after a
	// rule that may match has set one.
	mark, connMark           uint32
	markKnown, connMarkKnown bool
	// untracked: a rule took the packet out of connection tracking.
	untracked bool
	// filtered: the filter table has decided, which names the verdict best.
	filtered bool
}

// Trace follows one packet through the rules of its address family. Where a
// rule may or may not match, it follows the packet as if the rule did not,
// and then follows every other way to say how the packet ends there.
func Trace(rs *models.Ruleset, host *models.HostContext, packet models.Packet) *models.Trace {
	version := PacketVersion(packet)
	if rs == nil {
		rs = &models.Ruleset{IPVersion: version, Tables: map[string]*models.Table{}}
	}
	eval := newInputEvaluator(rs, host)
	first := traceRun(eval, packet, nil)
	result := first.trace
	if first.unsettled != "" {
		result.Alternatives = append(result.Alternatives, models.TraceEnd{If: first.unsettled, Verdict: "DROP", DecidedBy: "the kernel"})
	}

	// Each way is a set of rules that are taken as matching.
	type way struct {
		forced map[*models.Rule]bool
		label  string
	}
	extend := func(base way, open []decision) []way {
		var ways []way
		for _, next := range open {
			forced := map[*models.Rule]bool{next.rule: true}
			for rule := range base.forced {
				forced[rule] = true
			}
			label := ruleLabel(next.rule) + " matches (" + next.note + ")"
			if base.label != "" {
				label = base.label + " and " + label
			}
			ways = append(ways, way{forced: forced, label: label})
		}
		return ways
	}
	queue := extend(way{}, first.open)
	for runs := 0; len(queue) > 0; runs++ {
		if runs == maxTraceRuns {
			result.Alternatives = append(result.Alternatives, models.TraceEnd{
				If: "another combination of the rules that may match applies", Verdict: "UNDECIDED", DecidedBy: "too many ways to follow"})
			break
		}
		current := queue[0]
		queue = queue[1:]
		run := traceRun(eval, packet, current.forced)
		end := run.trace
		result.Alternatives = append(result.Alternatives, models.TraceEnd{If: current.label, Verdict: end.Verdict, DecidedBy: end.DecidedBy,
			Delivery: end.Delivery, Destination: end.Destination, Port: end.Port})
		if run.unsettled != "" {
			result.Alternatives = append(result.Alternatives, models.TraceEnd{If: current.label + " and " + run.unsettled, Verdict: "DROP", DecidedBy: "the kernel"})
		}
		queue = append(queue, extend(current, run.open)...)
	}
	result.Certain = result.Verdict != "UNDECIDED"
	for _, other := range result.Alternatives {
		if other.Verdict != result.Verdict {
			result.Certain = false
		}
	}
	return result
}

// traceRun follows the packet once. forced names the rules to take as
// matching where the packet does not decide.
func traceRun(eval *inputEvaluator, packet models.Packet, forced map[*models.Rule]bool) *tracer {
	version := eval.rs.IPVersion
	host := eval.host
	result := &models.Trace{Packet: packet, Family: int(version), Verdict: "ACCEPT"}
	src, _ := netip.ParseAddr(packet.Source)
	t := &tracer{
		eval: eval, trace: result, path: map[string]bool{}, budget: maxTraceRules, forced: forced,
		source: setOfPrefix(netip.PrefixFrom(src, src.BitLen())), markKnown: true, connMarkKnown: true,
	}
	t.query = packetQuery{
		Protocol: packet.Protocol, SrcPort: packet.SourcePort, DstPort: packet.Port, DstAddr: packet.Destination,
		DstType: "LOCAL", InIface: packet.In, State: packet.State, NATState: noNAT,
		OriginalDstAddr: packet.Destination, OriginalDstPort: packet.Port, Direction: "ORIGINAL",
		External: packet.In != "lo", ICMPType: packet.ICMPType, Ctx: t.eval.ctx,
	}
	tcpOrUDP := packet.Protocol == models.ProtoTCP || packet.Protocol == models.ProtoUDP
	if tcpOrUDP && packet.SourcePort == 0 {
		t.query.SrcPort = assumedSourcePort
		t.assume(fmt.Sprintf("The source port was not given: %d stands for a port that a client sends from.", assumedSourcePort))
	}
	if packet.In == "" {
		t.assume("The ingress interface was not given: a rule that names an interface may match (add \"in IFACE\").")
	}

	// Where the packet goes before any translation.
	forwarded := packet.Out != ""
	if dst, err := netip.ParseAddr(packet.Destination); err == nil && !forwarded {
		switch local, known := t.eval.isLocal(dst); {
		case known && !local:
			forwarded = true
		case !known:
			t.assume(packet.Destination + " is taken as an address of this host. Add \"out IFACE\" for a packet that this host routes on.")
		}
	}
	if forwarded {
		t.query.DstType = "UNICAST"
	}

	// PREROUTING: raw, mangle, then nat for the first packet of a connection.
	// The raw table runs before connection tracking: a packet has no
	// connection there, which the conntrack match reports as INVALID.
	raw := t.query
	raw.State = "INVALID"
	if !t.hook("raw", "PREROUTING", raw) || !t.hook("mangle", "PREROUTING", t.query) {
		return t.finish()
	}
	if packet.State == "NEW" && tcpOrUDP {
		if !t.translate() {
			return t.finish()
		}
		forwarded = t.query.DstType == "UNICAST"
	}

	// The routing decision. The kernel first tests the way back to the source.
	if sources, bounded := t.eval.arriving(packet.In); bounded && !sources.contains(src) {
		setting, _ := hostinfo.InterfaceSetting(host, "rp_filter", packet.In)
		result.Verdict = "DROP"
		result.DecidedBy = "the kernel: the reverse-path filter of " + packet.In + " (rp_filter is " + setting +
			") refuses a source whose route does not leave through that interface"
		if setting == "2" {
			result.DecidedBy = "the kernel: the reverse-path filter of " + packet.In + " (rp_filter is 2) refuses a source that has no route"
		}
		return t.finish()
	}
	hooks := []string{"mangle", "filter", "security"}
	chain := "INPUT"
	result.Delivery = "local"
	if forwarded {
		if on, known := host.Forwarding(version); known && !on {
			result.Verdict = "DROP"
			result.DecidedBy = "the kernel: this host does not route packets (" + forwardingSetting(version) + " is 0)"
			return t.finish()
		}
		chain, result.Delivery = "FORWARD", "forward"
		t.query.OutIface = packet.Out
		if t.query.OutIface == "" {
			t.query.OutIface = t.eval.egress(t.query.DstAddr)
		}
		if t.query.OutIface == "" {
			t.assume("The egress interface is not known: a rule that names one may match (add \"out IFACE\").")
		}
	}
	result.Destination, result.Port = t.query.DstAddr, t.query.DstPort
	for _, table := range hooks {
		if !t.hook(table, chain, t.query) {
			break
		}
	}
	return t.finish()
}

func (t *tracer) assume(text string) {
	for _, known := range t.trace.Assumptions {
		if known == text {
			return
		}
	}
	t.trace.Assumptions = append(t.trace.Assumptions, text)
}

// finish completes the result of one run.
func (t *tracer) finish() *tracer {
	result := t.trace
	if result.Verdict != "ACCEPT" {
		result.Delivery, result.Destination, result.Port = "", "", 0
		t.unsettled = ""
	}
	if result.DecidedBy == "" {
		result.DecidedBy = "no table on the way of the packet is loaded"
	}
	return t
}

// hook passes the packet through a built-in chain. It returns false when the
// packet does not go on to the next hook.
func (t *tracer) hook(tableName, chainName string, query packetQuery) bool {
	table := t.eval.rs.Tables[tableName]
	if table == nil || table.Chains[chainName] == nil {
		return true // a table that is not loaded passes every packet
	}
	t.trace.Stages = append(t.trace.Stages, models.TraceStage{Table: tableName, Chain: chainName, Steps: []models.TraceStep{}})
	t.stage = &t.trace.Stages[len(t.trace.Stages)-1]
	query.Chain, query.Hook = chainName, chainName
	outcome := t.chain(table, chainName, query, 0)
	if t.untracked {
		t.query.State = "UNTRACKED"
	}
	if outcome == traceContinues {
		policy := table.Chains[chainName].Policy
		t.by = "the policy of " + tableName + "/" + chainName
		t.stage.Result = "no rule decides: policy " + policy
		if policy == "DROP" {
			outcome = traceDropped
		} else {
			outcome = traceAccepted
		}
	}
	switch outcome {
	case traceDropped:
		t.trace.Verdict, t.trace.DecidedBy = "DROP", t.by
	case traceRejected:
		t.trace.Verdict, t.trace.DecidedBy = "REJECT", t.by
	case traceUnknown:
		t.trace.Verdict, t.trace.DecidedBy = "UNDECIDED", t.by
	default:
		// The verdict of the filter table says most about an accepted packet.
		if tableName != "nat" && (tableName == "filter" || !t.filtered) {
			t.trace.DecidedBy = t.by
			t.filtered = t.filtered || tableName == "filter"
		}
		return true
	}
	return false
}

// translate passes the packet through nat/PREROUTING and gives it the new
// destination of the rule that it meets.
func (t *tracer) translate() bool {
	table := t.eval.rs.Tables["nat"]
	if table == nil || table.Chains["PREROUTING"] == nil {
		return true
	}
	t.nat = nil
	if !t.hook("nat", "PREROUTING", t.query) {
		return false
	}
	if t.nat == nil {
		// An ACCEPT in the nat table only ends that table.
		t.stage.Result = "the destination stays"
		return true
	}
	port := portClass{first: t.query.DstPort, last: t.query.DstPort}
	target, ok := t.eval.translate(t.nat, t.query, port)
	if !ok {
		t.trace.Verdict, t.trace.DecidedBy = "UNDECIDED", ruleLabel(t.nat)
		t.stage.Result = "the new destination cannot be followed"
		if parsed, err := parseDNATTranslation(t.nat.DNATTarget); err == nil && t.nat.Target == "DNAT" {
			if addr, err := netip.ParseAddr(parsed.Address); err == nil && addr.IsLoopback() {
				t.trace.Verdict = "DROP"
				t.stage.Result = "new destination " + parsed.Address + ": the kernel drops packets of other hosts for a loopback address"
			}
		}
		return false
	}
	if target.uncertain {
		t.unsettled = "route_localnet is not set for the ingress interface, so that the kernel drops a packet of another host for " + target.addr
		t.assume("route_localnet is taken as set: without it the kernel drops a packet of another host for " + target.addr + ".")
	}
	t.query.DstPort, t.query.NATState = target.port, "DNAT"
	t.query.DstAddr = target.addr
	t.query.DstType = "UNICAST"
	destination := "this host"
	if target.local {
		t.query.DstType = "LOCAL"
		if target.addr != "" {
			destination = target.addr
		}
	} else {
		destination = target.addr
	}
	t.stage.Result = fmt.Sprintf("new destination: %s, port %d", destination, target.port)
	return true
}

func ruleLabel(rule *models.Rule) string {
	return rule.Table + "/" + rule.Chain + " #" + strconv.Itoa(rule.RuleNum)
}

// chain passes the packet through the rules of one chain.
func (t *tracer) chain(table *models.Table, name string, query packetQuery, depth int) traceOutcome {
	chain := table.Chains[name]
	if chain == nil {
		return traceContinues
	}
	if t.path[name] {
		t.by = "a loop of chains at " + table.Name + "/" + name
		return traceUnknown
	}
	t.path[name] = true
	defer delete(t.path, name)
	query.Chain = name

	for i := range chain.Rules {
		rule := &chain.Rules[i]
		if t.budget--; t.budget < 0 {
			t.by = "too many rules to follow"
			return traceUnknown
		}
		certainty, note := t.match(rule, query)
		if certainty == matchNo {
			continue
		}
		_, isChain := table.Chains[rule.Target]
		step := models.TraceStep{Table: table.Name, Chain: name, Num: rule.RuleNum, Spec: RuleSpec(rule), Depth: depth, Match: "yes", Note: note}
		if certainty == matchMaybe {
			deciding := isChain || translates(table, rule)
			switch rule.Target {
			case "ACCEPT", "DROP", "REJECT", "RETURN", "QUEUE", "NFQUEUE":
				deciding = true
			}
			switch {
			case !deciding:
				// A rule that does not decide needs no line. A mark that it may
				// have set is not known from here on.
				switch rule.Target {
				case "MARK":
					t.markKnown = false
				case "CONNMARK":
					t.markKnown, t.connMarkKnown = false, false
				}
				continue
			case t.forced[rule]:
				// This run follows the way on which the rule matches.
				step.Note = "taken as matching: " + note
			default:
				// The packet alone does not decide. This run goes on without
				// the rule; another run follows the way on which it matches.
				step.Match, step.Action = "maybe", "skipped"
				t.stage.Steps = append(t.stage.Steps, step)
				known := false
				for _, other := range t.open {
					known = known || other.rule == rule
				}
				if !known {
					t.open = append(t.open, decision{rule: rule, note: note})
				}
				continue
			}
		}

		switch {
		case isChain:
			step.Action = "jump"
			if rule.Goto {
				step.Action = "goto"
			}
			t.stage.Steps = append(t.stage.Steps, step)
			if outcome := t.chain(table, rule.Target, query, depth+1); outcome != traceContinues {
				return outcome
			}
			if rule.Goto {
				return traceContinues // the chain is not resumed
			}
		case translates(table, rule):
			step.Action = rule.Target
			t.stage.Steps = append(t.stage.Steps, step)
			t.nat, t.by = rule, ruleLabel(rule)
			return traceTranslated
		case rule.Target == "ACCEPT":
			step.Action = "ACCEPT"
			t.stage.Steps = append(t.stage.Steps, step)
			t.by, t.stage.Result = ruleLabel(rule), "ACCEPT"
			return traceAccepted
		case rule.Target == "DROP" || rule.Target == "REJECT":
			step.Action = rule.Target
			t.stage.Steps = append(t.stage.Steps, step)
			t.by, t.stage.Result = ruleLabel(rule), rule.Target
			if rule.Target == "REJECT" {
				return traceRejected
			}
			return traceDropped
		case rule.Target == "RETURN":
			step.Action = "RETURN"
			t.stage.Steps = append(t.stage.Steps, step)
			return traceContinues
		case rule.Target == "QUEUE" || rule.Target == "NFQUEUE":
			step.Action = rule.Target
			t.stage.Steps = append(t.stage.Steps, step)
			t.by, t.stage.Result = ruleLabel(rule), "a program decides"
			return traceUnknown
		default:
			// LOG, MARK, CT and other targets let the packet go on.
			step.Action = "continue"
			if note := t.apply(rule, &query); note != "" {
				step.Note = strings.TrimSpace(step.Note + " " + note)
			}
			if rule.Target == "LOG" || rule.Target == "NFLOG" || step.Note != "" {
				t.stage.Steps = append(t.stage.Steps, step)
			}
		}
	}
	return traceContinues
}

// match tests a rule against the packet. A condition that depends on earlier
// packets is judged for a first packet that stays below every limit.
func (t *tracer) match(rule *models.Rule, query packetQuery) (matchCertainty, string) {
	query.Mark, query.ConnMark = nil, nil
	if t.markKnown {
		query.Mark = &t.mark
	}
	if t.connMarkKnown {
		query.ConnMark = &t.connMark
	}
	result := ruleMatch(rule, query)
	if result.certainty == matchNo {
		return matchNo, ""
	}
	matched, _, known := splitBySource(t.source, rule, query)
	if known && matched.empty() {
		return matchNo, ""
	}
	if !known {
		return matchMaybe, "the source predicate cannot be read"
	}
	if result.certainty == matchYes {
		return matchYes, ""
	}
	switch result.kind {
	case kindConditional:
		if holds, decided := firstPacket(rule); decided {
			t.assume("Rate and connection limits are judged for a first packet, which stays below them.")
			if !holds {
				return matchNo, ""
			}
			return matchYes, "below the limit"
		}
		return matchMaybe, "depends on: " + result.label
	case kindNarrow, kindBroad:
		return matchMaybe, "depends on: " + result.label
	}
	if modules := unjudgedModules(rule); modules != "" {
		return matchMaybe, "depends on a match that is not evaluated: " + modules
	}
	switch {
	case rule.OutIface != "" && query.OutIface == "":
		return matchMaybe, "the egress interface is not known"
	case rule.InIface != "" && query.InIface == "":
		return matchMaybe, "the ingress interface was not given"
	case rule.DstAddr != "" && wildcardAddress(query.DstAddr):
		return matchMaybe, "the address of this host that the packet is for was not given"
	}
	return matchMaybe, "depends on a predicate that the packet does not decide"
}

// firstPacket judges the conditions of a rule that depend on the packets
// seen before, for the first packet of a source that stays below every
// limit. decided is false when the rule has another kind of condition.
func firstPacket(rule *models.Rule) (holds, decided bool) {
	holds = true
	for i := range rule.Matches {
		ext := &rule.Matches[i]
		below := true // the rule matches below the limit
		switch ext.Module {
		case "limit":
		case "hashlimit":
			_, above := ext.Params["--hashlimit-above"]
			below = !above
		case "connlimit":
			_, above := ext.Params["--connlimit-above"]
			below = !above != ext.Negations["--connlimit-above"]
		case "recent":
			if _, set := ext.Params["--set"]; set {
				continue
			}
			if _, limited := ext.Params["--hitcount"]; !limited {
				return false, false // a list of sources, not a limit
			}
			below = false
			for _, key := range []string{"--rcheck", "--update", "--remove"} {
				if ext.Negations[key] {
					below = true
				}
			}
		case "statistic", "time", "length", "string", "u32", "tos", "dscp", "ecn", "tcpmss", "ttl":
			return false, false
		default:
			continue
		}
		holds = holds && below
	}
	return holds, true
}

// unjudgedModules names the match extensions of a rule that the evaluation
// does not model.
func unjudgedModules(rule *models.Rule) string {
	var names []string
	for _, ext := range rule.Matches {
		switch ext.Module {
		case "tcp", "udp", "comment", "conntrack", "state", "multiport", "addrtype", "icmp", "icmp6", "icmpv6",
			"hl", "iprange", "pkttype", "limit", "hashlimit", "connlimit", "raw":
			continue
		}
		if !containsString(names, ext.Module) {
			names = append(names, ext.Module)
		}
	}
	return strings.Join(names, ", ")
}

// apply carries out a target that changes the packet and lets it go on.
func (t *tracer) apply(rule *models.Rule, query *packetQuery) string {
	args := rule.TargetArgs
	option := func(name string) (string, bool) {
		for i := 0; i < len(args); i++ {
			if args[i] == name {
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
					return args[i+1], true
				}
				return "", true
			}
		}
		return "", false
	}
	set := func(mark *uint32, what string) string {
		for _, operation := range []string{"--set-xmark", "--set-mark", "--and-mark", "--or-mark", "--xor-mark"} {
			text, found := option(operation)
			if !found {
				continue
			}
			value, mask, ok := parseMark(text)
			if !ok {
				return ""
			}
			switch operation {
			case "--set-xmark":
				*mark = (*mark &^ mask) ^ value
			case "--set-mark":
				*mark = (*mark &^ mask) | value
			case "--and-mark":
				*mark &= value
			case "--or-mark":
				*mark |= value
			case "--xor-mark":
				*mark ^= value
			}
			return fmt.Sprintf("%s is now 0x%x", what, *mark)
		}
		return ""
	}
	switch rule.Target {
	case "MARK":
		if !t.markKnown {
			return ""
		}
		return set(&t.mark, "the mark")
	case "CONNMARK":
		if !t.markKnown || !t.connMarkKnown {
			t.markKnown, t.connMarkKnown = false, false
			return ""
		}
		if _, save := option("--save-mark"); save {
			t.connMark = t.mark
			return fmt.Sprintf("the connection mark is now 0x%x", t.connMark)
		}
		if _, restore := option("--restore-mark"); restore {
			t.mark = t.connMark
			return fmt.Sprintf("the mark is now 0x%x", t.mark)
		}
		return set(&t.connMark, "the connection mark")
	case "NOTRACK":
		t.untracked, query.State = true, "UNTRACKED"
		return "the packet is not tracked"
	case "CT":
		if containsToken(args, "--notrack") {
			t.untracked, query.State = true, "UNTRACKED"
			return "the packet is not tracked"
		}
	}
	return ""
}
