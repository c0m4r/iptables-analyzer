package models

import "fmt"

// Protocol represents a network protocol
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoUDP  Protocol = "udp"
	ProtoICMP Protocol = "icmp"
	ProtoAll  Protocol = "all"
)

// IPVersion represents IPv4 or IPv6
type IPVersion int

const (
	IPv4 IPVersion = 4
	IPv6 IPVersion = 6
)

// FindingCode is a stable machine-readable identifier for a finding.
type FindingCode string

const (
	// FindingPolicyAccept: a built-in chain accepts the traffic that no rule
	// names, by its policy or by a rule that accepts everything.
	FindingPolicyAccept     FindingCode = "policy_accept"
	FindingDeadRule         FindingCode = "dead_rule"
	FindingMissingConntrack FindingCode = "missing_conntrack"
	FindingShadowedRule     FindingCode = "shadowed_rule"
	// FindingBroadAccept: a wide range of ports is open to any source.
	FindingBroadAccept FindingCode = "broad_accept"
	// FindingFamilyBlocked: INPUT accepts nothing at all for this family.
	FindingFamilyBlocked FindingCode = "family_blocked"
	// FindingIPv6Wider: a port is open to any source on IPv6 that IPv4
	// restricts or filters.
	FindingIPv6Wider       FindingCode = "ipv6_wider_than_ipv4"
	FindingDockerBypass    FindingCode = "docker_bypass"
	FindingExposedService  FindingCode = "exposed_service"
	FindingUnusedRule      FindingCode = "unused_rule"
	FindingMissingLoopback FindingCode = "missing_loopback"
	FindingIPv6NDPBlocked  FindingCode = "ipv6_ndp_blocked"

	// Docker-specific findings. FindingDockerBypass is reserved for published
	// ports that filter/INPUT (or its default policy) would have refused.
	FindingDockerPublished       FindingCode = "docker_published_port"
	FindingDockerIneffectiveRule FindingCode = "docker_ineffective_rule" // matches the pre-DNAT tuple
	FindingDockerShadowedRule    FindingCode = "docker_shadowed_rule"    // reached only after Docker accepted
	FindingDockerDirectRoute     FindingCode = "docker_direct_route"
	FindingDockerFragileRule     FindingCode = "docker_fragile_rule"
	FindingDockerIPv6Unfiltered  FindingCode = "docker_ipv6_unfiltered"
)

// Certainty distinguishes proven outcomes from paths that depend on an
// unsupported or otherwise indeterminate predicate.
type Certainty string

const (
	CertaintyDefinite Certainty = "DEFINITE"
	CertaintyPossible Certainty = "POSSIBLE"
)

// AssessmentStatus records whether an input-dependent part of the report was assessed.
type AssessmentStatus string

const (
	AssessmentNotRequested AssessmentStatus = "NOT_REQUESTED"
	AssessmentComplete     AssessmentStatus = "COMPLETE"
	AssessmentFailed       AssessmentStatus = "FAILED"
)

// AssessmentDiagnostic explains a portion of the analysis that was incomplete.
type AssessmentDiagnostic struct {
	Area    string
	Message string
}

// ServiceStatus records the result of assessing one listening socket.
type ServiceStatus string

const (
	ServiceNotAnalyzed ServiceStatus = "NOT_ANALYZED"
	ServiceFiltered    ServiceStatus = "FILTERED"
	ServiceReachable   ServiceStatus = "REACHABLE"
	ServiceLocalhost   ServiceStatus = "LOCALHOST"
	// ServiceInternal marks a listener that only guests of this host reach:
	// containers and virtual machines behind a bridge such as docker0 or virbr0.
	ServiceInternal ServiceStatus = "INTERNAL"
	// ServiceDocker marks a listener whose port Docker DNATs before INPUT;
	// its reachability is that of the published port.
	ServiceDocker ServiceStatus = "DOCKER_PUBLISHED"
)

// SocketFamily retains the family information conveyed by ss. A wildcard
// rendered as "*" can accept both IPv4 and IPv6 and must remain dual-stack.
type SocketFamily string

const (
	SocketIPv4 SocketFamily = "ipv4"
	SocketIPv6 SocketFamily = "ipv6"
	SocketDual SocketFamily = "dual"
)

// Severity levels for findings
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// MarshalText writes a severity as its name, so that reports do not carry
// numbers that only this program can read.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText reads a severity name.
func (s *Severity) UnmarshalText(text []byte) error {
	for _, candidate := range []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if candidate.String() == string(text) {
			*s = candidate
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", text)
}

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Rule represents a single iptables rule
type Rule struct {
	RuleNum    int
	Chain      string
	Table      string
	Target     string
	Protocol   Protocol
	SrcAddr    string
	DstAddr    string
	SrcPort    string
	DstPort    string
	InIface    string
	OutIface   string
	States     []string // conntrack states
	Matches    []MatchExt
	DNATTarget string // for DNAT: "ip:port"
	Comment    string
	Negations  map[string]bool // which fields are negated
	Goto       bool            // true for --goto/-g; false for --jump/-j
	TargetArgs []string        // options that follow the target, e.g. --notrack or --clamp-mss-to-pmtu
	Fragment   bool            // rule includes -f/--fragment
	RawLine    string
	IPVersion  IPVersion
}

// MatchExt represents a match extension module
type MatchExt struct {
	Module    string
	Params    map[string]string
	Negations map[string]bool // negated module parameters, keyed by option name
	RawTokens []string        // ordered module arguments for unsupported extensions
}

// IsTerminal returns true if this rule's target terminates packet processing
func (r *Rule) IsTerminal() bool {
	switch r.Target {
	case "ACCEPT", "DROP", "REJECT", "RETURN", "DNAT", "SNAT", "MASQUERADE", "REDIRECT":
		return true
	default:
		return false
	}
}

// IsBlock returns true if this rule blocks traffic
func (r *Rule) IsBlock() bool {
	return r.Target == "DROP" || r.Target == "REJECT"
}

// IsAllow returns true if this rule allows traffic
func (r *Rule) IsAllow() bool {
	return r.Target == "ACCEPT"
}

// Summary returns a human-readable summary of the rule
func (r *Rule) Summary() string {
	proto := string(r.Protocol)
	if proto == "" || proto == "all" {
		proto = "any"
	}
	port := r.DstPort
	if port == "" {
		port = "any"
	}
	src := r.SrcAddr
	if src == "" || src == "0.0.0.0/0" || src == "::/0" {
		src = "anywhere"
	}
	dst := r.DstAddr
	if dst == "" || dst == "0.0.0.0/0" || dst == "::/0" {
		dst = "anywhere"
	}
	return fmt.Sprintf("%s %s port %s from %s to %s", r.Target, proto, port, src, dst)
}

// Chain represents an iptables chain
type Chain struct {
	Name    string
	Policy  string // ACCEPT, DROP, or "" for custom chains
	Rules   []Rule
	Packets uint64
	Bytes   uint64
}

// Table represents an iptables table
type Table struct {
	Name   string
	Chains map[string]*Chain
}

// Ruleset is the complete parsed output
type Ruleset struct {
	IPVersion IPVersion
	Tables    map[string]*Table
	// Warnings repeat what iptables-save reported about rules that are in
	// effect but not part of its output (tables of the other backend).
	Warnings []string `json:",omitempty"`
	// Unreadable names tables that hold native nftables rules, which
	// iptables-save cannot print. Their filtering is unknown.
	Unreadable []string `json:",omitempty"`
}

// FamilyStatus tells how much is known about the rules of one address family.
type FamilyStatus string

const (
	// FamilyAnalyzed: tables were read and analyzed.
	FamilyAnalyzed FamilyStatus = "ANALYZED"
	// FamilyNoRules: the rules were read and nothing is loaded, so every
	// packet of this family is accepted.
	FamilyNoRules FamilyStatus = "NO_RULES"
	// FamilyExcluded: left out on request (-4 or -6).
	FamilyExcluded FamilyStatus = "EXCLUDED"
	// FamilyNotSupplied: file analysis without a file for this family.
	FamilyNotSupplied FamilyStatus = "NOT_SUPPLIED"
	// FamilyUnreadable: the rules are native nftables rules that
	// iptables-save cannot print.
	FamilyUnreadable FamilyStatus = "UNREADABLE"
)

// ListeningService from ss output
type ListeningService struct {
	Protocol Protocol
	Address  string
	// Device is the interface of an address shown as "addr%dev": the socket is
	// bound to that device, or the address is link-local on it. Such a socket
	// only receives packets that arrive on the device.
	Device  string `json:",omitempty"`
	Port    int
	Process string
	PID     int
	// Processes names every process that holds the socket. A socket-activated
	// daemon shares it with systemd.
	Processes  []string `json:",omitempty"`
	IsIPv6     bool
	IsWildcard bool // bound to 0.0.0.0 or ::
	Family     SocketFamily
	Status     ServiceStatus
}

// AnalysisResult holds the facts of an analysis. Package report turns them
// into the findings, the fixes and the score that are shown.
type AnalysisResult struct {
	IPv4Rules         *Ruleset
	IPv6Rules         *Ruleset
	IPv4Only          bool // the IPv6 stack was not analyzed (-4, or no IPv6 input)
	IPv6Only          bool // the IPv4 stack was not analyzed (-6, or no IPv4 input)
	IPv4Status        FamilyStatus
	IPv6Status        FamilyStatus
	ServiceAssessment AssessmentStatus
	Diagnostics       []AssessmentDiagnostic
	Notes             []string `json:",omitempty"` // scope of the analysis; not a defect of it
	Services          []ListeningService
	Host              *HostContext
	ShadowedRules     []ShadowFinding
	DockerBypasses    []DockerBypassFinding
	PublishedPorts    []PublishedPort
	ExposedServices   []ExposedServiceFinding
	OpenPorts         []OpenPort
	UnusedRules       []UnusedRuleFinding
	EffectiveIssues   []EffectivenessFinding
	Sandbox           *SandboxStatus `json:",omitempty"`
}

// FamilyState returns the status of an address family. Results that were
// built without a status get one from their rulesets: no ruleset, or one
// without tables, means that nothing filters the family.
func (r *AnalysisResult) FamilyState(version IPVersion) FamilyStatus {
	status, rs, excluded := r.IPv4Status, r.IPv4Rules, r.IPv6Only
	if version == IPv6 {
		status, rs, excluded = r.IPv6Status, r.IPv6Rules, r.IPv4Only
	}
	switch {
	case status != "":
		return status
	case excluded:
		return FamilyExcluded
	case rs == nil || len(rs.Tables) == 0:
		return FamilyNoRules
	}
	return FamilyAnalyzed
}

// SandboxStatus records the confinement in effect while the collected input
// was parsed, analyzed and rendered.
type SandboxStatus struct {
	Mode              string   // auto, strict or off
	LandlockABI       int      // highest Landlock ABI of the kernel, 0 without Landlock
	Landlock          bool     // a Landlock domain confines every thread
	Restricted        []string // what the domain denies, e.g. filesystem, tcp, signals
	PrivilegesDropped bool     // root privileges were dropped before parsing
	Notes             []string // why a part of the sandbox is missing
}

// ShadowFinding represents a rule shadowed by an earlier rule
type ShadowFinding struct {
	Code          FindingCode
	Certainty     Certainty
	ShadowedRule  Rule
	ShadowingRule Rule
	Reason        string
	Severity      Severity
}

// DockerBypassFinding represents a firewall decision that Docker's packet
// path makes ineffective, or a container endpoint reachable around the
// host firewall. Code distinguishes the individual finding kinds.
type DockerBypassFinding struct {
	Code      FindingCode
	Certainty Certainty
	IPVersion IPVersion
	InputRule Rule
	NATRule   Rule
	Rule      *Rule // the ineffective or fragile user rule, when one is involved
	// HostAddr is the local address of a translated port, when the
	// translation holds for one address only.
	HostAddr      string `json:",omitempty"`
	ExposedPort   string
	ContainerDest string
	Bridge        string
	GatewayMode   string // Docker bridge gateway mode inferred from the rules (nat, routed, nat-unprotected)
	Scope         AccessScope
	Interfaces    []string // ingress interfaces through which the path exists; empty means any
	Reason        string
	Fix           string
	Severity      Severity
}

// PublishedPort is a range of host ports that nat/PREROUTING translates to a
// forwarded destination, together with the verdicts of both packet paths.
type PublishedPort struct {
	IPVersion IPVersion
	Protocol  Protocol
	HostAddr  string // empty when the translation holds for every local address
	HostPort  int
	// HostPortEnd is the last port of the range; 0 or HostPort for one port.
	HostPortEnd   int `json:",omitempty"`
	ContainerAddr string
	ContainerPort int
	// ContainerPortEnd is the last destination port of the range.
	ContainerPortEnd int `json:",omitempty"`
	Bridge           string
	NATRule          Rule
	ForwardScope     AccessScope // "" when no source reaches the container
	InputScope       AccessScope // what filter/INPUT would decide for the same packet
	Certainty        Certainty
	Interfaces       []string
}

// OpenPort is a range of destination ports for which the firewall accepts
// new connections to the host itself, whether or not a service listens.
// Ports that nat/PREROUTING translates are listed as published ports instead.
type OpenPort struct {
	IPVersion   IPVersion
	Protocol    Protocol
	First       int
	Last        int
	Scope       AccessScope
	Certainty   Certainty
	Condition   string   `json:",omitempty"` // e.g. "rate limit"
	Restriction string   `json:",omitempty"` // for RESTRICTED: e.g. "ipset trusted"
	Interfaces  []string `json:",omitempty"` // empty means every interface
	Rule        *Rule    `json:",omitempty"` // nil when a chain policy accepts
	// Unnamed is true for ports that no rule names: they show what the
	// firewall does by default.
	Unnamed bool `json:",omitempty"`
	// Address is the local address for which the entry holds, when a rule of
	// nat/PREROUTING names one; empty for every other local address.
	Address string `json:",omitempty"`
	// NATRule is the rule of nat/PREROUTING that sends the connections to
	// another local port or address (REDIRECT, or DNAT to an address of this
	// host) before INPUT sees them. nil when the port is not translated.
	NATRule *Rule `json:",omitempty"`
	// LocalPort and LocalPortEnd are the ports that receive the connections to
	// First and Last after NATRule. LocalAddr is the new local address; it is
	// empty for REDIRECT, which uses the address of the ingress interface.
	// INPUT judges the packet by the new port and address.
	LocalPort    int    `json:",omitempty"`
	LocalPortEnd int    `json:",omitempty"`
	LocalAddr    string `json:",omitempty"`
}

// Redirected reports whether nat/PREROUTING sends the ports to other local
// ports or to another local address.
func (p *OpenPort) Redirected() bool {
	return p.NATRule != nil && (p.LocalPort != p.First || p.LocalPortEnd != p.Last || p.LocalAddr != "")
}

// HostInterface describes one network interface of the analyzed host.
type HostInterface struct {
	Name  string
	Addrs []string
	Up    bool
}

// HostContext carries facts about the analyzed host that are not contained in
// the rulesets. Live analysis and a snapshot supply them; nil means that
// none is known, and every part can be missing by itself.
type HostContext struct {
	// Interfaces is empty when the interfaces of the host are not known.
	Interfaces []HostInterface
	Hostname   string `json:",omitempty"`
	// Sysctls holds kernel settings by name, such as "net.ipv4.ip_forward",
	// as far as they were read.
	Sysctls map[string]string `json:",omitempty"`
	// NativeTables lists the nftables tables that iptables-save does not
	// print. NativeKnown is false when the list was not read.
	NativeTables []NativeTable `json:",omitempty"`
	NativeKnown  bool          `json:",omitempty"`
	// IPSets holds the contents of the sets that "ipset save" printed, by
	// name. nil when they were not read.
	IPSets map[string]IPSet `json:",omitempty"`
	// Routes is the main IPv4 routing table. RoutesKnown is false when it
	// was not read.
	Routes      []Route `json:",omitempty"`
	RoutesKnown bool    `json:",omitempty"`
}

// Route is one entry of the routing table.
type Route struct {
	// Destination is a network such as "192.168.1.0/24"; the default route
	// is "0.0.0.0/0".
	Destination string
	// Devices are the interfaces through which the route leaves. A route
	// that rejects packets (blackhole, unreachable) has none.
	Devices []string `json:",omitempty"`
	Metric  int      `json:",omitempty"`
}

// Sysctl returns a kernel setting, and whether it was read.
func (h *HostContext) Sysctl(name string) (string, bool) {
	if h == nil {
		return "", false
	}
	value, ok := h.Sysctls[name]
	return value, ok
}

// Forwarding reports whether the host routes packets of an address family
// for other hosts. known is false when the setting was not read.
func (h *HostContext) Forwarding(version IPVersion) (on, known bool) {
	name := "net.ipv4.ip_forward"
	if version == IPv6 {
		name = "net.ipv6.conf.all.forwarding"
	}
	value, ok := h.Sysctl(name)
	return ok && value != "0", ok
}

// NativeTable is a table of nftables that is not one of the tables that
// iptables manages. Its rules filter packets too.
type NativeTable struct {
	Family string // ip, ip6, inet or netdev
	Name   string
	// Hooks names the hooks of its base chains: ingress, prerouting, input,
	// forward, output, postrouting.
	Hooks []string `json:",omitempty"`
}

// IPSet is the content of one set of the ipset tool.
type IPSet struct {
	Name   string
	Type   string // hash:ip, hash:net, list:set, ...
	Family string `json:",omitempty"` // inet or inet6
	// Entries are addresses, networks ("10.0.0.0/8") and ranges
	// ("10.0.0.1-10.0.0.9"); Excluded are the entries marked "nomatch".
	Entries  []string `json:",omitempty"`
	Excluded []string `json:",omitempty"`
	// Members are the sets of a set of sets (list:set).
	Members []string `json:",omitempty"`
	// Addresses is false for a set whose entries are not plain addresses or
	// networks (ports, interfaces, MAC addresses): a source address alone
	// does not tell whether it matches.
	Addresses bool
}

// Baseline is a recommended default firewall for both address families.
type Baseline struct {
	IPv4  string
	IPv6  string
	Notes []string
}

// AccessScope describes how restricted access to a service is
type AccessScope string

const (
	ScopeExposed     AccessScope = "EXPOSED"     // reachable from any source
	ScopeSubnet      AccessScope = "SUBNET"      // reachable only from specific public networks (at most a /16 or an IPv6 /48 in total)
	ScopeRestricted  AccessScope = "RESTRICTED"  // reachable only from sources that a match selects which the analysis cannot evaluate (ipset, MAC address)
	ScopeLocalnet    AccessScope = "LOCALNET"    // reachable only from private IP ranges
	ScopeWhitelisted AccessScope = "WHITELISTED" // reachable only from specific /32 hosts
)

// ExposedServiceFinding represents a service accessible through the firewall
type ExposedServiceFinding struct {
	Code         FindingCode
	Certainty    Certainty
	IPVersion    IPVersion
	Service      ListeningService
	AllowingRule *Rule
	Severity     Severity
	Scope        AccessScope
	Interfaces   []string // ingress interfaces with this exposure; empty means any
	// Condition names what a packet must meet to be accepted from the scope,
	// for example "rate limit" or "source port 67". Empty when unconditional.
	Condition string `json:",omitempty"`
	// Restriction names what selects the sources of a RESTRICTED scope,
	// for example "ipset trusted".
	Restriction string `json:",omitempty"`
	Reason      string
	// ViaPort is the port that other hosts connect to when nat/PREROUTING
	// sends it to the port of the service (NATRule); 0 when they connect to
	// the port of the service itself. ViaPortEnd is the last port of a range.
	ViaPort    int   `json:",omitempty"`
	ViaPortEnd int   `json:",omitempty"`
	NATRule    *Rule `json:",omitempty"`
}

// UnusedRuleFinding represents a firewall rule with no matching service
type UnusedRuleFinding struct {
	Code      FindingCode
	Certainty Certainty
	IPVersion IPVersion
	Protocol  Protocol
	First     int // the open ports without a listener
	Last      int
	Scope     AccessScope
	Rule      Rule
	Reason    string
	// NATRule sends the ports to LocalPort before INPUT; nil when they are
	// not translated. Nothing listens on LocalPort then.
	NATRule   *Rule `json:",omitempty"`
	LocalPort int   `json:",omitempty"`
}

// EffectivenessFinding represents a general effectiveness issue
type EffectivenessFinding struct {
	Code      FindingCode
	Certainty Certainty
	Title     string
	Detail    string
	Severity  Severity
	Chain     string
	Table     string
	IPVersion IPVersion
	Rule      *Rule `json:",omitempty"` // the rule that causes the finding, when one does
	// Unrestricted marks a default accept that holds for every interface,
	// both transport protocols and every packet: the chain filters nothing.
	Unrestricted bool `json:",omitempty"`
}

// Packet is one packet, as the option --trace describes it.
type Packet struct {
	Protocol Protocol `json:"protocol"`
	Source   string   `json:"source"`
	// SourcePort is 0 when the port was not given. The trace then uses a port
	// from the range that clients send from.
	SourcePort int `json:"source_port,omitempty"`
	// Destination is empty for a packet to an address of this host.
	Destination string `json:"destination,omitempty"`
	Port        int    `json:"port,omitempty"`
	In          string `json:"in,omitempty"`
	Out         string `json:"out,omitempty"`
	// State is the connection state: NEW when not given.
	State    string `json:"state"`
	ICMPType string `json:"icmp_type,omitempty"`
}

// TraceStep is one rule that a traced packet matched, or may have matched.
type TraceStep struct {
	Table string `json:"table"`
	Chain string `json:"chain"`
	Num   int    `json:"num"`
	Spec  string `json:"spec"`
	// Depth is 0 for a rule in the built-in chain and one more for each jump.
	Depth int `json:"depth"`
	// Match is "yes", or "maybe" when the rule has a match that the packet
	// alone does not decide. The trace goes on as if such a rule did not
	// match, and lists under the alternatives what happens when it does.
	Match string `json:"match"`
	// Action says what the rule does with the packet: ACCEPT, DROP, REJECT,
	// RETURN, "jump", "goto", the target of a translation (DNAT, REDIRECT,
	// NETMAP), QUEUE or NFQUEUE, "continue" for a rule that does not decide,
	// or "skipped" for a rule that may match.
	Action string `json:"action"`
	// Note says what a "maybe" depends on, or what was assumed.
	Note string `json:"note,omitempty"`
}

// TraceStage is one hook that a traced packet passes.
type TraceStage struct {
	Table string      `json:"table"`
	Chain string      `json:"chain"`
	Steps []TraceStep `json:"steps"`
	// Result says how the packet leaves the hook.
	Result string `json:"result"`
}

// Trace is the way of one packet through the rules.
type Trace struct {
	Packet Packet       `json:"packet"`
	Family int          `json:"family"`
	Stages []TraceStage `json:"stages"`
	// Verdict is ACCEPT, DROP, REJECT, or UNDECIDED when the rules hand the
	// packet to a program or cannot be followed.
	Verdict string `json:"verdict"`
	// Certain is false when a rule that may match leads to another verdict.
	Certain bool `json:"certain"`
	// DecidedBy names the rule or the policy that gave the verdict.
	DecidedBy string `json:"decided_by"`
	// Delivery is "local" for a packet that this host receives and "forward"
	// for one that it routes to another host. Destination and Port are those
	// behind the address translation.
	Delivery    string `json:"delivery,omitempty"`
	Destination string `json:"destination,omitempty"`
	Port        int    `json:"port,omitempty"`
	// Assumptions lists what the trace took for granted.
	Assumptions []string `json:"assumptions,omitempty"`
	// Alternatives lists how the packet ends when rules that may match do
	// match. The stages above follow the packet as if they did not.
	Alternatives []TraceEnd `json:"alternatives,omitempty"`
}

// TraceEnd is how a traced packet ends on another way through the rules.
type TraceEnd struct {
	// If names the rules that match on this way, with what each depends on.
	If          string `json:"if"`
	Verdict     string `json:"verdict"`
	DecidedBy   string `json:"decided_by"`
	Delivery    string `json:"delivery,omitempty"`
	Destination string `json:"destination,omitempty"`
	Port        int    `json:"port,omitempty"`
}
