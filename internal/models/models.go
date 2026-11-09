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
	FindingPolicyAccept     FindingCode = "policy_accept"
	FindingDeadRule         FindingCode = "dead_rule"
	FindingMissingConntrack FindingCode = "missing_conntrack"
	FindingLateConntrack    FindingCode = "late_conntrack"
	FindingMissingFinalDrop FindingCode = "missing_final_drop"
	FindingShadowedRule     FindingCode = "shadowed_rule"
	FindingDockerBypass     FindingCode = "docker_bypass"
	FindingExposedService   FindingCode = "exposed_service"
	FindingUnusedRule       FindingCode = "unused_rule"
	FindingMissingLoopback  FindingCode = "missing_loopback"
	FindingIPv6NDPBlocked   FindingCode = "ipv6_ndp_blocked"

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
}

// ListeningService from ss output
type ListeningService struct {
	Protocol   Protocol
	Address    string
	Port       int
	Process    string
	PID        int
	IsIPv6     bool
	IsWildcard bool // bound to 0.0.0.0 or ::
	Family     SocketFamily
	Status     ServiceStatus
}

// AnalysisResult aggregates all findings
type AnalysisResult struct {
	IPv4Rules         *Ruleset
	IPv6Rules         *Ruleset
	IPv4Only          bool // set when -4 flag is used; IPv6 stack was not analyzed
	IPv6Only          bool // set when -6 flag is used; IPv4 stack was not analyzed
	ServiceAssessment AssessmentStatus
	Diagnostics       []AssessmentDiagnostic
	Services          []ListeningService
	Host              *HostContext
	ShadowedRules     []ShadowFinding
	DockerBypasses    []DockerBypassFinding
	PublishedPorts    []PublishedPort
	ExposedServices   []ExposedServiceFinding
	UnusedRules       []UnusedRuleFinding
	EffectiveIssues   []EffectivenessFinding
	Recommendations   []Recommendation
	Baseline          Baseline
	Score             ScoreResult
	Sandbox           *SandboxStatus `json:",omitempty"`
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
	Code          FindingCode
	Certainty     Certainty
	IPVersion     IPVersion
	InputRule     Rule
	NATRule       Rule
	Rule          *Rule // the ineffective or fragile user rule, when one is involved
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

// PublishedPort is one host port translated by nat/PREROUTING to a forwarded
// destination, together with the verdicts of both packet paths.
type PublishedPort struct {
	IPVersion     IPVersion
	Protocol      Protocol
	HostAddr      string // empty when the DNAT rule matches every local address
	HostPort      int
	ContainerAddr string
	ContainerPort int
	Bridge        string
	NATRule       Rule
	ForwardScope  AccessScope // "" when no source reaches the container
	InputScope    AccessScope // what filter/INPUT would decide for the same packet
	Certainty     Certainty
	Interfaces    []string
}

// HostInterface describes one network interface of the analyzed host.
type HostInterface struct {
	Name  string
	Addrs []string
	Up    bool
}

// HostContext carries facts about the analyzed host that are not contained in
// the rulesets. It is only populated in live mode; nil means unknown.
type HostContext struct {
	Interfaces []HostInterface
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
	Reason       string
}

// UnusedRuleFinding represents a firewall rule with no matching service
type UnusedRuleFinding struct {
	Code      FindingCode
	Certainty Certainty
	Rule      Rule
	Reason    string
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
}

// Recommendation is a security improvement suggestion
type Recommendation struct {
	Title    string
	Detail   string
	Severity Severity
	Category string // "policy", "docker", "exposure", "hygiene", "ipv6"
}

// ScoreResult is the security score
type ScoreResult struct {
	Total      int
	Breakdown  map[string]int
	Grade      string
	Complete   bool
	Unassessed []string
}
