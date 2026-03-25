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
	RawLine    string
	IPVersion  IPVersion
}

// MatchExt represents a match extension module
type MatchExt struct {
	Module string
	Params map[string]string
}

// IsTerminal returns true if this rule's target terminates packet processing
func (r *Rule) IsTerminal() bool {
	switch r.Target {
	case "ACCEPT", "DROP", "REJECT", "DNAT", "SNAT", "MASQUERADE", "REDIRECT":
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
}

// AnalysisResult aggregates all findings
type AnalysisResult struct {
	IPv4Rules       *Ruleset
	IPv6Rules       *Ruleset
	IPv4Only        bool // set when -4 flag is used; IPv6 stack was not analyzed
	IPv6Only        bool // set when -6 flag is used; IPv4 stack was not analyzed
	Services        []ListeningService
	ShadowedRules   []ShadowFinding
	DockerBypasses  []DockerBypassFinding
	ExposedServices []ExposedServiceFinding
	UnusedRules     []UnusedRuleFinding
	EffectiveIssues []EffectivenessFinding
	Recommendations []Recommendation
	Score           ScoreResult
}

// ShadowFinding represents a rule shadowed by an earlier rule
type ShadowFinding struct {
	ShadowedRule  Rule
	ShadowingRule Rule
	Reason        string
	Severity      Severity
}

// DockerBypassFinding represents an INPUT rule bypassed by Docker NAT
type DockerBypassFinding struct {
	InputRule     Rule
	NATRule       Rule
	ExposedPort   string
	ContainerDest string
	Reason        string
	Severity      Severity
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
	Service      ListeningService
	AllowingRule *Rule
	Severity     Severity
	Scope        AccessScope
	Reason       string
}

// UnusedRuleFinding represents a firewall rule with no matching service
type UnusedRuleFinding struct {
	Rule   Rule
	Reason string
}

// EffectivenessFinding represents a general effectiveness issue
type EffectivenessFinding struct {
	Title    string
	Detail   string
	Severity Severity
	Chain    string
	Table    string
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
	Total     int
	Breakdown map[string]int
	Grade     string
}
