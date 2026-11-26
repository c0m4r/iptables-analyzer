// Package report turns the facts of an analysis into the report that every
// output format shows: one list of findings, each with its evidence, its fix
// and the points it costs, next to the tables of ports and services.
//
// The analyzer states what the ruleset does. This package decides how that is
// told: which facts are one finding, how severe it is for the reader, what to
// do about it and what it does to the score.
package report

import "github.com/c0m4r/iptables-analyzer/internal/models"

// SchemaVersion is the version of the JSON form of Report. It changes when a
// field is removed or changes its meaning.
const SchemaVersion = 2

// Report is the result of one run, ready to render.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Tool          Tool      `json:"tool"`
	Generated     string    `json:"generated"` // RFC 3339
	Mode          string    `json:"mode"`      // live or file
	Host          string    `json:"host,omitempty"`
	Inputs        []string  `json:"inputs,omitempty"`
	Families      []Family  `json:"families"`
	Score         Score     `json:"score"`
	Counts        Counts    `json:"counts"`
	Findings      []Finding `json:"findings"`
	// OpenPorts are the ports for which INPUT accepts new connections.
	OpenPorts []OpenPort `json:"open_ports"`
	// Forwards are the ports that nat/PREROUTING translates to another host:
	// Docker published ports and port forwards.
	Forwards []Forward `json:"forwarded_ports"`
	// ServicesKnown is false when no list of listening sockets was read.
	ServicesKnown bool      `json:"services_known"`
	Services      []Service `json:"services"`
	Notes         []Note    `json:"notes"`
	Sandbox       *Sandbox  `json:"sandbox,omitempty"`
	Baseline      *Baseline `json:"baseline,omitempty"`
	Rulesets      []Ruleset `json:"rulesets,omitempty"`
}

// Tool names the program that wrote the report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

// Family describes one address family of the input.
type Family struct {
	Version  int               `json:"version"` // 4 or 6
	Status   string            `json:"status"`  // ANALYZED, NO_RULES, EXCLUDED, NOT_SUPPLIED or UNREADABLE
	Tables   int               `json:"tables"`
	Chains   int               `json:"chains"`
	Rules    int               `json:"rules"`
	Policies map[string]string `json:"policies,omitempty"` // policy of the built-in filter chains
	// Managers names the programs whose chains the rules contain.
	Managers []string `json:"managers,omitempty"`
}

// Score is the security score: 100 points less the deductions of the
// findings, limited for each category.
type Score struct {
	Total    int    `json:"total"`
	Grade    string `json:"grade"` // A to F, or INCOMPLETE
	Complete bool   `json:"complete"`
	// Cap explains a grade below the one that the points give.
	Cap        string     `json:"cap,omitempty"`
	Unassessed []string   `json:"unassessed,omitempty"`
	Categories []Category `json:"categories"`
}

// Category is one part of the score.
type Category struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Max   int    `json:"max"`
	Lost  int    `json:"lost"`
}

// Counts is the number of findings of each severity.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Finding is one thing to know or to fix.
type Finding struct {
	ID        string           `json:"id"`   // F1, F2, ... in the order of the report
	Code      string           `json:"code"` // stable identifier of the kind of finding
	Severity  models.Severity  `json:"severity"`
	Certainty models.Certainty `json:"certainty"`
	Category  string           `json:"category"`           // part of the score: policy, exposure, paths, hygiene or ipv6
	Families  []int            `json:"families,omitempty"` // 4, 6 or both
	Title     string           `json:"title"`
	Detail    string           `json:"detail"`
	Ports     []string         `json:"ports,omitempty"` // "22/tcp", "8000-8100/tcp"
	Rules     []RuleRef        `json:"rules,omitempty"`
	Fix       *Fix             `json:"fix,omitempty"`
	// Points is the deduction of this finding. A category does not lose more
	// than its maximum, and a port costs once for both address families.
	Points int `json:"points"`
	// Gain is the number of points that the score rises when this finding
	// alone is fixed. It is less than Points when the category already lost
	// more than its maximum, or when another finding costs for the same thing.
	Gain int `json:"gain"`
	// GradeAfter is the grade after that fix, when it is better than the
	// grade of the report.
	GradeAfter string `json:"grade_after,omitempty"`

	// key joins findings that cost points only once (the same port, the same
	// chain); empty for findings that stand alone.
	key string
	// order keeps the sequence in which the findings were made.
	order int
	// ceiling is the best grade that the report can have while the finding
	// stands; empty when the finding does not limit the grade.
	ceiling       string
	ceilingReason string
}

// limit lowers the best grade that the report can have while the finding
// stands.
func (f *Finding) limit(grade, reason string) {
	if f.ceiling == "" || gradeRank(grade) > gradeRank(f.ceiling) {
		f.ceiling, f.ceilingReason = grade, reason
	}
}

// RuleRef points to a rule of the input.
type RuleRef struct {
	Family int    `json:"family"`
	Table  string `json:"table"`
	Chain  string `json:"chain"`
	Num    int    `json:"num"`
	Spec   string `json:"spec"` // the rule without "-A CHAIN"
	// Role says what the rule does in the finding: accepts, causes, shadows,
	// shadowed, translates, bypassed or ineffective.
	Role string `json:"role,omitempty"`
	// Path lists the jumps from the built-in chain to the rule, as "CHAIN #N",
	// when the rule is in a user-defined chain.
	Path []string `json:"path,omitempty"`
}

// Fix says what to do about a finding: the reasoning, then the commands,
// each with what it does.
type Fix struct {
	Summary string    `json:"summary"`
	Steps   []FixStep `json:"steps,omitempty"`
}

// FixStep is one command of a fix. The command is ready for a root shell:
// every value from the analyzed rules is quoted. Text in angle brackets is a
// placeholder that the reader replaces.
type FixStep struct {
	Text    string `json:"text"`
	Command string `json:"command"`
}

// OpenPort is a range of ports for which INPUT accepts new connections.
type OpenPort struct {
	Families    []int              `json:"families"`
	Protocol    string             `json:"protocol"`
	First       int                `json:"first"`
	Last        int                `json:"last"`
	Scope       models.AccessScope `json:"scope"`
	Certainty   models.Certainty   `json:"certainty"`
	Condition   string             `json:"condition,omitempty"`
	Restriction string             `json:"restriction,omitempty"`
	Interfaces  []string           `json:"interfaces,omitempty"`
	Rules       []RuleRef          `json:"rules,omitempty"` // empty when a chain policy accepts
	// Default marks the ports that no rule names.
	Default bool `json:"default,omitempty"`
	// Listeners names the processes that listen in the range, when known.
	Listeners []string `json:"listeners,omitempty"`
	// Public marks ports that were declared public on purpose.
	Public bool `json:"public,omitempty"`
}

// Forward is a host port that nat/PREROUTING translates to another address.
type Forward struct {
	Family       int                `json:"family"`
	Protocol     string             `json:"protocol"`
	HostAddr     string             `json:"host_addr,omitempty"` // empty: every local address
	HostPort     int                `json:"host_port"`
	HostPortEnd  int                `json:"host_port_end"`
	DestAddr     string             `json:"dest_addr"`
	DestPort     int                `json:"dest_port"`
	DestPortEnd  int                `json:"dest_port_end"`
	Bridge       string             `json:"bridge,omitempty"`
	Docker       bool               `json:"docker"`
	ForwardScope models.AccessScope `json:"forward_scope,omitempty"` // empty: no source reaches the destination
	InputScope   models.AccessScope `json:"input_scope,omitempty"`   // what INPUT would do with the same packet
	Certainty    models.Certainty   `json:"certainty"`
	Interfaces   []string           `json:"interfaces,omitempty"`
	Rule         RuleRef            `json:"rule"`
}

// Service is one listening socket.
type Service struct {
	Protocol  string               `json:"protocol"`
	Address   string               `json:"address"`
	Device    string               `json:"device,omitempty"`
	Port      int                  `json:"port"`
	Process   string               `json:"process,omitempty"`
	PID       int                  `json:"pid,omitempty"`
	Processes []string             `json:"processes,omitempty"`
	Socket    models.SocketFamily  `json:"socket_family"` // ipv4, ipv6 or dual
	Status    models.ServiceStatus `json:"status"`
	// Scope is the widest scope of sources that reach the socket, when it
	// is reachable from other hosts.
	Scope models.AccessScope `json:"scope,omitempty"`
}

// Note says something about the analysis itself.
type Note struct {
	// Kind is "incomplete" for a part that could not be assessed, which makes
	// the grade INCOMPLETE, and "scope" for what was and was not examined.
	Kind string `json:"kind"`
	Area string `json:"area,omitempty"`
	Text string `json:"text"`
}

// Sandbox is the confinement of the process that analyzed the input.
type Sandbox struct {
	Mode              string   `json:"mode"`
	Landlock          bool     `json:"landlock"`
	LandlockABI       int      `json:"landlock_abi,omitempty"`
	Restricted        []string `json:"restricted,omitempty"`
	PrivilegesDropped bool     `json:"privileges_dropped"`
	Notes             []string `json:"notes,omitempty"`
}

// Baseline is the recommended default firewall.
type Baseline struct {
	IPv4  string   `json:"ipv4"`
	IPv6  string   `json:"ipv6"`
	Notes []string `json:"notes,omitempty"`
}

// Ruleset is the input of one address family, for display.
type Ruleset struct {
	Family int     `json:"family"`
	Tables []Table `json:"tables"`
}

// Table is one table of a ruleset.
type Table struct {
	Name   string  `json:"name"`
	Chains []Chain `json:"chains"`
}

// Chain is one chain with its rules.
type Chain struct {
	Name   string `json:"name"`
	Policy string `json:"policy,omitempty"` // empty for user-defined chains
	Owner  string `json:"owner,omitempty"`  // the program that manages the chain, when its name tells
	Rules  []Rule `json:"rules"`
}

// Rule is one rule as iptables-save prints it.
type Rule struct {
	Num    int    `json:"num"`
	Spec   string `json:"spec"`
	Target string `json:"target,omitempty"`
	// Jump is true when the target is a chain of the same table.
	Jump bool `json:"jump,omitempty"`
	// Findings lists the IDs of the findings that name the rule.
	Findings []string `json:"findings,omitempty"`
}
