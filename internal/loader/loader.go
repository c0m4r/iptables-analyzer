package loader

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/hostinfo"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
	"github.com/c0m4r/iptables-analyzer/internal/safeio"
	"github.com/c0m4r/iptables-analyzer/internal/textsafe"
)

// Config configures how rules are loaded
type Config struct {
	IPv4File string
	IPv6File string
	Live     bool
	IPv4Only bool
	IPv6Only bool
}

// Source is the unparsed iptables-save text of one address family. A nil
// *Source means that there is no input for the family: it was excluded, or
// file analysis got no file for it.
type Source struct {
	Version models.IPVersion
	Data    string
	// Warnings are messages of the live tool about rules it does not print.
	Warnings []string
}

// Sources holds the collected, still unparsed input of both families.
type Sources struct {
	IPv4 *Source
	IPv6 *Source
}

// Load reads and parses the rulesets selected by cfg.
func Load(cfg Config) (*models.Ruleset, *models.Ruleset, error) {
	sources, err := Read(cfg)
	if err != nil {
		return nil, nil, err
	}
	return Parse(sources)
}

// Read collects the rules text selected by cfg from files or, in live mode,
// from iptables-save/ip6tables-save, without parsing it.
func Read(cfg Config) (Sources, error) {
	var sources Sources
	var err error
	if !cfg.IPv6Only {
		sources.IPv4, err = readOne(cfg.IPv4File, cfg.Live, "iptables-save", models.IPv4)
		if err != nil {
			return Sources{}, fmt.Errorf("loading IPv4 rules: %w", err)
		}
	}
	if !cfg.IPv4Only {
		sources.IPv6, err = readOne(cfg.IPv6File, cfg.Live, "ip6tables-save", models.IPv6)
		if err != nil {
			return Sources{}, fmt.Errorf("loading IPv6 rules: %w (use --ipv4-only to skip IPv6)", err)
		}
	}
	return sources, nil
}

// Parse parses collected rules text. It is safe to call in the sandbox.
func Parse(sources Sources) (*models.Ruleset, *models.Ruleset, error) {
	ipv4, err := parseOne(sources.IPv4)
	if err != nil {
		return nil, nil, fmt.Errorf("loading IPv4 rules: %w", err)
	}
	ipv6, err := parseOne(sources.IPv6)
	if err != nil {
		return nil, nil, fmt.Errorf("loading IPv6 rules: %w (use --ipv4-only to skip IPv6)", err)
	}
	return ipv4, ipv6, nil
}

func readOne(filePath string, live bool, command string, ver models.IPVersion) (*Source, error) {
	switch {
	case filePath != "":
		raw, err := safeio.ReadFile(filePath, safeio.MaxRulesSize)
		if err != nil {
			return nil, fmt.Errorf("reading file %s: %w", filePath, err)
		}
		return &Source{Version: ver, Data: string(raw)}, nil
	case live:
		if os.Geteuid() != 0 {
			return nil, fmt.Errorf("%s requires root privileges; use sudo or provide files with --file/--file6", command)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, stderr, err := safeio.RunOutput(ctx, command, nil, safeio.MaxRulesSize)
		if err != nil {
			return nil, err
		}
		src := &Source{Version: ver, Data: string(out)}
		for _, line := range strings.Split(stderr, "\n") {
			// "# Warning: iptables-legacy tables present, use iptables-legacy-save to see them"
			if strings.Contains(line, "tables-legacy tables present") {
				src.Warnings = append(src.Warnings, strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(line), "#"), " Warning:")))
			}
		}
		return src, nil
	}
	return nil, nil
}

// parseOne parses one family. Output without any table is what iptables-save
// prints when no rules are loaded: it is a ruleset in which every chain
// accepts, not an error.
func parseOne(src *Source) (*models.Ruleset, error) {
	if src == nil {
		return nil, nil
	}
	rs, ok := parser.ParseNoTables(src.Data, src.Version)
	if !ok {
		var err error
		if rs, err = parser.Parse(src.Data, src.Version); err != nil {
			return rs, err
		}
	}
	rs.Warnings = append(rs.Warnings, src.Warnings...)
	return rs, nil
}

// IsRoot returns true if the process is running as root
func IsRoot() bool {
	return os.Geteuid() == 0
}

// Host returns the interfaces and addresses of the running system. They let
// live analysis evaluate interface and local-address predicates exactly.
func Host() (*models.HostContext, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing network interfaces: %w", err)
	}
	host := &models.HostContext{}
	if name, err := os.Hostname(); err == nil {
		host.Hostname = textsafe.Name(name)
	}
	for _, iface := range interfaces {
		// Interface names may contain any byte but '/', ':' and whitespace;
		// escape them like names read from rules files.
		entry := models.HostInterface{Name: textsafe.Name(iface.Name), Up: iface.Flags&net.FlagUp != 0}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("listing addresses of %s: %w", entry.Name, err)
		}
		for _, addr := range addrs {
			entry.Addrs = append(entry.Addrs, addr.String())
		}
		host.Interfaces = append(host.Interfaces, entry)
	}
	return host, nil
}

// Facts is what live analysis reads about the host besides its rules and
// its interfaces. The output of the tools is kept as text: it is parsed
// later, in the sandbox.
type Facts struct {
	// Sysctls holds the kernel settings that were read, by name.
	Sysctls map[string]string
	// NFTChains is the output of "nft list chains", and IPSets that of
	// "ipset save". The Have fields are false when the tool is not installed
	// or failed.
	NFTChains  string
	HaveNFT    bool
	IPSets     string
	HaveIPSets bool
	// Routes is the output of "ip -4 route show table main".
	Routes     string
	HaveRoutes bool
	// Notes say why a part could not be read.
	Notes []string
}

// factSizeLimit bounds the kernel settings, which are single numbers.
const factSizeLimit = 64

// CollectFacts reads the kernel settings that the analysis uses, the list of
// nftables chains and the contents of the ipsets. A tool that is not
// installed is no error: the analysis then states less.
func CollectFacts(host *models.HostContext) Facts {
	facts := Facts{Sysctls: map[string]string{}}
	var interfaces []string
	if host != nil {
		for _, iface := range host.Interfaces {
			interfaces = append(interfaces, iface.Name)
		}
	}
	for name, path := range hostinfo.SysctlPaths(interfaces) {
		raw, err := safeio.ReadFile(path, factSizeLimit)
		if err != nil {
			continue // IPv6 can be off, and an interface can have gone
		}
		if value, ok := hostinfo.CleanSysctl(string(raw)); ok {
			facts.Sysctls[name] = value
		}
	}
	facts.NFTChains, facts.HaveNFT = runFact(&facts,
		"The nftables tables could not be listed (%s), so this report cannot say whether rules exist outside the tables of iptables.",
		"nft", "list", "chains")
	facts.IPSets, facts.HaveIPSets = runFact(&facts,
		"The contents of the ipsets could not be read (%s); matches against them are judged without them.",
		"ipset", "save")
	facts.Routes, facts.HaveRoutes = runFact(&facts,
		"The routing table could not be read (%s); the reverse-path filter is left out of the analysis.",
		"ip", "-4", "route", "show", "table", "main")
	return facts
}

// runFact runs a tool that tells more about the host, when it is installed.
// note says what a failure means for the report; %s stands for the error.
func runFact(facts *Facts, note, name string, args ...string) (string, bool) {
	if _, err := safeio.LookTrusted(name); err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := safeio.Run(ctx, name, args, safeio.MaxRulesSize)
	if err != nil {
		// The first line of what the tool said is enough.
		reason, _, _ := strings.Cut(textsafe.Escape(err.Error()), "^J")
		facts.Notes = append(facts.Notes, fmt.Sprintf(note, strings.TrimSpace(reason)))
		return "", false
	}
	return string(out), true
}
