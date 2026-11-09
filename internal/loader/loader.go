package loader

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

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

// Source is the unparsed iptables-save text of one address family.
// A nil *Source means the family was excluded; an empty Data with
// Empty set means that no rules were supplied for it.
type Source struct {
	Version models.IPVersion
	Data    string
	Empty   bool
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
		out, err := safeio.Run(ctx, command, nil, safeio.MaxRulesSize)
		if err != nil {
			return nil, err
		}
		return &Source{Version: ver, Data: string(out)}, nil
	}
	return &Source{Version: ver, Empty: true}, nil
}

func parseOne(src *Source) (*models.Ruleset, error) {
	if src == nil {
		return nil, nil
	}
	if src.Empty {
		return &models.Ruleset{IPVersion: src.Version, Tables: make(map[string]*models.Table)}, nil
	}
	return parser.Parse(src.Data, src.Version)
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
	for _, iface := range interfaces {
		// Interface names may contain any byte but '/', ':' and whitespace;
		// escape them like names read from rules files.
		entry := models.HostInterface{Name: textsafe.Escape(iface.Name), Up: iface.Flags&net.FlagUp != 0}
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
