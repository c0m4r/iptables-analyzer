package loader

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
)

// Config configures how rules are loaded
type Config struct {
	IPv4File string
	IPv6File string
	Live     bool
	IPv4Only bool
	IPv6Only bool
}

// Load loads iptables rulesets based on config
func Load(cfg Config) (*models.Ruleset, *models.Ruleset, error) {
	var ipv4, ipv6 *models.Ruleset
	var err error

	if !cfg.IPv6Only {
		ipv4, err = loadOne(cfg.IPv4File, cfg.Live, "iptables-save", models.IPv4)
		if err != nil {
			return nil, nil, fmt.Errorf("loading IPv4 rules: %w", err)
		}
	}

	if !cfg.IPv4Only {
		ipv6, err = loadOne(cfg.IPv6File, cfg.Live, "ip6tables-save", models.IPv6)
		if err != nil {
			return nil, nil, fmt.Errorf("loading IPv6 rules: %w (use --ipv4-only to skip IPv6)", err)
		}
	}

	return ipv4, ipv6, nil
}

func loadOne(filePath string, live bool, command string, ver models.IPVersion) (*models.Ruleset, error) {
	var data string

	if filePath != "" {
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading file %s: %w", filePath, err)
		}
		data = string(raw)
	} else if live {
		if os.Geteuid() != 0 {
			return nil, fmt.Errorf("%s requires root privileges; use sudo or provide files with --file/--file6", command)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, command).Output()
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("running %s timed out: %w", command, ctx.Err())
			}
			return nil, fmt.Errorf("running %s: %w", command, err)
		}
		data = string(out)
	} else {
		return &models.Ruleset{IPVersion: ver, Tables: make(map[string]*models.Table)}, nil
	}

	return parser.Parse(data, ver)
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
		entry := models.HostInterface{Name: iface.Name, Up: iface.Flags&net.FlagUp != 0}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("listing addresses of %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			entry.Addrs = append(entry.Addrs, addr.String())
		}
		host.Interfaces = append(host.Interfaces, entry)
	}
	return host, nil
}
