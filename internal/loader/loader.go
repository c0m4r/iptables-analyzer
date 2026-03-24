package loader

import (
	"fmt"
	"os"
	"os/exec"

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
			// IPv6 failure is non-fatal if we have IPv4
			if ipv4 != nil {
				ipv6 = &models.Ruleset{IPVersion: models.IPv6, Tables: make(map[string]*models.Table)}
			} else {
				return nil, nil, fmt.Errorf("loading IPv6 rules: %w", err)
			}
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
			return nil, fmt.Errorf("%s requires root privileges; use sudo or provide a file with --ipv4-file/--ipv6-file", command)
		}
		out, err := exec.Command(command).Output()
		if err != nil {
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
