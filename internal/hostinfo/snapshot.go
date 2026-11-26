package hostinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/textsafe"
)

// SnapshotFormat names the file format, and SnapshotVersion its version. The
// version changes when a field is removed or changes its meaning.
const (
	SnapshotFormat  = "iptables-analyzer snapshot"
	SnapshotVersion = 1
)

// Snapshot holds everything that a live analysis reads from a host, as the
// tools printed it. Analyzing the file gives the result of a live analysis
// at the time when it was taken, on any machine.
type Snapshot struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	// Created is the time when the input was read, in RFC 3339 form.
	Created string `json:"created"`
	// Tool is the version of the program that wrote the file.
	Tool string `json:"tool,omitempty"`
	// Live is true when the input came from the running system, and false
	// when the file was put together from other files.
	Live       bool                `json:"live"`
	Hostname   string              `json:"hostname,omitempty"`
	Interfaces []SnapshotInterface `json:"interfaces,omitempty"`
	Sysctls    map[string]string   `json:"sysctls,omitempty"`
	// IPv4 and IPv6 are the output of iptables-save and ip6tables-save. A
	// family that was not read is missing.
	IPv4 *SnapshotRules `json:"iptables_save,omitempty"`
	IPv6 *SnapshotRules `json:"ip6tables_save,omitempty"`
	// Sockets is the output of ss; it is missing when the listening sockets
	// were not read.
	Sockets []SnapshotOutput `json:"ss,omitempty"`
	// NFTChains is the output of "nft list chains", IPSets that of
	// "ipset save" and Routes that of "ip -4 route show table main". Each is
	// missing when it was not read.
	NFTChains *string `json:"nft_list_chains,omitempty"`
	IPSets    *string `json:"ipset_save,omitempty"`
	Routes    *string `json:"ip_route,omitempty"`
}

// SnapshotInterface is one network interface of the host.
type SnapshotInterface struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs,omitempty"`
	Up    bool     `json:"up"`
}

// SnapshotRules is the output of one of the save tools.
type SnapshotRules struct {
	Data string `json:"data"`
	// Warnings are what the tool said about rules that it does not print.
	Warnings []string `json:"warnings,omitempty"`
}

// SnapshotOutput is the output of ss for one protocol; Proto is empty when
// one output lists the sockets of every protocol.
type SnapshotOutput struct {
	Proto string `json:"proto,omitempty"`
	Data  string `json:"data"`
}

// Write encodes the snapshot. The text of the tools is kept as it is: JSON
// escapes whatever it holds.
func (s *Snapshot) Write(w io.Writer) error {
	s.Format, s.Version = SnapshotFormat, SnapshotVersion
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(s)
}

// IsSnapshot reports whether a file looks like a snapshot. It reads the
// start of the text only; ParseSnapshot decides whether the file is valid.
func IsSnapshot(data string) bool {
	head := strings.TrimLeft(data[:min(len(data), 512)], " \t\r\n\xef\xbb\xbf")
	return strings.HasPrefix(head, "{") && strings.Contains(head, SnapshotFormat)
}

// ParseSnapshot reads a snapshot. The file can come from a host that the
// reader does not control, so every name in it is treated like input from a
// rules file: control characters are escaped, addresses and settings that do
// not have their form are dropped.
func ParseSnapshot(data []byte) (*Snapshot, error) {
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("not a snapshot: %w", err)
	}
	if snapshot.Format != SnapshotFormat {
		return nil, fmt.Errorf("not a snapshot: the format is %q", textsafe.Name(snapshot.Format))
	}
	if snapshot.Version < 1 || snapshot.Version > SnapshotVersion {
		return nil, fmt.Errorf("snapshot version %d is not supported (this program reads up to version %d)", snapshot.Version, SnapshotVersion)
	}
	snapshot.Hostname = textsafe.Name(snapshot.Hostname)
	snapshot.Created = textsafe.Name(snapshot.Created)
	snapshot.Tool = textsafe.Name(snapshot.Tool)
	for i := range snapshot.Interfaces {
		iface := &snapshot.Interfaces[i]
		iface.Name = textsafe.Name(iface.Name)
		var addrs []string
		for _, value := range iface.Addrs {
			if prefix, err := netip.ParsePrefix(value); err == nil {
				addrs = append(addrs, prefix.String())
			} else if addr, err := netip.ParseAddr(value); err == nil && addr.Zone() == "" {
				addrs = append(addrs, addr.String())
			}
		}
		iface.Addrs = addrs
	}
	sysctls := map[string]string{}
	for name, raw := range snapshot.Sysctls {
		if value, ok := CleanSysctl(raw); ok && strings.HasPrefix(name, "net.") && len(name) <= 128 {
			sysctls[textsafe.Name(name)] = value
		}
	}
	snapshot.Sysctls = sysctls
	for _, rules := range []*SnapshotRules{snapshot.IPv4, snapshot.IPv6} {
		if rules == nil {
			continue
		}
		for i, warning := range rules.Warnings {
			rules.Warnings[i] = textsafe.Name(warning)
		}
	}
	for i := range snapshot.Sockets {
		switch snapshot.Sockets[i].Proto {
		case "", "tcp", "udp":
		default:
			return nil, fmt.Errorf("snapshot: unknown protocol %q of a list of sockets", textsafe.Name(snapshot.Sockets[i].Proto))
		}
	}
	return &snapshot, nil
}

// Host returns the facts about the host that the snapshot holds itself. The
// caller adds what the output of nft and ipset tells.
func (s *Snapshot) Host() *models.HostContext {
	host := &models.HostContext{Hostname: s.Hostname, Sysctls: s.Sysctls}
	for _, iface := range s.Interfaces {
		host.Interfaces = append(host.Interfaces, models.HostInterface{Name: iface.Name, Addrs: iface.Addrs, Up: iface.Up})
	}
	return host
}
