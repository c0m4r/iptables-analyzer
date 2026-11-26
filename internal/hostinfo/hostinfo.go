// Package hostinfo reads the facts about a host that its iptables rules do
// not hold but that decide what the rules do: the contents of ipsets, the
// nftables tables next to the tables of iptables, and kernel settings.
//
// The parsers read text that tools printed as root, on a host that the
// reader of the report may not control. They are safe to call in the
// sandbox, and every name they return has its control characters escaped.
package hostinfo

import (
	"bufio"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/textsafe"
)

// maxLine bounds one line of input. ipset comments are at most 255 bytes.
const maxLine = 64 * 1024

// addressTypes are the set types whose entries are addresses or networks,
// so that a source address alone tells whether it matches.
var addressTypes = map[string]bool{"hash:ip": true, "hash:net": true, "bitmap:ip": true}

// ParseIPSets reads the output of "ipset save" (also "ipset list -o save"):
//
//	create trusted hash:net family inet hashsize 1024 maxelem 65536
//	add trusted 10.0.0.0/8
//	add trusted 10.9.0.0/16 nomatch
//
// Sets of other types are returned without entries: the analysis then knows
// that the set exists and that it cannot evaluate it.
func ParseIPSets(text string) (map[string]models.IPSet, error) {
	sets := map[string]models.IPSet{}
	// netmask holds the prefix length of a hash:ip set that stores networks.
	netmask := map[string]int{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), maxLine)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		fields := strings.Fields(textsafe.Escape(scanner.Text()))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "create", "-N":
			if len(fields) < 3 {
				return nil, fmt.Errorf("line %d: create needs a name and a type", lineNum)
			}
			set := models.IPSet{Name: fields[1], Type: fields[2], Addresses: addressTypes[fields[2]]}
			for i := 3; i+1 < len(fields); i++ {
				switch fields[i] {
				case "family":
					set.Family = fields[i+1]
				case "netmask":
					var bits int
					if _, err := fmt.Sscanf(fields[i+1], "%d", &bits); err == nil {
						netmask[set.Name] = bits
					}
				}
			}
			if _, exists := sets[set.Name]; exists {
				return nil, fmt.Errorf("line %d: set %q is created twice", lineNum, set.Name)
			}
			sets[set.Name] = set
		case "add", "-A":
			if len(fields) < 3 {
				return nil, fmt.Errorf("line %d: add needs a set and an entry", lineNum)
			}
			set, exists := sets[fields[1]]
			if !exists {
				return nil, fmt.Errorf("line %d: entry for the unknown set %q", lineNum, fields[1])
			}
			switch {
			case set.Type == "list:set":
				set.Members = append(set.Members, fields[2])
			case set.Addresses:
				entry, err := normalizeEntry(fields[2], netmask[set.Name])
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineNum, err)
				}
				excluded := false
				for _, option := range fields[3:] {
					if option == "comment" {
						break // the rest of the line is the text of the comment
					}
					excluded = excluded || option == "nomatch"
				}
				if excluded {
					set.Excluded = append(set.Excluded, entry)
				} else {
					set.Entries = append(set.Entries, entry)
				}
			}
			sets[fields[1]] = set
		default:
			return nil, fmt.Errorf("line %d: %q is not a line of \"ipset save\"", lineNum, fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sets, nil
}

// normalizeEntry checks an address, a network or a range of addresses and
// returns it in one form. bits is the prefix length of a set that stores
// networks of one size, or 0.
func normalizeEntry(entry string, bits int) (string, error) {
	if first, last, isRange := strings.Cut(entry, "-"); isRange {
		lo, errLo := netip.ParseAddr(first)
		hi, errHi := netip.ParseAddr(last)
		if errLo != nil || errHi != nil || lo.Is4() != hi.Is4() || lo.Compare(hi) > 0 {
			return "", fmt.Errorf("invalid range of addresses %q", entry)
		}
		return lo.String() + "-" + hi.String(), nil
	}
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("invalid entry %q", entry)
	}
	if bits > 0 && bits < addr.BitLen() {
		return netip.PrefixFrom(addr, bits).Masked().String(), nil
	}
	return addr.String(), nil
}

// iptablesTables are the tables that the nf_tables variant of iptables
// creates. iptables-save prints them, so they are not reported.
var iptablesTables = map[string]bool{"filter": true, "nat": true, "mangle": true, "raw": true, "security": true}

// ParseNFTChains reads the output of "nft list chains" and returns the
// tables that iptables-save does not print, each with the hooks of its
// chains:
//
//	table inet firewalld {
//		chain filter_INPUT {
//			type filter hook input priority filter + 10; policy accept;
//		}
//	}
//
// Tables of the families arp and bridge do not see the packets of this
// analysis and are left out.
func ParseNFTChains(text string) []models.NativeTable {
	var tables []models.NativeTable
	current := -1
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), maxLine)
	for scanner.Scan() {
		fields := strings.Fields(textsafe.Escape(scanner.Text()))
		switch {
		case len(fields) >= 3 && fields[0] == "table":
			current = -1
			family, name := fields[1], strings.Trim(fields[2], "\"")
			switch family {
			case "ip", "ip6":
				if iptablesTables[name] {
					continue
				}
			case "inet", "netdev":
			default:
				continue
			}
			tables = append(tables, models.NativeTable{Family: family, Name: name})
			current = len(tables) - 1
		case current >= 0 && len(fields) >= 4 && fields[0] == "type":
			for i := 1; i+1 < len(fields); i++ {
				if fields[i] != "hook" {
					continue
				}
				hook := strings.TrimSuffix(fields[i+1], ";")
				known := false
				for _, existing := range tables[current].Hooks {
					known = known || existing == hook
				}
				if !known {
					tables[current].Hooks = append(tables[current].Hooks, hook)
				}
			}
		}
	}
	for i := range tables {
		sort.Strings(tables[i].Hooks)
	}
	return tables
}

// sysctlNames are the settings that the analysis uses, as paths below
// /proc/sys. "%s" stands for the name of an interface.
var sysctlNames = []string{
	"net/ipv4/ip_forward",
	"net/ipv6/conf/all/forwarding",
	"net/ipv4/conf/all/rp_filter",
	"net/ipv4/conf/default/rp_filter",
	"net/ipv4/conf/all/route_localnet",
	"net/ipv4/conf/%s/rp_filter",
	"net/ipv4/conf/%s/route_localnet",
}

// SysctlPaths returns the files below /proc/sys to read for a host with the
// given interfaces, each with the name of its setting.
func SysctlPaths(interfaces []string) map[string]string {
	paths := map[string]string{}
	add := func(path string) {
		paths[strings.ReplaceAll(path, "/", ".")] = "/proc/sys/" + path
	}
	for _, name := range sysctlNames {
		if !strings.Contains(name, "%s") {
			add(name)
			continue
		}
		for _, iface := range interfaces {
			// The name is one part of a path. A VLAN device such as eth0.100
			// is that; a name with a slash or of dots only is not.
			if strings.Contains(iface, "/") || strings.Trim(iface, ".") == "" {
				continue
			}
			add(fmt.Sprintf(name, iface))
		}
	}
	return paths
}

// CleanSysctl returns the value of a setting when it is a small number, as
// all settings that the analysis reads are.
func CleanSysctl(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 4 {
		return "", false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return value, true
}

// InterfaceSetting returns a setting that the kernel reads for one interface
// together with the setting for all interfaces, and whether both are known.
// For rp_filter the kernel takes the higher of the two values; for
// route_localnet it is on when either is.
func InterfaceSetting(host *models.HostContext, name, iface string) (value string, known bool) {
	all, okAll := host.Sysctl("net.ipv4.conf.all." + name)
	own, okOwn := host.Sysctl("net.ipv4.conf." + iface + "." + name)
	switch {
	case !okAll:
		return "", false
	case !okOwn:
		return all, iface == ""
	case own > all:
		return own, true
	}
	return all, true
}

// routeTypes are the words that "ip route" prints in front of a destination
// to name the kind of the route.
var routeTypes = map[string]bool{
	"unicast": true, "local": true, "broadcast": true, "multicast": true, "anycast": true,
	"blackhole": true, "unreachable": true, "prohibit": true, "throw": true, "nat": true,
}

// ParseRoutes reads the output of "ip -4 route show table main":
//
//	default via 192.0.2.1 dev eth0 proto dhcp metric 100
//	192.168.1.0/24 dev eth1 proto kernel scope link src 192.168.1.1
//	blackhole 10.99.0.0/16
//
// A route with several next hops has them on lines of their own, each with
// its device. Lines that are no routes are an error: the caller then leaves
// the routes out, which only makes the analysis state less.
func ParseRoutes(text string) ([]models.Route, error) {
	var routes []models.Route
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), maxLine)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := textsafe.Escape(scanner.Text())
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		devices := func(route *models.Route) {
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == "dev" && !containsText(route.Devices, fields[i+1]) {
					route.Devices = append(route.Devices, fields[i+1])
				}
			}
		}
		if fields[0] == "nexthop" {
			if len(routes) == 0 {
				return nil, fmt.Errorf("line %d: a next hop without a route", lineNum)
			}
			devices(&routes[len(routes)-1])
			continue
		}
		if routeTypes[fields[0]] {
			if fields = fields[1:]; len(fields) == 0 {
				return nil, fmt.Errorf("line %d: a route without a destination", lineNum)
			}
		}
		route := models.Route{}
		switch destination := fields[0]; {
		case destination == "default":
			route.Destination = "0.0.0.0/0"
		default:
			prefix, err := netip.ParsePrefix(destination)
			if err != nil {
				addr, addrErr := netip.ParseAddr(destination)
				if addrErr != nil || addr.Zone() != "" {
					return nil, fmt.Errorf("line %d: %q is not the destination of a route", lineNum, destination)
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			if !prefix.Addr().Is4() {
				return nil, fmt.Errorf("line %d: %q is not an IPv4 destination", lineNum, destination)
			}
			route.Destination = prefix.Masked().String()
		}
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "metric" {
				route.Metric, _ = strconv.Atoi(fields[i+1])
			}
		}
		devices(&route)
		routes = append(routes, route)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return routes, nil
}

func containsText(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
