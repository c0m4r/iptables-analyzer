// Package baseline generates a recommended default firewall for both IPv4
// and IPv6. Both families are always generated: a stack that is not in use
// today still receives addresses automatically (IPv6 SLAAC in particular) and
// must not be left open.
package baseline

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// Options tailors the baseline to the analyzed host.
type Options struct {
	// SSHPorts are TCP ports kept open for remote administration. Empty means 22.
	SSHPorts []int
	// SSHDetected is true when SSHPorts come from a listening sshd.
	SSHDetected bool
	// Services are other listeners, emitted as commented allow rules.
	Services []models.ListeningService
	// Docker is true when Docker manages the host's FORWARD path.
	Docker bool
	// Published lists Docker-published ports, emitted as commented DOCKER-USER rules.
	Published []models.PublishedPort
	// KeptJumps are the rules of the current INPUT chain that jump to chains of
	// other programs (fail2ban, libvirt, Tailscale), as rule lines. The
	// baseline flushes INPUT, so it must repeat them or they are lost.
	KeptJumps map[models.IPVersion][]string
	// UFW is true when ufw manages the firewall. Its chains hold the whole
	// policy, so they are not kept, and the notes advise against the baseline.
	UFW bool
	// DockerUserRules are the current rules of DOCKER-USER, which the baseline
	// replaces. They are emitted as comments.
	DockerUserRules map[models.IPVersion][]string
	// ForwardPolicy is the FORWARD policy to keep for a family: the host
	// routes packets by rules that the baseline does not know.
	ForwardPolicy map[models.IPVersion]string
	// SystemdPorts are TCP ports that only systemd holds: possibly a
	// socket-activated sshd that has not been started yet.
	SystemdPorts []int
}

// FromResult derives options from an analysis.
func FromResult(result *models.AnalysisResult) Options {
	var opts Options
	if result == nil {
		return opts
	}
	opts.Docker = analyzer.DockerManaged(result.IPv4Rules) || analyzer.DockerManaged(result.IPv6Rules)
	opts.Published = result.PublishedPorts
	opts.KeptJumps = map[models.IPVersion][]string{}
	opts.DockerUserRules = map[models.IPVersion][]string{}
	opts.ForwardPolicy = map[models.IPVersion]string{}
	for _, rs := range []*models.Ruleset{result.IPv4Rules, result.IPv6Rules} {
		if rs == nil || rs.Tables["filter"] == nil {
			continue
		}
		filter := rs.Tables["filter"]
		if input := filter.Chains["INPUT"]; input != nil {
			for i := range input.Rules {
				rule := &input.Rules[i]
				if _, isChain := filter.Chains[rule.Target]; !isChain {
					continue
				}
				if strings.HasPrefix(rule.Target, "ufw-") {
					opts.UFW = true
					continue
				}
				opts.KeptJumps[rs.IPVersion] = append(opts.KeptJumps[rs.IPVersion], "-A INPUT "+analyzer.RuleSpec(rule))
			}
		}
		if user := filter.Chains["DOCKER-USER"]; user != nil {
			for i := range user.Rules {
				if spec := analyzer.RuleSpec(&user.Rules[i]); spec != "-j RETURN" {
					opts.DockerUserRules[rs.IPVersion] = append(opts.DockerUserRules[rs.IPVersion], "-A DOCKER-USER "+spec)
				}
			}
		}
		// Docker sets and needs FORWARD DROP itself. Any other host that
		// routes packets under an ACCEPT policy keeps that policy.
		if forward := filter.Chains["FORWARD"]; forward != nil && forward.Policy == "ACCEPT" && !analyzer.DockerManaged(rs) &&
			(len(forward.Rules) > 0 || analyzer.ForwardsPackets(rs)) {
			opts.ForwardPolicy[rs.IPVersion] = forward.Policy
		}
	}
	seenSSH := map[int]bool{}
	for _, svc := range result.Services {
		// Listeners on loopback, behind Docker's NAT or behind a guest bridge
		// do not need a rule for other hosts.
		if svc.Status == models.ServiceLocalhost || svc.Status == models.ServiceDocker || svc.Status == models.ServiceInternal {
			continue
		}
		if svc.Protocol == models.ProtoTCP && (svc.Process == "sshd" || strings.HasPrefix(svc.Process, "sshd-") || slices.Contains(svc.Processes, "sshd")) {
			if !seenSSH[svc.Port] {
				seenSSH[svc.Port] = true
				opts.SSHPorts = append(opts.SSHPorts, svc.Port)
			}
			continue
		}
		if svc.Process == "docker-proxy" {
			continue
		}
		if svc.Protocol == models.ProtoTCP && svc.Process == "systemd" && !slices.Contains(opts.SystemdPorts, svc.Port) {
			opts.SystemdPorts = append(opts.SystemdPorts, svc.Port)
		}
		opts.Services = append(opts.Services, svc)
	}
	sort.Ints(opts.SSHPorts)
	sort.Ints(opts.SystemdPorts)
	opts.SSHDetected = len(opts.SSHPorts) > 0
	return opts
}

// Generate renders the IPv4 and IPv6 baselines in iptables-restore format.
func Generate(opts Options) models.Baseline {
	sshPorts := opts.SSHPorts
	if len(sshPorts) == 0 {
		sshPorts = []int{22}
	}
	return models.Baseline{
		IPv4:  render(models.IPv4, opts, sshPorts),
		IPv6:  render(models.IPv6, opts, sshPorts),
		Notes: notes(opts, sshPorts),
	}
}

func render(version models.IPVersion, opts Options, sshPorts []int) string {
	v6 := version == models.IPv6
	command, family, loopback, icmp := "iptables", "IPv4", "127.0.0.0/8", "icmp"
	if v6 {
		command, family, loopback, icmp = "ip6tables", "IPv6", "::1/128", "ipv6-icmp"
	}
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	forwardPolicy := "DROP"
	if kept := opts.ForwardPolicy[version]; kept != "" {
		forwardPolicy = kept
	}
	line("# Recommended %s baseline generated by iptables-analyzer (%s-restore format).", family, command)
	if forwardPolicy == "DROP" {
		line("# Default deny inbound and forwarded traffic; outbound traffic is allowed.")
	} else {
		line("# Default deny inbound traffic; outbound traffic is allowed. FORWARD keeps its")
		line("# policy: this host routes packets by rules that this file does not replace.")
	}
	line("# Apply with \"%s-restore --noflush\": it replaces INPUT%s and keeps every", command, dockerUserSuffix(opts.Docker))
	line("# other chain, including Docker's, intact.")
	line("*filter")
	line(":INPUT DROP [0:0]")
	line(":FORWARD %s [0:0]", forwardPolicy)
	line(":OUTPUT ACCEPT [0:0]")
	if opts.Docker {
		line(":DOCKER-USER - [0:0]")
	}
	line("-F INPUT")
	line("-A INPUT -i lo -j ACCEPT")
	line("-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	if v6 {
		line("# Neighbor discovery is untracked by conntrack and must be allowed explicitly;")
		line("# a hop limit of 255 proves the sender is on-link.")
		for _, icmpType := range []struct {
			number int
			name   string
		}{{134, "router advertisement (SLAAC)"}, {135, "neighbor solicitation"}, {136, "neighbor advertisement"}} {
			line("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type %d -m hl --hl-eq 255 -m comment --comment \"%s\" -j ACCEPT", icmpType.number, icmpType.name)
		}
		line("-A INPUT -s fe80::/10 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -m comment --comment \"multicast listener query\" -j ACCEPT")
		line("-A INPUT -s fe80::/10 -d fe80::/10 -p udp -m udp --sport 547 --dport 546 -m comment --comment \"DHCPv6 client\" -j ACCEPT")
	}
	line("-A INPUT -m conntrack --ctstate INVALID -j DROP")
	line("-A INPUT -s %s ! -i lo -j DROP", loopback)
	if v6 {
		line("-A INPUT -p %s -m icmp6 --icmpv6-type 128 -m limit --limit 10/sec --limit-burst 20 -j ACCEPT", icmp)
	} else {
		line("-A INPUT -p %s -m icmp --icmp-type 8 -m limit --limit 10/sec --limit-burst 20 -j ACCEPT", icmp)
	}
	if jumps := opts.KeptJumps[version]; len(jumps) > 0 {
		line("# Jumps of the present INPUT chain to chains that other programs manage.")
		line("# They are repeated here because INPUT is flushed. A chain that accepts")
		line("# traffic decides before the rules below: review what each one admits.")
		for _, jump := range jumps {
			line("%s", jump)
		}
	}
	line("# Remote administration: new SSH connections are limited per source address.")
	for _, port := range sshPorts {
		name := fmt.Sprintf("ssh%d-%d", version, port)
		line("-A INPUT -p tcp -m tcp --dport %d -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/min --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name %s -j DROP", port, name)
		line("-A INPUT -p tcp -m tcp --dport %d -m conntrack --ctstate NEW -j ACCEPT", port)
	}
	if services := serviceLines(version, opts.Services); len(services) > 0 {
		line("# Other listening services found on this host. Uncomment only what must be")
		line("# reachable, preferably with -s <trusted-cidr>:")
		for _, service := range services {
			line("%s", service)
		}
	}
	if opts.Docker {
		line("# Docker: published ports never reach INPUT. Restrict them here; packets are")
		line("# already DNATed, so match the published port with conntrack, not --dport.")
		published := publishedLines(version, opts.Published)
		if len(published) == 0 {
			published = []string{
				"# -A DOCKER-USER -p tcp -m conntrack --ctorigdstport <port> --ctdir ORIGINAL -s <trusted-cidr> -j RETURN",
				"# -A DOCKER-USER -p tcp -m conntrack --ctorigdstport <port> --ctdir ORIGINAL -j DROP",
			}
		}
		for _, rule := range published {
			line("%s", rule)
		}
		if present := opts.DockerUserRules[version]; len(present) > 0 {
			line("# Rules that DOCKER-USER has now. This file replaces the chain: remove the")
			line("# comment sign from the rules that must stay.")
			for _, rule := range present {
				line("# %s", rule)
			}
		}
		line("-A DOCKER-USER -j RETURN")
	}
	line("COMMIT")
	return b.String()
}

func dockerUserSuffix(docker bool) string {
	if docker {
		return " and DOCKER-USER"
	}
	return ""
}

func serviceLines(version models.IPVersion, services []models.ListeningService) []string {
	type key struct {
		protocol models.Protocol
		port     int
	}
	seen := map[key]bool{}
	var lines []string
	for _, svc := range services {
		if svc.Status == models.ServiceLocalhost {
			continue
		}
		switch svc.Family {
		case models.SocketDual:
		case models.SocketIPv6:
			if version != models.IPv6 {
				continue
			}
		default:
			if (version == models.IPv6) != svc.IsIPv6 {
				continue
			}
		}
		k := key{svc.Protocol, svc.Port}
		if seen[k] || (svc.Protocol != models.ProtoTCP && svc.Protocol != models.ProtoUDP) {
			continue
		}
		seen[k] = true
		process := svc.Process
		if process == "" {
			process = "unknown process"
		}
		state := ""
		if svc.Protocol == models.ProtoTCP {
			state = " -m conntrack --ctstate NEW"
		}
		lines = append(lines, fmt.Sprintf("# -A INPUT -p %s -m %s --dport %d%s -j ACCEPT   # %s",
			svc.Protocol, svc.Protocol, svc.Port, state, process))
	}
	return lines
}

func publishedLines(version models.IPVersion, published []models.PublishedPort) []string {
	seen := map[string]bool{}
	var lines []string
	for _, mapping := range analyzer.GroupPublishedPorts(published) {
		if mapping.IPVersion != version || mapping.ForwardScope == "" {
			continue
		}
		hostPorts, containerPorts := strconv.Itoa(mapping.HostPort), strconv.Itoa(mapping.ContainerPort)
		if mapping.HostPortEnd > mapping.HostPort {
			hostPorts += ":" + strconv.Itoa(mapping.HostPortEnd)
			containerPorts += "-" + strconv.Itoa(mapping.ContainerPortEnd)
		}
		match := "-p " + string(mapping.Protocol) + " -m conntrack"
		if mapping.HostAddr != "" {
			match += " --ctorigdst " + mapping.HostAddr
		}
		match += " --ctorigdstport " + hostPorts + " --ctdir ORIGINAL"
		if seen[match] {
			continue
		}
		seen[match] = true
		dest := mapping.ContainerAddr + ":" + containerPorts
		if strings.Contains(mapping.ContainerAddr, ":") {
			dest = "[" + mapping.ContainerAddr + "]:" + containerPorts
		}
		lines = append(lines,
			fmt.Sprintf("# -A DOCKER-USER %s -s <trusted-cidr> -j RETURN   # published -> %s", match, dest),
			fmt.Sprintf("# -A DOCKER-USER %s -j DROP", match))
	}
	return lines
}

func notes(opts Options, sshPorts []int) []string {
	ports := make([]string, len(sshPorts))
	for i, port := range sshPorts {
		ports[i] = strconv.Itoa(port)
	}
	sshNote := "SSH stays reachable on TCP port " + strings.Join(ports, ", ") + " (detected from the listening sshd)."
	if !opts.SSHDetected {
		sshNote = "SSH is assumed on TCP port 22; change the port before applying if sshd listens elsewhere."
	}
	result := []string{
		sshNote,
		"Both families are always generated: IPv6 gets addresses automatically (SLAAC), so an unused stack must be closed too.",
		"Keep a second SSH session open and apply with an automatic rollback, for example:",
		"  printf '#!/bin/sh\\nexec iptables-restore --noflush /root/baseline.v4\\n' > /root/apply.v4 && chmod +x /root/apply.v4 && iptables-apply -t 60 -c /root/apply.v4",
		"  printf '#!/bin/sh\\nexec ip6tables-restore --noflush /root/baseline.v6\\n' > /root/apply.v6 && chmod +x /root/apply.v6 && ip6tables-apply -t 60 -c /root/apply.v6",
		"Persist the result with your distribution's mechanism (e.g. iptables-save > /etc/iptables/rules.v4 with iptables-persistent).",
	}
	if opts.Docker {
		result = append(result, "Docker hosts: always use --noflush. A full restore deletes Docker's chains and disconnects all containers until dockerd restarts.")
	}
	if opts.UFW {
		result = append(result, "CAUTION: ufw manages this firewall. Do not apply the baseline on top of it: the next 'ufw reload' replaces "+
			"what the baseline sets, and until then the chains of ufw are detached. Make the changes with ufw (ufw default deny incoming, ufw limit ssh).")
	}
	var targets []string
	for _, version := range []models.IPVersion{models.IPv4, models.IPv6} {
		for _, jump := range opts.KeptJumps[version] {
			fields := strings.Fields(jump)
			for i := 0; i+1 < len(fields); i++ {
				if (fields[i] == "-j" || fields[i] == "-g") && !slices.Contains(targets, fields[i+1]) {
					targets = append(targets, fields[i+1])
				}
			}
		}
	}
	if len(targets) > 0 {
		result = append(result, "The baseline keeps the jumps of INPUT to chains of other programs ("+strings.Join(targets, ", ")+
			"). Rules in those chains are not part of the baseline: a chain that accepts traffic opens it whatever the baseline says.")
	}
	if len(opts.DockerUserRules[models.IPv4])+len(opts.DockerUserRules[models.IPv6]) > 0 {
		result = append(result, "DOCKER-USER has rules now. The baseline replaces the chain and lists the present rules as comments.")
	}
	for _, version := range []models.IPVersion{models.IPv4, models.IPv6} {
		if policy := opts.ForwardPolicy[version]; policy != "" {
			result = append(result, fmt.Sprintf("IPv%d FORWARD keeps its policy (%s): this host routes packets, and the baseline does not replace its forwarding rules.", version, policy))
		}
	}
	if len(opts.SystemdPorts) > 0 {
		held := make([]string, len(opts.SystemdPorts))
		for i, port := range opts.SystemdPorts {
			held[i] = strconv.Itoa(port)
		}
		result = append(result, "systemd holds TCP port "+strings.Join(held, ", ")+" for a service that is not running yet. "+
			"If that is a socket-activated sshd, open the port before you apply the baseline.")
	}
	return result
}
