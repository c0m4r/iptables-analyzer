package report

import (
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// Many firewalls are written by a program: ufw, firewalld, csf, shorewall,
// Docker, kube-proxy. A change made with iptables on such a host is lost
// when the program writes its rules again, so a fix names the program and,
// where its commands are certain, gives them.

// chainOwner names the program that manages a chain, where the name of the
// chain tells. Rules in such a chain are changed with that program: a
// direct change is lost when it writes its rules again.
func chainOwner(chain string) string {
	switch {
	case strings.HasPrefix(chain, "ufw-") || strings.HasPrefix(chain, "ufw6-"):
		return "ufw"
	case strings.HasPrefix(chain, "DOCKER"):
		return "docker"
	case strings.HasPrefix(chain, "f2b-") || strings.HasPrefix(chain, "fail2ban-"):
		return "fail2ban"
	case strings.HasPrefix(chain, "LIBVIRT_"):
		return "libvirt"
	case strings.HasPrefix(chain, "KUBE-"):
		return "kubernetes"
	case strings.HasPrefix(chain, "cali-"):
		return "calico"
	case strings.HasPrefix(chain, "CNI-"):
		return "cni"
	case strings.HasPrefix(chain, "FLANNEL-"):
		return "flannel"
	case strings.HasPrefix(chain, "ts-"):
		return "tailscale"
	case strings.HasPrefix(chain, "IN_") || strings.HasPrefix(chain, "FWDI_") || strings.HasPrefix(chain, "FWDO_") ||
		strings.HasSuffix(chain, "_direct") || strings.HasSuffix(chain, "_ZONES") || strings.HasSuffix(chain, "_ZONES_SOURCE"):
		return "firewalld"
	case chain == "sshguard":
		return "sshguard"
	case strings.HasPrefix(chain, "CROWDSEC"):
		return "crowdsec"
	}
	return ""
}

// tableManager names the program that writes the whole filter table of a
// ruleset, when its chains show one: it also owns the rules in the built-in
// chains and the chains whose names do not tell.
func tableManager(rs *models.Ruleset) string {
	if rs == nil || rs.Tables["filter"] == nil {
		return ""
	}
	chains := rs.Tables["filter"].Chains
	has := func(names ...string) bool {
		for _, name := range names {
			if chains[name] == nil {
				return false
			}
		}
		return true
	}
	switch {
	case has("ufw-user-input", "ufw-before-input"):
		return "ufw"
	case has("INPUT_ZONES", "INPUT_direct"):
		return "firewalld"
	case has("LOCALINPUT", "LOGDROPIN"):
		return "csf"
	case has("shorewall"):
		return "shorewall"
	}
	return ""
}

func (b *builder) manager(version models.IPVersion) string {
	if b.managers == nil {
		b.managers = map[models.IPVersion]string{}
	}
	manager, known := b.managers[version]
	if !known {
		manager = tableManager(b.ruleset(version))
		b.managers[version] = manager
	}
	return manager
}

// ownerOf names the program that manages one chain of a ruleset. csf,
// shorewall and firewalld write every chain of the filter table. ufw keeps
// its rules in its own chains; a rule in a built-in chain of a ufw host
// that does not jump to them comes from somewhere else.
func (b *builder) ownerOf(version models.IPVersion, table, chain string) string {
	if owner := chainOwner(chain); owner != "" {
		return owner
	}
	if table != "filter" {
		return ""
	}
	switch manager := b.manager(version); manager {
	case "csf", "shorewall", "firewalld":
		return manager
	}
	return ""
}

func (b *builder) owner(rule *models.Rule) string {
	return b.ownerOf(rule.IPVersion, rule.Table, rule.Chain)
}

// firewalldZone returns the zone of a chain of firewalld, such as "public"
// for IN_public_allow.
func firewalldZone(chain string) string {
	for _, prefix := range []string{"IN_", "FWDI_", "FWDO_"} {
		if !strings.HasPrefix(chain, prefix) {
			continue
		}
		zone := strings.TrimPrefix(chain, prefix)
		for _, suffix := range []string{"_allow", "_deny", "_log", "_pre", "_post"} {
			zone = strings.TrimSuffix(zone, suffix)
		}
		return zone
	}
	return ""
}

// managedExposureFix says how to limit an open port on a host whose rules a
// program writes. ports is the port or the range as iptables writes it.
func managedExposureFix(owner string, protocol models.Protocol, first, last int, rule *models.Rule, limiter bool) *Fix {
	ports := strconv.Itoa(first)
	if last > first {
		ports += ":" + strconv.Itoa(last)
	}
	lost := "a change made with iptables is lost when it writes its rules again"
	switch owner {
	case "ufw":
		// "ufw limit" rules accept in a chain of their own.
		verb := "allow"
		if strings.HasSuffix(rule.Chain, "-user-limit-accept") {
			verb = "limit"
		}
		fix := &Fix{
			Summary: "ufw manages this rule, and a change made with iptables is lost at its next reload. " +
				"If the clients are known, allow only them and delete the open rule.",
			Steps: []FixStep{
				{"Allow the known clients", "ufw allow from " + trusted + " to any port " + ports + " proto " + string(protocol)},
				{"Delete the rule for any source", "ufw delete " + verb + " " + ports + "/" + string(protocol)},
			},
		}
		if limiter {
			fix.Steps = append(fix.Steps, FixStep{"Or keep SSH open and limit new connections for each source", "ufw limit " + ports + "/" + string(protocol)})
		}
		return fix
	case "firewalld":
		fix := &Fix{Summary: "firewalld manages this rule, and " + lost + ". If the clients are known, allow the port for them and remove it for all others."}
		zone := firewalldZone(rule.Chain)
		if zone == "" {
			fix.Summary += " The rule is not in a chain of a zone: look for it among the direct rules (firewall-cmd --direct --get-all-rules)."
			return fix
		}
		family := "ipv4"
		if rule.IPVersion == models.IPv6 {
			family = "ipv6"
		}
		dashed := strings.ReplaceAll(ports, ":", "-")
		zoneOption := "--zone=" + shellQuote(zone)
		fix.Steps = []FixStep{
			{"Allow the known clients", "firewall-cmd --permanent " + zoneOption + " --add-rich-rule='rule family=\"" + family +
				"\" source address=\"" + trusted + "\" port port=\"" + dashed + "\" protocol=\"" + string(protocol) + "\" accept'"},
			{"Remove the port for any source (when the zone lists it as a service, use --remove-service=NAME)",
				"firewall-cmd --permanent " + zoneOption + " --remove-port=" + dashed + "/" + string(protocol)},
			{"Load the permanent configuration", "firewall-cmd --reload"},
		}
		return fix
	case "csf":
		list := strings.ToUpper(string(protocol)) + "_IN"
		if rule.IPVersion == models.IPv6 {
			list = strings.ToUpper(string(protocol)) + "6_IN"
		}
		fix := &Fix{Summary: "csf (ConfigServer Firewall) writes these rules from /etc/csf/csf.conf, and " + lost + ". " +
			"If the clients are known, remove the port from " + list + " in /etc/csf/csf.conf and allow it for their addresses in /etc/csf/csf.allow."}
		if last == first {
			fix.Steps = []FixStep{
				{"Allow the known clients for this port", "echo '" + string(protocol) + "|in|d=" + ports + "|s=" + trusted + "' >> /etc/csf/csf.allow"},
				{"After you removed the port from " + list + ", load the rules again", "csf -r"},
			}
		}
		return fix
	case "shorewall":
		return &Fix{
			Summary: "shorewall compiles these rules from /etc/shorewall/rules, and " + lost + ". If the clients are known, give the rule their " +
				"addresses as its source there, for example \"ACCEPT net:" + trusted + " $FW " + string(protocol) + " " + ports + "\".",
			Steps: []FixStep{{"Check the changed configuration and load it", "shorewall check && shorewall reload"}},
		}
	}
	return &Fix{Summary: "The chain of this rule belongs to " + owner + ". If the clients are known, limit the rule to their addresses there; " +
		lost + "."}
}
