package analyzer

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The report comes from the evaluation of sets of sources; the trace follows
// one packet, and its verdicts are compared with the kernel. This test ties
// the two together: for sampled sources, ports and interfaces of every
// fixture, a source that the evaluation accepts for certain must be accepted
// by the trace, and a source that it does not accept at all must not be.

var consistencySources = []string{
	"203.0.113.5", "203.0.113.66", "198.51.100.23", "192.0.2.44", "8.8.8.8",
	"10.1.2.3", "10.244.0.9", "192.168.1.77", "192.168.122.9", "172.17.0.9", "172.16.5.5", "169.254.3.3",
}

func consistencyRulesets(t *testing.T) map[string]string {
	rulesets := map[string]string{
		"kernel filter rules": kernelFilterRulesText,
		"redirects": natRules([]string{
			"-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080",
			"-A PREROUTING -p tcp -m tcp --dport 8443 -j DNAT --to-destination 10.8.0.2:443",
			"-A PREROUTING -s 203.0.113.0/24 -p tcp -m tcp --dport 9000 -j REDIRECT --to-ports 3128",
			"-A PREROUTING -i eth1 -p udp -j REDIRECT --to-ports 53",
		},
			"-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT",
			"-A INPUT -p tcp -m tcp --dport 9000 -j ACCEPT",
			"-A INPUT -p tcp -m conntrack --ctorigdstport 9000 -j ACCEPT",
			"-A INPUT -p udp -m udp --dport 53 -j ACCEPT",
			"-A FORWARD -d 10.8.0.2/32 -p tcp -m tcp --dport 443 -j ACCEPT"),
	}
	for _, name := range []string{"basic", "insecure", "docker", "docker29", "ufw", "k8s", "fail2ban", "libvirt", "firewalld", "router"} {
		rulesets[name] = readFixture(t, name+".iptables-save")
	}
	return rulesets
}

func TestTraceAgreesWithTheEvaluation(t *testing.T) {
	compared := 0
	for name, rules := range consistencyRulesets(t) {
		rs := mustParse(t, rules, models.IPv4)
		e := newInputEvaluator(rs, nil)
		for _, protocol := range []models.Protocol{models.ProtoTCP, models.ProtoUDP} {
			for _, class := range e.classes(protocol) {
				if !class.named && class.first != 1 {
					continue // one of the ports that no rule names stands for all
				}
				for _, candidate := range e.candidates {
					iface := candidate.name
					if iface == otherInterface {
						iface = "zz9" // an interface that no rule names
					}
					query := e.newConnection(protocol, class.first, "0.0.0.0")
					query.InIface = candidate.name
					type outcome struct {
						accepted, possible bool
						delivery           string
					}
					outcomes := map[string]*outcome{}
					for _, source := range consistencySources {
						outcomes[source] = &outcome{}
					}
					for _, way := range e.ways(query, class) {
						path, delivery := e.deliver(way), "local"
						if !way.local {
							path, delivery = e.forward(way), "forward"
						}
						for _, segment := range path.Accepted {
							for _, source := range consistencySources {
								if !segment.Set.contains(netip.MustParseAddr(source)) {
									continue
								}
								result := outcomes[source]
								if segment.Possible || segment.Narrowed != "" || segment.Condition != "" {
									result.possible = true
								} else {
									result.accepted, result.delivery = true, delivery
								}
							}
						}
					}
					for _, source := range consistencySources {
						trace := Trace(rs, nil, models.Packet{Protocol: protocol, Source: source, Port: class.first, In: iface, State: "NEW"})
						if !trace.Certain {
							continue
						}
						result := outcomes[source]
						where := fmt.Sprintf("%s: %s %s -> :%d in %s", name, protocol, source, class.first, iface)
						switch {
						case result.accepted && (trace.Verdict != "ACCEPT" || trace.Delivery != result.delivery):
							t.Errorf("%s: the evaluation accepts (%s), the trace says %s %s by %s", where, result.delivery, trace.Verdict, trace.Delivery, trace.DecidedBy)
						case !result.accepted && !result.possible && trace.Verdict == "ACCEPT":
							t.Errorf("%s: the evaluation does not accept, the trace says ACCEPT (%s) by %s", where, trace.Delivery, trace.DecidedBy)
						}
						if result.accepted || !result.possible {
							compared++
						}
					}
				}
			}
		}
	}
	if compared < 2000 {
		t.Errorf("only %d packets were compared", compared)
	}
	t.Logf("%d packets compared", compared)
}

// kernelFilterRulesText is the ruleset of the kernel comparison, which uses
// most of the matches that the evaluation models. It is repeated here for
// platforms where that comparison is not built.
var kernelFilterRulesText = strings.Join([]string{
	"*raw", ":PREROUTING ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]",
	"-A PREROUTING -s 10.1.2.3/32 -p tcp -m tcp --dport 7001 -j DROP",
	"-A PREROUTING -p tcp -m tcp --dport 7002 -j NOTRACK", "COMMIT",
	"*mangle", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]",
	"-A PREROUTING -p tcp -m tcp --dport 7003 -j MARK --set-xmark 0x10/0xff",
	"-A INPUT -p tcp -m tcp --dport 7004 -j DROP", "COMMIT",
	"*filter", ":INPUT DROP [0:0]", ":FORWARD DROP [0:0]", ":OUTPUT ACCEPT [0:0]", ":ADMIN - [0:0]", ":LIMITED - [0:0]", ":SERVICES - [0:0]",
	"-A INPUT -i lo -j ACCEPT",
	"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
	"-A INPUT -m conntrack --ctstate INVALID -j DROP",
	"-A INPUT -s 203.0.113.5/32 -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable",
	"-A INPUT -p tcp -m tcp --dport 5000 -j ACCEPT",
	"-A INPUT -p tcp -m tcp --dport 22 -j ADMIN",
	"-A INPUT -j SERVICES",
	"-A INPUT -p tcp -m multiport --dports 6000:6010,6020 -m iprange --src-range 10.1.2.0-10.1.2.9 -j ACCEPT",
	"-A INPUT -i eth0 -p tcp -m tcp --dport 6501 -j ACCEPT",
	"-A INPUT ! -i eth0 -p tcp -m tcp --dport 6502 -j ACCEPT",
	"-A INPUT ! -s 10.0.0.0/8 -p tcp -m tcp --dport 6503 -j ACCEPT",
	"-A INPUT -p tcp -m tcp --dport 6504 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT",
	"-A INPUT -p tcp -m tcp --dport 7001 -j ACCEPT",
	"-A INPUT -p tcp -m tcp --dport 7004 -j ACCEPT",
	"-A INPUT -p udp -m udp --dport 53 -j ACCEPT",
	"-A INPUT -p udp -m udp --sport 1024:65535 --dport 123 -j ACCEPT",
	"-A INPUT -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 6600 -j ACCEPT",
	"-A INPUT -p tcp -m addrtype ! --dst-type LOCAL -m tcp --dport 6601 -j ACCEPT",
	"-A INPUT -p tcp -m pkttype --pkt-type unicast -m tcp --dport 6604 -j ACCEPT",
	"-A INPUT -p tcp -m tcp ! --dport 1:9999 -j ACCEPT",
	"-A ADMIN -s 192.168.1.0/24 -j ACCEPT",
	"-A ADMIN -s 10.1.2.3/32 -j RETURN",
	"-A ADMIN -j DROP",
	"-A LIMITED -s 203.0.113.0/24 -j ACCEPT",
	"-A LIMITED -s 10.0.0.0/8 -j RETURN",
	"-A SERVICES -p tcp -m tcp --dport 80 -j ACCEPT",
	"-A SERVICES -p tcp -m tcp --dport 443 -g LIMITED",
	"-A SERVICES -p tcp -m tcp --dport 443 -j ACCEPT",
	"COMMIT", "",
}, "\n")
