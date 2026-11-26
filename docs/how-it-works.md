# How the analysis works

This document describes the analysis method, the code structure and the limits of the tool.

## Checks

- **Rule analysis**: the tool parses iptables and ip6tables rules.
- **Shadow detection**: the tool finds rules that an earlier deterministic rule covers.
  Stateful and probabilistic matches do not prove that a rule is shadowed.
- **Docker firewall bypass detection**: the tool follows each published port through
  `raw` → `mangle` → `nat` (DNAT) → `mangle`/`filter`/`security` FORWARD.
  It compares the verdict with the verdict of `filter/INPUT`. It reports:
  - INPUT rules (also ufw and firewalld rules) and default-deny policies that Docker DNAT bypasses,
  - `DOCKER-USER` and `FORWARD` rules that never match, because they test the port or the host
    address before DNAT (`--dport 8080`, `-d <host-ip>`, `--dst-type LOCAL`),
  - `FORWARD` rules after the Docker ACCEPT rules, and rules above the Docker jumps that
    `dockerd` moves when it restarts,
  - containers that other hosts can reach by direct routing: a missing Docker 28+
    `raw/PREROUTING` protection (this also exposes ports published only on `127.0.0.1`),
    and the `routed` and `nat-unprotected` gateway modes,
  - IPv6 forwarding without a filter, when Docker manages iptables but not ip6tables.

  The tool also identifies effective restrictions, for example `--ctorigdstport` and
  `--ctorigsrc` in `DOCKER-USER`, or drops in `raw` or `mangle` PREROUTING.
- **Default behavior**: the tool sends a probe for a port that no rule names through the
  INPUT path and through the FORWARD path. A chain that accepts the probe accepts by default.
  The policy line does not decide: a final `REJECT` under an ACCEPT policy denies by default,
  and a rule `-j ACCEPT` under a DROP policy accepts by default.
- **Open ports**: the tool evaluates one new connection for each range of ports that the
  rules handle in the same way. The result is the list of open ports with their sources.
  It needs no list of listening services.
- **Unreachable rules**: the tool finds rules after a rule that ends the chain for all
  packets. It reports them as one finding for the chain.
  Conditional matches, for example `recent --update`, do not end the chain.
- **Service cross-reference**: the tool compares the firewall rules with the listening
  services from `ss`. It follows user-defined chains. Listeners of Docker published ports
  follow the Docker path.
- **IPv4 and IPv6 comparison**: the tool reports ports that IPv6 opens to all sources
  while IPv4 restricts or filters them.
- **Configuration errors**: the tool finds dropped loopback traffic, dropped packets of
  established connections under default deny, and blocked IPv6 neighbor discovery
  and router advertisements. These errors stop IPv6 connectivity.
  An address family with a DROP policy and no accepting rule is closed on purpose:
  the tool shows one note for it.
- **Certainty**: each finding is `DEFINITE` or `POSSIBLE`. The tool evaluates
  interface-specific rules for each interface. In live mode, it uses the real interface list.

## Packages

| Package | Function |
| --- | --- |
| `cmd/` | Command-line flags and the order of the steps (cobra) |
| `internal/models/` | Data structures: rules, chains, tables, rulesets and findings |
| `internal/parser/` | Parser for the iptables-save format |
| `internal/loader/` | Reads rules from files or from the live system |
| `internal/safeio/` | Bounded file reads and safe execution of system tools |
| `internal/sandbox/` | Privilege drop, no_new_privs and the Landlock sandbox |
| `internal/textsafe/` | Escape of control characters and shell quotes |
| `internal/analyzer/` | The analysis (see below) |
| `internal/services/` | Parser for `ss` output |
| `internal/baseline/` | The recommended IPv4/IPv6 baseline firewall |
| `internal/report/` | The report: the findings with their evidence, fixes and points, and the score |
| `internal/ui/` | The report as text for a terminal (lipgloss), as JSON and as an HTML page |

Files of `internal/analyzer/`:

- `evaluation.go`: order-aware packet-path evaluation with jump, goto and RETURN.
- `addrset.go`: sets of source addresses as sorted address ranges.
- `analyzer.go`: service exposure and the cross-reference with listening services.
- `shadow.go`: shadowed rules (CIDR containment, port ranges, match extensions).
- `docker.go`: Docker published ports, ineffective rules, rule order and direct routing.
- `docker_topology.go`: bridges, container addresses, raw protection and gateway modes,
  from the Docker rules.
- `effectiveness.go`: default behavior, open ports, unreachable rules, replies, loopback,
  neighbor discovery and the comparison of IPv4 with IPv6.

## Order of the steps

1. Read all input: rule files or `iptables-save` output, the `ss` data and the interface list.
   Open the file for `--html`.
2. Start the sandbox (see [security.md](security.md)).
3. Find out what each file holds, parse the input, then analyze it.
4. Make the baseline and build the report.
5. Write the report in the forms that were asked for.

## From the analysis to the report

The analysis states facts: this chain accepts by default, this rule accepts this port
from these sources, this rule never matches. Each fact has a stable code.

The package `internal/report` makes one report from the facts. All output forms show
that report and nothing else, so the terminal, the JSON form and the HTML page always agree.
The report:

- makes one finding from facts that say the same thing: a port that is open on IPv4 and
  on IPv6, the services that are open only because INPUT accepts by default, many open
  ports of one severity, the rules that one rule shadows,
- gives each finding the rules that cause it. For a rule in a user-defined chain, it
  finds the jumps that lead from the built-in chain to the rule,
- writes the fix. A command is written only when it keeps the restrictions of the rule
  that it changes. Rules in the chains of ufw get `ufw` commands,
- gives each finding its severity and its deduction. For a port that is open to all
  sources, both follow from the kind of service that usually listens there: remote
  administration, databases, file services and clear-text protocols weigh most,
  the ports of public services (mail, DNS, web) least,
- adds up the score. A category cannot lose more than its maximum. Findings about one
  port cost one time. Some findings limit the grade,
- finds for each finding what its fix alone gains, and which grade follows.
  This gives the list `Fix first`.

For the deductions and the grade limits, see [usage.md](usage.md#score-and-grade).
For the fields of the report, see [json.md](json.md).

## Algorithms

### Shadow detection

For each rule in a chain, the tool examines if an earlier rule matches a superset of its packets:

- protocol superset (all > specific),
- CIDR containment (a larger network contains a smaller network),
- port range containment,
- interface wildcards,
- conntrack state superset,
- match extensions (rate limits, ICMP types, `recent` parameters).

### Docker bypass detection

1. Find the Docker topology from the Docker rules: bridges (`docker0`, `br-*` and custom names),
   container addresses, bridge subnets, the `raw/PREROUTING` direct-access protection
   and the gateway modes.
2. For each possible ingress interface, evaluate the original packet through `raw` and
   `mangle` PREROUTING. Then walk `nat/PREROUTING` in order through jumps, `goto` and
   `RETURN` (with `addrtype --dst-type LOCAL`). Keep the remaining source ranges.
3. Evaluate each port in each reachable DNAT range. Keep the original and translated
   tuples, the connection state (`NEW`) and the NAT status (`DNAT`).
4. Evaluate the translated packet through `mangle`, `filter` and `security` FORWARD.
   `-o` resolves to the bridge of the container. The tool uses `--ctorigdstport`,
   `--ctorigdst`, `--ctorigsrc` and `--ctdir`. Evaluate the untranslated packet
   through the INPUT hooks.
5. Sources that FORWARD accepts and INPUT refuses are a bypass.
   Otherwise, a FORWARD path without restriction is a published-port exposure.
6. User DROP and REJECT rules on the FORWARD path are ineffective when they match the tuple
   before DNAT but not the translated tuple, or when a Docker ACCEPT rule shadows them.
7. Evaluate packets to each container endpoint without DNAT (and to an unpublished port
   on `nat-unprotected` bridges) to find direct-routing exposure.

### Service cross-reference

The tool walks `filter/INPUT` in order. It follows user-defined jumps, `goto`, `RETURN`
and the default policies. It splits the source CIDRs symbolically.
Thus earlier terminal rules and partial allowlists have their correct effect.
Then it compares the result with the listening services from `ss`.

The tool gives each reachable service the scope of the sources that it accepts:

| Scope | Sources |
| --- | --- |
| `EXPOSED` | Any source, or public networks with more than 65,536 IPv4 addresses (one IPv6 /48) in total. |
| `SUBNET` | Only specific public networks, for example `-s 203.0.113.0/24`. |
| `RESTRICTED` | Only sources that a match selects which the tool cannot read: an ipset, a MAC address, a GeoIP match, a `recent` list. |
| `LOCALNET` | Only private address ranges, for example `10.0.0.0/8` or `fc00::/7`. |
| `WHITELISTED` | Only single hosts (/32 or /128). |

When more than one scope applies, the tool uses the widest scope.
The scope follows from the addresses, not from the form of the rules:
`-m iprange --src-range` gives the same scope as the equivalent `-s` rules.
The report lists only `EXPOSED` services as findings, and only they decrease the score.
The lists of open ports and of listening sockets show the other scopes.
Docker published ports use the same scopes.

### Predicates that the tool cannot decide

The tool does not know if a packet is below a rate limit, or if a source is in an ipset.
It keeps both results and handles each kind of predicate in a different way:

| Kind | Examples | Effect |
| --- | --- | --- |
| All sources can meet it | `limit`, `hashlimit`, `connlimit`, `time`, `statistic`, a source port | An ACCEPT is a definite exposure with a condition. Traffic that passes a rule that drops the excess has the same condition. |
| An unknown set of sources | `set` with `src`, `mac`, `geoip`, `recent --rcheck`, `policy --pol ipsec` | An ACCEPT has the scope `RESTRICTED`. After a DROP with the negated match (`! --match-set allow src`), only the set continues. A DROP of the set (a blocklist) does not change the scope. |
| Not known | `mark`, extensions that are not modeled | The finding is `POSSIBLE`. |

The tool decides these matches exactly: `--syn` and `--tcp-flags` for the first packet of a
connection, `iprange`, `multiport --ports` and `pkttype`.

### Sets of sources

The tool keeps the remaining sources as sorted address ranges.
A rule for one address divides one range into two.
A chain with 20,000 single-address rules (a fail2ban jail) is examined in approximately one second.

### Evaluation limit

Each jump evaluates the target chain again. Chains that jump to the next chain more than
one time make the work grow exponentially. Thus the tool stops after 262,144 chain
traversals for one ruleset. The affected results are then `POSSIBLE`, and the report
shows an assessment note. A real Docker host with many networks uses approximately
200 traversals.

## Limits

- The input must be in the `iptables-save` format. Native nftables rules, routing,
  policy routing and the host network configuration are not in the scope.
- Exposure analysis covers the `raw`, `mangle`, `filter` and `security` INPUT hooks.
  Published-port analysis covers the PREROUTING and FORWARD hooks of these tables and
  `nat/PREROUTING`. The tool does not model routing decisions, `TPROXY`, `REDIRECT`
  to local ports or policy routing.
- Direct-routing findings are always `POSSIBLE`: an attacker must be able to route the
  container subnet through the host, for example on the same L2 segment.
- Saved rulesets do not show the interfaces of the host. The tool evaluates rules for a
  named interface for each interface and for one placeholder for other interfaces.
  This gives `POSSIBLE` findings. Live mode uses the real interface list.
- The Docker userland proxy serves IPv6 for IPv4-only networks through a local
  `docker-proxy` socket. `ip6tables` INPUT filters this path. The tool examines it
  only when it has the listening services.
- The tool keeps match extensions that it does not model, and handles them conservatively.
  They cannot prove shadowed or dead rules. Possible exposure paths stay visible.
- Stateful, probabilistic and side-effect matches, for example `limit`, `statistic` and
  `recent`, do not prove that a rule is shadowed.
- Saved `ss` wildcard sockets shown as `*` count for IPv4 and IPv6, because the saved
  text does not show if a socket is IPv6-only.
- The tool does not use rule counters.
- A `REDIRECT` in `nat/PREROUTING` gives an assessment note. The tool does not follow it.
- The tool examines published ports only for DNAT rules that have a destination port.
  kube-proxy matches the port in an earlier chain. The tool gives one assessment note
  for these rules.
- Interfaces with the names of host-only bridges (`docker0`, `br-*`, `virbr*`, `lxcbr*`,
  `lxdbr*`, `incusbr*`, `podman*`) connect containers and virtual machines of the host.
  A listener that only they reach has the status `INTERNAL`.
  Overlay devices and the pod interfaces of a cluster (`flannel.1`, `cni0`, `cali*`) are
  ordinary interfaces: they can carry traffic of other hosts.
- The tool does not read the contents of ipsets, sysctl values, or native nftables rules.
