# How the analysis works

This document describes the analysis method, the code structure and the limits of the tool.

## Checks

- **Rule analysis**: the tool parses iptables and ip6tables rules and shows them in tables.
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
- **Dead rule detection**: the tool finds rules after a catch-all DROP.
  Conditional matches, for example `recent --update`, are not catch-all rules.
- **Service cross-reference**: the tool compares the firewall rules with the listening
  services from `ss`. It follows user-defined chains. Listeners of Docker published ports
  follow the Docker path.
- **Configuration errors**: the tool finds dropped loopback traffic, a missing
  `ESTABLISHED,RELATED` rule under default deny, and blocked IPv6 neighbor discovery
  and router advertisements. These errors stop IPv6 connectivity.
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
| `internal/scorer/` | The 100-point security score |
| `internal/recommender/` | The recommendations |
| `internal/ui/` | The terminal report (lipgloss) and JSON |

Files of `internal/analyzer/`:

- `evaluation.go`: order-aware packet-path evaluation with jump, goto and RETURN.
- `analyzer.go`: service exposure and the cross-reference with listening services.
- `shadow.go`: shadowed rules (CIDR containment, port ranges, match extensions).
- `docker.go`: Docker published ports, ineffective rules, rule order and direct routing.
- `docker_topology.go`: bridges, container addresses, raw protection and gateway modes,
  from the Docker rules.
- `effectiveness.go`: policy checks, dead rules and conntrack.

## Order of the steps

1. Read all input: rule files or `iptables-save` output, the `ss` data and the interface list.
2. Start the sandbox (see [security.md](security.md)).
3. Parse the input, then analyze it.
4. Make the recommendations, the baseline and the score.
5. Write the report.

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
| `LOCALNET` | Only private address ranges, for example `10.0.0.0/8` or `fc00::/7`. |
| `WHITELISTED` | Only single hosts (/32 or /128). |

When more than one scope applies, the tool uses the widest scope.
The report lists only `EXPOSED` services as findings, and only they decrease the score.
The service table shows the other scopes. Docker published ports use the same scopes.

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
