<div align="center">

# iptables-analyzer

![Linux](https://img.shields.io/badge/made%20for-linux-yellow?logo=linux&logoColor=ffffff)
![Go](https://img.shields.io/badge/go%20go%20go-blue?logo=go&logoColor=ffffff)
[![License: GPL v3](https://img.shields.io/badge/License-AGPLv3-red.svg)](https://www.gnu.org/licenses/agpl-3.0)

A Go CLI tool for analyzing iptables/ip6tables firewall rules to find security issues, shadowed rules, Docker NAT bypasses, exposed services, and policy violations. Provides security scoring and actionable recommendations.

<img width="833" height="330" alt="image" src="https://github.com/user-attachments/assets/3ec0795e-7ab7-4494-ba69-5fa00404cfc8" />

</div>

## Features

- **Rule Analysis**: Parses and displays iptables/ip6tables rules in readable tables
- **Shadow Detection**: Finds rules that are covered by earlier deterministic rules; stateful and probabilistic matches are kept out of definite shadow proofs
- **Docker Firewall Bypass Detection**: Follows every published port through `raw` → `mangle` → `nat` (DNAT) → `mangle`/`filter`/`security` FORWARD and compares the verdict with what `filter/INPUT` would have decided. It reports:
  - INPUT rules (including ufw/firewalld ones) and default-deny policies that Docker's DNAT bypasses
  - `DOCKER-USER`/`FORWARD` rules that can never match because they test the pre-DNAT port or host address (`--dport 8080`, `-d <host-ip>`, `--dst-type LOCAL`)
  - `FORWARD` rules placed after Docker's ACCEPT rules, and rules above Docker's jumps that `dockerd` reorders on restart
  - containers reachable by direct routing: missing Docker 28+ `raw/PREROUTING` protection (which also exposes ports published only on `127.0.0.1`), and the `routed` and `nat-unprotected` gateway modes
  - IPv6 forwarding left unfiltered when Docker manages iptables but not ip6tables
  - effective restrictions are recognized, e.g. `--ctorigdstport`/`--ctorigsrc` in `DOCKER-USER`, or drops in `raw`/`mangle` PREROUTING
- **Dead Rule Detection**: Identifies rules that come after a catch-all DROP and are unreachable, correctly handling conditional match extensions (e.g. `recent --update` is not a catch-all)
- **Service Cross-Reference**: Matches firewall rules against actual listening services (`ss` output) to find exposed ports, following user-defined chain jumps (e.g. SSHBRUTE, ICMPFLOOD chains); listeners of Docker-published ports follow the Docker path
- **Configuration Errors**: Detects dropped loopback traffic, missing `ESTABLISHED,RELATED` handling under default deny, and blocked IPv6 neighbor discovery/router advertisements (which break IPv6 connectivity)
- **Recommended Baseline**: Always generates a reviewed default-deny firewall for **both** IPv4 and IPv6, tailored to the detected SSH port, listening services, and Docker
- **Security Scoring**: 100-point security score with A-F grades when every scored category was assessed, and an explicit `INCOMPLETE` grade otherwise:
  - Policy (default ACCEPT policies)
  - Exposure (listening services open to the network)
  - Shadows/Docker bypasses
  - Hygiene (best practices like conntrack, rate limiting)
  - IPv6 coverage
- **Recommendations**: Suggestions that identify the exact table, chain, and rule; ready-to-run replacements are emitted only when the original restrictions can be preserved
- **Dual Stack**: Full support for both IPv4 (iptables) and IPv6 (ip6tables)
- **Certainty**: Every finding is `DEFINITE` or `POSSIBLE`. Predicates the analysis cannot decide (ipsets, marks, rate limits) only make a verdict possible when the verdict depends on them matching; interface-specific rules are evaluated per interface (the live interface list is used in live mode)
- **Flexible Input**: Analyze live system (requires root) or saved iptables-save output files
- **Multiple Output Formats**: Colored CLI, JSON, score-only
- **Rich TUI**: Polished terminal UI built with lipgloss — 256-color palette, rounded borders, health bars, grade cards

## Installation

### Download

This is sketchy, unsafe, don't do it at home, diry as Dirty Diana, omg what the fuck way of installing iptables-analyzer:

```bash
LATEST_VERSION=$(curl -s https://github.com/c0m4r/iptables-analyzer/releases | grep "releases/tag" | grep -o "<a href.*</a>" | head -n 1 | cut -f2 -d\> | cut -f1 -d\<)
if [[ ! "$(echo ${LATEST_VERSION} | sed 's/\.//g;')" =~ ^[0-9]+$ ]]; then echo "wrong version :(" ; fi
case "$(uname -m)" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  riscv64) ARCH="riscv64" ;;
esac
if [[ "$ARCH" && "$LATEST_VERSION" ]]; then wget -nv -O iptables-analyzer https://github.com/c0m4r/iptables-analyzer/releases/download/${LATEST_VERSION}/iptables-analyzer-${LATEST_VERSION}-${ARCH} ; else echo "<sad pepe the frog meme>" ; fi
```

### From source
```bash
git clone https://github.com/c0m4r/iptables-analyzer
cd iptables-analyzer
make build        # or: go build -ldflags="-s -w" -o iptables-analyzer .
```

The binary is self-contained with no runtime dependencies.

### Cross build

```bash
./addons/build.sh
```

## Usage

### Live system analysis
```bash
sudo ./iptables-analyzer
```

### File-based analysis
Save your firewall rules first:
```bash
sudo iptables-save > /tmp/rules.v4
sudo ip6tables-save > /tmp/rules.v6
./iptables-analyzer --file /tmp/rules.v4 --file6 /tmp/rules.v6
```

File mode does not inspect services on the machine running the analyzer. To
cross-reference saved rules with listening sockets from the same host, capture
and provide `ss` output explicitly (`ss -tlnp`/`ss -ulnp` output and the
combined `ss -tulnp` format are both accepted):

```bash
sudo ss -tulnp > /tmp/services.txt
./iptables-analyzer --file /tmp/rules.v4 --file6 /tmp/rules.v6 --services-file /tmp/services.txt
```

Without `--services-file`, the report marks service exposure and the overall
grade as `INCOMPLETE`. A missing or malformed explicitly requested services
file is a fatal input error. A valid header-only `ss` capture represents an
assessed host with no listeners.

### Other modes
```bash
# Security score only
./iptables-analyzer -f /tmp/rules.v4 --score-only

# JSON output for integration
./iptables-analyzer --file /tmp/rules.v4 --json

# Verbose: show all rules including empty chains
./iptables-analyzer --file /tmp/rules.v4 --verbose

# IPv4-only (skip IPv6 check)
./iptables-analyzer -4 --file /tmp/rules.v4

# IPv6-only
./iptables-analyzer -6 --file6 /tmp/rules.v6

# No colors (for logs/piping)
./iptables-analyzer --no-color

# Recommended baseline only (iptables-restore format); the value needs "="
./iptables-analyzer --baseline            # IPv4 and IPv6 with notes
sudo ./iptables-analyzer --baseline=4 > baseline.v4
sudo ./iptables-analyzer --baseline=6 > baseline.v6
```

### Recommended baseline

Every report ends with a recommended baseline for IPv4 **and** IPv6, whichever
stack the host uses: hosts usually get global IPv6 addresses automatically, and
IPv4 rules do not protect them. The baseline:

- denies inbound and forwarded traffic by default, allows outbound traffic
- accepts loopback, `ESTABLISHED,RELATED`, rate-limited ping, and SSH with a per-source `hashlimit`
- keeps IPv6 working: neighbor discovery and router advertisements (hop limit 255), MLD queries, and DHCPv6 replies
- drops `INVALID` packets and spoofed loopback sources
- lists the other detected listeners as commented rules, and on Docker hosts adds commented `DOCKER-USER` rules for every published port

It only replaces `INPUT` (and `DOCKER-USER` on Docker hosts) when applied with
`--noflush`, so Docker's chains survive. Apply it with an automatic rollback:

```bash
printf '#!/bin/sh\nexec iptables-restore --noflush /root/baseline.v4\n' > /root/apply.v4 && chmod +x /root/apply.v4
iptables-apply -t 60 -c /root/apply.v4      # confirm within 60 s or the old rules are restored
```

Without rule files and without root, `--baseline` prints the generic version.

### Full help
```bash
./iptables-analyzer --help
```

## Understanding the Output

### Security Score
Shows a 0-100 score with letter grade (A-F) and breakdown of deductions when
all categories were assessed. The numeric subtotal remains visible with an
`INCOMPLETE` grade and an `unassessed` list when service evidence or a firewall
translation could not be evaluated:

- **Policy**: -15 INPUT ACCEPT, -10 FORWARD ACCEPT (maximum -25); OUTPUT ACCEPT is advisory
- **Exposure**: -5 per well-known TCP/UDP port, -2 per high TCP/UDP port exposed to the world (maximum -25); a port reachable over both IPv4 and IPv6 is counted once
- **Exposure** also charges Docker-published ports that are open to any source, once per protocol/port together with listeners
- **Shadows/Bypasses**: -12 per critical, -5 per high, -2 per medium Docker finding (bypasses, ineffective rules, direct routing); -5 per high-severity and -2 per other shadowed rule (maximum -25)
- **Hygiene**: -5 no conntrack ESTABLISHED, -5 no final DROP, -2 dead rules
- **IPv6**: -10 when IPv6 is in scope but no IPv6 rules were loaded, -5 when Docker leaves IPv6 forwarding unfiltered

### Findings
Lists security issues grouped by severity:
- **CRITICAL**: explicit INPUT restrictions bypassed by Docker for any source
- **HIGH**: Exposed services on well-known ports, missing policies
- **MEDIUM**: Effectiveness issues, potential hygiene problems
- **LOW**: Best practice suggestions
- **INFO**: Unused rules or minor findings

### Recommendations
Numbered list of prioritized improvements. Commands cite the actual table,
chain, and rule. The analyzer provides descriptive guidance instead of a
replacement command when it cannot prove that the replacement preserves the
original access restrictions and established-session behavior.

## Examples

### Basic secure configuration
```bash
# Set default policies to DROP
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH with rate limiting
sudo iptables -I INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 5 -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow ICMP
sudo iptables -A INPUT -p icmp -j ACCEPT
```

### Docker with restricted access
```bash
# DOCKER-USER sees post-DNAT packets: match the original published port.
# --ctdir ORIGINAL keeps replies to the containers' own outbound connections working.
sudo iptables -I DOCKER-USER 1 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -s 10.0.0.0/8 -j RETURN
sudo iptables -I DOCKER-USER 2 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP
```

These rules do not see packets routed directly to a container address. Docker
28+ drops those in `raw/PREROUTING`; on older releases, or for the `routed` and
`nat-unprotected` gateway modes, also refuse non-DNAT connections into the bridge:

```bash
sudo iptables -I DOCKER-USER -o docker0 ! -i docker0 -m conntrack --ctstate NEW -m conntrack ! --ctstate DNAT -j DROP
```

### Analyze Docker setup
```bash
sudo ./iptables-analyzer
# Lists every published port with its FORWARD and INPUT verdicts and flags
# bypassed INPUT rules, ineffective DOCKER-USER/FORWARD rules and direct routing
```

## Architecture

### Packages

- **cmd/**: CLI flag parsing and orchestration using cobra
- **internal/models/**: Data structures (Rule, Chain, Table, Ruleset, findings)
- **internal/parser/**: Hand-rolled iptables-save format parser with token walker
- **internal/loader/**: Load from files or live system (exec iptables-save/ip6tables-save)
- **internal/analyzer/**: Core analysis logic
  - `evaluation.go`: Order-aware packet-path evaluation with jump, goto, and RETURN traversal
  - `analyzer.go`: Service exposure detection and listening-service cross-reference
  - `shadow.go`: Detect shadowed rules using CIDR containment, port range logic, and match extension awareness
  - `docker.go`: Docker published-port, ineffective-rule, rule-order and direct-routing analysis
  - `docker_topology.go`: bridges, container addresses, raw protection and gateway modes inferred from Docker's own rules
  - `effectiveness.go`: Policy checks, dead rules (with match extension awareness), conntrack optimization
- **internal/services/**: Parse `ss -tlnp`/`-ulnp`/`-tulnp` output, cross-reference with rules
- **internal/baseline/**: Recommended IPv4/IPv6 baseline firewall
- **internal/scorer/**: 100-point security score calculation with breakdown
- **internal/recommender/**: Generate actionable recommendations
- **internal/ui/**: Render output with lipgloss — 256-color palette, rounded borders, health bars, grade cards

### Key Algorithms

**Shadow Detection**: For each rule in a chain, check if any earlier rule's match criteria is a superset:
- Protocol superset (all > specific)
- CIDR containment (larger network covers smaller)
- Port range containment
- Interface wildcard matching
- Conntrack state superset
- Match extension awareness (rate-limiting, ICMP types, recent module parameters)

**Docker Bypass Detection**:

1. Infer Docker's topology from its own rules: bridges (`docker0`, `br-*`, custom names), container addresses, bridge subnets, `raw/PREROUTING` direct-access protection, and gateway modes
2. For each candidate ingress interface, evaluate the original packet through `raw` and `mangle` PREROUTING, then walk `nat/PREROUTING` in order through jumps, `goto`, and `RETURN` (with `addrtype --dst-type LOCAL`), carrying the remaining source ranges
3. Evaluate every port in each reachable DNAT range, retaining original and translated tuples plus connection state (`NEW`) and NAT status (`DNAT`)
4. Evaluate the translated packet through `mangle`, `filter` and `security` FORWARD (`-o` resolves to the container's bridge; `--ctorigdstport`, `--ctorigdst`, `--ctorigsrc` and `--ctdir` are honored), and the untranslated packet through the INPUT hooks
5. Sources accepted by FORWARD but refused by INPUT are a bypass; otherwise an unrestricted FORWARD path is a published-port exposure
6. User DROP/REJECT rules on the FORWARD path that match the pre-DNAT tuple but not the translated one, or that Docker's earlier ACCEPT shadows, are reported as ineffective
7. Packets addressed directly to each container endpoint (and to an unpublished port on `nat-unprotected` bridges) are evaluated without DNAT to find direct-routing exposure

**Cross-Reference Services**: Walk filter/INPUT rules in order, following user-defined jumps, goto, RETURN, and default policies. Source CIDRs are split symbolically so earlier terminal rules and partial allowlists are respected before comparing the result with listening services from `ss`.

## Testing

```bash
make test         # Run unit tests
make check        # Run vet, fmt, test
```

Test fixtures in `testdata/`:
- `basic.iptables-save`: IPv4 baseline (100-point subtotal but `INCOMPLETE` without services; B with the bundled service inventory)
- `docker.iptables-save`: legacy Docker layout with INPUT blocks on two DNAT ports (score: F, detects two bypasses)
- `docker29.iptables-save` / `docker29.ip6tables-save`: real Docker 29.9.3 captures with NAT, routed, nat-unprotected, internal and IPv6 networks; the tests derive variants from them whose verdicts were reproduced on a live host
- `insecure.iptables-save`: Default ACCEPT policies with shadowed rules (score: F)

## Building

```bash
# Development build
go build -o iptables-analyzer .

# Optimized build (stripped, minimal size)
make build        # ~4.5MB stripped binary

# Cross-compile
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o iptables-analyzer-amd64 .
```

## Dependencies

Only runtime dependencies:
- Go 1.26+
- iptables/ip6tables (for live analysis, requires root)
- ss utility (for service cross-referencing, usually in iproute2 package)

## Limitations

- Requires `iptables-save`/`ip6tables-save` format. Native nftables rules, routing, policy routing, and host network configuration are outside the assessment scope
- Exposure analysis covers the `raw`, `mangle`, `filter` and `security` INPUT hooks, and published-port analysis the PREROUTING and FORWARD hooks of those tables plus `nat/PREROUTING`. Routing decisions, `TPROXY`, `REDIRECT` to local ports and policy routing are not modeled
- Direct-routing findings are always `POSSIBLE`: they require an attacker that can route the container subnet via the host (for example on the same L2 segment)
- Saved rulesets do not reveal the host's interfaces. Rules restricted to a named interface are evaluated per interface plus one placeholder for unnamed interfaces, which yields `POSSIBLE` findings; live mode uses the real interface list
- Docker's userland proxy serves IPv6 for IPv4-only networks through a local `docker-proxy` socket; that path is filtered by `ip6tables` INPUT and is only assessed when listening services are available
- Advanced match extensions that are not modeled are preserved and handled conservatively: they cannot prove shadow/dead-rule findings, while possible exposure paths remain visible
- Stateful, probabilistic, and side-effecting matches such as `limit`, `statistic`, and `recent` do not establish definite shadowing
- Saved `ss` wildcard sockets rendered as `*` are assessed for both IPv4 and IPv6 because the saved text does not establish an IPv6-only socket option
- Does not track iptables rule counters/statistics

## Disclaimer

This tool analyzes firewall rules but does not modify them. Always test recommendations in a non-production environment first. Be especially careful with production firewalls - incorrect changes could lock you out of your system.
