# iptables-analyzer

A Go CLI tool for analyzing iptables/ip6tables firewall rules to find security issues, shadowed rules, Docker NAT bypasses, exposed services, and policy violations. Provides security scoring and actionable recommendations.

<img width="822" height="724" alt="image" src="https://github.com/user-attachments/assets/ccbd372d-625c-47e0-b623-d7d77363eda4" />

## Features

- **Rule Analysis**: Parses and displays iptables/ip6tables rules in readable tables
- **Shadow Detection**: Finds rules that are covered by earlier rules and will never match, with match extension awareness (rate-limiting, ICMP type, recent module parameters)
- **Docker NAT Bypass Detection**: Detects the critical issue where INPUT chain blocks are ineffective because Docker DNAT rules in the nat table redirect traffic through FORWARD, completely bypassing INPUT
- **Dead Rule Detection**: Identifies rules that come after a catch-all DROP and are unreachable, correctly handling conditional match extensions (e.g. `recent --update` is not a catch-all)
- **Service Cross-Reference**: Matches firewall rules against actual listening services (`ss` output) to find exposed ports, following user-defined chain jumps (e.g. SSHBRUTE, ICMPFLOOD chains)
- **Security Scoring**: 100-point security score (A-F grades) with breakdown by category:
  - Policy (default ACCEPT policies)
  - Exposure (listening services open to the network)
  - Shadows/Docker bypasses
  - Hygiene (best practices like conntrack, rate limiting)
  - IPv6 coverage
- **Recommendations**: Specific, actionable security improvement suggestions with iptables commands
- **Dual Stack**: Full support for both IPv4 (iptables) and IPv6 (ip6tables)
- **Flexible Input**: Analyze live system (requires root) or saved iptables-save output files
- **Multiple Output Formats**: Colored CLI, JSON, score-only
- **Rich TUI**: Polished terminal UI built with lipgloss — 256-color palette, rounded borders, health bars, grade cards

## Installation

### Download

This is sketchy, unsafe, don't do it at home, diry as Dirty Diana, omg what the fuck way of installing iptables-analyzer:

```bash
LATEST_VERSION=$(curl -s https://github.com/c0m4r/iptables-analyzer/releases | grep "releases/tag" | grep -o "<a href.*</a>" | head -n 1 | cut -f2 -d\> | cut -f1 -d\<)
if [[ ! "$(echo ${LATEST_VERSION} | sed 's/\.//g;')" =~ ^[0-9]+$ ]]; then echo "wrong version :(" ; fi
if [[ "$(uname -m)" == "x86_64" ]]; then ARCH="amd64" ; fi
if [[ "$(uname -m | grep risc)" ]]; then ARCH="riscv64" ; fi
if [[ "$(uname -m | grep arm)" ]]; then ARCH="arm64" ; fi
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

### Other modes
```bash
# Security score only
./iptables-analyzer --ipv4-file /tmp/rules.v4 --score-only

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
```

### Full help
```bash
./iptables-analyzer --help
```

## Understanding the Output

### Security Score
Shows a 0-100 score with letter grade (A-F) and breakdown of deductions:
- **Policy**: -15 INPUT ACCEPT, -10 FORWARD ACCEPT, -5 OUTPUT ACCEPT
- **Exposure**: -5 per well-known port, -2 per high port exposed to world
- **Shadows/Bypasses**: -10 per Docker bypass, -5 per shadowed rule
- **Hygiene**: -5 no conntrack ESTABLISHED, -5 no final DROP, -2 dead rules
- **IPv6**: -10 no rules, -5 ACCEPT policy

### Findings
Lists security issues grouped by severity:
- **CRITICAL**: Docker bypasses, input blocks that are ineffective
- **HIGH**: Exposed services on well-known ports, missing policies
- **MEDIUM**: Effectiveness issues, potential hygiene problems
- **LOW**: Best practice suggestions
- **INFO**: Unused rules or minor findings

### Recommendations
Numbered list of prioritized improvements with specific iptables commands.

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
# Add to DOCKER-USER chain (processed before Docker's own rules)
sudo iptables -I DOCKER-USER -i eth0 -p tcp --dport 8080 -j DROP
sudo iptables -I DOCKER-USER -i eth0 -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT
```

### Analyze Docker setup
```bash
sudo ./iptables-analyzer --live --check-services
# Will flag any DNAT rules with bypassed INPUT blocks
```

## Architecture

### Packages

- **cmd/**: CLI flag parsing and orchestration using cobra
- **internal/models/**: Data structures (Rule, Chain, Table, Ruleset, findings)
- **internal/parser/**: Hand-rolled iptables-save format parser with token walker
- **internal/loader/**: Load from files or live system (exec iptables-save/ip6tables-save)
- **internal/analyzer/**: Core analysis logic
  - `analyzer.go`: Service exposure detection with user-defined chain jump traversal
  - `shadow.go`: Detect shadowed rules using CIDR containment, port range logic, and match extension awareness
  - `docker.go`: Docker NAT bypass detection by cross-referencing nat and filter tables
  - `effectiveness.go`: Policy checks, dead rules (with match extension awareness), conntrack optimization
- **internal/services/**: Parse `ss -tlnp` output, cross-reference with rules
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
1. Collect all DNAT rules from nat/PREROUTING and nat/DOCKER
2. Collect all DROP/REJECT rules from filter/INPUT
3. For each DNAT port, check if there's a corresponding INPUT block
4. Flag: Input block is ineffective because traffic goes PREROUTING (DNAT) → FORWARD, bypassing INPUT entirely
5. Also flag DNAT ports with no FORWARD restriction

**Cross-Reference Services**: Walk filter/INPUT chain rules in order to determine if a port is ACCEPT/DROP/DROP, following user-defined chain jumps (e.g. SSHBRUTE → ACCEPT means port is exposed), then compare with listening services from `ss`.

## Testing

```bash
make test         # Run unit tests
make check        # Run vet, fmt, test
```

Test fixtures in `testdata/`:
- `basic.iptables-save`: Secure baseline (score: B)
- `docker.iptables-save`: Docker with INPUT blocks on DNAT ports (score: F, detects bypasses)
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
- iptables/ip6tables (for --live mode)
- ss utility (for --check-services mode, usually in iproute2 package)

## Limitations

- Requires iptables-save format (supports most iptables rule syntax)
- Some advanced match extensions may not parse (falls back to storing in Matches)
- IPv6 address parsing follows IPv4 logic; may not handle all IPv6 notation
- Does not track iptables rule counters/statistics

## Disclaimer

This tool analyzes firewall rules but does not modify them. Always test recommendations in a non-production environment first. Be especially careful with production firewalls - incorrect changes could lock you out of your system.
