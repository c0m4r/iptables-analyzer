# Development Guide

## Quick Start

```bash
# Build and check
make build        # Optimized static build (CGO_ENABLED=0)
make check        # Run vet, fmt check, tests
make test         # Run all unit tests
make test-race    # Run all tests with race detector (needs cgo)
make test-sandbox # Run the Landlock enforcement tests (skipped without Landlock)
make test-kernel  # Compare the analysis with the Linux kernel in network namespaces
make fuzz         # Fuzz the parsers, the whole pipeline, the queries and the HTML report (FUZZTIME=30s)
make update-golden # Rewrite the golden files of the report formats
make check-deps   # go mod verify, go mod tidy -diff, dependency cooldown

# View help
./iptables-analyzer --help

# Test with fixtures
./iptables-analyzer testdata/docker.iptables-save
./iptables-analyzer testdata/ufw.iptables-save testdata/ufw-services.txt --html /tmp/report.html
./iptables-analyzer testdata/router.snapshot.json --trace 'tcp 203.0.113.5 -> :8443 in eth0'
./iptables-analyzer --diff testdata/basic.iptables-save testdata/insecure.iptables-save
```

## Project Structure

```
iptables-analyzer/
├── main.go                    # Entry point
├── go.mod, go.sum            # Module dependencies
├── README.md                  # User documentation (short)
├── DEVELOPMENT.md            # This file
├── Makefile                  # Build and test targets
├── docs/                     # Usage, analysis method, security, supply chain
├── .github/
│   ├── dependabot.yml              # Dependency updates with a cooldown
│   └── workflows/                  # CI and release (SHA-pinned actions)
├── addons/
│   ├── build.sh                    # Cross-platform build script
│   ├── update-deps.sh              # Update Go dependencies (with the cooldown)
│   ├── check-deps-cooldown.sh      # Fail on module versions younger than the cooldown
│   ├── cooldown.sh                 # Helpers of the two scripts above
│   ├── deps.conf                   # Cooldown days and reviewed exceptions
│   ├── bash-completion/
│   │   └── iptables-analyzer       # Bash completion script
│   └── man1/
│       └── iptables-analyzer.1     # Manpage
├── cmd/
│   ├── root.go              # CLI setup with cobra, order of the steps, exit status
│   ├── golden_test.go       # The reports of the fixtures against testdata/golden
│   ├── query_test.go        # --trace, --expect, --diff, --snapshot, --ipset-file, iptables -S input
│   └── testdata/golden/     # Expected text, JSON and HTML reports, traces and comparisons
├── internal/
│   ├── models/
│   │   └── models.go        # All shared data structures
│   ├── parser/
│   │   ├── parser.go        # Parser for iptables-save output and for "iptables -S" listings
│   │   ├── parser_test.go   # Parser unit tests
│   │   └── listing_test.go  # "iptables -S" listings
│   ├── loader/
│   │   └── loader.go        # File and live system input (read, then parse); the facts about a live host
│   ├── hostinfo/
│   │   ├── hostinfo.go      # Parsers for "ipset save", "nft list chains" and "ip route"; kernel settings
│   │   └── snapshot.go      # The snapshot file: everything that a live analysis reads
│   ├── safeio/
│   │   └── safeio.go        # Bounded reads, trusted tool execution
│   ├── sandbox/
│   │   └── sandbox_linux.go # Privilege drop, no_new_privs, Landlock
│   ├── textsafe/
│   │   └── textsafe.go      # Control-character escaping, shell quoting
│   ├── analyzer/
│   │   ├── evaluation.go    # Ordered jump/goto/RETURN evaluator and multi-table packet paths
│   │   ├── ingress.go       # One new connection: PREROUTING with its translation, then INPUT or FORWARD
│   │   ├── trace.go         # One concrete packet through the same chains (--trace)
│   │   ├── hostfacts.go     # ipset contents, routes and kernel settings in the analysis
│   │   ├── addrset.go       # Source-address sets as sorted ranges
│   │   ├── shadow.go        # Shadowed rule detection (with match extension awareness)
│   │   ├── docker.go        # Docker published-port, ineffective-rule and direct-routing analysis
│   │   ├── docker_topology.go # Bridges, container addresses and gateway modes inferred from rules
│   │   ├── docker_test.go   # Regression tests on real Docker 29 captures
│   │   ├── effectiveness.go # Default behavior, open ports, unreachable rules, IPv4/IPv6 comparison
│   │   ├── analyzer.go      # Main analysis orchestration (with chain jump traversal)
│   │   ├── analyzer_test.go # Analyzer unit tests
│   │   ├── regress_test.go  # The inputs of docs/audit-0.7.1.md
│   │   ├── ingress_test.go  # REDIRECT, DNAT to the host, node ports, port forwards
│   │   ├── hostfacts_test.go # ipsets, forwarding, route_localnet, nftables tables, reverse path
│   │   ├── consistency_test.go # The trace against the analysis of all sources
│   │   ├── kernel_linux_test.go # Harness: rules in a network namespace, real packets
│   │   ├── kernel_scenarios_linux_test.go # The scenarios that are compared with the kernel
│   │   ├── addrset_test.go  # Set operations against membership tables
│   │   └── perf_test.go     # Blocklist timing test and benchmarks
│   ├── baseline/
│   │   └── baseline.go      # Recommended IPv4/IPv6 baseline firewall
│   ├── services/
│   │   └── services.go      # ss output parsing
│   ├── report/
│   │   ├── model.go         # The report: the documented JSON form (docs/json.md)
│   │   ├── build.go         # From the facts of the analysis to findings
│   │   ├── fixes.go         # What to do about a finding, with quoted commands
│   │   ├── owners.go        # The program that writes the rules (ufw, firewalld, csf, shorewall), and its commands
│   │   ├── score.go         # Points, category limits, grade limits, gain of a fix
│   │   ├── ports.go         # --public, port risk and points
│   │   ├── tables.go        # Open ports, translated ports, sockets, rules
│   │   └── diff.go          # The trace report, and the comparison of two reports (--diff)
│   └── ui/
│       ├── text.go          # The terminal report (lipgloss)
│       ├── query.go         # The trace and the comparison as text
│       ├── html.go          # The HTML report: view model, content security policy
│       ├── assets/          # report.html (template), report.css, report.js
│       ├── common.go        # What both renderers say in the same words
│       ├── markup_test.go   # Strict reader of the page, for the injection tests
│       └── colors.go        # Color palette and style definitions
└── testdata/
    ├── basic.iptables-save      # IPv4 baseline (B with bundled service evidence)
    ├── docker.iptables-save     # Legacy Docker layout with bypasses (score: F)
    ├── docker29.iptables-save   # Real Docker 29.9.3 capture (nat, routed, nat-unprotected, internal)
    ├── docker29.ip6tables-save  # Real Docker 29.9.3 IPv6 capture
    ├── insecure.iptables-save   # ACCEPT policies (score: F)
    ├── ufw.iptables-save        # A host managed by ufw (no false findings expected)
    ├── ufw-services.txt         # Its listeners
    ├── k8s.iptables-save        # A Kubernetes node: kube-proxy, flannel, node ports, a load balancer address
    ├── fail2ban.iptables-save   # Jails with banned addresses in front of the services
    ├── libvirt.iptables-save    # The default NAT network of libvirt
    ├── firewalld.iptables-save  # firewalld with its iptables backend: zones, a rich rule, a forward port
    ├── router.iptables-save     # A gateway: masquerading, port forwards, a transparent proxy
    ├── router.snapshot.json     # The same gateway as a snapshot, with interfaces, routes and settings
    └── *-services.txt           # The listeners of each of these hosts
```

## Dependencies

External dependencies:
- `github.com/spf13/cobra` - CLI framework
- `github.com/charmbracelet/lipgloss` - Terminal UI styling, tables, borders, layout
- `github.com/muesli/termenv` - Terminal capability detection

Check `go.mod` for exact versions.

## Code Style

Follow Go conventions:
- Run `make fmt` to auto-format code
- Run `make vet` to check for common mistakes
- Use meaningful variable names
- Keep functions small and focused
- Add comments for non-obvious logic

## Testing

### Run all tests
```bash
make test          # Static build, like the release binaries
make test-race     # With race detector
go test -v ./...   # Verbose
```

### Sandbox tests

`internal/sandbox` and `cmd` enforce the real sandbox in child processes (a sandbox
cannot be lifted). Without Landlock in the kernel these tests are skipped; check with
`cat /sys/kernel/security/lsm`. With cgo, they are also skipped on kernels before
Landlock ABI 8, so run them with `CGO_ENABLED=0` (the Makefile default). Tests that
call `newRootCommand` in-process must use `testDependencies`, which replaces the
sandbox with one that does not confine the test binary.

### Fuzzing

```bash
make fuzz FUZZTIME=2m
```

`FuzzAnalysis` runs the whole command on random rules and `ss` output and fails if the
`--no-color` report contains a control character. `FuzzQueries` does the same for
`--trace` and `--diff`, with random rules (or a random snapshot) and a random packet.
`FuzzHostFacts` and `FuzzSnapshot` run the parsers of `internal/hostinfo`.
`FuzzHTMLReport` renders the HTML report for random input and fails when the page holds
markup that the template does not write. Failing inputs are written to `testdata/fuzz/`
of the package; commit them as regression tests after the fix.

### Golden files

`cmd/testdata/golden/` holds the report of each fixture as text (default and
`--verbose --rules`), JSON and HTML. `TestGoldenReports` compares them with what the
command writes. `TestGoldenQueries` does the same for some traces and comparisons.
A change of the analysis or of a renderer shows as a diff of what the user reads:

```bash
make update-golden
git diff cmd/testdata/golden/     # read it: this is the change that users see
```

The HTML files hold the markup without the style sheet and the script, so an edit of
`report.css` does not change them.

### The HTML report

Text from the rules must reach the page only as text. Three tests keep it so:

- `TestHTMLStructureDoesNotDependOnTheText` replaces every string of a report by a
  string full of markup. The tags, the attributes and their values must be the same
  as for a harmless string.
- `checkMarkup` (in `markup_test.go`) reads a page strictly: only the elements and
  attributes of the template, links only to anchors of the page, one style and one
  script element with the embedded content.
- `FuzzHTMLReport` runs `checkMarkup` on pages for random input.

When you change `internal/ui/assets/report.html`:

- Do not write a `style` attribute or an event handler: the content security policy
  of the page refuses both. Use a class, and attach handlers in `report.js`.
- Do not build a class name, an `id` or a link from the input. Take class names from
  a fixed list in `html.go`, and anchors from counters.
- Add a new element or attribute to the lists in `markup_test.go`.

To look at the page, open it in a browser, or take a picture without one:

```bash
./iptables-analyzer testdata/docker29.iptables-save --html /tmp/report.html
chromium --headless --screenshot=/tmp/report.png --window-size=1280,2400 file:///tmp/report.html
```

### Timing

`TestLargeBlocklistsAreAnalyzedQuickly` analyzes 20,000 single-address rules and fails
when that takes more than ten seconds. `go test -short` skips it. For numbers:

```bash
go test -run '^$' -bench Blocklist ./internal/analyzer
```

### Tests with the real iptables

`internal/baseline` loads the generated baseline with `iptables-restore` in a new network
namespace (`unshare -rn`). The test is skipped when the tools or unprivileged user
namespaces are not available.

### Comparison with the kernel

```bash
make test-kernel
```

`internal/analyzer/kernel_linux_test.go` checks the analysis against what Linux does.
For each scenario, the test binary starts itself again in a new user and network
namespace (the "host"), and once more for each network around it (the "peers").
It connects them with veth pairs, loads the rules of the scenario with the real
`iptables-restore`, and sets the kernel settings of the scenario. Each process listens
on the ports of the scenario, and each answer names the process that gave it.
The peers then send real TCP and UDP packets. For each packet the test knows what
happened: which listener answered, a refusal, or no answer.

`Trace` must give the same result for the same packet. Where the rules share the packets
among several destinations (the pods of a service), the kernel selects one of them, and
each destination that the trace lists is correct. A probe for which the trace is not
certain is not compared; each scenario states how many of its probes must be certain.

- The test needs no root. It needs `ip`, `iptables-restore` and unprivileged user
  namespaces, and it is skipped without them. Ubuntu 24.04 restricts such namespaces:
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` lifts the restriction.
  CI does this in a step of its own.
- A scenario whose rules do not load fails the test: the fixtures must be rules that
  the real tool accepts.
- `go test -short` skips the scenarios.

To add a scenario, write a `kernelScenario` in `kernel_scenarios_linux_test.go`:
the rules, the networks with their peers, and the probes. Take the fixture of a program
(`testdata/*.iptables-save`) when you can, so that the fixture itself is tested.
A probe from a forged source address is possible (`Forged`), for the reverse-path filter.

`consistency_test.go` ties the analysis of all sources to the trace: for some thousand
packets over the fixtures, the analysis and the trace must agree on what is accepted.
Together the two tests mean that a result of the analysis is a statement about the kernel.

### Test coverage
```bash
make test-coverage # Generates coverage.html
```

### Add new tests
1. Create `*_test.go` file in the package
2. Write `TestXxx(t *testing.T)` functions
3. Use existing fixtures in `testdata/` when possible

### Test fixtures
- `basic.iptables-save`: IPv4 baseline. Expected with `testdata/services.txt`: grade A, SSH open to all sources as the one HIGH finding
- `docker.iptables-save`: Docker setup with two DNAT ports blocked in INPUT. Expected: score F, two Docker bypass findings
- `insecure.iptables-save`: Default ACCEPT policies and rules behind a catch-all ACCEPT. Expected: grade F, one finding for the default accept and one for the unreachable rules
- `ufw.iptables-save` with `ufw-services.txt`: the chains that ufw creates, with `ufw limit 22/tcp`. Expected: no effectiveness finding above INFO, SSH as rate limited (MEDIUM), the DHCP client as LOW, fixes as `ufw` commands
- `docker29.iptables-save` / `docker29.ip6tables-save`: unmodified captures from Docker 29.9.3 (iptables 1.8.11, nf_tables). `internal/analyzer/docker_test.go` derives variants from them (an INPUT block, `DOCKER-USER --dport`, raw/mangle drops, removed raw protection, ...). Each variant was reproduced on a live host with a probe container, and the test asserts the observed verdict
- `k8s`, `fail2ban`, `libvirt`, `firewalld`, `router`: written after the rules that these programs make, not captured from a host. Each loads with the real `iptables-restore`, and each is a scenario of the kernel comparison. Expected: `k8s` reports the node ports and the load-balancer address as translated ports with all pods, with a fix for Kubernetes; `firewalld` gives fixes as `firewall-cmd` commands; `router` reports the port forwards and shows the transparent proxy as `80 → 3128`
- `router.snapshot.json`: the router as a snapshot. With its routes and `rp_filter`, the rules for the LAN interface open their ports to the LAN only

### Verifying Docker behavior on a host

The Docker tests encode kernel behavior; when adding a scenario, reproduce it first:

```bash
docker run -d --name web -p 8080:80 busybox httpd -f -p 80
docker network create probe
sudo iptables -I INPUT -p tcp --dport 8080 -j DROP           # the rule under test
docker run --rm --network probe busybox wget -T 3 -qO- http://<host-ip>:8080/   # 404 = reachable, timeout = blocked
sudo iptables -D INPUT -p tcp --dport 8080 -j DROP
```

The probe container arrives through a Docker bridge rather than an external
interface, so only use it for rules that do not match on the ingress interface.

## Adding Features

### New Analysis Check

1. **Add to analyzer package**:
   - Create function in appropriate file (e.g., `analyzer/newcheck.go`)
   - The function states a fact about the rules: it returns a typed finding
     (`models.EffectivenessFinding` or similar) with a stable code
   - Call it from `analyzer.AnalyzeHost()`

2. **Add it to the report** (`internal/report/build.go`):
   - Convert the fact into a `report.Finding`: title, detail, the rules as evidence,
     the category of the score and the points
   - Add the fix in `fixes.go`. Write a command only when it keeps the restrictions
     of the rule that it changes, and quote every value from the rules with
     `textsafe.ShellQuote`
   - The text, JSON and HTML reports show every finding of the report: the renderers
     need no change

3. **Document it**:
   - Add the code to `docs/json.md` and the deduction to `docs/usage.md`

4. **Test it**:
   - Add test fixture to `testdata/` if needed
   - Add unit tests to `*_test.go`
   - Run `make test`, then `make update-golden` and read the diff

### New CLI Flag

1. **Update `cmd/root.go`**:
   - Add the field to `commandOptions` and register the flag in `newRootCommand`
   - Check it in `checkOptions`, which refuses combinations that make no sense
   - Read every file that the flag names in `collect` or `load`, before the sandbox starts.
     Open an output file there too. Nothing can be opened later

2. **Update help**:
   - Flag automatically appears in `--help`
   - Update README.md, `docs/usage.md`, the manpage and the bash completion

## Debugging

### Print debug info
```go
import "fmt"
fmt.Fprintf(os.Stderr, "Debug: %+v\n", obj)
```

### Detailed output
```bash
./iptables-analyzer rules.v4 --verbose --rules
```

### JSON output for inspection
```bash
./iptables-analyzer rules.v4 --json | jq '.findings[] | {id, code, severity, points, gain}'
DUMP=1 go test ./internal/report -run TestDumpForReview -v   # the reports of the fixtures, finding by finding
```

### Test parsing
```go
// In parser_test.go
const testData = `...`
rs, _ := parser.Parse(testData, models.IPv4)
// Inspect rs.Tables, rs.Rules, etc.
```

## Dependency Updates

New module versions are adopted only after a cooldown (7 days, `addons/deps.conf`).
See [docs/supply-chain.md](docs/supply-chain.md).

```bash
make update-deps                    # newest versions past the cooldown, then verify
make update-deps-patch              # patch versions only
./addons/update-deps.sh --dry-run   # show what would change
make check-deps                     # what CI checks
```

Do not use `go get -u` directly: it ignores the cooldown, and CI rejects the result.

## Building

### Development
```bash
make build-dev     # Unstripped, easier debugging
```

### Production
```bash
make build         # Stripped, static (CGO_ENABLED=0)
```

Release binaries are built by `.github/workflows/release.yml` when a version tag is
pushed; see [docs/supply-chain.md](docs/supply-chain.md#releases).

### Cross-platform
```bash
./addons/build.sh "linux/amd64,linux/arm64,linux/riscv64"
# Outputs to dist/
```

## Troubleshooting

### Build fails
```bash
go mod tidy           # Fix dependency issues
go clean              # Clear cache
make clean && make build
```

### Tests fail
- Check testdata fixtures are valid
- Run with `-v` flag for details
- Check for race conditions: `go test -race ./...`

### Parsing issues
- Add test to `parser_test.go` with failing iptables-save
- Debug by printing tokenized output
- Check flag parsing order matters (position-dependent in rules)

## Documentation

- **README.md**: Short user guide in Simplified Technical English (ASD-STE100)
- **docs/**: Detailed usage, analysis method, security and supply chain
- **DEVELOPMENT.md**: This file
- **Code comments**: Explain non-obvious algorithms
- **Function docstrings**: Public API documentation
