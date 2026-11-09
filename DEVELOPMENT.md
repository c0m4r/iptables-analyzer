# Development Guide

## Quick Start

```bash
# Build and check
make build        # Optimized static build (CGO_ENABLED=0)
make check        # Run vet, fmt check, tests
make test         # Run all unit tests
make test-race    # Run all tests with race detector (needs cgo)
make test-sandbox # Run the Landlock enforcement tests (skipped without Landlock)
make fuzz         # Fuzz the parsers and the whole pipeline (FUZZTIME=30s)
make check-deps   # go mod verify, go mod tidy -diff, dependency cooldown

# View help
./iptables-analyzer --help

# Test with fixtures
./iptables-analyzer -f testdata/docker.iptables-save
./iptables-analyzer -f testdata/insecure.iptables-save
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
│   └── root.go              # CLI setup with cobra
├── internal/
│   ├── models/
│   │   └── models.go        # All shared data structures
│   ├── parser/
│   │   ├── parser.go        # iptables-save format parser
│   │   └── parser_test.go   # Parser unit tests
│   ├── loader/
│   │   └── loader.go        # File and live system input (read, then parse)
│   ├── safeio/
│   │   └── safeio.go        # Bounded reads, trusted tool execution
│   ├── sandbox/
│   │   └── sandbox_linux.go # Privilege drop, no_new_privs, Landlock
│   ├── textsafe/
│   │   └── textsafe.go      # Control-character escaping, shell quoting
│   ├── analyzer/
│   │   ├── evaluation.go    # Ordered jump/goto/RETURN evaluator and multi-table packet paths
│   │   ├── shadow.go        # Shadowed rule detection (with match extension awareness)
│   │   ├── docker.go        # Docker published-port, ineffective-rule and direct-routing analysis
│   │   ├── docker_topology.go # Bridges, container addresses and gateway modes inferred from rules
│   │   ├── docker_test.go   # Regression tests on real Docker 29 captures
│   │   ├── effectiveness.go # Policy and hygiene checks (with match extension awareness)
│   │   ├── analyzer.go      # Main analysis orchestration (with chain jump traversal)
│   │   └── analyzer_test.go # Analyzer unit tests
│   ├── baseline/
│   │   └── baseline.go      # Recommended IPv4/IPv6 baseline firewall
│   ├── services/
│   │   └── services.go      # ss output parsing
│   ├── scorer/
│   │   └── scorer.go        # Security scoring algorithm
│   ├── recommender/
│   │   └── recommender.go   # Recommendation generation
│   └── ui/
│       ├── ui.go            # Main rendering orchestrator (lipgloss layout)
│       ├── tables.go        # Table formatting (lipgloss/table)
│       └── colors.go        # 256-color palette and style definitions
└── testdata/
    ├── basic.iptables-save      # IPv4 baseline (B with bundled service evidence)
    ├── docker.iptables-save     # Legacy Docker layout with bypasses (score: F)
    ├── docker29.iptables-save   # Real Docker 29.9.3 capture (nat, routed, nat-unprotected, internal)
    ├── docker29.ip6tables-save  # Real Docker 29.9.3 IPv6 capture
    └── insecure.iptables-save   # ACCEPT policies (score: F)
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
`--no-color` report contains a control character. Failing inputs are written to
`testdata/fuzz/` of the package; commit them as regression tests after the fix.

### Test coverage
```bash
make test-coverage # Generates coverage.html
```

### Add new tests
1. Create `*_test.go` file in the package
2. Write `TestXxx(t *testing.T)` functions
3. Use existing fixtures in `testdata/` when possible

### Test fixtures
- `basic.iptables-save`: IPv4 baseline. Expected with `--ipv4-only`: 100-point subtotal and `INCOMPLETE` without services; B with `testdata/services.txt`
- `docker.iptables-save`: Docker setup with two DNAT ports blocked in INPUT. Expected: score F, two Docker bypass findings
- `insecure.iptables-save`: Default ACCEPT policies with shadowed rules. Expected: score F, multiple shadow findings
- `docker29.iptables-save` / `docker29.ip6tables-save`: unmodified captures from Docker 29.9.3 (iptables 1.8.11, nf_tables). `internal/analyzer/docker_test.go` derives variants from them (an INPUT block, `DOCKER-USER --dport`, raw/mangle drops, removed raw protection, ...). Each variant was reproduced on a live host with a probe container, and the test asserts the observed verdict

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
   - Function should return `[]Finding` or similar
   - Call it from `analyzer.Analyze()` or add to orchestration

2. **Update UI**:
   - Add rendering function in `ui/ui.go` if needed
   - Use existing color and formatting functions

3. **Add recommendation**:
   - Update `recommender.Generate()` to suggest improvements
   - Provide specific iptables commands

4. **Test it**:
   - Add test fixture to `testdata/` if needed
   - Add unit tests to `*_test.go`
   - Run `make test`

### New CLI Flag

1. **Update `cmd/root.go`**:
   - Add flag variable
   - Register with `rootCmd.Flags().XxxVar()`
   - Use in `runAnalysis()` function

2. **Update help**:
   - Flag automatically appears in `--help`
   - Update README.md examples if user-facing

## Debugging

### Print debug info
```go
import "fmt"
fmt.Fprintf(os.Stderr, "Debug: %+v\n", obj)
```

### Detailed output
```bash
./iptables-analyzer -f rules.v4 --verbose
```

### JSON output for inspection
```bash
./iptables-analyzer -f rules.v4 --json | jq .ShadowedRules
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
