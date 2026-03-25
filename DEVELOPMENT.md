# Development Guide

## Quick Start

```bash
# Build and check
make build        # Optimized build (3MB)
make check        # Run vet, fmt check, tests
make test         # Run tests with race detector

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
├── README.md                  # User documentation
├── DEVELOPMENT.md            # This file
├── Makefile                  # Build and test targets
├── addons/
│   ├── build.sh                    # Cross-platform build script
│   ├── update-deps.sh              # Update Go dependencies
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
│   │   └── loader.go        # File and live system input
│   ├── analyzer/
│   │   ├── shadow.go        # Shadowed rule detection (with match extension awareness)
│   │   ├── docker.go        # Docker NAT bypass detection
│   │   ├── effectiveness.go # Policy and hygiene checks (with match extension awareness)
│   │   ├── analyzer.go      # Main analysis orchestration (with chain jump traversal)
│   │   └── analyzer_test.go # Analyzer unit tests
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
    ├── basic.iptables-save      # Secure config (score: B)
    ├── docker.iptables-save     # Docker with bypasses (score: F)
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
make test          # With race detector
go test ./...      # Basic
go test -v ./...   # Verbose
```

### Test coverage
```bash
make test-coverage # Generates coverage.html
```

### Add new tests
1. Create `*_test.go` file in the package
2. Write `TestXxx(t *testing.T)` functions
3. Use existing fixtures in `testdata/` when possible

### Test fixtures
- `basic.iptables-save`: Clean, secure config. Expected: score B, no critical findings
- `docker.iptables-save`: Docker setup with DNAT on ports blocked in INPUT. Expected: score F, 4+ Docker bypass findings
- `insecure.iptables-save`: Default ACCEPT policies with shadowed rules. Expected: score F, multiple shadow findings

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

```bash
# Update all dependencies
./addons/update-deps.sh

# Manual update and verification
go get -u ./...
go mod tidy
make check
```

## Building

### Development
```bash
make build-dev     # Unstripped, easier debugging
```

### Production
```bash
make build         # Stripped, optimized size (~3MB)
```

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

- **README.md**: User guide and quick start
- **DEVELOPMENT.md**: This file
- **Code comments**: Explain non-obvious algorithms
- **Function docstrings**: Public API documentation

