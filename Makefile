.PHONY: build build-dev check check-deps test test-cover test-race test-sandbox fuzz vet fmt fmt-check clean help update-deps update-deps-patch rebuild test-coverage pre-commit

BINARY_NAME=iptables-analyzer
GO=go
LDFLAGS=-ldflags="-s -w"
# Static binaries: without cgo the Landlock sandbox can confine every thread
# on kernels older than Landlock ABI 8 (Linux 7.0).
export CGO_ENABLED ?= 0
# Minimum age in days of adopted module versions; empty uses addons/deps.conf.
DEPS_COOLDOWN ?=
COOLDOWN_FLAG=$(if $(DEPS_COOLDOWN),--cooldown $(DEPS_COOLDOWN))
FUZZTIME ?= 30s

help:
	@echo "Available targets:"
	@echo "  build          - Build optimized binary (stripped, minimal)"
	@echo "  build-dev      - Build development binary (unstripped)"
	@echo "  check          - Run vet, fmt check, and tests"
	@echo "  check-deps     - Verify modules, go.mod tidiness and the dependency cooldown"
	@echo "  test           - Run unit tests"
	@echo "  test-race      - Run unit tests with the race detector (needs cgo)"
	@echo "  test-sandbox   - Run the Landlock sandbox enforcement tests"
	@echo "  fuzz           - Fuzz the parsers and the analysis pipeline (FUZZTIME=30s)"
	@echo "  vet            - Run go vet"
	@echo "  fmt            - Format code"
	@echo "  fmt-check      - Check code formatting without modifying"
	@echo "  clean          - Remove built binary"
	@echo "  update-deps    - Update dependencies to the newest versions past the cooldown"
	@echo "  update-deps-patch - Same, patch versions only (DEPS_COOLDOWN=days overrides)"
	@echo "  help           - Show this help message"

build: vet test
	@echo "Building optimized binary..."
	$(GO) build -mod=readonly $(LDFLAGS) -trimpath -buildvcs=false -o $(BINARY_NAME) .
	@ls -lh $(BINARY_NAME)

build-dev:
	@echo "Building development binary..."
	$(GO) build -mod=readonly -o $(BINARY_NAME) .
	@ls -lh $(BINARY_NAME)

check: fmt-check vet test
	@echo "✓ All checks passed"

test:
	@echo "Running tests..."
	$(GO) test -mod=readonly -v ./...

test-cover:
	@echo "Running tests with coverage..."
	$(GO) test -mod=readonly -v -cover ./...

test-race:
	@echo "Running tests with race detector..."
	CGO_ENABLED=1 $(GO) test -mod=readonly -v -race ./...

test-sandbox:
	@echo "Running sandbox enforcement tests (skipped without Landlock)..."
	$(GO) test -mod=readonly -count=1 -v -run 'Sandbox|Enforce' ./internal/sandbox ./cmd

fuzz:
	$(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME) ./internal/parser
	$(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzParseSSData$$' -fuzztime $(FUZZTIME) ./internal/services
	$(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzAnalysis$$' -fuzztime $(FUZZTIME) ./cmd
	$(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzShellQuote$$' -fuzztime $(FUZZTIME) ./internal/textsafe
	$(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzEscape$$' -fuzztime $(FUZZTIME) ./internal/textsafe

check-deps:
	$(GO) mod verify
	$(GO) mod tidy -diff
	./addons/check-deps-cooldown.sh $(COOLDOWN_FLAG)

vet:
	@echo "Running go vet..."
	$(GO) vet -mod=readonly ./...

fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

fmt-check:
	@echo "Checking code formatting..."
	@if [ -n "$$(gofmt -l $$(find . -name '*.go' -type f))" ]; then \
		gofmt -l $$(find . -name '*.go' -type f); \
		echo "❌ Code formatting issues found. Run 'make fmt' to fix."; \
		exit 1; \
	else \
		echo "✓ Code formatting OK"; \
	fi

clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME)
	$(GO) clean

update-deps:
	./addons/update-deps.sh $(COOLDOWN_FLAG)

update-deps-patch:
	./addons/update-deps.sh --patch $(COOLDOWN_FLAG)

# Rebuild after dependency update
.PHONY: rebuild
rebuild: clean update-deps check build
	@echo "✓ Complete rebuild with updated deps finished"

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test -mod=readonly -cover -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

# Run formatter, vet, and tests before commit
.PHONY: pre-commit
pre-commit: fmt vet test
	@echo "✓ Pre-commit checks passed"
