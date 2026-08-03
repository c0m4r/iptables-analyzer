.PHONY: build build-dev check test test-cover test-race vet fmt fmt-check clean help update-deps update-deps-patch rebuild test-coverage pre-commit

BINARY_NAME=iptables-analyzer
GO=go
LDFLAGS=-ldflags="-s -w"

help:
	@echo "Available targets:"
	@echo "  build          - Build optimized binary (stripped, minimal)"
	@echo "  build-dev      - Build development binary (unstripped)"
	@echo "  check          - Run vet, fmt check, and tests"
	@echo "  test           - Run unit tests"
	@echo "  vet            - Run go vet"
	@echo "  fmt            - Format code"
	@echo "  fmt-check      - Check code formatting without modifying"
	@echo "  clean          - Remove built binary"
	@echo "  update-deps    - Update all dependencies to latest"
	@echo "  update-deps-patch - Update to latest patch versions only"
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
	$(GO) test -mod=readonly -v -race ./...

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
	@echo "Updating all dependencies to latest..."
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "✓ Dependencies updated"
	@echo "Run 'make check' to verify"

update-deps-patch:
	@echo "Updating to latest patch versions..."
	$(GO) get -u=patch ./...
	$(GO) mod tidy
	@echo "✓ Patch dependencies updated"
	@echo "Run 'make check' to verify"

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
