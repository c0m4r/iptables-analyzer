#!/bin/bash
# Update Go dependencies and verify the build

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "=== Go Dependency Updater ==="
echo ""

if [ "$1" = "--patch" ]; then
    echo "Updating to latest patch versions..."
    go get -u=patch ./...
elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [--patch]"
    echo ""
    echo "Updates Go module dependencies."
    echo ""
    echo "Options:"
    echo "  --patch    Update only patch versions (x.y.Z)"
    echo "  --help     Show this help message"
    echo ""
    echo "By default, updates to the latest version of all dependencies."
    exit 0
else
    echo "Updating all dependencies to latest versions..."
    go get -u ./...
fi

echo ""
echo "Running go mod tidy..."
go mod tidy

echo ""
echo "=== Verification ==="
echo ""
echo "Running tests..."
make test

echo ""
echo "Running go vet..."
make vet

echo ""
echo "✓ Dependencies updated and verified"
echo ""
echo "Next steps:"
echo "  1. Review go.mod and go.sum changes"
echo "  2. Test with: make build"
echo "  3. Commit changes if satisfied"
