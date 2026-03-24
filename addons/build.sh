#!/bin/bash
# Build script for cross-platform binaries

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="iptables-analyzer"
VERSION="${VERSION:-v1.0}"
LDFLAGS="-s -w"

cd "$PROJECT_ROOT"

# Default to linux/amd64 if no targets specified
TARGETS="${1:-linux/amd64,linux/arm64,linux/riscv64}"

echo "=== iptables-analyzer Build ==="
echo "Version: $VERSION"
echo "Targets: $TARGETS"
echo ""

# Create dist directory
mkdir -p dist

IFS=',' read -ra PLATFORM_PAIRS <<< "$TARGETS"

for PLATFORM in "${PLATFORM_PAIRS[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$PLATFORM"

    OUTPUT_NAME="${BINARY_NAME}-${GOARCH}"

    OUTPUT_PATH="dist/${OUTPUT_NAME}"

    echo "Building $GOOS/$GOARCH → $OUTPUT_PATH"

    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
        -ldflags="$LDFLAGS -X main.Version=$VERSION -s -w" \
        -trimpath \
        -buildvcs=false \
        -o "$OUTPUT_PATH" \
        .

    SIZE=$(ls -lh "$OUTPUT_PATH" | awk '{print $5}')
    echo "  ✓ Built ($SIZE)"
done

echo ""
echo "=== Summary ==="
ls -lh dist/ | tail -n +2 | awk '{printf "  %-40s %5s\n", $9, $5}'
echo ""
echo "Binaries ready in dist/"
