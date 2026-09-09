#!/bin/bash
# Save current iptables/ip6tables rules to files for offline analysis

set -euo pipefail

OUTPUT_DIR="${1:-.}"

mkdir -p "$OUTPUT_DIR"

TMP_V4=""
TMP_V6=""
cleanup() {
	if [[ -n "$TMP_V4" ]]; then rm -f "$TMP_V4"; fi
	if [[ -n "$TMP_V6" ]]; then rm -f "$TMP_V6"; fi
}
trap cleanup EXIT INT TERM
TMP_V4=$(mktemp "$OUTPUT_DIR/.rules.v4.XXXXXX")
TMP_V6=$(mktemp "$OUTPUT_DIR/.rules.v6.XXXXXX")

echo "Saving iptables rules to $OUTPUT_DIR..."

sudo iptables-save | tee "$TMP_V4" >/dev/null

sudo ip6tables-save | tee "$TMP_V6" >/dev/null

mv "$TMP_V4" "$OUTPUT_DIR/rules.v4"
TMP_V4=""
echo "✓ Saved: $OUTPUT_DIR/rules.v4"

mv "$TMP_V6" "$OUTPUT_DIR/rules.v6"
TMP_V6=""
echo "✓ Saved: $OUTPUT_DIR/rules.v6"

echo ""
echo "To analyze:"
echo "  iptables-analyzer --file $OUTPUT_DIR/rules.v4 --file6 $OUTPUT_DIR/rules.v6"
echo ""
echo "To share rules for review:"
echo "  # Share the files, but note they may contain sensitive network info"
