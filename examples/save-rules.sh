#!/bin/bash
# Save current iptables/ip6tables rules to files for offline analysis

OUTPUT_DIR="${1:-.}"

if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir -p "$OUTPUT_DIR"
fi

echo "Saving iptables rules to $OUTPUT_DIR..."

sudo iptables-save > "$OUTPUT_DIR/rules.v4"
echo "✓ Saved: $OUTPUT_DIR/rules.v4"

sudo ip6tables-save > "$OUTPUT_DIR/rules.v6"
echo "✓ Saved: $OUTPUT_DIR/rules.v6"

echo ""
echo "To analyze:"
echo "  iptables-analyzer --ipv4-file $OUTPUT_DIR/rules.v4 --ipv6-file $OUTPUT_DIR/rules.v6"
echo ""
echo "To share rules for review:"
echo "  # Share the files, but note they may contain sensitive network info"
