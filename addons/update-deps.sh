#!/bin/bash
# Update Go dependencies with a supply-chain cooldown and verify the build.
#
# Only versions published at least the cooldown ago are adopted (see
# addons/deps.conf), so a compromised release has time to be found and
# withdrawn before it reaches this project.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"
# shellcheck source=addons/cooldown.sh
. "$SCRIPT_DIR/cooldown.sh"

usage() {
	echo "Usage: $0 [--patch] [--cooldown DAYS] [--dry-run]"
	echo ""
	echo "Updates Go module dependencies to the newest versions that were"
	echo "published at least DAYS days ago."
	echo ""
	echo "Options:"
	echo "  --patch          Update only patch versions (x.y.Z)"
	echo "  --cooldown DAYS  Minimum version age (default: GO_DEPS_COOLDOWN_DAYS,"
	echo "                   else COOLDOWN_DAYS in addons/deps.conf; 0 disables)"
	echo "  --dry-run        Only show what would be updated"
	echo "  --help           Show this help message"
}

mode=all
dry_run=false
cooldown=$(default_cooldown)
while [ $# -gt 0 ]; do
	case "$1" in
	--patch) mode="patch" ;;
	--cooldown) shift; cooldown="${1:-}" ;;
	--cooldown=*) cooldown="${1#*=}" ;;
	--dry-run) dry_run=true ;;
	-h | --help) usage; exit 0 ;;
	*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
	shift
done
validate_cooldown "$cooldown"

# Never switch to another Go toolchain implicitly; a dependency that needs a
# newer Go is skipped and reported instead.
pin_toolchain
modules=$(build_modules)
now=$(date +%s)
cutoff=$((now - cooldown * 86400))

echo "=== Go Dependency Updater ==="
echo "Mode: $mode, cooldown: $cooldown days (published before $(format_date "$cutoff")), toolchain: $GOTOOLCHAIN"
echo ""

# newest_eligible prints the newest release of $1 that is newer than $2,
# old enough, and (with --patch) in the same minor version.
newest_eligible() {
	local path=$1 current=$2 candidate published prefix=""
	local -a versions
	read -r -a versions <<<"$(go list -m -versions -f '{{range .Versions}}{{.}} {{end}}' "$path")"
	if [ "$mode" = patch ]; then
		prefix="$(echo "$current" | cut -d. -f1,2)."
	fi
	for ((i = ${#versions[@]} - 1; i >= 0; i--)); do
		candidate=${versions[i]}
		version_gt "$candidate" "$current" || return 1
		case "$candidate" in *-*) continue ;; esac # pre-release
		if [ -n "$prefix" ] && [[ "$candidate" != "$prefix"* ]]; then
			continue
		fi
		published=$(module_time "$path" "$candidate")
		if [ -n "$published" ] && [ "$published" -le "$cutoff" ]; then
			echo "$candidate"
			return 0
		fi
		if [ -n "$published" ]; then
			echo "  wait   $path@$candidate (published $(((now - published) / 86400)) day(s) ago)" >&2
		fi
	done
	return 1
}

changed=0
while read -r path version; do
	if [ "$version" = "-" ]; then
		echo "  keep   $path (replaced)"
		continue
	fi
	# An earlier update may have raised this module already.
	current=$(go list -m -f '{{.Version}}' "$path")
	picked=$(newest_eligible "$path" "$current") || continue
	if $dry_run; then
		echo "  update $path $current -> $picked (dry run)"
		continue
	fi
	echo "  update $path $current -> $picked"
	if GOFLAGS='' go get "$path@$picked"; then
		changed=1
	else
		echo "  skip   $path@$picked: go get failed (see above)" >&2
	fi
done <<<"$modules"

if $dry_run; then
	exit 0
fi
if [ "$changed" -eq 0 ]; then
	echo ""
	echo "No eligible updates."
	exit 0
fi

echo ""
echo "Running go mod tidy..."
GOFLAGS='' go mod tidy

echo ""
echo "=== Verification ==="
echo ""
"$SCRIPT_DIR/check-deps-cooldown.sh" --cooldown "$cooldown"
go mod verify

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
