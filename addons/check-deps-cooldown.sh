#!/bin/bash
# Verify that every Go module used by the build or the tests was published
# at least the cooldown ago (see addons/deps.conf), and that Dependabot uses
# the same cooldown. CI runs this on every push and pull request.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"
# shellcheck source=addons/cooldown.sh
. "$SCRIPT_DIR/cooldown.sh"

usage() {
	echo "Usage: $0 [--cooldown DAYS]"
	echo ""
	echo "Fails when a Go module version in the build is younger than DAYS"
	echo "(default: GO_DEPS_COOLDOWN_DAYS, else COOLDOWN_DAYS in addons/deps.conf)."
}

cooldown=$(default_cooldown)
while [ $# -gt 0 ]; do
	case "$1" in
	--cooldown) shift; cooldown="${1:-}" ;;
	--cooldown=*) cooldown="${1#*=}" ;;
	-h | --help) usage; exit 0 ;;
	*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
	shift
done
validate_cooldown "$cooldown"

failed=0
report() {
	failed=1
	if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
		echo "::error::$1"
	else
		echo "ERROR: $1" >&2
	fi
}

# Dependabot reads its own configuration; it must match addons/deps.conf.
configured=$(configured_cooldown)
dependabot=".github/dependabot.yml"
if [ -f "$dependabot" ]; then
	while read -r days; do
		if [ "$days" != "$configured" ]; then
			report "$dependabot sets a cooldown of $days days, but addons/deps.conf sets $configured"
		fi
	done < <(sed -n 's/^[[:space:]]*default-days:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$dependabot")
fi

exceptions=" $(cooldown_exceptions | tr '\n' ' ') "
modules=$(build_modules)
now=$(date +%s)
echo "Cooldown: $cooldown days (now: $(format_date "$now"))"
while read -r path version; do
	if [ "$version" = "-" ]; then
		echo "  skip  $path (replaced)"
		continue
	fi
	published=$(module_time "$path" "$version")
	if [ -z "$published" ]; then
		report "the module proxy has no publication time for $path@$version"
		continue
	fi
	age=$(((now - published) / 86400))
	if [ "$age" -lt "$cooldown" ] && [[ "$exceptions" == *" $path@$version "* ]]; then
		printf '  allow %-48s %-36s %5d days (exception in addons/deps.conf)\n' "$path" "$version" "$age"
	elif [ "$age" -lt "$cooldown" ]; then
		report "$path@$version was published $age day(s) ago ($(format_date "$published")); the cooldown is $cooldown days"
	else
		printf '  ok    %-48s %-36s %5d days\n' "$path" "$version" "$age"
	fi
done <<<"$modules"

if [ "$failed" -ne 0 ]; then
	echo "Dependency cooldown check failed." >&2
	exit 1
fi
echo "All modules respect the cooldown."
