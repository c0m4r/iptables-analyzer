#!/bin/bash
# Helpers for the Go dependency cooldown, sourced by update-deps.sh and
# check-deps-cooldown.sh. The caller sets PROJECT_ROOT and works in it.

COOLDOWN_CONF="${PROJECT_ROOT}/addons/deps.conf"

# configured_cooldown prints COOLDOWN_DAYS from addons/deps.conf (default 7).
configured_cooldown() {
	local days=""
	if [ -f "$COOLDOWN_CONF" ]; then
		days=$(sed -n 's/^COOLDOWN_DAYS=\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$COOLDOWN_CONF" | tail -n 1)
	fi
	echo "${days:-7}"
}

# cooldown_exceptions prints the module@version exceptions of the config.
cooldown_exceptions() {
	if [ -f "$COOLDOWN_CONF" ]; then
		sed -n 's/^COOLDOWN_EXCEPTION=\([^[:space:]#]*\).*/\1/p' "$COOLDOWN_CONF"
	fi
}

# default_cooldown prints the cooldown: GO_DEPS_COOLDOWN_DAYS, else the config.
default_cooldown() {
	if [ -n "${GO_DEPS_COOLDOWN_DAYS:-}" ]; then
		echo "$GO_DEPS_COOLDOWN_DAYS"
	else
		configured_cooldown
	fi
}

validate_cooldown() {
	if ! [[ "$1" =~ ^[0-9]+$ ]]; then
		echo "Invalid cooldown '$1': expected a number of days" >&2
		exit 2
	fi
}

# format_date prints a Unix time as a UTC date (GNU and BSD date).
format_date() {
	date -u -d "@$1" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || date -u -r "$1" '+%Y-%m-%d %H:%M UTC'
}

# pin_toolchain makes go use exactly the toolchain that go.mod selects
# (downloaded and checksum-verified if needed) and never switch to a newer
# one: a dependency that needs a newer Go fails instead of upgrading Go.
pin_toolchain() {
	local version
	version=$(go mod edit -print | sed -n 's/^toolchain \(go[0-9.]*\)$/\1/p')
	if [ -z "$version" ]; then
		version="go$(go mod edit -print | sed -n 's/^go \([0-9.]*\)$/\1/p')"
	fi
	export GOTOOLCHAIN="$version"
}

# build_modules prints "path version" for every module that provides a
# package to the build or its tests ("path -" for replaced modules).
# Capture its output with $(...): a failure in <(...) would go unnoticed.
build_modules() {
	go list -mod=readonly -deps -test \
		-f '{{with .Module}}{{if not .Main}}{{.Path}} {{if .Replace}}-{{else}}{{.Version}}{{end}}{{end}}{{end}}' ./... |
		sed '/^$/d' | sort -u
}

# module_time prints when path@version was published (Unix seconds), as
# recorded by the module proxy.
module_time() {
	go list -m -f '{{with .Time}}{{.Unix}}{{end}}' "$1@$2"
}

# version_gt reports whether semantic version $1 is newer than $2.
version_gt() {
	[ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" = "$1" ]
}
