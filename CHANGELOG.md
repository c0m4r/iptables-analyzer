# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Types of changes: Added, Changed, Deprecated, Removed, Fixed, Security

## [Unreleased]

### Added

- `SUBNET` access scope for sources that are specific public networks; the report shows it in the service table ("SUBNET") and the Docker published-port table ("PUBLIC NETS")

### Fixed

- a source restriction to a public network, for example `-s 203.0.113.0/24`, was reported as a HIGH `EXPOSED` service like `0.0.0.0/0`; public networks that add up to at most a /16 (IPv4) or a /48 (IPv6) are now `SUBNET` (LOW, not scored as exposure), while wider ranges and complements such as `! -s 10.0.0.0/8` stay `EXPOSED`
- service findings with a source restriction said "accessible from the network"; they now name the sources ("from specific public networks", "from private networks", "from individual hosts")

## [0.7.0] - 2026-11-09

### Added

- Landlock sandbox: after the input is collected, the analyzer drops root privileges to uid/gid 65534, sets no_new_privs and enforces a Landlock domain without allow rules (no file access, execution, TCP/UDP, abstract UNIX sockets or signals, as far as the kernel's ABI allows) before it parses, analyzes and renders anything; `--sandbox=auto|strict|off`, sandbox status in the report overview and in JSON (`Sandbox`)
- dependency cooldown: `addons/update-deps.sh` adopts only module versions published at least `COOLDOWN_DAYS` ago (`addons/deps.conf`, `--cooldown`, `GO_DEPS_COOLDOWN_DAYS`), with reviewed per-version exceptions; `addons/check-deps-cooldown.sh` and `make check-deps` verify it
- Dependabot configuration for Go modules and GitHub Actions with the same cooldown
- release workflow that builds, tests and attests (SLSA build provenance) the binaries and creates a draft release with `SHA256SUMS`
- fuzz tests for the parsers, the escaping and shell quoting, and the whole command; `make fuzz`, `make test-sandbox`
- documentation in `docs/` (usage, analysis method, security, supply chain); the README is now short and written in Simplified Technical English

### Changed

- input is collected first and parsed only inside the sandbox; `loader.Read`/`loader.Parse` and `services.Collect`/`Capture.Parse` replace the combined helpers in the command
- `make build`, `make test` and `make build-dev` produce static binaries (`CGO_ENABLED=0`), which the sandbox needs on kernels before Landlock ABI 8
- CI: actions pinned to commit SHAs, `permissions: {}` by default, no persisted credentials, no caches, fixed toolchain and module proxy, `go mod tidy -diff`, dependency cooldown, hidden-Unicode check, pinned govulncheck, zizmor workflow audit, dependency review on pull requests, sandbox tests without cgo, fuzz smoke tests and a reproducible-build check
- recommended commands quote ruleset values for the shell, so comments are shown in single quotes

### Security

- rule comments, chain and interface names and ss process names could inject terminal escape sequences into the report; control characters, bidirectional overrides and invalid UTF-8 are now shown as `^[`, `<U+202E>` and `<0xNN>`
- recommended commands embedded rule text unquoted, so a comment such as `$(...)` ran when the command was copied into a shell; every ruleset value is now shell-quoted
- live mode ran `iptables-save`, `ip6tables-save` and `ss` from `PATH` with the caller's environment (for example `XTABLES_LIBDIR`); they now run only from root-owned, non-writable trusted locations with an environment of `PATH` and `LC_ALL=C`, without standard input and with `Pdeathsig`
- rule files, ss files and tool output were read without a size limit; they are now limited to 64 MiB (rules) and 16 MiB (ss)
- crafted rulesets whose chains jump to each other several times made the evaluation exponential (a 41-rule file took minutes, larger ones never finished); chain traversals are now bounded per ruleset, and affected results are reported as possible with an assessment note

## [0.6.0] - 2026-11-09

### Added

- recommended baseline firewall, always generated for both IPv4 and IPv6 and tailored to the detected SSH port, listeners and Docker; shown in every report, in JSON, and alone with `--baseline[=4|6|all]`
- Docker analysis of published ports along the full hook sequence (raw, mangle, nat, filter, security), a "Docker Published Ports" table, and new finding codes: `docker_published_port`, `docker_ineffective_rule`, `docker_shadowed_rule`, `docker_fragile_rule`, `docker_direct_route`, `docker_ipv6_unfiltered`
- detection of DOCKER-USER/FORWARD rules that match the pre-DNAT port or host address, FORWARD rules shadowed by Docker's ACCEPT rules, and rules above Docker's jumps that `dockerd` reorders on restart
- detection of containers reachable by direct routing (missing Docker 28+ raw protection, loopback-only publications, `routed` and `nat-unprotected` gateway modes) and of IPv6 forwarding left unfiltered by Docker
- checks for dropped loopback traffic and blocked IPv6 neighbor discovery/router advertisements
- live mode reads the host's interfaces and addresses to evaluate `-i` and local-address predicates exactly
- `ss -tulnp` (Netid column) inventories, `-F` lines in iptables-restore files, and target options such as `-j CT --notrack`
- regression tests on real Docker 29.9.3 captures whose variants were reproduced on a live host

### Changed

- open published ports are reported and scored as exposure; `docker_bypass` is reserved for ports that INPUT or its default-deny policy would refuse
- certainty is tracked per accepted source range: undecidable predicates (rate limits, ipsets) only make a verdict possible when it depends on them matching
- interface-specific rules are evaluated per ingress interface, and findings name the interfaces they apply to
- Docker recommendations use `--ctorigdstport ... --ctdir ORIGINAL`, allow trusted sources before the drop, and are ordered by severity

### Fixed

- Docker findings were always "Possible path" because `addrtype`, Docker bridge interfaces and the container's output interface were not modeled
- drops in raw/mangle PREROUTING were ignored, producing false Docker bypasses
- sources accepted by a chain policy were classified as WHITELISTED instead of LOCALNET/EXPOSED
- multiple `-m conntrack` matches in one rule overwrote each other's state list
- SSH rate limiting implemented as a preceding `hashlimit`/`recent` DROP was not recognized
- the INCOMPLETE grade was wrapped in the score card

## [0.5.0] - 2026-11-09

### Added

- stable finding codes, service-assessment status, per-socket family/status metadata, and incomplete-score diagnostics in JSON output
- regression coverage for fragmented traffic, dual-stack listeners, nested-chain remediation, DNAT state and ranges, ordered NAT traversal, original-tuple matches, malformed inventories, policy validation, semantic rendering, and output failures

### Changed

- Docker analysis evaluates every published port with ordered PREROUTING traversal and retains original and translated conntrack tuples
- service discovery distinguishes dual-stack, excluded, filtered, reachable, malformed, and valid empty inventories
- verbose rule tables include raw rules and render negations, fragments, extension predicates, and goto control flow
- the capture helper writes through temporary files and preserves prior captures when collection fails

### Fixed

- unsafe SSH replacements, wrong-chain exposure advice, discarded fragment predicates, IPv6 wildcard loss, DNAT-state false negatives, range sampling, bare IPv6 target parsing, original-port protection false positives, stateful shadow false positives, duplicate listener findings and dual-stack exposure deductions, successful incomplete scores, invalid policy acceptance, excluded-service labeling, and ignored output errors

## [0.4.0] - 2026-08-03

### Added

- order-aware packet-path evaluation with support for jumps, `goto`, `RETURN`, default policies, negation, and symbolic CIDR splitting
- conservative handling of unsupported match extensions and strict diagnostics for malformed or incomplete rulesets
- regression coverage across the analyzer, loader, parser, recommender, scorer, service discovery, CLI, and UI, plus continuous integration

### Changed

- offline analysis reads listening services only when an explicit services file is provided
- Docker exposure analysis now follows externally reachable DNAT paths and evaluates post-DNAT traffic through `FORWARD` and `DOCKER-USER`
- security scoring now uses a true 100-point category total without double-counting policy findings
- CLI validation, output ordering, build checks, examples, and documentation have been tightened and made deterministic

### Fixed

- service exposure false positives and negatives caused by ignoring rule order, default policies, source restrictions, and user-defined chains
- Docker false positives for `OUTPUT`-only, loopback-bound, source-restricted, and translated-port-filtered DNAT rules
- Docker recommendations now match original published ports with conntrack instead of ineffective post-DNAT destination ports
- swallowed IPv6 file errors, module-level negation loss, conditional-drop catch-all scoring, IPv6 CIDR handling, and cross-family unused-rule matches

### Security

- firewall parsing and evaluation now fail conservatively instead of producing reassuring results from incomplete or unsupported rulesets

## [0.3.1] - 2026-03-25

### Changed

- adaptive color scheme based on terminal theme

### Fixed

- v4/v6 mode enhancements/fixes

## [0.3.0] - 2026-03-24

### Added

- bash-completion file
- man page file

### Changed

- Arg --ipv4-only is now -4
- Arg --ipv6-only is now -6
- Arg --ipv4-file is now -f/--file
- Arg --ipv6-file is now -f6/--file6
- Usage description/header

### Removed

- Args --check-services, --live removed because these are implicit

## [0.2.0] - 2026-03-24

### Added

- LOCALNET/WHITELISTED classification

### Fixed

- Docker bypass duplicates
- addrtype catch-all false positives

## [0.1.0] - 2026-03-24

### Added

- First iptables-analyzer version
