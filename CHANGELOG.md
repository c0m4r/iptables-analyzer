# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Types of changes: Added, Changed, Deprecated, Removed, Fixed, Security

## [Unreleased]

The changes of this release follow the audit in `docs/audit-0.7.1.md`; `ROADMAP.md` has the plan.
This release changes the report, the JSON form and some options. See "Changed" before you update scripts.

### Added

- an interactive HTML report: `--html FILE` writes one page that loads nothing from the network, with filters and a search for the findings, links between findings and rules, copy buttons for the commands of a fix, the rules of each chain, the recommended baseline, and a light and a dark theme
- file names as arguments: `iptables-analyzer rules.v4 rules.v6 ss.txt`; the tool finds out what each file holds
- `--fail-on SEVERITY` and `--min-grade GRADE`: exit status 2 when the result is below the threshold, for scripts and CI
- `--quiet`: one line with the score, the grade and the number of findings
- `--rules`: the rules of each chain, with the findings that name them
- `--public LIST`: ports that are open to all sources on purpose (`tcp/80,tcp/443`) are notes without a deduction
- every finding names the rules that cause it; for a rule in a user-defined chain the report shows the jumps that lead to it (`INPUT #2 → ufw-before-input #13 → ufw-user-input #4`)
- every finding has its fix with it: what to do and why, then the commands, each with its purpose
- "Fix first": the findings whose fix alone gives a better grade, then those that gain the most points (`gain` and `grade_after` in JSON)
- fixes for rules in the chains of ufw are `ufw` commands; for chains of other programs (Docker, firewalld, fail2ban, ...) the fix says where to make the change
- open ports: the report lists the ports for which INPUT accepts new connections, with their sources, without a list of listening sockets (`open_ports` in JSON)
- finding `no_rules`: an address family without any rule is one finding
- finding `open_port`: a port that is open to all sources, when no list of listening sockets was read
- finding `broad_accept`: a range of 1,024 or more ports that is open to any source
- finding `ipv6_wider_than_ipv4`: ports that IPv6 opens to any source while IPv4 restricts or filters them
- finding `family_blocked`: an address family with a DROP policy and no accepting rule is one note instead of three findings
- access scope `RESTRICTED` for sources that an ipset, a MAC address, a GeoIP match, a `recent` list or an IPsec policy selects; the report names the set
- conditions on open ports (`condition`): rate limit, connection limit, time window, source port
- service status `INTERNAL` for listeners that only containers or virtual machines of the host reach (`docker0`, `virbr0`, ...)
- family status (`families[].status`): analyzed, no rules loaded, excluded, not supplied, or unreadable (native nftables)
- notes for rules that `iptables-save` cannot show (`iptables-legacy tables present`, `is incompatible, use 'nft' tool`) and for `REDIRECT` rules
- a grade limit: F when INPUT accepts all new connections, D when it accepts by default for one protocol or interface, C for a critical Docker bypass (`score.cap` in JSON)
- the baseline repeats the jumps of INPUT to chains of other programs (fail2ban, libvirt, Tailscale), lists the present `DOCKER-USER` rules as comments, keeps the FORWARD policy of hosts that route packets, and warns on hosts that ufw manages
- modeled matches: `--syn` and `--tcp-flags` for the first packet of a connection, `iprange`, `multiport --ports`, `pkttype`
- `docs/json.md`: the fields of the JSON report
- golden files for the text, JSON and HTML reports of the fixtures (`make update-golden`)

### Changed

- the text report starts with the grade and what to fix first, then lists the findings with their rules and fixes, then the open ports; it wraps to the width of the terminal
- the text report no longer prints the rules and the recommended baseline: use `--rules` and `--baseline`, or the HTML report
- `--verbose` adds the findings of severity INFO, the listening sockets and the sandbox status; the raw rules are in `--rules`
- the JSON form is new (`schema_version` 2): lower-case keys, one `findings` list with the fix of each finding, severities as names, the rules only with `--rules`; see `docs/json.md`
- the grade is complete without a list of listening sockets: each open port is then judged as if a service uses it, and a note says so
- the severity and the deduction of a port that is open to all sources follow the kind of service that usually listens on it: 5 points for remote administration, databases, file services and clear-text protocols, 1 for public services (mail, DNS, web), 2 for other ports
- findings that say the same for IPv4 and IPv6 are one finding; more than 8 open ports of one severity are one finding; the services that are open only because INPUT accepts by default are one finding
- `--score-only` prints the score and the grade (`87 B`)
- the exit status is 0 for a complete analysis, 1 for an error and 2 for a result below `--fail-on` or `--min-grade`
- the checks for the default policy, the conntrack rule and unused rules use the packet-path evaluator instead of the form of the rules in `filter/INPUT`; they follow user-defined chains
- `policy_accept` means that a chain accepts the traffic that no rule names, by its policy or by a rule; the title and the detail name the cause
- rules after a rule that ends the chain are one `dead_rule` finding for the chain, and they are no longer reported as shadowed too
- every deduction of the score comes from a finding; a `POSSIBLE` finding costs half; FORWARD ACCEPT costs 5 points while nothing shows that the host routes packets
- OUTPUT ACCEPT is INFO
- the fix for SSH that is open to all sources inserts a per-source `hashlimit` DROP in front of the accepting rule; it no longer replaces the rule with a global `-m limit`
- a DNAT rule outside Docker's chains is a port forward: no Docker titles, no `DOCKER-USER` commands
- a Docker bypass is CRITICAL only when an INPUT rule names the port or the destination address
- notes of one kind are one note with a count
- source sets are sorted address ranges; the scope of sources follows from the addresses and no longer from the form of the rules

### Removed

- findings `missing_final_drop` and `late_conntrack`
- the separate list of recommendations: each finding has its fix
- the packages `internal/scorer` and `internal/recommender`: `internal/report` builds the findings, the fixes and the score

### Fixed

- a ruleset that accepts all traffic by a rule (`-A INPUT -j ACCEPT` under a DROP policy) got grade A
- wide accepts such as `-p tcp -j ACCEPT` were not reported without a matching listener
- live analysis stopped with an error when `iptables-save` or `ip6tables-save` printed nothing, which is their output when no rules are loaded; an empty rules file was refused in the same way
- a rules file for one address family counted as "no rules" for the other family (-10 points)
- ufw rulesets got a HIGH finding "never accepts ESTABLISHED,RELATED traffic"
- an ACCEPT policy in front of a final REJECT or DROP got HIGH policy findings while the score counted it as default deny
- allowlists with `iprange`, `set` or `mac` were reported as "may be accessible from the network" and scored as exposure; an ipset allowlist written as a negated DROP was reported as definitely exposed
- rate-limited accepts and `--syn` rules were reported as only possible
- the DHCP client rule (`--sport 67 --dport 68`) was a HIGH exposure
- a web server on ports 80 and 443 was a HIGH exposure
- a comment that starts with `-` or equals `!` stopped the analysis (`--comment requires a value`)
- the second argument of `--tcp-flags` and `--match-set` was lost; a negation in front of a rule option after a match was taken for a match option
- the old form of a negation (`--option ! value`), which iptables still accepts, was not read; an argument that belongs to no option is now an error, as it is for `iptables-restore`
- process names with spaces were lost; a socket-activated daemon was named `systemd`; a socket bound to a device (`0.0.0.0%virbr0`) was evaluated for every interface
- a tab in a process name was printed as it is; it is now shown as `^I`
- analysis time grew with the square of the number of single-address rules (3,000 rules: 30 s); 20,000 rules now take approximately one second
- unused-rule findings for negated port predicates named the wrong port, and a file without a filter table lost 25 points without a finding
- the recommendation text named `--baseline 6`, which is not accepted
- advice for rules in ufw chains named `iptables` commands, which ufw overwrites
- the same advice was repeated for each published port and for each address family

### Security

- the HTML report writes text from the input only into text nodes, and the page has a content security policy that names its style sheet and its script by hash; see `docs/security.md`
- the file for `--html` is opened before the sandbox starts and written from inside it; a symbolic link at that path is not followed, and an input file cannot be the output

## [0.7.1] - 2026-11-09

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
