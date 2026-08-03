# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Types of changes: Added, Changed, Deprecated, Removed, Fixed, Security

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
