# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Types of changes: Added, Changed, Deprecated, Removed, Fixed, Security

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

### Fixed

- v4/v6 mode enhancements/fixes

## [0.2.0] - 2026-03-24

### Added

- LOCALNET/WHITELISTED classification

### Fixed

- Docker bypass duplicates
- addrtype catch-all false positives

## [0.1.0] - 2026-03-24

### Added

- First iptables-analyzer version
