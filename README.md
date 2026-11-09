<div align="center">

# iptables-analyzer

![Linux](https://img.shields.io/badge/made%20for-linux-yellow?logo=linux&logoColor=ffffff)
![Go](https://img.shields.io/badge/go%20go%20go-blue?logo=go&logoColor=ffffff)
[![License: GPL v3](https://img.shields.io/badge/License-AGPLv3-red.svg)](https://www.gnu.org/licenses/agpl-3.0)

A command-line tool that examines iptables and ip6tables rules and finds security problems.

<img width="833" height="330" alt="image" src="https://github.com/user-attachments/assets/3ec0795e-7ab7-4494-ba69-5fa00404cfc8" />

</div>

## What the tool does

The tool reads iptables and ip6tables rules and finds these problems:

- Rules that never match, because an earlier rule matches the same packets.
- Docker published ports that bypass the INPUT rules.
- DOCKER-USER and FORWARD rules that have no effect on Docker traffic.
- Containers that other hosts can reach by direct routing.
- Listening services that the firewall does not protect.
- ACCEPT default policies, a missing conntrack rule, and blocked IPv6 neighbor discovery.

The tool gives a security score from 0 to 100 and a grade from A to F.
It also gives recommendations and a recommended baseline firewall for IPv4 and IPv6.

The tool does not change the firewall.

## Requirements

- Linux.
- Root access to examine the live rules. Without root access, use saved rule files.
- For live analysis: `iptables-save`, `ip6tables-save` and `ss` (iproute2).
- To build from source: Go 1.26 or later.

## Install

### Download a release

1. Download the binary for your architecture (amd64, arm64 or riscv64) from the
   [releases page](https://github.com/c0m4r/iptables-analyzer/releases).
2. Download the `SHA256SUMS` file of the same release.
3. Make sure that the checksum is correct:

   ```bash
   sha256sum --ignore-missing -c SHA256SUMS
   ```

4. Optional: make sure that GitHub Actions built the binary from this repository:

   ```bash
   gh attestation verify iptables-analyzer-<version>-amd64 --repo c0m4r/iptables-analyzer
   ```

5. Install the binary:

   ```bash
   sudo install -m 0755 iptables-analyzer-<version>-amd64 /usr/local/bin/iptables-analyzer
   ```

Older releases do not have a `SHA256SUMS` file or an attestation.

### Build from source

```bash
git clone https://github.com/c0m4r/iptables-analyzer
cd iptables-analyzer
make build
```

The result is one static binary, `iptables-analyzer`, without runtime dependencies.
To build for amd64, arm64 and riscv64, use `./addons/build.sh`.

## Use

### Examine the live rules

```bash
sudo iptables-analyzer
```

### Examine saved rules

1. Save the rules:

   ```bash
   sudo iptables-save > rules.v4
   sudo ip6tables-save > rules.v6
   ```

2. Save the list of listening services:

   ```bash
   sudo ss -tulnp > services.txt
   ```

3. Examine the files:

   ```bash
   iptables-analyzer -f rules.v4 --file6 rules.v6 --services-file services.txt
   ```

Without a services file, the tool cannot examine the service exposure.
The grade is then `INCOMPLETE`.

### Options

| Option | Function |
| --- | --- |
| `-f`, `--file FILE` | Read the IPv4 rules from FILE |
| `--file6 FILE` | Read the IPv6 rules from FILE |
| `--services-file FILE` | Read the listening services from FILE (`ss` output) |
| `-4`, `-6` | Examine only IPv4 or only IPv6 |
| `--json` | Write the result as JSON |
| `-s`, `--score-only` | Show only the score |
| `-v`, `--verbose` | Show all rules and the raw rule text |
| `--no-color` | Do not use colors |
| `--baseline[=4\|6\|all]` | Write only the recommended baseline, in iptables-restore format |
| `--sandbox=auto\|strict\|off` | Set the sandbox mode (default: `auto`) |

## Security

The tool reads data that other persons can control, for example rule comments and process names.
The tool has these protections:

- After it reads the input, it drops root privileges and starts a Landlock sandbox.
  In the sandbox, the process cannot open files, start programs or connect to the network.
- It starts only root-owned system tools from trusted directories, with a minimal environment.
- It shows control characters from the input as visible text.
  Terminal escape sequences in the input have no effect.
- It puts quotes around all values from the rules in the recommended commands.

Landlock is available in Linux 5.13 and later.
To stop when the full sandbox is not available, use `--sandbox=strict`.

## Documentation

- [docs/usage.md](docs/usage.md): all modes, the report, the baseline and examples.
- [docs/how-it-works.md](docs/how-it-works.md): the analysis method and its limits.
- [docs/security.md](docs/security.md): the sandbox and the other protections.
- [docs/supply-chain.md](docs/supply-chain.md): the dependency cooldown, the CI checks and the release verification.
- [DEVELOPMENT.md](DEVELOPMENT.md): build, test and change the tool.
- [CHANGELOG.md](CHANGELOG.md): the changes in each release.
- The manual page: `man -l addons/man1/iptables-analyzer.1`.

## Caution

The recommendations can change the access to the system.
Test all changes before you use them on a production system.
An incorrect firewall change can lock you out of the system.
