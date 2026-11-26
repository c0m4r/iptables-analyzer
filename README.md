<div align="center">

# iptables-analyzer

![Linux](https://img.shields.io/badge/made%20for-linux-yellow?logo=linux&logoColor=ffffff)
![Go](https://img.shields.io/badge/go%20go%20go-blue?logo=go&logoColor=ffffff)
[![License: GPL v3](https://img.shields.io/badge/License-AGPLv3-red.svg)](https://www.gnu.org/licenses/agpl-3.0)

A command-line tool that examines iptables and ip6tables rules and finds security problems.

</div>

```text
$ iptables-analyzer rules.v4 ss.txt

iptables-analyzer v0.8.0 · file analysis · 2026-11-25 12:00
inputs: rules.v4, ss.txt
IPv4: 7 rules in 3 chains · INPUT DROP · FORWARD DROP · OUTPUT ACCEPT
IPv6: not supplied

  Grade A  93/100    1 high · 2 low · 1 info

  Policy                ▰▰▰▰▰▰▰▰▰▰ 25/25    Hygiene               ▰▰▰▰▰▰▰▰▰▰ 15/15
  Exposure              ▰▰▰▰▰▰▰▱▱▱ 18/25    IPv6                  ▰▰▰▰▰▰▰▰▰▰ 10/10
  Shadows and bypasses  ▰▰▰▰▰▰▰▰▰▰ 25/25

  Findings

  HIGH     F1   sshd is open to any source on 22/tcp                                    -5
                IPv4: accepted by filter/INPUT rule #3.
                filter/INPUT #3:  -p tcp --dport 22 -j ACCEPT
                fix  If the clients are known, accept only their addresses. ...
                     Replace the rule with one for the known clients:
                       iptables -R INPUT 3 -s <trusted-cidr> -p tcp --dport 22 -j ACCEPT
  ...

  Open to any source
    tcp  22 sshd · 80 nginx · 443 nginx

  Not shown: 7 rules (--rules) · 1 info finding, 9 listening sockets (-v) · recommended baseline (--baseline)
  Interactive report: --html FILE · machine-readable: --json
```

## What the tool does

The tool reads iptables and ip6tables rules and finds these problems:

- Chains that accept all traffic by default, by their policy or by a rule.
- Ports and port ranges that are open to all sources, also when no service listens on them.
- Listening services that the firewall does not protect.
- Ports that are open on IPv6 and restricted on IPv4.
- Rules that never match, because an earlier rule matches the same packets.
- Docker published ports that bypass the INPUT rules.
- DOCKER-USER and FORWARD rules that have no effect on Docker traffic.
- Containers that other hosts can reach by direct routing.
- Dropped replies, dropped loopback traffic, and blocked IPv6 neighbor discovery.

The report starts with a security score from 0 to 100 and a grade from A to F.
Each finding names the rules that cause it and says how to fix it, with commands.
The tool writes the report for the terminal, as an interactive HTML page, or as JSON.
It can also write a recommended baseline firewall for IPv4 and IPv6.

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

1. Save the rules and the list of listening sockets on the host that you want to examine:

   ```bash
   sudo iptables-save > rules.v4
   sudo ip6tables-save > rules.v6
   sudo ss -tulnp > ss.txt
   ```

2. Examine the files on any host:

   ```bash
   iptables-analyzer rules.v4 rules.v6 ss.txt
   ```

The tool finds out what each file holds. All files are optional, but it needs the rules
of one address family:

- Without the IPv6 rules, the tool examines only IPv4, and the report says so.
- Without the `ss` output, the tool judges each open port as if a service uses it.
- An empty rules file means that no rules are loaded: all traffic is accepted.

### Get an interactive report

```bash
sudo iptables-analyzer --html report.html
```

The file is one HTML page that loads nothing from the network.
You can filter the findings, go from a finding to its rules, and copy the commands of a fix.
The page also holds the rules and the recommended baseline.

### Use the result in a script

```bash
# Exit status 2 when a finding is high or critical
iptables-analyzer rules.v4 rules.v6 --quiet --fail-on high

# Exit status 2 when the grade is worse than B
sudo iptables-analyzer --quiet --min-grade B
```

### Options

| Option | Function |
| --- | --- |
| `FILE...` | Read saved `iptables-save`, `ip6tables-save` and `ss` output |
| `-f`, `--file FILE` | Read the IPv4 rules from FILE |
| `--file6 FILE` | Read the IPv6 rules from FILE |
| `--services-file FILE` | Read the listening sockets from FILE (`ss` output) |
| `-4`, `-6` | Examine only IPv4 or only IPv6 |
| `--public LIST` | Ports that are open to all sources on purpose, for example `tcp/80,tcp/443`: no deduction |
| `--html FILE` | Also write an interactive HTML report to FILE |
| `--json` | Write the report as JSON |
| `--rules` | Also show the rules of each chain |
| `-v`, `--verbose` | Also show notes, the listening sockets and the sandbox status |
| `-q`, `--quiet` | Show one line: the score, the grade and the number of findings |
| `-s`, `--score-only` | Show only the score and the grade |
| `--fail-on SEVERITY` | Exit with status 2 when a finding has this severity or a higher one |
| `--min-grade GRADE` | Exit with status 2 when the grade is worse than GRADE |
| `--baseline[=4\|6\|all]` | Write only the recommended baseline, in iptables-restore format |
| `--no-color` | Do not use colors |
| `--sandbox=auto\|strict\|off` | Set the sandbox mode (default: `auto`) |

## Security

The tool reads data that other persons can control, for example rule comments and process names.
The tool has these protections:

- After it reads the input, it drops root privileges and starts a Landlock sandbox.
  In the sandbox, the process cannot open files, start programs or connect to the network.
- It starts only root-owned system tools from trusted directories, with a minimal environment.
- It shows control characters from the input as visible text.
  Terminal escape sequences in the input have no effect.
- It puts quotes around all values from the rules in the commands of a fix.
- It writes text from the input into the HTML report only as text. The page has a content
  security policy that permits no network access and no script but its own.

Landlock is available in Linux 5.13 and later.
To stop when the full sandbox is not available, use `--sandbox=strict`.

## Documentation

- [docs/usage.md](docs/usage.md): all modes, the report, the baseline and examples.
- [docs/json.md](docs/json.md): the fields of the JSON report.
- [docs/how-it-works.md](docs/how-it-works.md): the analysis method and its limits.
- [docs/security.md](docs/security.md): the sandbox and the other protections.
- [docs/supply-chain.md](docs/supply-chain.md): the dependency cooldown, the CI checks and the release verification.
- [DEVELOPMENT.md](DEVELOPMENT.md): build, test and change the tool.
- [CHANGELOG.md](CHANGELOG.md): the changes in each release.
- The manual page: `man -l addons/man1/iptables-analyzer.1`.

## Caution

The commands of a fix and the baseline change the access to the system.
Test all changes before you use them on a production system.
An incorrect firewall change can lock you out of the system.
