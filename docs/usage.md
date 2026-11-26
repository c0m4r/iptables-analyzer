# Usage

This document gives the full procedures and describes the report.
For a short introduction, see the [README](../README.md).

## Input

### Live analysis

Run the tool as root without files:

```bash
sudo iptables-analyzer
```

The tool then reads:

- the rules from `iptables-save` and `ip6tables-save`,
- the listening sockets from `ss -tlnp` and `ss -ulnp`,
- the network interfaces and their addresses, and the host name,
- the kernel settings for routing (`ip_forward`), the reverse-path filter (`rp_filter`)
  and `route_localnet`, and the IPv4 routing table from `ip route`,
- the list of nftables tables from `nft list chains`, when `nft` is installed,
- the contents of the ipsets from `ipset save`, when `ipset` is installed.

These facts make the result more exact:

- The interface list lets the tool evaluate `-i` and local-address predicates exactly.
- A host that does not route packets (`ip_forward` is 0) sends nothing to other hosts.
  The FORWARD chain and the port forwards then have no effect, and there is no deduction for them.
- With the reverse-path filter in strict mode, only sources whose route leaves through an
  interface can arrive on it. A rule that accepts SSH on the interface of the local network
  then opens the port to that network, not to all sources. A note in the report shows the limit.
- With the contents of an ipset, a `-m set` match is evaluated like a list of `-s` addresses.
- An nftables table that `iptables-save` does not print can filter packets too
  (firewalld with its nftables backend, a hand-written table). The tool cannot read its rules.
  When such a table has a chain on the way of incoming packets, a note names it
  and the grade is `INCOMPLETE`.

`iptables-save` prints nothing when no rules are loaded.
The tool then reports that the address family accepts all traffic.

The nf_tables variant of `iptables-save` cannot print native nftables rules,
and it warns when the legacy tables also hold rules.
The tool shows these messages as notes, and the grade is `INCOMPLETE`.
To see such rules, use `nft list ruleset` or `iptables-legacy-save`.

### File analysis

1. Save the input on the host that you want to examine:

   ```bash
   sudo iptables-save > rules.v4
   sudo ip6tables-save > rules.v6
   sudo ss -tulnp > ss.txt
   ```

   The script `examples/save-rules.sh [DIRECTORY]` saves the two rule files in one step.
   A snapshot saves more in one file. See [Snapshots](#snapshots).

2. Examine the files on any host:

   ```bash
   iptables-analyzer rules.v4 rules.v6 ss.txt
   ```

The tool finds out what each file holds:

- The first line of `iptables-save` and `ip6tables-save` output names the program.
- Without that line, the addresses and the ICMP matches of the rules show the address family.
- Rules without any sign of their family are IPv4 rules. A second such file holds IPv6 rules.
- `ss` output has its header line, or rows with `LISTEN` or `UNCONN`.
- A snapshot names its format in its first lines.

To name the kind of a file yourself, use `--file` (IPv4 rules), `--file6` (IPv6 rules)
and `--services-file` (`ss` output). You can use these options together with plain file names.

The tool also reads the output of `iptables -S` and `ip6tables -S`. Such a listing does not
name its table. The tool finds the table from the built-in chains whose policy the listing
gives. The listings of more than one table can be in one file, one after the other:

```bash
{ sudo iptables -S; sudo iptables -t nat -S; } > rules.v4
```

If the rules use ipsets, save their contents and give the file with `--ipset-file`:

```bash
sudo ipset save > ipsets.txt
iptables-analyzer rules.v4 ss.txt --ipset-file ipsets.txt
```

Without the contents, a match against a set restricts the sources to a set that the tool
cannot read, and the report names the set.

All files are optional, but the tool needs the rules of one address family:

- Without a file for one address family, the tool examines only the other family.
  The report shows the family as `not supplied`. There is no deduction for it.
- Without `ss` output, the tool judges each open port as if a service uses it.
  The grade is complete. A note in the report says that the listening sockets were not read.
- A rules file without tables (an empty file) means that no rules are loaded for that family.
- An `ss` file with only a header means a host on which nothing listens.

A file that does not exist, or that holds something else, is an error.
The tool reads at most 64 MiB of rules and 16 MiB of `ss` output.
Process substitution works, for example `--file <(sudo iptables-save)`.

In file mode, the tool does not examine the host that runs it.

### Snapshots

A snapshot is one file with everything that a live analysis reads: the output of the tools,
the interfaces and the kernel settings. Write it on the host that you want to examine:

```bash
sudo iptables-analyzer --snapshot host.json
```

The usual report is written too. Add `--quiet` for one line.
Then examine the file on any host, with every option of the tool:

```bash
iptables-analyzer host.json
iptables-analyzer host.json --html report.html
iptables-analyzer host.json --trace 'tcp 203.0.113.5 -> :22 in eth0'
```

The result is the same as on the host at the time of the snapshot. The header of the report
shows the host name and that time.

- A snapshot is a complete input. You cannot use it together with other rule files.
  `-4`, `-6` and `--ipset-file` work with it.
- `--snapshot` also works with files. The snapshot then holds what the files hold.
- The file is JSON. It holds the rules, the host name, the addresses of the interfaces and
  the names of the listening processes. A new file is readable only by its owner (mode `0600`).
  With `sudo`, the owner is the user who started `sudo`.
- The tool does not follow a symbolic link at `FILE`, and it does not overwrite an input file.

### One address family

```bash
iptables-analyzer -4 rules.v4      # only IPv4
sudo iptables-analyzer -6          # only IPv6
```

## Output

By default, the tool writes a text report to the terminal. The other forms:

| Option | Output |
| --- | --- |
| `--rules` | The text report, and the rules of each chain with the findings that name them |
| `-v`, `--verbose` | The text report, and the findings of severity INFO, the listening sockets and the sandbox status |
| `-q`, `--quiet` | One line: the score, the grade and the number of findings, for example `87 B  1 high, 2 low` |
| `-s`, `--score-only` | The score and the grade, for example `87 B` |
| `--json` | The full report as JSON. See [json.md](json.md) |
| `--html FILE` | The usual output, and an interactive report in `FILE` |
| `--snapshot FILE` | The usual output, and a snapshot of the input in `FILE`. See [Snapshots](#snapshots) |
| `--trace PACKET` | Only the way of one packet through the rules. See [Follow one packet](#follow-one-packet) |
| `--diff OLD NEW` | Only the differences between two inputs. See [Compare two rule sets](#compare-two-rule-sets) |
| `--baseline[=4\|6\|all]` | Only the recommended baseline, in iptables-restore format |

`--no-color` writes the text without colors. The tool also obeys the `NO_COLOR` variable,
and it uses no colors when the output is not a terminal.

The text report wraps to the width of the terminal, between 60 and 120 columns.
Without a terminal, the width is 100 columns. The `COLUMNS` variable sets a different width.
Commands and rules are never wrapped: each stays one line that you can copy.

### The HTML report

```bash
sudo iptables-analyzer --html report.html
```

The file is one page that needs nothing else. It holds the same report as the terminal,
and also the rules of each chain and the recommended baseline. In the page you can:

- show and hide the findings of each severity, and search in them,
- go from a finding to its rules, and from a rule to its findings,
- copy the commands of a fix,
- sort the tables of ports and sockets, and search in the rules,
- change between the light and the dark theme. The page follows the system setting until you choose.

The page loads nothing from the network and works without JavaScript, except for the functions above.
For its protections, see [security.md](security.md#6-the-html-report).

The report shows the rules of the host. A new file is readable only by its owner (mode `0600`).
With `sudo`, the owner is the user who started `sudo`. An existing file keeps its mode and its owner.
The tool does not follow a symbolic link at `FILE`, and it does not overwrite an input file.
When a run fails, an older report in `FILE` stays as it was.

### Follow one packet

`--trace` shows what the rules do with one packet: the rules that it matches in each chain,
the jumps, a new destination from the nat table, and the verdict.

```bash
iptables-analyzer rules.v4 --trace 'tcp 203.0.113.5 -> :22 in eth0'
sudo iptables-analyzer --trace 'tcp 203.0.113.5 -> 192.0.2.10:8443 in eth0'
```

The packet is written as:

```text
PROTOCOL SOURCE[:PORT] -> [DESTINATION]:PORT [in IFACE] [out IFACE] [state STATE]
```

- `PROTOCOL` is `tcp`, `udp`, `icmp` or `icmpv6`. For ICMP there is no port; `type N` gives the type.
- A destination without an address (`:22`) is an address of this host.
- An IPv6 address with a port is in brackets: `[2001:db8::5]:40000`.
- `in IFACE` is the interface where the packet arrives. Without it, a rule that names an
  interface may or may not match.
- `out IFACE` is for a packet that the host routes to another host.
- `state` is `NEW` (the default), `ESTABLISHED`, `RELATED`, `INVALID` or `UNTRACKED`.

The trace follows the packet as the kernel does:

- It knows the marks that rules set on the way, and it uses the contents of the ipsets,
  the routes and the kernel settings when they were read (live analysis or a snapshot).
- A rate limit is judged for a first packet, which is below the limit.
- Some matches cannot be decided for one packet, for example a set without its contents or
  a random share of the packets. The trace then goes on as if the rule did not match, and a
  list shows how the packet ends when it does match. If the verdicts differ, the verdict is
  `not certain`.

`--expect accept`, `--expect drop` or `--expect reject` gives exit status 2 when the verdict
is a different one or is not certain. Thus a script can test what the rules must do:

```bash
iptables-analyzer host.json --trace 'tcp 203.0.113.5 -> :22 in eth0' --expect drop
iptables-analyzer host.json --trace 'tcp 10.1.2.3 -> :22 in eth1' --expect accept
```

The verdicts of the trace are compared with the Linux kernel in the tests of the tool.
See [how-it-works.md](how-it-works.md#comparison-with-the-kernel).

### Compare two rule sets

`--diff OLD NEW` shows what a change of the rules changes. Each of the two files is the
output of `iptables-save` or `ip6tables-save`, or a snapshot.

```bash
iptables-analyzer --diff rules-before.v4 rules-after.v4
iptables-analyzer --diff monday.json friday.json
```

The output shows:

- the two grades,
- the findings that only the new input has, those that are gone, and those whose severity changed,
- the ports of the host whose sources changed, for example `tcp 3306  closed → any source`,
- the ports that are sent to other hosts and that are new, gone or changed.

`--quiet` gives one line, `--verbose` adds the details of the findings, `--json` gives the data.
With `--diff`, the thresholds judge the change: `--fail-on high` gives status 2 when the new
input adds a high or critical finding, and `--min-grade` reads the grade of the new input.

### Use in scripts

The exit status is:

| Status | Meaning |
| --- | --- |
| 0 | The analysis is complete |
| 1 | An error: the input could not be read, or an option is not correct |
| 2 | The analysis is complete, and the result is below what `--fail-on`, `--min-grade` or `--expect` asks for |

`--fail-on SEVERITY` gives status 2 when a finding has this severity or a higher one.
`SEVERITY` is `low`, `medium`, `high` or `critical`.

`--min-grade GRADE` gives status 2 when the grade is worse than `GRADE` (`A` to `D`).
A grade of `INCOMPLETE` is always worse.

The report is written before the status is set. Examples:

```bash
# Stop a deployment when the rules have a high or critical finding
iptables-analyzer rules.v4 rules.v6 --quiet --fail-on high

# Keep a record, and tell the monitoring when the grade is below B
sudo iptables-analyzer --quiet --min-grade B --html /var/lib/firewall/report.html

# Read the result with jq
sudo iptables-analyzer --json | jq -r '.findings[] | select(.severity == "HIGH") | .title'

# Refuse a change of the rules that opens something
iptables-analyzer --diff deployed.v4 proposed.v4 --quiet --fail-on medium

# Test that the database stays closed to the Internet
iptables-analyzer proposed.v4 --trace 'tcp 203.0.113.5 -> :5432' --expect drop
```

### Ports that are public on purpose

A web server must accept connections from all sources. Tell the tool which ports are public:

```bash
sudo iptables-analyzer --public tcp/80,tcp/443
```

The findings for these ports then have the severity INFO and no deduction.
The list accepts `tcp/80`, `80/tcp`, `udp/53`, ranges such as `tcp/8000-8100`, and `443` (TCP).
Only ports that are open to all sources change. Other findings stay as they are.

## The report

### Header

The first lines show what the tool examined: the input, and for each address family
the number of rules and chains, the programs whose chains the rules contain (for example
Docker or ufw), and the policies of the built-in filter chains.

### Score and grade

The score is 0 to 100. Each finding has a deduction, and each category has a maximum:

| Category | Deductions | Maximum |
| --- | --- | --- |
| Policy | 15 when INPUT accepts connections to ports that no rule names. 10 when FORWARD accepts traffic that no rule names and the host routes packets, 5 when routing is not known, 0 when the host does not route packets. 25 when no IPv4 rules are loaded. OUTPUT ACCEPT is only a note. | 25 |
| Exposure | For each port that is open to all sources: 5 for a port of remote administration, a database, a file service or a clear-text protocol, 1 for a port of a public service (mail, DNS, web), 2 for any other port. At most 2 for a port with a rate limit, 1 for a port that needs a specific source port. 10 for a range of 1,024 or more ports. A port that is open on IPv4 and IPv6 counts one time. Ports that are sent to other hosts for all sources (Docker published ports, node ports of Kubernetes, port forwards) count in the same way. A port that is redirected to a different local port counts by its own number. | 25 |
| Shadows and bypasses | 12 for each critical, 5 for each high and 2 for each medium finding about translated ports. 5 for a shadowed rule with the opposite decision, 2 for any other shadowed rule. | 25 |
| Hygiene | 5 when INPUT drops the replies to the connections of the host. 5, 3 or 1 for each chain with unreachable rules, for dropped loopback traffic, and for blocked IPv6 neighbor discovery and router advertisements. | 15 |
| IPv6 | 10 when no IPv6 rules are loaded. 5 when Docker does not filter IPv6 forwarding. 5, 3 or 1 when IPv6 opens ports that IPv4 restricts or filters. | 10 |

A finding with the certainty `POSSIBLE` has half of the deduction.

The grade follows from the score: A from 90, B from 80, C from 70, D from 50, F below 50.
Some findings also limit the grade, whatever the score is:

- **F** when INPUT accepts all new connections, for example with an ACCEPT policy
  and no final DROP, or with a rule `-j ACCEPT`. Also when no IPv4 rules are loaded,
  and when no IPv6 rules are loaded on a host that has a global IPv6 address.
- **D** when INPUT accepts connections to all ports that no rule names, but not for
  all protocols or interfaces. Also when IPv6 accepts everything, or has no rules,
  and the tool does not know if the host uses IPv6 (saved rules do not show the addresses).
- **C** when a Docker published port bypasses an INPUT rule that names it, for all sources.

An IPv6 stack without rules on a host that has only link-local IPv6 addresses
does not limit the grade.

The report shows the limit below the grade.

The grade is `INCOMPLETE` when the tool could not examine a part of the firewall:
rules that `iptables-save` cannot show, an nftables table next to the tables of iptables,
or a translation that the tool cannot follow (`NETMAP`, `TPROXY`).
The report then shows the score and a line `not assessed` for each such part.

### Fix first

When more than one finding has a fix, the report names up to three to start with.
First come the findings whose fix alone gives a better grade, then the findings with
the highest gain. The number at the right is what the score gains when you fix only
that finding. It can be less than the deduction of the finding, because a category
cannot lose more than its maximum.

### Findings

The findings are in order of severity:

- **CRITICAL**: Docker bypasses an INPUT rule that names the port, for all sources.
- **HIGH**: a chain that accepts by default, no rules, a port of remote administration
  or of a database that is open to all sources, wide open port ranges.
- **MEDIUM**: other ports that are open to all sources, open ports with a rate limit,
  shadowed rules, and rules that do not have the effect that they are written for.
- **LOW**: ports of public services (mail, DNS, web) that are open to all sources,
  and ports that need a specific source port.
- **INFO**: notes that need no action, for example a port that you declared public.
  The text report shows them only with `--verbose`.

Each finding has a number (`F1`, `F2`, ...) and shows:

- what the tool found, and why it matters,
- the rules that cause it, as `table/chain #number`. For a rule in a chain of a program,
  for example ufw, the report shows the jumps that lead to it,
- the fix: what to do and why, then the commands, each with its purpose.

Each finding is `DEFINITE` or `POSSIBLE`.
The tool cannot evaluate some predicates, for example packet marks.
A finding that depends on such a predicate is `POSSIBLE`.

Some predicates do not make a finding uncertain:

- A rate limit, a connection limit or a time window does not restrict the sources.
  The port is open, and the finding shows the condition (`Limited by: rate limit`).
- An ipset, a MAC address or a GeoIP match restricts the sources to a set that the tool
  cannot read. The scope is then `RESTRICTED`, and the report names the set.

Findings that say the same thing for IPv4 and IPv6 are one finding for both families.
More than 8 open ports of one severity are one finding with a list.
Services that are open only because INPUT accepts by default are one finding:
the finding about the default has the cause and the fix.

### Commands in a fix

The tool writes a command only when the command keeps the restrictions of the rule
that it changes. Otherwise, the fix is a description.

- All values from the rules are in shell quotes, for example `--comment 'my rule'`.
- `<trusted-cidr>` is a placeholder for the addresses of your clients. A shell refuses
  a command with a placeholder, so that a command that is not complete cannot run.
- When a program writes the rules, a change with `iptables` is lost when the program loads
  its rules again. The fix then names the program:

  | Program | The fix gives |
  | --- | --- |
  | ufw | `ufw` commands |
  | firewalld (iptables backend) | `firewall-cmd` commands for the zone of the rule |
  | csf | the line for `/etc/csf/csf.allow`, the list in `csf.conf` to change, and `csf -r` |
  | shorewall | the rule for `/etc/shorewall/rules`, and `shorewall check && shorewall reload` |
  | Kubernetes (kube-proxy) | what to change in the Service, and a rule in the raw table that filters the port in front of the translation |
  | Docker | rules for `DOCKER-USER` |
  | fail2ban, libvirt and others | a description of where to make the change |

CAUTION: The commands change the access to the system. Test each change before you use
it on a production system. An incorrect firewall change can lock you out.

### Open ports

The report lists the ports for which INPUT accepts new connections, with their sources.
The tool does not need the listening sockets for this list.
`all ports that no rule names` shows what the firewall does by default.
With the listening sockets, each port shows the process that listens on it.

A rule of `nat/PREROUTING` can send a port to a different port of the host itself
(`REDIRECT`, or `DNAT` to an address of the host). INPUT then sees the packet with the
new port. The list shows such a port as `80 → 8080`: clients connect to port 80, and the
process on port 8080 answers. A rule for port 8080 decides about both ports.
The findings are about the port that the clients use: a web server behind `80 → 8080`
is judged as a web server.

An entry such as `192.0.2.10:2222 → 192.0.2.10:22` holds for one address of the host only,
because a rule names that address.

A `DNAT` to `127.0.0.1` reaches the host only when `route_localnet` is set.
Saved rules do not show that setting, and the entry is then `possible`.

### Translated ports

Ports that `nat/PREROUTING` translates to a different host pass `filter/FORWARD` and not
`filter/INPUT`. The report lists them apart, with the sources that FORWARD accepts.
These are Docker published ports, node ports and load-balancer addresses of Kubernetes
(kube-proxy), and port forwards of a router. The tool finds them by following a packet
through the chains, so a port that is matched in one chain and translated in a different
chain is found too.

- A port that the rules share among several destinations (the pods of a Kubernetes service)
  is one entry with all destinations.
- `8443/tcp → 192.168.1.50:443: any source, possible` means that a FORWARD rule names an
  interface that the tool does not know. With the interfaces of the host (live analysis or
  a snapshot), the result is definite.
- The tool does not examine the cluster addresses of Kubernetes services. A cluster address
  is not an address of the node. Only hosts that route the service network through the node
  can reach it. A note gives the number of these addresses.
- On a host that does not route packets (`ip_forward` is 0), no port goes to a different host.
  A note says so.

### Listening sockets

`--verbose` and the HTML report show each listening socket with its status:

| Status | Meaning |
| --- | --- |
| `EXPOSED`, `SUBNET`, `RESTRICTED`, `LOCALNET`, `WHITELISTED` | Reachable from other hosts, with this scope of sources |
| `INTERNAL` | Reachable only through a bridge of containers or virtual machines of this host (`docker0`, `virbr0`) |
| `DOCKER: ...` | The port is published by Docker; the scope is that of the forwarded path |
| `FILTERED` | Not reachable from other hosts |
| `LOCALHOST` | Bound to a loopback address or to the loopback device |
| `NOT ANALYZED` | The address family of the socket was not examined |

The HTML report shows the same statuses in words, for example `open to any source`.

A socket that `ss` shows as `address%device` receives packets only from that device.
The tool evaluates it for that interface only.

### Notes

A line that starts with `note:` says what the tool did not read, for example the rules
of one address family, or what limits the result, for example the reverse-path filter.
A line that starts with `not assessed:` names a part that the tool
could not examine. Only these lines make the grade `INCOMPLETE`.

## The recommended baseline

`--baseline` writes a recommended baseline for IPv4 and IPv6. The HTML report also has it.
The usual report only names the option.

```bash
iptables-analyzer --baseline            # IPv4 and IPv6 with notes
sudo iptables-analyzer --baseline=4 > baseline.v4
sudo iptables-analyzer --baseline=6 > baseline.v6
```

The value must follow `=`. Hosts usually get global IPv6 addresses automatically,
and IPv4 rules do not protect them. Thus the tool always writes both families.

The baseline:

- drops incoming and forwarded traffic by default, and accepts outgoing traffic,
- accepts loopback traffic, `ESTABLISHED,RELATED` traffic and rate-limited ping,
- accepts SSH with a per-source `hashlimit`,
- keeps IPv6 operational: neighbor discovery, router advertisements (hop limit 255),
  MLD queries and DHCPv6 replies,
- drops `INVALID` packets and spoofed loopback sources,
- shows the other listeners as commented rules,
- on Docker hosts, adds commented `DOCKER-USER` rules for each published port.

With `--noflush`, the baseline replaces only `INPUT` (and `DOCKER-USER` on Docker hosts).
The Docker chains stay.

The baseline keeps what it cannot know:

- Jumps from `INPUT` to chains of other programs (fail2ban, libvirt, Tailscale) are in the
  baseline again, before the SSH rules. Rules in those chains are not part of the baseline.
- The rules that `DOCKER-USER` has now are in the file as comments.
- A host that routes packets with a `FORWARD` policy of ACCEPT keeps that policy.
- A TCP socket that only systemd holds can be a socket-activated `sshd`. The notes name the port.

CAUTION: Do not apply the baseline on a host that ufw manages. Use ufw to change its rules.
The notes of the baseline show this caution when the rules have ufw chains.

To apply the baseline with an automatic rollback:

1. Keep a second SSH session open.
2. Write a script that restores the baseline:

   ```bash
   printf '#!/bin/sh\nexec iptables-restore --noflush /root/baseline.v4\n' > /root/apply.v4
   chmod +x /root/apply.v4
   ```

3. Apply the script. Confirm in 60 seconds, or `iptables-apply` restores the old rules:

   ```bash
   iptables-apply -t 60 -c /root/apply.v4
   ```

4. Do steps 2 and 3 again for IPv6 with `ip6tables-restore` and `ip6tables-apply`.
5. Save the result with the mechanism of your distribution,
   for example `iptables-save > /etc/iptables/rules.v4` with iptables-persistent.

CAUTION: On Docker hosts, always use `--noflush`.
A full restore deletes the Docker chains and disconnects all containers until dockerd restarts.

Without rule files and without root, `--baseline` writes a generic baseline.

## The sandbox

`--sandbox=auto` (the default) confines the tool after it has read its input.
`--sandbox=strict` stops when the full sandbox is not available. `--sandbox=off` turns it off.
`--verbose` and the HTML report show the sandbox status. For more data, see [security.md](security.md).

## Examples

### A basic secure configuration

```bash
# Set the default policies to DROP
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP

# Accept loopback traffic
sudo iptables -A INPUT -i lo -j ACCEPT

# Accept established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Accept SSH with a rate limit for each source
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/min --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name ssh -j DROP
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Accept HTTP and HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Accept ICMP
sudo iptables -A INPUT -p icmp -j ACCEPT
```

Examine it, and tell the tool that the web ports are public:

```bash
sudo iptables-analyzer --public tcp/80,tcp/443
```

### Docker with restricted access

DOCKER-USER sees the packets after DNAT. Thus, match the original published port, not `--dport`.
`--ctdir ORIGINAL` keeps the replies to the outgoing connections of the containers.

```bash
sudo iptables -I DOCKER-USER 1 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -s 10.0.0.0/8 -j RETURN
sudo iptables -I DOCKER-USER 2 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP
```

These rules do not see packets that are routed directly to a container address.
Docker 28 and later drop these packets in `raw/PREROUTING`.
For older releases, and for the `routed` and `nat-unprotected` gateway modes,
also refuse connections into the bridge that do not come through DNAT:

```bash
sudo iptables -I DOCKER-USER -o docker0 ! -i docker0 -m conntrack --ctstate NEW -m conntrack ! --ctstate DNAT -j DROP
```

### Examine a Docker host

```bash
sudo iptables-analyzer --html report.html
```

The report shows each published port with the sources that FORWARD accepts.
It identifies bypassed INPUT rules, ineffective DOCKER-USER and FORWARD rules, and direct routing.
