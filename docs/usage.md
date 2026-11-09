# Usage

This document gives the full procedures and describes the report.
For a short introduction, see the [README](../README.md).

## Live analysis

Run the tool as root without rule files:

```bash
sudo iptables-analyzer
```

The tool then reads:

- the rules from `iptables-save` and `ip6tables-save`,
- the listening services from `ss -tlnp` and `ss -ulnp`,
- the network interfaces and their addresses.

The interface list lets the tool evaluate `-i` and local-address predicates exactly.

## File analysis

1. Save the rules on the host that you want to examine:

   ```bash
   sudo iptables-save > /tmp/rules.v4
   sudo ip6tables-save > /tmp/rules.v6
   ```

2. Save the listening services on the same host.
   The tool accepts `ss -tlnp` and `ss -ulnp` output, and the combined `ss -tulnp` format.

   ```bash
   sudo ss -tulnp > /tmp/services.txt
   ```

3. Examine the files on any host:

   ```bash
   iptables-analyzer --file /tmp/rules.v4 --file6 /tmp/rules.v6 --services-file /tmp/services.txt
   ```

The script `examples/save-rules.sh [DIRECTORY]` saves the two rule files in one step.

In file mode, the tool does not examine the services of the host that runs it.
Without `--services-file`, the service exposure and the grade are `INCOMPLETE`.
A missing or malformed services file is a fatal error.
A valid `ss` file with only a header means a host without listeners.

The tool reads at most 64 MiB of rules and 16 MiB of `ss` output.
Process substitution works, for example `-f <(sudo iptables-save)`.

## Other modes

```bash
# Show only the security score
iptables-analyzer -f /tmp/rules.v4 --score-only

# Write the result as JSON
iptables-analyzer --file /tmp/rules.v4 --json

# Show all rules, empty chains and the raw rule text
iptables-analyzer --file /tmp/rules.v4 --verbose

# Examine only IPv4 or only IPv6
iptables-analyzer -4 --file /tmp/rules.v4
iptables-analyzer -6 --file6 /tmp/rules.v6

# Do not use colors (for logs and pipes)
iptables-analyzer --no-color

# Write only the recommended baseline (the value must follow "=")
iptables-analyzer --baseline            # IPv4 and IPv6 with notes
sudo iptables-analyzer --baseline=4 > baseline.v4
sudo iptables-analyzer --baseline=6 > baseline.v6

# Stop if the full sandbox is not available
sudo iptables-analyzer --sandbox=strict
```

## The recommended baseline

Each report ends with a recommended baseline for IPv4 and IPv6.
Hosts usually get global IPv6 addresses automatically, and IPv4 rules do not protect them.
Thus the tool always writes both families.

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

## The report

### Security score

The score is 0 to 100. The grade is A to F when the tool examined all categories.
When the tool did not have service data, or could not examine a firewall translation,
the grade is `INCOMPLETE`. The report then shows the subtotal and a list of the categories that it did not examine.

| Category | Deductions |
| --- | --- |
| Policy | -15 for INPUT ACCEPT, -10 for FORWARD ACCEPT (maximum -25). OUTPUT ACCEPT is only advisory. |
| Exposure | -5 for each well-known TCP/UDP port and -2 for each high port open to all sources (maximum -25). A port open on IPv4 and IPv6 counts one time. Docker published ports open to all sources also count. |
| Shadows and bypasses | -12 for each critical, -5 for each high and -2 for each medium Docker finding; -5 for each high-severity and -2 for each other shadowed rule (maximum -25). |
| Hygiene | -5 without a conntrack `ESTABLISHED` rule, -5 without a final DROP, -2 for dead rules. |
| IPv6 | -10 when IPv6 is in scope but there are no IPv6 rules, -5 when Docker does not filter IPv6 forwarding. |

### Findings

The report sorts the findings by severity:

- **CRITICAL**: Docker bypasses an explicit INPUT restriction for all sources.
- **HIGH**: exposed services on well-known ports, missing policies.
- **MEDIUM**: effectiveness problems and possible hygiene problems.
- **LOW**: best-practice suggestions.
- **INFO**: unused rules and small findings.

Each finding is `DEFINITE` or `POSSIBLE`.
Some predicates are not decidable, for example ipsets, marks and rate limits.
A finding that depends on such a predicate is `POSSIBLE`.

### Recommendations

The recommendations are in order of priority. Each one identifies the table, the chain and the rule.
The tool writes a replacement command only when the command keeps the original restrictions.
Otherwise, it gives a description.

All values from the rules are in shell quotes, for example `--comment 'my rule'`.

### Sandbox line

The overview shows the sandbox status, for example:

```text
Sandbox:         Landlock ABI 7 (filesystem, exec, tcp, abstract-unix-sockets, signals) · root dropped
```

For more data, see [security.md](security.md).

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

# Accept SSH with a rate limit
sudo iptables -I INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 5 -j ACCEPT

# Accept HTTP and HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Accept ICMP
sudo iptables -A INPUT -p icmp -j ACCEPT
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
sudo iptables-analyzer
```

The report shows each published port with its FORWARD and INPUT verdicts.
It identifies bypassed INPUT rules, ineffective DOCKER-USER and FORWARD rules, and direct routing.
