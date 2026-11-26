# The JSON report

`--json` writes the report as one JSON object. This is the form for scripts and other programs.
The text report and the HTML report show the same data.

```bash
sudo iptables-analyzer --json > report.json
iptables-analyzer rules.v4 rules.v6 ss.txt --json --rules
```

`--json --score-only` writes only the `score` object.
`--json` with `--trace` writes a [trace object](#the-trace-object), and with `--diff`
a [comparison object](#the-comparison-object).

## Stability

`schema_version` is `2`. The number changes when a field is removed or changes its meaning.
New fields can come without a change of the number: ignore the fields that you do not know.

The values of `code`, `severity`, `certainty`, `category`, `status`, `scope` and `kind`
are stable names. Use them in scripts. `title`, `detail` and the text of a fix are for
persons, and their words can change in any release.

Version 2 replaces the form of 0.7.x, which was a copy of the internal data of the tool.
The findings were in five lists there, and the report always held all rules.

## The report object

| Field | Type | Contents |
| --- | --- | --- |
| `schema_version` | number | `2` |
| `tool` | object | `name`, `version` and `url` of the program |
| `generated` | string | The time of the run (RFC 3339) |
| `mode` | string | `live`, `file` or `snapshot` |
| `host` | string | The host name, for a live analysis and for a snapshot |
| `captured` | string | For a snapshot: the time when the host was read (RFC 3339) |
| `inputs` | list of strings | The names of the files that were read |
| `families` | list | One [family](#family) object for IPv4 and one for IPv6 |
| `score` | object | The [score](#score) |
| `counts` | object | The number of findings of each severity: `critical`, `high`, `medium`, `low`, `info` |
| `findings` | list | The [findings](#finding), the most severe first |
| `open_ports` | list | The [ports](#open-port) for which INPUT accepts new connections |
| `forwarded_ports` | list | The [ports](#forwarded-port) that `nat/PREROUTING` translates to a different host |
| `services_known` | boolean | `false` when no list of listening sockets was read |
| `services` | list | The listening [sockets](#service) |
| `notes` | list | [Notes](#note) about the analysis |
| `sandbox` | object | The [sandbox](#sandbox) status |
| `baseline` | object | The recommended baseline: `ipv4` and `ipv6` (text in iptables-restore format) and `notes` |
| `rulesets` | list | The [rules](#ruleset) of the input. Only with `--rules` |

A field that is empty can be absent.

### Family

| Field | Type | Contents |
| --- | --- | --- |
| `version` | number | `4` or `6` |
| `status` | string | `ANALYZED`, `NO_RULES` (the save tool printed no table: all traffic is accepted), `EXCLUDED` (`-4` or `-6`), `NOT_SUPPLIED` (no file for this family) or `UNREADABLE` (native nftables rules) |
| `tables`, `chains`, `rules` | number | What the input holds |
| `policies` | object | The policy of `INPUT`, `FORWARD` and `OUTPUT` in the filter table |
| `managers` | list of strings | The programs whose chains the rules contain, for example `docker`, `ufw`, `firewalld`, `csf`, `shorewall`, `kubernetes`, `flannel`, `libvirt` or `fail2ban` |

### Score

| Field | Type | Contents |
| --- | --- | --- |
| `total` | number | 0 to 100 |
| `grade` | string | `A`, `B`, `C`, `D`, `F` or `INCOMPLETE` |
| `complete` | boolean | `false` when a part of the firewall could not be examined |
| `cap` | string | Why the grade is below the grade that the points give |
| `unassessed` | list of strings | The parts that could not be examined |
| `categories` | list | For each category: `key` (`policy`, `exposure`, `paths`, `hygiene`, `ipv6`), `label`, `max` and `lost` |

`total` is 100 minus the `lost` points of the categories.
For the deductions, see [usage.md](usage.md#score-and-grade).

### Finding

| Field | Type | Contents |
| --- | --- | --- |
| `id` | string | `F1`, `F2`, ... in the order of the report. The number is for one report only |
| `code` | string | The kind of finding. See the list below |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO` |
| `certainty` | string | `DEFINITE` or `POSSIBLE` |
| `category` | string | The category of the score that the finding belongs to |
| `families` | list of numbers | `4`, `6` or both |
| `title` | string | One line |
| `detail` | string | What was found, and why it matters |
| `ports` | list of strings | The ports of the finding, for example `22/tcp` or `8000-8100/tcp` |
| `rules` | list | The [rules](#rule-reference) that the finding is about |
| `fix` | object | `summary` (what to do and why) and `steps`. Each step has `text` and `command` |
| `points` | number | The deduction of the finding |
| `gain` | number | What `score.total` gains when only this finding is fixed. It is less than `points` when the category already lost more than its maximum |
| `grade_after` | string | The grade after that fix, when it is better than `score.grade` |

A `command` is for a root shell. All values from the rules are in shell quotes.
Text in angle brackets, for example `<trusted-cidr>`, is a placeholder.

The codes:

| Code | Finding |
| --- | --- |
| `no_rules` | No rules are loaded for an address family |
| `policy_accept` | A chain accepts the traffic that no rule names, by its policy or by a rule |
| `family_blocked` | An address family with a DROP policy and no accepting rule |
| `broad_accept` | A range of 1,024 or more ports is open to all sources |
| `exposed_service` | A service listens on a port that is open to all sources |
| `open_port` | A port is open to all sources. Used when no list of listening sockets was read |
| `unused_rule` | A rule opens a port on which nothing listens |
| `shadowed_rule` | A rule never applies, because an earlier rule matches the same packets |
| `dead_rule` | Rules after a rule that ends the chain |
| `missing_conntrack` | INPUT drops the replies to the connections of the host |
| `missing_loopback` | INPUT drops loopback traffic |
| `ipv6_ndp_blocked` | INPUT drops IPv6 neighbor discovery or router advertisements |
| `ipv6_wider_than_ipv4` | IPv6 opens ports that IPv4 restricts or filters |
| `docker_bypass` | A translated port is open although INPUT refuses it |
| `docker_published_port` | A translated port is open to all sources |
| `docker_ineffective_rule` | A rule on the forwarding path never matches translated traffic |
| `docker_shadowed_rule` | A rule comes after the ACCEPT rules of Docker |
| `docker_fragile_rule` | A rule above the jumps of Docker, which `dockerd` moves |
| `docker_direct_route` | Containers are reachable by direct routing |
| `docker_ipv6_unfiltered` | Docker does not filter IPv6 forwarding |

The `docker_` codes are also used for a port that something else sends to a different host:
a port forward of a router, or a node port of Kubernetes.
`title` and `detail` then do not speak of Docker.

`exposed_service` and `open_port` are about the port that clients connect to. When
`nat/PREROUTING` sends that port to a different local port, the finding has the redirecting
rule in `rules` with the role `redirects`, and the service of `exposed_service` listens on
the new port.

### Rule reference

| Field | Type | Contents |
| --- | --- | --- |
| `family` | number | `4` or `6` |
| `table`, `chain` | string | Where the rule is |
| `num` | number | The position of the rule in its chain, from 1 |
| `spec` | string | The rule as `iptables-save` prints it, without `-A CHAIN` |
| `role` | string | What the rule does in the finding: `accepts`, `causes`, `shadows`, `shadowed`, `translates`, `redirects`, `bypassed` or `ineffective` |
| `path` | list of strings | For a rule in a user-defined chain: the jumps from the built-in chain to the rule, each as `CHAIN #N`. The last entry is the rule |

### Open port

| Field | Type | Contents |
| --- | --- | --- |
| `families` | list of numbers | `4`, `6` or both |
| `protocol` | string | `tcp` or `udp` |
| `address` | string | The address of the host for which the entry applies, when a rule of `nat/PREROUTING` names one. Absent for all other addresses |
| `first`, `last` | number | The range of ports. Both are `0` when `default` is `true` |
| `redirect` | object | Present when `nat/PREROUTING` sends the ports to different local ports. See below |
| `default` | boolean | `true` for the entry that stands for all ports that no rule names |
| `scope` | string | The sources that reach the port. See [Scope](#scope) |
| `certainty` | string | `DEFINITE` or `POSSIBLE` |
| `condition` | string | A condition that all sources can meet, for example `rate limit` or `source port 67` |
| `restriction` | string | The set that restricts the sources, for example an ipset, when `scope` is `RESTRICTED` |
| `interfaces` | list of strings | The interfaces for which the entry applies, when not all |
| `rules` | list | The [rules](#rule-reference) that accept. Empty when the policy of the chain accepts |
| `listeners` | list of strings | The processes that listen in the range. For an entry with `redirect`: the processes on the new ports |
| `public` | boolean | `true` when `--public` names the ports |

The `redirect` object:

| Field | Type | Contents |
| --- | --- | --- |
| `first`, `last` | number | The local ports that receive the connections. Both are `0` when the port stays and only the address changes |
| `address` | string | The new local address of a `DNAT`. Absent for `REDIRECT`, which uses the address of the ingress interface |
| `rules` | list | The [rules](#rule-reference) that translate, one for each address family |

For an entry with `redirect`, `scope` and `rules` are those of the new port: INPUT sees the
packet with it.

### Forwarded port

| Field | Type | Contents |
| --- | --- | --- |
| `family` | number | `4` or `6` |
| `protocol` | string | `tcp` or `udp` |
| `host_addr` | string | The local address that the rule matches. Absent for all local addresses |
| `host_port`, `host_port_end` | number | The range of ports on this host |
| `dest_addr`, `dest_port`, `dest_port_end` | | Where the packets go |
| `destinations` | list of strings | All destinations as `address:port`, when the rules share the port among more than one (the pods of a Kubernetes service). `dest_addr` is the first |
| `bridge` | string | The bridge of the destination, when it is known |
| `docker` | boolean | `true` when Docker made the rule |
| `forward_scope` | string | The sources that `filter/FORWARD` accepts. Absent when no source gets through |
| `input_scope` | string | The sources that `filter/INPUT` accepts for the same packet |
| `certainty` | string | `DEFINITE` or `POSSIBLE` |
| `interfaces` | list of strings | The ingress interfaces for which the entry applies, when not all |
| `rule` | object | The [rule](#rule-reference) that translates the port |

### Service

| Field | Type | Contents |
| --- | --- | --- |
| `protocol` | string | `tcp` or `udp` |
| `address`, `port` | | Where the socket listens |
| `device` | string | The device that the socket is bound to |
| `process`, `pid`, `processes` | | The process that holds the socket, and all processes when there is more than one |
| `socket_family` | string | `ipv4`, `ipv6` or `dual` |
| `status` | string | `REACHABLE`, `FILTERED`, `LOCALHOST`, `INTERNAL`, `DOCKER_PUBLISHED` or `NOT_ANALYZED` |
| `scope` | string | For `REACHABLE` and `DOCKER_PUBLISHED`: the widest [scope](#scope) of sources that reach the socket |

### Scope

| Value | Sources |
| --- | --- |
| `EXPOSED` | Any source |
| `SUBNET` | Specific public networks |
| `RESTRICTED` | A set that the tool cannot read: an ipset without its contents, a MAC address, a GeoIP match |
| `LOCALNET` | Private address ranges |
| `WHITELISTED` | Single hosts |

### Note

| Field | Type | Contents |
| --- | --- | --- |
| `kind` | string | `incomplete` for a part that could not be examined: the grade is then `INCOMPLETE`. `scope` for what the tool did and did not read |
| `area` | string | The part of the analysis: `rules`, `docker`, `nat` or `services` |
| `text` | string | The note |

### Sandbox

| Field | Type | Contents |
| --- | --- | --- |
| `mode` | string | `auto`, `strict` or `off` |
| `landlock` | boolean | A Landlock domain confines the process |
| `landlock_abi` | number | The Landlock ABI of the kernel |
| `restricted` | list of strings | What the domain denies |
| `privileges_dropped` | boolean | Root privileges were dropped |
| `notes` | list of strings | Why a part of the sandbox is missing |

### Ruleset

Only with `--rules`. One object for each address family: `family` and `tables`.
A table has `name` and `chains`. A chain has `name`, `policy` (built-in chains),
`owner` (the program that manages the chain, when its name shows it) and `rules`.

| Field of a rule | Type | Contents |
| --- | --- | --- |
| `num` | number | The position in the chain, from 1 |
| `spec` | string | The rule without `-A CHAIN` |
| `target` | string | The target |
| `jump` | boolean | `true` when the target is a chain of the same table |
| `findings` | list of strings | The `id` of each finding that names the rule |

## The trace object

`--json --trace PACKET` writes this object instead of the report:

| Field | Type | Contents |
| --- | --- | --- |
| `schema_version`, `tool`, `generated`, `mode`, `host`, `captured`, `inputs` | | As in the report object |
| `trace` | object | The way of the packet |

The `trace` object:

| Field | Type | Contents |
| --- | --- | --- |
| `packet` | object | The packet: `protocol`, `source`, `source_port`, `destination`, `port`, `in`, `out`, `state`, `icmp_type`. A field that was not given is absent |
| `family` | number | `4` or `6` |
| `stages` | list | The chains that the packet passes, in order. Each has `table`, `chain`, `steps` and `result` (how the packet leaves the chain, in words) |
| `verdict` | string | `ACCEPT`, `DROP`, `REJECT` or `UNDECIDED` |
| `certain` | boolean | `false` when a rule that can match or not gives a different verdict |
| `decided_by` | string | The rule or the policy that gave the verdict, for example `filter/INPUT #7` |
| `delivery` | string | For `ACCEPT`: `local` when the host receives the packet, `forward` when it sends the packet to a different host |
| `destination`, `port` | | For `ACCEPT`: the destination after the address translation |
| `assumptions` | list of strings | What the trace took for granted, for example the source port |
| `alternatives` | list | How the packet ends when rules that can match or not do match. Each has `if`, `verdict`, `decided_by`, `delivery`, `destination` and `port` |

A step is one rule that the packet matched:

| Field | Type | Contents |
| --- | --- | --- |
| `table`, `chain`, `num`, `spec` | | The rule |
| `depth` | number | `0` for a rule in the built-in chain, one more for each jump |
| `match` | string | `yes`, or `maybe` when the packet alone does not decide. The trace then goes on without the rule |
| `action` | string | `ACCEPT`, `DROP`, `REJECT`, `RETURN`, `jump`, `goto`, the target of a translation (`DNAT`, `REDIRECT`, `NETMAP`), `QUEUE` or `NFQUEUE`, `continue` for a rule that does not decide, or `skipped` for a `maybe` |
| `note` | string | What a `maybe` depends on, or what the rule changed (a mark) |

## The comparison object

`--json --diff OLD NEW` writes this object instead of the report:

| Field | Type | Contents |
| --- | --- | --- |
| `schema_version`, `tool`, `generated` | | As in the report object |
| `old`, `new` | object | For each input: `mode`, `host`, `captured`, `inputs`, `families`, `score` and `counts`, as in the report object |
| `added` | list | The [findings](#finding) that only the new input has |
| `removed` | list | The findings that only the old input has |
| `changed` | list | Findings of both inputs whose severity, certainty, points or address families differ. Each has `old` and `new` |
| `ports` | list | The ports of the host whose state differs. See below |
| `forwarded_ports` | list | The [ports](#forwarded-port) that go to a different host and differ. Each has `old`, `new` or both |
| `notes` | list of strings | What could not be compared, for example an address family that only one input has |

Findings are matched by `code` and by what they are about (the port, the chain), not by `id`.

A port change:

| Field | Type | Contents |
| --- | --- | --- |
| `family` | number | `4` or `6` |
| `protocol` | string | `tcp` or `udp` |
| `address` | string | For ports of one address of the host |
| `first`, `last` | number | The range of ports |
| `old`, `new` | object | The state before and after: `scope` (absent for a closed port), `certainty`, `condition`, and `local_port` when the port is redirected to one local port |

## Examples

```bash
# The grade
iptables-analyzer rules.v4 --json | jq -r '.score.grade'

# The titles of the high and critical findings
iptables-analyzer rules.v4 --json | jq -r '.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL") | .title'

# All commands of the fixes
iptables-analyzer rules.v4 --json | jq -r '.findings[].fix.steps[]?.command'

# The ports that are open to all sources
iptables-analyzer rules.v4 --json | jq -r '.open_ports[] | select(.scope == "EXPOSED" and (.default | not)) | "\(.first)/\(.protocol)"'

# The verdict for one packet
iptables-analyzer rules.v4 --json --trace 'tcp 203.0.113.5 -> :22' | jq -r '.trace.verdict'

# The ports that a change opens to all sources
iptables-analyzer --json --diff old.v4 new.v4 | jq -r '.ports[] | select(.new.scope == "EXPOSED") | "\(.first)-\(.last)/\(.protocol)"'
```

For a result in the exit status, use `--fail-on`, `--min-grade` and `--expect` instead:
see [usage.md](usage.md#use-in-scripts).

## The snapshot file

`--snapshot FILE` writes a JSON file of a different kind: the input of an analysis, not its
result. It has `"format": "iptables-analyzer snapshot"` and `"version": 1`, and it holds the
output of the tools as text (`iptables_save`, `ip6tables_save`, `ss`, `nft_list_chains`,
`ipset_save`, `ip_route`), next to `created`, `hostname`, `interfaces` and `sysctls`.
A part that was not read is absent. The tool reads the file like the output of the tools
on a live host; other programs can read it too.
