# The JSON report

`--json` writes the report as one JSON object. This is the form for scripts and other programs.
The text report and the HTML report show the same data.

```bash
sudo iptables-analyzer --json > report.json
iptables-analyzer rules.v4 rules.v6 ss.txt --json --rules
```

`--json --score-only` writes only the `score` object.

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
| `mode` | string | `live` or `file` |
| `host` | string | The host name, in live mode |
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
| `managers` | list of strings | The programs whose chains the rules contain, for example `docker` or `ufw` |

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

The `docker_` codes are also used for a port forward that is not made by Docker.
`title` and `detail` then do not speak of Docker.

### Rule reference

| Field | Type | Contents |
| --- | --- | --- |
| `family` | number | `4` or `6` |
| `table`, `chain` | string | Where the rule is |
| `num` | number | The position of the rule in its chain, from 1 |
| `spec` | string | The rule as `iptables-save` prints it, without `-A CHAIN` |
| `role` | string | What the rule does in the finding: `accepts`, `causes`, `shadows`, `shadowed`, `translates`, `bypassed` or `ineffective` |
| `path` | list of strings | For a rule in a user-defined chain: the jumps from the built-in chain to the rule, each as `CHAIN #N`. The last entry is the rule |

### Open port

| Field | Type | Contents |
| --- | --- | --- |
| `families` | list of numbers | `4`, `6` or both |
| `protocol` | string | `tcp` or `udp` |
| `first`, `last` | number | The range of ports. Both are `0` when `default` is `true` |
| `default` | boolean | `true` for the entry that stands for all ports that no rule names |
| `scope` | string | The sources that reach the port. See [Scope](#scope) |
| `certainty` | string | `DEFINITE` or `POSSIBLE` |
| `condition` | string | A condition that all sources can meet, for example `rate limit` or `source port 67` |
| `restriction` | string | The set that restricts the sources, for example an ipset, when `scope` is `RESTRICTED` |
| `interfaces` | list of strings | The interfaces for which the entry applies, when not all |
| `rules` | list | The [rules](#rule-reference) that accept. Empty when the policy of the chain accepts |
| `listeners` | list of strings | The processes that listen in the range |
| `public` | boolean | `true` when `--public` names the ports |

### Forwarded port

| Field | Type | Contents |
| --- | --- | --- |
| `family` | number | `4` or `6` |
| `protocol` | string | `tcp` or `udp` |
| `host_addr` | string | The local address that the rule matches. Absent for all local addresses |
| `host_port`, `host_port_end` | number | The range of ports on this host |
| `dest_addr`, `dest_port`, `dest_port_end` | | Where the packets go |
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
| `RESTRICTED` | A set that the tool cannot read: an ipset, a MAC address, a GeoIP match |
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
```

For a result in the exit status, use `--fail-on` and `--min-grade` instead:
see [usage.md](usage.md#use-in-scripts).
