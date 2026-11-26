# Roadmap

This plan follows the [audit of 0.7.1](docs/audit-0.7.1.md). The codes in
brackets (A1, B3, ...) refer to audit findings. Each item lists what changes,
where, and how to tell that it is done.

Order of work: Phase 1 makes the results correct inside the present structure.
Phase 2 changes the data model and the report. Phase 3 widens the analysis.

## Status

| Phase | State |
| --- | --- |
| 1. Correct results | Done (2026-11-25), not released. See `CHANGELOG.md`, section Unreleased |
| 2. Report | Done (2026-11-25), not released |
| 3. Wider analysis | Next |

Before the release: set `VERSION` (decision 3 names 0.8), give the section Unreleased
of `CHANGELOG.md` its version and date, and set the same in the manual page.
The picture in `README.md` showed the old report; the README now has a text example.

Phase 1 differs from the plan below in these points:

- 1.2: a family whose tables hold native nftables rules is left out of the analysis,
  with an assessment note. Analyzing the visible part would report a filtered host as open.
- 1.4: shadow detection had the same quadratic cost and got an index by source prefix.
- 1.5: traffic that passes a rule which drops the excess (`hashlimit --hashlimit-above ... -j DROP`,
  `ufw limit`) carries the condition "rate limit" too. A limiter in front of an ACCEPT is thus visible.
- 1.6: `missing_final_drop` and `late_conntrack` are removed. FORWARD that accepts by default is
  MEDIUM (-5) while nothing shows that the host routes packets.
- 1.7: a REDIRECT gives an assessment note and the grade INCOMPLETE until 3.1 follows it.
- 1.8: on ufw hosts the baseline only warns. Phase 2 added the fixes in ufw's own commands
  (audit D2) and joined identical advice with its findings.
- 1.9: the ceiling is F when INPUT accepts all new connections, and D when it accepts by
  default for one protocol or interface only.

Phase 2 applies the decisions below as recommended. It differs from the plan in these points:

- 2.1: the analyzer keeps its typed facts. The new package `internal/report` makes the one
  list of findings from them, with the evidence, the fix and the points of each finding.
  The renderers and the score read only that list. A finding has `families` (a list),
  `rules` and `ports` as evidence, and also `gain` and `grade_after`. The categories are
  `policy`, `exposure`, `paths`, `hygiene` and `ipv6`.
- 2.2: "Fix first" puts the findings first whose fix alone gives a better grade. The number
  is the real gain of the score, after the limits of the categories.
  Services that are open only because INPUT accepts by default are one finding.
- 2.3: the page is written by `html/template` on the server side, not from an embedded
  data block. Text from the input stands only in text nodes; no attribute value comes from
  it. A test replaces every string of a report by markup and compares the structure of the
  page; a fuzz target reads the page strictly. The filters are the severity and a text
  search (the search also finds a category or an address family). The baseline has a copy
  button, not a download.
- 2.4: the thresholds are two options, `--fail-on SEVERITY` and `--min-grade GRADE`.
- 2.5: an open port without a listener stays INFO (`unused_rule`), without points.
  The ports of public services (25, 53, 80, 443, 465, 587, 993, 995) are a class of their
  own: LOW, 1 point.
- 3.2 is done in part: fixes for rules in ufw chains are `ufw` commands, and the report
  names the programs whose chains the rules contain. For the other programs the fix says
  where to make the change.

## Decisions

These choices shape Phase 2. The recommended option is applied unless changed.

| # | Question | Recommended |
| --- | --- | --- |
| 1 | Baseline in every report? | No. One line points to `--baseline`. The HTML report has it in a tab |
| 2 | Rule tables in the text report? | Only with `--rules` (and in HTML). Findings quote the rules they involve |
| 3 | JSON format | Break it once in 0.8: `schema_version`, one `findings` list, text severities, no embedded rulesets |
| 4 | Grade without an `ss` file | A complete grade from the rules alone. Listener data raises or lowers single findings |
| 5 | HTML report | `--html FILE`: one self-contained file, no network requests, strict CSP, printed next to the terminal report |
| 6 | Exit status | 0 for a completed run; `--fail-on high` (or a grade) returns 2 for CI |
| 7 | Ports that are public on purpose | `--public tcp/80,tcp/443`: reported as INFO, no deduction |

## Phase 1: correct results

No change to the report layout. Every item ends with a regression test built
from the input named in the audit appendix.

### 1.1 Parser: arguments by table, quoted tokens [C1, C2, C5]

- The tokenizer keeps whether a token was quoted. A quoted token is never an
  option or a negation.
- A table gives the argument count of known options (`--comment` 1,
  `--tcp-flags` 2, `--match-set` 2, `--log-prefix` 1, ...). Unknown options
  keep the present heuristic.
- Files: `internal/parser/parser.go`.
- Done when: `dash-comment` and `syn` parse; a table test covers one real
  `iptables-save` line for each supported extension; the fuzz target passes.

### 1.2 Input states: loaded, empty, not supplied [A3, A4, B11]

- Empty `iptables-save` output or an empty file is a ruleset without rules:
  every chain accepts. It is analyzed and reported, not refused.
- A family without a file in file mode is "not supplied": no deduction, a
  visible note, and no claim about that family.
- The comments `iptables-legacy tables present` and `is incompatible, use
  'nft' tool` become assessment notes and make the grade INCOMPLETE.
- Files: `internal/loader`, `internal/parser`, `internal/models`,
  `internal/scorer`, `internal/recommender`, `cmd/root.go`.
- Done when: `empty-v6`, `nft-incompatible`, `legacy-warning` and
  `v4-only-file` give the expected notes; a `cmd` test runs live mode with
  empty tool output.

### 1.3 `ss` parser [C3, B7]

- Read the process list from the whole row; keep every process of a socket.
- A `%device` suffix limits the evaluation to that ingress interface.
- Files: `internal/services/services.go`, `internal/analyzer/analyzer.go`.
- Done when: `ss-spaces` keeps the name; a socket-activated sshd is recognized;
  `0.0.0.0%virbr0:67` is evaluated for `virbr0` only.

### 1.4 Source sets as address ranges [C4]

- Replace prefix lists with sorted, disjoint address ranges
  (`internal/analyzer/addrset.go`). Convert to prefixes only for display and
  classification.
- Done when: all analyzer tests pass unchanged; a property test compares the
  set operations with brute force on a small address space; `f2b-3000` runs
  in less than one second and a benchmark guards it.

### 1.5 Kinds of undecidable predicates [B3, B4, B5, B6]

- Model what is decidable: `--tcp-flags`/`--syn` for new TCP connections,
  `iprange`, `multiport --ports`.
- Predicates that any source can satisfy (`limit`, `hashlimit`, `connlimit`,
  `statistic`, `time`, `length`): an ACCEPT stays a definite exposure and is
  labeled "rate limited" or "conditional".
- Predicates that select an unknown subset of sources (`set` with `src`,
  `mac`, `geoip`, `recent --rcheck`): new scope `RESTRICTED`. It is not an
  exposure, costs no points, and the report names the set.
  A negated match in a DROP rule narrows the traffic that continues.
- A rule that needs a privileged source port (`--sport 67`) is LOW.
- Files: `internal/analyzer/evaluation.go`, `internal/models`, `internal/ui`.
- Done when: `allowlists`, `ipset-negated-drop`, `syn`, `limit` and the DHCP
  rule of `ufw` give the scope and certainty stated in the audit.

### 1.6 Checks that use the evaluator [A1, A2, A7, B1, B2, B10, B12, B13]

Replace the pattern checks in `effectiveness.go` with probes:

| Check | Probe | Replaces |
| --- | --- | --- |
| Default for new connections | TCP and UDP to a port that no rule names, per ingress interface | `policy_accept`, `missing_final_drop` |
| Return traffic | the same packet in state ESTABLISHED | `missing_conntrack` |
| Open ports | one probe per class of ports that the rules treat alike | `unused_rule` |
| Family parity | compare the open ports of IPv4 and IPv6 | new |
| Unreachable rules | shadowed and dead rules as one finding per cause | `shadowed_rule` + `dead_rule` |
| Blocked family | INPUT policy DROP and no reachable ACCEPT | three findings of B10 |

- The open-port result is kept in the analysis result: Phase 2 shows it as the
  attack surface and Phase 2.5 scores it.
- A wide range open to any source (more than 1,024 ports) is a HIGH finding
  even without listeners.
- OUTPUT policy ACCEPT becomes INFO.
- Done when: `accept-all`, `broad-accept`, `ufw`, `rhel`, `v6-blocked`,
  `insecure`, `negated-dport` and `nat-only` give one correct finding each and
  no false one.

### 1.7 NAT wording and severity [A5, A6, B8, B9]

- A DNAT rule outside Docker's chains is a "port forward": no Docker title,
  no `DOCKER-USER` commands.
- CRITICAL only when an INPUT rule names the published port or its address.
- Assessment notes of one kind are grouped ("600 DNAT rules without a port").
- A REDIRECT in `nat/PREROUTING` gives an assessment note until 3.1 models it.
- Done when: `router-dnat`, `trust-lan`, `k8s` and `redirect` give the
  expected text.

### 1.8 Advice [B14, D1, D3, D4, D5]

- SSH rate limit: per-source `hashlimit` DROP in front of the ACCEPT, the same
  as the baseline. A ruleset that already has it gets no recommendation.
- A service that the ruleset admits by the baseline's own rules is not HIGH:
  SSH that is rate limited per source is MEDIUM "public by design".
- Baseline: list the jumps that `-F INPUT` removes and keep them in the
  generated file; carry existing `DOCKER-USER` rules over as comments; keep the
  FORWARD policy on hosts that forward without Docker; treat every socket with
  an `sshd` process as SSH.
- Fix `--baseline 6` in texts. Group identical recommendations.
- Done when: `baseline-self` has no HIGH finding; `baseline-apply` keeps the
  fail2ban jump; a test loads the baseline in a namespace when `unshare` and
  `iptables-restore` are available.

### 1.9 Score consistency [E1, E2, E3, E6]

- A POSSIBLE finding costs half.
- Every deduction comes from a listed finding.
- The grade has a ceiling: D with an unrestricted default accept, C with any
  CRITICAL finding.
- Done when: `accept-all` is F; the sum of the listed deductions equals the
  score in every fixture.

## Phase 2: report

### 2.1 One finding model [F2, F10]

```go
type Finding struct {
    ID        string      // F1, F2, ... in report order
    Code      FindingCode // stable identifier
    Severity  Severity
    Certainty Certainty
    Category  string      // policy, exposure, nat, hygiene, ipv6, input
    Family    IPVersion   // 0 when both
    Title     string
    Detail    string      // why it matters
    Evidence  Evidence    // rules, path, service, ports, interfaces
    Fix       *Fix        // text and commands; nil when there is none
    Points    int         // deduction after weighting
}
```

- The five finding types and the separate recommendation list go away.
  The scorer, the three renderers and JSON read one list.
- JSON schema 2: `schema_version`, lower-case keys, text severities, rules
  referenced by `table/chain#n` with their text.
- Done when: no renderer or scorer code switches on a finding type; the JSON
  schema is documented in `docs/json.md`.

### 2.2 Text report [F1 to F7, F12]

```text
iptables-analyzer 0.8.0 · live · web01 · 2026-11-25 04:46

  Grade C  62/100     3 high · 9 medium · 2 low · 4 info
  Policy ▰▰▰▰▱▱▱▱▱▱ 10/25   Exposure ▰▰▰▱▱▱▱▱▱▱ 9/25   Paths ▰▰▰▰▰▰▰▱▱▱ 18/25
  Hygiene ▰▰▰▰▰▰▰▰▰▰ 15/15  IPv6 ▰▰▰▰▰▰▰▰▰▰ 10/10

  Fix first
   1. Set the INPUT policy to DROP (IPv4, IPv6)                   F1   +15
   2. Restrict 7 published ports in DOCKER-USER                   F4   +14
   3. Block direct routing to bridge br-982052ef0162              F2    +5

  HIGH  F1  INPUT accepts new connections to any port (IPv4, IPv6)
        The chain policy is ACCEPT and no rule drops the remaining traffic.
        fix   iptables -P INPUT DROP       (after the allow rules; see --baseline)

  ...

  Reachable from any source
   tcp   22 sshd · 80, 443 nginx · 8080 → 172.17.0.2:80 (docker0)
   udp   none

  Not shown: 55 rules (--rules) · 4 notes (-v) · baseline (--baseline)
  Interactive report: --html report.html
```

- Grade and counts first; then the actions that gain the most points; then
  findings by severity, each with its reason, the rule path and its fix.
- Text is wrapped to the terminal width (read before the sandbox starts).
- Bars use two glyphs, so they read without color.
- The path to the deciding rule is shown:
  `INPUT #2 → ufw-before-input #13 → ufw-user-input #4`.
- Rule tables with `--rules`; the baseline only with `--baseline`.

### 2.3 HTML report

- `--html FILE` writes one file. The file is opened before the sandbox starts.
- Contents: grade and score; findings with filters for severity, category and
  family, and a search field; each finding with evidence, path and a copy
  button for its commands; the attack surface table; the listener table; the
  ruleset as a browsable tree where jump targets are links and rules carry the
  findings that mention them; the baseline with download.
- Light and dark theme, print style sheet.
- Security: no external resources; `Content-Security-Policy` with a hash for
  the one script; data embedded as escaped JSON and written to the page with
  `textContent` only. A fuzz target checks that no input breaks out of the
  data block.

### 2.4 Command line [F8, F9, F11]

- File names as arguments: `iptables-analyzer rules.v4 rules.v6 ss.txt`,
  with the family detected from the content.
- `--fail-on SEVERITY|GRADE` gives exit status 2. `--quiet` prints one line.
  `--score-only` prints `62 C`.
- `--rules`, `--public`, `--html`.

### 2.5 Score model [E4, E5, D5]

- The grade is complete from the rules alone. Open ports are scored by class:
  remote administration and databases (22, 3389, 5900, 3306, 5432, 6379,
  27017, 9200, 11211, 2375), clear-text protocols (21, 23), file sharing
  (111, 139, 445, 2049), then other ports.
- Listener data changes single findings: an open port with a listener keeps
  its class; an open port without one is LOW "open, unused".
- Ports named with `--public` are INFO.

### 2.6 Golden tests

- The text, JSON and HTML reports of every fixture are compared with stored
  files (`go test -update` rewrites them).

## Phase 3: wider analysis

### 3.1 One ingress simulation [A5, A6]

For each class of ports and each ingress interface: `raw` and `mangle`
PREROUTING, then the `nat/PREROUTING` walk that returns the translation for
each source range (none, DNAT, REDIRECT), then INPUT or FORWARD by the
translated destination. Docker ports, Kubernetes NodePorts, plain port
forwards and redirects come out of the same code.

### 3.2 Chain owners [D2]

Done in Phase 2: ufw, firewalld, Docker, libvirt, fail2ban, kube-proxy, Calico,
CNI, Tailscale, sshguard and CrowdSec are recognized by chain names. The owner is in
the report header, and fixes for ufw chains are `ufw` commands.

Open: CSF and shorewall; fixes in the commands of firewalld (`firewall-cmd`) and of
the other programs; the wording of findings for each owner.

### 3.3 Host facts [A4]

Live mode also reads, before the sandbox starts: `ip_forward` and IPv6
forwarding, `rp_filter`, the list of nftables tables (to report rules that
`iptables-save` cannot show), and ipset contents. `--ipset-file` supplies
`ipset save` output for saved rulesets.

### 3.4 Snapshots and input formats

`--snapshot FILE` saves rules, listeners, interfaces and host facts in one
file; the file is accepted as input and gives live accuracy offline.
`iptables -S` output is accepted.

### 3.5 Queries

- `--trace 'tcp 203.0.113.5 -> :22 in eth0'` prints the rule path and verdict
  of one packet.
- `--diff OLD NEW` compares the open ports and findings of two rulesets.

### 3.6 Tests

- Fixtures for UFW, firewalld, libvirt, fail2ban, Kubernetes and a router.
- A differential test loads rulesets in a network namespace and compares the
  evaluator with real packets (`unshare -rn`, skipped when unavailable).
