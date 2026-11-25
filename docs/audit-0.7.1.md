# Audit of iptables-analyzer 0.7.1

- **Date:** 2026-11-25, commit `17ff62d`
- **Scope:** analysis coverage, correctness, edge cases, report UX
- **Follow-up:** [ROADMAP.md](../ROADMAP.md)

## Method

1. Read all non-test Go code (about 7,000 lines) and the documentation.
2. Ran the test suite: all tests pass, 75.8% statement coverage.
3. Ran the binary on the five fixtures and on about 30 purpose-built inputs
   (UFW, classic RHEL, libvirt, fail2ban, Kubernetes-like, plain router, ipset
   allowlists, empty and partial inputs).
4. Loaded the generated baseline with real `iptables-restore` and
   `ip6tables-restore` 1.8.13 (nf_tables) in a throwaway network namespace.

Each finding says how it was established: **reproduced** (an input in the
appendix shows it) or **by inspection** (read from the code, not run).

Severity of audit findings:

| Level | Meaning |
| --- | --- |
| S1 | Wrong security conclusion, or the tool fails on a common host |
| S2 | Misleading result or advice that a careful user would act on |
| S3 | Noise, cosmetic defect, or a rare edge case |

## Verdict

The core is sound and should stay: the order-aware symbolic evaluator
(`evaluation.go`), the per-source certainty tracking, the Docker path analysis
that was checked against a live host, and the hardening around untrusted input
(sandbox, `textsafe`, bounded reads, fuzzing).

The defects cluster in five places:

1. **Half of the checks do not use the evaluator.** Policy, conntrack, final
   drop, dead rules, unused rules and the SSH rate limit are pattern matches on
   the top level of `filter/INPUT`. They are wrong for every ruleset that uses
   user chains (UFW, firewalld, libvirt) and they miss a plain `-j ACCEPT`.
2. **There is no view of the attack surface from the rules alone.** Exposure
   exists only for sockets in an `ss` file. A ruleset that accepts everything
   gets grade A when nothing happens to listen.
3. **Live mode fails where it matters most.** With the nf_tables backend,
   `iptables-save` prints nothing when a family has no rules. The tool then
   stops with an error and suggests `--ipv4-only`.
4. **Undecidable predicates are all treated the same.** A rate limit, a TCP
   flag test and an ipset allowlist all become "possibly exposed to any source",
   and that is scored like a proven exposure.
5. **The report buries the result.** The grade is on the last line, the
   findings and their fixes are two separate lists, and the rule dump and the
   baseline are most of the output.

None of this needs a rewrite from zero. It needs the syntactic checks replaced
by evaluator queries, one finding model in place of five, and a new report.

## A. False negatives

### A1. A ruleset that accepts everything gets grade A (S1, reproduced)

`:INPUT DROP` followed by `-A INPUT -j ACCEPT`, with an `ss` file without
listeners: **95/100, grade A**. The policy check reads the policy line only.
The one deduction is itself wrong ("INPUT denies by default but never accepts
ESTABLISHED,RELATED"). Appendix: `accept-all`.

### A2. Broad accepts are invisible without a matching listener (S1, reproduced)

`-A INPUT -p tcp -j ACCEPT` plus `-p udp --dport 1024:65535 -j ACCEPT` under a
DROP policy: **100/100, grade A**. The only output is an INFO "unused rule"
for the UDP range. Every service started later is exposed at once.
Appendix: `broad-accept`.

### A3. Live analysis aborts when a family has no rules (S1, reproduced and by inspection)

`iptables-save` 1.8.13 (nf_tables) prints nothing for an empty ruleset
(verified in an empty namespace). `parser.Parse("")` returns "input contains no
iptables-save tables" and `loader.readOne` sets `Empty` only when no file was
given, so:

- a host without any firewall: `Error: loading rules: loading IPv4 rules: ...`
- a host with IPv4 rules and untouched IPv6 (very common):
  `Error: ... loading IPv6 rules: input contains no iptables-save tables (use --ipv4-only to skip IPv6)`

The user follows the hint, and the unprotected IPv6 stack is never reported.
`examples/save-rules.sh` writes the same empty `rules.v6`, which the tool then
refuses. The live path has no test (`services.Collect`, `runSS` and the live
branch of `readOne` have 0% coverage).

### A4. nftables blind spots are silent (S1, reproduced)

- `# Warning: iptables-legacy tables present, use iptables-legacy-save to see them`
  is skipped as a comment. Half of the firewall is missing and the report
  says grade A.
- `# Table `filter' is incompatible, use 'nft' tool.` gives the generic
  "no iptables-save tables" error.
- Native nftables tables (firewalld with the nftables backend, a hand-written
  `inet filter`) do not appear in `iptables-save` at all. Live mode does not
  look for them, so the report describes a firewall that is not the real one.

### A5. Kubernetes NodePorts are not analyzed (S2, reproduced)

`analyzePublishedPorts` only follows DNAT rules that carry their own `--dport`
(Docker's shape). kube-proxy matches the port in `KUBE-NODEPORTS` and DNATs
three chains later. Result for 200 services: no published port, 600
"Assessment note" lines in the overview, grade INCOMPLETE, 4 MB of JSON.

### A6. REDIRECT is ignored without a note (S2, reproduced)

`-t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080`: the report
does not say that port 80 reaches the listener on 8080. The limit is in
`how-it-works.md`, but the report has no assessment note, unlike DNAT.

### A7. No check compares the two address families (S2, by inspection)

A port filtered on IPv4 and open on IPv6 is the classic dual-stack mistake.
The data is there (per-family exposure), but nothing reports the difference.

## B. False positives and wrong statements

### B1. UFW: "never accepts ESTABLISHED,RELATED traffic" (S1, reproduced)

On a standard UFW ruleset the report shows a HIGH finding that replies to
outbound connections are dropped. The rule is `ufw-before-input` #2.
`checkConntrack` scans the top level of INPUT only. The recommendation tells
the user to insert a rule into INPUT. Every UFW host gets this.

### B2. ACCEPT policy with a final REJECT (S2, reproduced)

The classic RHEL layout ends INPUT and FORWARD with a catch-all REJECT. The
report shows two HIGH findings ("All traffic not explicitly blocked will be
allowed") and two HIGH recommendations, while the score gives policy 25/25.
The report contradicts itself.

### B3. Allowlists by `iprange`, `set` or `mac` are "exposed" (S2, reproduced)

SSH limited to `--src-range 192.168.1.10-192.168.1.20`: "sshd may be accessible
from the network", HIGH, scope EXPOSED, -5 points. The same for an ipset and a
MAC address. `iprange` is exactly decidable; `set` and `mac` restrict the
source to an unknown subset, which is not "any source".

### B4. An ipset allowlist written as a negated DROP is "definitely exposed" (S2, reproduced)

`-m set ! --match-set allowlist src -j DROP` followed by `--dport 22 -j ACCEPT`:
"sshd **is** accessible from the network", DEFINITE. The evaluator treats the
branch where an undecidable predicate does not match as certain and as the
full source range. For a rate limit that is right; for an allowlist it is the
opposite of the truth. The same pattern in `DOCKER-USER` makes a restricted
published port "open to any source".

### B5. Rate limits and `--syn` make an exposure "possible" (S2, reproduced)

- The README example (`--ctstate NEW -m limit --limit 3/min -j ACCEPT`) gives
  "sshd **may be** accessible". Any source can connect while tokens remain.
- `--syn` is saved as `--tcp-flags FIN,SYN,RST,ACK SYN`; the parser drops the
  second argument and the evaluator does not model the option.
- The tool's own SSH recommendation creates exactly such a rule, so applying
  the advice turns a definite finding into a "possible" one with the same
  severity and the same deduction.

### B6. The DHCP client is a HIGH exposure (S2, reproduced)

UFW's `--sport 67 --dport 68 -j ACCEPT` gives "systemd-network on port 68/udp
may be accessible from the network", HIGH, -5.

### B7. Listeners on virtual bridges, and device-bound sockets (S2, reproduced)

libvirt's dnsmasq (`0.0.0.0%virbr0:67`, `192.168.122.1:53`) gives two HIGH
findings "accessible from the network via virbr0". The `%virbr0` suffix means
the socket only receives packets from that device; the tool evaluates it for
every interface and treats `virbr0` as external.

### B8. A plain port forward is reported as a Docker bypass (S2, reproduced)

A router with `-j DNAT --to-destination 192.168.1.50:443` and a matching
FORWARD rule gets "Docker: INPUT Bypassed by Published Ports", a
"Docker Published Ports" table with a CONTAINER column, and commands for a
`DOCKER-USER` chain that does not exist on the host.

### B9. Severity inflation for Docker bypasses (S3, reproduced)

With `-A INPUT -s 192.168.0.0/16 -j ACCEPT` and a DROP policy, each published
port is CRITICAL: "port 8080/tcp is restricted by filter/INPUT rule #3".
A general trust rule is not a restriction of that port. By the tool's own
definition this is the HIGH case (default-deny bypass).

### B10. An IPv6 stack that is blocked on purpose (S2, reproduced)

`ip6tables` with all three policies DROP and no rules gives three findings
(loopback dropped, neighbor discovery dropped, router advertisements dropped)
and -11 points.

### B11. A missing `--file6` counts as "no IPv6 firewall" (S2, reproduced)

`-f rules.v4` alone gives -10 and the HIGH recommendation "No ip6tables rules
detected". The file was not supplied; nothing was detected.

### B12. Double reports (S3, reproduced)

- A rule behind a catch-all rule is "shadowed" and "dead": two findings and two
  deductions per rule (`insecure` fixture: rules 3 to 5).
- An ACCEPT policy also gives "No explicit DROP at end of INPUT".
- Dead rules are listed one line per rule.

### B13. Small wrong statements (S3, reproduced)

- `! --dport 22 -j ACCEPT` is reported as "allows tcp port(s) 22 but no
  matching service is listening".
- A file without a `filter` table loses 25 policy points with no finding that
  explains the deduction.
- "5 table · 24 chains" (plural).

### B14. The tool objects to its own baseline (S2, reproduced)

The generated baseline, analyzed with a listening sshd: two HIGH findings
"sshd is accessible from the network", two HIGH recommendations to restrict
it, and "unused rule" for the DHCPv6 rule that the baseline added. A user who
applies the recommended configuration cannot clear the report.

## C. Parser and input robustness

### C1. A comment that starts with `-` aborts the analysis (S1, reproduced)

`-m comment --comment "-- ssh --"` gives `Error: ... --comment requires a
value`, and the whole run stops. A comment of `!` does the same. The parser
decides whether the next token is a value by its first character, and the
tokenizer forgets whether a token was quoted.

### C2. Options with two arguments lose the second (S2, reproduced)

`--tcp-flags MASK COMPARE` and `--match-set NAME FLAGS` keep the first argument
only. See B5 for the consequence.

### C3. `ss` parsing (S2, reproduced; second item by inspection)

- A process name with a space (`"Plex Media Serv"`) becomes "(unknown process)"
  because the row is split on spaces before the name is matched.
- Only the first entry of `users:((...))` is read. A socket-activated sshd is
  listed as `("systemd",pid=1,...),("sshd",...)`, so the baseline does not
  recognize the SSH port (see D4).

### C4. Analysis time grows quadratically with blocklists (S2, reproduced)

A fail2ban-style chain of single-address REJECT rules, three services:

| Blocked addresses | Time |
| --- | --- |
| 200 | 0.1 s |
| 1,000 | 3.7 s |
| 3,000 | 30 s |

Each excluded address splits the remaining source set into up to 32 more
prefixes, and every later rule scans and re-normalizes the whole list through
a string-keyed map. The traversal budget (`maxChainVisits`) does not bound
this work. A CSF or recidive jail with 20,000 entries will not finish.

### C5. Smaller items (S3, by inspection)

- `Rule.States` keeps the last `--ctstate` only. The evaluator reads the
  match extensions and is right; shadow detection, `IsCatchAll` and the
  conntrack check read `Rule.States`.
- `portCovers` returns true when the second port list does not parse.
- The copy of a service inside an exposure finding keeps
  `Status: NOT_ANALYZED` in JSON.
- `-N`, `-P`, `-I` lines (valid for `iptables-restore`, and the format of
  `iptables -S`) are rejected.

## D. Advice: recommendations and baseline

### D1. The SSH rate limit can lock the administrator out (S2, by inspection)

The recommendation replaces the SSH rule with `-m limit --limit 3/min
--limit-burst 5 -j ACCEPT`. `limit` is global, so anyone who sends three SYNs a
minute denies SSH to everyone. The baseline uses a per-source `hashlimit`;
the recommendation should too.

### D2. Commands that edit chains owned by another tool (S2, reproduced)

On UFW the advice is `iptables -I ufw-user-limit-accept -p tcp --dport 22 ...`.
The change is lost at the next `ufw reload`, and it is the wrong chain. The
tool does not know which program manages a chain (ufw, firewalld, Docker,
libvirt, fail2ban, kube-proxy, Tailscale).

### D3. The baseline removes jumps without a warning (S2, reproduced)

`-F INPUT` deleted the jump to `f2b-sshd` in the namespace test. The same
happens to `ufw-*`, `LIBVIRT_INP`, `ts-input` and `KUBE-*` jumps. The notes do
not mention it. On Docker hosts the existing `DOCKER-USER` rules are replaced
(the header says so, the old rules are not carried over). `:FORWARD DROP` is
applied to hosts that forward by policy.

What works: both baseline files load without error, Docker's chains survive
`--noflush`, and user chains are flushed as documented.

### D4. SSH port detection (S2, by inspection)

The baseline keeps the ports of sockets whose first process is `sshd`.
With socket activation on a non-standard port the baseline opens 22 and lists
the real port as a commented `systemd` rule. Applying it closes SSH.

### D5. The text of the recommendations (S3, reproduced)

- "see ... or `--baseline 6`": that syntax fails (`unknown command "6"`).
- Seven published ports give seven copies of the same paragraph.
- The same advice for nginx on 443 and mysqld on 3306. There are no risk
  classes for services, and no way to state that a port is public on purpose.

## E. Score

| # | Defect | Source |
| --- | --- | --- |
| E1 | Accept-all rulesets get grade A | A1, A2 |
| E2 | POSSIBLE findings cost the same as DEFINITE | scorer.go:56 |
| E3 | Category caps hide a critical defect: no finding limits the grade | by design |
| E4 | No `ss` file gives INCOMPLETE, although policy, shadows and NAT are assessed | scorer.go:155 |
| E5 | A public web server cannot get grade A: 80 and 443 cost 10 points | by design |
| E6 | Double deductions and deductions without a finding | B12, B13 |

## F. Report and command line

| # | Defect |
| --- | --- |
| F1 | The grade is the last line. For the Docker 29 fixture the report has 434 lines: 200 are the rule dump, 80 the baseline |
| F2 | Findings and recommendations are two lists that describe the same items twice |
| F3 | The baseline is printed on every run (43 to 80 lines) |
| F4 | Lines are not wrapped; finding lines are 250 characters and more |
| F5 | Without color the score bars are the same for 0/25 and 25/25 |
| F6 | The allowing rule is the leaf (`ufw-user-limit-accept` #1), not the path that led to it |
| F7 | The header has no host name and no input file names |
| F8 | The exit status is 0 for every completed run; there is no threshold for CI |
| F9 | `--score-only` prints a drawing, not a line a script can read |
| F10 | JSON: Go field names, numeric severities, no schema version, whole rulesets inside each finding |
| F11 | A file name without `-f` gives `unknown command "rules.v4"` |
| F12 | Raw enum values in the text ("Service exposure: NOT_REQUESTED") |

## G. Coverage of iptables features

| Area | State |
| --- | --- |
| `tcp`/`udp` ports, `multiport --dports/--sports`, `conntrack`/`state`, `addrtype`, `icmp`, `icmp6`, `hl`, `comment` | Modeled |
| `--syn`/`--tcp-flags`, `iprange`, `multiport --ports`, `pkttype` | Decidable, not modeled |
| `limit`, `hashlimit`, `connlimit`, `recent`, `statistic`, `time` | Any source can satisfy them; treated as unknown |
| `set`, `mac`, `geoip` | Restrict the source to an unknown subset; treated as unknown |
| `mark`, `connmark`, `string`, `u32`, `owner`, others | Unknown, conservative (correct) |
| Targets ACCEPT, DROP, REJECT, RETURN, jumps, goto, DNAT, NOTRACK, NFQUEUE | Modeled |
| REDIRECT, DNAT to a local address, TPROXY, SNAT side effects | Not modeled |
| `filter/INPUT` with `raw`, `mangle`, `security` hooks | Modeled |
| FORWARD on routers without NAT, OUTPUT | Policy line only |
| Docker (bridge, routed, nat-unprotected, raw protection) | Modeled, live-verified |
| Kubernetes, libvirt, LXD, plain routers | Generic DNAT only, with Docker wording |
| ipset contents, sysctls (`ip_forward`, `rp_filter`), native nftables | Not read |

## H. Test coverage

| Package | Coverage | Gap |
| --- | --- | --- |
| analyzer | 85.6% | No ruleset from UFW, firewalld, libvirt, fail2ban or Kubernetes |
| parser | 69.6% | No table of real `iptables-save` lines per extension |
| recommender | 73.9% | `rulesMayOverlap`, `portSpecsOverlap`, `dstToOrigDst` at 0% |
| services | 55.9% | Collection path at 0% |
| ui | 55.8% | No golden file for the report; overview and rule tables at 0% |
| loader | 72.7% | Live branch untested (A3) |
| cmd | 75.2% | |

Missing kinds of test:

- **Self-consistency:** the baseline analyzed by the tool (B14).
- **Performance:** a benchmark with a large blocklist (C4).
- **Golden reports:** the full text and JSON for each fixture.
- **Differential:** rules loaded with `iptables-restore` in a namespace and
  probed with real packets. The audit used this method by hand; it works
  without root (`unshare -rn`).

## What is good

- The evaluator follows jumps, `goto`, `RETURN` and policies, splits source
  ranges symbolically, and keeps certainty per source segment.
- The Docker analysis covers direct routing, gateway modes, rule order and
  the IPv6 gap, and its tests encode behavior that was observed on a host.
- Untrusted input is handled with care: Landlock, privilege drop, trusted tool
  lookup, size limits, escaping of control characters, shell quoting.
- Findings have stable codes and a certainty.
- The supply chain is controlled (cooldown, pinned actions, attestations).
- The fuzz targets cover the parsers and the whole pipeline.

## Appendix: inputs

Each input is a regression test for the roadmap item that fixes it.
Unless noted, the chains are `:INPUT DROP`, `:FORWARD DROP`, `:OUTPUT ACCEPT`,
with `-i lo -j ACCEPT` and `--ctstate RELATED,ESTABLISHED -j ACCEPT` first.

| Name | Input | Observed |
| --- | --- | --- |
| `accept-all` | `-A INPUT -j ACCEPT` only; `ss` header only | 95/100 A |
| `broad-accept` | `-p tcp -j ACCEPT`; `-p udp --dport 1024:65535 -j ACCEPT` | 100/100 A |
| `empty-v6` | valid v4 file, empty v6 file | fatal error |
| `nft-incompatible` | only the two comment lines of `iptables-nft-save` | fatal error |
| `legacy-warning` | warning comment, then `basic.iptables-save` | 100/100 A, no note |
| `k8s` | NodePort → `KUBE-EXT` → `KUBE-SVC` → three `KUBE-SEP` DNATs, 200 services | 0 ports, 600 notes |
| `redirect` | `nat/PREROUTING --dport 80 -j REDIRECT --to-ports 8080`; INPUT accepts 8080 | port 80 not mentioned |
| `ufw` | standard UFW chains, `ufw limit 22`, 80, 443, 5432 from 10.0.0.0/8 | B1, B6, D2 |
| `rhel` | ACCEPT policies; INPUT and FORWARD end with `-j REJECT` | B2 |
| `allowlists` | 22 by `iprange`, 80 by `set`, 443 by `mac` | 3 × HIGH possible, 85 B |
| `ipset-negated-drop` | `-m set ! --match-set allowlist src -j DROP`; `--dport 22 -j ACCEPT` | HIGH definite |
| `syn` | `--dport 22 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT` | possible |
| `limit` | `--dport 22 --ctstate NEW -m limit --limit 3/min -j ACCEPT` | possible |
| `libvirt` | `LIBVIRT_INP -i virbr0` rules; `0.0.0.0%virbr0:67`, `192.168.122.1:53` | 2 × HIGH |
| `router-dnat` | `PREROUTING -i eth0 --dport 8443 -j DNAT --to 192.168.1.50:443`; FORWARD accept | Docker wording |
| `trust-lan` | `docker` fixture with DROP policy and `-s 192.168.0.0/16 -j ACCEPT` | 2 × CRITICAL |
| `v6-blocked` | v6: three DROP policies, no rules | 3 findings, -11 |
| `v4-only-file` | `-f basic.iptables-save` without `--file6` | -10, HIGH recommendation |
| `insecure` | fixture | rules 3 to 5 reported twice |
| `negated-dport` | `-s 10.0.0.0/8 -p tcp ! --dport 22 -j ACCEPT` | "allows port 22" |
| `nat-only` | file with a `nat` table only | -25, no finding |
| `baseline-self` | output of `--baseline=4` and `=6`; sshd on both families | 2 × HIGH |
| `dash-comment` | `--comment "-- ssh --"`, `--comment "!"` | fatal error |
| `ss-spaces` | `users:(("Plex Media Serv",pid=2000,fd=60))` | process lost |
| `f2b-N` | `f2b-sshd` with N single-address REJECT rules | see C4 |
| `baseline-apply` | baseline restored with `--noflush` over `-A INPUT -p tcp --dport 22 -j f2b-sshd` | jump removed |
