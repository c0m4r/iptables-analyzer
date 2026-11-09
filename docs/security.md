# Security

This document describes how the tool protects the system that runs it.

## Threat model

The tool usually runs as root. It reads data that other persons can control:

- **Rule files** can come from a different host or from a different person.
- **Rule comments, chain names and interface names** come from all users and containers
  that can change the firewall (for example, containers with `NET_ADMIN` in the host namespace).
- **Process names** in `ss` output come from all local users.
  Any user can give a process a name with terminal escape sequences.

A person who controls this data must not be able to:

- run code with the privileges of the tool,
- read or change files through the tool,
- send terminal escape sequences to the terminal of the administrator,
- hide a command in a recommended command, so that it runs when the administrator copies it,
- make the tool use all memory or all CPU time.

## Protections

### 1. Bounded input

- The tool reads at most 64 MiB of rules and 16 MiB of `ss` output.
  A larger input, or an endless device such as `/dev/zero`, gives an error.
- Each line can have at most 1 MiB.
- The tool stops the evaluation of a ruleset after 262,144 chain traversals
  (see [how-it-works.md](how-it-works.md#evaluation-limit)).
  The affected results are `POSSIBLE`, and the report shows an assessment note.

### 2. Safe execution of system tools

In live mode, the tool starts `iptables-save`, `ip6tables-save` and `ss`. It:

- finds them only in `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin`. `PATH` is only a fallback
  (for example on NixOS), and a relative `PATH` entry is refused,
- refuses a tool when the file, a symbolic link to it, or a directory on the way is not owned
  by root (or the current user), or when group or other users can write to it.
  A sticky directory, for example `/nix/store`, is permitted,
- gives the tool an environment with only `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LC_ALL=C`.
  Variables such as `XTABLES_LIBDIR` (iptables loads extensions from it) and `LD_PRELOAD`
  do not get to the tool,
- starts the tool in `/`, without standard input, with a time limit,
  and kills it when the analyzer stops.

### 3. Sandbox

After the tool reads all input, it starts a sandbox. Then it parses and analyzes the input
and writes the report. The steps:

1. **Privilege drop**: when the tool runs as root, it changes all user and group IDs to
   65534 (nobody) and removes the supplementary groups. This also removes all capabilities.
   Thus the process cannot change the firewall through netlink.
2. **no_new_privs**: no program can give the process more privileges.
3. **Landlock**: a Landlock domain without allow rules. The restrictions depend on the
   Landlock ABI of the kernel:

   | Landlock ABI | Kernel | Denied |
   | --- | --- | --- |
   | 1 | 5.13 | Open, create, delete and execute files; read directories |
   | 2 | 5.19 | Also: link and rename files to other directories |
   | 3 | 6.2 | Also: truncate files |
   | 4 | 6.7 | Also: TCP bind and connect |
   | 5 | 6.10 | Also: ioctl on devices |
   | 6 | 6.12 | Also: abstract UNIX sockets and signals to other processes |
   | 8 | 7.0 | The kernel applies the domain to all threads in one step (TSYNC) |
   | 9 | — | Also: connect to UNIX sockets with a path |
   | 10 | — | Also: UDP bind and send |

The file descriptors that are open before the sandbox, for example standard output,
continue to operate.

The report shows the sandbox status in the overview. The JSON output has the status in `Sandbox`.

#### Sandbox modes

| Mode | Function |
| --- | --- |
| `--sandbox=auto` (default) | Apply all parts that the system supports. Continue without the other parts. `--verbose` shows the missing parts. |
| `--sandbox=strict` | Stop with an error when a part is not available. |
| `--sandbox=off` | Do not use the sandbox. Use this mode only to find a problem. |

#### Enable Landlock

Landlock must be in the kernel (`CONFIG_SECURITY_LANDLOCK=y`) and in the list of active LSMs.
To see the active LSMs:

```bash
cat /sys/kernel/security/lsm
```

If `landlock` is not in the list, add it to the `lsm=` kernel parameter, for example
`lsm=landlock,lockdown,yama,integrity,apparmor`, and restart the host.

#### Binaries with cgo

Landlock and no_new_privs apply to one thread. The Go runtime starts threads before `main`.
Before Landlock ABI 8, the tool applies the domain to each thread with
`syscall.AllThreadsSyscall`. Go supports this function only in binaries without cgo.

- `make build` and `addons/build.sh` make static binaries without cgo.
- A binary with cgo (for example from `go install` with a C compiler) gets the Landlock
  sandbox only on Linux 7.0 and later. The privilege drop operates in all binaries.

### 4. Safe terminal output

The parser and the `ss` parser replace characters that a terminal can interpret:

| Input | Shown as |
| --- | --- |
| C0 control characters and DEL | Caret notation, for example `^[` for ESC |
| C1 control characters, bidirectional overrides, zero-width characters, line separators | `<U+XXXX>`, for example `<U+202E>` |
| Bytes that are not valid UTF-8 | `<0xNN>` |

Interface names from the live system get the same treatment.
Thus an escape sequence in a rule comment or in a process name has no effect on the terminal.
The placeholders contain no quotes or backslashes, so the rules parse the same.

### 5. Safe recommended commands

A recommended command contains values from the analyzed rules: comments, chain names,
interface names and addresses. The tool puts each value in POSIX shell quotes.
Thus a comment such as `$(curl ... | sh)` stays one argument when you copy the command
into a shell:

```text
iptables -R INPUT 2 -p tcp --dport 22 -m comment --comment '$(curl ... | sh)' -m limit --limit 3/min --limit-burst 5 -j ACCEPT
```

Values without special characters, for example `tcp`, `10.0.0.0/8` or `DOCKER-USER`, have no quotes.

## Tests

- `internal/sandbox`: a child process enforces the sandbox while other threads run.
  The test makes sure that all threads cannot read files, that the process cannot create files,
  list directories, start programs or connect over TCP, and that open descriptors operate.
- `cmd`: the real command runs in a child process with each sandbox mode.
  The JSON report must be the same with and without the sandbox.
- Fuzz tests send random rules and `ss` data through the full command.
  The `--no-color` report must not contain control characters.
- `internal/recommender`: a rule comment with shell syntax must stay one literal argument.
- `internal/safeio`: tests for the input limits, the environment, the time limit and the
  ownership checks.

Without Landlock in the kernel, the enforcement tests are skipped. CI runs them on a
kernel with Landlock. For the commands, see [DEVELOPMENT.md](../DEVELOPMENT.md).

## Report a vulnerability

Do not open a public issue. Use the private vulnerability report on the
[Security tab](https://github.com/c0m4r/iptables-analyzer/security) of the repository,
or speak to the author directly.
