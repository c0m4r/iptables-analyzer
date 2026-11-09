# Supply-chain protection

This document describes how the project controls its dependencies, its CI and its releases.

## Dependency cooldown

Most malicious package releases are found and removed in a few days.
Thus the project adopts a Go module version only when it is old enough.
This time is the *cooldown*.

### Configuration

The cooldown is in [`addons/deps.conf`](../addons/deps.conf):

```sh
COOLDOWN_DAYS=7
```

The tools read the cooldown in this order:

1. the `--cooldown DAYS` option,
2. the `GO_DEPS_COOLDOWN_DAYS` environment variable,
3. `COOLDOWN_DAYS` in `addons/deps.conf`,
4. 7 days.

A value of 0 disables the cooldown.

Dependabot reads its own configuration. The `default-days` values in
[`.github/dependabot.yml`](../.github/dependabot.yml) must be the same as `COOLDOWN_DAYS`.
The check script fails when they are different.

### Exceptions

Sometimes an urgent fix must be adopted before its cooldown ends.
Add a reviewed exception to `addons/deps.conf`, with the reason:

```sh
COOLDOWN_EXCEPTION=github.com/example/module@v1.2.3 # fixes CVE-2026-12345
```

An exception applies only to that exact version.
Remove the exception when the cooldown of the version is complete.

### Update the dependencies

```bash
make update-deps                     # newest versions older than the cooldown
make update-deps-patch               # only patch versions (x.y.Z)
make update-deps DEPS_COOLDOWN=14    # use a different cooldown
./addons/update-deps.sh --dry-run    # only show the updates
```

The update script:

1. finds all modules that supply packages to the build or the tests,
2. selects for each module the newest release that is older than the cooldown
   (it ignores pre-releases),
3. updates each module with `go get`. It uses only the Go toolchain that `go.mod` selects.
   If a module needs a newer Go version, the script skips that module,
4. runs `go mod tidy`, the cooldown check, `go mod verify`, the tests and `go vet`.

Examine the changes in `go.mod` and `go.sum` before you commit them.

### Check the dependencies

```bash
make check-deps
```

This target runs `go mod verify`, `go mod tidy -diff` and `addons/check-deps-cooldown.sh`.
The check script fails when a module in the build is younger than the cooldown and has no
exception. It gets the publication time of each version from the Go module proxy.

## CI

The workflows in [`.github/workflows/`](../.github/workflows/) use these measures:

- **Actions pinned to commit SHAs**: a changed tag cannot change the workflow.
  A comment shows the version. Dependabot updates the SHAs with the same cooldown.
- **Minimum token permissions**: the default is `permissions: {}`.
  Each job requests only the permissions that it needs.
- **No stored credentials**: `actions/checkout` runs with `persist-credentials: false`.
- **No caches**: a poisoned module or build cache cannot bypass `go.sum`.
- **Fixed Go toolchain and module source**: `GOTOOLCHAIN=local` uses only the Go version
  from `go.mod`. `GOPROXY=https://proxy.golang.org` without `direct` and `GOSUMDB=sum.golang.org`
  make sure that each module comes from the checksum-verified proxy. `GOFLAGS=-mod=readonly`
  prevents changes to `go.mod` during the build.
- **Module checks**: `go mod verify`, `go mod tidy -diff` and the dependency cooldown.
- **Hidden Unicode check**: the sources must not contain bidirectional overrides,
  zero-width characters or escape characters (Trojan Source attacks).
- **Vulnerability scan**: `govulncheck` at a fixed version, installed with `go install`
  (the Go checksum database verifies it).
- **Workflow audit**: [zizmor](https://docs.zizmor.sh/) examines the workflows for
  injection, permission and pinning problems. The action installs zizmor from a hash-pinned wheel.
- **Dependency review**: on pull requests, `actions/dependency-review-action` stops
  dependencies with known vulnerabilities.
- **Reproducible build**: CI builds the binary two times and clears the build cache between
  the builds. The two binaries must be identical.
- **Sandbox and fuzz tests**: the Landlock tests run in a static build;
  the fuzz targets run for a short time on each push.

## Releases

When you push a version tag (for example `0.7.0`), the release workflow:

1. makes sure that the tag is the same as the `VERSION` file,
2. runs the module checks, the cooldown check and the tests,
3. builds the binaries with `addons/build.sh` (static, `-trimpath`, without VCS data),
4. writes `SHA256SUMS`,
5. signs a [SLSA build provenance](https://slsa.dev/) attestation for each binary,
6. makes a **draft** release with the binaries and `SHA256SUMS`.

Examine the draft release, then publish it.
If a release for the tag already exists, the workflow fails and changes nothing.

### Verify a release

```bash
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify iptables-analyzer-<version>-amd64 --repo c0m4r/iptables-analyzer
```

The attestation shows that GitHub Actions built the binary from this repository,
and from which commit and workflow.
