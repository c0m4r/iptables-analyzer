// Package safeio reads analyzer input from the host with bounded memory use.
// Live analysis runs as root, so external tools are only executed from
// trusted, root-owned locations with a minimal environment: a writable PATH
// entry or an inherited variable such as XTABLES_LIBDIR (which makes iptables
// load extension libraries from another directory) must not run code as root.
package safeio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/textsafe"
)

// Input size limits. Rulesets of large Kubernetes nodes are a few tens of
// megabytes; anything larger is far more likely a wrong file or a device.
const (
	MaxRulesSize    = 64 << 20
	MaxServicesSize = 16 << 20
	maxStderrSize   = 4 << 10
)

// TrustedDirs are searched, in order, for the tools used by live analysis.
var TrustedDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// childEnv is the complete environment of executed tools.
var childEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// ReadFile reads path, refusing files larger than limit bytes. Pipes and
// process substitutions such as <(iptables-save) are read the same way.
func ReadFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %s input limit", path, formatSize(limit))
	}
	return data, nil
}

// Run executes a system tool found by LookTrusted and returns its standard
// output, which may not exceed limit bytes. The tool gets no standard input,
// "/" as working directory and only a fixed PATH and LC_ALL=C.
func Run(ctx context.Context, name string, args []string, limit int64) ([]byte, error) {
	path, err := LookTrusted(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := &limitedBuffer{limit: limit, onOverflow: cancel}
	stderr := &limitedBuffer{limit: maxStderrSize, truncate: true}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Args[0] = name
	cmd.Env = childEnv
	cmd.Dir = "/"
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = procAttr()
	cmd.WaitDelay = 2 * time.Second
	command := strings.TrimSpace(name + " " + strings.Join(args, " "))
	err = cmd.Run()
	switch {
	case stdout.overflow:
		return nil, fmt.Errorf("%s output exceeds the %s input limit", command, formatSize(limit))
	case err == nil:
		return stdout.Bytes(), nil
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("%s timed out: %w", command, ctx.Err())
	}
	if msg := strings.TrimSpace(textsafe.Escape(stderr.String())); msg != "" {
		return nil, fmt.Errorf("running %s: %w: %s", command, err, msg)
	}
	return nil, fmt.Errorf("running %s: %w", command, err)
}

// LookTrusted finds name in TrustedDirs, or else in PATH, and verifies that
// the executable, every symlink leading to it, and every directory on the
// way can only be modified by root (or the current user).
func LookTrusted(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("invalid tool name %q", name)
	}
	for _, dir := range TrustedDirs {
		candidate := filepath.Join(dir, name)
		if _, err := os.Lstat(candidate); err != nil {
			continue
		}
		if err := checkTrusted(candidate); err != nil {
			return "", err
		}
		return candidate, nil
	}
	// Some distributions (NixOS) keep system tools elsewhere; PATH is only
	// a fallback, and its result must pass the same ownership checks.
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found in %s or PATH", name, strings.Join(TrustedDirs, ":"))
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("refusing to run %s from relative PATH entry %q", name, path)
	}
	if err := checkTrusted(path); err != nil {
		return "", err
	}
	return path, nil
}

// checkTrusted follows path to a regular executable and checks every hop.
func checkTrusted(path string) error {
	const maxHops = 40
	for hop := 0; hop < maxHops; hop++ {
		if err := checkDirChain(filepath.Dir(path)); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(path), target)
			}
			path = target
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to run %s: not a regular file", path)
		}
		return checkOwner(path, info, false)
	}
	return fmt.Errorf("refusing to run %s: too many symbolic links", path)
}

// checkDirChain checks dir and all its ancestors, both as written and with
// symbolic links resolved (/sbin -> usr/sbin on merged-/usr systems).
func checkDirChain(dir string) error {
	paths := []string{filepath.Clean(dir)}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != paths[0] {
		paths = append(paths, resolved)
	}
	for _, p := range paths {
		for {
			info, err := os.Stat(p)
			if err != nil {
				return err
			}
			if err := checkOwner(p, info, true); err != nil {
				return err
			}
			parent := filepath.Dir(p)
			if parent == p {
				break
			}
			p = parent
		}
	}
	return nil
}

func checkOwner(path string, info os.FileInfo, dir bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("refusing to run from %s: ownership unavailable", path)
	}
	if stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("refusing to run from %s: owned by uid %d, not root", path, stat.Uid)
	}
	writable := info.Mode().Perm()&0o022 != 0
	// A sticky directory (/nix/store) only lets owners replace their entries.
	if writable && !(dir && info.Mode()&os.ModeSticky != 0) {
		return fmt.Errorf("refusing to run from %s: writable by group or others (mode %s)", path, info.Mode().Perm())
	}
	return nil
}

// limitedBuffer collects output up to limit bytes. Beyond the limit it
// either drops the rest (truncate) or fails and calls onOverflow. The
// buffer is a named field: an embedded bytes.Buffer would promote ReadFrom,
// which io.Copy prefers over Write, bypassing the limit.
type limitedBuffer struct {
	buf        bytes.Buffer
	limit      int64
	truncate   bool
	overflow   bool
	onOverflow func()
}

func (b *limitedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *limitedBuffer) String() string { return b.buf.String() }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.limit - int64(b.buf.Len())
	if int64(len(p)) <= room {
		return b.buf.Write(p)
	}
	if b.truncate {
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	b.overflow = true
	if b.onOverflow != nil {
		b.onOverflow()
	}
	return 0, errors.New("output limit exceeded")
}

func formatSize(n int64) string {
	if n >= 1<<20 && n%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d bytes", n)
}
