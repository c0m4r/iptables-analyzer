package safeio

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadFileEnforcesLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFile(path, 10); err != nil || string(data) != "0123456789" {
		t.Fatalf("ReadFile at the limit = %q, %v", data, err)
	}
	if _, err := ReadFile(path, 9); err == nil || !strings.Contains(err.Error(), "input limit") {
		t.Fatalf("expected a size error, got %v", err)
	}
}

func TestReadFileStopsOnEndlessDevice(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	if _, err := ReadFile("/dev/zero", 1<<20); err == nil {
		t.Fatal("reading /dev/zero must fail at the limit")
	}
}

func TestRunScrubsEnvironment(t *testing.T) {
	t.Setenv("XTABLES_LIBDIR", "/tmp/evil")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	out, err := Run(context.Background(), "env", nil, 4096)
	if err != nil {
		t.Skipf("env unavailable: %v", err)
	}
	got := strings.Fields(string(out))
	if strings.Join(got, " ") != strings.Join(childEnv, " ") {
		t.Fatalf("tool environment = %q, want %q", got, childEnv)
	}
}

func TestRunBoundsOutput(t *testing.T) {
	if _, err := LookTrusted("yes"); err != nil {
		t.Skipf("yes unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := Run(ctx, "yes", nil, 64<<10)
	if err == nil || !strings.Contains(err.Error(), "input limit") {
		t.Fatalf("expected an output limit error, got %v", err)
	}
}

func TestRunTimesOut(t *testing.T) {
	if _, err := LookTrusted("sleep"); err != nil {
		t.Skipf("sleep unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Run(ctx, "sleep", []string{"30"}, 1024)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout, got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("timed-out tool was not killed")
	}
}

func TestRunReportsStderr(t *testing.T) {
	if _, err := LookTrusted("ls"); err != nil {
		t.Skipf("ls unavailable: %v", err)
	}
	_, err := Run(context.Background(), "ls", []string{"/nonexistent-iptables-analyzer"}, 1024)
	if err == nil || !strings.Contains(err.Error(), "nonexistent-iptables-analyzer") {
		t.Fatalf("expected stderr in the error, got %v", err)
	}
}

// privateDir returns a new directory that only the current user can modify,
// independent of the umask.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, path := range []string{dir, filepath.Dir(dir)} {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLookTrustedRejectsWritableLocations(t *testing.T) {
	dir := filepath.Join(privateDir(t), "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(dir, "iptables-analyzer-test-tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if _, err := LookTrusted("iptables-analyzer-test-tool"); err != nil {
		t.Fatalf("a private directory owned by the current user should be trusted: %v", err)
	}

	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LookTrusted("iptables-analyzer-test-tool"); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("world-writable directory accepted: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(tool, 0o757); err != nil {
		t.Fatal(err)
	}
	if _, err := LookTrusted("iptables-analyzer-test-tool"); err == nil {
		t.Fatal("world-writable executable accepted")
	}
	if err := os.Chmod(tool, 0o755); err != nil {
		t.Fatal(err)
	}

	// A symlink in a trusted directory that points into a writable one.
	writable := filepath.Join(privateDir(t), "drop")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(writable, "real")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tool); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, tool); err != nil {
		t.Fatal(err)
	}
	if _, err := LookTrusted("iptables-analyzer-test-tool"); err == nil {
		t.Fatal("symlink into a world-writable directory accepted")
	}
}

func TestLookTrustedRejectsRelativePath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "iptables-analyzer-test-tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", ".")
	if _, err := LookTrusted("iptables-analyzer-test-tool"); err == nil {
		t.Fatal("tool from a relative PATH entry accepted")
	}
	if _, err := LookTrusted("../iptables-analyzer-test-tool"); err == nil {
		t.Fatal("tool name with a path accepted")
	}
}
