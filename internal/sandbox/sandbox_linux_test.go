//go:build linux

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The enforcement test runs in a child process: a sandbox cannot be lifted,
// and the parent test binary must keep its access to the filesystem.
// This file deliberately avoids package net, which would link runtime/cgo
// into cgo-enabled test builds and disable syscall.AllThreadsSyscall.
const childEnv = "IPTABLES_ANALYZER_SANDBOX_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) != "" {
		os.Exit(sandboxChild())
	}
	os.Exit(m.Run())
}

func TestPolicyGrowsWithABI(t *testing.T) {
	if attr, restricted := policy(0); attr != (rulesetAttr{}) || restricted != nil {
		t.Fatalf("ABI 0 must not restrict anything: %+v %v", attr, restricted)
	}
	v1, r1 := policy(1)
	if v1.handledAccessFS != 0x1fff || v1.handledAccessNet != 0 || v1.scoped != 0 {
		t.Fatalf("unexpected ABI 1 ruleset %+v", v1)
	}
	if strings.Join(r1, ",") != "filesystem,exec" {
		t.Fatalf("unexpected ABI 1 restrictions %v", r1)
	}
	v6, r6 := policy(6)
	if v6.handledAccessFS != 0xffff || v6.handledAccessNet != 0x3 || v6.scoped != 0x3 {
		t.Fatalf("unexpected ABI 6 ruleset %+v", v6)
	}
	if strings.Join(r6, ",") != "filesystem,exec,tcp,abstract-unix-sockets,signals" {
		t.Fatalf("unexpected ABI 6 restrictions %v", r6)
	}
	v10, r10 := policy(10)
	if v10.handledAccessFS != 0x1ffff || v10.handledAccessNet != 0xf || !strings.Contains(strings.Join(r10, ","), "udp") {
		t.Fatalf("unexpected ABI 10 ruleset %+v %v", v10, r10)
	}
}

func TestParseMode(t *testing.T) {
	for _, value := range []string{"auto", "strict", "off"} {
		if mode, err := ParseMode(value); err != nil || string(mode) != value {
			t.Fatalf("ParseMode(%q) = %q, %v", value, mode, err)
		}
	}
	if _, err := ParseMode("on"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestOffModeDoesNothing(t *testing.T) {
	status, err := Enforce(Off)
	if err != nil || status.Landlock || status.PrivilegesDropped {
		t.Fatalf("Off mode applied restrictions: %+v %v", status, err)
	}
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatalf("Off mode blocked file creation: %v", err)
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("Off mode blocked file access: %v", err)
	}
}

type childReport struct {
	Status   models.SandboxStatus
	Err      string
	Failures []string
}

func TestEnforceConfinesEveryThread(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	// As root, Enforce also drops to uid 65534: open up the permissions so
	// that only Landlock, not file ownership, can deny the child's access.
	for _, path := range []string{dir, filepath.Dir(dir)} {
		if err := os.Chmod(path, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(secret, 0o644); err != nil {
		t.Fatal(err)
	}
	port, closeListener := listenTCP(t)
	defer closeListener()

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		childEnv+"=1",
		"SANDBOX_TEST_SECRET="+secret,
		"SANDBOX_TEST_DIR="+dir,
		"SANDBOX_TEST_PORT="+strconv.Itoa(port),
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sandbox child failed: %v\n%s", err, out)
	}
	var report childReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("unreadable child report %q: %v", out, err)
	}
	if !report.Status.Landlock {
		if report.Status.LandlockABI == 0 || strings.Contains(strings.Join(report.Status.Notes, " "), "cgo") {
			t.Skipf("Landlock unavailable: %v", report.Status.Notes)
		}
		t.Fatalf("Landlock was not enforced: %+v %s", report.Status, report.Err)
	}
	if report.Err != "" {
		t.Fatalf("strict sandbox failed: %s", report.Err)
	}
	for _, failure := range report.Failures {
		t.Error(failure)
	}
	t.Logf("sandbox status: %+v", report.Status)
}

// sandboxChild enforces the sandbox with threads already running, then
// verifies the restrictions from several threads.
func sandboxChild() int {
	report := childReport{}
	fail := func(format string, args ...any) {
		report.Failures = append(report.Failures, fmt.Sprintf(format, args...))
	}
	secret := os.Getenv("SANDBOX_TEST_SECRET")
	dir := os.Getenv("SANDBOX_TEST_DIR")
	port, _ := strconv.Atoi(os.Getenv("SANDBOX_TEST_PORT"))

	preopened, err := os.Open(secret)
	if err != nil {
		fail("pre-opening: %v", err)
	}

	// Park goroutines on dedicated OS threads that exist before Enforce.
	const workers = 4
	start := make(chan struct{})
	results := make(chan error, workers)
	var ready sync.WaitGroup
	for i := 0; i < workers; i++ {
		ready.Add(1)
		go func() {
			runtime.LockOSThread()
			ready.Done()
			<-start
			_, err := os.ReadFile(secret)
			results <- err
		}()
	}
	ready.Wait()

	status, err := Enforce(Strict)
	report.Status = status
	if err != nil {
		report.Err = err.Error()
	}
	if status.Landlock {
		close(start)
		for i := 0; i < workers; i++ {
			if err := <-results; !errors.Is(err, fs.ErrPermission) {
				fail("thread %d read a file after enforcement: %v", i, err)
			}
		}
		if _, err := os.ReadFile(secret); !errors.Is(err, fs.ErrPermission) {
			fail("reading a file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "created"), nil, 0o600); !errors.Is(err, fs.ErrPermission) {
			fail("creating a file: %v", err)
		}
		if _, err := os.ReadDir("/"); !errors.Is(err, fs.ErrPermission) {
			fail("listing a directory: %v", err)
		}
		if err := exec.Command("/bin/sh", "-c", "exit 0").Run(); err == nil {
			fail("executing /bin/sh succeeded")
		}
		if data, err := io.ReadAll(preopened); err != nil || string(data) != "secret" {
			fail("descriptor opened before enforcement: %q, %v", data, err)
		}
		if status.LandlockABI >= 4 {
			if err := connectTCP(port); !errors.Is(err, syscall.EACCES) {
				fail("TCP connect: %v", err)
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return 1
	}
	return 0
}

func listenTCP(t *testing.T) (int, func()) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	return sa.(*syscall.SockaddrInet4).Port, func() { syscall.Close(fd) }
}

func connectTCP(port int) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Connect(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: port})
}
