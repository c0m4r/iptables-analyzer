//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"golang.org/x/sys/unix"
)

// Enforce confines the calling process; see the package documentation.
// In Auto mode missing kernel support is reported in the status only; in
// Strict mode it is an error. Enforce cannot be undone.
func Enforce(mode Mode) (models.SandboxStatus, error) {
	status := models.SandboxStatus{Mode: string(mode)}
	if mode == Off {
		return status, nil
	}
	preload()

	var problems []string
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		if err := dropPrivileges(); err != nil {
			problems = append(problems, "dropping root privileges: "+err.Error())
		} else {
			status.PrivilegesDropped = true
		}
	}

	abi, err := landlockABI()
	status.LandlockABI = abi
	if err == nil {
		err = restrict(abi)
	}
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		status.Landlock = true
		_, status.Restricted = policy(abi)
	}

	status.Notes = problems
	if mode == Strict && len(problems) > 0 {
		return status, incomplete(problems)
	}
	return status, nil
}

// dropPrivileges switches every thread to the unprivileged user. Changing
// all user ids away from 0 also clears the capability sets.
func dropPrivileges() error {
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setresgid(unprivilegedID, unprivilegedID, unprivilegedID); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := syscall.Setresuid(unprivilegedID, unprivilegedID, unprivilegedID); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("still running as root")
	}
	return nil
}

func landlockABI() (int, error) {
	abi, _, errno := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	switch errno {
	case 0:
		return int(abi), nil
	case syscall.ENOSYS:
		return 0, errors.New("the kernel does not support Landlock")
	case syscall.EOPNOTSUPP:
		return 0, errors.New("Landlock is disabled; add landlock to the lsm= kernel parameter")
	}
	return 0, fmt.Errorf("querying the Landlock ABI: %w", errno)
}

// rulesetAttr is struct landlock_ruleset_attr up to the scoped field.
// The kernel accepts this prefix of the structure on every ABI.
type rulesetAttr struct {
	handledAccessFS  uint64
	handledAccessNet uint64
	scoped           uint64
}

// policy returns a ruleset that handles every access right abi knows. With
// no rules added, all of them are denied. It also names the restrictions.
func policy(abi int) (rulesetAttr, []string) {
	var attr rulesetAttr
	if abi < 1 {
		return attr, nil
	}
	attr.handledAccessFS = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	restricted := []string{"filesystem", "exec"}
	if abi >= 2 {
		attr.handledAccessFS |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		attr.handledAccessFS |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 4 {
		attr.handledAccessNet |= unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
		restricted = append(restricted, "tcp")
	}
	if abi >= 5 {
		attr.handledAccessFS |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	if abi >= 6 {
		attr.scoped |= unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL
		restricted = append(restricted, "abstract-unix-sockets", "signals")
	}
	if abi >= 9 {
		attr.handledAccessFS |= unix.LANDLOCK_ACCESS_FS_RESOLVE_UNIX
		restricted = append(restricted, "pathname-unix-sockets")
	}
	if abi >= 10 {
		attr.handledAccessNet |= unix.LANDLOCK_ACCESS_NET_BIND_UDP | unix.LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP
		restricted = append(restricted, "udp")
	}
	return attr, restricted
}

// restrict enforces policy(abi) on every thread of the process. Landlock
// and no_new_privs are per-thread attributes, and the Go runtime has
// started several threads already: ABI 8 confines all of them with one
// call (TSYNC); before that, syscall.AllThreadsSyscall repeats the call on
// each thread, which the runtime only supports in binaries without cgo.
func restrict(abi int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	allThreads := true
	if _, _, errno := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno == syscall.ENOTSUP {
		allThreads = false
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("setting no_new_privs: %w", err)
		}
	} else if errno != 0 {
		return fmt.Errorf("setting no_new_privs: %w", errno)
	}
	if abi < 8 && !allThreads {
		return errors.New("Landlock below ABI 8 cannot confine every thread of a cgo binary; build with CGO_ENABLED=0")
	}

	attr, _ := policy(abi)
	fd, _, errno := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("creating the Landlock ruleset: %w", errno)
	}
	defer syscall.Close(int(fd))

	if abi >= 8 {
		_, _, errno = syscall.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, unix.LANDLOCK_RESTRICT_SELF_TSYNC, 0)
	} else {
		_, _, errno = syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0)
	}
	if errno != 0 {
		return fmt.Errorf("enforcing Landlock: %w", errno)
	}
	return nil
}
