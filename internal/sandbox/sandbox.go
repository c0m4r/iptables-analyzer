// Package sandbox confines the analyzer once it has collected its input.
//
// Rules files, saved ss output and the output of the live tools are
// untrusted: comments, chain names and process names are chosen by whoever
// controls the firewall or runs a process on the host. Everything that
// processes them (parsing, analysis, rendering through third-party
// libraries) runs after Enforce, which
//
//   - drops root privileges to uid/gid 65534 (live mode runs as root),
//   - sets no_new_privs, and
//   - installs a Landlock domain without any allow rule, so the process can
//     no longer open, create or execute files, use TCP or UDP, connect to
//     sockets outside the domain, or signal other processes. Descriptors
//     opened earlier, such as standard output, keep working.
package sandbox

import (
	"fmt"
	"strings"
	"time"
)

// Mode selects how strictly the sandbox is applied.
type Mode string

const (
	// Auto applies every restriction the system supports and continues
	// without the unsupported ones.
	Auto Mode = "auto"
	// Strict fails unless privileges could be dropped and Landlock enforced.
	Strict Mode = "strict"
	// Off disables the sandbox.
	Off Mode = "off"
)

// ParseMode validates a --sandbox value.
func ParseMode(value string) (Mode, error) {
	switch mode := Mode(value); mode {
	case Auto, Strict, Off:
		return mode, nil
	}
	return "", fmt.Errorf("--sandbox must be auto, strict or off")
}

// unprivilegedID is the conventional nobody/nogroup id that root drops to.
const unprivilegedID = 65534

// preload initializes lazily loaded process state that needs the
// filesystem, so that it is available after the filesystem is closed.
func preload() {
	time.Now().Zone() // loads /etc/localtime or $TZ for report timestamps
}

func incomplete(problems []string) error {
	return fmt.Errorf("sandbox could not be fully enforced: %s", strings.Join(problems, "; "))
}
