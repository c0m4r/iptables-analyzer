//go:build !linux

package sandbox

import "github.com/c0m4r/iptables-analyzer/internal/models"

// Enforce is only implemented on Linux.
func Enforce(mode Mode) (models.SandboxStatus, error) {
	status := models.SandboxStatus{Mode: string(mode)}
	if mode == Off {
		return status, nil
	}
	preload()
	problems := []string{"the sandbox is only available on Linux"}
	status.Notes = problems
	if mode == Strict {
		return status, incomplete(problems)
	}
	return status, nil
}
