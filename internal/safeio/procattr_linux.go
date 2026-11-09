package safeio

import "syscall"

// procAttr kills a tool if the analyzer dies before it.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
