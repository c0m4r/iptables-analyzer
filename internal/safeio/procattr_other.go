//go:build !linux

package safeio

import "syscall"

func procAttr() *syscall.SysProcAttr {
	return nil
}
