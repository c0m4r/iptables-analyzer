//go:build linux

package ui

import (
	"os"

	"golang.org/x/sys/unix"
)

// terminalWidth returns the width of the terminal behind f, or 0 when f is
// not a terminal.
func terminalWidth(f *os.File) int {
	size, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(size.Col)
}
