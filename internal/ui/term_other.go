//go:build !linux

package ui

import "os"

func terminalWidth(*os.File) int { return 0 }
