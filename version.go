package main

import (
	_ "embed"
	"strings"

	"github.com/c0m4r/iptables-analyzer/cmd"
)

//go:embed VERSION
var versionFile string

func init() {
	cmd.Version = strings.TrimSpace(versionFile)
}
