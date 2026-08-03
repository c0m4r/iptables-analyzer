package cmd

import "testing"

func TestRootCommandRejectsPositionalArguments(t *testing.T) {
	if err := rootCmd.Args(rootCmd, []string{"rules.v4"}); err == nil {
		t.Fatal("expected positional argument error")
	}
}
