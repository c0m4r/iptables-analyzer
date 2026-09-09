package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRootCommandRejectsPositionalArguments(t *testing.T) {
	if err := rootCmd.Args(rootCmd, []string{"rules.v4"}); err == nil {
		t.Fatal("expected positional argument error")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestExplicitServicesFileFailuresAreFatal(t *testing.T) {
	command := NewRootCommand()
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{
		"-4", "--file", filepath.Join("..", "testdata", "basic.iptables-save"),
		"--services-file", filepath.Join(t.TempDir(), "missing-services.txt"), "--json", "--score-only",
	})
	if err := command.Execute(); err == nil {
		t.Fatal("missing explicitly requested services file was not fatal")
	}
}

func TestMixedFamilyInventoryMarksExcludedStackNotAnalyzed(t *testing.T) {
	command := NewRootCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{
		"-4", "--no-color", "--file", filepath.Join("..", "testdata", "basic.iptables-save"),
		"--services-file", filepath.Join("..", "testdata", "services.txt"),
	})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte("NOT ANALYZED")) {
		t.Fatalf("excluded IPv6 services were not labeled NOT ANALYZED: %s", output.String())
	}
}

func TestMalformedServicesFileIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "services.txt")
	if err := os.WriteFile(path, []byte("this is not ss output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := NewRootCommand()
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"-4", "--file", filepath.Join("..", "testdata", "basic.iptables-save"), "--services-file", path})
	if err := command.Execute(); err == nil {
		t.Fatal("malformed explicitly requested services file was not fatal")
	}
}

func TestCommandPropagatesOutputFailure(t *testing.T) {
	command := NewRootCommand()
	command.SetOut(errorWriter{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"-4", "--file", filepath.Join("..", "testdata", "basic.iptables-save"), "--json", "--score-only"})
	if err := command.Execute(); err == nil {
		t.Fatal("command ignored output failure")
	}
}
