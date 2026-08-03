package models

import "testing"

func TestReturnIsTerminalWithinChain(t *testing.T) {
	rule := Rule{Target: "RETURN"}
	if !rule.IsTerminal() {
		t.Fatal("RETURN must make following rules in the same chain unreachable")
	}
}
