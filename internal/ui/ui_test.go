package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

func TestRenderScoreUsesHundredPointCategoryTotal(t *testing.T) {
	if categoryMax["policy"]+categoryMax["exposure"]+categoryMax["shadow"]+
		categoryMax["hygiene"]+categoryMax["ipv6"] != 100 {
		t.Fatalf("category maxima must total 100: %+v", categoryMax)
	}
	var output bytes.Buffer
	renderScore(&output, models.ScoreResult{Total: 100, Grade: "A", Breakdown: map[string]int{}})
	if !strings.Contains(output.String(), "100/100") {
		t.Fatalf("missing score in output: %q", output.String())
	}
}
