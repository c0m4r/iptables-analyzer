package recommender

import (
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

func TestDockerRecommendationMatchesOriginalPort(t *testing.T) {
	result := &models.AnalysisResult{DockerBypasses: []models.DockerBypassFinding{{
		NATRule:     models.Rule{Protocol: models.ProtoTCP, IPVersion: models.IPv4},
		ExposedPort: "8080", ContainerDest: "172.17.0.2:80", Severity: models.SeverityCritical,
	}}}
	recs := Generate(result)
	if len(recs) < 2 || !strings.Contains(recs[1].Detail, "--ctorigdstport 8080") {
		t.Fatalf("expected original-port conntrack recommendation, got %+v", recs)
	}
	if strings.Contains(recs[1].Detail, "--dport 8080") {
		t.Fatalf("recommendation incorrectly matches post-DNAT dport: %s", recs[1].Detail)
	}
}

func TestIPv6PolicyRecommendationUsesIP6Tables(t *testing.T) {
	result := &models.AnalysisResult{EffectiveIssues: []models.EffectivenessFinding{{
		Title: "INPUT default policy is ACCEPT", Chain: "INPUT", IPVersion: models.IPv6,
	}}}
	recs := Generate(result)
	if len(recs) == 0 || !strings.Contains(recs[0].Detail, "ip6tables -P INPUT DROP") {
		t.Fatalf("expected ip6tables recommendation, got %+v", recs)
	}
}
