package report

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// PortSpec is a range of ports of one protocol.
type PortSpec struct {
	Protocol models.Protocol
	First    int
	Last     int
}

// ParsePublic reads a list of ports that are public on purpose, as the
// --public option takes it: "tcp/80,tcp/443,udp/53". The protocol may follow
// the port ("443/tcp"), a port may be a range ("tcp/8000-8100"), and a port
// without a protocol is TCP.
func ParsePublic(value string) ([]PortSpec, error) {
	var specs []PortSpec
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		protocol, ports := models.ProtoTCP, item
		if left, right, found := strings.Cut(item, "/"); found {
			switch {
			case left == "tcp" || left == "udp":
				protocol, ports = models.Protocol(left), right
			case right == "tcp" || right == "udp":
				protocol, ports = models.Protocol(right), left
			default:
				return nil, fmt.Errorf("invalid port %q: the protocol must be tcp or udp", item)
			}
		}
		first, last, isRange := strings.Cut(ports, "-")
		spec := PortSpec{Protocol: protocol}
		var err error
		if spec.First, err = strconv.Atoi(first); err != nil {
			return nil, fmt.Errorf("invalid port %q", item)
		}
		spec.Last = spec.First
		if isRange {
			if spec.Last, err = strconv.Atoi(last); err != nil {
				return nil, fmt.Errorf("invalid port %q", item)
			}
		}
		if spec.First < 1 || spec.Last > 65535 || spec.First > spec.Last {
			return nil, fmt.Errorf("invalid port %q: ports are 1 to 65535", item)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// declaredPublic reports whether every port of the range was declared public.
func (b *builder) declaredPublic(protocol models.Protocol, first, last int) bool {
	for port := first; port <= last; {
		covered := false
		for _, spec := range b.opts.Public {
			if spec.Protocol == protocol && spec.First <= port && port <= spec.Last {
				port, covered = spec.Last+1, true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// portText renders "22/tcp" or "8000-8100/tcp".
func portText(protocol models.Protocol, first, last int) string {
	if last > first {
		return strconv.Itoa(first) + "-" + strconv.Itoa(last) + "/" + string(protocol)
	}
	return strconv.Itoa(first) + "/" + string(protocol)
}

// parsePortRange reads "8080" or "9000-9002".
func parsePortRange(text string) (first, last int, ok bool) {
	low, high, isRange := strings.Cut(text, "-")
	first, err := strconv.Atoi(low)
	if err != nil {
		return 0, 0, false
	}
	last = first
	if isRange {
		if last, err = strconv.Atoi(high); err != nil || last < first {
			return 0, 0, false
		}
	}
	return first, last, true
}

// exposurePoints is what a range of ports that is open to any source costs.
// It follows the kind of service that usually listens there: a database or
// remote administration costs more than a web server.
func exposurePoints(first, last int, condition string) int {
	points := 2
	switch analyzer.RiskOfPorts(first, last) {
	case analyzer.RiskSensitive:
		points = 5
	case analyzer.RiskPublic:
		points = 1
	}
	switch {
	case strings.HasPrefix(condition, "source port"):
		points = 1
	case strings.Contains(condition, "rate limit") || strings.Contains(condition, "connection limit"):
		points = min(points, 2)
	}
	return points
}

// weigh halves the points of a finding that is only possible.
func weigh(points int, certainty models.Certainty) int {
	if certainty == models.CertaintyPossible {
		return (points + 1) / 2
	}
	return points
}
