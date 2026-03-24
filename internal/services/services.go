package services

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// GetListening returns all listening services from ss output
func GetListening() ([]models.ListeningService, error) {
	var services []models.ListeningService

	// Get TCP listeners
	tcpSvcs, err := getListeners("tcp")
	if err != nil {
		return nil, err
	}
	services = append(services, tcpSvcs...)

	// Get UDP listeners
	udpSvcs, err := getListeners("udp")
	if err != nil {
		return nil, err
	}
	services = append(services, udpSvcs...)

	return services, nil
}

func getListeners(proto string) ([]models.ListeningService, error) {
	flag := "-tlnp"
	if proto == "udp" {
		flag = "-ulnp"
	}

	out, err := exec.Command("ss", flag).Output()
	if err != nil {
		// Try without -p (no root)
		if proto == "tcp" {
			flag = "-tln"
		} else {
			flag = "-uln"
		}
		out, err = exec.Command("ss", flag).Output()
		if err != nil {
			return nil, err
		}
	}

	return parseSSOutput(string(out), proto)
}

var processRe = regexp.MustCompile(`users:\(\("([^"]*)",pid=(\d+)`)

func parseSSOutput(output string, proto string) ([]models.ListeningService, error) {
	var services []models.ListeningService
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip header
	if scanner.Scan() {
		// header line
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Local address is typically field index 3 (State Recv-Q Send-Q Local)
		// But for UDP UNCONN, layout might differ
		localAddrIdx := 3
		if fields[0] == "UNCONN" || fields[0] == "LISTEN" {
			localAddrIdx = 3
		}
		if localAddrIdx >= len(fields) {
			continue
		}

		localAddr := fields[localAddrIdx]
		addr, port := parseAddress(localAddr)
		if port == 0 {
			continue
		}

		svc := models.ListeningService{
			Protocol: models.Protocol(proto),
			Address:  addr,
			Port:     port,
		}

		// Determine if IPv6
		svc.IsIPv6 = strings.Contains(addr, ":")

		// Determine if wildcard
		svc.IsWildcard = addr == "0.0.0.0" || addr == "::" || addr == "*"

		// Parse process info if available
		for _, f := range fields {
			matches := processRe.FindStringSubmatch(f)
			if len(matches) >= 3 {
				svc.Process = matches[1]
				svc.PID, _ = strconv.Atoi(matches[2])
				break
			}
		}

		services = append(services, svc)
	}

	return services, nil
}

func parseAddress(addr string) (string, int) {
	// Handle formats:
	// 0.0.0.0:22
	// 127.0.0.1:631
	// [::]:22
	// :::22
	// *:68

	// Try [::]:port format first
	if strings.HasPrefix(addr, "[") {
		closeBracket := strings.LastIndex(addr, "]")
		if closeBracket >= 0 && closeBracket+1 < len(addr) && addr[closeBracket+1] == ':' {
			ip := addr[1:closeBracket]
			port, _ := strconv.Atoi(addr[closeBracket+2:])
			return ip, port
		}
	}

	// Handle :::port (IPv6 wildcard shorthand from ss)
	if strings.HasPrefix(addr, ":::") {
		port, _ := strconv.Atoi(addr[3:])
		return "::", port
	}

	// Handle *:port
	if strings.HasPrefix(addr, "*:") {
		port, _ := strconv.Atoi(addr[2:])
		return "0.0.0.0", port
	}

	// Handle IPv4 addr:port - split on last colon
	lastColon := strings.LastIndex(addr, ":")
	if lastColon >= 0 {
		ip := addr[:lastColon]
		port, _ := strconv.Atoi(addr[lastColon+1:])
		return ip, port
	}

	return addr, 0
}

// ParseSSFile parses ss output saved to a file for offline analysis.
// The file should contain output from: ss -tlnp && ss -ulnp
func ParseSSFile(path string) ([]models.ListeningService, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading services file %s: %w", path, err)
	}
	return ParseSSData(string(data))
}

// ParseSSData parses combined ss output provided as a string.
// Detects TCP (LISTEN) and UDP (UNCONN) entries automatically.
func ParseSSData(data string) ([]models.ListeningService, error) {
	var services []models.ListeningService

	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Detect protocol from state column
		var proto string
		switch fields[0] {
		case "LISTEN":
			proto = "tcp"
		case "UNCONN":
			proto = "udp"
		default:
			continue
		}

		localAddr := fields[3]
		addr, port := parseAddress(localAddr)
		if port == 0 {
			continue
		}

		svc := models.ListeningService{
			Protocol:   models.Protocol(proto),
			Address:    addr,
			Port:       port,
			IsIPv6:     strings.Contains(addr, ":"),
			IsWildcard: addr == "0.0.0.0" || addr == "::" || addr == "*",
		}

		// Parse process info if available
		for _, f := range fields {
			matches := processRe.FindStringSubmatch(f)
			if len(matches) >= 3 {
				svc.Process = matches[1]
				svc.PID, _ = strconv.Atoi(matches[2])
				break
			}
		}

		services = append(services, svc)
	}

	return services, nil
}
