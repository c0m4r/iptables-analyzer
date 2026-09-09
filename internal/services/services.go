package services

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// GetListening returns all listening services from ss output
func GetListening() ([]models.ListeningService, error) {
	var services []models.ListeningService
	var errs []error

	// Get TCP listeners
	tcpSvcs, err := getListeners("tcp")
	if err != nil {
		errs = append(errs, fmt.Errorf("TCP listener discovery: %w", err))
	}
	services = append(services, tcpSvcs...)

	// Get UDP listeners
	udpSvcs, err := getListeners("udp")
	if err != nil {
		errs = append(errs, fmt.Errorf("UDP listener discovery: %w", err))
	}
	services = append(services, udpSvcs...)

	return services, errors.Join(errs...)
}

func getListeners(proto string) ([]models.ListeningService, error) {
	flag := "-tlnp"
	if proto == "udp" {
		flag = "-ulnp"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ss", flag).Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("ss %s timed out: %w", flag, ctx.Err())
		}
		// Try without -p (no root)
		if proto == "tcp" {
			flag = "-tln"
		} else {
			flag = "-uln"
		}
		out, err = exec.CommandContext(ctx, "ss", flag).Output()
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("ss %s timed out: %w", flag, ctx.Err())
			}
			return nil, err
		}
	}

	return parseSSOutput(string(out), proto)
}

var processRe = regexp.MustCompile(`users:\(\("([^"]*)",pid=(\d+)`)

func parseSSOutput(output string, proto string) ([]models.ListeningService, error) {
	return parseSSData(output, proto)
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
		return "*", port
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
	return parseSSData(data, "")
}

func parseSSData(data, forcedProto string) ([]models.ListeningService, error) {
	var services []models.ListeningService
	var parseErrs []error
	recognized := false

	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "State" || strings.Contains(line, "Local Address:Port") {
			recognized = true
			continue
		}
		if len(fields) < 5 {
			parseErrs = append(parseErrs, fmt.Errorf("line %d: malformed ss row", lineNum))
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
			parseErrs = append(parseErrs, fmt.Errorf("line %d: unsupported ss state %q", lineNum, fields[0]))
			continue
		}
		if forcedProto != "" {
			proto = forcedProto
		}

		localAddr := fields[3]
		addr, port := parseAddress(localAddr)
		if port < 1 || port > 65535 {
			parseErrs = append(parseErrs, fmt.Errorf("line %d: invalid local address %q", lineNum, localAddr))
			continue
		}
		family := socketFamily(localAddr)

		svc := models.ListeningService{
			Protocol:   models.Protocol(proto),
			Address:    addr,
			Port:       port,
			IsIPv6:     family == models.SocketIPv6,
			IsWildcard: addr == "0.0.0.0" || addr == "::" || addr == "*",
			Family:     family,
			Status:     models.ServiceNotAnalyzed,
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
		recognized = true
	}

	if err := scanner.Err(); err != nil {
		parseErrs = append(parseErrs, fmt.Errorf("scanning ss data: %w", err))
	}
	if !recognized {
		parseErrs = append(parseErrs, errors.New("input contains no recognizable ss header or listener rows"))
	}
	return services, errors.Join(parseErrs...)
}

func socketFamily(localAddr string) models.SocketFamily {
	if strings.HasPrefix(localAddr, "*:") {
		return models.SocketDual
	}
	if strings.HasPrefix(localAddr, "[") || strings.Count(localAddr, ":") > 1 {
		return models.SocketIPv6
	}
	return models.SocketIPv4
}
