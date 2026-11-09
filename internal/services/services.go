package services

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/safeio"
	"github.com/c0m4r/iptables-analyzer/internal/textsafe"
)

// Capture is the unparsed ss output collected on the live system.
type Capture struct {
	Outputs []Output
	Err     error // failed listener discovery
}

// Output is the ss output listing the listeners of one protocol.
type Output struct {
	Proto string
	Data  string
}

// GetListening collects and parses the listening services of the system.
func GetListening() ([]models.ListeningService, error) {
	return Collect().Parse()
}

// Collect runs ss for TCP and UDP listeners without parsing its output.
func Collect() Capture {
	var capture Capture
	var errs []error
	for _, proto := range []string{"tcp", "udp"} {
		data, err := runSS(proto)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s listener discovery: %w", strings.ToUpper(proto), err))
			continue
		}
		capture.Outputs = append(capture.Outputs, Output{Proto: proto, Data: data})
	}
	capture.Err = errors.Join(errs...)
	return capture
}

// Parse parses the captured output. It is safe to call in the sandbox.
// The error includes the collection failures.
func (c Capture) Parse() ([]models.ListeningService, error) {
	var services []models.ListeningService
	errs := []error{c.Err}
	for _, output := range c.Outputs {
		svcs, err := parseSSData(output.Data, output.Proto)
		services = append(services, svcs...)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s listener discovery: %w", strings.ToUpper(output.Proto), err))
		}
	}
	return services, errors.Join(errs...)
}

func runSS(proto string) (string, error) {
	flag, fallback := "-tlnp", "-tln"
	if proto == "udp" {
		flag, fallback = "-ulnp", "-uln"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := safeio.Run(ctx, "ss", []string{flag}, safeio.MaxServicesSize)
	if err != nil {
		if ctx.Err() != nil {
			return "", err
		}
		// Try without -p (no root)
		out, err = safeio.Run(ctx, "ss", []string{fallback}, safeio.MaxServicesSize)
		if err != nil {
			return "", err
		}
	}
	return string(out), nil
}

var processRe = regexp.MustCompile(`users:\(\("([^"]*)",pid=(\d+)`)

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
	data, err := ReadSSFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSSData(data)
}

// ReadSSFile reads saved ss output without parsing it.
func ReadSSFile(path string) (string, error) {
	data, err := safeio.ReadFile(path, safeio.MaxServicesSize)
	if err != nil {
		return "", fmt.Errorf("reading services file %s: %w", path, err)
	}
	return string(data), nil
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
		// Process names are chosen by any local user; keep their control
		// characters away from the terminal.
		line := textsafe.Escape(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "State" || fields[0] == "Netid" || strings.Contains(line, "Local Address:Port") {
			recognized = true
			continue
		}
		// ss -tulnp prefixes every row with a Netid column (tcp, udp, ...).
		netid := ""
		if len(fields) > 1 && (fields[1] == "LISTEN" || fields[1] == "UNCONN") {
			netid = fields[0]
			fields = fields[1:]
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
		switch netid {
		case "":
		case "tcp", "udp":
			proto = netid
		default:
			parseErrs = append(parseErrs, fmt.Errorf("line %d: unsupported ss socket type %q", lineNum, netid))
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
