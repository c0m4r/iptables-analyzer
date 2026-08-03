package parser

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// Parse parses iptables-save format output into a Ruleset
func Parse(data string, ipVersion models.IPVersion) (*models.Ruleset, error) {
	rs := &models.Ruleset{
		IPVersion: ipVersion,
		Tables:    make(map[string]*models.Table),
	}

	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var currentTable *models.Table
	var parseErrs []error
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		normalizedLine, counterErr := stripRuleCounters(line)
		if counterErr != nil {
			parseErrs = append(parseErrs, fmt.Errorf("line %d: %w", lineNum, counterErr))
			continue
		}

		switch {
		case strings.HasPrefix(normalizedLine, "*"):
			// Table declaration: *filter, *nat, *mangle, *raw
			if currentTable != nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: table %q is missing COMMIT", lineNum, currentTable.Name))
			}
			tableName := strings.TrimSpace(normalizedLine[1:])
			if tableName == "" {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: empty table declaration", lineNum))
				currentTable = nil
				continue
			}
			if _, exists := rs.Tables[tableName]; exists {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: duplicate table %q", lineNum, tableName))
			}
			currentTable = &models.Table{
				Name:   tableName,
				Chains: make(map[string]*models.Chain),
			}
			rs.Tables[tableName] = currentTable

		case strings.HasPrefix(normalizedLine, ":"):
			// Chain declaration: :INPUT ACCEPT [123:456]
			if currentTable == nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: chain declaration outside a table", lineNum))
				continue
			}
			chain, err := parseChainDecl(normalizedLine)
			if err != nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: %w", lineNum, err))
				continue
			}
			if _, exists := currentTable.Chains[chain.Name]; exists {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: duplicate chain %q", lineNum, chain.Name))
				continue
			}
			currentTable.Chains[chain.Name] = chain

		case strings.HasPrefix(normalizedLine, "-A "):
			// Rule: -A INPUT -p tcp --dport 22 -j ACCEPT
			if currentTable == nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: rule outside a table", lineNum))
				continue
			}
			rule, err := parseRule(normalizedLine, currentTable.Name, ipVersion)
			if err != nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: %w", lineNum, err))
				continue
			}
			if ch, ok := currentTable.Chains[rule.Chain]; ok {
				rule.RawLine = line
				rule.RuleNum = len(ch.Rules) + 1
				ch.Rules = append(ch.Rules, rule)
			} else {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: rule references undeclared chain %q", lineNum, rule.Chain))
			}

		case normalizedLine == "COMMIT":
			if currentTable == nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: COMMIT outside a table", lineNum))
				continue
			}
			currentTable = nil

		default:
			parseErrs = append(parseErrs, fmt.Errorf("line %d: unsupported iptables-save line %q", lineNum, line))
		}
	}

	if err := scanner.Err(); err != nil {
		parseErrs = append(parseErrs, err)
	}
	if currentTable != nil {
		parseErrs = append(parseErrs, fmt.Errorf("table %q is missing COMMIT", currentTable.Name))
	}
	if len(rs.Tables) == 0 {
		parseErrs = append(parseErrs, errors.New("input contains no iptables-save tables"))
	}

	return rs, errors.Join(parseErrs...)
}

func stripRuleCounters(line string) (string, error) {
	if !strings.HasPrefix(line, "[") {
		return line, nil
	}
	end := strings.Index(line, "]")
	if end < 0 {
		return "", fmt.Errorf("unterminated rule counter prefix")
	}
	parts := strings.Split(line[1:end], ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid rule counter prefix %q", line[:end+1])
	}
	for _, value := range parts {
		if _, err := strconv.ParseUint(value, 10, 64); err != nil {
			return "", fmt.Errorf("invalid rule counter prefix %q: %w", line[:end+1], err)
		}
	}
	return strings.TrimSpace(line[end+1:]), nil
}

func parseChainDecl(line string) (*models.Chain, error) {
	// :INPUT ACCEPT [123:456]
	// :DOCKER - [0:0]
	line = strings.TrimPrefix(line, ":")

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid chain declaration: %s", line)
	}

	chain := &models.Chain{
		Name: parts[0],
	}

	policy := parts[1]
	if policy != "-" {
		chain.Policy = policy
	}

	// Parse counters [packets:bytes]
	if len(parts) >= 3 {
		counters := strings.Trim(parts[2], "[]")
		if idx := strings.Index(counters, ":"); idx >= 0 {
			var err error
			chain.Packets, err = strconv.ParseUint(counters[:idx], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid packet counter in chain declaration %q: %w", line, err)
			}
			chain.Bytes, err = strconv.ParseUint(counters[idx+1:], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid byte counter in chain declaration %q: %w", line, err)
			}
		} else {
			return nil, fmt.Errorf("invalid counters in chain declaration: %s", line)
		}
	}

	return chain, nil
}

func parseRule(line string, tableName string, ipVersion models.IPVersion) (models.Rule, error) {
	rule := models.Rule{
		Table:     tableName,
		IPVersion: ipVersion,
		RawLine:   line,
		Negations: make(map[string]bool),
	}

	tokens, err := tokenizeChecked(line)
	if err != nil {
		return rule, err
	}
	if len(tokens) < 2 || tokens[0] != "-A" {
		return rule, fmt.Errorf("invalid rule: %s", line)
	}

	rule.Chain = tokens[1]

	i := 2
	negateNext := false

	for i < len(tokens) {
		tok := tokens[i]

		if tok == "!" {
			negateNext = true
			i++
			continue
		}

		switch tok {
		case "-p", "--protocol":
			if i+1 < len(tokens) {
				rule.Protocol = models.Protocol(strings.ToLower(tokens[i+1]))
				if negateNext {
					rule.Negations["protocol"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "-s", "--source":
			if i+1 < len(tokens) {
				rule.SrcAddr = tokens[i+1]
				if negateNext {
					rule.Negations["src"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "-d", "--destination":
			if i+1 < len(tokens) {
				rule.DstAddr = tokens[i+1]
				if negateNext {
					rule.Negations["dst"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "--sport", "--source-port":
			if i+1 < len(tokens) {
				rule.SrcPort = tokens[i+1]
				if negateNext {
					rule.Negations["sport"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "--dport", "--destination-port":
			if i+1 < len(tokens) {
				rule.DstPort = tokens[i+1]
				if negateNext {
					rule.Negations["dport"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "--dports":
			if i+1 < len(tokens) {
				rule.DstPort = tokens[i+1]
				if negateNext {
					rule.Negations["dport"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "--sports":
			if i+1 < len(tokens) {
				rule.SrcPort = tokens[i+1]
				if negateNext {
					rule.Negations["sport"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "-i", "--in-interface":
			if i+1 < len(tokens) {
				rule.InIface = tokens[i+1]
				if negateNext {
					rule.Negations["in-iface"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "-o", "--out-interface":
			if i+1 < len(tokens) {
				rule.OutIface = tokens[i+1]
				if negateNext {
					rule.Negations["out-iface"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "-j", "--jump":
			if i+1 < len(tokens) {
				rule.Target = tokens[i+1]
				rule.Goto = false
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "-g", "--goto":
			if i+1 < len(tokens) {
				rule.Target = tokens[i+1]
				rule.Goto = true
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "-m", "--match":
			if i+1 < len(tokens) {
				mod := tokens[i+1]
				ext := models.MatchExt{
					Module:    mod,
					Params:    make(map[string]string),
					Negations: make(map[string]bool),
				}
				i += 2
				paramsStart := i
				// Consume module params until next flag
				for i < len(tokens) && !isMainFlag(tokens[i]) {
					param := tokens[i]
					paramNegated := false
					if param == "!" {
						paramNegated = true
						i++
						if i >= len(tokens) {
							return rule, fmt.Errorf("dangling negation in rule: %s", line)
						}
						param = tokens[i]
					}
					if strings.HasPrefix(param, "--") {
						key := param
						val := ""
						if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") && tokens[i+1] != "!" {
							val = tokens[i+1]
							i++
						}
						if val == "" && moduleParamRequiresValue(key) {
							return rule, fmt.Errorf("%s requires a value", key)
						}
						ext.Params[key] = val
						if paramNegated {
							ext.Negations[key] = true
						}

						// Extract well-known params to rule fields
						switch key {
						case "--ctstate", "--state":
							rule.States = strings.Split(val, ",")
							if paramNegated {
								rule.Negations["state"] = true
							}
						case "--dport", "--destination-port":
							if rule.DstPort == "" {
								rule.DstPort = val
							}
							if paramNegated {
								rule.Negations["dport"] = true
							}
						case "--sport", "--source-port":
							if rule.SrcPort == "" {
								rule.SrcPort = val
							}
							if paramNegated {
								rule.Negations["sport"] = true
							}
						case "--dports", "--destination-ports":
							if rule.DstPort == "" {
								rule.DstPort = val
							}
							if paramNegated {
								rule.Negations["dport"] = true
							}
						case "--sports", "--source-ports":
							if rule.SrcPort == "" {
								rule.SrcPort = val
							}
							if paramNegated {
								rule.Negations["sport"] = true
							}
						case "--comment":
							rule.Comment = strings.Trim(val, "\"")
						case "--to-destination":
							rule.DNATTarget = val
						case "--to-source":
							rule.DNATTarget = val
						}
					} else {
						i++
						continue
					}
					i++
				}
				ext.RawTokens = append(ext.RawTokens, tokens[paramsStart:i]...)
				rule.Matches = append(rule.Matches, ext)
				continue // don't increment i again
			} else {
				return rule, fmt.Errorf("%s requires a module name", tok)
			}

		case "--to-destination":
			if i+1 < len(tokens) {
				rule.DNATTarget = tokens[i+1]
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "--to-source":
			if i+1 < len(tokens) {
				rule.DNATTarget = tokens[i+1]
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "--comment":
			if i+1 < len(tokens) {
				rule.Comment = strings.Trim(tokens[i+1], "\"")
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		case "--ctstate", "--state":
			if i+1 < len(tokens) {
				rule.States = strings.Split(tokens[i+1], ",")
				if negateNext {
					rule.Negations["state"] = true
					negateNext = false
				}
				i += 2
			} else {
				return rule, fmt.Errorf("%s requires a value", tok)
			}

		default:
			if strings.HasPrefix(tok, "--") && !isTargetOption(tok) {
				ext := models.MatchExt{Module: "raw", Params: map[string]string{}, Negations: map[string]bool{}, RawTokens: []string{tok}}
				val := ""
				if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") && tokens[i+1] != "!" {
					val = tokens[i+1]
					ext.RawTokens = append(ext.RawTokens, val)
					i++
				}
				ext.Params[tok] = val
				if negateNext {
					ext.Negations[tok] = true
				}
				rule.Matches = append(rule.Matches, ext)
			}
			negateNext = false
			i++
		}
	}
	if negateNext {
		return rule, fmt.Errorf("dangling negation in rule: %s", line)
	}
	return rule, nil
}

func moduleParamRequiresValue(param string) bool {
	switch param {
	case "--ctstate", "--state", "--dport", "--destination-port", "--sport", "--source-port",
		"--dports", "--destination-ports", "--sports", "--source-ports", "--comment",
		"--to-destination", "--to-source", "--seconds", "--hitcount", "--limit",
		"--limit-burst", "--icmp-type", "--icmpv6-type", "--dst-type", "--src-type",
		"--mark", "--match-set", "--probability", "--every", "--mode":
		return true
	default:
		return false
	}
}

func isTargetOption(tok string) bool {
	switch tok {
	case "--reject-with", "--log-prefix", "--log-level", "--log-tcp-sequence",
		"--log-tcp-options", "--log-ip-options", "--nflog-group", "--nflog-prefix",
		"--nflog-range", "--nflog-threshold", "--queue-num", "--queue-balance",
		"--queue-bypass", "--queue-cpu-fanout", "--set-mark", "--set-xmark",
		"--and-mark", "--or-mark", "--xor-mark", "--save-mark", "--restore-mark":
		return true
	default:
		return false
	}
}

func isMainFlag(tok string) bool {
	switch tok {
	case "-p", "--protocol", "-s", "--source", "-d", "--destination",
		"-i", "--in-interface", "-o", "--out-interface",
		"-j", "--jump", "-g", "--goto", "-m", "--match",
		"-A", "-I", "-D", "-R", "-N", "-X", "-P", "-F", "-Z", "-L":
		return true
	}
	return false
}

// tokenize splits a rule line into tokens, handling quoted strings
func tokenize(line string) []string {
	tokens, _ := tokenizeChecked(line)
	return tokens
}

func tokenizeChecked(line string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)
	escaped := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inQuote:
			if escaped {
				current.WriteByte(ch)
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quoteChar {
				inQuote = false
				tokens = append(tokens, current.String())
				current.Reset()
			} else {
				current.WriteByte(ch)
			}
		case ch == '"' || ch == '\'':
			inQuote = true
			quoteChar = ch
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		case ch == ' ' || ch == '\t':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if escaped || inQuote {
		return nil, fmt.Errorf("unterminated quoted string in rule: %s", line)
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens, nil
}
