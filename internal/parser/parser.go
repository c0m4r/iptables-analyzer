package parser

import (
	"bufio"
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
	var currentTable *models.Table

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "*"):
			// Table declaration: *filter, *nat, *mangle, *raw
			tableName := line[1:]
			currentTable = &models.Table{
				Name:   tableName,
				Chains: make(map[string]*models.Chain),
			}
			rs.Tables[tableName] = currentTable

		case strings.HasPrefix(line, ":"):
			// Chain declaration: :INPUT ACCEPT [123:456]
			if currentTable == nil {
				continue
			}
			chain, err := parseChainDecl(line)
			if err != nil {
				continue
			}
			currentTable.Chains[chain.Name] = chain

		case strings.HasPrefix(line, "-A "):
			// Rule: -A INPUT -p tcp --dport 22 -j ACCEPT
			if currentTable == nil {
				continue
			}
			rule, err := parseRule(line, currentTable.Name, ipVersion)
			if err != nil {
				continue
			}
			if ch, ok := currentTable.Chains[rule.Chain]; ok {
				rule.RuleNum = len(ch.Rules) + 1
				ch.Rules = append(ch.Rules, rule)
			}

		case line == "COMMIT":
			currentTable = nil
		}
	}

	return rs, scanner.Err()
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
			chain.Packets, _ = strconv.ParseUint(counters[:idx], 10, 64)
			chain.Bytes, _ = strconv.ParseUint(counters[idx+1:], 10, 64)
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

	tokens := tokenize(line)
	if len(tokens) < 3 || tokens[0] != "-A" {
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
				i++
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
				i++
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
				i++
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
				i++
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
				i++
			}

		case "--dports":
			if i+1 < len(tokens) {
				rule.DstPort = tokens[i+1]
				i += 2
			} else {
				i++
			}

		case "--sports":
			if i+1 < len(tokens) {
				rule.SrcPort = tokens[i+1]
				i += 2
			} else {
				i++
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
				i++
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
				i++
			}

		case "-j", "--jump":
			if i+1 < len(tokens) {
				rule.Target = tokens[i+1]
				i += 2
			} else {
				i++
			}

		case "-g", "--goto":
			if i+1 < len(tokens) {
				rule.Target = tokens[i+1]
				i += 2
			} else {
				i++
			}

		case "-m", "--match":
			if i+1 < len(tokens) {
				mod := tokens[i+1]
				ext := models.MatchExt{
					Module: mod,
					Params: make(map[string]string),
				}
				i += 2
				// Consume module params until next flag
				for i < len(tokens) && !isMainFlag(tokens[i]) {
					param := tokens[i]
					if param == "!" {
						i++
						continue
					}
					if strings.HasPrefix(param, "--") {
						key := param
						val := ""
						if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") && tokens[i+1] != "!" {
							val = tokens[i+1]
							i++
						}
						ext.Params[key] = val

						// Extract well-known params to rule fields
						switch key {
						case "--ctstate", "--state":
							rule.States = strings.Split(val, ",")
						case "--dport", "--destination-port":
							if rule.DstPort == "" {
								rule.DstPort = val
							}
						case "--sport", "--source-port":
							if rule.SrcPort == "" {
								rule.SrcPort = val
							}
						case "--dports", "--destination-ports":
							if rule.DstPort == "" {
								rule.DstPort = val
							}
						case "--sports", "--source-ports":
							if rule.SrcPort == "" {
								rule.SrcPort = val
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
				rule.Matches = append(rule.Matches, ext)
				continue // don't increment i again
			} else {
				i++
			}

		case "--to-destination":
			if i+1 < len(tokens) {
				rule.DNATTarget = tokens[i+1]
				i += 2
			} else {
				i++
			}

		case "--to-source":
			if i+1 < len(tokens) {
				rule.DNATTarget = tokens[i+1]
				i += 2
			} else {
				i++
			}

		case "--comment":
			if i+1 < len(tokens) {
				rule.Comment = strings.Trim(tokens[i+1], "\"")
				i += 2
			} else {
				i++
			}

		default:
			negateNext = false
			i++
		}
	}

	return rule, nil
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
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inQuote:
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
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}
