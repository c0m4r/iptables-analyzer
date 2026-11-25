package parser

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/textsafe"
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
		// Control characters in comments or names would reach the terminal
		// and copied commands; escaping keeps the tokenization unchanged.
		line := textsafe.Escape(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			noteSaveComment(rs, line)
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
			chain, err := parseChainDecl(normalizedLine, currentTable.Name)
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

		case normalizedLine == "-F" || strings.HasPrefix(normalizedLine, "-F ") || strings.HasPrefix(normalizedLine, "--flush"):
			// iptables-restore files (not iptables-save output) may flush a
			// chain before re-adding its rules, e.g. for --noflush restores.
			if currentTable == nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: flush outside a table", lineNum))
				continue
			}
			fields := strings.Fields(normalizedLine)
			switch len(fields) {
			case 1:
				for _, chain := range currentTable.Chains {
					chain.Rules = nil
				}
			case 2:
				chain, ok := currentTable.Chains[fields[1]]
				if !ok {
					parseErrs = append(parseErrs, fmt.Errorf("line %d: flush of undeclared chain %q", lineNum, fields[1]))
					continue
				}
				chain.Rules = nil
			default:
				parseErrs = append(parseErrs, fmt.Errorf("line %d: invalid flush command %q", lineNum, line))
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

// ParseNoTables returns the ruleset of iptables-save output that holds no
// table at all: only blank lines and comments. This is what iptables-save
// prints when no rules are loaded, so every chain accepts. ok is false for
// any other input, which Parse must read.
func ParseNoTables(data string, ipVersion models.IPVersion) (rs *models.Ruleset, ok bool) {
	rs = &models.Ruleset{IPVersion: ipVersion, Tables: make(map[string]*models.Table)}
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := textsafe.Escape(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			return nil, false
		}
		noteSaveComment(rs, line)
	}
	if scanner.Err() != nil {
		return nil, false
	}
	return rs, true
}

// noteSaveComment records the two comments with which the nf_tables variant
// of iptables-save reports rules that it does not print.
func noteSaveComment(rs *models.Ruleset, line string) {
	switch {
	case strings.Contains(line, "is incompatible, use 'nft' tool"):
		// # Table `filter' is incompatible, use 'nft' tool.
		name := "?"
		if start := strings.Index(line, "`"); start >= 0 {
			if end := strings.Index(line[start+1:], "'"); end >= 0 {
				name = line[start+1 : start+1+end]
			}
		}
		rs.Unreadable = append(rs.Unreadable, name)
	case strings.Contains(line, "tables-legacy tables present"):
		// # Warning: iptables-legacy tables present, use iptables-legacy-save to see them
		rs.Warnings = append(rs.Warnings, strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "#"), " Warning:")))
	}
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

func parseChainDecl(line, tableName string) (*models.Chain, error) {
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
		if policy != "ACCEPT" && policy != "DROP" {
			return nil, fmt.Errorf("invalid policy %q for chain %s", policy, chain.Name)
		}
		if !isBuiltinChain(tableName, chain.Name) {
			return nil, fmt.Errorf("user-defined chain %s cannot have policy %s", chain.Name, policy)
		}
		chain.Policy = policy
	} else if isBuiltinChain(tableName, chain.Name) {
		return nil, fmt.Errorf("built-in chain %s must declare an ACCEPT or DROP policy", chain.Name)
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

func isBuiltinChain(tableName, chainName string) bool {
	builtins := map[string]map[string]bool{
		"filter":   {"INPUT": true, "FORWARD": true, "OUTPUT": true},
		"nat":      {"PREROUTING": true, "INPUT": true, "OUTPUT": true, "POSTROUTING": true},
		"mangle":   {"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true},
		"raw":      {"PREROUTING": true, "OUTPUT": true},
		"security": {"INPUT": true, "FORWARD": true, "OUTPUT": true},
	}
	return builtins[tableName][chainName]
}

// token is one argument of a rule line. A quoted argument is always a value:
// it is never an option name or a negation, whatever its text is.
type token struct {
	text   string
	quoted bool
}

func (t token) isOption() bool { return !t.quoted && len(t.text) > 1 && t.text[0] == '-' }
func (t token) isBang() bool   { return !t.quoted && t.text == "!" }
func (t token) isMainFlag() bool {
	return !t.quoted && isMainFlag(t.text)
}

// freeTextOptions take exactly one argument that cannot be recognized by its
// form: iptables-save only quotes values that contain characters other than
// letters, digits, "-" and "_", so a comment may be written as --comment -x-.
var freeTextOptions = map[string]bool{
	"--comment": true, "--log-prefix": true, "--nflog-prefix": true,
	"--string": true, "--hex-string": true, "--name": true, "--hashlimit-name": true,
	"--helper": true, "--u32": true, "--bytecode": true, "--object-pinned": true,
	"--path": true, "--label": true, "--condition": true, "--nfacct-name": true,
}

// pairOptions take exactly two arguments.
var pairOptions = map[string]bool{
	"--tcp-flags": true, "--match-set": true,
	"--add-set": true, "--del-set": true, "--map-set": true,
}

// optionValues returns the arguments of the option at tokens[i] and the index
// of the token after them. Options that are not in the tables above take the
// next token unless it looks like an option or a negation.
func optionValues(tokens []token, i int) ([]string, int, error) {
	option := tokens[i].text
	count := 0
	switch {
	case pairOptions[option]:
		count = 2
	case freeTextOptions[option]:
		count = 1
	default:
		if i+1 < len(tokens) && !tokens[i+1].isOption() && !tokens[i+1].isBang() {
			return []string{tokens[i+1].text}, i + 2, nil
		}
		return nil, i + 1, nil
	}
	if i+count >= len(tokens) {
		if count == 1 {
			return nil, 0, fmt.Errorf("%s requires a value", option)
		}
		return nil, 0, fmt.Errorf("%s requires %d values", option, count)
	}
	values := make([]string, 0, count)
	for k := 1; k <= count; k++ {
		values = append(values, tokens[i+k].text)
	}
	return values, i + count + 1, nil
}

func parseRule(line string, tableName string, ipVersion models.IPVersion) (models.Rule, error) {
	rule := models.Rule{
		Table:     tableName,
		IPVersion: ipVersion,
		RawLine:   line,
		Negations: make(map[string]bool),
	}

	tokens, err := tokenizeQuoted(line)
	if err != nil {
		return rule, err
	}
	if len(tokens) < 2 || tokens[0].quoted || tokens[0].text != "-A" {
		return rule, fmt.Errorf("invalid rule: %s", line)
	}

	rule.Chain = tokens[1].text

	// field maps an address, port or interface option to the rule field it
	// sets and the key of its negation.
	field := func(option string) (*string, string) {
		switch option {
		case "-s", "--source":
			return &rule.SrcAddr, "src"
		case "-d", "--destination":
			return &rule.DstAddr, "dst"
		case "--sport", "--source-port", "--sports":
			return &rule.SrcPort, "sport"
		case "--dport", "--destination-port", "--dports":
			return &rule.DstPort, "dport"
		case "-i", "--in-interface":
			return &rule.InIface, "in-iface"
		case "-o", "--out-interface":
			return &rule.OutIface, "out-iface"
		}
		return nil, ""
	}

	i := 2
	negateNext := false
	// value returns the argument of the main option at i.
	value := func() (string, error) {
		if i+1 >= len(tokens) {
			return "", fmt.Errorf("%s requires a value", tokens[i].text)
		}
		return tokens[i+1].text, nil
	}

	for i < len(tokens) {
		tok := tokens[i]

		if tok.isBang() {
			negateNext = true
			i++
			continue
		}
		if tok.quoted {
			// A quoted value without an option in front of it.
			negateNext = false
			i++
			continue
		}

		switch tok.text {
		case "-p", "--protocol":
			val, err := value()
			if err != nil {
				return rule, err
			}
			rule.Protocol = models.Protocol(strings.ToLower(val))
			if negateNext {
				rule.Negations["protocol"] = true
				negateNext = false
			}
			i += 2

		case "-s", "--source", "-d", "--destination",
			"--sport", "--source-port", "--sports",
			"--dport", "--destination-port", "--dports",
			"-i", "--in-interface", "-o", "--out-interface":
			val, err := value()
			if err != nil {
				return rule, err
			}
			target, negation := field(tok.text)
			*target = val
			if negateNext {
				rule.Negations[negation] = true
				negateNext = false
			}
			i += 2

		case "-j", "--jump", "-g", "--goto":
			val, err := value()
			if err != nil {
				return rule, err
			}
			rule.Target = val
			rule.Goto = tok.text == "-g" || tok.text == "--goto"
			i += 2

		case "-m", "--match":
			if i+1 >= len(tokens) {
				return rule, fmt.Errorf("%s requires a module name", tok.text)
			}
			next, err := parseMatch(&rule, tokens, i, line)
			if err != nil {
				return rule, err
			}
			i = next

		case "--to-destination", "--to-source":
			val, err := value()
			if err != nil {
				return rule, err
			}
			rule.DNATTarget = val
			i += 2

		case "--comment":
			val, err := value()
			if err != nil {
				return rule, err
			}
			rule.Comment = strings.Trim(val, "\"")
			i += 2

		case "--ctstate", "--state":
			val, err := value()
			if err != nil {
				return rule, err
			}
			rule.States = strings.Split(val, ",")
			if negateNext {
				rule.Negations["state"] = true
				negateNext = false
			}
			i += 2

		case "-f", "--fragment":
			rule.Fragment = true
			if negateNext {
				rule.Negations["fragment"] = true
				negateNext = false
			}
			i++

		case "-4", "--ipv4", "-6", "--ipv6":
			i++

		case "-c", "--set-counters":
			// Packet and byte counters do not affect what the rule matches.
			if i+2 >= len(tokens) {
				return rule, fmt.Errorf("%s requires 2 values", tok.text)
			}
			i += 3

		default:
			if !tok.isOption() {
				negateNext = false
				i++
				continue
			}
			if rule.Target != "" && !negateNext {
				// iptables-save emits target options after the target. They do
				// not constrain which packets the rule matches.
				values, next, err := optionValues(tokens, i)
				if err != nil {
					return rule, err
				}
				rule.TargetArgs = append(rule.TargetArgs, tok.text)
				rule.TargetArgs = append(rule.TargetArgs, values...)
				for next < len(tokens) && !tokens[next].isOption() && !tokens[next].isBang() {
					rule.TargetArgs = append(rule.TargetArgs, tokens[next].text)
					next++
				}
				i = next
				continue
			}
			if isTargetOption(tok.text) {
				negateNext = false
				i++
				continue
			}
			rawTokens := []string{tok.text}
			if negateNext {
				rawTokens = []string{"!", tok.text}
			}
			ext := models.MatchExt{Module: "raw", Params: map[string]string{}, Negations: map[string]bool{}, RawTokens: rawTokens}
			values, next, err := optionValues(tokens, i)
			if err != nil {
				return rule, err
			}
			ext.RawTokens = append(ext.RawTokens, values...)
			ext.Params[tok.text] = strings.Join(values, " ")
			if negateNext {
				ext.Negations[tok.text] = true
			}
			rule.Matches = append(rule.Matches, ext)
			negateNext = false
			i = next
		}
	}
	if negateNext {
		return rule, fmt.Errorf("dangling negation in rule: %s", line)
	}
	return rule, nil
}

// parseMatch parses "-m module" at tokens[i] with the options that follow it,
// up to the next option of the rule itself. It returns the index of the first
// token it did not consume.
func parseMatch(rule *models.Rule, tokens []token, i int, line string) (int, error) {
	ext := models.MatchExt{
		Module:    tokens[i+1].text,
		Params:    make(map[string]string),
		Negations: make(map[string]bool),
	}
	i += 2
	start := i
	for i < len(tokens) {
		tok := tokens[i]
		negated := false
		if tok.isBang() {
			if i+1 >= len(tokens) {
				return i, fmt.Errorf("dangling negation in rule: %s", line)
			}
			if tokens[i+1].isMainFlag() {
				break // "! -i eth0" negates an option of the rule, not of the module
			}
			negated = true
			i++
			tok = tokens[i]
		} else if tok.isMainFlag() {
			break
		}
		if !tok.isOption() || !strings.HasPrefix(tok.text, "--") {
			// An argument this parser does not attribute to an option. It stays
			// in RawTokens, so the rule is not mistaken for an unconditional one.
			i++
			continue
		}
		key := tok.text
		values, next, err := optionValues(tokens, i)
		if err != nil {
			return i, err
		}
		val := strings.Join(values, " ")
		if val == "" && moduleParamRequiresValue(key) {
			return i, fmt.Errorf("%s requires a value", key)
		}
		ext.Params[key] = val
		if negated {
			ext.Negations[key] = true
		}

		// Extract well-known params to rule fields
		switch key {
		case "--ctstate", "--state":
			rule.States = strings.Split(val, ",")
			if negated {
				rule.Negations["state"] = true
			}
		case "--dport", "--destination-port", "--dports", "--destination-ports":
			if rule.DstPort == "" {
				rule.DstPort = val
			}
			if negated {
				rule.Negations["dport"] = true
			}
		case "--sport", "--source-port", "--sports", "--source-ports":
			if rule.SrcPort == "" {
				rule.SrcPort = val
			}
			if negated {
				rule.Negations["sport"] = true
			}
		case "--comment":
			rule.Comment = strings.Trim(val, "\"")
		case "--to-destination", "--to-source":
			rule.DNATTarget = val
		}
		i = next
	}
	for _, tok := range tokens[start:i] {
		ext.RawTokens = append(ext.RawTokens, tok.text)
	}
	rule.Matches = append(rule.Matches, ext)
	return i, nil
}

func moduleParamRequiresValue(param string) bool {
	switch param {
	case "--ctstate", "--state", "--dport", "--destination-port", "--sport", "--source-port",
		"--dports", "--destination-ports", "--sports", "--source-ports", "--comment",
		"--to-destination", "--to-source", "--seconds", "--hitcount", "--limit",
		"--limit-burst", "--icmp-type", "--icmpv6-type", "--dst-type", "--src-type",
		"--mark", "--match-set", "--probability", "--every", "--mode",
		"--ctorigdstport", "--ctorigdst", "--ctdir", "--tcp-flags",
		"--src-range", "--dst-range", "--mac-source":
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
		"-f", "--fragment",
		"-A", "-I", "-D", "-R", "-N", "-X", "-P", "-F", "-Z", "-L":
		return true
	}
	return false
}

// Tokenize splits an iptables-save rule specification into arguments,
// removing the quoting that iptables-save applies.
func Tokenize(line string) ([]string, error) {
	return tokenizeChecked(line)
}

// tokenize splits a rule line into tokens, handling quoted strings
func tokenize(line string) []string {
	tokens, _ := tokenizeChecked(line)
	return tokens
}

func tokenizeChecked(line string) ([]string, error) {
	tokens, err := tokenizeQuoted(line)
	if err != nil {
		return nil, err
	}
	texts := make([]string, len(tokens))
	for i, tok := range tokens {
		texts[i] = tok.text
	}
	return texts, nil
}

// tokenizeQuoted splits a rule line into tokens and records which of them
// were quoted.
func tokenizeQuoted(line string) ([]token, error) {
	var tokens []token
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
				tokens = append(tokens, token{text: current.String(), quoted: true})
				current.Reset()
			} else {
				current.WriteByte(ch)
			}
		case ch == '"' || ch == '\'':
			inQuote = true
			quoteChar = ch
			if current.Len() > 0 {
				tokens = append(tokens, token{text: current.String()})
				current.Reset()
			}
		case ch == ' ' || ch == '\t':
			if current.Len() > 0 {
				tokens = append(tokens, token{text: current.String()})
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
		tokens = append(tokens, token{text: current.String()})
	}
	return tokens, nil
}
