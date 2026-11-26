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

// Parse parses the output of iptables-save into a Ruleset. It also reads
// the output of "iptables -S", which lists one table without naming it:
//
//	-P INPUT DROP
//	-N f2b-sshd
//	-A INPUT -p tcp -m tcp --dport 22 -j f2b-sshd
//
// The table of such a listing is told from the chains whose policy it
// states. The listings of several tables can follow each other in one file.
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
	// A listing has no table lines. listed is true inside the table of a
	// listing; policies holds the -P lines of the table that starts, until
	// its other lines follow; named is true after a table line was read.
	listed, named := false, false
	var policies [][2]string
	// openListing makes the table of the -P lines that were read.
	openListing := func() error {
		table, err := listingTable(rs, policies)
		policies = nil
		if err != nil {
			return err
		}
		currentTable, listed = table, true
		return nil
	}

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

		// The lines of a listing: -P opens a table, and the first other line
		// after the -P lines tells that all of them were read.
		policyLine := strings.HasPrefix(normalizedLine, "-P ")
		if policyLine && !named && (currentTable == nil || listed) {
			fields := strings.Fields(normalizedLine)
			if len(fields) != 3 || (fields[2] != "ACCEPT" && fields[2] != "DROP") {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: invalid policy line %q", lineNum, line))
				continue
			}
			currentTable, listed = nil, false // the table before this one is complete
			// The chains of a listing come in the order of the hooks. A chain
			// that is not behind the last one starts the next table.
			if n := len(policies); n > 0 && hookOrder[fields[1]] <= hookOrder[policies[n-1][0]] {
				if err := openListing(); err != nil {
					parseErrs = append(parseErrs, fmt.Errorf("line %d: %w", lineNum, err))
				}
				currentTable, listed = nil, false
			}
			policies = append(policies, [2]string{fields[1], fields[2]})
			continue
		}
		if len(policies) > 0 {
			if err := openListing(); err != nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: %w", lineNum, err))
			}
		}

		switch {
		case strings.HasPrefix(normalizedLine, "*"):
			// Table declaration: *filter, *nat, *mangle, *raw
			named = true
			if listed {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: a table line after the lines of a listing (iptables -S)", lineNum))
				currentTable, listed = nil, false
			}
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

		case policyLine:
			// "-P CHAIN POLICY" in a table of a rules file sets the policy.
			fields := strings.Fields(normalizedLine)
			if currentTable == nil || len(fields) != 3 || (fields[2] != "ACCEPT" && fields[2] != "DROP") {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: invalid policy line %q", lineNum, line))
				continue
			}
			chain, ok := currentTable.Chains[fields[1]]
			if !ok || !isBuiltinChain(currentTable.Name, fields[1]) {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: policy for %q, which is no built-in chain of table %s", lineNum, fields[1], currentTable.Name))
				continue
			}
			chain.Policy = fields[2]

		case strings.HasPrefix(normalizedLine, "-N "):
			// "-N CHAIN" declares a user-defined chain.
			fields := strings.Fields(normalizedLine)
			switch {
			case currentTable == nil:
				parseErrs = append(parseErrs, fmt.Errorf("line %d: chain %q outside a table; a listing (iptables -S) starts with its -P lines", lineNum, line))
			case len(fields) != 2 || isBuiltinChain(currentTable.Name, fields[1]):
				parseErrs = append(parseErrs, fmt.Errorf("line %d: invalid chain line %q", lineNum, line))
			case currentTable.Chains[fields[1]] != nil:
				parseErrs = append(parseErrs, fmt.Errorf("line %d: duplicate chain %q", lineNum, fields[1]))
			default:
				currentTable.Chains[fields[1]] = &models.Chain{Name: fields[1]}
			}

		case strings.HasPrefix(normalizedLine, "-A "), strings.HasPrefix(normalizedLine, "-I "):
			// Rule: -A INPUT -p tcp --dport 22 -j ACCEPT
			if currentTable == nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: rule outside a table", lineNum))
				continue
			}
			// "-I CHAIN [N] ..." puts the rule in front of rule N, or first.
			position, insert := 0, false
			if strings.HasPrefix(normalizedLine, "-I ") {
				insert = true
				fields := strings.Fields(normalizedLine)
				if len(fields) < 2 {
					parseErrs = append(parseErrs, fmt.Errorf("line %d: invalid rule %q", lineNum, line))
					continue
				}
				position = 1
				rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(normalizedLine, "-I"), " "+fields[1]))
				if len(fields) > 2 {
					if number, err := strconv.Atoi(fields[2]); err == nil {
						position = number
						rest = strings.TrimSpace(strings.TrimPrefix(rest, fields[2]))
					}
				}
				normalizedLine = strings.TrimSpace("-A " + fields[1] + " " + rest)
				line = normalizedLine
			}
			rule, err := parseRule(normalizedLine, currentTable.Name, ipVersion)
			if err != nil {
				parseErrs = append(parseErrs, fmt.Errorf("line %d: %w", lineNum, err))
				continue
			}
			ch, ok := currentTable.Chains[rule.Chain]
			switch {
			case !ok:
				parseErrs = append(parseErrs, fmt.Errorf("line %d: rule references undeclared chain %q", lineNum, rule.Chain))
			case !insert:
				rule.RawLine = line
				rule.RuleNum = len(ch.Rules) + 1
				ch.Rules = append(ch.Rules, rule)
			case position < 1 || position > len(ch.Rules)+1:
				parseErrs = append(parseErrs, fmt.Errorf("line %d: rule number %d is not in chain %q", lineNum, position, rule.Chain))
			default:
				rule.RawLine = line
				ch.Rules = append(ch.Rules, models.Rule{})
				copy(ch.Rules[position:], ch.Rules[position-1:])
				ch.Rules[position-1] = rule
				for i := range ch.Rules {
					ch.Rules[i].RuleNum = i + 1
				}
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
	if len(policies) > 0 {
		// A listing of a table without chains and rules of its own.
		if err := openListing(); err != nil {
			parseErrs = append(parseErrs, err)
		}
	}
	if currentTable != nil && !listed {
		parseErrs = append(parseErrs, fmt.Errorf("table %q is missing COMMIT", currentTable.Name))
	}
	if len(rs.Tables) == 0 {
		parseErrs = append(parseErrs, errors.New("input contains no iptables-save tables"))
	}

	return rs, errors.Join(parseErrs...)
}

// hookOrder is the order in which a listing prints the built-in chains.
var hookOrder = map[string]int{"PREROUTING": 1, "INPUT": 2, "FORWARD": 3, "OUTPUT": 4, "POSTROUTING": 5}

// listingTable makes the table of a listing (iptables -S) from its -P lines.
// The built-in chains tell the table: a listing does not name it.
func listingTable(rs *models.Ruleset, policies [][2]string) (*models.Table, error) {
	chains := map[string]bool{}
	for _, policy := range policies {
		if chains[policy[0]] {
			return nil, fmt.Errorf("two policies for chain %q in one listing", policy[0])
		}
		chains[policy[0]] = true
	}
	name := ""
	for _, candidate := range []string{"filter", "security", "nat", "mangle", "raw"} {
		if _, exists := rs.Tables[candidate]; exists {
			continue
		}
		fits := len(chains) > 0
		for chain := range chains {
			fits = fits && isBuiltinChain(candidate, chain)
		}
		for _, chain := range []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"} {
			fits = fits && (!isBuiltinChain(candidate, chain) || chains[chain])
		}
		if fits {
			name = candidate
			break
		}
	}
	if name == "" {
		var names []string
		for _, policy := range policies {
			names = append(names, policy[0])
		}
		return nil, fmt.Errorf("a listing (iptables -S) with the policies of %s is no table, or the table is listed twice", strings.Join(names, ", "))
	}
	table := &models.Table{Name: name, Chains: map[string]*models.Chain{}}
	for _, policy := range policies {
		table.Chains[policy[0]] = &models.Chain{Name: policy[0], Policy: policy[1]}
	}
	rs.Tables[name] = table
	return table, nil
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

// Tokens are judged by their text, whether or not they were quoted: that is
// what iptables-restore does after it has removed the quotes. A quoted "-j"
// is the option -j there, so it must be the option -j here, or a rules file
// could show this program one ruleset and load another.

func isOption(tok string) bool { return len(tok) > 1 && tok[0] == '-' }

// freeTextOptions take exactly one argument that cannot be recognized by its
// form: iptables-save only quotes values that contain characters other than
// letters, digits, "-" and "_", so a comment may be written as --comment -x-.
// The option parser of iptables takes the next argument of such an option
// whatever it looks like, and so does this one.
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
// next token unless it looks like an option. negated reports the old form
// "--option ! value", which iptables still accepts.
func optionValues(tokens []string, i int) (values []string, next int, negated bool, err error) {
	option := tokens[i]
	count := 0
	switch {
	case pairOptions[option]:
		count = 2
	case freeTextOptions[option]:
		count = 1
	default:
		if i+2 < len(tokens) && tokens[i+1] == "!" && !isOption(tokens[i+2]) {
			return []string{tokens[i+2]}, i + 3, true, nil
		}
		if i+1 < len(tokens) && !isOption(tokens[i+1]) && tokens[i+1] != "!" {
			return []string{tokens[i+1]}, i + 2, false, nil
		}
		return nil, i + 1, false, nil
	}
	if i+count >= len(tokens) {
		if count == 1 {
			return nil, 0, false, fmt.Errorf("%s requires a value", option)
		}
		return nil, 0, false, fmt.Errorf("%s requires %d values", option, count)
	}
	return tokens[i+1 : i+1+count], i + count + 1, false, nil
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
	// value returns the argument of the option at i and moves i behind it.
	// The option takes the next token whatever it looks like. "! value" is
	// the old place of the negation; it sets negateNext like "! --option".
	value := func() (string, error) {
		option := tokens[i]
		if i+2 < len(tokens) && tokens[i+1] == "!" {
			negateNext = true
			i += 3
			return tokens[i-1], nil
		}
		if i+1 >= len(tokens) {
			return "", fmt.Errorf("%s requires a value", option)
		}
		i += 2
		return tokens[i-1], nil
	}
	// negated reports and clears a pending negation.
	negated := func() bool {
		was := negateNext
		negateNext = false
		return was
	}

	for i < len(tokens) {
		tok := tokens[i]

		if tok == "!" {
			negateNext = true
			i++
			continue
		}

		switch tok {
		case "-p", "--protocol":
			val, err := value()
			if err != nil {
				return rule, err
			}
			rule.Protocol = models.Protocol(strings.ToLower(val))
			if negated() {
				rule.Negations["protocol"] = true
			}

		case "-s", "--source", "-d", "--destination",
			"--sport", "--source-port", "--sports",
			"--dport", "--destination-port", "--dports",
			"-i", "--in-interface", "-o", "--out-interface":
			val, err := value()
			if err != nil {
				return rule, err
			}
			target, negation := field(tok)
			*target = val
			if negated() {
				rule.Negations[negation] = true
			}

		case "-j", "--jump", "-g", "--goto":
			if i+1 >= len(tokens) {
				return rule, fmt.Errorf("%s requires a value", tok)
			}
			if negated() {
				return rule, fmt.Errorf("a target cannot be negated in rule: %s", line)
			}
			rule.Target = tokens[i+1]
			rule.Goto = tok == "-g" || tok == "--goto"
			i += 2

		case "-m", "--match":
			if i+1 >= len(tokens) {
				return rule, fmt.Errorf("%s requires a module name", tok)
			}
			if negated() {
				return rule, fmt.Errorf("a match module cannot be negated in rule: %s", line)
			}
			next, err := parseMatch(&rule, tokens, i, line)
			if err != nil {
				return rule, err
			}
			i = next

		case "--to-destination", "--to-source":
			if i+1 >= len(tokens) {
				return rule, fmt.Errorf("%s requires a value", tok)
			}
			rule.DNATTarget = tokens[i+1]
			negateNext = false
			i += 2

		case "--comment":
			if i+1 >= len(tokens) {
				return rule, fmt.Errorf("%s requires a value", tok)
			}
			rule.Comment = strings.Trim(tokens[i+1], "\"")
			negateNext = false
			i += 2

		case "--ctstate", "--state":
			val, err := value()
			if err != nil {
				return rule, err
			}
			rule.States = strings.Split(val, ",")
			if negated() {
				rule.Negations["state"] = true
			}

		case "-f", "--fragment":
			rule.Fragment = true
			if negated() {
				rule.Negations["fragment"] = true
			}
			i++

		case "-4", "--ipv4", "-6", "--ipv6":
			negateNext = false
			i++

		case "-c", "--set-counters":
			// Packet and byte counters do not affect what the rule matches.
			if i+2 >= len(tokens) {
				return rule, fmt.Errorf("%s requires 2 values", tok)
			}
			negateNext = false
			i += 3

		default:
			if !isOption(tok) {
				// iptables-restore refuses an argument that belongs to no
				// option. Reading on would analyze rules that cannot be loaded.
				return rule, fmt.Errorf("unexpected argument %q in rule: %s", tok, line)
			}
			if rule.Target != "" && !negateNext {
				// iptables-save emits target options after the target. They do
				// not constrain which packets the rule matches.
				values, next, _, err := optionValues(tokens, i)
				if err != nil {
					return rule, err
				}
				rule.TargetArgs = append(rule.TargetArgs, tok)
				rule.TargetArgs = append(rule.TargetArgs, values...)
				for next < len(tokens) && !isOption(tokens[next]) && tokens[next] != "!" {
					rule.TargetArgs = append(rule.TargetArgs, tokens[next])
					next++
				}
				i = next
				continue
			}
			if isTargetOption(tok) {
				// A target option in front of its target: skip it with its value.
				_, next, _, err := optionValues(tokens, i)
				if err != nil {
					return rule, err
				}
				negateNext = false
				i = next
				continue
			}
			rawTokens := []string{tok}
			if negateNext {
				rawTokens = []string{"!", tok}
			}
			ext := models.MatchExt{Module: "raw", Params: map[string]string{}, Negations: map[string]bool{}, RawTokens: rawTokens}
			values, next, inverted, err := optionValues(tokens, i)
			if err != nil {
				return rule, err
			}
			ext.RawTokens = append(ext.RawTokens, tokens[i+1:next]...)
			ext.Params[tok] = strings.Join(values, " ")
			if negateNext || inverted {
				ext.Negations[tok] = true
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
func parseMatch(rule *models.Rule, tokens []string, i int, line string) (int, error) {
	ext := models.MatchExt{
		Module:    tokens[i+1],
		Params:    make(map[string]string),
		Negations: make(map[string]bool),
	}
	i += 2
	start := i
	for i < len(tokens) {
		tok := tokens[i]
		negated := false
		if tok == "!" {
			if i+1 >= len(tokens) {
				return i, fmt.Errorf("dangling negation in rule: %s", line)
			}
			if isMainFlag(tokens[i+1]) {
				break // "! -i eth0" negates an option of the rule, not of the module
			}
			negated = true
			i++
			tok = tokens[i]
		} else if isMainFlag(tok) {
			break
		}
		if !strings.HasPrefix(tok, "--") {
			// An argument this parser does not attribute to an option. It stays
			// in RawTokens, so the rule is not mistaken for an unconditional one.
			i++
			continue
		}
		key := tok
		values, next, inverted, err := optionValues(tokens, i)
		if err != nil {
			return i, err
		}
		negated = negated || inverted
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
	ext.RawTokens = append(ext.RawTokens, tokens[start:i]...)
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
