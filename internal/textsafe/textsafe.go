// Package textsafe neutralizes untrusted text before it reaches a terminal or
// a shell. Rule comments, chain and interface names, and process names are
// chosen by whoever controls the firewall or runs a process on the host, so
// they must not be able to emit terminal escape sequences or run commands
// when a recommended command is copied into a shell.
package textsafe

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escape replaces characters that a terminal could interpret, or that could
// visually disguise text, with visible placeholders: C0 controls and DEL in
// caret notation (^[ for ESC), C1 controls, Unicode format characters (bidi
// overrides, zero-width characters) and line separators as <U+XXXX>, and
// invalid UTF-8 bytes as <0xNN>. Tabs and spaces are kept. The placeholders
// contain no backslashes or quotes, so escaped iptables-save lines tokenize
// the same way, and escaping is idempotent.
func Escape(s string) string {
	if isPlain(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, "<0x%02X>", s[i])
		case r == '\t':
			b.WriteRune(r)
		case r < 0x20:
			b.WriteByte('^')
			b.WriteByte(byte(r) + '@')
		case r == 0x7f:
			b.WriteString("^?")
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r):
			fmt.Fprintf(&b, "<U+%04X>", r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// isPlain reports whether s is printable ASCII (plus tab), the common case.
func isPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c >= 0x7f {
			return false
		}
	}
	return true
}

// ShellQuote returns s quoted for a POSIX shell. Words made only of
// characters without special meaning are returned unchanged, so ordinary
// iptables arguments (tcp, 10.0.0.0/8, DOCKER-USER, ! ) stay readable.
func ShellQuote(s string) string {
	if s == "!" || (s != "" && isShellSafe(s)) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ShellJoin quotes every argument and joins them with spaces.
func ShellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = ShellQuote(arg)
	}
	return strings.Join(quoted, " ")
}

func isShellSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("@%+=:,./_-", c) >= 0:
		default:
			return false
		}
	}
	return true
}
