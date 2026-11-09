package textsafe

import (
	"os/exec"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestEscapeNeutralizesTerminalControls(t *testing.T) {
	cases := map[string]string{
		"plain text":           "plain text",
		"tab\tkept":            "tab\tkept",
		"\x1b[2J\x1b]52;c;x\a": "^[[2J^[]52;c;x^G",
		"new\nline\r":          "new^Jline^M",
		"del\x7f":              "del^?",
		"c1 \u009b31m":         "c1 <U+009B>31m",
		"bidi \u202eevil":      "bidi <U+202E>evil",
		"zero\u200bwidth":      "zero<U+200B>width",
		"line\u2028sep":        "line<U+2028>sep",
		"bad \xff byte":        "bad <0xFF> byte",
		"żółw ✓":               "żółw ✓",
	}
	for in, want := range cases {
		if got := Escape(in); got != want {
			t.Errorf("Escape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShellQuoteRoundTripsThroughShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell available")
	}
	values := []string{
		"tcp", "10.0.0.0/8", "DOCKER-USER", "!", "", "my rule", "$(touch /tmp/pwned)",
		"`id`", "it's", "a'b'c", "x;y|z&w", "*", "~root", "a\nb", "\"quoted\"", "-j", "{a,b}",
	}
	for _, value := range values {
		out, err := exec.Command(sh, "-c", "printf '%s' "+ShellQuote(value)).Output()
		if err != nil {
			t.Fatalf("shell rejected %q quoted as %s: %v", value, ShellQuote(value), err)
		}
		if string(out) != value {
			t.Errorf("ShellQuote(%q) = %s evaluates to %q", value, ShellQuote(value), out)
		}
	}
}

func TestShellJoinKeepsSafeWordsReadable(t *testing.T) {
	got := ShellJoin([]string{"-p", "tcp", "!", "-s", "10.0.0.0/8", "-m", "comment", "--comment", "a b", "-j", "ACCEPT"})
	want := "-p tcp ! -s 10.0.0.0/8 -m comment --comment 'a b' -j ACCEPT"
	if got != want {
		t.Fatalf("ShellJoin = %s, want %s", got, want)
	}
}

// unquote parses the output of ShellQuote the way a POSIX shell parses one word.
func unquote(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch s[i] {
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return "", false
			}
			b.WriteString(s[i+1 : i+1+end])
			i += end + 2
		case '\\':
			if i+1 >= len(s) {
				return "", false
			}
			b.WriteByte(s[i+1])
			i += 2
		default:
			if !isShellSafe(s[i:i+1]) && s[i] != '!' {
				return "", false
			}
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String(), true
}

func FuzzShellQuote(f *testing.F) {
	for _, seed := range []string{"", "tcp", "a b", "it's", "'", "$(id)", "!", "!!"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		quoted := ShellQuote(value)
		got, ok := unquote(quoted)
		if !ok || got != value {
			t.Fatalf("ShellQuote(%q) = %s does not parse back (got %q, ok %v)", value, quoted, got, ok)
		}
		if value != "!" && strings.Contains(quoted, "!") && !strings.HasPrefix(quoted, "'") {
			t.Fatalf("unquoted history expansion in %s", quoted)
		}
	})
}

func FuzzEscape(f *testing.F) {
	for _, seed := range []string{"", "plain", "\x1b[31mred", "\u202e", "\xff\xfe", "^[", "<U+202E>"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		escaped := Escape(value)
		if !utf8.ValidString(escaped) {
			t.Fatalf("Escape(%q) produced invalid UTF-8 %q", value, escaped)
		}
		for _, r := range escaped {
			if r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)) {
				t.Fatalf("Escape(%q) kept control rune %U", value, r)
			}
		}
		if again := Escape(escaped); again != escaped {
			t.Fatalf("Escape is not idempotent: %q -> %q -> %q", value, escaped, again)
		}
	})
}
