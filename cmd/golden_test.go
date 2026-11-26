package cmd

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// update rewrites the golden files: go test ./cmd -run TestGoldenReports -update
// (or "make update-golden"). Read the diff before you commit it: it is the
// change that users see.
var update = flag.Bool("update", false, "rewrite the golden files of the report formats")

var (
	styleElement  = regexp.MustCompile(`(?s)<style>.*?</style>`)
	scriptElement = regexp.MustCompile(`(?s)<script>.*?</script>`)
	policyHashes  = regexp.MustCompile(`'sha256-[A-Za-z0-9+/=]+'`)
)

// pageWithoutAssets replaces the style and the script of a page, and their
// hashes, with placeholders. The golden files then show the markup that the
// report decides, and do not change with every edit of the style sheet.
func pageWithoutAssets(page string) string {
	page = styleElement.ReplaceAllString(page, "<style>(style)</style>")
	page = scriptElement.ReplaceAllString(page, "<script>(script)</script>")
	return policyHashes.ReplaceAllString(page, "'sha256-(hash)'")
}

func compareGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run the test with -update to write the golden files)", err)
	}
	if got == string(want) {
		return
	}
	wantLines, gotLines := strings.Split(string(want), "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var wantLine, gotLine string
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if wantLine != gotLine {
			t.Fatalf("%s differs from the golden file at line %d:\n want: %s\n  got: %s\n"+
				"If the change is intended, run: go test ./cmd -run TestGoldenReports -update", name, i+1, wantLine, gotLine)
		}
	}
}

// The reports of the fixtures, in every format, are kept as files. A change
// of the analysis or of a renderer shows as a diff of what the user reads.
func TestGoldenReports(t *testing.T) {
	// The width of the text must not depend on where the tests run.
	t.Setenv("COLUMNS", "")
	for _, c := range []struct {
		name string
		deps commandDependencies
		args []string
	}{
		{"basic", testDependencies(false), []string{data("basic.iptables-save"), data("services.txt")}},
		{"ufw", testDependencies(false), []string{data("ufw.iptables-save"), data("ufw-services.txt")}},
		{"docker29", testDependencies(false), []string{data("docker29.iptables-save"), data("docker29.ip6tables-save"), data("services.txt")}},
		{"insecure", testDependencies(false), []string{data("insecure.iptables-save")}},
		{"no-rules", liveDependencies("", "", ssListenBoth), nil},
	} {
		text, err := run(t, c.deps, c.args...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		compareGolden(t, c.name+".txt", text)

		verbose, err := run(t, c.deps, append([]string{"--verbose", "--rules"}, c.args...)...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		compareGolden(t, c.name+".verbose.txt", verbose)

		page := &memoryFile{}
		deps := c.deps
		deps.createFile = func(string) (io.WriteCloser, error) { return page, nil }
		json, err := run(t, deps, append([]string{"--json", "--html", "report.html"}, c.args...)...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		compareGolden(t, c.name+".json", json)
		compareGolden(t, c.name+".html", pageWithoutAssets(page.String()))
	}
}

func TestPageWithoutAssets(t *testing.T) {
	page := `<meta content="style-src 'sha256-AbC+/=' script-src 'sha256-xyz0='"><style>a{}` + "\n" + `b{}</style><p>x</p><script>var a;` + "\n" + `</script>`
	want := `<meta content="style-src 'sha256-(hash)' script-src 'sha256-(hash)'"><style>(style)</style><p>x</p><script>(script)</script>`
	if got := pageWithoutAssets(page); got != want {
		t.Fatalf("%s", got)
	}
}
