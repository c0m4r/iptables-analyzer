package ui

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/parser"
	"github.com/c0m4r/iptables-analyzer/internal/report"
	"github.com/c0m4r/iptables-analyzer/internal/services"
)

// The page names its style and its script in the content security policy by
// their hash, and allows nothing else: no network, no other script.
func TestHTMLPolicyAllowsOnlyTheStyleAndTheScriptOfThePage(t *testing.T) {
	page := renderHTML(t, fixtureReport(t, "basic.iptables-save", "", "services.txt"))
	policy := regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]*)">`).FindStringSubmatch(page)
	if policy == nil {
		t.Fatal("no content security policy")
	}
	style := page[strings.Index(page, "<style>")+len("<style>") : strings.Index(page, "</style>")]
	script := page[strings.Index(page, "<script>")+len("<script>") : strings.Index(page, "</script>")]
	want := "default-src 'none'; style-src '" + sourceHash(style) + "'; script-src '" + sourceHash(script) + "'; base-uri 'none'; form-action 'none'"
	if policy[1] != want {
		t.Fatalf("policy:\n got %s\nwant %s", policy[1], want)
	}
	if strings.Index(page, policy[0]) > strings.Index(page, "<style>") {
		t.Fatal("the policy must come before the style and the script that it governs")
	}
	if strings.Contains(policy[1], "unsafe") || strings.Contains(policy[1], "*") || strings.Contains(policy[1], "http") {
		t.Fatalf("the policy allows too much: %s", policy[1])
	}
	if !strings.HasPrefix(sourceHash("x"), "sha256-") || sourceHash("alert(1)") != "sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI=" {
		t.Fatalf("the hash is not the base64 form of SHA-256: %s", sourceHash("alert(1)"))
	}
}

// The style and the script must not be able to end their element, load
// anything or build markup from text.
func TestHTMLAssetsNeedNothingElse(t *testing.T) {
	for name, source := range map[string]string{"style": pageCSS, "script": pageJS, "template": pageBody} {
		lower := strings.ToLower(source)
		for _, unwanted := range []string{"</style", "</script", "\r", "http://", "//cdn", "@import", "url(", "src="} {
			if strings.Contains(lower, unwanted) {
				t.Errorf("the %s contains %q", name, unwanted)
			}
		}
	}
	for _, unwanted := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(", "fetch(", "XMLHttpRequest",
		"WebSocket", "import(", "setAttribute('on", "location.href", "window.open"} {
		if strings.Contains(pageJS, unwanted) {
			t.Errorf("the script uses %s", unwanted)
		}
	}
	// The template writes no style attribute and no event handler: the
	// policy would refuse both.
	if regexp.MustCompile(`\sstyle=|\son[a-z]+=`).MatchString(pageBody) {
		t.Error("the template holds an inline style or an event handler")
	}
	if strings.Count(pageBody, "https://") != 0 {
		t.Error("the template holds a link that does not come from the report")
	}
}

func TestHTMLPageShowsTheReport(t *testing.T) {
	rep := fixtureReport(t, "docker29.iptables-save", "docker29.ip6tables-save", "")
	page := renderHTML(t, rep)
	if err := checkMarkup(page); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"<title>Firewall report · 2026-11-25 12:00</title>",
		`<div class="grade g-F"><div><b>F</b><small>65/100</small></div></div>`,
		`<span class="chip c-HIGH">2 high</span>`,
		"Grade limited to F: IPv4 INPUT accepts every new connection.",
		`<h3>Fix first</h3>`,
		`<span class="gain">&#43;15, grade B</span>`,
		`<details class="card finding s-HIGH" id="f-1" data-sev="HIGH" open>`,
		`<span class="ftitle">INPUT accepts new connections to any port</span><span class="points"><span class="part">Policy</span> −15</span>`,
		`<pre id="c-1-1">iptables -P INPUT DROP</pre><button class="btn js-only inline" type="button" data-copy="c-1-1">Copy</button>`,
		`<span class="tag">IPv4</span> <span class="tag">possible</span>`,
		"all that no rule names",
		`<span class="scope sc-EXPOSED">any source</span>`,
		`[fd00:dead:beef::2]:443`,
		"No list of listening sockets was read.",
		`<span class="t-ACCEPT">-j ACCEPT</span>`,
		`<span class="t-jump">-j <a href="#ch4-1-9">DOCKER-USER</a></span>`,
		`<details class="chain" id="ch4-1-9">`,
		`policy <span class="policy-ACCEPT">ACCEPT</span>`,
		`<pre class="file" id="baseline-4"># Recommended IPv4 baseline`,
		"loads nothing from the network",
	} {
		if !strings.Contains(page, wanted) {
			t.Errorf("the page lacks %q", wanted)
		}
	}
	// A finding links to its rule, and the rule links back.
	link := regexp.MustCompile(`<a class="loc mono" href="#(r4-[0-9-]+)">IPv4 nat/DOCKER #1</a>`).FindStringSubmatch(page)
	if link == nil {
		t.Fatal("the finding about published ports does not link to its rule")
	}
	rule := regexp.MustCompile(`<li id="` + link[1] + `">.*?</li>`).FindString(page)
	if !strings.Contains(rule, "--dport 8080") || !strings.Contains(rule, `<a class="badge" href="#f-3">F3</a>`) {
		t.Fatalf("the rule does not link back to the finding: %s", rule)
	}
	// Low and informational findings start folded.
	if !strings.Contains(page, `<details class="card finding s-INFO" id="f-5" data-sev="INFO">`) {
		t.Error("the informational finding is not folded")
	}
}

func TestHTMLPageForEveryFixture(t *testing.T) {
	for _, c := range []struct{ v4, v6, ss string }{
		{"basic.iptables-save", "", "services.txt"},
		{"docker.iptables-save", "", "services.txt"},
		{"docker29.iptables-save", "docker29.ip6tables-save", "services.txt"},
		{"insecure.iptables-save", "", ""},
		{"ufw.iptables-save", "", "ufw-services.txt"},
		{"k8s.iptables-save", "", "k8s-services.txt"},
		{"router.iptables-save", "", "router-services.txt"},
		{"libvirt.iptables-save", "", "libvirt-services.txt"},
		{"firewalld.iptables-save", "", "firewalld-services.txt"},
		{"fail2ban.iptables-save", "", "fail2ban-services.txt"},
	} {
		page := renderHTML(t, fixtureReport(t, c.v4, c.v6, c.ss))
		if err := checkMarkup(page); err != nil {
			t.Errorf("%s: %v", c.v4, err)
		}
	}
	// A port that is sent to another local port names the port and the rule.
	page := renderHTML(t, fixtureReport(t, "router.iptables-save", "", "router-services.txt"))
	if !strings.Contains(page, "80 → 3128") || !strings.Contains(page, "sent there by <a class=\"mono\" href=\"#r4-") ||
		!strings.Contains(page, "8443/tcp") {
		t.Error("the page does not show the redirected port with its rule")
	}
	// A report with nothing in it.
	empty := &report.Report{Tool: report.Tool{Name: "iptables-analyzer", Version: "0", URL: "https://github.com/c0m4r/iptables-analyzer"}}
	page = renderHTML(t, empty)
	if err := checkMarkup(page); err != nil {
		t.Errorf("empty report: %v", err)
	}
	if !strings.Contains(page, "Nothing to report.") || strings.Contains(page, `id="rules"`) || strings.Contains(page, `id="baseline"`) {
		t.Errorf("empty report shows parts that it does not have")
	}
}

// taintStrings replaces the strings of a report. With all set, also empty
// strings and the strings of named types are replaced.
func taintStrings(v reflect.Value, text string, all bool, keep map[string]bool) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			taintStrings(v.Elem(), text, all, keep)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if !field.IsExported() || keep[field.Name] {
				continue
			}
			taintStrings(v.Field(i), text, all, keep)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			taintStrings(v.Index(i), text, all, keep)
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			value := reflect.New(v.Type().Elem()).Elem()
			value.Set(v.MapIndex(key))
			taintStrings(value, text, all, keep)
			v.SetMapIndex(key, value)
		}
	case reflect.String:
		if all || (v.Len() > 0 && v.Type().PkgPath() == "") {
			v.SetString(text)
		}
	}
}

// hostile holds what ends a text node, an attribute, an element, a script,
// a style, a URL and a template in one string.
const hostile = `x"'><script>alert(1)</script><img src=x onerror=alert(2)></style></title></textarea></pre>` +
	`<!-- javascript:alert(3) {{.}} ${4} \u003c \ &amp; &#x3c; ` + "`" + ` onload=alert(5) data:text/html,6 ]]> %3Cb%3E`

// Whatever a string of the report holds, it changes only the text of the
// page: the elements, their attributes and the values of the attributes are
// the same as for a harmless string in its place. This covers every string
// of the report at once, not a list of known bad inputs.
func TestHTMLStructureDoesNotDependOnTheText(t *testing.T) {
	// The names that select a branch of the template keep their value in the
	// first two passes, so that the usual branches are compared.
	names := map[string]bool{"Mode": true, "Status": true, "Kind": true, "Grade": true, "GradeAfter": true, "Role": true, "Category": true,
		"Code": true, "Protocol": true, "Target": true, "Policy": true, "ID": true, "Findings": true, "Area": true, "Generated": true, "URL": true}
	// The address of the project is a constant of the program, and the only
	// link out of the page.
	constants := map[string]bool{"URL": true}
	for _, c := range []struct {
		name string
		all  bool
		keep map[string]bool
	}{
		{"text fields", false, names},
		{"text fields, also the empty ones", true, names},
		{"every string", false, constants},
		{"every string, also the empty ones and the names", true, constants},
	} {
		pages := map[string]string{}
		for _, text := range []string{"benign", hostile} {
			rep := fixtureReport(t, "docker29.iptables-save", "docker29.ip6tables-save", "services.txt")
			more := fixtureReport(t, "ufw.iptables-save", "", "ufw-services.txt")
			rep.Findings = append(rep.Findings, more.Findings...)
			rep.OpenPorts = append(rep.OpenPorts, more.OpenPorts...)
			rep.Services = append(rep.Services, more.Services...)
			rep.Notes = append(rep.Notes, report.Note{Kind: "incomplete", Area: "rules", Text: "a note"})
			taintStrings(reflect.ValueOf(rep), text, c.all, c.keep)
			page := renderHTML(t, rep)
			if err := checkMarkup(page); err != nil {
				t.Fatalf("%s, %q: %v", c.name, text[:6], err)
			}
			pages[text] = page
		}
		want, err := skeleton(pages["benign"])
		if err != nil {
			t.Fatal(err)
		}
		got, err := skeleton(pages[hostile])
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			wantLines, gotLines := strings.Split(want, "\n"), strings.Split(got, "\n")
			for i := range wantLines {
				if i >= len(gotLines) || wantLines[i] != gotLines[i] {
					t.Fatalf("%s: the text changed the structure of the page at tag %d:\n harmless: %s\n  hostile: %s", c.name, i, wantLines[i], gotLines[min(i, len(gotLines)-1)])
				}
			}
			t.Fatalf("%s: the text added %d tags to the page", c.name, len(gotLines)-len(wantLines))
		}
		page := pages[hostile]
		if strings.Count(page, "<script") != 1 || strings.Count(page, "<img") != 0 || strings.Count(page, "<!--") != 0 {
			t.Fatalf("%s: markup from the text is in the page", c.name)
		}
		if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
			t.Fatalf("%s: the text is not in the page as text", c.name)
		}
	}
}

// Markup in a rule comment, a chain name and a process name is shown as text.
func TestHTMLShowsMarkupFromTheRulesAsText(t *testing.T) {
	rules := "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:\"<b>chain</b>\" - [0:0]\n" +
		"-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n" +
		"-A INPUT -p tcp --dport 22 -m comment --comment \"<script>alert(1)</script>\" -j ACCEPT\n" +
		"-A INPUT -i \"\\\"><img src=x onerror=alert(2)>\" -p tcp --dport 8080 -j ACCEPT\n" +
		"-A INPUT -j \"<b>chain</b>\"\nCOMMIT\n"
	ss := "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
		"LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"</pre><svg onload=alert(3)>\",pid=1,fd=3))\n"
	page := renderHTML(t, buildReport(t, rules, "", ss))
	if err := checkMarkup(page); err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"<script>alert", "<img", "<svg onload", "<b>chain"} {
		if strings.Contains(page, unwanted) {
			t.Errorf("the page holds %q as markup", unwanted)
		}
	}
	for _, wanted := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;b&gt;chain&lt;/b&gt;", "&lt;svg onload=alert(3)&gt;"} {
		if !strings.Contains(page, wanted) {
			t.Errorf("the page does not show %q", wanted)
		}
	}
}

// A long rule set starts with only the chains that matter unfolded.
func TestHTMLFoldsTheChainsOfALongRuleSet(t *testing.T) {
	var rules strings.Builder
	rules.WriteString("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:blocklist - [0:0]\n:quiet - [0:0]\n")
	rules.WriteString("-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -j blocklist\n-A INPUT -j quiet\n")
	rules.WriteString("-A INPUT -p tcp --dport 22 -j ACCEPT\n")
	for i := 0; i < 300; i++ {
		rules.WriteString("-A blocklist -s 198.51.100." + itoa(i%250+1) + "/32 -p tcp --dport " + itoa(1000+i) + " -j DROP\n")
	}
	rules.WriteString("-A quiet -p udp --dport 137 -j DROP\nCOMMIT\n")
	page := renderHTML(t, buildReport(t, rules.String(), "", ""))
	if err := checkMarkup(page); err != nil {
		t.Fatal(err)
	}
	open := regexp.MustCompile(`<details class="chain" id="[a-z0-9-]+" open>\n<summary><b>([^<]+)</b>`).FindAllStringSubmatch(page, -1)
	if len(open) != 1 || open[0][1] != "INPUT" {
		t.Fatalf("unfolded chains: %v", open)
	}
	if !strings.Contains(page, "<summary><b>blocklist</b><span class=\"sub\">300 rules</span></summary>") {
		t.Fatal("the long chain is missing")
	}
}

func TestSplitTarget(t *testing.T) {
	for spec, want := range map[string][2]string{
		"-p tcp --dport 22 -j ACCEPT":            {"-p tcp --dport 22 ", "-j ACCEPT"},
		"-j DROP":                                {"", "-j DROP"},
		"-g chain":                               {"", "-g chain"},
		"-p tcp":                                 {"-p tcp", ""},
		"-m comment --comment \"a -j b\" -j LOG": {"-m comment --comment \"a -j b\" ", "-j LOG"},
		"-p tcp -j DNAT --to-destination 10.0.0.1:1": {"-p tcp ", "-j DNAT --to-destination 10.0.0.1:1"},
		"": {"", ""},
	} {
		if head, tail := splitTarget(spec); head != want[0] || tail != want[1] {
			t.Errorf("splitTarget(%q) = %q, %q", spec, head, tail)
		}
	}
}

func TestMarkupCheckFindsWhatDoesNotBelong(t *testing.T) {
	page := renderHTML(t, fixtureReport(t, "basic.iptables-save", "", "services.txt"))
	if err := checkMarkup(page); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string][2]string{
		"an unknown element":       {"<h2>Findings</h2>", "<h2>Findings</h2><iframe></iframe>"},
		"an event handler":         {`<main class="wrap">`, `<main class="wrap" onclick="x">`},
		"a link to another site":   {`href="#summary"`, `href="https://example.com/"`},
		"a script URL":             {`href="#summary"`, `href="javascript:alert(1)"`},
		"a second script":          {"</main>", "</main><script>alert(1)</script>"},
		"an unbalanced element":    {"<h2>Findings</h2>", "<h2>Findings</h2></div>"},
		"a link to nothing":        {`href="#summary"`, `href="#nowhere"`},
		"an id from the input":     {`id="summary"`, `id="x y"`},
		"text in an attribute":     {`id="search"`, `id="search" aria-label="a &amp; b"`},
		"a style attribute":        {`<main class="wrap">`, `<main class="wrap" style="x">`},
		"a value without quotes":   {`<main class="wrap">`, `<main class=wrap>`},
		"a changed script":         {"'use strict';", "'use strict';alert(1);"},
		"a comment":                {"<h2>Findings</h2>", "<!-- x --><h2>Findings</h2>"},
		"a bare greater-than sign": {"<h2>Findings</h2>", "<h2>Findings ></h2>"},
	} {
		if !strings.Contains(page, change[0]) {
			t.Fatalf("%s: the page does not hold %q", name, change[0])
		}
		if checkMarkup(strings.Replace(page, change[0], change[1], 1)) == nil {
			t.Errorf("the check does not find %s", name)
		}
	}
}

func itoa(n int) string {
	digits := ""
	for n > 0 || digits == "" {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// FuzzHTMLReport renders the page for arbitrary rules and ss output. The
// page must keep the markup of the template, whatever the input holds.
func FuzzHTMLReport(f *testing.F) {
	ss := fixture(f, "services.txt")
	for _, name := range []string{"basic.iptables-save", "docker.iptables-save", "docker29.iptables-save", "insecure.iptables-save", "ufw.iptables-save",
		"k8s.iptables-save", "router.iptables-save", "libvirt.iptables-save", "firewalld.iptables-save"} {
		f.Add(fixture(f, name), ss)
	}
	f.Add("*filter\n:INPUT ACCEPT [0:0]\n:\"<i>\" - [0:0]\n-A INPUT -i \"\\\"><script>\" -p tcp --dport 22 -m comment --comment \"</style><script>alert(1)</script>\" -j ACCEPT\nCOMMIT\n",
		"State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 1 0.0.0.0:22 0.0.0.0:* users:((\"<img src=x onerror=alert(1)>\",pid=1,fd=3))\n")
	f.Fuzz(func(t *testing.T, rules, ssData string) {
		rs, err := parser.Parse(rules, models.IPv4)
		if err != nil {
			return
		}
		result := analyzer.Analyze(rs, nil)
		if svcs, err := services.ParseSSData(ssData); err == nil {
			analyzer.CrossReferenceServices(result, svcs)
		}
		rep := report.Build(result, report.Options{Version: "fuzz", Now: testTime, Inputs: []string{rules[:min(len(rules), 20)]}})
		var page strings.Builder
		if err := RenderHTML(&page, rep); err != nil {
			t.Fatal(err)
		}
		if err := checkMarkup(page.String()); err != nil {
			t.Fatal(err)
		}
	})
}
