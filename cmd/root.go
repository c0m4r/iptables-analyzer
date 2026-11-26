package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/baseline"
	"github.com/c0m4r/iptables-analyzer/internal/hostinfo"
	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/report"
	"github.com/c0m4r/iptables-analyzer/internal/safeio"
	"github.com/c0m4r/iptables-analyzer/internal/sandbox"
	"github.com/c0m4r/iptables-analyzer/internal/services"
	"github.com/c0m4r/iptables-analyzer/internal/textsafe"
	"github.com/c0m4r/iptables-analyzer/internal/ui"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
)

// Version is set by main via go:embed VERSION.
var Version = "dev"

type commandOptions struct {
	ipv4File     string
	ipv6File     string
	ipv4Only     bool
	ipv6Only     bool
	noColor      bool
	jsonOutput   bool
	verbose      bool
	rules        bool
	servicesFile string
	ipsetFile    string
	scoreOnly    bool
	quiet        bool
	showVersion  bool
	baseline     string
	sandbox      string
	htmlFile     string
	snapshotFile string
	public       string
	failOn       string
	minGrade     string
	trace        string
	expect       string
	diff         bool
}

// commandDependencies collect input from the host and confine the process.
// Parsing and analysis are not injected: they always run after sandbox.
type commandDependencies struct {
	readRules       func(loader.Config) (loader.Sources, error)
	readServices    func(string) (string, error)
	readFile        func(string) ([]byte, error)
	createFile      func(string) (io.WriteCloser, error)
	collectServices func() services.Capture
	getHost         func() (*models.HostContext, error)
	collectFacts    func(*models.HostContext) loader.Facts
	isRoot          func() bool
	sandbox         func(sandbox.Mode) (models.SandboxStatus, error)
	now             func() time.Time
}

func defaultCommandDependencies() commandDependencies {
	return commandDependencies{
		readRules:       loader.Read,
		readServices:    services.ReadSSFile,
		readFile:        func(path string) ([]byte, error) { return safeio.ReadFile(path, safeio.MaxRulesSize) },
		createFile:      createReportFile,
		collectServices: services.Collect,
		getHost:         loader.Host,
		collectFacts:    loader.CollectFacts,
		isRoot:          loader.IsRoot,
		sandbox:         sandbox.Enforce,
		now:             time.Now,
	}
}

// createReportFile opens a file that the program writes: the HTML report or
// a snapshot. The file is not truncated here: an existing file stays whole
// until the new content is ready. A symbolic link is not followed, so that a
// file written as root does not land where another user of the host chose.
//
// The file holds what only root can read on the host: the rules, the
// contents of the ipsets and the names of the listening processes. A new
// file is therefore for its owner alone. An existing file keeps the mode
// that somebody gave it. Under sudo the new file goes to the user who called
// sudo, who would otherwise not be able to open the report just written.
func createReportFile(path string) (io.WriteCloser, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	}
	if created {
		if uid, gid, ok := sudoOwner(os.Geteuid(), os.Getenv); ok {
			// Without the change of owner the file stays with root: the
			// report is still written.
			_ = file.Chown(uid, gid)
		}
	}
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is a symbolic link", path)
	}
	if err != nil {
		return nil, err
	}
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return file, nil
}

// sudoOwner returns the user and group that called sudo, for a process that
// runs as root through it.
func sudoOwner(euid int, getenv func(string) string) (uid, gid int, ok bool) {
	if euid != 0 {
		return 0, 0, false
	}
	uid, errUID := strconv.Atoi(getenv("SUDO_UID"))
	gid, errGID := strconv.Atoi(getenv("SUDO_GID"))
	if errUID != nil || errGID != nil || uid <= 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// sameFile reports whether two paths name one existing file.
func sameFile(a, b string) bool {
	first, err := os.Stat(a)
	if err != nil {
		return false
	}
	second, err := os.Stat(b)
	return err == nil && os.SameFile(first, second)
}

// thresholdError reports that the analysis ran and its result is below what
// --fail-on, --min-grade or --expect asks for. It gives exit status 2.
type thresholdError struct{ message string }

func (e *thresholdError) Error() string { return e.message }

// NewRootCommand constructs an isolated command with its own flag state.
func NewRootCommand() *cobra.Command {
	return newRootCommand(defaultCommandDependencies())
}

const usageExamples = `  sudo iptables-analyzer                          the rules and listeners of this host
  iptables-analyzer rules.v4 rules.v6 ss.txt      saved iptables-save, ip6tables-save and ss output
  sudo iptables-analyzer --html report.html       also write an interactive report
  sudo iptables-analyzer --snapshot host.json     also save everything that was read, to analyze elsewhere
  iptables-analyzer host.json --trace 'tcp 203.0.113.5 -> :22 in eth0'
                                                  what the rules do with one packet
  iptables-analyzer --diff old.v4 new.v4          what a change of the rules opens and closes
  iptables-analyzer rules.v4 --fail-on high       exit status 2 when a finding is high or critical`

func newRootCommand(deps commandDependencies) *cobra.Command {
	opts := &commandOptions{}
	cmd := &cobra.Command{
		Use:           "iptables-analyzer [flags] [FILE...]",
		Short:         "Analyze iptables/ip6tables firewall rules for security issues",
		Long:          fmt.Sprintf("iptables-analyzer v%s - Analyze iptables/ip6tables firewall rules for security issues", Version),
		Example:       usageExamples,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runAnalysis(cmd, opts, deps, args)
	}
	flags := cmd.Flags()
	flags.SortFlags = false
	flags.StringVarP(&opts.ipv4File, "file", "f", "", "Read the IPv4 rules (iptables-save output) from `FILE`")
	flags.StringVar(&opts.ipv6File, "file6", "", "Read the IPv6 rules (ip6tables-save output) from `FILE`")
	flags.StringVar(&opts.servicesFile, "services-file", "", "Read the listening sockets (ss -tulnp output) from `FILE`")
	flags.StringVar(&opts.ipsetFile, "ipset-file", "", "Read the contents of the ipsets (ipset save output) from `FILE`")
	flags.BoolVarP(&opts.ipv4Only, "ipv4-only", "4", false, "Analyze only IPv4")
	flags.BoolVarP(&opts.ipv6Only, "ipv6-only", "6", false, "Analyze only IPv6")
	flags.StringVar(&opts.public, "public", "", "Ports that are open to any source on purpose, e.g. `tcp/80,tcp/443`: reported as notes, no deduction")
	flags.StringVar(&opts.htmlFile, "html", "", "Also write an interactive HTML report to `FILE`")
	flags.StringVar(&opts.snapshotFile, "snapshot", "", "Also save everything that was read to `FILE`, which can be analyzed like a live system")
	flags.StringVar(&opts.trace, "trace", "", "Show what the rules do with one `PACKET`, e.g. 'tcp 203.0.113.5 -> :22 in eth0'")
	flags.StringVar(&opts.expect, "expect", "", "With --trace: exit with status 2 unless the `VERDICT` is accept, drop or reject")
	flags.BoolVar(&opts.diff, "diff", false, "Compare two inputs, OLD and NEW: the ports and findings that differ")
	flags.BoolVar(&opts.jsonOutput, "json", false, "Write the report as JSON")
	flags.BoolVarP(&opts.verbose, "verbose", "v", false, "Also show notes, listening sockets and the sandbox status")
	flags.BoolVar(&opts.rules, "rules", false, "Also show the rules of every chain")
	flags.BoolVarP(&opts.quiet, "quiet", "q", false, "Print one line: score, grade and number of findings")
	flags.BoolVarP(&opts.scoreOnly, "score-only", "s", false, "Print only the score and the grade")
	flags.StringVar(&opts.failOn, "fail-on", "", "Exit with status 2 when a finding has this `SEVERITY` or a higher one: low, medium, high or critical")
	flags.StringVar(&opts.minGrade, "min-grade", "", "Exit with status 2 when the grade is worse than `GRADE` (A to D) or incomplete")
	flags.StringVar(&opts.baseline, "baseline", "", "Print only the recommended baseline firewall: 4, 6 or all (default all)")
	flags.Lookup("baseline").NoOptDefVal = "all"
	flags.BoolVar(&opts.noColor, "no-color", false, "Disable colored output")
	flags.StringVar(&opts.sandbox, "sandbox", string(sandbox.Auto), "Confine parsing and analysis with Landlock and a root privilege drop: auto, strict or off")
	flags.BoolVarP(&opts.showVersion, "version", "V", false, "Print version and exit")
	return cmd
}

var rootCmd = NewRootCommand()

// Execute runs the root command. The exit status is 0 for a completed
// analysis, 2 when the result is below --fail-on, --min-grade or --expect,
// and 1 for an error.
func Execute() {
	rootCmd.Long = fmt.Sprintf("iptables-analyzer v%s - Analyze iptables/ip6tables firewall rules for security issues", Version)
	os.Exit(exitStatus(rootCmd.Execute(), os.Stderr))
}

// exitStatus prints an error and returns the exit status for it.
func exitStatus(err error, stderr io.Writer) int {
	var threshold *thresholdError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &threshold):
		fmt.Fprintln(stderr, "iptables-analyzer: "+threshold.message)
		return 2
	}
	fmt.Fprintln(stderr, "Error: "+err.Error())
	return 1
}

var severityNames = map[string]models.Severity{
	"low": models.SeverityLow, "medium": models.SeverityMedium, "high": models.SeverityHigh, "critical": models.SeverityCritical,
}

// settings are the options of a run after they were checked.
type settings struct {
	mode      sandbox.Mode
	public    []report.PortSpec
	failOn    models.Severity
	failOnSet bool
	minGrade  string
	// packet is the packet to trace, nil for a report.
	packet *models.Packet
	// expect is the verdict that --expect asks for, in upper case.
	expect string
}

func checkOptions(opts *commandOptions) (settings, error) {
	var set settings
	if opts.ipv4Only && opts.ipv6Only {
		return set, fmt.Errorf("--ipv4-only and --ipv6-only cannot be used together")
	}
	if opts.ipv4Only && opts.ipv6File != "" {
		return set, fmt.Errorf("--file6 cannot be used with --ipv4-only")
	}
	if opts.ipv6Only && opts.ipv4File != "" {
		return set, fmt.Errorf("--file cannot be used with --ipv6-only")
	}
	switch opts.baseline {
	case "", "4", "6", "all":
	default:
		return set, fmt.Errorf("--baseline must be 4, 6 or all")
	}
	var err error
	if set.mode, err = sandbox.ParseMode(opts.sandbox); err != nil {
		return set, err
	}
	if set.public, err = report.ParsePublic(opts.public); err != nil {
		return set, fmt.Errorf("--public: %w", err)
	}
	set.failOn, set.failOnSet = severityNames[strings.ToLower(opts.failOn)]
	if opts.failOn != "" && !set.failOnSet {
		return set, fmt.Errorf("--fail-on must be low, medium, high or critical")
	}
	set.minGrade = strings.ToUpper(opts.minGrade)
	if set.minGrade != "" && (len(set.minGrade) != 1 || !strings.Contains("ABCD", set.minGrade)) {
		return set, fmt.Errorf("--min-grade must be A, B, C or D")
	}
	if opts.trace != "" {
		packet, err := analyzer.ParsePacket(opts.trace)
		if err != nil {
			return set, fmt.Errorf("--trace: %w", err)
		}
		set.packet = &packet
		for name, used := range map[string]bool{"--baseline": opts.baseline != "", "--html": opts.htmlFile != "", "--diff": opts.diff,
			"--quiet": opts.quiet, "--score-only": opts.scoreOnly, "--fail-on": opts.failOn != "", "--min-grade": opts.minGrade != ""} {
			if used {
				return set, fmt.Errorf("--trace shows the way of one packet and cannot be used with %s", name)
			}
		}
	}
	switch set.expect = strings.ToUpper(opts.expect); {
	case set.expect == "":
	case set.packet == nil:
		return set, fmt.Errorf("--expect needs --trace")
	case set.expect != "ACCEPT" && set.expect != "DROP" && set.expect != "REJECT":
		return set, fmt.Errorf("--expect must be accept, drop or reject")
	}
	return set, nil
}

func runAnalysis(cmd *cobra.Command, opts *commandOptions, deps commandDependencies, args []string) error {
	if opts.showVersion {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "iptables-analyzer v%s\nhttps://github.com/c0m4r/iptables-analyzer\n", Version)
		return err
	}
	if opts.noColor {
		lipgloss.DefaultRenderer().SetColorProfile(termenv.Ascii)
	}
	set, err := checkOptions(opts)
	if err != nil {
		return err
	}
	if opts.diff {
		return runDiff(cmd, opts, deps, set, args)
	}

	hasFiles := opts.ipv4File != "" || opts.ipv6File != "" || len(args) > 0
	live := false
	if !hasFiles {
		if deps.isRoot() {
			live = true
		} else if opts.baseline != "" {
			// Without rules the baseline is still useful; it is just not tailored.
			if _, err := enforceSandbox(cmd, opts, deps, set.mode); err != nil {
				return err
			}
			return writeBaseline(cmd, baseline.Generate(baseline.Options{}), opts.baseline)
		} else {
			stderr := cmd.ErrOrStderr()
			fmt.Fprintln(stderr, "No input specified. Provide rule files or run as root for live analysis.")
			fmt.Fprintln(stderr)
			fmt.Fprintln(stderr, "Examples:")
			fmt.Fprintln(stderr, "  sudo iptables-analyzer")
			fmt.Fprintln(stderr, "  iptables-analyzer rules.v4 rules.v6 ss.txt")
			fmt.Fprintln(stderr)
			fmt.Fprintln(stderr, "To save the input on the host that you want to examine:")
			fmt.Fprintln(stderr, "  sudo iptables-analyzer --snapshot host.json     (everything in one file)")
			fmt.Fprintln(stderr, "or")
			fmt.Fprintln(stderr, "  sudo iptables-save > rules.v4")
			fmt.Fprintln(stderr, "  sudo ip6tables-save > rules.v6")
			fmt.Fprintln(stderr, "  sudo ss -tulnp > ss.txt")
			return fmt.Errorf("no input specified")
		}
	}

	// Collect every input first. The sandbox then closes the filesystem and
	// drops root, and only the collected data is parsed and analyzed.
	in, err := collect(cmd, opts, deps, live, args)
	if err != nil {
		return err
	}

	// The files that the program writes are opened while the filesystem is
	// still reachable, and written when their content is ready.
	open := func(option, path string) (io.WriteCloser, error) {
		for _, input := range append([]string{opts.ipv4File, opts.ipv6File, opts.servicesFile, opts.ipsetFile}, args...) {
			if input != "" && sameFile(input, path) {
				return nil, fmt.Errorf("%s %s would overwrite an input file", option, path)
			}
		}
		return deps.createFile(path)
	}
	var htmlOut, snapshotOut io.WriteCloser
	if opts.htmlFile != "" && opts.baseline == "" && set.packet == nil {
		if htmlOut, err = open("--html", opts.htmlFile); err != nil {
			return fmt.Errorf("opening the HTML report: %w", err)
		}
		defer htmlOut.Close()
	}
	if opts.snapshotFile != "" {
		if opts.htmlFile != "" && sameFile(opts.htmlFile, opts.snapshotFile) {
			return fmt.Errorf("--snapshot and --html name the same file")
		}
		if snapshotOut, err = open("--snapshot", opts.snapshotFile); err != nil {
			return fmt.Errorf("opening the snapshot: %w", err)
		}
		defer snapshotOut.Close()
	}

	out := cmd.OutOrStdout()
	width := 0
	if opts.baseline == "" && !opts.jsonOutput {
		width = ui.Prepare(out)
	}
	status, err := enforceSandbox(cmd, opts, deps, set.mode)
	if err != nil {
		return err
	}

	state, err := in.load(opts)
	if err != nil {
		return err
	}
	if snapshotOut != nil {
		if err := writeFile(snapshotOut, func(w io.Writer) error { return state.snapshot(deps.now()).Write(w) }); err != nil {
			return fmt.Errorf("writing the snapshot: %w", err)
		}
	}
	if set.packet != nil {
		return runTrace(cmd, opts, deps, set, state, width)
	}
	result, err := state.analyze(cmd, opts, status)
	if err != nil {
		return err
	}

	recommended := baseline.Generate(baseline.FromResult(result))
	if opts.baseline != "" {
		return writeBaseline(cmd, recommended, opts.baseline)
	}
	rep := report.Build(result, state.reportOptions(deps, set, recommended))

	if htmlOut != nil {
		if err := writeFile(htmlOut, func(w io.Writer) error { return ui.RenderHTML(w, rep) }); err != nil {
			return fmt.Errorf("writing the HTML report: %w", err)
		}
	}
	switch {
	case opts.jsonOutput && opts.scoreOnly:
		err = ui.RenderJSON(out, rep.Score)
	case opts.jsonOutput:
		if !opts.rules {
			rep.Rulesets = nil
		}
		err = ui.RenderJSON(out, rep)
	case opts.scoreOnly:
		err = ui.RenderScoreLine(out, rep)
	case opts.quiet:
		err = ui.RenderSummaryLine(out, rep)
	default:
		written := ""
		if htmlOut != nil {
			written = textsafe.Escape(opts.htmlFile)
		}
		err = ui.RenderText(out, rep, ui.TextOptions{Width: width, Verbose: opts.verbose, Rules: opts.rules, HTMLFile: written})
	}
	if err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return checkThresholds(rep, set.failOn, set.failOnSet, set.minGrade)
}

// writeFile renders the content in memory first, so that a failure leaves an
// existing file as it was.
func writeFile(out io.Writer, render func(io.Writer) error) error {
	var content bytes.Buffer
	if err := render(&content); err != nil {
		return err
	}
	if truncater, ok := out.(interface{ Truncate(int64) error }); ok {
		if err := truncater.Truncate(0); err != nil {
			return err
		}
	}
	_, err := out.Write(content.Bytes())
	return err
}

// checkThresholds returns a thresholdError when the report is below what the
// caller accepts.
func checkThresholds(rep *report.Report, failOn models.Severity, failOnSet bool, minGrade string) error {
	if failOnSet {
		count := 0
		for _, finding := range rep.Findings {
			if finding.Severity >= failOn {
				count++
			}
		}
		if count > 0 {
			return &thresholdError{fmt.Sprintf("%d finding%s at or above %s", count, pluralS(count), strings.ToLower(failOn.String()))}
		}
	}
	return checkGrade(rep.Score, minGrade)
}

func checkGrade(score report.Score, minGrade string) error {
	if minGrade == "" {
		return nil
	}
	if !score.Complete {
		return &thresholdError{"the grade is incomplete, so it does not reach " + minGrade}
	}
	if strings.Index("ABCDF", score.Grade) > strings.Index("ABCDF", minGrade) {
		return &thresholdError{"grade " + score.Grade + " is worse than " + minGrade}
	}
	return nil
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// rawInput is a file that was given without saying what it holds.
type rawInput struct {
	name string
	data string
}

// input is everything that one analysis reads, collected before the sandbox
// starts and not parsed yet.
type input struct {
	live    bool
	sources loader.Sources
	// named lists the files that an option names, for the header of the report.
	named []string
	// files are the files given without an option. Their content tells what
	// they are.
	files []rawInput
	host  *models.HostContext
	// services is the text of --services-file; capture is what ss printed on
	// the live system.
	services     string
	haveServices bool
	capture      services.Capture
	haveCapture  bool
	facts        loader.Facts
	haveFacts    bool
	// ipsets is the text of --ipset-file.
	ipsets     string
	haveIPSets bool
}

// collect reads every input of an analysis.
func collect(cmd *cobra.Command, opts *commandOptions, deps commandDependencies, live bool, args []string) (*input, error) {
	in := &input{live: live}
	var err error
	cfg := loader.Config{
		IPv4File: opts.ipv4File,
		IPv6File: opts.ipv6File,
		Live:     live,
		IPv4Only: opts.ipv4Only,
		IPv6Only: opts.ipv6Only,
	}
	if in.sources, err = deps.readRules(cfg); err != nil {
		return nil, fmt.Errorf("loading rules: %w", err)
	}
	// Files given without an option are read as they are and told apart by
	// their content, in the sandbox.
	for _, path := range args {
		data, err := deps.readFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		in.files = append(in.files, rawInput{name: path, data: string(data)})
	}
	if live && deps.getHost != nil {
		if in.host, err = deps.getHost(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v; interface predicates are evaluated conservatively\n", err)
			in.host = nil
		}
	}
	if opts.servicesFile != "" {
		if in.services, err = deps.readServices(opts.servicesFile); err != nil {
			return nil, fmt.Errorf("loading services file: %w", err)
		}
		in.haveServices = true
	} else if live {
		in.capture, in.haveCapture = deps.collectServices(), true
	}
	if live && deps.collectFacts != nil {
		in.facts, in.haveFacts = deps.collectFacts(in.host), true
	}
	if opts.ipsetFile != "" {
		data, err := deps.readFile(opts.ipsetFile)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", opts.ipsetFile, err)
		}
		in.ipsets, in.haveIPSets = string(data), true
	}
	for _, path := range []string{opts.ipv4File, opts.ipv6File, opts.servicesFile, opts.ipsetFile} {
		if path != "" {
			in.named = append(in.named, textsafe.Escape(path))
		}
	}
	return in, nil
}

// loaded is the parsed input of one analysis.
type loaded struct {
	// mode is live, file or snapshot; captured is the time of a snapshot.
	mode     string
	captured string
	inputs   []string
	sources  loader.Sources
	ipv4     *models.Ruleset
	ipv6     *models.Ruleset
	// missing4 and missing6: the input holds nothing for the family, and
	// the family was not left out on request.
	missing4, missing6 bool
	host               *models.HostContext
	// outputs is the output of ss: one text from a file, or one for each
	// protocol from the live system. fromFile: a failure to read it is an
	// error of the input, not of the host.
	outputs      []services.Output
	captureErr   error
	haveServices bool
	fromFile     bool
	// nft, ipsets and routes are the output of "nft list chains",
	// "ipset save" and "ip -4 route show table main".
	nft, ipsets, routes             string
	haveNFT, haveIPSets, haveRoutes bool
	notes                           []string
}

type inputKind int

const (
	inputUnknown inputKind = iota
	inputRules4
	inputRules6
	inputServices
)

// load tells the files apart and parses the rules and the facts about the
// host. It runs in the sandbox.
func (in *input) load(opts *commandOptions) (*loaded, error) {
	state := &loaded{mode: "file", inputs: append([]string{}, in.named...), sources: in.sources, host: in.host,
		nft: in.facts.NFTChains, haveNFT: in.facts.HaveNFT, ipsets: in.facts.IPSets, haveIPSets: in.facts.HaveIPSets,
		routes: in.facts.Routes, haveRoutes: in.facts.HaveRoutes}
	if in.live {
		state.mode = "live"
	}
	if in.haveServices {
		state.outputs, state.haveServices, state.fromFile = []services.Output{{Data: in.services}}, true, true
	} else if in.haveCapture {
		state.outputs, state.captureErr, state.haveServices = in.capture.Outputs, in.capture.Err, true
	}
	if in.haveFacts {
		if state.host == nil {
			state.host = &models.HostContext{}
		}
		state.host.Sysctls = in.facts.Sysctls
		state.notes = append(state.notes, in.facts.Notes...)
	}

	for _, file := range in.files {
		name := textsafe.Escape(file.name)
		state.inputs = append(state.inputs, name)
		if hostinfo.IsSnapshot(file.data) {
			if in.live || len(in.files) > 1 || in.sources.IPv4 != nil || in.sources.IPv6 != nil || in.haveServices {
				return nil, fmt.Errorf("%s is a snapshot: it holds the rules and the listening sockets, so it cannot be combined with files for them", name)
			}
			if err := state.useSnapshot(file.data, opts); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			continue
		}
		switch classifyInput(file.data, state.sources.IPv4 != nil) {
		case inputServices:
			if state.haveServices {
				return nil, fmt.Errorf("%s: a second list of listening sockets", name)
			}
			state.outputs, state.haveServices, state.fromFile = []services.Output{{Data: file.data}}, true, true
		case inputRules4:
			if state.sources.IPv4 != nil {
				return nil, fmt.Errorf("%s: a second file with IPv4 rules; if it holds IPv6 rules, name it with --file6", name)
			}
			if opts.ipv6Only {
				return nil, fmt.Errorf("%s holds IPv4 rules, which --ipv6-only leaves out", name)
			}
			state.sources.IPv4 = &loader.Source{Version: models.IPv4, Data: file.data}
		case inputRules6:
			if state.sources.IPv6 != nil {
				return nil, fmt.Errorf("%s: a second file with IPv6 rules", name)
			}
			if opts.ipv4Only {
				return nil, fmt.Errorf("%s holds IPv6 rules, which --ipv4-only leaves out", name)
			}
			state.sources.IPv6 = &loader.Source{Version: models.IPv6, Data: file.data}
		default:
			return nil, fmt.Errorf("%s is neither iptables-save output, nor ss output, nor a snapshot; name the kind with --file, --file6 or --services-file", name)
		}
	}
	if !in.live && state.sources.IPv4 == nil && state.sources.IPv6 == nil {
		return nil, fmt.Errorf("no rules: give the output of iptables-save or ip6tables-save, or a snapshot")
	}
	// The option names the ipsets of saved rules; it also replaces those of a
	// snapshot.
	if in.haveIPSets {
		state.ipsets, state.haveIPSets = in.ipsets, true
	}

	var err error
	if state.ipv4, state.ipv6, err = loader.Parse(state.sources); err != nil {
		return nil, fmt.Errorf("loading rules: %w", err)
	}
	// Analysis of files without a file for one family says nothing about
	// that family: it is left out like with -4 or -6, and the report says so.
	state.missing4 = !in.live && state.sources.IPv4 == nil && !opts.ipv6Only
	state.missing6 = !in.live && state.sources.IPv6 == nil && !opts.ipv4Only

	if state.haveNFT {
		if state.host == nil {
			state.host = &models.HostContext{}
		}
		state.host.NativeTables, state.host.NativeKnown = hostinfo.ParseNFTChains(state.nft), true
	}
	if state.haveRoutes {
		routes, err := hostinfo.ParseRoutes(state.routes)
		if err != nil {
			state.notes = append(state.notes, "The routing table could not be read ("+err.Error()+"); the reverse-path filter is left out of the analysis.")
		} else {
			if state.host == nil {
				state.host = &models.HostContext{}
			}
			state.host.Routes, state.host.RoutesKnown = routes, true
		}
	}
	if state.haveIPSets {
		sets, err := hostinfo.ParseIPSets(state.ipsets)
		switch {
		case err != nil && in.haveIPSets:
			return nil, fmt.Errorf("reading the ipsets: %w", err)
		case err != nil:
			state.notes = append(state.notes, "The contents of the ipsets could not be read ("+err.Error()+"); matches against them are judged without them.")
		default:
			if state.host == nil {
				state.host = &models.HostContext{}
			}
			state.host.IPSets = sets
		}
	}
	return state, nil
}

// useSnapshot takes the whole input from a snapshot.
func (state *loaded) useSnapshot(data string, opts *commandOptions) error {
	snapshot, err := hostinfo.ParseSnapshot([]byte(data))
	if err != nil {
		return err
	}
	state.mode, state.captured, state.host = "snapshot", snapshot.Created, snapshot.Host()
	if snapshot.IPv4 != nil && !opts.ipv6Only {
		state.sources.IPv4 = &loader.Source{Version: models.IPv4, Data: snapshot.IPv4.Data, Warnings: snapshot.IPv4.Warnings}
	}
	if snapshot.IPv6 != nil && !opts.ipv4Only {
		state.sources.IPv6 = &loader.Source{Version: models.IPv6, Data: snapshot.IPv6.Data, Warnings: snapshot.IPv6.Warnings}
	}
	switch {
	case snapshot.IPv4 == nil && snapshot.IPv6 == nil:
		return fmt.Errorf("the snapshot holds no rules")
	case snapshot.IPv6 == nil && opts.ipv6Only:
		return fmt.Errorf("the snapshot holds no IPv6 rules, and --ipv6-only leaves out the others")
	case snapshot.IPv4 == nil && opts.ipv4Only:
		return fmt.Errorf("the snapshot holds no IPv4 rules, and --ipv4-only leaves out the others")
	}
	if snapshot.Sockets != nil {
		state.haveServices, state.fromFile = true, true
		for _, output := range snapshot.Sockets {
			state.outputs = append(state.outputs, services.Output{Proto: output.Proto, Data: output.Data})
		}
	}
	if snapshot.NFTChains != nil {
		state.nft, state.haveNFT = *snapshot.NFTChains, true
	}
	if snapshot.IPSets != nil {
		state.ipsets, state.haveIPSets = *snapshot.IPSets, true
	}
	if snapshot.Routes != nil {
		state.routes, state.haveRoutes = *snapshot.Routes, true
	}
	return nil
}

// snapshot puts everything that was read into one file.
func (state *loaded) snapshot(now time.Time) *hostinfo.Snapshot {
	snapshot := &hostinfo.Snapshot{Created: now.Format(time.RFC3339), Tool: Version, Live: state.mode == "live"}
	if state.mode == "snapshot" {
		// A copy of a snapshot keeps the time when the host was read.
		snapshot.Created, snapshot.Live = state.captured, true
	}
	if host := state.host; host != nil {
		snapshot.Hostname, snapshot.Sysctls = host.Hostname, host.Sysctls
		for _, iface := range host.Interfaces {
			snapshot.Interfaces = append(snapshot.Interfaces, hostinfo.SnapshotInterface{Name: iface.Name, Addrs: iface.Addrs, Up: iface.Up})
		}
	}
	if source := state.sources.IPv4; source != nil {
		snapshot.IPv4 = &hostinfo.SnapshotRules{Data: source.Data, Warnings: source.Warnings}
	}
	if source := state.sources.IPv6; source != nil {
		snapshot.IPv6 = &hostinfo.SnapshotRules{Data: source.Data, Warnings: source.Warnings}
	}
	if state.haveServices && state.captureErr == nil {
		snapshot.Sockets = []hostinfo.SnapshotOutput{}
		for _, output := range state.outputs {
			snapshot.Sockets = append(snapshot.Sockets, hostinfo.SnapshotOutput{Proto: output.Proto, Data: output.Data})
		}
	}
	if state.haveNFT {
		snapshot.NFTChains = &state.nft
	}
	if state.haveIPSets {
		snapshot.IPSets = &state.ipsets
	}
	if state.haveRoutes {
		snapshot.Routes = &state.routes
	}
	return snapshot
}

// analyze runs the analysis of the loaded input.
func (state *loaded) analyze(cmd *cobra.Command, opts *commandOptions, status models.SandboxStatus) (*models.AnalysisResult, error) {
	result := analyzer.AnalyzeHost(state.ipv4, state.ipv6, state.host)
	result.IPv4Only = opts.ipv4Only || state.missing6
	result.IPv6Only = opts.ipv6Only || state.missing4
	if state.missing4 {
		result.IPv4Status = models.FamilyNotSupplied
		result.Notes = append(result.Notes, "No IPv4 rules were supplied: only IPv6 was analyzed. Add the output of iptables-save as another file.")
	}
	if state.missing6 {
		result.IPv6Status = models.FamilyNotSupplied
		result.Notes = append(result.Notes, "No IPv6 rules were supplied: only IPv4 was analyzed, and IPv4 rules do not filter IPv6. "+
			"Add the output of ip6tables-save as another file.")
	}
	result.Notes = append(result.Notes, state.notes...)
	result.Sandbox = &status
	if !state.haveServices {
		return result, nil
	}
	svcs, err := services.Capture{Outputs: state.outputs, Err: state.captureErr}.Parse()
	switch {
	case err == nil:
		analyzer.CrossReferenceServices(result, svcs)
	case state.fromFile:
		return nil, fmt.Errorf("loading services file: %w", err)
	default:
		result.ServiceAssessment = models.AssessmentFailed
		result.Diagnostics = append(result.Diagnostics, models.AssessmentDiagnostic{
			Area: "services", Message: "the listening sockets could not be read in full: " + err.Error(),
		})
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: the listening sockets could not be read in full: %v\n", err)
	}
	return result, nil
}

func (state *loaded) reportOptions(deps commandDependencies, set settings, recommended models.Baseline) report.Options {
	return report.Options{
		Version: Version, Live: state.mode == "live", Snapshot: state.mode == "snapshot", Captured: state.captured,
		Now: deps.now(), Inputs: state.inputs, Public: set.public, Baseline: recommended,
	}
}

// runTrace follows one packet through the loaded rules.
func runTrace(cmd *cobra.Command, opts *commandOptions, deps commandDependencies, set settings, state *loaded, width int) error {
	version := analyzer.PacketVersion(*set.packet)
	rs, missing, excluded := state.ipv4, state.missing4, opts.ipv6Only
	if version == models.IPv6 {
		rs, missing, excluded = state.ipv6, state.missing6, opts.ipv4Only
	}
	name := fmt.Sprintf("IPv%d", version)
	switch {
	case excluded:
		return fmt.Errorf("the packet is %s, which was left out on request", name)
	case missing || rs == nil:
		return fmt.Errorf("the packet is %s, but no %s rules were read", name, name)
	case len(rs.Unreadable) > 0:
		return fmt.Errorf("the %s rules are native nftables rules that iptables-save cannot print, so the packet cannot be followed", name)
	}
	result := report.NewTrace(analyzer.Trace(rs, state.host, *set.packet), state.reportOptions(deps, set, models.Baseline{}), state.host)

	out := cmd.OutOrStdout()
	var err error
	if opts.jsonOutput {
		err = ui.RenderJSON(out, result)
	} else {
		err = ui.RenderTrace(out, result, ui.TextOptions{Width: width, Verbose: opts.verbose})
	}
	if err != nil {
		return fmt.Errorf("writing the trace: %w", err)
	}
	trace := result.Trace
	switch {
	case set.expect == "":
	case !trace.Certain:
		return &thresholdError{"the verdict depends on a rule that the packet does not decide, so it is not certain that the packet meets " + strings.ToLower(set.expect)}
	case trace.Verdict != set.expect:
		return &thresholdError{"the verdict is " + strings.ToLower(trace.Verdict) + ", not " + strings.ToLower(set.expect)}
	}
	return nil
}

// runDiff compares the analysis of two inputs.
func runDiff(cmd *cobra.Command, opts *commandOptions, deps commandDependencies, set settings, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("--diff needs two files, the old input and the new one: each the output of iptables-save or ip6tables-save, or a snapshot")
	}
	for name, used := range map[string]bool{"--file": opts.ipv4File != "", "--file6": opts.ipv6File != "", "--services-file": opts.servicesFile != "",
		"--ipset-file": opts.ipsetFile != "", "--html": opts.htmlFile != "", "--snapshot": opts.snapshotFile != "", "--baseline": opts.baseline != "",
		"--rules": opts.rules, "--score-only": opts.scoreOnly} {
		if used {
			return fmt.Errorf("--diff compares two files and cannot be used with %s", name)
		}
	}
	sides := make([]*input, 2)
	for i, path := range args {
		data, err := deps.readFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		sides[i] = &input{files: []rawInput{{name: path, data: string(data)}}}
	}
	out := cmd.OutOrStdout()
	width := 0
	if !opts.jsonOutput {
		width = ui.Prepare(out)
	}
	status, err := enforceSandbox(cmd, opts, deps, set.mode)
	if err != nil {
		return err
	}
	reports := make([]*report.Report, 2)
	results := make([]*models.AnalysisResult, 2)
	for i, side := range sides {
		state, err := side.load(opts)
		if err != nil {
			return err
		}
		if results[i], err = state.analyze(cmd, opts, status); err != nil {
			return err
		}
		reports[i] = report.Build(results[i], state.reportOptions(deps, set, models.Baseline{}))
	}
	diff := report.Compare(reports[0], reports[1], results[0], results[1])
	switch {
	case opts.jsonOutput:
		err = ui.RenderJSON(out, diff)
	case opts.quiet:
		err = ui.RenderDiffLine(out, diff)
	default:
		err = ui.RenderDiff(out, diff, ui.TextOptions{Width: width, Verbose: opts.verbose})
	}
	if err != nil {
		return fmt.Errorf("writing the comparison: %w", err)
	}
	// The thresholds judge what the new input adds.
	if set.failOnSet {
		count := 0
		for _, finding := range diff.Added {
			if finding.Severity >= set.failOn {
				count++
			}
		}
		for _, change := range diff.Changed {
			if change.New.Severity >= set.failOn && change.New.Severity > change.Old.Severity {
				count++
			}
		}
		if count > 0 {
			return &thresholdError{fmt.Sprintf("the new input adds %d finding%s at or above %s", count, pluralS(count), strings.ToLower(set.failOn.String()))}
		}
	}
	return checkGrade(reports[1].Score, set.minGrade)
}

// classifyInput tells iptables-save output, ip6tables-save output and ss
// output apart. Both save tools name themselves in the first line of their
// output; without that line the addresses and the ICMP matches of the rules
// tell the family. haveIPv4 says that IPv4 rules were already found: rules
// without any sign of their family are then IPv6 rules.
func classifyInput(data string, haveIPv4 bool) inputKind {
	rules, sockets := false, false
	named, guessed := inputUnknown, inputUnknown
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "#"):
			switch {
			case named != inputUnknown:
			case strings.Contains(line, "ip6tables-save"):
				named = inputRules6
			case strings.Contains(line, "iptables-save"):
				named = inputRules4
			}
		case strings.HasPrefix(line, "*") || strings.HasPrefix(line, ":") || line == "COMMIT":
			rules = true
		case fields[0] == "-A" || fields[0] == "-P" || fields[0] == "-N" || fields[0] == "-I":
			// -P and -N are the lines of "iptables -S".
			rules = true
			if guessed == inputUnknown {
				guessed = familyOfRule(fields)
			}
		case fields[0] == "Netid" || fields[0] == "State" || fields[0] == "LISTEN" || fields[0] == "UNCONN" ||
			(len(fields) > 1 && (fields[1] == "LISTEN" || fields[1] == "UNCONN")):
			sockets = true
		}
	}
	switch {
	case rules && sockets:
		return inputUnknown
	case sockets:
		return inputServices
	case !rules:
		return inputUnknown
	case named != inputUnknown:
		return named
	case guessed != inputUnknown:
		return guessed
	case haveIPv4:
		return inputRules6
	}
	return inputRules4
}

// familyOfRule tells the address family of a rule from its addresses and its
// ICMP matches. Only the values of options are read, not comments.
func familyOfRule(fields []string) inputKind {
	for i, field := range fields {
		switch field {
		case "-s", "-d", "--source", "--destination", "--src", "--dst":
			value := ""
			for _, next := range fields[i+1:] {
				if next != "!" {
					value = next
					break
				}
			}
			switch {
			case strings.Contains(value, ":"):
				return inputRules6
			case strings.Contains(value, "."):
				return inputRules4
			}
		case "ipv6-icmp", "icmpv6", "icmp6", "--icmpv6-type":
			return inputRules6
		case "icmp", "--icmp-type":
			return inputRules4
		}
	}
	return inputUnknown
}

// enforceSandbox confines the process. In auto mode the missing parts of
// the sandbox are only reported with --verbose (and in the report itself).
func enforceSandbox(cmd *cobra.Command, opts *commandOptions, deps commandDependencies, mode sandbox.Mode) (models.SandboxStatus, error) {
	status, err := deps.sandbox(mode)
	if err != nil {
		return status, err
	}
	if opts.verbose {
		for _, note := range status.Notes {
			fmt.Fprintf(cmd.ErrOrStderr(), "Sandbox: %s\n", note)
		}
	}
	return status, nil
}

// writeBaseline prints the baseline for the requested families. A single
// family is printed alone so that it can be redirected into a rules file.
func writeBaseline(cmd *cobra.Command, b models.Baseline, family string) error {
	out := cmd.OutOrStdout()
	var err error
	switch family {
	case "4":
		_, err = fmt.Fprint(out, b.IPv4)
	case "6":
		_, err = fmt.Fprint(out, b.IPv6)
	default:
		_, err = fmt.Fprintf(out, "%s\n%s", b.IPv4, b.IPv6)
		if err == nil {
			for _, note := range b.Notes {
				if _, err = fmt.Fprintln(out, "# "+note); err != nil {
					break
				}
			}
		}
	}
	if err != nil {
		return fmt.Errorf("writing baseline: %w", err)
	}
	return nil
}
