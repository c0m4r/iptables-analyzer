package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/baseline"
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
	scoreOnly    bool
	quiet        bool
	showVersion  bool
	baseline     string
	sandbox      string
	htmlFile     string
	public       string
	failOn       string
	minGrade     string
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
		isRoot:          loader.IsRoot,
		sandbox:         sandbox.Enforce,
		now:             time.Now,
	}
}

// createReportFile opens the file for the HTML report. The file is not
// truncated here: an existing report stays whole until the new one is ready.
// A symbolic link is not followed, so that a report written as root does not
// land in a file that another user of the host chose.
func createReportFile(path string) (io.WriteCloser, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o644)
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
// --fail-on or --min-grade asks for. It gives exit status 2.
type thresholdError struct{ message string }

func (e *thresholdError) Error() string { return e.message }

// NewRootCommand constructs an isolated command with its own flag state.
func NewRootCommand() *cobra.Command {
	return newRootCommand(defaultCommandDependencies())
}

const usageExamples = `  sudo iptables-analyzer                          the rules and listeners of this host
  iptables-analyzer rules.v4 rules.v6 ss.txt      saved iptables-save, ip6tables-save and ss output
  sudo iptables-analyzer --html report.html       also write an interactive report
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
	flags.BoolVarP(&opts.ipv4Only, "ipv4-only", "4", false, "Analyze only IPv4")
	flags.BoolVarP(&opts.ipv6Only, "ipv6-only", "6", false, "Analyze only IPv6")
	flags.StringVar(&opts.public, "public", "", "Ports that are open to any source on purpose, e.g. `tcp/80,tcp/443`: reported as notes, no deduction")
	flags.StringVar(&opts.htmlFile, "html", "", "Also write an interactive HTML report to `FILE`")
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
// analysis, 2 when the result is below --fail-on or --min-grade, and 1 for
// an error.
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

func runAnalysis(cmd *cobra.Command, opts *commandOptions, deps commandDependencies, args []string) error {
	if opts.showVersion {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "iptables-analyzer v%s\nhttps://github.com/c0m4r/iptables-analyzer\n", Version)
		return err
	}

	if opts.noColor {
		lipgloss.DefaultRenderer().SetColorProfile(termenv.Ascii)
	}
	if opts.ipv4Only && opts.ipv6Only {
		return fmt.Errorf("--ipv4-only and --ipv6-only cannot be used together")
	}
	if opts.ipv4Only && opts.ipv6File != "" {
		return fmt.Errorf("--file6 cannot be used with --ipv4-only")
	}
	if opts.ipv6Only && opts.ipv4File != "" {
		return fmt.Errorf("--file cannot be used with --ipv6-only")
	}
	switch opts.baseline {
	case "", "4", "6", "all":
	default:
		return fmt.Errorf("--baseline must be 4, 6 or all")
	}
	mode, err := sandbox.ParseMode(opts.sandbox)
	if err != nil {
		return err
	}
	public, err := report.ParsePublic(opts.public)
	if err != nil {
		return fmt.Errorf("--public: %w", err)
	}
	failOn, failOnSet := severityNames[strings.ToLower(opts.failOn)]
	if opts.failOn != "" && !failOnSet {
		return fmt.Errorf("--fail-on must be low, medium, high or critical")
	}
	minGrade := strings.ToUpper(opts.minGrade)
	if minGrade != "" && (len(minGrade) != 1 || !strings.Contains("ABCD", minGrade)) {
		return fmt.Errorf("--min-grade must be A, B, C or D")
	}

	hasFiles := opts.ipv4File != "" || opts.ipv6File != "" || len(args) > 0
	live := false
	if !hasFiles {
		if deps.isRoot() {
			live = true
		} else if opts.baseline != "" {
			// Without rules the baseline is still useful; it is just not tailored.
			if _, err := enforceSandbox(cmd, opts, deps, mode); err != nil {
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
			fmt.Fprintln(stderr, "  sudo iptables-save > rules.v4")
			fmt.Fprintln(stderr, "  sudo ip6tables-save > rules.v6")
			fmt.Fprintln(stderr, "  sudo ss -tulnp > ss.txt")
			return fmt.Errorf("no input specified")
		}
	}

	// Collect every input first. The sandbox then closes the filesystem and
	// drops root, and only the collected data is parsed and analyzed.
	cfg := loader.Config{
		IPv4File: opts.ipv4File,
		IPv6File: opts.ipv6File,
		Live:     live,
		IPv4Only: opts.ipv4Only,
		IPv6Only: opts.ipv6Only,
	}
	sources, err := deps.readRules(cfg)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}
	// Files given without an option are read as they are and told apart by
	// their content, in the sandbox.
	var unsorted []rawInput
	for _, path := range args {
		data, err := deps.readFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		unsorted = append(unsorted, rawInput{name: path, data: string(data)})
	}

	var host *models.HostContext
	if live && deps.getHost != nil {
		if host, err = deps.getHost(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v; interface predicates are evaluated conservatively\n", err)
			host = nil
		}
	}
	var servicesData string
	var capture services.Capture
	haveServices := opts.servicesFile != ""
	if haveServices {
		if servicesData, err = deps.readServices(opts.servicesFile); err != nil {
			return fmt.Errorf("loading services file: %w", err)
		}
	} else if live {
		capture = deps.collectServices()
	}

	// The report file is opened while the filesystem is still reachable, and
	// written when the report is ready.
	var htmlOut io.WriteCloser
	if opts.htmlFile != "" && opts.baseline == "" {
		for _, input := range append([]string{opts.ipv4File, opts.ipv6File, opts.servicesFile}, args...) {
			if input != "" && sameFile(input, opts.htmlFile) {
				return fmt.Errorf("--html %s would overwrite an input file", opts.htmlFile)
			}
		}
		if htmlOut, err = deps.createFile(opts.htmlFile); err != nil {
			return fmt.Errorf("opening the HTML report: %w", err)
		}
		defer htmlOut.Close()
	}

	out := cmd.OutOrStdout()
	width := 0
	if opts.baseline == "" && !opts.jsonOutput {
		width = ui.Prepare(out)
	}
	status, err := enforceSandbox(cmd, opts, deps, mode)
	if err != nil {
		return err
	}

	inputs := []string{}
	for _, path := range []string{opts.ipv4File, opts.ipv6File, opts.servicesFile} {
		if path != "" {
			inputs = append(inputs, textsafe.Escape(path))
		}
	}
	for _, input := range unsorted {
		inputs = append(inputs, textsafe.Escape(input.name))
		switch classifyInput(input.data, sources.IPv4 != nil) {
		case inputServices:
			if haveServices {
				return fmt.Errorf("%s: a second list of listening sockets", input.name)
			}
			servicesData, haveServices = input.data, true
		case inputRules4:
			if sources.IPv4 != nil {
				return fmt.Errorf("%s: a second file with IPv4 rules; if it holds IPv6 rules, name it with --file6", input.name)
			}
			if opts.ipv6Only {
				return fmt.Errorf("%s holds IPv4 rules, which --ipv6-only leaves out", input.name)
			}
			sources.IPv4 = &loader.Source{Version: models.IPv4, Data: input.data}
		case inputRules6:
			if sources.IPv6 != nil {
				return fmt.Errorf("%s: a second file with IPv6 rules", input.name)
			}
			if opts.ipv4Only {
				return fmt.Errorf("%s holds IPv6 rules, which --ipv4-only leaves out", input.name)
			}
			sources.IPv6 = &loader.Source{Version: models.IPv6, Data: input.data}
		default:
			return fmt.Errorf("%s is neither iptables-save output nor ss output; name the kind with --file, --file6 or --services-file", input.name)
		}
	}
	if !live && sources.IPv4 == nil && sources.IPv6 == nil {
		return fmt.Errorf("no rules: give the output of iptables-save or ip6tables-save")
	}

	ipv4Rules, ipv6Rules, err := loader.Parse(sources)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}
	result := analyzer.AnalyzeHost(ipv4Rules, ipv6Rules, host)
	// File analysis without a file for one family says nothing about that
	// family: it is left out like with -4 or -6, and the report says so.
	ipv4Missing := !live && sources.IPv4 == nil && !opts.ipv6Only
	ipv6Missing := !live && sources.IPv6 == nil && !opts.ipv4Only
	result.IPv4Only = opts.ipv4Only || ipv6Missing
	result.IPv6Only = opts.ipv6Only || ipv4Missing
	if ipv4Missing {
		result.IPv4Status = models.FamilyNotSupplied
		result.Notes = append(result.Notes, "No IPv4 rules were supplied: only IPv6 was analyzed. Add the output of iptables-save as another file.")
	}
	if ipv6Missing {
		result.IPv6Status = models.FamilyNotSupplied
		result.Notes = append(result.Notes, "No IPv6 rules were supplied: only IPv4 was analyzed, and IPv4 rules do not filter IPv6. "+
			"Add the output of ip6tables-save as another file.")
	}
	result.Sandbox = &status
	if haveServices {
		svcs, err := services.ParseSSData(servicesData)
		if err != nil {
			return fmt.Errorf("loading services file: %w", err)
		}
		analyzer.CrossReferenceServices(result, svcs)
	} else if live {
		svcs, err := capture.Parse()
		if err != nil {
			result.ServiceAssessment = models.AssessmentFailed
			result.Diagnostics = append(result.Diagnostics, models.AssessmentDiagnostic{
				Area: "services", Message: "the listening sockets could not be read in full: " + err.Error(),
			})
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: the listening sockets could not be read in full: %v\n", err)
		} else {
			analyzer.CrossReferenceServices(result, svcs)
		}
	}

	recommended := baseline.Generate(baseline.FromResult(result))
	if opts.baseline != "" {
		return writeBaseline(cmd, recommended, opts.baseline)
	}
	rep := report.Build(result, report.Options{
		Version: Version, Live: live, Now: deps.now(), Inputs: inputs, Public: public, Baseline: recommended,
	})

	if htmlOut != nil {
		if err := writeHTML(htmlOut, rep); err != nil {
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
	return checkThresholds(rep, failOn, failOnSet, minGrade)
}

// writeHTML renders the page in memory first, so that a failure leaves an
// existing file as it was.
func writeHTML(out io.Writer, rep *report.Report) error {
	var page bytes.Buffer
	if err := ui.RenderHTML(&page, rep); err != nil {
		return err
	}
	if truncater, ok := out.(interface{ Truncate(int64) error }); ok {
		if err := truncater.Truncate(0); err != nil {
			return err
		}
	}
	_, err := out.Write(page.Bytes())
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
	if minGrade != "" {
		grade := rep.Score.Grade
		if !rep.Score.Complete {
			return &thresholdError{"the grade is incomplete, so it does not reach " + minGrade}
		}
		if strings.Index("ABCDF", grade) > strings.Index("ABCDF", minGrade) {
			return &thresholdError{"grade " + grade + " is worse than " + minGrade}
		}
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

type inputKind int

const (
	inputUnknown inputKind = iota
	inputRules4
	inputRules6
	inputServices
)

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
		case fields[0] == "-A":
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
