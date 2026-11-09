package cmd

import (
	"fmt"
	"os"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/baseline"
	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/recommender"
	"github.com/c0m4r/iptables-analyzer/internal/sandbox"
	"github.com/c0m4r/iptables-analyzer/internal/scorer"
	"github.com/c0m4r/iptables-analyzer/internal/services"
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
	servicesFile string
	scoreOnly    bool
	showVersion  bool
	baseline     string
	sandbox      string
}

// commandDependencies collect input from the host and confine the process.
// Parsing and analysis are not injected: they always run after sandbox.
type commandDependencies struct {
	readRules       func(loader.Config) (loader.Sources, error)
	readServices    func(string) (string, error)
	collectServices func() services.Capture
	getHost         func() (*models.HostContext, error)
	isRoot          func() bool
	sandbox         func(sandbox.Mode) (models.SandboxStatus, error)
}

func defaultCommandDependencies() commandDependencies {
	return commandDependencies{
		readRules:       loader.Read,
		readServices:    services.ReadSSFile,
		collectServices: services.Collect,
		getHost:         loader.Host,
		isRoot:          loader.IsRoot,
		sandbox:         sandbox.Enforce,
	}
}

// NewRootCommand constructs an isolated command with its own flag state.
func NewRootCommand() *cobra.Command {
	return newRootCommand(defaultCommandDependencies())
}

func newRootCommand(deps commandDependencies) *cobra.Command {
	opts := &commandOptions{}
	cmd := &cobra.Command{
		Use:                "iptables-analyzer",
		Short:              "Analyze iptables/ip6tables firewall rules for security issues",
		Long:               fmt.Sprintf("iptables-analyzer v%s - Analyze iptables/ip6tables firewall rules for security issues", Version),
		DisableFlagParsing: false,
		SilenceUsage:       true,
		Args:               cobra.NoArgs,
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runAnalysis(cmd, opts, deps)
	}
	cmd.Flags().StringVarP(&opts.ipv4File, "file", "f", "", "Path to iptables-save output file")
	cmd.Flags().StringVar(&opts.ipv6File, "file6", "", "Path to ip6tables-save output file")
	cmd.Flags().BoolVarP(&opts.ipv4Only, "ipv4-only", "4", false, "Analyze only IPv4 rules")
	cmd.Flags().BoolVarP(&opts.ipv6Only, "ipv6-only", "6", false, "Analyze only IPv6 rules")
	cmd.Flags().BoolVar(&opts.noColor, "no-color", false, "Disable colored output")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "Output results as JSON")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Show all rules, empty chains, and raw rule text")
	cmd.Flags().StringVar(&opts.servicesFile, "services-file", "", "Path to saved ss output file (alternative to live ss)")
	cmd.Flags().BoolVarP(&opts.scoreOnly, "score-only", "s", false, "Only print the security score")
	cmd.Flags().BoolVarP(&opts.showVersion, "version", "V", false, "Print version and exit")
	cmd.Flags().StringVar(&opts.baseline, "baseline", "", "Print only the recommended baseline firewall: 4, 6 or all (default all)")
	cmd.Flags().Lookup("baseline").NoOptDefVal = "all"
	cmd.Flags().StringVar(&opts.sandbox, "sandbox", string(sandbox.Auto), "Confine parsing and analysis with Landlock and a root privilege drop: auto, strict or off")
	return cmd
}

var rootCmd = NewRootCommand()

// Execute runs the root command.
func Execute() {
	rootCmd.Long = fmt.Sprintf("iptables-analyzer v%s - Analyze iptables/ip6tables firewall rules for security issues", Version)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runAnalysis(cmd *cobra.Command, opts *commandOptions, deps commandDependencies) error {
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

	hasFiles := opts.ipv4File != "" || opts.ipv6File != ""
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
			fmt.Fprintln(stderr, "  iptables-analyzer -f rules.v4 --file6 rules.v6")
			fmt.Fprintln(stderr)
			fmt.Fprintln(stderr, "To save rules for offline analysis:")
			fmt.Fprintln(stderr, "  sudo iptables-save > rules.v4")
			fmt.Fprintln(stderr, "  sudo ip6tables-save > rules.v6")
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

	var host *models.HostContext
	if live && deps.getHost != nil {
		if host, err = deps.getHost(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v; interface predicates are evaluated conservatively\n", err)
			host = nil
		}
	}
	var servicesData string
	var capture services.Capture
	if opts.servicesFile != "" {
		if servicesData, err = deps.readServices(opts.servicesFile); err != nil {
			return fmt.Errorf("loading services file: %w", err)
		}
	} else if live {
		capture = deps.collectServices()
	}

	renderOpts := ui.RenderOptions{
		NoColor:  opts.noColor,
		Verbose:  opts.verbose,
		JSON:     opts.jsonOutput,
		LiveMode: live,
		IPv4Only: opts.ipv4Only,
		IPv6Only: opts.ipv6Only,
		Version:  Version,
		Writer:   cmd.OutOrStdout(),
	}
	if opts.baseline == "" {
		ui.Prepare(renderOpts)
	}
	status, err := enforceSandbox(cmd, opts, deps, mode)
	if err != nil {
		return err
	}

	ipv4Rules, ipv6Rules, err := loader.Parse(sources)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}
	result := analyzer.AnalyzeHost(ipv4Rules, ipv6Rules, host)
	result.IPv4Only = opts.ipv4Only
	result.IPv6Only = opts.ipv6Only
	result.Sandbox = &status
	if opts.servicesFile != "" {
		svcs, err := services.ParseSSData(servicesData)
		if err != nil {
			return fmt.Errorf("loading services file: %w", err)
		}
		analyzer.CrossReferenceServices(result, svcs)
	} else if live {
		svcs, err := capture.Parse()
		if len(svcs) > 0 {
			analyzer.CrossReferenceServices(result, svcs)
		}
		if err != nil {
			result.ServiceAssessment = models.AssessmentFailed
			result.Diagnostics = append(result.Diagnostics, models.AssessmentDiagnostic{
				Area: "services", Message: "listening-service discovery was incomplete: " + err.Error(),
			})
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: listening-service discovery was incomplete: %v\n", err)
			fmt.Fprintln(cmd.ErrOrStderr(), "  Tip: save ss output with: ss -tlnp > services.txt && ss -ulnp >> services.txt")
			fmt.Fprintln(cmd.ErrOrStderr(), "  Then use: --services-file services.txt")
		} else if len(svcs) == 0 {
			analyzer.CrossReferenceServices(result, nil)
		}
	}

	result.Recommendations = recommender.Generate(result)
	result.Baseline = baseline.Generate(baseline.FromResult(result))
	result.Score = scorer.Calculate(result)
	if opts.baseline != "" {
		return writeBaseline(cmd, result.Baseline, opts.baseline)
	}
	if opts.scoreOnly {
		if err := ui.RenderScoreOnly(result, renderOpts); err != nil {
			return fmt.Errorf("writing score: %w", err)
		}
		return nil
	}
	if err := ui.Render(result, renderOpts); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
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
