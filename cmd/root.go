package cmd

import (
	"fmt"
	"os"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/baseline"
	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/recommender"
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
}

type commandDependencies struct {
	loadRules     func(loader.Config) (*models.Ruleset, *models.Ruleset, error)
	parseServices func(string) ([]models.ListeningService, error)
	getServices   func() ([]models.ListeningService, error)
	getHost       func() (*models.HostContext, error)
	isRoot        func() bool
}

func defaultCommandDependencies() commandDependencies {
	return commandDependencies{
		loadRules:     loader.Load,
		parseServices: services.ParseSSFile,
		getServices:   services.GetListening,
		getHost:       loader.Host,
		isRoot:        loader.IsRoot,
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

	hasFiles := opts.ipv4File != "" || opts.ipv6File != ""
	live := false
	if !hasFiles {
		if deps.isRoot() {
			live = true
		} else if opts.baseline != "" {
			// Without rules the baseline is still useful; it is just not tailored.
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

	cfg := loader.Config{
		IPv4File: opts.ipv4File,
		IPv6File: opts.ipv6File,
		Live:     live,
		IPv4Only: opts.ipv4Only,
		IPv6Only: opts.ipv6Only,
	}
	ipv4Rules, ipv6Rules, err := deps.loadRules(cfg)
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
	result := analyzer.AnalyzeHost(ipv4Rules, ipv6Rules, host)
	result.IPv4Only = opts.ipv4Only
	result.IPv6Only = opts.ipv6Only
	if opts.servicesFile != "" {
		svcs, err := deps.parseServices(opts.servicesFile)
		if err != nil {
			return fmt.Errorf("loading services file: %w", err)
		}
		analyzer.CrossReferenceServices(result, svcs)
	} else if live {
		svcs, err := deps.getServices()
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
