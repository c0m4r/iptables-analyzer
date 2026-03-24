package cmd

import (
	"fmt"
	"os"

	"github.com/c0m4r/iptables-analyzer/internal/analyzer"
	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/recommender"
	"github.com/c0m4r/iptables-analyzer/internal/scorer"
	"github.com/c0m4r/iptables-analyzer/internal/services"
	"github.com/c0m4r/iptables-analyzer/internal/ui"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
)

// Version is set by main via go:embed VERSION
var Version = "dev"

var (
	ipv4File      string
	ipv6File      string
	live          bool
	ipv4Only      bool
	ipv6Only      bool
	noColor       bool
	jsonOutput    bool
	verbose       bool
	checkServices bool
	servicesFile  string
	scoreOnly     bool
)

// rootCmd is the base command
var rootCmd = &cobra.Command{
	Use:   "iptables-analyzer",
	Short: "Analyze iptables/ip6tables firewall rules for security issues",
	Long: `iptables-analyzer inspects your iptables and ip6tables rules to find:
  - Shadowed or ineffective rules
  - Docker NAT bypasses that make INPUT rules useless
  - Services exposed to the network
  - Missing best practices

It provides a security score and actionable recommendations.`,
	RunE: runAnalysis,
}

func init() {
	rootCmd.SetVersionTemplate("iptables-analyzer v{{.Version}}\nhttps://github.com/c0m4r/iptables-analyzer\n")
	rootCmd.Flags().StringVar(&ipv4File, "ipv4-file", "", "Path to iptables-save output file")
	rootCmd.Flags().StringVar(&ipv6File, "ipv6-file", "", "Path to ip6tables-save output file")
	rootCmd.Flags().BoolVar(&live, "live", false, "Read rules from live system (requires root)")
	rootCmd.Flags().BoolVar(&ipv4Only, "ipv4-only", false, "Analyze only IPv4 rules")
	rootCmd.Flags().BoolVar(&ipv6Only, "ipv6-only", false, "Analyze only IPv6 rules")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Show all rules including empty chains")
	rootCmd.Flags().BoolVar(&checkServices, "check-services", false, "Cross-reference with listening services (auto-enabled with --live)")
	rootCmd.Flags().StringVar(&servicesFile, "services-file", "", "Path to saved ss output file (alternative to live ss)")
	rootCmd.Flags().BoolVar(&scoreOnly, "score-only", false, "Only print the security score")
}

// Execute runs the root command
func Execute() {
	rootCmd.Version = Version
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runAnalysis(cmd *cobra.Command, args []string) error {
	if noColor {
		lipgloss.DefaultRenderer().SetColorProfile(termenv.Ascii)
	}

	// Determine mode
	hasFiles := ipv4File != "" || ipv6File != ""
	if !hasFiles && !live {
		// Auto-detect: if root, use live; otherwise show help
		if loader.IsRoot() {
			live = true
		} else {
			fmt.Fprintln(os.Stderr, "No input specified. Use --live (requires root) or --ipv4-file/--ipv6-file.")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Examples:")
			fmt.Fprintln(os.Stderr, "  sudo iptables-analyzer --live --check-services")
			fmt.Fprintln(os.Stderr, "  iptables-analyzer --ipv4-file rules.v4 --ipv6-file rules.v6")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "To save rules for offline analysis:")
			fmt.Fprintln(os.Stderr, "  sudo iptables-save > rules.v4")
			fmt.Fprintln(os.Stderr, "  sudo ip6tables-save > rules.v6")
			return nil
		}
	}

	// Load rulesets
	cfg := loader.Config{
		IPv4File: ipv4File,
		IPv6File: ipv6File,
		Live:     live,
		IPv4Only: ipv4Only,
		IPv6Only: ipv6Only,
	}

	ipv4Rules, ipv6Rules, err := loader.Load(cfg)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	// Run analysis
	result := analyzer.Analyze(ipv4Rules, ipv6Rules)

	// Cross-reference with listening services
	// Auto-enable on --live mode, unless explicitly running with file-only analysis
	if live && !checkServices && servicesFile == "" {
		checkServices = true
	}

	if servicesFile != "" {
		svcs, err := services.ParseSSFile(servicesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not parse services file: %v\n", err)
		} else {
			analyzer.CrossReferenceServices(result, svcs)
		}
	} else if checkServices {
		svcs, err := services.GetListening()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not get listening services: %v\n", err)
			fmt.Fprintf(os.Stderr, "  Tip: save ss output with: ss -tlnp && ss -ulnp > services.txt\n")
			fmt.Fprintf(os.Stderr, "  Then use: --services-file services.txt\n")
		} else {
			analyzer.CrossReferenceServices(result, svcs)
		}
	}

	// Generate recommendations
	result.Recommendations = recommender.Generate(result)

	// Calculate score
	result.Score = scorer.Calculate(result)

	// Render output
	opts := ui.RenderOptions{
		NoColor:  noColor,
		Verbose:  verbose,
		JSON:     jsonOutput,
		LiveMode: live,
		Version:  Version,
	}

	if scoreOnly {
		ui.RenderScoreOnly(result, opts)
	} else {
		ui.Render(result, opts)
	}

	return nil
}
