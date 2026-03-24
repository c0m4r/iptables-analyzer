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
)

// rootCmd is the base command
var rootCmd = &cobra.Command{
	Use:                "iptables-analyzer",
	Short:              "Analyze iptables/ip6tables firewall rules for security issues",
	DisableFlagParsing: false,
	SilenceUsage:       true,
	RunE:               runAnalysis,
}

func init() {
	rootCmd.Flags().StringVarP(&ipv4File, "file", "f", "", "Path to iptables-save output file")
	rootCmd.Flags().StringVar(&ipv6File, "file6", "", "Path to ip6tables-save output file")
	rootCmd.Flags().BoolVarP(&ipv4Only, "ipv4-only", "4", false, "Analyze only IPv4 rules")
	rootCmd.Flags().BoolVarP(&ipv6Only, "ipv6-only", "6", false, "Analyze only IPv6 rules")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show all rules including empty chains")
	rootCmd.Flags().StringVar(&servicesFile, "services-file", "", "Path to saved ss output file (alternative to live ss)")
	rootCmd.Flags().BoolVarP(&scoreOnly, "score-only", "s", false, "Only print the security score")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "V", false, "Print version and exit")
}

// Execute runs the root command
func Execute() {
	rootCmd.Long = fmt.Sprintf("iptables-analyzer v%s - Analyze iptables/ip6tables firewall rules for security issues", Version)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runAnalysis(cmd *cobra.Command, args []string) error {
	if showVersion {
		fmt.Printf("iptables-analyzer v%s\nhttps://github.com/c0m4r/iptables-analyzer\n", Version)
		return nil
	}

	if noColor {
		lipgloss.DefaultRenderer().SetColorProfile(termenv.Ascii)
	}

	// Determine mode
	hasFiles := ipv4File != "" || ipv6File != ""
	live := false
	if !hasFiles {
		// Auto-detect: if root, use live; otherwise show help
		if loader.IsRoot() {
			live = true
		} else {
			fmt.Fprintln(os.Stderr, "No input specified. Provide rule files or run as root for live analysis.")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Examples:")
			fmt.Fprintln(os.Stderr, "  sudo iptables-analyzer")
			fmt.Fprintln(os.Stderr, "  iptables-analyzer -f rules.v4 --file6 rules.v6")
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
	if servicesFile != "" {
		svcs, err := services.ParseSSFile(servicesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not parse services file: %v\n", err)
		} else {
			analyzer.CrossReferenceServices(result, svcs)
		}
	} else {
		svcs, err := services.GetListening()
		if err != nil {
			if live {
				fmt.Fprintf(os.Stderr, "Warning: could not get listening services: %v\n", err)
				fmt.Fprintf(os.Stderr, "  Tip: save ss output with: ss -tlnp && ss -ulnp > services.txt\n")
				fmt.Fprintf(os.Stderr, "  Then use: --services-file services.txt\n")
			}
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
