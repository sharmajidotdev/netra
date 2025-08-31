package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sharmajidotdev/netra/internal/config"
	"github.com/sharmajidotdev/netra/internal/exitcode"
	"github.com/sharmajidotdev/netra/internal/logger"
	"github.com/sharmajidotdev/netra/internal/output"
	"github.com/sharmajidotdev/netra/internal/scanner"
	"github.com/sharmajidotdev/netra/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Options holds CLI flags and configuration
type Options struct {
	// Input paths to scan
	Inputs []string

	// DiffFile is path to git diff file to scan
	DiffFile string

	// CommitRange is git commit range to scan
	CommitRange string

	// StagedOnly scans only git staged changes
	StagedOnly bool

	// Output formats
	Json   bool
	Human  bool
	Sarif  bool
	ExitOn string

	// LLM options
	LLM         bool
	LLMProvider string
	LLMModel    string
	LLMApiKey   string
	Explain     bool

	// Scan options
	MaxDepth    int
	MaxFileSize int64
	SkipGit     bool
	SkipVendor  bool
	Threads     int
	LogLevel    string
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "netra [flags] [paths...]",
	Short: "A security scanner for detecting secrets and credentials",
	Long: `Netra scans files and directories for potential secrets, credentials, API keys
and other sensitive information using a combination of pattern matching and machine learning techniques.

Scan Modes:
  1. Regular file scanning:
     netra [paths...]
  
  2. Scan a diff file:
     netra --diff-file path/to/changes.diff
  
  3. Scan git commit range:
     netra --commit-range HEAD~1..HEAD
  
  4. Scan staged changes:
     netra --staged`,
	RunE: runScan,
}

var opts = &Options{}

func init() {
	// Add config commands
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage netra configuration",
	}

	initConfigCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new configuration file",
		RunE:  initConfig,
	}

	configCmd.AddCommand(initConfigCmd)
	rootCmd.AddCommand(configCmd)

	// Create and add scan command
	scanCmd := &cobra.Command{
		Use:   "scan [flags] [paths...]",
		Short: "Scan files and directories for secrets",
		Long: `Scan files and directories for potential secrets, credentials, API keys
and other sensitive information.

Scan Modes:
  1. Regular file scanning:
     netra scan [paths...]
  
  2. Scan a diff file:
     netra scan --diff-file path/to/changes.diff
  
  3. Scan git commit range:
     netra scan --commit-range HEAD~1..HEAD
  
  4. Scan staged changes:
     netra scan --staged`,
		RunE: runScan,
		Args: cobra.ArbitraryArgs,
	}

	// Add all scan-related flags to scanCmd

	// Input flags
	scanCmd.Flags().StringVarP(&opts.DiffFile, "diff", "d", "", "Scan a git diff file")

	// Output flags
	scanCmd.Flags().BoolVar(&opts.Json, "json", false, "Output results in JSON format")
	scanCmd.Flags().BoolVarP(&opts.Human, "human", "H", true, "Output results in human-readable format")
	scanCmd.Flags().BoolVar(&opts.Sarif, "sarif", false, "Output results in SARIF format")
	scanCmd.Flags().StringVar(&opts.ExitOn, "exit-on", "high", "Exit with code 1 on finding severity [high|medium|low]")

	// Scanning flags
	scanCmd.Flags().IntVar(&opts.MaxDepth, "max-depth", 10, "Maximum directory depth to scan")
	scanCmd.Flags().BoolVar(&opts.SkipGit, "skip-git", true, "Skip .git directories")
	scanCmd.Flags().BoolVar(&opts.SkipVendor, "skip-vendor", true, "Skip vendor and node_modules directories")
	scanCmd.Flags().IntVar(&opts.Threads, "threads", 4, "Number of concurrent scanning threads")
	scanCmd.Flags().Int64Var(&opts.MaxFileSize, "max-file-size", 1024*1024, "Maximum file size to scan in bytes")

	// LLM flags
	scanCmd.Flags().BoolVarP(&opts.LLM, "llm", "l", false, "Use LLM to validate findings")
	scanCmd.Flags().StringVar(&opts.LLMProvider, "llm-provider", "openai", "LLM provider [openai]")
	scanCmd.Flags().StringVar(&opts.LLMModel, "llm-model", "gpt-4", "LLM model to use")
	scanCmd.Flags().StringVar(&opts.LLMApiKey, "llm-api-key", "", "LLM API key")
	scanCmd.Flags().BoolVarP(&opts.Explain, "explain", "e", false, "Include explanations in output")

	rootCmd.AddCommand(scanCmd)

	// Logging flags
	scanCmd.Flags().StringVar(&opts.LogLevel, "log-level", "info", "Set logging level (debug, info, warn, error)")

	// Config file
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default is $HOME/.netra.yaml)")

	// Environment variables
	viper.SetEnvPrefix("NETRA")
	viper.AutomaticEnv()
	viper.BindEnv("llm-api-key", "NETRA_LLM_API_KEY", "OPENAI_API_KEY")

	cobra.OnInitialize(initializeConfig)
}

// initializeConfig loads and processes configuration
func initializeConfig() {
	configFile := viper.GetString("config")
	if configFile == "" {
		// Try default locations
		home, err := os.UserHomeDir()
		if err == nil {
			defaultConfig := filepath.Join(home, ".netra.yaml")
			if _, err := os.Stat(defaultConfig); err == nil {
				configFile = defaultConfig
			}
		}
	}

	cfg, err := config.LoadOrDefault(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Update CLI options from config
	if !rootCmd.Flags().Changed("max-depth") {
		opts.MaxDepth = cfg.Scan.MaxDepth
	}
	if !rootCmd.Flags().Changed("threads") {
		opts.Threads = cfg.Scan.Threads
	}
	if !rootCmd.Flags().Changed("max-file-size") {
		opts.MaxFileSize = cfg.Scan.MaxFileSize
	}
	if !rootCmd.Flags().Changed("skip-git") {
		opts.SkipGit = cfg.Scan.SkipGit
	}
	if !rootCmd.Flags().Changed("skip-vendor") {
		opts.SkipVendor = cfg.Scan.SkipVendor
	}
	if !rootCmd.Flags().Changed("exit-on") {
		opts.ExitOn = cfg.Scan.ExitOn
	}

	// Update output format
	if !rootCmd.Flags().Changed("json") && !rootCmd.Flags().Changed("sarif") {
		switch cfg.Output.Format {
		case "json":
			opts.Json = true
			opts.Sarif = false
			opts.Human = false
		case "sarif":
			opts.Json = false
			opts.Sarif = true
			opts.Human = false
		default:
			opts.Json = false
			opts.Sarif = false
			opts.Human = true
		}
	}

	// Update LLM settings
	if cfg.LLM.Enabled {
		if !rootCmd.Flags().Changed("llm") {
			opts.LLM = true
		}
		if !rootCmd.Flags().Changed("llm-provider") {
			opts.LLMProvider = cfg.LLM.Provider
		}
		if !rootCmd.Flags().Changed("llm-model") {
			opts.LLMModel = cfg.LLM.Model
		}
		if !rootCmd.Flags().Changed("llm-api-key") {
			opts.LLMApiKey = cfg.LLM.APIKey
		}
		if !rootCmd.Flags().Changed("explain") {
			opts.Explain = cfg.LLM.Explain
		}
	}
}

// Execute runs the CLI application
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runScan performs the actual scanning operation
func runScan(cmd *cobra.Command, args []string) error {
	// Set up logging
	logger.SetLevel(logger.ParseLevel(opts.LogLevel))
	logger.Debug("Debug logging enabled")

	// Log all configuration details
	logger.Info("Starting scan with the following configuration:")
	logger.Info("Input Configuration:")
	if opts.DiffFile != "" {
		logger.Info("  - Scan Mode: Diff file scanning")
		logger.Info("  - Diff File: %s", opts.DiffFile)
	} else if opts.CommitRange != "" {
		logger.Info("  - Scan Mode: Commit range scanning")
		logger.Info("  - Commit Range: %s", opts.CommitRange)
	} else if opts.StagedOnly {
		logger.Info("  - Scan Mode: Staged changes scanning")
	} else {
		logger.Info("  - Scan Mode: Regular file scanning")
		logger.Info("  - Target Paths: %v", args)
	}

	logger.Info("Scan Configuration:")
	logger.Info("  - Max Depth: %d", opts.MaxDepth)
	logger.Info("  - Max File Size: %d bytes", opts.MaxFileSize)
	logger.Info("  - Skip Git: %v", opts.SkipGit)
	logger.Info("  - Skip Vendor: %v", opts.SkipVendor)
	logger.Info("  - Threads: %d", opts.Threads)

	logger.Info("Output Configuration:")
	logger.Info("  - JSON Output: %v", opts.Json)
	logger.Info("  - Human Output: %v", opts.Human)
	logger.Info("  - SARIF Output: %v", opts.Sarif)
	logger.Info("  - Exit On: %s", opts.ExitOn)

	if opts.LLM {
		logger.Info("LLM Configuration:")
		logger.Info("  - Provider: %s", opts.LLMProvider)
		logger.Info("  - Model: %s", opts.LLMModel)
		logger.Info("  - Explain: %v", opts.Explain)
		logger.Debug("  - API Key Length: %d", len(opts.LLMApiKey)) // Don't log the actual key
	}

	// Create scanner configuration
	scanConfig := &types.ScanConfig{
		MaxDepth:    opts.MaxDepth,
		SkipGit:     opts.SkipGit,
		SkipVendor:  opts.SkipVendor,
		Threads:     opts.Threads,
		MaxFileSize: opts.MaxFileSize,
	}

	// Create scanner options
	scannerOpts := []scanner.Option{
		scanner.WithConfig(scanConfig),
	}

	// Add LLM configuration if enabled
	if opts.LLM {
		// Get API key from flag, env var, or config file
		apiKey := opts.LLMApiKey
		if apiKey == "" {
			apiKey = viper.GetString("llm-api-key")
		}
		if apiKey == "" {
			return fmt.Errorf("LLM API key required. Set via --llm-api-key flag or NETRA_LLM_API_KEY environment variable")
		}

		mlConfig := &types.MLConfig{
			Enabled:     true,
			Provider:    opts.LLMProvider,
			Model:       opts.LLMModel,
			APIKey:      apiKey,
			MaxTokens:   1000,
			Temperature: 0.1,
			Threshold:   0.8,
			CacheSize:   1000,
		}
		scannerOpts = append(scannerOpts, scanner.WithMLConfig(mlConfig))
	}

	ctx := context.Background()
	var result *types.Result
	var err error

	// Handle different scan modes TODO: re-enable diff file scanning
	if opts.DiffFile != "" {
		// Diff file scanning mode
		diffScanner := scanner.NewDiffScanner(scannerOpts...)
		result, err = diffScanner.ScanDiffFile(opts.DiffFile)
	} else if opts.CommitRange != "" {
		// Commit range scanning mode
		diffScanner := scanner.NewDiffScanner(scannerOpts...)
		commits := strings.Split(opts.CommitRange, "..")
		if len(commits) != 2 {
			return fmt.Errorf("invalid commit range format. Use: fromCommit..toCommit")
		}
		result, err = diffScanner.ScanCommitRange(".", commits[0], commits[1])
	} else if opts.StagedOnly {
		// Staged changes scanning mode
		diffScanner := scanner.NewDiffScanner(scannerOpts...)
		result, err = diffScanner.ScanStagedChanges(".")
	} else {
		// Regular file scanning mode
		if len(args) == 0 {
			args = []string{"."}
		}
		s := scanner.New(scannerOpts...)
		result, err = s.Scan(ctx, args...)
	}

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Process and output results
	exitCode := processResults(result)
	os.Exit(exitCode)
	return nil
}

// initConfig creates a new default config file
func initConfig(cmd *cobra.Command, args []string) error {
	defaultConfig := config.DefaultConfig()

	// Get the directory where the binary is located
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting executable path: %w", err)
	}
	binDir := filepath.Dir(exePath)

	configPath := filepath.Join(binDir, ".netra.yaml")
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file already exists at %s", configPath)
	}

	// Save default config
	if err := defaultConfig.Save(configPath); err != nil {
		return fmt.Errorf("saving config file: %w", err)
	}

	fmt.Printf("Created default config file at %s\n", configPath)
	return nil
}

// processResults handles scan results and returns exit code
func processResults(result *types.Result) int {
	// Handle output generation errors
	if err := generateOutput(result); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating output: %v\n", err)
		return exitcode.Error
	}

	// If no findings, return success
	if len(result.Findings) == 0 {
		return exitcode.Success
	}

	// Get severities from all findings
	severities := make([]string, len(result.Findings))
	for i, f := range result.Findings {
		severities[i] = strings.ToLower(f.Severity)
	}

	// Get the highest severity from findings
	highestSeverity := exitcode.GetHighestSeverity(severities)

	// Check if we should exit with error based on configured exit level
	if exitcode.ShouldExit(highestSeverity, exitcode.ParseExitLevel(opts.ExitOn)) {
		return exitcode.ScanError
	}

	return exitcode.Success
}

// generateOutput handles the generation of output in the appropriate format
func generateOutput(result *types.Result) error {
	version := "1.0.0" // Program version
	switch {
	case opts.Json:
		jsonOpts := &output.Options{
			LLM:        opts.LLM,
			MaxDepth:   opts.MaxDepth,
			Threads:    opts.Threads,
			MaxSize:    opts.MaxFileSize,
			SkipGit:    opts.SkipGit,
			SkipVendor: opts.SkipVendor,
		}
		data, err := output.ToJSON(result, version, jsonOpts)
		if err != nil {
			return fmt.Errorf("generating JSON output: %w", err)
		}
		fmt.Println(string(data))
	// case opts.Sarif:
	// 	data, err := output.ToSARIF(result, version)
	// 	if err != nil {
	// 		return fmt.Errorf("generating SARIF output: %w", err)
	// 	}
	// 	fmt.Println(string(data))
	default:
		if err := output.WriteHuman(result, opts.Explain); err != nil {
			return fmt.Errorf("generating human output: %w", err)
		}
	}
	return nil
}
