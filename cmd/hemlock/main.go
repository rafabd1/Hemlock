package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/core"
	"github.com/rafabd1/Hemlock/internal/networking"
	"github.com/rafabd1/Hemlock/internal/report"
	"github.com/rafabd1/Hemlock/internal/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfg config.Config
var logger utils.Logger

const defaultWordlistDir = "wordlists"
const defaultHeadersFilename = "headers.txt"

var rootCmd = &cobra.Command{
	Use:   "hemlock",
	Short: "Hemlock is a tool for detecting Web Cache Poisoning.",
	Long: `Hemlock - Web Cache Poisoning Vulnerability Scanner.

Analyzes URLs to identify potential cache poisoning vulnerabilities
via unkeyed HTTP headers and URL parameters.
Uses probing techniques to verify if injected payloads are reflected and cached.
`,
	Example: `  # Scan a single target with debug verbosity and JSON output to file:
  hemlock -t http://example.com -V debug -o results.json

  # Scan multiple targets (comma-separated) with 50 concurrent workers:
  hemlock --targets "http://site1.com,https://site2.org" -c 50

  # Scan targets from a file, using a custom headers file and proxy:
  hemlock --targets-file /path/to/targets.txt --headers-file /path/to/my_headers.txt --proxy http://localhost:8080

  # Silent scan, showing only fatal errors and final report in text format:
  hemlock -t http://vulnerable.site --silent --output-format text

  # Scan with custom request headers and 5 retries:
  hemlock -t http://test.com -H "User-Agent: MyScanner/1.0" -H "Authorization: Bearer xyz" -r 5`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize Viper to read configs, env vars, and flags
		vp := viper.New()
		vp.SetEnvPrefix("HEMLOCK")
		vp.AutomaticEnv()
		vp.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

		// Bind all persistent flags to Viper
		if err := vp.BindPFlags(cmd.PersistentFlags()); err != nil {
			return fmt.Errorf("error binding persistent flags to viper: %w", err)
		}
		// Bind all local flags (if there are child commands) to Viper
		if err := vp.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("error binding local flags to viper: %w", err)
		}

		// Populate the cfg struct with values from Viper
		cfg = *config.GetDefaultConfig() // Start with hardcoded defaults

		// String arrays from Viper
		if vp.IsSet("targets") { cfg.Targets = vp.GetStringSlice("targets") }
		if vp.IsSet("payloads") { cfg.BasePayloads = vp.GetStringSlice("payloads") }
		if vp.IsSet("header") { cfg.CustomHeaders = vp.GetStringSlice("header") }
		
		cfg.DefaultPayloadPrefix = vp.GetString("payload-prefix")
		cfg.Concurrency = vp.GetInt("concurrency")
		cfg.RequestTimeout = vp.GetDuration("timeout")
		cfg.OutputFile = vp.GetString("output-file")
		cfg.OutputFormat = vp.GetString("output-format")
		cfg.Verbosity = vp.GetString("verbosity")
		cfg.ProxyInput = vp.GetString("proxy")
		cfg.HeadersFile = vp.GetString("headers-file")
		cfg.TargetsFile = vp.GetString("targets-file")
		cfg.MinRequestDelayMs = vp.GetInt("min-delay")
		cfg.DomainCooldownMs = vp.GetInt("cooldown")
		cfg.MaxRetries = vp.GetInt("max-retries")
		cfg.RetryDelayBaseMs = vp.GetInt("retry-delay-base")
		cfg.RetryDelayMaxMs = vp.GetInt("retry-delay-max")
		cfg.MaxConsecutiveFailuresToBlock = vp.GetInt("max-consecutive-failures")
		cfg.NoColor = vp.GetBool("no-color")
		cfg.Silent = vp.GetBool("silent")

		// Special logic for -v (verbose) that affects verbosity
		if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
			cfg.Verbosity = "debug"
		}

		// Initialize Logger (after verbosity, noColor and silent are set)
		logLevel := utils.StringToLogLevel(cfg.Verbosity)
		logger = utils.NewDefaultLogger(logLevel, cfg.NoColor, cfg.Silent)
		
		// Load targets from --targets-file if specified (takes precedence over --targets)
		if cfg.TargetsFile != "" {
			logger.Infof("Reading targets from file specified by --targets-file: %s", cfg.TargetsFile)
			fileTargets, err := config.LoadLinesFromFile(cfg.TargetsFile)
		    if err != nil {
				return fmt.Errorf("error reading targets from file '%s': %w", cfg.TargetsFile, err)
			}
			cfg.Targets = fileTargets
		} else if len(cfg.Targets) > 0 { // If --targets was used and not --targets-file
		    // If targets came as a single string from viper (e.g., from env var), split it
		    // If it's already a slice (from flag that accepts multiple times or CSV list), it's fine
		    // Cobra/Viper usually handles StringSliceP well, so it may already be a slice.
		    // But if it's a single-element slice containing commas, split it for safety.
		    if len(cfg.Targets) == 1 && strings.Contains(cfg.Targets[0], ",") {
		        cfg.Targets = strings.Split(cfg.Targets[0], ",")
		    }
		    for i := range cfg.Targets {
			    cfg.Targets[i] = strings.TrimSpace(cfg.Targets[i])
		    }
	    }

		// Load HeadersToTest
		if cfg.HeadersFile == "" { // If --headers-file not provided, try default paths
			exePath, err := os.Executable()
			if err != nil {
				logger.Warnf("Could not get executable path: %v", err)
			}
			potentialPaths := []string{
				filepath.Join(defaultWordlistDir, defaultHeadersFilename),                           // ./wordlists/headers.txt
				filepath.Join(filepath.Dir(exePath), defaultWordlistDir, defaultHeadersFilename),    // <exe_dir>/wordlists/headers.txt
				filepath.Join(filepath.Dir(exePath), "..", defaultWordlistDir, defaultHeadersFilename), // <exe_dir>/../wordlists/headers.txt (for dev)
				// Add other default installation paths here if needed (e.g., /usr/local/share/...)
			}
			foundPath := ""
			for _, p := range potentialPaths {
				if _, err := os.Stat(p); err == nil {
					cfg.HeadersFile = p
					foundPath = p
					logger.Debugf("Default headers file found at: %s", p)
					break
				}
			}
			if foundPath == "" {
				return fmt.Errorf("default headers file ('%s') not found in standard locations and --headers-file not specified. This file is essential.", defaultHeadersFilename)
			}
		} // else cfg.HeadersFile was provided by the flag

		logger.Infof("Loading headers from: %s", cfg.HeadersFile)
		loadedHeaders, err := config.LoadLinesFromFile(cfg.HeadersFile)
		if err != nil {
			return fmt.Errorf("error loading headers from '%s': %w", cfg.HeadersFile, err)
		}
		if len(loadedHeaders) == 0 {
			return fmt.Errorf("headers file '%s' is empty.", cfg.HeadersFile)
		}
		cfg.HeadersToTest = loadedHeaders

		// Parse ProxyInput
		if cfg.ProxyInput != "" {
			parsedPx, errPx := utils.ParseProxyInput(cfg.ProxyInput, logger)
			if errPx != nil {
				logger.Warnf("Error parsing proxy input '%s': %v. Continuing without proxies from this input.", cfg.ProxyInput, errPx)
				cfg.ParsedProxies = []config.ProxyEntry{}
			} else {
				cfg.ParsedProxies = parsedPx
			}
	    } else {
			cfg.ParsedProxies = []config.ProxyEntry{}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.Infof("Hemlock Cache Scanner starting...")
		logger.Debugf("Effective Configuration: %s", cfg.String())

		if err := cfg.Validate(); err != nil {
			logger.Fatalf("Invalid configuration: %v", err)
		}

	    if len(cfg.Targets) == 0 {
			logger.Fatalf("No targets specified. Use --targets or --targets-file.")
		}
		if len(cfg.HeadersToTest) == 0 {
			logger.Fatalf("No headers to test were loaded. Check --headers-file or the default file.")
	    }

		httpClient, errClient := networking.NewClient(&cfg, logger)
	    if errClient != nil {
			logger.Fatalf("Failed to create HTTP client: %v", errClient)
		}
		logger.Debugf("HTTP client initialized.")

		processor := core.NewProcessor(&cfg, logger)
		logger.Debugf("Processor initialized.")

		// Initialize DomainManager
		domainManager := networking.NewDomainManager(&cfg, logger)
		logger.Debugf("DomainManager initialized.")

		// Pass domainManager to NewScheduler
		scheduler := core.NewScheduler(&cfg, httpClient, processor, domainManager, logger)
		logger.Debugf("Scheduler initialized.")

		logger.Infof("Starting scan for %d target(s)...", len(cfg.Targets))
	    findings := scheduler.StartScan() 

		logger.Infof("Scan completed. Generating report for %d findings...", len(findings))
	    errReport := report.GenerateReport(findings, cfg.OutputFile, cfg.OutputFormat)
	    if errReport != nil {
			logger.Errorf("Failed to generate report: %v", errReport)
		    if cfg.OutputFile != "" && (strings.ToLower(cfg.OutputFormat) == "text" || strings.ToLower(cfg.OutputFormat) == "json") {
				logger.Warnf("Attempting to print report to stdout as fallback...")
			    fbErr := report.GenerateReport(findings, "", cfg.OutputFormat) 
			    if fbErr != nil {
					logger.Errorf("Fallback to stdout also failed: %v", fbErr)
			    }
		    }
	    } else {
			logger.Infof("Report generated successfully.")
		}

		logger.Infof("Hemlock Cache Scanner finished.")
		return nil
	},
}

func init() {
	// Configuration of Viper for defaults
	defaults := config.GetDefaultConfig()
	// Viper is now initialized and used locally in PersistentPreRunE to populate cfg
	// and here to set the defaults for Cobra flags.

	// Persistent Flags (available to the root command and any subcommands)
	rootCmd.PersistentFlags().StringSliceP("targets", "t", defaults.Targets, "List of target URLs separated by comma (e.g., http://host1,http://host2)")
	rootCmd.PersistentFlags().StringP("targets-file", "f", defaults.TargetsFile, "Path to a file containing target URLs (one per line)")

	rootCmd.PersistentFlags().String("headers-file", defaults.HeadersFile, "Path to the file of headers to test (default: wordlists/headers.txt in standard locations)")
	rootCmd.PersistentFlags().StringSlice("payloads", defaults.BasePayloads, "List of base payloads to use (comma-separated)")
	rootCmd.PersistentFlags().String("payload-prefix", defaults.DefaultPayloadPrefix, "Prefix for automatically generated payloads if base payloads list is empty")

	rootCmd.PersistentFlags().StringP("output-file", "o", defaults.OutputFile, "Path to file for saving results (default: stdout)")
	rootCmd.PersistentFlags().String("output-format", defaults.OutputFormat, "Output format: json or text")

	rootCmd.PersistentFlags().StringP("verbosity", "V", defaults.Verbosity, "Log level: debug, info, warn, error, fatal")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Shortcut for --verbosity debug")

	rootCmd.PersistentFlags().IntP("concurrency", "c", defaults.Concurrency, "Number of concurrent workers")
	rootCmd.PersistentFlags().DurationP("timeout", "T", defaults.RequestTimeout, "HTTP request timeout (e.g., 10s, 1m)")
	// Remove --user-agent flag and add --header flag
	rootCmd.PersistentFlags().StringSliceP("header", "H", defaults.CustomHeaders, "Custom HTTP header to add to requests (can be specified multiple times, format: \"Name: Value\")")
	rootCmd.PersistentFlags().String("proxy", defaults.ProxyInput, "Proxy to use (URL, CSV list, or file path)")

	rootCmd.PersistentFlags().Int("min-delay", defaults.MinRequestDelayMs, "Minimum delay in ms between requests to the same domain")
	rootCmd.PersistentFlags().Int("cooldown", defaults.DomainCooldownMs, "Cooldown period in ms for a domain after being blocked")

	// Retry flags
	rootCmd.PersistentFlags().IntP("max-retries", "r", defaults.MaxRetries, "Maximum number of retries per request")
	rootCmd.PersistentFlags().Int("retry-delay-base", defaults.RetryDelayBaseMs, "Base delay in ms for exponential backoff between retries")
	rootCmd.PersistentFlags().Int("retry-delay-max", defaults.RetryDelayMaxMs, "Maximum delay in ms for backoff between retries")
	rootCmd.PersistentFlags().Int("max-consecutive-failures", defaults.MaxConsecutiveFailuresToBlock, "Number of consecutive network failures to block a domain (0 to disable this method)")

	rootCmd.PersistentFlags().Bool("no-color", defaults.NoColor, "Disable colors in text output")
	rootCmd.PersistentFlags().Bool("silent", defaults.Silent, "Suppress all logs except final results (findings)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing hemlock: %v\n", err)
		os.Exit(1)
	}
} 