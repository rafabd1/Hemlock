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
		cfg.DelayMs = vp.GetInt("delay")
		cfg.MaxRetries = vp.GetInt("max-retries")
		cfg.MaxConsecutiveFailuresToBlock = vp.GetInt("max-consecutive-failures")
		cfg.NoColor = vp.GetBool("no-color")
		cfg.Silent = vp.GetBool("silent")

		// Restaurar UserAgent padrão se o Viper o zerou (porque a flag não existe mais)
		if cfg.UserAgent == "" {
			defaultCfg := config.GetDefaultConfig()
			cfg.UserAgent = defaultCfg.UserAgent
		}

		// Special logic for -v (verbose) that affects verbosity
		if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
			cfg.Verbosity = "debug"
		}

		// Initialize Logger (after verbosity, noColor and silent are set)
		logLevel := utils.StringToLogLevel(cfg.Verbosity)
		logger = utils.NewDefaultLogger(logLevel, cfg.NoColor, cfg.Silent)
		
		// Load targets from --targets-file if specified (takes precedence over --targets)
		if cfg.TargetsFile != "" {
			fileTargets, err := config.LoadLinesFromFile(cfg.TargetsFile)
		if err != nil {
				return fmt.Errorf("error reading targets from file '%s': %w", cfg.TargetsFile, err)
			}
			cfg.Targets = fileTargets
		} else if len(cfg.Targets) > 0 { 
		    if len(cfg.Targets) == 1 && strings.Contains(cfg.Targets[0], ",") {
		        cfg.Targets = strings.Split(cfg.Targets[0], ",")
		    }
		for i := range cfg.Targets {
			cfg.Targets[i] = strings.TrimSpace(cfg.Targets[i])
		}
	}

		// Load HeadersToTest
		if cfg.HeadersFile == "" { 
			exePath, err := os.Executable()
			if err != nil {
				logger.Warnf("Could not get executable path: %v", err) 
			}
			potentialPaths := []string{
				filepath.Join(defaultWordlistDir, defaultHeadersFilename),                           
				filepath.Join(filepath.Dir(exePath), defaultWordlistDir, defaultHeadersFilename),    
				filepath.Join(filepath.Dir(exePath), "..", defaultWordlistDir, defaultHeadersFilename), 
			}
			foundPath := ""
			for _, p := range potentialPaths {
				if _, err := os.Stat(p); err == nil {
					cfg.HeadersFile = p
					foundPath = p
					break
				}
			}
			if foundPath == "" {
				return fmt.Errorf("default headers file ('%s') not found in standard locations and --headers-file not specified. This file is essential", defaultHeadersFilename)
			}
		} 

		loadedHeaders, err := config.LoadLinesFromFile(cfg.HeadersFile)
		if err != nil {
			return fmt.Errorf("error loading headers from '%s': %w", cfg.HeadersFile, err)
		}
		if len(loadedHeaders) == 0 {
			return fmt.Errorf("headers file '%s' is empty", cfg.HeadersFile)
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
		// Display Banner (only if not in silent mode and verbosity is info or higher)
		if !cfg.Silent && utils.StringToLogLevel(cfg.Verbosity) <= utils.LevelInfo {
			banner := `
   _    _                _            _    
  | |  | |              | |          | |   
  | |__| | ___ _ __ ___ | | ___   ___| | __
  |  __  |/ _ \ '_ ` + "`" + ` _ \| |/ _ \ / __| |/ /
  | |  | |  __/ | | | | | | (_) | (__|   < 
  |_|  |_|\___|_| |_| |_|_|\___/ \___|_|\_\
`
			version := "v0.1.0" // Placeholder version, update as needed
			author := "github.com/rafabd1"    // Placeholder author, update as needed
			fmt.Printf("%s\n", banner)
			fmt.Printf("\t\t\t\tVersion: %s by %s\n\n", version, author)
		}
		
		// Log file loading info
		if cfg.TargetsFile != "" {
			logger.Infof("Reading targets from file: %s", cfg.TargetsFile)
		} else if len(cfg.Targets) > 0 {
			logger.Infof("Using %d target(s) from command line arguments.", len(cfg.Targets))
		}
		logger.Infof("Using headers from: %s", cfg.HeadersFile)
		
		if err := cfg.Validate(); err != nil {
			logger.Fatalf("Invalid configuration: %v", err)
		}

	if len(cfg.Targets) == 0 {
			logger.Fatalf("No targets specified. Use --targets or --targets-file")
		}
		if len(cfg.HeadersToTest) == 0 {
			logger.Fatalf("No headers to test were loaded. Check --headers-file or the default file")
	    }

		// Pre-process URLs here to get parameter counts for the summary
		// Note: This is a bit redundant as Scheduler will do it again, but needed for summary before scan starts.
		_, _, totalParamsFoundForSummary, baseURLsWithParamsCountForSummary := utils.PreprocessAndGroupURLs(cfg.Targets, logger) 
		// Suppress logger output from this specific call if it's too verbose before the main scan log
		// For now, we assume the logger level will handle this appropriately, or we'd need a temp silent logger.

		// Enhanced Initial Statistics Log
		if !cfg.Silent && utils.StringToLogLevel(cfg.Verbosity) <= utils.LevelInfo {
			fmt.Println("------------------------------------------------------------")
			fmt.Println(" Scan Configuration Summary")
			fmt.Println("------------------------------------------------------------")
			fmt.Printf(" Initial Targets Provided: %d (Unique base URLs will be logged by the scanner)\n", len(cfg.Targets))
			fmt.Printf(" Headers to Test: %d loaded from '%s'\n", len(cfg.HeadersToTest), cfg.HeadersFile)

			paramTestsEnabled := len(cfg.BasePayloads) > 0 || cfg.DefaultPayloadPrefix != ""
			if paramTestsEnabled && totalParamsFoundForSummary > 0 {
				fmt.Printf(" URL Parameters to Test: %d (from %d base URL(s) with parameters)\n", totalParamsFoundForSummary, baseURLsWithParamsCountForSummary)
				if len(cfg.BasePayloads) > 0 {
					fmt.Printf("   Custom Base Payloads for Parameters: %d\n", len(cfg.BasePayloads))
					for i, p := range cfg.BasePayloads {
						fmt.Printf("     - Payload %d: %s\n", i+1, p) 
						if i > 2 && len(cfg.BasePayloads) > 5 { 
							fmt.Printf("     ... and %d more\n", len(cfg.BasePayloads)-(i+1))
							break
						}
					}
				}
			} else if paramTestsEnabled {
				fmt.Println(" URL Parameter Tests: Enabled, but no URL parameters found in the provided targets.")
			} else {
				fmt.Println(" URL Parameter Tests: Disabled (no base payloads or prefix defined)")
			}

			fmt.Printf(" Concurrency: %d workers\n", cfg.Concurrency)
			fmt.Printf(" Request Timeout: %s\n", cfg.RequestTimeout.String())
			
			// Default User-Agent and Custom Headers
			if len(cfg.CustomHeaders) > 0 {
				fmt.Printf(" Custom Global Headers (%d):\n", len(cfg.CustomHeaders))
				for _, h := range cfg.CustomHeaders {
					fmt.Printf("   - %s\n", h)
				}
			} else {
				fmt.Println(" Custom Global Headers: None")
			}

			if len(cfg.ParsedProxies) > 0 {
				fmt.Printf(" Proxies: %d configured\n", len(cfg.ParsedProxies))
			} else {
				fmt.Println(" Proxies: None configured")
			}
			fmt.Printf(" Max Retries per Request: %d\n", cfg.MaxRetries)
			fmt.Printf(" Delay Between Requests (same domain): %dms\n", cfg.DelayMs)
			fmt.Printf(" Max Consecutive Failures to Block Domain: %d\n", cfg.MaxConsecutiveFailuresToBlock)
			if cfg.OutputFile != "" {
				fmt.Printf(" Output File: %s (Format: %s)\n", cfg.OutputFile, cfg.OutputFormat)
			} else {
				fmt.Printf(" Output: stdout (Format: %s)\n", cfg.OutputFormat)
			}
			fmt.Printf(" Log Level: %s\n", cfg.Verbosity)
			fmt.Println("------------------------------------------------------------")
		}

		logger.Infof("Hemlock Cache Scanner initializing...")

		// Initialize services
		httpClient, errClient := networking.NewClient(&cfg, logger)
	if errClient != nil {
		logger.Fatalf("Failed to create HTTP client: %v", errClient)
	}
		logger.Debugf("HTTP client initialized.")

		processor := core.NewProcessor(&cfg, logger)
	logger.Debugf("Processor initialized.")

		domainManager := networking.NewDomainManager(&cfg, logger)
		logger.Debugf("DomainManager initialized.")

		scheduler := core.NewScheduler(&cfg, httpClient, processor, domainManager, logger)
	logger.Debugf("Scheduler initialized.")

		// StartScan agora retorna contagens, mas elas não são usadas diretamente aqui, pois o sumário já usou as suas próprias.
		findings, _, _, _ := scheduler.StartScan()

		logger.Infof("Scan completed. Generating report for %d finding(s)...", len(findings))
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
	rootCmd.PersistentFlags().StringSliceP("header", "H", defaults.CustomHeaders, "Custom HTTP header to add to requests (can be specified multiple times, format: \"Name: Value\")")
	rootCmd.PersistentFlags().String("proxy", defaults.ProxyInput, "Proxy to use (URL, CSV list, or file path)")

	rootCmd.PersistentFlags().Int("delay", defaults.DelayMs, "Delay in ms between requests to the same domain")

	// Retry flags
	rootCmd.PersistentFlags().IntP("max-retries", "r", defaults.MaxRetries, "Maximum number of retries per request")
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