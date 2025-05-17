package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Required for time.Duration in examples if any
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
  hemlock -i http://example.com -vv -o results.json

  # Scan multiple targets (comma-separated in a string) with 50 concurrent workers:
  hemlock --input "http://site1.com,https://site2.org" -c 50

  # Scan targets from a file, using a custom headers file and proxy, with a 5 req/s rate limit:
  hemlock -i /path/to/targets.txt --headers-file /path/to/my_headers.txt --proxy http://localhost:8080 -l 5

  # Silent scan, showing only fatal errors and final report in text format, skipping TLS verification:
  hemlock -i http://vulnerable.site --silent --output-format text --insecure

  # Scan with custom request headers, 5 retries and a 5s timeout:
  hemlock -i http://test.com -H "User-Agent: MyScanner/1.0" -H "Authorization: Bearer xyz" -r 5 -t 5s`,
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

		// --- Populate config from Viper/Flags ---
		cfg.Input = vp.GetString("input")
		cfg.CustomHeaders = vp.GetStringSlice("header")
		cfg.Concurrency = vp.GetInt("concurrency")
		timeoutSeconds := vp.GetInt("timeout")
		cfg.RequestTimeout = time.Duration(timeoutSeconds) * time.Second
		cfg.OutputFile = vp.GetString("output-file")
		cfg.OutputFormat = vp.GetString("output-format")
		cfg.ProxyInput = vp.GetString("proxy")
		cfg.HeadersFile = vp.GetString("headers-file")
		cfg.MaxRetries = vp.GetInt("max-retries")
		cfg.NoColor = vp.GetBool("no-color")
		cfg.Silent = vp.GetBool("silent")
		cfg.InsecureSkipVerify = vp.GetBool("insecure")
		cfg.MaxTargetRPS = vp.GetFloat64("rate-limit")

		// Handle verbosity flags to set both Verbosity (string) and VerbosityLevel (int)
		verboseFlag, _ := cmd.Flags().GetBool("verbose")       // -v
		veryVerboseFlag, _ := cmd.Flags().GetBool("vverbose") // -vv (Note: standard is often just two v's for the flag name, e.g. cmd.Flags().Count("v"))
		                                                    // Let's assume separate flags for now as defined in init()

		if cfg.Silent {
			cfg.VerbosityLevel = -1 // Special level for silent, logger will handle this
			cfg.Verbosity = "fatal" // Or some equivalent concept for the logger
		} else if veryVerboseFlag {
			cfg.VerbosityLevel = 2
			cfg.Verbosity = "debug"
		} else if verboseFlag {
			cfg.VerbosityLevel = 1
			cfg.Verbosity = "debug" // -v can also map to debug, with level 1 filtering in app
		} else {
			cfg.VerbosityLevel = 0  // Default (info)
			cfg.Verbosity = "info"
		}

		// Initialize Logger (after verbosity, noColor and silent are set)
		logLevel := utils.StringToLogLevel(cfg.Verbosity)
		logger = utils.NewDefaultLogger(logLevel, cfg.NoColor, cfg.Silent)
		
		// --- Process Input (-i, --input) ---
		if cfg.Input != "" {
			// Check if input is a file path
			if _, err := os.Stat(cfg.Input); err == nil {
				// Input is a file, load targets from it
				logger.Infof("Input '%s' detected as a file. Reading targets from file.", cfg.Input)
				fileTargets, errLoad := config.LoadLinesFromFile(cfg.Input)
				if errLoad != nil {
					logger.Errorf("Error reading targets from input file '%s': %v", cfg.Input, errLoad)
					return fmt.Errorf("error reading targets from input file '%s': %w", cfg.Input, errLoad)
				}
				cfg.Targets = fileTargets
				cfg.TargetsFile = cfg.Input // Store the fact it came from a file for logging consistency
			} else {
				// Input is not a file, treat as comma-separated list or single URL
				logger.Infof("Input '%s' detected as URL(s).", cfg.Input)
				if strings.Contains(cfg.Input, ",") {
					cfg.Targets = strings.Split(cfg.Input, ",")
				} else {
					cfg.Targets = []string{cfg.Input}
				}
				// Trim spaces from targets
				for i := range cfg.Targets {
					cfg.Targets[i] = strings.TrimSpace(cfg.Targets[i])
				}
			}
		}

		// --- Load HeadersToTest ---
		if cfg.HeadersFile == "" { 
			exePath, err := os.Executable()
			if err != nil {
				logger.Warnf("Could not get executable path to find default headers: %v", err) 
			}
			potentialPaths := []string{
				filepath.Join(defaultWordlistDir, defaultHeadersFilename),                           
				filepath.Join(filepath.Dir(exePath), defaultWordlistDir, defaultHeadersFilename),    
				filepath.Join(filepath.Dir(exePath), "..", defaultWordlistDir, defaultHeadersFilename), 
				"./" + defaultWordlistDir + "/" + defaultHeadersFilename, // Relative to current dir
			}
			foundPath := ""
			for _, p := range potentialPaths {
				if _, err := os.Stat(p); err == nil {
					cfg.HeadersFile = p
					foundPath = p
					logger.Debugf("Found default headers file at: %s", p)
					break
				}
			}
			if foundPath == "" {
				errMsg := fmt.Sprintf("default headers file ('%s') not found in standard locations ('%s', relative paths) and --headers-file not specified. This file is essential", defaultHeadersFilename, defaultWordlistDir)
				logger.Errorf(errMsg)
				return fmt.Errorf("%s", errMsg)
			}
		} 

		logger.Infof("Using headers from: %s", cfg.HeadersFile)
		loadedHeaders, err := config.LoadLinesFromFile(cfg.HeadersFile)
		if err != nil {
			logger.Errorf("Error loading headers from '%s': %v", cfg.HeadersFile, err)
			return fmt.Errorf("error loading headers from '%s': %w", cfg.HeadersFile, err)
		}
		if len(loadedHeaders) == 0 {
			errMsg := fmt.Sprintf("headers file '%s' is empty", cfg.HeadersFile)
			logger.Errorf(errMsg)
			return fmt.Errorf("%s", errMsg)
		}
		cfg.HeadersToTest = loadedHeaders

		// --- Parse ProxyInput ---
		if cfg.ProxyInput != "" {
			parsedPx, errPx := utils.ParseProxyInput(cfg.ProxyInput, logger) // This line has the linter error
			if errPx != nil {
				logger.Warnf("Error parsing proxy input '%s': %v. Continuing without proxies from this input.", cfg.ProxyInput, errPx)
				cfg.ParsedProxies = []config.ProxyEntry{}
			} else {
				// Assuming the linter error is resolved elsewhere, and parsedPx is of type []config.ProxyEntry
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
			version := "v0.1.1" // Placeholder version, update as needed
			author := "github.com/rafabd1"    // Placeholder author, update as needed
			fmt.Printf("%s\n", banner)
			fmt.Printf("\t\t\t\tVersion: %s by %s\n\n", version, author)
		}
		
		// Log file loading info (simplified as Input provides context now)
		if cfg.TargetsFile != "" { // TargetsFile is populated if input was a file
			logger.Infof("Targets loaded from file: %s", cfg.TargetsFile)
		} else if len(cfg.Targets) > 0 {
			logger.Infof("Using %d target(s) from --input argument.", len(cfg.Targets))
		} 
		// HeadersFile logging is already done in PersistentPreRunE
		
		if err := cfg.Validate(); err != nil {
			logger.Fatalf("Invalid configuration: %v", err)
		}

		if len(cfg.Targets) == 0 {
			logger.Fatalf("No targets specified. Use --input or -i to provide a URL, list of URLs, or a file path.")
		}
		if len(cfg.HeadersToTest) == 0 {
			logger.Fatalf("No headers to test were loaded. Check --headers-file or the default file location.")
	    }

		// Pre-process URLs for summary (optional, could be removed if too verbose)
		_, _, totalParamsFoundForSummary, baseURLsWithParamsCountForSummary := utils.PreprocessAndGroupURLs(cfg.Targets, logger)

		// Enhanced Initial Statistics Log
		if !cfg.Silent && utils.StringToLogLevel(cfg.Verbosity) <= utils.LevelInfo {
			fmt.Println("------------------------------------------------------------")
			fmt.Println(" Scan Configuration Summary")
			fmt.Println("------------------------------------------------------------")
			fmt.Printf(" Targets Provided: %d (via --input '%s')\n", len(cfg.Targets), cfg.Input)
			fmt.Printf(" Headers to Test: %d loaded from '%s'\n", len(cfg.HeadersToTest), cfg.HeadersFile)

			// Parameter test info (payload flags removed, so this is about internal logic now)
			// This might need adjustment if BasePayloads/DefaultPayloadPrefix are always default
			paramTestsImplicitlyEnabled := cfg.DefaultPayloadPrefix != "" || len(cfg.BasePayloads) > 0
			if paramTestsImplicitlyEnabled && totalParamsFoundForSummary > 0 {
				fmt.Printf(" URL Parameter Tests: Implicitly enabled, %d params found in %d base URLs\n", totalParamsFoundForSummary, baseURLsWithParamsCountForSummary)
			} else if paramTestsImplicitlyEnabled {
				fmt.Println(" URL Parameter Tests: Implicitly enabled, but no URL parameters found in targets.")
			} else {
				fmt.Println(" URL Parameter Tests: Implicitly disabled (internal payload config empty)")
			}

			fmt.Printf(" Concurrency: %d workers\n", cfg.Concurrency)
			fmt.Printf(" Request Timeout: %s\n", cfg.RequestTimeout.String())
			
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
			
			// Rate Limit Info
			if cfg.MaxTargetRPS > 0 {
				fmt.Printf(" Rate Limit: Up to %.2f requests/second per domain\n", cfg.MaxTargetRPS)
			} else {
				fmt.Printf(" Rate Limit: Auto (Initial: %.2f req/s, Min: %.2f req/s per domain)\n", cfg.InitialTargetRPS, cfg.MinTargetRPS)
			}
			fmt.Printf(" TLS Verification: %s\n", map[bool]string{true: "Disabled (insecure)", false: "Enabled"}[cfg.InsecureSkipVerify])

			if cfg.OutputFile != "" {
				fmt.Printf(" Output File: %s (Format: %s)\n", cfg.OutputFile, cfg.OutputFormat)
			} else {
				fmt.Printf(" Output: stdout (Format: %s)\n", cfg.OutputFormat)
			}
			fmt.Printf(" Log Level: %s (Verbosity Level: %d)\n", cfg.Verbosity, cfg.VerbosityLevel)
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

		findings := scheduler.StartScan() 

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
	defaults := config.GetDefaultConfig()

	// Input
	rootCmd.PersistentFlags().StringP("input", "i", defaults.Input, "Input: URL, comma-separated URLs, or path to a file with URLs (one per line)")

	// Headers
	rootCmd.PersistentFlags().String("headers-file", defaults.HeadersFile, "Path to the file of headers to test (default: wordlists/headers.txt in standard locations)")
	rootCmd.PersistentFlags().StringSliceP("header", "H", defaults.CustomHeaders, "Custom HTTP header to add to requests (can be specified multiple times, format: \"Name: Value\")")

	// Output
	rootCmd.PersistentFlags().StringP("output-file", "o", defaults.OutputFile, "Path to file for saving results (default: stdout)")
	rootCmd.PersistentFlags().String("output-format", defaults.OutputFormat, "Output format: json or text")

	// Concurrency & Performance
	rootCmd.PersistentFlags().IntP("concurrency", "c", defaults.Concurrency, "Number of concurrent workers")
	rootCmd.PersistentFlags().IntP("timeout", "t", int(defaults.RequestTimeout.Seconds()), "HTTP request timeout in seconds")
	rootCmd.PersistentFlags().IntP("max-retries", "r", defaults.MaxRetries, "Maximum number of retries per request")
	rootCmd.PersistentFlags().Float64P("rate-limit", "l", 0.0, "Max requests per second per domain (0 for auto-adjustment)")

	// Security & Verbosity
	rootCmd.PersistentFlags().Bool("insecure", defaults.InsecureSkipVerify, "Disable TLS certificate verification")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose (debug level 1) logging")
	rootCmd.PersistentFlags().Bool("vverbose", false, "Enable very verbose (debug level 2) logging (use as -vv)") // Cobra typically handles -vv by Count("v"), this is an alternative
	rootCmd.PersistentFlags().Bool("no-color", defaults.NoColor, "Disable colors in text output")
	rootCmd.PersistentFlags().Bool("silent", defaults.Silent, "Suppress all logs except fatal errors and final results (findings)")

	// Proxy
	rootCmd.PersistentFlags().String("proxy", defaults.ProxyInput, "Proxy to use (URL, CSV list, or file path)")

	// Removed flags (placeholders for user information, not to be re-added without discussion):
	// --targets, -t (replaced by --input, -i)
	// --targets-file, -f (replaced by --input, -i)
	// --verbosity, -V (replaced by -v, -vv, --silent)
	// --payloads (internal logic now)
	// --payload-prefix (internal logic now)
	// --delay (internal logic now, part of RPS)
	// --initial-rps (internal logic now)
	// --min-rps (internal logic now)
	// --max-rps (replaced by --rate-limit, -l)
	// --initial-standby (internal logic now)
	// --max-standby (internal logic now)
	// --standby-increment (internal logic now) - This one was not explicitly removed by user, but falls into internal rate control logic
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		// Logger might not be initialized here if error is from Cobra parsing itself pre-PersistentPreRunE
		// So, fmt.Fprintf to stderr is appropriate.
		fmt.Fprintf(os.Stderr, "Error executing hemlock: %v\n", err)
		os.Exit(1)
	}
} 