package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/core"
	"github.com/rafabd1/Hemlock/internal/networking"
	"github.com/rafabd1/Hemlock/internal/report"
	"github.com/rafabd1/Hemlock/internal/utils"
)

// Variables to be set by CLI flags
var (
	configFile     string
	targetsCLI     string // Comma-separated list of targets
	targetsFileCLI string // Path to a file containing target URLs
	outputFileCLI  string
	outputFormatCLI string
	verbosityCLI   string
	concurrencyCLI int
	verboseFlag    bool // For -v
)

func init() {
	flag.StringVar(&configFile, "config", "", "Path to the YAML configuration file. If not provided, defaults and other CLI flags are used.")
	flag.StringVar(&targetsCLI, "targets", "", "Comma-separated target URLs (overrides config file). E.g., http://host1,http://host2")
	flag.StringVar(&targetsFileCLI, "targets-file", "", "Path to a file containing target URLs (one per line, overrides -targets and config file targets).")
	flag.StringVar(&targetsFileCLI, "tf", "", "Short for -targets-file.") // Alias
	flag.StringVar(&outputFileCLI, "output-file", "", "Output file path (overrides config file). E.g., findings.json")
	flag.StringVar(&outputFormatCLI, "output-format", "", "Output format: json or text (overrides config file). E.g., json")
	flag.StringVar(&verbosityCLI, "verbosity", "", "Log level: debug, info, warn, error, fatal (overrides config file or -v). E.g., debug")
	flag.IntVar(&concurrencyCLI, "concurrency", 0, "Number of concurrent workers (overrides config file). E.g., 20")
	flag.BoolVar(&verboseFlag, "v", false, "Enable verbose (debug) logging. Equivalent to -verbosity debug.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Hemlock Cache Scanner - Uncover Web Cache Poisoning Vulnerabilities\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -config hemlock_config.yaml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -targets http://example.com,http://test.com -verbosity debug\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -tf /path/to/targets.txt -v -output-format text\n", os.Args[0])
	}
}

func main() {
	flag.Parse()

	// 1. Load Configuration
	cfg, err := config.LoadConfig(configFile) 
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during configuration loading: %v\n", err)
		os.Exit(1)
	}

	// Override config with CLI flags if they were provided
	// Note: -targets-file (targetsFileCLI) takes precedence over -targets (targetsCLI)
	// and both override targets from the config file.
	if targetsFileCLI != "" {
		loggerForFileOps := utils.NewDefaultLogger(utils.LevelInfo) // Temporary logger for this operation
		loggerForFileOps.Infof("Reading targets from file specified by -targets-file/-tf: %s", targetsFileCLI)
		fileTargets, err := config.LoadLinesFromFile(targetsFileCLI) // Using existing helper from config pkg
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading targets from file '%s': %v\n", targetsFileCLI, err)
			os.Exit(1)
		}
		cfg.Targets = fileTargets // Override completely with file targets
	} else if targetsCLI != "" {
		cfg.Targets = strings.Split(targetsCLI, ",")
		for i := range cfg.Targets {
			cfg.Targets[i] = strings.TrimSpace(cfg.Targets[i])
		}
	}

	if outputFileCLI != "" {
		cfg.OutputFile = outputFileCLI
	}
	if outputFormatCLI != "" {
		cfg.OutputFormat = outputFormatCLI
	}
	// Handle verbosity: -v sets to debug, -verbosity can override
	if verboseFlag && verbosityCLI == "" { // If -v is set and -verbosity is not, set to debug
		cfg.Verbosity = "debug"
	} else if verbosityCLI != "" { // If -verbosity is set, it takes precedence
		cfg.Verbosity = verbosityCLI
	}
	if concurrencyCLI > 0 {
		cfg.Concurrency = concurrencyCLI
	}

	// 2. Initialize Logger (after potential verbosity override from CLI)
	logLevel := utils.StringToLogLevel(cfg.Verbosity)
	logger := utils.NewDefaultLogger(logLevel)

	logger.Infof("Hemlock Cache Scanner starting...")
	if configFile != "" {
		logger.Infof("Using configuration file: %s", configFile)
	} else {
		logger.Infof("No configuration file specified, using defaults and/or CLI arguments.")
	}
	logger.Debugf("Effective Configuration:")
	logger.Debugf("  Targets: %v", cfg.Targets)
	logger.Debugf("  HeadersToTest (count): %d", len(cfg.HeadersToTest)) 
	// logger.Debugf("  HeadersToTest: %v", cfg.HeadersToTest) // Avoid logging potentially huge list
	logger.Debugf("  Concurrency: %d", cfg.Concurrency)
	logger.Debugf("  RequestTimeout: %s", cfg.RequestTimeout)
	logger.Debugf("  OutputFile: %s", cfg.OutputFile)
	logger.Debugf("  OutputFormat: %s", cfg.OutputFormat)
	logger.Debugf("  Verbosity: %s (parsed as %v)", cfg.Verbosity, logLevel)
	logger.Debugf("  UserAgent: %s", cfg.UserAgent)
	logger.Debugf("  ProxyURL: '%s'", cfg.ProxyURL)
	logger.Debugf("  MinRequestDelayMs: %dms", cfg.MinRequestDelayMs)
	logger.Debugf("  DomainCooldownMs: %dms", cfg.DomainCooldownMs)


	// Basic validation after logger is initialized and CLI overrides applied
	if len(cfg.Targets) == 0 {
		logger.Fatalf("No targets specified. Please provide targets via config file or CLI arguments (-targets or -targets-file).")
	}

	// 3. Initialize HTTP Client
	httpClient, errClient := networking.NewClient(cfg.RequestTimeout, cfg.UserAgent, cfg.ProxyURL, logger)
	if errClient != nil {
		logger.Fatalf("Failed to create HTTP client: %v", errClient)
	}
	logger.Debugf("HTTP Client initialized.") 

	// 4. Initialize Processor
	processor := core.NewProcessor(cfg, logger) 
	logger.Debugf("Processor initialized.")

	// 5. Initialize Scheduler
	scheduler := core.NewScheduler(cfg, httpClient, processor, logger)
	logger.Debugf("Scheduler initialized.")

	// 6. Start Scan
	logger.Infof("Starting scan for %d target(s) with %d header(s) each...", len(cfg.Targets), len(cfg.HeadersToTest))
	findings := scheduler.StartScan() 

	// 7. Generate Report
	logger.Infof("Scan finished. Generating report for %d findings...", len(findings))
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

	// 8. Log completion
	logger.Infof("Hemlock Cache Scanner finished.")
} 