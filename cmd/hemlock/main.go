package main

import (
	"flag"
	// "context" // Removed as unused
	// "fmt" // Removed as unused
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/core"
	"github.com/rafabd1/Hemlock/internal/input"
	"github.com/rafabd1/Hemlock/internal/networking"
	"github.com/rafabd1/Hemlock/internal/report"
	"github.com/rafabd1/Hemlock/internal/utils"
	// "github.com/spf13/viper" // Placeholder for Viper integration
)

var (
	configFile = flag.String("config", "", "Path to config file (e.g., config.yaml). If empty, uses default config and environment variables.")
	targetsFile = flag.String("targets", "", "File containing target URLs, one per line.")
	useStdin = flag.Bool("stdin", false, "Read target URLs from stdin.")
	outputFile = flag.String("output", "", "File to save the report (e.g., report.json). Default is stdout.")
	outputFormat = flag.String("format", "text", "Report format (text, json, csv).")
	logLevel = flag.String("loglevel", "info", "Log level (debug, info, warn, error, fatal).")
	numWorkers = flag.Int("workers", 10, "Number of concurrent workers.")
)

func main() {
	flag.Parse()

	appConfig := loadConfig()
	logger := utils.NewDefaultLogger(appConfig.Log.GetLogLevel())

	logger.Infof("Hemlock Cache Poisoning Detection Tool Initializing...")
	logger.Debugf("Using User-Agent: %s", appConfig.Network.UserAgent)
	if len(appConfig.Proxies) > 0 {
		logger.Infof("Using %d proxies.", len(appConfig.Proxies))
	}

	domainManager := networking.NewDomainManager(appConfig.Network, logger)
	logger.Debugf("DomainManager initialized with MinRequestDelay: %dms, Cooldown: %dms", appConfig.Network.MinRequestDelayMs, appConfig.Network.DomainCooldownMs)

	clientConfig := networking.ClientConfig{
		Timeout:           time.Duration(appConfig.Network.TimeoutSeconds) * time.Second,
		MaxRetries:        appConfig.Network.MaxRetries,
		UserAgent:         appConfig.Network.UserAgent,
		Proxies:           appConfig.Proxies,
		InsecureSkipVerify: appConfig.Network.InsecureSkipVerify,
	}
	httpClient, err := networking.NewClient(clientConfig, domainManager, logger)
	if err != nil {
		logger.Fatalf("Error creating HTTP client: %v", err)
	}
	logger.Debugf("HTTP Client initialized with timeout: %s, max retries: %d", clientConfig.Timeout, clientConfig.MaxRetries)

	urls, err := readTargets(appConfig, logger)
	if err != nil {
		logger.Fatalf("Error reading targets: %v", err)
	}
	if len(urls) == 0 {
		logger.Fatalf("No target URLs provided.")
	}
	logger.Infof("Loaded %d target URLs.", len(urls))

	processor := core.NewProcessor(appConfig, logger)
	logger.Debugf("Processor initialized.")

	scheduler, err := core.NewScheduler(appConfig, httpClient, domainManager, processor, logger)
	if err != nil {
		logger.Fatalf("Error creating scheduler: %v", err)
	}
	logger.Debugf("Scheduler initialized.")

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Warnf("Interrupt signal received. Shutting down gracefully...")
		scheduler.Shutdown() // This will also cancel the context for ongoing operations
	}()

	defer scheduler.Shutdown() // Ensure shutdown is called on normal exit or panic

	reporter := report.NewReporter() // TODO: Pass appConfig.Report and logger to NewReporter if needed
	var findings []report.Finding
	var errorsEncountered int

	logger.Infof("Starting scan...")
	resultsChannel := scheduler.Schedule(urls)

	for result := range resultsChannel { // This loop will break when resultsChannel is closed by the scheduler
		if result.Error != nil {
			logger.Errorf("Error scanning URL %s: %v", result.URL, result.Error)
			errorsEncountered++
		}
		if result.Finding != nil {
			logger.Infof("Vulnerability found for URL %s: %s", result.URL, result.Finding.Vulnerability)
			findings = append(findings, *result.Finding)
			reporter.AddFinding(*result.Finding) // Assuming AddFinding stores or prints directly for now
		}
	}

	logger.Infof("Scan finished. Found %d vulnerabilities. Encountered %d errors during scans.", len(findings), errorsEncountered)

	if err := reporter.GenerateReport(findings, appConfig.Report.OutputFile, appConfig.Report.Format);
	err != nil {
		logger.Fatalf("Error generating report: %v", err)
	}
	logger.Infof("Report generated to %s in %s format.", appConfig.Report.OutputFile, appConfig.Report.Format)

	logger.Infof("Hemlock finished.")
}

// loadConfig simulates loading configuration. Viper would replace this.
// It prioritizes command-line flags, then config file (not yet implemented), then defaults.
func loadConfig() *config.Config {
	cfg := config.DefaultConfig()

	// Override defaults with command-line flags where provided
	if *logLevel != "" {
		cfg.Log.Level = *logLevel
	}
	if *outputFile != "" {
		cfg.Report.OutputFile = *outputFile
	}
	if *outputFormat != "" {
		cfg.Report.Format = *outputFormat
	}
	if *numWorkers > 0 {
		cfg.Workers.NumWorkers = *numWorkers
	}
    if *targetsFile != "" {
        cfg.Input.TargetsFile = *targetsFile
        cfg.Input.Stdin = false // Explicit file overrides stdin from default
    }
    if *useStdin {
        cfg.Input.Stdin = true
        cfg.Input.TargetsFile = "" // Stdin overrides file from default
    }

	// TODO: Implement Viper loading from file (*configFile)
	// if *configFile != "" { ... viper.SetConfigFile(*configFile) ... viper.ReadInConfig() ... viper.Unmarshal(cfg) ... }

	// TODO: Viper can also automatically bind environment variables.

	return cfg
}

// readTargets centralizes the logic for reading target URLs
func readTargets(appConfig *config.Config, logger utils.Logger) ([]string, error) {
	var urls []string
	var err error
	inputReader := input.NewReader()

	// Priority: -stdin flag, then -targets flag, then command line args, then config file stdin, then config file targetsFile
	if *useStdin {
		logger.Infof("Reading target URLs from stdin...")
		urls, err = inputReader.ReadURLsFromStdin()
	} else if *targetsFile != "" {
		logger.Infof("Reading target URLs from file specified by -targets flag: %s", *targetsFile)
		urls, err = inputReader.ReadURLsFromFile(*targetsFile)
	} else if len(flag.Args()) > 0 {
		// If non-flag arguments are present, treat them as URLs or a single file path
		if len(flag.Args()) == 1 {
			// Could be a single URL or a file. Let's try as file first if it looks like one, then as URL.
			// For simplicity now, assume if one arg, it's a file (as per previous logic)
			fi, statErr := os.Stat(flag.Arg(0))
			if statErr == nil && !fi.IsDir() {
				logger.Infof("Reading target URLs from file provided as argument: %s", flag.Arg(0))
				urls, err = inputReader.ReadURLsFromFile(flag.Arg(0))
			} else {
				logger.Infof("Treating command line arguments as direct URLs.")
				urls = flag.Args() // Treat as list of URLs
			}
		} else {
			logger.Infof("Treating command line arguments as direct URLs.")
			urls = flag.Args()
		}
	} else if appConfig.Input.Stdin { // Check config if no flags/args for stdin
		logger.Infof("Reading target URLs from stdin (as per config)...")
		urls, err = inputReader.ReadURLsFromStdin()
	} else if appConfig.Input.TargetsFile != "" { // Check config for file path
		logger.Infof("Reading target URLs from file specified in config: %s", appConfig.Input.TargetsFile)
		urls, err = inputReader.ReadURLsFromFile(appConfig.Input.TargetsFile)
	}
	return urls, err
} 