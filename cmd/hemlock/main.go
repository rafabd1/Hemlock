package main

import (
	"fmt"
	"net/url"
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
		vp := viper.New()
		vp.SetEnvPrefix("HEMLOCK")
		vp.AutomaticEnv()
		vp.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

		if err := vp.BindPFlags(cmd.PersistentFlags()); err != nil {
			return fmt.Errorf("error binding persistent flags to viper: %w", err)
		}
		if err := vp.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("error binding local flags to viper: %w", err)
		}

		cfg = *config.GetDefaultConfig()

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
		cfg.ProbeConcurrency = vp.GetInt("probes")

		// Lógica de verbosidade revisada
		verbosityCount, _ := cmd.Flags().GetCount("verbose") // Usar GetCount diretamente do cmd.Flags()

		if cfg.Silent {
			cfg.VerbosityLevel = -1
			cfg.Verbosity = "fatal"
		} else {
			cfg.VerbosityLevel = verbosityCount
			switch verbosityCount {
			case 0:
				cfg.Verbosity = "info"
			case 1:
				cfg.Verbosity = "debug"
			default: // >= 2
				cfg.Verbosity = "debug"
				// Se VerbosityLevel for 2 ou mais, o logger usará isso para mostrar mais detalhes
				// mantendo a string "debug" para o tipo de log.
			}
		}

		// Initialize Logger (after verbosity, noColor and silent are set)
		logLevel := utils.StringToLogLevel(cfg.Verbosity) // cfg.Verbosity string ainda é usada aqui
		logger = utils.NewDefaultLogger(logLevel, cfg.NoColor, cfg.Silent) 
		// No futuro, NewDefaultLogger poderia aceitar cfg.VerbosityLevel diretamente
		// para um controle mais granular se "trace" etc., fossem adicionados.

		// --- Process Input (-i, --input) ---
		if cfg.Input != "" {
			// Check if input is a file path
			if _, err := os.Stat(cfg.Input); err == nil {
				// Input is a file, load targets from it
				logger.Debugf("Input '%s' detected as a file. Reading targets from file.", cfg.Input)
				fileTargets, errLoad := config.LoadLinesFromFile(cfg.Input)
				if errLoad != nil {
					logger.Errorf("Error reading targets from input file '%s': %v", cfg.Input, errLoad)
					return fmt.Errorf("error reading targets from input file '%s': %w", cfg.Input, errLoad)
				}
				cfg.Targets = fileTargets
				cfg.TargetsFile = cfg.Input // Store the fact it came from a file for logging consistency
			} else {
				// Input is not a file, treat as comma-separated list or single URL
				logger.Debugf("Input '%s' detected as URL(s).", cfg.Input)
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

		logger.Debugf("Using headers from: %s", cfg.HeadersFile)
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
		// Define ANSI color codes directly here for the banner
		const colorGreenForBanner = "\033[32m"
		const colorResetForBanner = "\033[0m"

		// 1. Display Banner (somente se não estiver no modo silencioso)
		if !cfg.Silent {
			banner := `
   _    _                _            _    
  | |  | |              | |          | |   
  | |__| | ___ _ __ ___ | | ___   ___| | __
  |  __  |/ _ \ '_ ` + "`" + ` _ \| |/ _ \ / __| |/ /
  | |  | |  __/ | | | | | | (_) | (__|   < 
  |_|  |_|\___|_| |_| |_|_|\___/ \___|_|\_\
`
			version := "v0.1.2" // Atualizar conforme necessário
			author := "github.com/rafabd1"

			// Apply color to the banner string
			coloredBanner := banner
			if !cfg.NoColor {
				coloredBanner = colorGreenForBanner + banner + colorResetForBanner
			}
			fmt.Printf("%s\n", coloredBanner)
			fmt.Printf("\t\t\tWeb Cache Poisoning Scanner | %s by %s\n\n", version, author)
		}
		
		// 2. Validar configuração (após o banner, antes de mais logs)
		if err := cfg.Validate(); err != nil {
			logger.Fatalf("Invalid configuration: %v", err)
		}
		if len(cfg.Targets) == 0 {
			logger.Fatalf("No targets specified. Use --input or -i to provide a URL, list of URLs, or a file path.")
		}
		if len(cfg.HeadersToTest) == 0 {
			logger.Fatalf("No headers to test were loaded. Check --headers-file or the default file location.")
	    }

		// Log sobre a origem dos alvos
		if cfg.TargetsFile != "" {
			logger.Infof("Targets: Loaded %d URLs from file: %s", len(cfg.Targets), cfg.TargetsFile)
		} else {
			logger.Infof("Targets: %d URL(s) provided via direct input argument.", len(cfg.Targets))
		}
		// Log sobre a origem dos headers (já existia um similar, vamos garantir que esteja no formato e local corretos)
		// O log logger.Infof("Using headers from: %s", cfg.HeadersFile) foi movido para Debugf em PersistentPreRunE
		// Adicionamos um aqui mais conciso e focado no que foi carregado, não no processo de encontrar.
		logger.Infof("Headers: %d loaded to test from: '%s'", len(cfg.HeadersToTest), cfg.HeadersFile)

		// 3. Log de Configuração Essencial (Formato SecretHound)
		rateLimitStr := fmt.Sprintf("%.2f req/s per domain", cfg.MaxTargetRPS)
		if cfg.MaxTargetRPS == 0 {
			rateLimitStr = fmt.Sprintf("Auto (Initial: %.2f, Min: %.2f, Max Default: %.2f req/s per domain)", cfg.InitialTargetRPS, cfg.MinTargetRPS, config.DefaultMaxInternalRPS)
		}
		logger.Infof("HTTP config: %s timeout | %d max retries | %s", cfg.RequestTimeout, cfg.MaxRetries, rateLimitStr)
		logger.Infof("Concurrency: %d workers | Headers: %d loaded from '%s'", cfg.Concurrency, len(cfg.HeadersToTest), cfg.HeadersFile)

		if cfg.OutputFile != "" {
			logger.Infof("Output: Results will be saved to %s (Format: %s)", cfg.OutputFile, cfg.OutputFormat)
		} else {
			logger.Infof("Output: Results to stdout (Format: %s)", cfg.OutputFormat)
		}

		if cfg.InsecureSkipVerify {
			logger.Infof("SSL/TLS certificate verification disabled")
		}
		if len(cfg.ParsedProxies) > 0 {
		    logger.Infof("Proxies: %d configured", len(cfg.ParsedProxies))
		}

		// 4. Processamento de URLs e Geração de Jobs
		// Pre-process URLs for initial logging
		// We only need uniqueBaseURLs here for logging purposes.
		// The scheduler will perform its own full preprocessing.
		// Capturamos totalParamsFound e numURLsWithParams para o log.
		_, uniqueBaseURLs, totalParamsFound, numURLsWithParams := utils.PreprocessAndGroupURLs(cfg.Targets, logger)
		// No error is returned by PreprocessAndGroupURLs; it logs errors internally.

		// Calculate numUniqueDomains from uniqueBaseURLs
		numUniqueDomains := 0
		if len(uniqueBaseURLs) > 0 {
			domainSet := make(map[string]struct{})
			for _, baseURL := range uniqueBaseURLs {
				u, errParseURL := url.Parse(baseURL)
				if errParseURL == nil {
					domainSet[u.Hostname()] = struct{}{}
	} else {
					// Log a warning if a base URL cannot be parsed, though this should be rare
					// if PreprocessAndGroupURLs produced it.
					logger.Warnf("Could not parse base URL '%s' from preprocessed list to count domain: %v", baseURL, errParseURL)
				}
			}
			numUniqueDomains = len(domainSet)
		}

		if len(uniqueBaseURLs) == 0 {
			logger.Fatalf("No processable URLs after pre-processing. Check your target list and filters.")
		}
		logger.Infof("Processing %d unique target URLs across %d domains.", len(uniqueBaseURLs), numUniqueDomains)

		if totalParamsFound > 0 && numURLsWithParams > 0 {
			logger.Infof("Parameters: Extracted %d total unique query parameters from %d URLs.", totalParamsFound, numURLsWithParams)
		}

		// 5. Inicializar Serviços e Iniciar Scan
		logger.Infof("Hemlock Cache Scanner initializing scan...")

		httpClient, errClient := networking.NewClient(&cfg, logger)
	if errClient != nil {
		logger.Fatalf("Failed to create HTTP client: %v", errClient)
	}

		processor := core.NewProcessor(&cfg, logger)
		domainManager := networking.NewDomainManager(&cfg, logger)
		scheduler := core.NewScheduler(&cfg, httpClient, processor, domainManager, logger)

	findings := scheduler.StartScan() 

		logger.Infof("Scan completed. Found %d potential vulnerabilities.", len(findings))
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
		} else if len(findings) > 0 {
			logger.Infof("Report generated successfully.")
	} else {
		    logger.Infof("No vulnerabilities found or report not generated due to no findings.")
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
	rootCmd.PersistentFlags().IntP("concurrency", "c", defaults.Concurrency, "Number of concurrent workers (overall URL processing)")
	rootCmd.PersistentFlags().IntP("probes", "p", defaults.ProbeConcurrency, "Number of concurrent probes (e.g., header/param tests) per URL")
	rootCmd.PersistentFlags().IntP("timeout", "t", int(defaults.RequestTimeout.Seconds()), "HTTP request timeout in seconds")
	rootCmd.PersistentFlags().IntP("max-retries", "r", defaults.MaxRetries, "Maximum number of retries per request")
	rootCmd.PersistentFlags().Float64P("rate-limit", "l", 0.0, "Max requests per second per domain (0 for auto-adjustment)")

	// Security & Verbosity
	rootCmd.PersistentFlags().Bool("insecure", defaults.InsecureSkipVerify, "Disable TLS certificate verification")
	rootCmd.PersistentFlags().CountP("verbose", "v", "Verbosity level (-v for debug, -vv for more debug)")
	rootCmd.PersistentFlags().Bool("no-color", defaults.NoColor, "Disable colors in text output")
	rootCmd.PersistentFlags().Bool("silent", defaults.Silent, "Suppress all logs except fatal errors and final results (findings)")

	// Proxy
	rootCmd.PersistentFlags().String("proxy", defaults.ProxyInput, "Proxy to use (URL, CSV list, or file path)")

	// Adicionar descrição para a nova flag de probes
	if err := rootCmd.PersistentFlags().SetAnnotation("probes", "description", []string{"Number of concurrent probes (e.g., header/param tests) per URL"}); err != nil {
		// Não usar logger aqui pois ele pode não estar inicializado ainda em init()
		fmt.Fprintf(os.Stderr, "Warning: Failed to set description for probes flag: %v\n", err)
	}
	// Atualizar descrição para a flag de verbosidade (verbose count)
	if err := rootCmd.PersistentFlags().SetAnnotation("verbose", "description", []string{"Verbosity level (-v for debug, -vv for more debug)"}); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to set description for verbose flag: %v\n", err)
	}

	if err := viper.ReadInConfig(); err == nil {
		// ... existing code ...
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		// Logger might not be initialized here if error is from Cobra parsing itself pre-PersistentPreRunE
		// So, fmt.Fprintf to stderr is appropriate.
		fmt.Fprintf(os.Stderr, "Error executing hemlock: %v\n", err)
		os.Exit(1)
	}
} 