package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultHeadersFilePath = "wordlists/headers.txt"

// fallbackHeaders are used if the defaultHeadersFilePath cannot be read.
var fallbackHeaders = []string{
	"X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Proto",
	"X-Host", "True-Client-IP", "X-Client-IP", "Referer", "X-Forwarded-For",
	"X-Real-IP", "Forwarded", "User-Agent",
}

// Config holds all the configuration for the Hemlock scanner.
type Config struct {
	Targets              []string      `yaml:"targets"`               // List of target URLs or file paths containing URLs
	HeadersToTest        []string      `yaml:"headersToTest"`       // List of HTTP headers to test for injection
	BasePayloads         []string      `yaml:"basePayloads"`        // Optional base payloads to use with GenerateUniquePayload
	DefaultPayloadPrefix string        `yaml:"defaultPayloadPrefix"` // Prefix for auto-generated payloads if BasePayloads is empty
	Concurrency          int           `yaml:"concurrency"`         // Number of concurrent workers
	RequestTimeout       time.Duration `yaml:"requestTimeout"`      // Timeout for individual HTTP requests
	OutputFile           string        `yaml:"outputFile"`          // Path to the output file for findings
	OutputFormat         string        `yaml:"outputFormat"`        // Output format (e.g., "json", "text", "csv")
	Verbosity            string        `yaml:"verbosity"`           // Log level (e.g., "debug", "info", "warn", "error")
	UserAgent            string        `yaml:"userAgent"`           // Custom User-Agent string
	ProxyURL             string        `yaml:"proxyUrl"`            // Proxy URL (e.g., http://127.0.0.1:8080)
	HeadersFile          string        `yaml:"headersFile"`         // Path to a file containing additional headers to test (one per line)
	TargetsFile          string        `yaml:"targetsFile"`         // Path to a file containing target URLs (one per line)
	MinRequestDelayMs    int           `yaml:"minRequestDelayMs"`   // Minimum delay in milliseconds between requests to the same domain
	DomainCooldownMs     int           `yaml:"domainCooldownMs"`    // Cooldown period in milliseconds for a domain after being blocked
}

// getDefaultConfig provides a basic configuration with sensible defaults.
// It now attempts to load headers from defaultHeadersFilePath.
func getDefaultConfig() *Config {
	defaultHdrs, err := LoadLinesFromFile(defaultHeadersFilePath)
	if err != nil {
		log.Printf("WARN: Could not load default headers from '%s': %v. Using fallback list.", defaultHeadersFilePath, err)
		defaultHdrs = fallbackHeaders
	}
	if len(defaultHdrs) == 0 { // Should not happen with fallback, but as a safeguard
		log.Printf("WARN: Default header list is empty even after fallback. Using minimal fallback.")
		defaultHdrs = fallbackHeaders
	}

	return &Config{
		Targets:              []string{},
		HeadersToTest:        defaultHdrs, // Initialized with headers from file or fallback
		BasePayloads:         []string{},
		DefaultPayloadPrefix: "hemlock",
		Concurrency:          10,
		RequestTimeout:       10 * time.Second,
		OutputFile:           "hemlock_findings.json",
		OutputFormat:         "json",
		Verbosity:            "info",
		UserAgent:            "Hemlock Cache Scanner/0.1",
		ProxyURL:             "",
		HeadersFile:          "", // This will be used to ADD to the default/fallback list if specified in YAML
		TargetsFile:          "",
		MinRequestDelayMs:    500,
		DomainCooldownMs:     300000,
	}
}

// LoadConfig loads configuration from a specified YAML file path.
func LoadConfig(filePath string) (*Config, error) {
	cfg := getDefaultConfig() // Starts with defaults, including headers from wordlists/headers.txt or fallback

	var yamlCfg Config // Temporary struct to unmarshal YAML into

	if filePath != "" {
		yamlFile, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file '%s': %w", filePath, err)
		}
		// Unmarshal into the temporary struct to avoid overwriting defaults immediately
		err = yaml.Unmarshal(yamlFile, &yamlCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal YAML from '%s': %w", filePath, err)
		}

		// Apply non-empty/non-zero values from yamlCfg to cfg, selectively
		if len(yamlCfg.Targets) > 0 { cfg.Targets = yamlCfg.Targets }
		// Headers logic: if HeadersToTest is set in YAML, it overrides everything.
		// If HeadersFile is set in YAML, its contents are ADDED to the current HeadersToTest (from default file/fallback).
		if len(yamlCfg.HeadersToTest) > 0 {
			cfg.HeadersToTest = yamlCfg.HeadersToTest // YAML HeadersToTest takes precedence and overwrites
			cfg.HeadersFile = "" // Nullify HeadersFile if HeadersToTest is explicitly set in YAML
		} else if yamlCfg.HeadersFile != "" {
			cfg.HeadersFile = yamlCfg.HeadersFile // Keep the path for loading below
		}

		if len(yamlCfg.BasePayloads) > 0 { cfg.BasePayloads = yamlCfg.BasePayloads }
		if yamlCfg.DefaultPayloadPrefix != "" { cfg.DefaultPayloadPrefix = yamlCfg.DefaultPayloadPrefix }
		if yamlCfg.Concurrency > 0 { cfg.Concurrency = yamlCfg.Concurrency }
		if yamlCfg.RequestTimeout > 0 { cfg.RequestTimeout = yamlCfg.RequestTimeout }
		if yamlCfg.OutputFile != "" { cfg.OutputFile = yamlCfg.OutputFile }
		if yamlCfg.OutputFormat != "" { cfg.OutputFormat = yamlCfg.OutputFormat }
		if yamlCfg.Verbosity != "" { cfg.Verbosity = yamlCfg.Verbosity }
		if yamlCfg.UserAgent != "" { cfg.UserAgent = yamlCfg.UserAgent }
		if yamlCfg.ProxyURL != "" { cfg.ProxyURL = yamlCfg.ProxyURL }
		// TargetsFile from YAML is handled below, as it appends.
		if yamlCfg.TargetsFile != "" { cfg.TargetsFile = yamlCfg.TargetsFile }
		if yamlCfg.MinRequestDelayMs > 0 { cfg.MinRequestDelayMs = yamlCfg.MinRequestDelayMs }
		if yamlCfg.DomainCooldownMs > 0 { cfg.DomainCooldownMs = yamlCfg.DomainCooldownMs }
	}

	// Load targets from TargetsFile if specified (either by default or by YAML)
	if cfg.TargetsFile != "" {
		fileTargets, err := LoadLinesFromFile(cfg.TargetsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load targets from file '%s': %w", cfg.TargetsFile, err)
		}
		cfg.Targets = append(cfg.Targets, fileTargets...)
	}

	// Load additional headers from HeadersFile if specified (and not overridden by YAML's HeadersToTest)
	if cfg.HeadersFile != "" { // This condition means HeadersToTest was NOT set in YAML, but HeadersFile was.
		fileHeaders, err := LoadLinesFromFile(cfg.HeadersFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load additional headers from file '%s': %w", cfg.HeadersFile, err)
		}
		cfg.HeadersToTest = append(cfg.HeadersToTest, fileHeaders...)
	}

	// Deduplicate targets and headers
	cfg.Targets = deduplicateStringSlice(cfg.Targets)
	cfg.HeadersToTest = deduplicateStringSlice(cfg.HeadersToTest)

	// Final check: ensure there are headers to test
	if len(cfg.HeadersToTest) == 0 {
		log.Println("WARN: HeadersToTest list is empty after all loading attempts. Using minimal fallback headers.")
		cfg.HeadersToTest = fallbackHeaders
	}

	return cfg, nil
}

// LoadLinesFromFile reads a file and returns its lines as a slice of strings.
// It is now exported for use by other packages (e.g., main.go for -targets-file).
func LoadLinesFromFile(filePath string) ([]string, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var result []string
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			result = append(result, trimmedLine)
		}
	}
	return result, nil
}

// deduplicateStringSlice removes duplicate strings from a slice.
func deduplicateStringSlice(s []string) []string {
	seen := make(map[string]struct{})
	result := []string{}
	for _, item := range s {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// GetUserConfigDir returns the default directory to store user-specific config files.
func GetUserConfigDir() (string, error) {
	return os.UserConfigDir()
}

// GetUserHomeDir returns the current user's home directory.
func GetUserHomeDir() (string, error) {
	return os.UserHomeDir()
}

// Validate checks the configuration for any invalid settings.
func (c *Config) Validate() error {
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("requestTimeout must be positive")
	}
	if c.Concurrency <= 0 {
		return fmt.Errorf("concurrency must be positive")
	}
	if c.DefaultPayloadPrefix == "" {
		return fmt.Errorf("defaultPayloadPrefix cannot be empty")
	}
	if c.OutputFormat == "" {
		return fmt.Errorf("outputFormat cannot be empty")
	}
	if c.Verbosity == "" {
		return fmt.Errorf("verbosity cannot be empty")
	}
	if c.UserAgent == "" {
		return fmt.Errorf("userAgent cannot be empty")
	}
	if c.ProxyURL == "" {
		return fmt.Errorf("proxyUrl cannot be empty")
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("targets cannot be empty")
	}
	if len(c.HeadersToTest) == 0 {
		return fmt.Errorf("headersToTest cannot be empty")
	}
	return nil
}

// String returns a string representation of the Config (careful with sensitive data).
func (c *Config) String() string {
	// Basic string representation, can be expanded. Be cautious about logging sensitive info.
	return fmt.Sprintf("UserAgent: %s, Timeout: %ds, Concurrency: %d, Targets: %v",
		c.UserAgent, c.RequestTimeout, c.Concurrency, c.Targets)
} 