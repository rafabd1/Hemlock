package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

// const defaultHeadersFilePath = "wordlists/headers.txt"   // Removido - Não mais utilizado aqui

// Config holds all the configuration for the Hemlock scanner.
// Fields will be populated by Viper from flags and defaults.
// YAML tags are removed as there will be no direct YAML loading to this struct here.
type Config struct {
	Targets              []string
	HeadersToTest        []string
	BasePayloads         []string
	DefaultPayloadPrefix string
	Concurrency          int
	RequestTimeout       time.Duration
	OutputFile           string
	OutputFormat         string
	Verbosity            string
	UserAgent            string
	ProxyInput           string // Raw input for proxies (URL, list, or file path)
	ParsedProxies        []ProxyEntry
	HeadersFile          string // Path to a file containing additional headers to test
	TargetsFile          string // Path to a file containing target URLs
	MinRequestDelayMs    int
	DomainCooldownMs     int
	MaxRetries           int    // Maximum number of retries per request
	RetryDelayBaseMs     int    // Base delay for exponential backoff in ms
	RetryDelayMaxMs      int    // Maximum delay for backoff in ms
	MaxConsecutiveFailuresToBlock int    // Number of consecutive network failures to block a domain
	CustomHeaders        []string // Custom HTTP headers to add to every request (format: "Name: Value")
	// New flags/options can be added here and managed by Viper
	NoColor bool // To disable colored output
	Silent  bool // To suppress non-critical logs
}

// ProxyEntry holds the parsed components of a proxy string.
type ProxyEntry struct {
	Scheme   string
	Host     string
	Port     string
	User     string
	Password string
}

// String returns the proxy URL string representation.
// Omits user/pass if not present. Defaults to http scheme if not present.
func (pe *ProxyEntry) String() string {
	userInfo := ""
	if pe.User != "" {
		userInfo = pe.User
		if pe.Password != "" {
			userInfo += ":" + pe.Password
		}
		userInfo += "@"
	}
	schemeToUse := pe.Scheme
	if schemeToUse == "" {
		schemeToUse = "http" // Default to http if scheme is empty
	}
	return fmt.Sprintf("%s://%s%s:%s", schemeToUse, userInfo, pe.Host, pe.Port)
}

// GetDefaultConfig returns a Config struct populated with default values.
// Viper in main.go will set these defaults and override them with flags.
func GetDefaultConfig() *Config {
	return &Config{
		Targets:              []string{},
		HeadersToTest:        []string{}, // Will be filled in main.go after loading headersFile
		BasePayloads:         []string{},
		DefaultPayloadPrefix: "hemlock",
		Concurrency:          10,
		RequestTimeout:       10 * time.Second,
		OutputFile:           "",       // No output file by default
		OutputFormat:         "json",   // Default to JSON
		Verbosity:            "info",   // Default verbosity
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		ProxyInput:           "",
		ParsedProxies:        []ProxyEntry{},
		HeadersFile:          "", // Will be set by flag or default in main.go
		TargetsFile:          "",
		MinRequestDelayMs:    500,
		DomainCooldownMs:     60000, // Changed from 300000ms (5 min) to 60000ms (1 min)
		MaxRetries:           3,    // Default of 3 retries
		RetryDelayBaseMs:     200,  // Default of 200ms for base delay
		RetryDelayMaxMs:      5000, // Default of 5000ms (5s) for max delay
		MaxConsecutiveFailuresToBlock: 3,    // Default to 3 consecutive failures
		CustomHeaders:        []string{},
		NoColor:              false,
		Silent:               false,
	}
}

// LoadConfig is now a stub. Configuration will be loaded and managed
// primarily by Viper and Cobra in cmd/hemlock/main.go.
// This function can be used to initialize with defaults if needed before Viper,
// or removed entirely if Viper handles all defaults.
// For now, it just returns the hardcoded defaults.
func LoadConfig(userConfigFilePath string /* parameter no longer used */) (*Config, error) {
	if userConfigFilePath != "" {
		// Logic to load user YAML has been removed.
		// Could log a warning that config file flag is no longer supported if it's used.
		log.Printf("WARN: Configuration via YAML file ('%s') is deprecated and no longer supported. Please use CLI flags.", userConfigFilePath)
	}
	// Logic to load hemlock_default_config.yaml has been removed.
	// Logic to load HeadersToTest from here has been removed - will be done in main.go.
	cfg := GetDefaultConfig()
	return cfg, nil
}

// LoadLinesFromFile is still useful for loading targets/headers from files specified by flags.
func LoadLinesFromFile(filePath string) ([]string, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var result []string
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") { // Ignore comments and empty lines
			result = append(result, trimmedLine)
		}
	}
	return result, nil
}

// deduplicateStringSlice is still useful.
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

// GetUserConfigDir e GetUserHomeDir podem não ser mais relevantes se não há config de usuário.
// Removê-las-ei por enquanto para simplificar.
/*
func GetUserConfigDir() (string, error) {
	return os.UserConfigDir()
}

func GetUserHomeDir() (string, error) {
	return os.UserHomeDir()
}
*/

// Validate is still useful for validating the Config struct after being populated by Viper.
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
	if len(c.Targets) == 0 {
		return fmt.Errorf("targets cannot be empty")
	}
	if len(c.HeadersToTest) == 0 {
		return fmt.Errorf("headersToTest cannot be empty")
	}
	if c.MaxRetries < 0 {
		return fmt.Errorf("maxRetries cannot be negative")
	}
	if c.RetryDelayBaseMs < 0 {
		return fmt.Errorf("retryDelayBaseMs cannot be negative")
	}
	if c.RetryDelayMaxMs < 0 {
		return fmt.Errorf("retryDelayMaxMs cannot be negative")
	}
	if c.RetryDelayBaseMs > c.RetryDelayMaxMs && c.RetryDelayMaxMs > 0 { // Only if MaxMs is not unlimited (0)
		return fmt.Errorf("retryDelayBaseMs (%d) cannot be greater than retryDelayMaxMs (%d)", c.RetryDelayBaseMs, c.RetryDelayMaxMs)
	}
	if c.MaxConsecutiveFailuresToBlock < 0 { // 0 can mean disabled, but not negative
		return fmt.Errorf("maxConsecutiveFailuresToBlock cannot be negative")
	}
	return nil
}

// String (Config method) remains useful for debugging.
func (c *Config) String() string {
	return fmt.Sprintf("UserAgent: %s, Timeout: %s, Concurrency: %d, Targets: %v, HeadersToTest (count): %d, ProxyInput: '%s', Verbosity: %s, MaxRetries: %d, RetryDelayBaseMs: %d, RetryDelayMaxMs: %d, MaxConsecutiveFailuresToBlock: %d, CustomHeaders (count): %d",
		c.UserAgent, c.RequestTimeout.String(), c.Concurrency, c.Targets, len(c.HeadersToTest), c.ProxyInput, c.Verbosity, c.MaxRetries, c.RetryDelayBaseMs, c.RetryDelayMaxMs, c.MaxConsecutiveFailuresToBlock, len(c.CustomHeaders))
} 