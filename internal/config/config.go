package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
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
	Verbosity            string // String representation from CLI/Viper (e.g., "debug", "info")
	VerbosityLevel       int    // Integer representation (0: normal, 1: -v, 2: -vv)
	ProxyInput           string // Raw input for proxies (URL, list, or file path)
	ParsedProxies        []ProxyEntry
	HeadersFile          string // Path to a file containing additional headers to test
	TargetsFile          string // Path to a file containing target URLs
	MaxRetries           int    // Maximum number of retries per request
	CustomHeaders        []string // Custom HTTP headers to add to every request (format: "Name: Value")
	UserAgent            string   // User-Agent still needed for default if no -H "User-Agent: ..." is provided
	NoColor              bool     // To disable colored output
	Silent               bool     // To suppress non-critical logs

	// New fields for dynamic rate limiting and standby
	InitialTargetRPS         float64       `mapstructure:"initial-target-rps"`
	MinTargetRPS             float64       `mapstructure:"min-target-rps"`
	MaxTargetRPS             float64       `mapstructure:"max-target-rps"`
	InitialStandbyDuration   time.Duration `mapstructure:"initial-standby-duration"`
	MaxStandbyDuration       time.Duration `mapstructure:"max-standby-duration"`
	StandbyDurationIncrement time.Duration `mapstructure:"standby-duration-increment"`

	// New fields for unified input
	Input string // New: For unified input -i, --input

	// New field for insecure skip verify
	InsecureSkipVerify bool // New: For --insecure flag
}

// ProxyEntry holds the parsed information for a single proxy.
type ProxyEntry struct {
	URL      string // Full proxy URL, e.g., http://user:pass@host:port
	Scheme   string // http, https, socks5, etc.
	Host     string // host:port
	Username string // Optional
	Password string // Optional
}

// String method for ProxyEntry to construct the full proxy URL string.
// This is useful for http.Transport.Proxy.
func (p *ProxyEntry) String() string {
	if p.URL != "" { // If a full URL is already provided, use it (e.g. by ParseProxyInput)
		// Optionally, re-parse and re-build if username/password might need to be injected
		// into a p.URL that doesn't already have them, but for now, assume p.URL is authoritative if set.
		u, err := url.Parse(p.URL)
		if err == nil {
			if p.Username != "" || p.Password != "" {
				u.User = url.UserPassword(p.Username, p.Password)
				return u.String()
			}
			return p.URL // Return original p.URL if no user/pass to inject or already there
		}
		// If p.URL is set but malformed (should not happen if ParseProxyInput is robust), fall through or log. 
	}
	
	// Fallback or alternative construction if p.URL is not set but Scheme/Host are
	if p.Scheme != "" && p.Host != "" {
		var u url.URL
		u.Scheme = p.Scheme
		u.Host = p.Host
		if p.Username != "" || p.Password != "" {
			u.User = url.UserPassword(p.Username, p.Password)
		}
		return u.String()
	}
	return p.URL // Default to p.URL if other parts are missing
}

// Valores padrão para RPS se não especificados ou se MaxTargetRPS (flag -l) for 0.
const (
	DefaultInitialRPS       float64 = 5.0
	DefaultMinRPS           float64 = 5.0  // Mínimo de 5 req/s como solicitado
	DefaultMaxInternalRPS   float64 = 30.0 // Máximo de 30 req/s se -l 0 ou não especificado
	DefaultSuccessThreshold int     = 10   // Aumentar RPS a cada N sucessos
	DefaultRPSIncrement     float64 = 1.0  // Quanto aumentar o RPS
)

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
		Verbosity:            "info",   // Default string verbosity
		VerbosityLevel:       0,        // Default int verbosity (0 = normal/info)
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		ProxyInput:           "",
		ParsedProxies:        []ProxyEntry{},
		HeadersFile:          "", // Will be set by flag or default in main.go
		TargetsFile:          "",
		MaxRetries:           3,    // Default of 3 retries
		CustomHeaders:        []string{},
		NoColor:              false,
		Silent:               false,

		// Defaults for new fields
		InitialTargetRPS:         1.0,
		MinTargetRPS:             0.5,
		MaxTargetRPS:             10.0,
		InitialStandbyDuration:   1 * time.Minute,
		MaxStandbyDuration:       5 * time.Minute,
		StandbyDurationIncrement: 1 * time.Minute,

		// Defaults for new fields for unified input
		Input: "", // Default for new input flag

		// Defaults for new field for insecure skip verify
		InsecureSkipVerify: false, // Default for new --insecure flag
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
	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") { // Skip empty lines and comments
			cleanedLines = append(cleanedLines, trimmedLine)
		}
	}
	return cleanedLines, nil
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
	if c.UserAgent == "" { // Still validate UserAgent as it's a field, though mainly set by default
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
	if c.InitialTargetRPS <= 0 {
		return fmt.Errorf("initialTargetRPS must be positive")
	}
	if c.MinTargetRPS <= 0 {
		return fmt.Errorf("minTargetRPS must be positive")
	}
	if c.MaxTargetRPS < c.MinTargetRPS {
		return fmt.Errorf("maxTargetRPS (%.2f) must be greater than or equal to minTargetRPS (%.2f)", c.MaxTargetRPS, c.MinTargetRPS)
	}
	if c.InitialTargetRPS > c.MaxTargetRPS {
		return fmt.Errorf("initialTargetRPS (%.2f) must not exceed maxTargetRPS (%.2f)", c.InitialTargetRPS, c.MaxTargetRPS)
	}
	if c.InitialStandbyDuration <= 0 {
		return fmt.Errorf("initialStandbyDuration must be positive")
	}
	if c.MaxStandbyDuration < c.InitialStandbyDuration {
		return fmt.Errorf("maxStandbyDuration must be greater than or equal to initialStandbyDuration")
	}
	if c.StandbyDurationIncrement <= 0 {
		return fmt.Errorf("standbyDurationIncrement must be positive")
	}
	if c.MaxTargetRPS < 0 {
		return fmt.Errorf("rate-limit (MaxTargetRPS) cannot be negative")
	}

	// Validate output format
	validFormats := map[string]bool{"text": true, "json": true}
	if _, ok := validFormats[strings.ToLower(c.OutputFormat)]; !ok {
		return fmt.Errorf("invalid output format: %s. Must be 'text' or 'json'", c.OutputFormat)
	}

	return nil
}

// String (Config method) remains useful for debugging.
func (c *Config) String() string {
	return fmt.Sprintf("UserAgent: %s, Timeout: %s, Concurrency: %d, Targets: %v, HeadersToTest (count): %d, ProxyInput: '%s', Verbosity: %s (Level: %d), MaxRetries: %d, InitialRPS: %.2f, MaxRPS: %.2f",
		c.UserAgent, c.RequestTimeout.String(), c.Concurrency, c.Targets, len(c.HeadersToTest), c.ProxyInput, c.Verbosity, c.VerbosityLevel, c.MaxRetries, c.InitialTargetRPS, c.MaxTargetRPS)
} 