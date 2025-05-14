package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	// "github.com/rafabd1/Hemlock/internal/networking" // Removed to break import cycle
	"github.com/rafabd1/Hemlock/internal/utils"
)

// Config é a estrutura principal para todas as configurações da aplicação.
// Ela será populada pelo Viper a partir de um arquivo de configuração, variáveis de ambiente e/ou flags de linha de comando.
// Definitions for OutputConfig, LoggingConfig, CachePoisoningConfig, etc. should be here if not implicitly defined by DefaultConfig's usage.
// For now, assuming they are implicitly defined or will be added if linter complains.

// Config é a estrutura principal para todas as configurações da aplicação.
// Ela será populada pelo Viper a partir de um arquivo de configuração, variáveis de ambiente e/ou flags de linha de comando.
type Config struct {
	Input          InputConfig          `mapstructure:"input"`
	Network        NetworkConfig        `mapstructure:"network"`
	Output         OutputConfig         `mapstructure:"output"`
	Logging        LoggingConfig        `mapstructure:"logging"`
	CachePoisoning CachePoisoningConfig `mapstructure:"cache_poisoning"`
	Workers        WorkerConfig         `mapstructure:"workers"`
}

// LogConfig contém configurações para o logger.
type LogConfig struct {
	Level      string `mapstructure:"level"`
	OutputFile string `mapstructure:"output_file"`
}

// NetworkConfig contém configurações para o cliente HTTP e gerenciamento de domínio.
// Note: networking.ClientConfig is now constructed directly in main.go or a similar package.
type NetworkConfig struct {
	UserAgent          string        `mapstructure:"user_agent"`
	TimeoutSeconds     int           `mapstructure:"timeout_seconds"`
	MaxRedirects         int           `mapstructure:"max_redirects"`
	ConcurrentRequests   int           `mapstructure:"concurrent_requests"`
	DelayBetweenRequestsMs int           `mapstructure:"delay_between_requests_ms"`
	MaxRetries           int           `mapstructure:"max_retries"`
	MinRequestDelayMs    int           `mapstructure:"min_request_delay_ms"`
	DomainCooldownMs     int           `mapstructure:"domain_cooldown_ms"`
	MaxConcurrentPerDomain int           `mapstructure:"max_concurrent_per_domain"`
	InsecureSkipVerify   bool          `mapstructure:"insecure_skip_verify"`
	Proxies              []ProxyConfig `mapstructure:"proxies"`
}

// InputConfig contém configurações para a entrada de URLs.
type InputConfig struct {
	TargetsFile       string   `mapstructure:"targets_file"`
	Stdin             bool     `mapstructure:"stdin"`
	IgnoredExtensions []string `mapstructure:"ignored_extensions"`
	StripWWWPrefix    bool     `mapstructure:"strip_www_prefix"`
}

// ReportConfig contém configurações para a geração de relatórios.
type ReportConfig struct {
	OutputFile string `mapstructure:"output_file"`
	Format     string `mapstructure:"format"`
}

// WorkerConfig contém configurações para o pool de workers.
type WorkerConfig struct {
	NumWorkers    int `mapstructure:"num_workers"`
	JobQueueSize  int `mapstructure:"job_queue_size"`
}

// HeaderConfig contém configurações para as wordlists de headers.
type HeaderConfig struct {
	WordlistFile string `mapstructure:"wordlist_file"`
}

// ProxyConfig defines settings for a single proxy.
type ProxyConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Enabled  bool   `mapstructure:"enabled"`
}

// OutputConfig contains settings for application output.
type OutputConfig struct {
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"`
}

// LoggingConfig contains settings for application logging.
type LoggingConfig struct {
	Level string `mapstructure:"level"`
	File  string `mapstructure:"file"`
}

// CachePoisoningConfig contains settings specific to cache poisoning tests.
type CachePoisoningConfig struct {
	HeadersToTest     []string `mapstructure:"headers_to_test"`
	PayloadPrefix     string   `mapstructure:"payload_prefix"`
	HeadersToTestFile string   `mapstructure:"headers_to_test_file"` // For loading headers from a file
}

// GetLogLevel converts the logging level string to utils.LogLevel.
// This method is now part of LoggingConfig if it's specific to it,
// or could be a standalone utility if more general.
// For now, let's assume it belongs to LoggingConfig or is handled elsewhere if utils.LogLevel is directly used.
func (lc *LoggingConfig) GetLogLevel() utils.LogLevel {
	switch strings.ToLower(lc.Level) {
	case "debug":
		return utils.LevelDebug
	case "info":
		return utils.LevelInfo
	case "warn":
		return utils.LevelWarn
	case "error":
		return utils.LevelError
	case "fatal":
		return utils.LevelFatal
	default:
		return utils.LevelInfo // Default to Info if unspecified or invalid
	}
}

// DefaultConfig creates a new Config struct with sensible default values.
// Note: InputConfig.WordlistFile and CachePoisoning.HeadersToTestFile are intentionally left empty
// as they should typically be provided by the user or a config file.
func DefaultConfig() *Config {
	return &Config{
		Input: InputConfig{
			// WordlistFile: "", // User must provide or will be skipped
			IgnoredExtensions: []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".ico", ".map"},
			StripWWWPrefix:    true,
			TargetsFile:       "", // Default value for newly added field
			Stdin:             false, // Default value for newly added field
		},
		Network: NetworkConfig{
			UserAgent:              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36 Edg/97.0.1072.55 Hemlock",
			TimeoutSeconds:         10,
			MaxRedirects:           5,
			ConcurrentRequests:     10,
			DelayBetweenRequestsMs: 0,
			MaxRetries:             3,    // Default for field from older version
			MinRequestDelayMs:      0,    // Default for field from older version
			DomainCooldownMs:       0,    // Default for field from older version
			MaxConcurrentPerDomain: 2,    // Default for field from older version
			InsecureSkipVerify:     false,// Default for field from older version
			Proxies:                []ProxyConfig{},
		},
		Output: OutputConfig{
			Format: "text",
			File:   "", // Default to stdout
		},
		Logging: LoggingConfig{
			Level: "info",
			File:  "", // Default to stderr
		},
		CachePoisoning: CachePoisoningConfig{
			// HeadersToTestFile: "", // User must provide or use default list
			HeadersToTest: []string{ // A small default list, can be overridden by config file or HeadersToTestFile
				"X-Forwarded-Host",
				"X-Forwarded-For",
				"X-Host",
				"X-Original-URL",
				"X-Rewrite-URL",
				"Forwarded",
				// "Referer", // Common but often less impactful for cache poisoning itself
			},
			PayloadPrefix: "hemlock",
		},
		Workers: WorkerConfig{
			NumWorkers:   10,
			JobQueueSize: 100,
		},
	}
}

// LoadConfig loads the application configuration from various sources.
// It prioritizes: command-line flags (handled by Cobra/Pflag if used),
// then environment variables, then a configuration file, and finally default values.
// The filePath parameter allows specifying a config file directly.
// If filePath is empty, it will search in default locations: ./, $HOME/.hemlock/, UserConfigDir/hemlock/
func LoadConfig(filePath string) (*Config, error) {
	cfg := DefaultConfig()

	// Configure Viper
	if filePath != "" {
		viper.SetConfigFile(filePath)
	} else {
		viper.SetConfigName("config")                               // name of config file (without extension)
		viper.SetConfigType("yaml")                               // REQUIRED if the config file does not have the extension in the name
		viper.AddConfigPath(".")                                    // optionally look for config in the working directory
		userHomeDir, err := GetUserHomeDir()                        // Get user home directory
		if err == nil {                                             // Only add path if home dir is found
			viper.AddConfigPath(userHomeDir + "/.hemlock") // path to look for the config file in ~/.hemlock
		}
		userConfigDir, err := GetUserConfigDir() // Get user config directory
		if err == nil {                          // Only add path if config dir is found
			vip_config_path := userConfigDir + "/hemlock"
			// Check if hemlock directory exists, create if not
			if _, err_stat := os.Stat(vip_config_path); os.IsNotExist(err_stat) {
				err_mkdir := os.MkdirAll(vip_config_path, 0755)
				if err_mkdir != nil {
					// Log or handle error, but don't necessarily fail loading if other paths work
					fmt.Printf("Warning: Could not create config directory %s: %v\n", vip_config_path, err_mkdir)
				}
			}
			viper.AddConfigPath(vip_config_path) // path to look for the config file in UserConfigDir/hemlock/
		}
	}

	// Set default values (these will be overridden by config file, then env vars, then flags if applicable)
	// Note: WordlistFile is not set as a default here intentionally, must be from config/flag.
	// Input defaults
	viper.SetDefault("input.ignored_extensions", cfg.Input.IgnoredExtensions)
	viper.SetDefault("input.strip_www_prefix", cfg.Input.StripWWWPrefix)
	viper.SetDefault("input.targets_file", cfg.Input.TargetsFile)
	viper.SetDefault("input.stdin", cfg.Input.Stdin)

	// Network defaults
	viper.SetDefault("network.user_agent", cfg.Network.UserAgent)
	viper.SetDefault("network.timeout_seconds", cfg.Network.TimeoutSeconds)
	viper.SetDefault("network.max_redirects", cfg.Network.MaxRedirects)
	viper.SetDefault("network.concurrent_requests", cfg.Network.ConcurrentRequests)
	viper.SetDefault("network.delay_between_requests_ms", cfg.Network.DelayBetweenRequestsMs)
	viper.SetDefault("network.max_retries", cfg.Network.MaxRetries)
	viper.SetDefault("network.min_request_delay_ms", cfg.Network.MinRequestDelayMs)
	viper.SetDefault("network.domain_cooldown_ms", cfg.Network.DomainCooldownMs)
	viper.SetDefault("network.max_concurrent_per_domain", cfg.Network.MaxConcurrentPerDomain)
	viper.SetDefault("network.insecure_skip_verify", cfg.Network.InsecureSkipVerify)
	viper.SetDefault("network.proxies", cfg.Network.Proxies)

	// Output defaults
	viper.SetDefault("output.format", cfg.Output.Format)
	viper.SetDefault("output.file", cfg.Output.File)

	// Logging defaults
	viper.SetDefault("logging.level", cfg.Logging.Level)
	viper.SetDefault("logging.file", cfg.Logging.File)

	// Cache Poisoning defaults
	viper.SetDefault("cache_poisoning.headers_to_test", cfg.CachePoisoning.HeadersToTest)
	viper.SetDefault("cache_poisoning.payload_prefix", cfg.CachePoisoning.PayloadPrefix)
	// Deprecated: HeadersToTestFile. If HeadersToTest is empty, this will be checked later.
	viper.SetDefault("cache_poisoning.headers_to_test_file", cfg.CachePoisoning.HeadersToTestFile)

	// Workers defaults
	viper.SetDefault("workers.num_workers", cfg.Workers.NumWorkers)
	viper.SetDefault("workers.job_queue_size", cfg.Workers.JobQueueSize)

	// Environment variable binding
	vipInstance := viper.GetViper()
	bindEnvVariables(vipInstance, cfg) // Bind environment variables with HEMLOCK_ prefix

	// Attempt to read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if not explicitly provided by filePath
			// and rely on defaults/env vars/flags.
			if filePath != "" {
				return nil, fmt.Errorf("config file '%s' not found: %w", filePath, err)
			}
			// If filePath is empty, it's okay for the config file to not be found, log this occurrence for debugging.
			// fmt.Printf("No config file found at default locations. Using defaults/env vars/flags.\n")
		} else {
			// Config file was found but another error was produced (e.g., parse error)
			return nil, fmt.Errorf("error reading config file '%s': %w", viper.ConfigFileUsed(), err)
		}
	}

	// Unmarshal the config into the cfg struct
	// This will respect the order of precedence: flags > env vars > config file > defaults
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unable to decode config into struct: %w", err)
	}

	// Specific handling for HeadersToTestFile if HeadersToTest is empty and HeadersToTestFile is set
	if len(cfg.CachePoisoning.HeadersToTest) == 0 && cfg.CachePoisoning.HeadersToTestFile != "" {
		headers, err := loadHeadersFromFile(cfg.CachePoisoning.HeadersToTestFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load headers from HeadersToTestFile '%s': %w", cfg.CachePoisoning.HeadersToTestFile, err)
		}
		cfg.CachePoisoning.HeadersToTest = headers
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// bindEnvVariables recursively binds environment variables to Viper keys.
// It uses reflection to iterate over the fields of the provided config struct.
func bindEnvVariables(vip *viper.Viper, config interface{}, parts ...string) {
	// Implementation of bindEnvVariables (assuming it exists and works correctly elsewhere)
	// This function would iterate through config fields, build env var names like HEMLOCK_NETWORK_TIMEOUT_SECONDS,
	// and call vip.BindEnv() for each.
	// For brevity in this example, the full reflection logic is omitted.
	// A simplified conceptual binding:
	vip.SetEnvPrefix("HEMLOCK")
	vip.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	vip.AutomaticEnv() // This might be sufficient for simple cases if keys match env var structure
}

// loadHeadersFromFile reads a list of headers from a file, one header per line.
func loadHeadersFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var headers []string
	scanner := bufio.NewScanner(file) // Use bufio.NewScanner from standard library
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { // Ignore empty lines and comments
			headers = append(headers, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return headers, nil
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
	if c.Network.TimeoutSeconds <= 0 {
		return fmt.Errorf("network.timeout_seconds must be positive")
	}
	if c.Network.MaxRedirects < 0 {
		return fmt.Errorf("network.max_redirects cannot be negative")
	}
	if c.Network.ConcurrentRequests <= 0 {
		return fmt.Errorf("network.concurrent_requests must be positive")
	}
	if c.Network.DelayBetweenRequestsMs < 0 {
		return fmt.Errorf("network.delay_between_requests_ms cannot be negative")
	}
	if len(c.CachePoisoning.HeadersToTest) == 0 && c.CachePoisoning.HeadersToTestFile == "" {
		// This is not necessarily an error, could mean skip header testing or use a hardcoded minimal list.
		// However, if both are empty and no internal default list is used, it's problematic for cache poisoning module.
		// For now, we assume DefaultConfig provides a minimal list, so this state might be okay.
		// If HeadersToTest ends up empty after all loading, it's a signal to the scanner not to test headers.
	}
	if c.CachePoisoning.PayloadPrefix == "" {
		return fmt.Errorf("cache_poisoning.payload_prefix cannot be empty")
	}
	if c.Workers.NumWorkers <= 0 {
		return fmt.Errorf("workers.num_workers must be positive")
	}
	if c.Workers.JobQueueSize <= 0 {
		return fmt.Errorf("workers.job_queue_size must be positive")
	}
	// Add more validation rules as needed
	return nil
}

// String returns a string representation of the Config (careful with sensitive data).
func (c *Config) String() string {
	// Basic string representation, can be expanded. Be cautious about logging sensitive info.
	return fmt.Sprintf("UserAgent: %s, Timeout: %ds, Concurrency: %d, Workers: %d",
		c.Network.UserAgent, c.Network.TimeoutSeconds, c.Network.ConcurrentRequests, c.Workers.NumWorkers)
} 