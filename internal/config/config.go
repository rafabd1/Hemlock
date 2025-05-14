package config

import (
	// "github.com/rafabd1/Hemlock/internal/networking" // Removed to break import cycle
	"github.com/rafabd1/Hemlock/internal/utils"
)

// Config é a estrutura principal para todas as configurações da aplicação.
// Ela será populada pelo Viper a partir de um arquivo de configuração, variáveis de ambiente e/ou flags de linha de comando.
type Config struct {
	Log      LogConfig               `mapstructure:"log"`
	Network  NetworkingConfig        `mapstructure:"network"`
	Input    InputConfig             `mapstructure:"input"`
	Report   ReportConfig            `mapstructure:"report"`
	Workers  WorkerPoolConfig        `mapstructure:"workers"`
	Headers  HeaderConfig            `mapstructure:"headers"`
	Proxies  []string                `mapstructure:"proxies"`
}

// LogConfig contém configurações para o logger.
type LogConfig struct {
	Level      string `mapstructure:"level"`
	OutputFile string `mapstructure:"output_file"`
}

// NetworkingConfig contém configurações para o cliente HTTP e gerenciamento de domínio.
// Note: networking.ClientConfig is now constructed directly in main.go or a similar package.
type NetworkingConfig struct {
	UserAgent          string        `mapstructure:"user_agent"`
	TimeoutSeconds     int           `mapstructure:"timeout_seconds"`
	MaxRetries         int           `mapstructure:"max_retries"`
	InsecureSkipVerify bool          `mapstructure:"insecure_skip_verify"`
	MinRequestDelayMs  int           `mapstructure:"min_request_delay_ms"`
	DomainCooldownMs   int           `mapstructure:"domain_cooldown_ms"`
}

// InputConfig contém configurações para a entrada de URLs.
type InputConfig struct {
	TargetsFile string   `mapstructure:"targets_file"`
	Stdin       bool     `mapstructure:"stdin"`
}

// ReportConfig contém configurações para a geração de relatórios.
type ReportConfig struct {
	OutputFile string `mapstructure:"output_file"`
	Format     string `mapstructure:"format"`
}

// WorkerPoolConfig contém configurações para o pool de workers.
type WorkerPoolConfig struct {
	NumWorkers    int `mapstructure:"num_workers"`
	JobQueueSize  int `mapstructure:"job_queue_size"`
}

// HeaderConfig contém configurações para as wordlists de headers.
type HeaderConfig struct {
	WordlistFile string `mapstructure:"wordlist_file"`
}

// GetLogLevel converte o nível de log de string para utils.LogLevel.
func (lc *LogConfig) GetLogLevel() utils.LogLevel {
	switch lc.Level {
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
		return utils.LevelInfo
	}
}

// DefaultConfig retorna uma configuração com valores padrão.
func DefaultConfig() *Config {
	return &Config{
		Log: LogConfig{
			Level: "info",
		},
		Network: NetworkingConfig{
			UserAgent:      "Hemlock Cache Poisoning Scanner",
			TimeoutSeconds: 10,
			MaxRetries:     3,
			InsecureSkipVerify: false,
			MinRequestDelayMs: 200,
			DomainCooldownMs:  300000, // 5 minutes
		},
		Input: InputConfig{
			Stdin: true,
		},
		Report: ReportConfig{
			Format: "text",
		},
		Workers: WorkerPoolConfig{
			NumWorkers:   10,
			JobQueueSize: 100,
		},
		Headers: HeaderConfig{
			WordlistFile: "wordlists/headers.txt",
		},
		Proxies: []string{},
	}
} 