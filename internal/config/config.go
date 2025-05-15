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
// YAML tags são removidas pois não haverá mais loading direto de YAML para esta struct aqui.
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
	MaxRetries           int    // Número máximo de retentativas por requisição
	RetryDelayBaseMs     int    // Delay base para backoff exponencial em ms
	RetryDelayMaxMs      int    // Delay máximo para backoff em ms
	MaxConsecutiveFailuresToBlock int    // Novo: Número de falhas de rede consecutivas para bloquear um domínio
	// Novas flags/opções podem ser adicionadas aqui e gerenciadas pelo Viper
	NoColor bool // Para desabilitar output colorido
	Silent  bool // Para suprimir logs não críticos
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
// Viper em main.go definirá estes defaults e os sobrescreverá com flags.
func GetDefaultConfig() *Config {
	return &Config{
		Targets:              []string{},
		HeadersToTest:        []string{}, // Será preenchido em main.go após carregar headersFile
		BasePayloads:         []string{},
		DefaultPayloadPrefix: "hemlock",
		Concurrency:          10,
		RequestTimeout:       10 * time.Second,
		OutputFile:           "",       // Sem output file por padrão
		OutputFormat:         "json",   // Default para JSON
		Verbosity:            "info",   // Default verbosity
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		ProxyInput:           "",
		ParsedProxies:        []ProxyEntry{},
		HeadersFile:          "", // Será definido por flag ou default em main.go
		TargetsFile:          "",
		MinRequestDelayMs:    500,
		DomainCooldownMs:     300000,
		MaxRetries:           3,    // Default de 3 retentativas
		RetryDelayBaseMs:     200,  // Default de 200ms para delay base
		RetryDelayMaxMs:      5000, // Default de 5000ms (5s) para delay máximo
		MaxConsecutiveFailuresToBlock: 3,    // Default para 3 falhas consecutivas
		NoColor:              false,
		Silent:               false,
	}
}

// LoadConfig é agora um stub. A configuração será carregada e gerenciada
// primariamente por Viper e Cobra em cmd/hemlock/main.go.
// Esta função pode ser usada para inicializar com defaults se necessário antes do Viper,
// ou totalmente removida se o Viper cuidar de todos os defaults.
// Por ora, ela apenas retorna os defaults codificados.
func LoadConfig(userConfigFilePath string /* parâmetro não mais usado */) (*Config, error) {
	if userConfigFilePath != "" {
		// Logica de carregar YAML de usuário foi removida.
		// Poderia logar um aviso que a flag de config file não é mais suportada se ela for usada.
		log.Printf("WARN: Configuration via YAML file ('%s') is deprecated and no longer supported. Please use CLI flags.", userConfigFilePath)
	}
	// A lógica de carregar hemlock_default_config.yaml também foi removida.
	// A lógica de carregar HeadersToTest daqui também foi removida - será feita em main.go.
	cfg := GetDefaultConfig()
	return cfg, nil
}

// LoadLinesFromFile continua útil para carregar targets/headers de arquivos especificados por flags.
func LoadLinesFromFile(filePath string) ([]string, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var result []string
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") { // Ignora comentários e linhas vazias
			result = append(result, trimmedLine)
		}
	}
	return result, nil
}

// deduplicateStringSlice continua útil.
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

// Validate continua útil para validar a struct Config após ser populada pelo Viper.
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
	if c.MaxConsecutiveFailuresToBlock < 0 { // 0 pode significar desabilitado, mas não negativo
		return fmt.Errorf("maxConsecutiveFailuresToBlock cannot be negative")
	}
	return nil
}

// String (método de Config) permanece útil para debugging.
func (c *Config) String() string {
	return fmt.Sprintf("UserAgent: %s, Timeout: %s, Concurrency: %d, Targets: %v, HeadersToTest (count): %d, ProxyInput: '%s', Verbosity: %s, MaxRetries: %d, RetryDelayBaseMs: %d, RetryDelayMaxMs: %d, MaxConsecutiveFailuresToBlock: %d",
		c.UserAgent, c.RequestTimeout.String(), c.Concurrency, c.Targets, len(c.HeadersToTest), c.ProxyInput, c.Verbosity, c.MaxRetries, c.RetryDelayBaseMs, c.RetryDelayMaxMs, c.MaxConsecutiveFailuresToBlock)
} 