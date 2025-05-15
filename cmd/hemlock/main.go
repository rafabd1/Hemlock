package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	Short: "Hemlock é uma ferramenta para detectar Web Cache Poisoning.",
	Long: `Hemlock - Scanner de Vulnerabilidades de Web Cache Poisoning.

Analisa URLs para identificar potenciais vulnerabilidades de envenenamento de cache
via headers HTTP não chaveados e parâmetros de URL.
Usa técnicas de probing para verificar se payloads injetados são refletidos e cacheados.
`,
	Example: `  # Scan de um único alvo com verbosidade debug e output em arquivo JSON:
  hemlock -t http://example.com -V debug -o results.json

  # Scan de múltiplos alvos (separados por vírgula) com 50 workers concorrentes:
  hemlock --targets "http://site1.com,https://site2.org" -c 50

  # Scan de alvos de um arquivo, usando um arquivo de headers customizado e proxy:
  hemlock --targets-file /path/to/targets.txt --headers-file /path/to/my_headers.txt --proxy http://localhost:8080

  # Scan silencioso, apenas mostrando erros fatais e o relatório final em texto:
  hemlock -t http://vulnerable.site --silent --output-format text

  # Scan com User-Agent específico e timeout de 20 segundos:
  hemlock -t http://test.com --user-agent "MyCustomScanner/1.0" -T 20s`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Inicializar Viper para ler configs, env vars, e flags
		vp := viper.New()
		vp.SetEnvPrefix("HEMLOCK")
		vp.AutomaticEnv()
		vp.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

		// Vincular todas as flags persistentes ao Viper
		if err := vp.BindPFlags(cmd.PersistentFlags()); err != nil {
			return fmt.Errorf("erro ao vincular flags persistentes ao viper: %w", err)
		}
		// Vincular todas as flags locais (se houver comandos filhos) ao Viper
		if err := vp.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("erro ao vincular flags locais ao viper: %w", err)
		}

		// Popular a struct cfg com os valores do Viper
		cfg = *config.GetDefaultConfig() // Começa com defaults codificados

		// String arrays from Viper
		if vp.IsSet("targets") { cfg.Targets = vp.GetStringSlice("targets") }
		if vp.IsSet("payloads") { cfg.BasePayloads = vp.GetStringSlice("payloads") }
		
		cfg.DefaultPayloadPrefix = vp.GetString("payload-prefix")
		cfg.Concurrency = vp.GetInt("concurrency")
		cfg.RequestTimeout = vp.GetDuration("timeout")
		cfg.OutputFile = vp.GetString("output-file")
		cfg.OutputFormat = vp.GetString("output-format")
		cfg.Verbosity = vp.GetString("verbosity")
		cfg.UserAgent = vp.GetString("user-agent")
		cfg.ProxyInput = vp.GetString("proxy")
		cfg.HeadersFile = vp.GetString("headers-file")
		cfg.TargetsFile = vp.GetString("targets-file")
		cfg.MinRequestDelayMs = vp.GetInt("min-delay")
		cfg.DomainCooldownMs = vp.GetInt("cooldown")
		cfg.NoColor = vp.GetBool("no-color")
		cfg.Silent = vp.GetBool("silent")

		// Lógica especial para -v (verbose) que afeta verbosity
		if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
			cfg.Verbosity = "debug"
		}

		// Inicializar Logger (após verbosity, noColor e silent serem definidos)
		logLevel := utils.StringToLogLevel(cfg.Verbosity)
		logger = utils.NewDefaultLogger(logLevel, cfg.NoColor, cfg.Silent)
		
		// Carregar targets de --targets-file se especificado (tem precedência sobre --targets)
		if cfg.TargetsFile != "" {
			logger.Infof("Lendo alvos do arquivo especificado por --targets-file: %s", cfg.TargetsFile)
			fileTargets, err := config.LoadLinesFromFile(cfg.TargetsFile)
			if err != nil {
				return fmt.Errorf("erro ao ler alvos do arquivo '%s': %w", cfg.TargetsFile, err)
			}
			cfg.Targets = fileTargets
		} else if len(cfg.Targets) > 0 { // Se --targets foi usado e não --targets-file
		    // Se targets veio como uma string única do viper (ex: de env var), splitar
		    // Se já é slice (de flag que aceita múltiplas vezes ou lista CSV), está ok
		    // Cobra/Viper geralmente lida bem com StringSliceP, então pode já ser um slice.
		    // Mas se for uma string única com vírgulas, pode precisar de split.
		    // Por segurança, se for um slice de 1 elemento que contém vírgulas, splitar.
		    if len(cfg.Targets) == 1 && strings.Contains(cfg.Targets[0], ",") {
		        cfg.Targets = strings.Split(cfg.Targets[0], ",")
		    }
		    for i := range cfg.Targets {
			    cfg.Targets[i] = strings.TrimSpace(cfg.Targets[i])
		    }
		}

		// Carregar HeadersToTest
		if cfg.HeadersFile == "" { // Se --headers-file não foi fornecido, tentar caminhos padrão
			exePath, err := os.Executable()
			if err != nil {
				logger.Warnf("Não foi possível obter o caminho do executável: %v", err)
			}
			potentialPaths := []string{
				filepath.Join(defaultWordlistDir, defaultHeadersFilename),                               // ./wordlists/headers.txt
				filepath.Join(filepath.Dir(exePath), defaultWordlistDir, defaultHeadersFilename),      // <exe_dir>/wordlists/headers.txt
				filepath.Join(filepath.Dir(exePath), "..", defaultWordlistDir, defaultHeadersFilename), // <exe_dir>/../wordlists/headers.txt (para dev)
				// Adicionar outros caminhos padrão de instalação aqui se necessário (ex: /usr/local/share/...)
			}
			foundPath := ""
			for _, p := range potentialPaths {
				if _, err := os.Stat(p); err == nil {
					cfg.HeadersFile = p
					foundPath = p
					logger.Debugf("Arquivo de headers padrão encontrado em: %s", p)
					break
				}
			}
			if foundPath == "" {
				return fmt.Errorf("arquivo de headers padrão ('%s') não encontrado nos locais padrão e --headers-file não especificado. Este arquivo é essencial.", defaultHeadersFilename)
			}
		} // else cfg.HeadersFile foi fornecido pela flag

		logger.Infof("Carregando headers de: %s", cfg.HeadersFile)
		loadedHeaders, err := config.LoadLinesFromFile(cfg.HeadersFile)
		if err != nil {
			return fmt.Errorf("erro ao carregar headers de '%s': %w", cfg.HeadersFile, err)
		}
		if len(loadedHeaders) == 0 {
			return fmt.Errorf("o arquivo de headers '%s' está vazio.", cfg.HeadersFile)
		}
		cfg.HeadersToTest = loadedHeaders

		// Parse ProxyInput
		if cfg.ProxyInput != "" {
			parsedPx, errPx := utils.ParseProxyInput(cfg.ProxyInput, logger)
			if errPx != nil {
				logger.Warnf("Erro ao parsear proxy input '%s': %v. Continuando sem proxies deste input.", cfg.ProxyInput, errPx)
				cfg.ParsedProxies = []config.ProxyEntry{}
			} else {
				cfg.ParsedProxies = parsedPx
			}
		} else {
			cfg.ParsedProxies = []config.ProxyEntry{}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.Infof("Hemlock Cache Scanner iniciando...")
		logger.Debugf("Configuração Efetiva: %s", cfg.String())

		if len(cfg.Targets) == 0 {
			logger.Fatalf("Nenhum alvo especificado. Use --targets ou --targets-file.")
		}
		if len(cfg.HeadersToTest) == 0 {
			logger.Fatalf("Nenhum header para testar foi carregado. Verifique --headers-file ou o arquivo padrão.")
		}

		var firstProxyURL string
		if len(cfg.ParsedProxies) > 0 {
			proxyEntry := cfg.ParsedProxies[0]
			firstProxyURL = proxyEntry.String()
			logger.Debugf("Usando primeiro proxy parseado para cliente HTTP: %s", firstProxyURL)
		}

		httpClient, errClient := networking.NewClient(cfg.RequestTimeout, cfg.UserAgent, firstProxyURL, logger)
		if errClient != nil {
			logger.Fatalf("Falha ao criar cliente HTTP: %v", errClient)
		}
		logger.Debugf("Cliente HTTP inicializado.")

		processor := core.NewProcessor(&cfg, logger)
		logger.Debugf("Processador inicializado.")

		// Inicializar DomainManager
		domainManager := networking.NewDomainManager(&cfg, logger)
		logger.Debugf("DomainManager inicializado.")

		// Passar domainManager para o NewScheduler
		scheduler := core.NewScheduler(&cfg, httpClient, processor, domainManager, logger)
		logger.Debugf("Scheduler inicializado.")

		logger.Infof("Iniciando scan para %d alvo(s)...", len(cfg.Targets))
		findings := scheduler.StartScan()

		logger.Infof("Scan finalizado. Gerando relatório para %d achados...", len(findings))
		errReport := report.GenerateReport(findings, cfg.OutputFile, cfg.OutputFormat)
		if errReport != nil {
			logger.Errorf("Falha ao gerar relatório: %v", errReport)
			if cfg.OutputFile != "" && (strings.ToLower(cfg.OutputFormat) == "text" || strings.ToLower(cfg.OutputFormat) == "json") {
				logger.Warnf("Tentando imprimir relatório para stdout como fallback...")
				fbErr := report.GenerateReport(findings, "", cfg.OutputFormat)
				if fbErr != nil {
					logger.Errorf("Fallback para stdout também falhou: %v", fbErr)
				}
			}
		} else {
			logger.Infof("Relatório gerado com sucesso.")
		}

		logger.Infof("Hemlock Cache Scanner finalizado.")
		return nil
	},
}

func init() {
	// Configuração do Viper para defaults
	defaults := config.GetDefaultConfig()
	vp := viper.New() // Usar uma instância local para definir defaults, não a global do Viper

	vp.SetDefault("payload-prefix", defaults.DefaultPayloadPrefix)
	vp.SetDefault("concurrency", defaults.Concurrency)
	vp.SetDefault("timeout", defaults.RequestTimeout) // Viper lida com time.Duration
	vp.SetDefault("output-format", defaults.OutputFormat)
	vp.SetDefault("verbosity", defaults.Verbosity)
	vp.SetDefault("user-agent", defaults.UserAgent)
	vp.SetDefault("min-delay", defaults.MinRequestDelayMs)
	vp.SetDefault("cooldown", defaults.DomainCooldownMs)
	vp.SetDefault("no-color", defaults.NoColor)
	vp.SetDefault("silent", defaults.Silent)
	// Para campos que não têm um "zero value" útil (como strings vazias para paths):
	vp.SetDefault("output-file", defaults.OutputFile)     // Default é ""
	vp.SetDefault("proxy", defaults.ProxyInput)             // Default é ""
	vp.SetDefault("headers-file", defaults.HeadersFile)   // Default é ""
	vp.SetDefault("targets-file", defaults.TargetsFile)   // Default é ""
	// Viper.SetDefault para slices como "targets" e "payloads" pode ser um pouco tricky se eles podem vir de múltiplas fontes.
	// Geralmente, para flags que podem ser repetidas ou são CSV, Cobra as parseia em slices diretamente.
	// Viper as lerá como tal se vinculadas. Definir default como slice vazio é seguro.
	vp.SetDefault("targets", []string{})
	vp.SetDefault("payloads", []string{})

	// Flags Persistentes (disponíveis para o comando raiz e qualquer subcomando)
	rootCmd.PersistentFlags().StringSliceP("targets", "t", vp.GetStringSlice("targets"), "Lista de URLs alvo separadas por vírgula (ex: http://host1,http://host2)")
	rootCmd.PersistentFlags().StringP("targets-file", "f", vp.GetString("targets-file"), "Caminho para um arquivo contendo URLs alvo (uma por linha)")
	// Alias -tf para targets-file, Cobra não suporta alias nativo para flags, então definimos duas flags que fazem a mesma coisa e a lógica em PreRun lida com isso.
	// Ou podemos apenas documentar -f como short.

	rootCmd.PersistentFlags().String("headers-file", vp.GetString("headers-file"), "Caminho para o arquivo de headers a testar (default: wordlists/headers.txt em locais padrão)")
	rootCmd.PersistentFlags().StringSlice("payloads", vp.GetStringSlice("payloads"), "Lista de payloads base para usar (separados por vírgula)")
	rootCmd.PersistentFlags().String("payload-prefix", vp.GetString("payload-prefix"), "Prefixo para payloads gerados automaticamente se a lista de payloads base estiver vazia")

	rootCmd.PersistentFlags().StringP("output-file", "o", vp.GetString("output-file"), "Caminho do arquivo para salvar os resultados (default: stdout)")
	rootCmd.PersistentFlags().String("output-format", vp.GetString("output-format"), "Formato da saída: json ou text")

	rootCmd.PersistentFlags().StringP("verbosity", "V", vp.GetString("verbosity"), "Nível de log: debug, info, warn, error, fatal")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Atalho para --verbosity debug") // Flag booleana separada para -v

	rootCmd.PersistentFlags().IntP("concurrency", "c", vp.GetInt("concurrency"), "Número de workers concorrentes")
	rootCmd.PersistentFlags().DurationP("timeout", "T", vp.GetDuration("timeout"), "Timeout para requisições HTTP (ex: 10s, 1m)")
	rootCmd.PersistentFlags().String("user-agent", vp.GetString("user-agent"), "User-Agent customizado para as requisições")
	rootCmd.PersistentFlags().String("proxy", vp.GetString("proxy"), "Proxy para usar (URL, lista CSV ou path de arquivo)")

	rootCmd.PersistentFlags().Int("min-delay", vp.GetInt("min-delay"), "Atraso mínimo em ms entre requisições para o mesmo domínio")
	rootCmd.PersistentFlags().Int("cooldown", vp.GetInt("cooldown"), "Período de cooldown em ms para um domínio após ser bloqueado")

	rootCmd.PersistentFlags().Bool("no-color", vp.GetBool("no-color"), "Desabilitar cores na saída de texto")
	rootCmd.PersistentFlags().Bool("silent", vp.GetBool("silent"), "Suprimir todos os logs exceto resultados finais (achados)")

	// Vincular as flags definidas acima ao Viper (para que Viper possa ler os valores das flags)
	// Isso é feito no PersistentPreRunE para garantir que a instância correta do viper (vp local ao comando) seja usada.
	// No entanto, a documentação do Viper sugere fazer isso no init() se possível.
	// A questão é que as flags são definidas em rootCmd.PersistentFlags(), e precisamos dessa referência.
	// A abordagem de BindPFlags no PreRun é mais segura para garantir que estamos vinculando ao conjunto correto de flags.
	// Ou, alternativamente, podemos passar vp do init para PreRun, mas isso é mais complicado.
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Erro ao executar hemlock: %v\n", err)
		os.Exit(1)
	}
} 