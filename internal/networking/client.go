package networking

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/utils"
)

// Client manages HTTP requests and client-specific configurations.
// It's a wrapper around http.Client to include custom logic for Hemlock.
type Client struct {
	httpClient        *http.Client
	userAgent         string
	logger            utils.Logger
	cfg               *config.Config
	currentProxyIndex int
	proxyMutex        sync.Mutex
}

// ClientRequestData holds all necessary data to perform an HTTP request.
// This structure standardizes how requests are made by the client.
type ClientRequestData struct {
	URL           string
	Method        string
	Body          []byte // For POST, PUT, etc.
	CustomHeaders http.Header
}

// ClientResponseData holds the outcome of an HTTP request.
// This includes the HTTP response, body, and any errors encountered.
type ClientResponseData struct {
	Response    *http.Response
	Body        []byte
	RespHeaders http.Header
	Error       error
}

// NewClient creates a new instance of the custom HTTP client.
// It configures the underlying http.Client with timeouts and proxy settings with rotation.
func NewClient(cfg *config.Config, logger utils.Logger) (*Client, error) {
	clientInstance := &Client{
		userAgent:         cfg.UserAgent,
		logger:            logger,
		cfg:               cfg,
		currentProxyIndex: 0,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   cfg.RequestTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if len(cfg.ParsedProxies) > 0 {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			clientInstance.proxyMutex.Lock()
			defer clientInstance.proxyMutex.Unlock()

			if len(clientInstance.cfg.ParsedProxies) == 0 {
				return nil, nil // Sem proxies para usar
			}

			// Seleciona o proxy atual e avança o índice para a próxima vez
			proxyEntry := clientInstance.cfg.ParsedProxies[clientInstance.currentProxyIndex]
			clientInstance.currentProxyIndex = (clientInstance.currentProxyIndex + 1) % len(clientInstance.cfg.ParsedProxies)

			proxyStr := proxyEntry.String()
			proxyURL, err := url.Parse(proxyStr)
			if err != nil {
				clientInstance.logger.Warnf("Falha ao parsear URL do proxy rotacionado ('%s'): %v. Tentando sem proxy para esta requisição.", proxyStr, err)
				return nil, nil // Não usar proxy se o parse falhar
			}
			clientInstance.logger.Debugf("Usando proxy rotacionado para requisição a %s: %s", req.URL.Host, proxyURL.String())
			return proxyURL, nil
		}
	} else {
		logger.Debugf("Nenhum proxy configurado para o cliente HTTP.")
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			logger.Debugf("Redirect detectado de %s para %s", via[len(via)-1].URL, req.URL)
			return nil
		},
	}

	clientInstance.httpClient = httpClient
	return clientInstance, nil
}

// PerformRequest executes an HTTP request based on ClientRequestData.
// It returns ClientResponseData containing the response details or any error.
func (c *Client) PerformRequest(reqData ClientRequestData) ClientResponseData {
	var finalRespData ClientResponseData

	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			baseDelay := time.Duration(c.cfg.RetryDelayBaseMs) * time.Millisecond
			maxDelay := time.Duration(c.cfg.RetryDelayMaxMs) * time.Millisecond

			delay := baseDelay * time.Duration(1<<(attempt-1)) // Exponencial: 2^(attempt-1)
			// Adicionar jitter: +/- 20% do delay calculado
			jitter := time.Duration(rand.Intn(int(delay/5))) - (delay / 10)
			delay += jitter

			if delay > maxDelay && maxDelay > 0 { // maxDelay > 0 significa que há um limite
				delay = maxDelay
			}
			if delay < 0 { // Garantir que o delay não seja negativo devido ao jitter
				delay = 0
			}

			c.logger.Debugf("[Client] Tentativa %d/%d falhou para %s. Erro: %v. Aguardando %s antes de tentar novamente.", attempt, c.cfg.MaxRetries, reqData.URL, finalRespData.Error, delay)
			time.Sleep(delay)
		}

		req, err := http.NewRequest(reqData.Method, reqData.URL, nil) // TODO: Support request body (reqData.Body)
		if err != nil {
			finalRespData.Error = fmt.Errorf("falha ao criar requisição para %s: %w", reqData.URL, err)
			continue // Tenta a próxima retentativa se houver erro ao criar a requisição
		}

		req.Header.Set("User-Agent", c.userAgent)
		for key, values := range reqData.CustomHeaders {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		c.logger.Debugf("[Client Attempt: %d] Enviando %s para %s com headers: %v", attempt+1, reqData.Method, reqData.URL, req.Header)
		resp, err := c.httpClient.Do(req)
		if err != nil {
			finalRespData.Error = fmt.Errorf("falha ao executar requisição para %s (tentativa %d): %w", reqData.URL, attempt+1, err)
			// Verificar se o erro é transiente para decidir se continua ou não
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				c.logger.Warnf("[Client] Timeout na requisição para %s (tentativa %d).", reqData.URL, attempt+1)
				// Timeouts são bons candidatos para retentativas
			} else {
				// Para outros erros de rede não-timeout, podemos decidir parar ou continuar
				// Se for um erro definitivo (ex: host não encontrado), não adianta tentar de novo.
				// Por enquanto, vamos tentar de novo para a maioria dos erros de httpClient.Do()
			}
			// Se for a última tentativa, o erro será o finalRespData.Error
			if attempt == c.cfg.MaxRetries {
				return finalRespData
			}
			continue // Próxima tentativa
		}

		// Se a requisição foi bem-sucedida (mesmo que status code não seja 2xx)
		defer resp.Body.Close()
		body, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			finalRespData.Error = fmt.Errorf("falha ao ler corpo da resposta de %s (tentativa %d): %w", reqData.URL, attempt+1, readErr)
			// Mesmo se falhar ao ler o corpo, o status code pode ser útil.
			// Para consistência, vamos tratar isso como uma falha da tentativa e possivelmente tentar de novo.
			if attempt == c.cfg.MaxRetries {
				finalRespData.Response = resp // Ainda guardar a resposta se possível
				finalRespData.RespHeaders = resp.Header
				return finalRespData
			}
			continue // Próxima tentativa
		}

		c.logger.Debugf("[Client] Resposta recebida de %s (tentativa %d): Status %s, Body Size: %d", reqData.URL, attempt+1, resp.Status, len(body))

		// Verificar se o status code HTTP deve acionar uma retentativa (ex: 5xx)
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			finalRespData.Error = fmt.Errorf("servidor retornou status %s para %s (tentativa %d)", resp.Status, reqData.URL, attempt+1)
			finalRespData.Response = resp
			finalRespData.Body = body
			finalRespData.RespHeaders = resp.Header
			if attempt == c.cfg.MaxRetries {
				return finalRespData
			}
			continue // Próxima tentativa
		}

		// Requisição e leitura do corpo bem-sucedidas, e status code não é 5xx
		finalRespData.Response = resp
		finalRespData.Body = body
		finalRespData.RespHeaders = resp.Header
		finalRespData.Error = nil // Limpa qualquer erro de tentativas anteriores
		return finalRespData      // Sucesso, retorna imediatamente
	}

	// Se todas as tentativas falharem (MaxRetries atingido)
	c.logger.Errorf("[Client] Todas as %d tentativas falharam para %s. Último erro: %v", c.cfg.MaxRetries+1, reqData.URL, finalRespData.Error)
	return finalRespData
}

// TODO: Implementar GetJSContent(url string) ([]string, error)
// - Este método deve buscar uma URL, parsear o HTML para encontrar tags <script src="...">
// - Para cada src, se for um path relativo, resolver para absoluto baseado na URL original.
// - Baixar o conteúdo de cada script JS.
// - Retornar uma lista de strings, cada string sendo o conteúdo de um arquivo JS.
// - Este método também deve usar a lógica de retentativas.

// loggerIsDebugEnabled is a helper to check if the logger is configured for debug output.
// This is a simplistic check; a more robust Logger interface might have a IsLevelEnabled(level) method.
func (c *Client) loggerIsDebugEnabled() bool {
	return true
} 