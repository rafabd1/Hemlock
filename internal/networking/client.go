package networking

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	// "net/http/httputil" // Removido pois não está sendo usado
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/utils"
)

const (
	// DefaultRetryDelayBaseMs is the base delay for exponential backoff.
	DefaultRetryDelayBaseMs = 200 // formerly from config.RetryDelayBaseMs
	// DefaultRetryDelayMaxMs is the maximum delay for exponential backoff.
	DefaultRetryDelayMaxMs = 5000 // formerly from config.RetryDelayMaxMs
)

// Client struct manages HTTP requests, including custom headers, retries, and proxy support.
type Client struct {
	baseClient       *http.Client
	config           *config.Config
	logger           utils.Logger
	userAgent        string
	parsedProxies    []config.ProxyEntry
	proxyLock        sync.Mutex
	domainProxyIndex map[string]int
	defaultTransport *http.Transport
	currentProxyIndex int // For global round-robin if needed, not primary for domain-specific
	// proxyMutex        sync.Mutex // proxyLock é usado para domainProxyIndex
}

// ClientRequestData struct encapsulates all necessary data for making a request.
type ClientRequestData struct {
	URL            string
	Method         string
	Body           string
	CustomHeaders  http.Header // Alterado para http.Header para facilitar o uso
	RequestHeaders http.Header // Renomeado de CustomHeaders para clareza, usado para headers específicos da requisição
	Ctx            context.Context
}

// ClientResponseData struct holds the outcome of an HTTP request.
type ClientResponseData struct {
	Response    *http.Response
	Body        []byte
	RespHeaders http.Header
	Error       error
}

// NewClient creates a new HTTP Client with specified configurations.
func NewClient(cfg *config.Config, logger utils.Logger) (*Client, error) {
	baseTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	c := &Client{
		config:           cfg,
		logger:           logger,
		userAgent:        cfg.UserAgent,
		parsedProxies:    cfg.ParsedProxies,
		domainProxyIndex: make(map[string]int),
		defaultTransport: baseTransport,
		currentProxyIndex: 0,
	}

	c.baseClient = &http.Client{
		Transport: c.defaultTransport,
		Timeout:   cfg.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Always return the last response (e.g. the 302 itself)
		},
	}

	return c, nil
}

// getProxyForDomain selects a proxy for a given target domain using round-robin per domain.
func (c *Client) getProxyForDomain(targetDomain string) *url.URL {
	c.proxyLock.Lock()
	defer c.proxyLock.Unlock()

	if len(c.parsedProxies) == 0 {
		return nil
	}

	currentIndex, exists := c.domainProxyIndex[targetDomain]
	if !exists {
		currentIndex = 0
	} else {
		currentIndex = (currentIndex + 1) % len(c.parsedProxies)
	}
	c.domainProxyIndex[targetDomain] = currentIndex

	selectedProxyEntry := c.parsedProxies[currentIndex]
	proxyURL, err := url.Parse(selectedProxyEntry.URL)
	if err != nil {
		c.logger.Warnf("Failed to parse stored proxy URL '%s': %v. Skipping proxy.", selectedProxyEntry.URL, err)
		return nil
	}

	if c.config.VerbosityLevel >= 1 {
		c.logger.Debugf("Selected proxy '%s' for target domain '%s' (Index: %d)", proxyURL.String(), targetDomain, currentIndex)
	}
	return proxyURL
}

// PerformRequest executes an HTTP request based on the provided ClientRequestData.
func (c *Client) PerformRequest(reqData ClientRequestData) ClientResponseData {
	var finalRespData ClientResponseData

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		req, errBuildReq := http.NewRequestWithContext(reqData.Ctx, reqData.Method, reqData.URL, strings.NewReader(reqData.Body))
		if errBuildReq != nil {
			finalRespData.Error = fmt.Errorf("failed to build request for %s: %w", reqData.URL, errBuildReq)
			return finalRespData
		}

		req.Header.Set("User-Agent", c.userAgent)

		// Aplicar headers específicos da requisição (reqData.RequestHeaders)
		if reqData.RequestHeaders != nil {
			for key, values := range reqData.RequestHeaders {
				for _, value := range values {
					req.Header.Add(key, value) // Use Add para suportar múltiplos valores para o mesmo header
				}
			}
		}

		// Aplicar headers customizados globais (c.config.CustomHeaders)
		// Estes são aplicados apenas se não foram definidos pelos headers específicos da requisição.
		for _, headerStr := range c.config.CustomHeaders {
			parts := strings.SplitN(headerStr, ":", 2)
			if len(parts) == 2 {
				headerName := strings.TrimSpace(parts[0])
				headerValue := strings.TrimSpace(parts[1])
				if req.Header.Get(headerName) == "" { // Só adiciona se não foi definido por reqData.RequestHeaders
					req.Header.Set(headerName, headerValue)
				}
			}
		}

		// Determinar o cliente HTTP a ser usado (com ou sem proxy)
		currentHttpClient := c.baseClient
		targetHost := req.URL.Hostname() // Obter o host do URL da requisição

		if len(c.parsedProxies) > 0 {
			selectedProxyURL := c.getProxyForDomain(targetHost)
			if selectedProxyURL != nil {
				proxiedTransport := c.defaultTransport.Clone()
				proxiedTransport.Proxy = http.ProxyURL(selectedProxyURL)
				currentHttpClient = &http.Client{
					Transport:     proxiedTransport,
					Timeout:       c.config.RequestTimeout,
					CheckRedirect: c.baseClient.CheckRedirect,
				}
				if c.config.VerbosityLevel >= 1 {
					c.logger.Debugf("Using proxy %s for request to %s (target host: %s)", selectedProxyURL.String(), reqData.URL, targetHost)
				}
			} else {
				if c.config.VerbosityLevel >= 1 {
					c.logger.Debugf("No proxy selected by getProxyForDomain for %s (target host: %s), using direct connection.", reqData.URL, targetHost)
				}
			}
		}

		if c.config.VerbosityLevel >= 2 {
			c.logger.Debugf("[Client Attempt: %d] Sending %s to %s with headers: %v", attempt+1, reqData.Method, reqData.URL, req.Header)
			if reqData.Body != "" {
				c.logger.Debugf("[Client Attempt: %d] Request body: %s", attempt+1, reqData.Body)
			}
		}

		resp, err := currentHttpClient.Do(req)
		if err != nil {
			finalRespData.Error = fmt.Errorf("failed to execute request for %s (attempt %d/%d): %w", reqData.URL, attempt+1, c.config.MaxRetries+1, err)
			if reqData.Ctx.Err() == context.DeadlineExceeded {
				c.logger.Debugf("Request to %s timed out (attempt %d/%d)", reqData.URL, attempt+1, c.config.MaxRetries+1)
			} else if reqData.Ctx.Err() == context.Canceled {
				c.logger.Debugf("Request to %s canceled by context (attempt %d/%d)", reqData.URL, attempt+1, c.config.MaxRetries+1)
			} else if strings.Contains(err.Error(), "dial tcp") && strings.Contains(err.Error(), "timeout") {
				c.logger.Debugf("Request to %s failed with TCP dial timeout (attempt %d/%d): %v", reqData.URL, attempt+1, c.config.MaxRetries+1, err)
			}
			if attempt == c.config.MaxRetries {
				return finalRespData
			}
			time.Sleep(time.Duration(c.config.ConductorInitialRetryDelaySeconds) * time.Second)
			continue
		}

		bodyBytes, errReadBody := io.ReadAll(resp.Body)
		resp.Body.Close() // Fechar o corpo aqui, independentemente do erro de leitura
		if errReadBody != nil {
			finalRespData.Error = fmt.Errorf("failed to read response body for %s (attempt %d/%d): %w", reqData.URL, attempt+1, c.config.MaxRetries+1, errReadBody)
			if attempt == c.config.MaxRetries {
				return finalRespData
			}
			time.Sleep(time.Duration(c.config.ConductorInitialRetryDelaySeconds) * time.Second)
			continue
		}

		finalRespData.Response = resp
		finalRespData.Body = bodyBytes
		finalRespData.RespHeaders = resp.Header
		finalRespData.Error = nil

		if c.config.VerbosityLevel >= 2 {
			c.logger.Debugf("Request to %s (attempt %d) successful. Status: %s. Body size: %d", reqData.URL, attempt+1, resp.Status, len(finalRespData.Body))
			if len(finalRespData.Body) > 0 { // Logar corpos pequenos para depuração, apenas se não estiver vazio
				logLength := len(finalRespData.Body)
				if logLength > 500 {
					logLength = 500
				}
				c.logger.Debugf("Response body (first %d bytes): %s", logLength, string(finalRespData.Body[:logLength]))
			}
		}
		return finalRespData
	}
	return finalRespData
}

