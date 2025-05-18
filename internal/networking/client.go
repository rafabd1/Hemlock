package networking

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
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
	Ctx           context.Context
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
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
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
				// This is a configuration error, should be visible in normal mode.
				clientInstance.logger.Warnf("Falha ao parsear URL do proxy rotacionado ('%s'): %v. Tentando sem proxy para esta requisição.", proxyStr, err)
				return nil, nil // Não usar proxy se o parse falhar
			}
			if clientInstance.cfg.VerbosityLevel >= 2 { // -vv
				clientInstance.logger.Debugf("Usando proxy rotacionado para requisição a %s: %s", req.URL.Host, proxyURL.String())
			}
			return proxyURL, nil
		}
	} else {
		if cfg.VerbosityLevel >= 2 { // -vv
			logger.Debugf("Nenhum proxy configurado para o cliente HTTP.")
		}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if cfg.VerbosityLevel >= 2 { // -vv
				logger.Debugf("Redirect detectado de %s para %s", via[len(via)-1].URL, req.URL)
			}
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
			baseDelay := time.Duration(DefaultRetryDelayBaseMs) * time.Millisecond
			maxDelay := time.Duration(DefaultRetryDelayMaxMs) * time.Millisecond

			delay := baseDelay * time.Duration(1<<(attempt-1)) // Exponential: 2^(attempt-1)
			// Add jitter: +/- 20% of calculated delay
			jitter := time.Duration(rand.Intn(int(delay/5))) - (delay / 10)
			delay += jitter

			if delay > maxDelay && maxDelay > 0 { // maxDelay > 0 means there's a limit
				delay = maxDelay
			}
			if delay < 0 { // Ensure delay is not negative due to jitter
				delay = 0
			}

			if c.cfg.VerbosityLevel >= 1 { // -v or -vv
				logMsg := fmt.Sprintf("[Client] Request for %s failed (attempt %d/%d). Error: %v. Retrying after %s.", 
					reqData.URL, attempt, c.cfg.MaxRetries, finalRespData.Error, delay)
				if c.cfg.VerbosityLevel >= 2 { // -vv for more detail
					c.logger.Debugf(logMsg) 
				} else { // -v
					c.logger.Warnf(logMsg) // Use Warnf for -v to make retries more visible than pure debug
				}
			}
			time.Sleep(delay)
		}

		var req *http.Request
		var err error

		// Usar contexto se disponível
		if reqData.Ctx != nil {
			req, err = http.NewRequestWithContext(reqData.Ctx, reqData.Method, reqData.URL, strings.NewReader(string(reqData.Body)))
		} else {
			// Fallback para o caso de Ctx não ser fornecido (idealmente, deve ser sempre fornecido)
			c.logger.Warnf("[Client] Performing request for %s without context. Consider passing a context.", reqData.URL)
			req, err = http.NewRequest(reqData.Method, reqData.URL, strings.NewReader(string(reqData.Body)))
		}
		
		if err != nil {
			finalRespData.Error = fmt.Errorf("failed to create request for %s: %w", reqData.URL, err)
			continue 
		}

		// Set User-Agent and then any custom headers from config
		req.Header.Set("User-Agent", c.userAgent)
		
		// Add any custom headers specified in config
		for _, headerLine := range c.cfg.CustomHeaders {
			parts := strings.SplitN(headerLine, ":", 2)
			if len(parts) == 2 {
				headerName := strings.TrimSpace(parts[0])
				headerValue := strings.TrimSpace(parts[1])
				req.Header.Set(headerName, headerValue)
			} else {
				c.logger.Warnf("[Client] Invalid custom header format (expected 'Name: Value'): %s", headerLine)
			}
		}
		
		// Finally add any request-specific custom headers (these have highest priority)
		for key, values := range reqData.CustomHeaders {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		if c.cfg.VerbosityLevel >= 2 { // -vv
			c.logger.Debugf("[Client Attempt: %d] Sending %s to %s with headers: %v", attempt+1, reqData.Method, reqData.URL, req.Header)
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			finalRespData.Error = fmt.Errorf("failed to execute request for %s (attempt %d/%d): %w", reqData.URL, attempt+1, c.cfg.MaxRetries+1, err)
			if attempt == c.cfg.MaxRetries {
				break 
			}
			continue 
		}

		defer resp.Body.Close()
		body, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			finalRespData.Error = fmt.Errorf("failed to read response body from %s (attempt %d/%d): %w", reqData.URL, attempt+1, c.cfg.MaxRetries+1, readErr)
			finalRespData.Response = resp 
			finalRespData.RespHeaders = resp.Header
			if attempt == c.cfg.MaxRetries {
				break 
			}
			continue 
		}

		if c.cfg.VerbosityLevel >= 2 { // -vv
			c.logger.Debugf("[Client] Response received from %s (attempt %d/%d): Status %s, Body Size: %d", reqData.URL, attempt+1, c.cfg.MaxRetries+1, resp.Status, len(body))
		}

		if resp.StatusCode >= 500 && resp.StatusCode <= 599 { // Retry on 5xx errors
			finalRespData.Error = fmt.Errorf("server returned status %s for %s (attempt %d/%d)", resp.Status, reqData.URL, attempt+1, c.cfg.MaxRetries+1)
			finalRespData.Response = resp
			finalRespData.Body = body
			finalRespData.RespHeaders = resp.Header
			if attempt == c.cfg.MaxRetries {
				break
			}
			continue
		}

		// Request and body reading successful, and status code is not a retryable one (e.g. 5xx)
		finalRespData.Response = resp
		finalRespData.Body = body
		finalRespData.RespHeaders = resp.Header
		finalRespData.Error = nil // Clear any previous attempt error
		return finalRespData // Success, return immediately
	}

	// If all retries failed, finalRespData.Error will contain the last error encountered.
	// Log the final failure only if verbosity allows (error is returned anyway for scheduler to handle)
	if finalRespData.Error != nil && c.cfg.VerbosityLevel >= 1 { // -v or -vv
		c.logger.Errorf("[Client] All %d attempts failed for %s. Last error: %v", c.cfg.MaxRetries+1, reqData.URL, finalRespData.Error)
	}
	return finalRespData
}

// TODO: Implement GetJSContent(url string) ([]string, error)
// - This method should fetch a URL, parse the HTML to find <script src="..."> tags
// - For each src, if it's a relative path, resolve it to an absolute path based on the original URL.
// - Download the content of each JS script.
// - Return a list of strings, each string being the content of a JS file.
// - This method should also use the retry logic.

// Removed loggerIsDebugEnabled as it's better to use c.cfg.VerbosityLevel directly. 