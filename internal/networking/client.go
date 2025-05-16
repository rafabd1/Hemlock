package networking

import (
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

			if c.cfg.VerbosityLevel >= 2 { // -vv
				c.logger.Debugf("[Client] Attempt %d/%d failed for %s. Error: %v. Waiting %s before trying again.", attempt, c.cfg.MaxRetries, reqData.URL, finalRespData.Error, delay)
			} else if c.cfg.VerbosityLevel >= 1 { // -v
				c.logger.Warnf("[Client] Request for %s failed (attempt %d/%d, error: %v). Retrying after delay.", reqData.URL, attempt, c.cfg.MaxRetries, finalRespData.Error)
			}
			time.Sleep(delay)
		}

		req, err := http.NewRequest(reqData.Method, reqData.URL, nil) // TODO: Support request body (reqData.Body)
		if err != nil {
			finalRespData.Error = fmt.Errorf("failed to create request for %s: %w", reqData.URL, err)
			// This is an internal error, should be logged in normal mode if it's the final error.
			// No direct log here, let the loop decide based on MaxRetries.
			continue // Try next retry if there's an error creating the request
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
				// If the header is User-Agent, it will override the default one
			} else {
				// Configuration warning, should be visible in normal mode.
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
			finalRespData.Error = fmt.Errorf("failed to execute request for %s (attempt %d): %w", reqData.URL, attempt+1, err)
			// Check if the error is transient to decide whether to continue
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if c.cfg.VerbosityLevel >= 1 { // -v
					c.logger.Warnf("[Client] Timeout on request to %s (attempt %d).", reqData.URL, attempt+1)
				}
			} else {
				// Other network errors, log if verbose and it's not the last attempt (which gets logged by the final Errorf)
				if c.cfg.VerbosityLevel >= 1 && attempt < c.cfg.MaxRetries {
					c.logger.Warnf("[Client] Network error for %s (attempt %d): %v", reqData.URL, attempt+1, err)
				}
			}
			// If it's the last attempt, the error will be the finalRespData.Error
			if attempt == c.cfg.MaxRetries {
				break // Break to log the final error outside the loop
			}
			continue // Next attempt
		}

		// If the request was successful (even if status code is not 2xx)
		defer resp.Body.Close()
		body, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			finalRespData.Error = fmt.Errorf("failed to read response body from %s (attempt %d): %w", reqData.URL, attempt+1, readErr)
			// Even if reading the body fails, the status code might be useful.
			// For consistency, we'll treat this as a failed attempt and possibly retry.
			if c.cfg.VerbosityLevel >= 1 && attempt < c.cfg.MaxRetries { // -v
				c.logger.Warnf("[Client] Failed to read response body from %s (attempt %d): %v", reqData.URL, attempt+1, readErr)
			}
			if attempt == c.cfg.MaxRetries {
				finalRespData.Response = resp // Still store the response if possible
				finalRespData.RespHeaders = resp.Header
				break // Break to log the final error outside the loop
			}
			continue // Next attempt
		}

		if c.cfg.VerbosityLevel >= 2 { // -vv
			c.logger.Debugf("[Client] Response received from %s (attempt %d): Status %s, Body Size: %d", reqData.URL, attempt+1, resp.Status, len(body))
		}

		// Check if HTTP status code should trigger a retry (e.g., 5xx)
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			finalRespData.Error = fmt.Errorf("server returned status %s for %s (attempt %d)", resp.Status, reqData.URL, attempt+1)
			finalRespData.Response = resp
			finalRespData.Body = body
			finalRespData.RespHeaders = resp.Header
			if c.cfg.VerbosityLevel >= 1 { // -v
				c.logger.Warnf("[Client] Server error %s for %s (attempt %d). Retrying if possible.", resp.Status, reqData.URL, attempt+1)
			}
			if attempt == c.cfg.MaxRetries {
				break // Break to log the final error outside the loop
			}
			continue // Next attempt
		}

		// Request and body reading successful, and status code is not 5xx
		finalRespData.Response = resp
		finalRespData.Body = body
		finalRespData.RespHeaders = resp.Header
		finalRespData.Error = nil // Clear any errors from previous attempts
		return finalRespData      // Success, return immediately
	}

	// If all attempts fail (MaxRetries reached and loop finished or broke to here)
	// This error is an execution error as the client could not get a valid response after all retries.
	c.logger.Errorf("[Client] All %d attempts failed for %s. Last error: %v", c.cfg.MaxRetries+1, reqData.URL, finalRespData.Error)
	return finalRespData
}

// TODO: Implement GetJSContent(url string) ([]string, error)
// - This method should fetch a URL, parse the HTML to find <script src="..."> tags
// - For each src, if it's a relative path, resolve it to an absolute path based on the original URL.
// - Download the content of each JS script.
// - Return a list of strings, each string being the content of a JS file.
// - This method should also use the retry logic.

// Removed loggerIsDebugEnabled as it's better to use c.cfg.VerbosityLevel directly. 