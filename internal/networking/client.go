package networking

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	// "net/http/httputil" // Removido pois não está sendo usado
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/utils"
)

// simulationState stores the poisoned value for a given path during a simulated test.
var simulationState = make(map[string]string)
var simMutex sync.Mutex

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
		DisableKeepAlives:   true,
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
// If simulation mode is enabled in the config, it will perform a simulated request instead.
func (c *Client) PerformRequest(reqData ClientRequestData) ClientResponseData {
	if c.config.Simulate {
		return c.performSimulatedRequest(reqData)
	}

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

		// NOVO: Forçar o header Host se ele for especificado nos headers da requisição.
		// Isso é crucial para virtual hosting e testes como os do Varnish.
		if hostHeaderValue := req.Header.Get("Host"); hostHeaderValue != "" {
			req.Host = hostHeaderValue
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
			// Check if the error indicates a rate-limiting issue from a proxy/CDN that doesn't return a proper 429 response.
			if strings.Contains(strings.ToLower(err.Error()), "too many requests") {
				if c.config.VerbosityLevel >= 2 { // Only log this for -vv
					c.logger.Debugf("Request to %s failed but error indicates rate limiting ('Too Many Requests'). Treating as a 429 response.", reqData.URL)
				}
				// Create a mock 429 response to propagate the rate-limiting signal
				finalRespData.Response = &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Status:     "429 Too Many Requests (Inferred from error)",
					Header:     make(http.Header),
					Request:    req,
				}
				finalRespData.Error = nil // Clear the original error as we are now handling it as a 429 response
				return finalRespData
			}

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

// performSimulatedRequest generates a mock response based on the request data.
// This is used to test the tool's logic without making real network requests.
func (c *Client) performSimulatedRequest(reqData ClientRequestData) ClientResponseData {
	simMutex.Lock()
	defer simMutex.Unlock()

	u, _ := url.Parse(reqData.URL)
	// Use a consistent key for state: the hostname.
	stateKey := u.Host

	body := ""
	headers := http.Header{}
	statusCode := 200
	
	// Default cache headers that indicate a cacheable response
	headers.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	headers.Set("Content-Type", "text/html")
	headers.Set("Cache-Control", "public, max-age=3600")

	// --- Logic to detect probe type and manage state ---
	isPoisoningProbeA := false
	var poisonValue string

	// Check for header poisoning payload
	if fwdHost := reqData.RequestHeaders.Get("X-Forwarded-Host"); fwdHost != "" {
		isPoisoningProbeA = true
		poisonValue = fwdHost
		body = "<h1>Header Poisoning Test</h1><p>Reflected Host: " + poisonValue + "</p>"
	}

	// Check for param poisoning payload
	if utmContent := u.Query().Get("utm_content"); utmContent != "" {
		isPoisoningProbeA = true
		poisonValue = utmContent
		body = "<h1>Param Poisoning Test</h1><p>Content: " + poisonValue + "</p>"
	}

	// Check for cache deception payload by looking for the path mutations used in performDeceptionTests
	mutatedPath := u.Path
	if strings.HasSuffix(mutatedPath, `\`) || strings.HasSuffix(mutatedPath, `;`) || strings.HasSuffix(mutatedPath, `#`) || strings.HasSuffix(mutatedPath, `/.`) || strings.HasSuffix(mutatedPath, `//`) {
		isPoisoningProbeA = true
		// The "poison" is the content of the page that shouldn't be cached for the base path.
		poisonValue = "<h1>Cache Deception Content</h1>"
		body = poisonValue
		// The stateKey is already set to the host, which correctly isolates the test.
	}
	

	if isPoisoningProbeA {
		// This is Probe A. Store the value and return a MISS.
		simulationState[stateKey] = poisonValue
		headers.Set("X-Cache", "MISS")
		headers.Set("Age", "0")
		c.logger.Debugf("[SIMULATOR] Stored state for key '%s': '%s'", stateKey, poisonValue)
	} else {
		// This is Probe B (or a baseline request). Check for a poisoned state.
		if poisonedValue, ok := simulationState[stateKey]; ok {
			// State found! This is a poisoned cache hit.
			headers.Set("X-Cache", "HIT")
			headers.Set("Age", "10")
			
			// Craft body based on the stored poisoned value
			if strings.Contains(poisonedValue, "<h1>Cache Deception Content</h1>") {
				body = poisonedValue
			} else if strings.HasPrefix(poisonedValue, "hemlock-header-") {
				body = "<h1>Header Poisoning Test</h1><p>Reflected Host: " + poisonedValue + "</p>"
			} else if strings.HasPrefix(poisonedValue, "hemlock-paramval") {
				body = "<h1>Param Poisoning Test</h1><p>Content: " + poisonedValue + "</p>"
			} else {
				body = "<h1>Poisoned Page</h1><p>" + poisonedValue + "</p>"
			}

			delete(simulationState, stateKey) // Clean up state after use
			c.logger.Debugf("[SIMULATOR] Hit and cleared state for key '%s'. Reflected value.", stateKey)
		} else {
			// No state found. This is a normal MISS or a HIT on un-poisoned content.
			body = "<h1>Baseline Page for " + u.Host + "</h1>"
			headers.Set("X-Cache", "MISS") 
			headers.Set("Age", "0")
			c.logger.Debugf("[SIMULATOR] No state for key '%s'. Treating as baseline.", stateKey)
		}
	}
	
	// Set a default status code if the host is not one of our test cases
	if u.Host != "deception.test" && u.Host != "header-poisoning.test" && u.Host != "param-poisoning.test" && u.Host != "control.test" {
		if !isPoisoningProbeA {
			body = "<h1>Default Simulated Page</h1>"
			statusCode = 404
		}
	}


	resp := &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Body:       ioutil.NopCloser(bytes.NewBufferString(body)),
		Request:    &http.Request{Method: reqData.Method, URL: u},
	}

	return ClientResponseData{
		Response:    resp,
		Body:        []byte(body),
		RespHeaders: headers,
		Error:       nil,
	}
}

