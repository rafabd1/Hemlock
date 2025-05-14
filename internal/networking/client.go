package networking

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config" // For config.ProxyConfig
	"github.com/rafabd1/Hemlock/internal/utils"  // Assuming logger might be passed or used here
)

// Client manages HTTP requests, including retries, timeouts, custom headers, and proxy usage.
// It will be based on the resilient client described in your architecture document.
type Client struct {
	httpClient      *http.Client // This client will have a base transport, potentially without a proxy or with ProxyFromEnvironment
	baseTransport   *http.Transport // Store the base transport for cloning
	config          ClientConfig
	domainManager   *DomainManager // Added DomainManager
	logger          utils.Logger   // Added Logger
	proxyList       []*url.URL
	proxyMu         sync.Mutex
	nextProxy       int
}

// ClientConfig holds configuration for the HTTP client.
type ClientConfig struct {
	Timeout            time.Duration
	MaxRetries         int
	UserAgent          string
	Proxies            []config.ProxyConfig // Changed to use ProxyConfig struct
	InsecureSkipVerify bool    // To ignore SSL/TLS errors
	// TODO: Add other relevant config fields like RetryDelay (min/max for backoff)
}

// NewClient creates a new HTTP Client.
func NewClient(cfg ClientConfig, dm *DomainManager, logger utils.Logger) (*Client, error) {
	var parsedProxyList []*url.URL
	for _, proxyCfg := range cfg.Proxies {
		if !proxyCfg.Enabled {
			logger.Debugf("Proxy %s is disabled, skipping.", proxyCfg.URL)
			continue
		}

		proxyStr := proxyCfg.URL
		// If username and password are provided, prepend them to the URL string
		// This assumes url.Parse can handle user:pass@host:port format for proxies.
		if proxyCfg.Username != "" {
			tempUrl, err := url.Parse(proxyStr)
			if err != nil {
				logger.Warnf("Failed to parse proxy URL %s before adding auth: %v. Skipping proxy.", proxyStr, err)
				continue
			}
			if proxyCfg.Password != "" {
				tempUrl.User = url.UserPassword(proxyCfg.Username, proxyCfg.Password)
			} else {
				tempUrl.User = url.User(proxyCfg.Username)
			}
			proxyStr = tempUrl.String()
		}

		proxyURL, err := url.Parse(proxyStr)
		if err != nil {
			logger.Warnf("Invalid proxy URL %s: %v. Skipping proxy.", proxyStr, err)
			continue // Skip invalid proxy URLs
		}
		parsedProxyList = append(parsedProxyList, proxyURL)
		logger.Debugf("Added enabled proxy: %s", proxyURL.Host) // Log host part for brevity
	}

	if len(parsedProxyList) > 0 {
		logger.Infof("Initialized with %d enabled proxies.", len(parsedProxyList))
	}

	baseTransport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		Proxy:               http.ProxyFromEnvironment, // Default, can be overridden per request if needed by cloning transport
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// Consider MaxIdleConnsPerHost, ResponseHeaderTimeout, ExpectContinueTimeout etc. for finer control
	}

	httpClient := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: baseTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Client{
		httpClient:    httpClient,
		baseTransport: baseTransport,
		config:        cfg,
		domainManager: dm,
		logger:        logger,
		proxyList:     parsedProxyList, // Use the list of parsed and enabled proxies
	}, nil
}

// getNextProxy returns the next proxy from the list in a round-robin fashion.
// Returns nil if no proxies are configured or if all are disabled (though disabled ones are filtered at init).
func (c *Client) getNextProxy() *url.URL {
	if len(c.proxyList) == 0 {
		return nil
	}
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	
	proxy := c.proxyList[c.nextProxy]
	c.nextProxy = (c.nextProxy + 1) % len(c.proxyList)
	return proxy
}

// Get performs a GET request with the client's retry and error handling logic.
// It will interact with the DomainManager before making requests and can use proxies.
func (c *Client) Get(targetUrlStr string, customHeaders map[string]string) (*http.Response, []byte, error) {
	domain, err := utils.GetDomainFromURL(targetUrlStr)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing domain from URL %s: %w", targetUrlStr, err)
	}

	var resp *http.Response
	var body []byte
	var lastErr error

	for i := 0; i < c.config.MaxRetries+1; i++ {
		if !c.domainManager.CanRequest(domain) {
			c.logger.Debugf("Rate limit or block on domain %s, attempt %d for URL %s", domain, i+1, targetUrlStr)
			// TODO: Implement proper backoff or task re-queuing instead of simple error. For now, error out.
			return nil, nil, fmt.Errorf("domain %s is currently rate-limited or blocked", domain) // Or a specific error type
		}

		req, err := http.NewRequest("GET", targetUrlStr, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating request for %s: %w", targetUrlStr, err)
		}

		req.Header.Set("User-Agent", c.config.UserAgent)
		for key, value := range customHeaders {
			req.Header.Set(key, value)
		}

		currentClient := c.httpClient // Use the base client by default
		selectedProxy := c.getNextProxy()

		if selectedProxy != nil {
			c.logger.Debugf("Using proxy %s for URL %s", selectedProxy.String(), targetUrlStr)
			// Clone the base transport and set the proxy for this specific request
			proxyTransport := c.baseTransport.Clone()
			proxyTransport.Proxy = http.ProxyURL(selectedProxy)
			currentClient = &http.Client{
				Transport:     proxyTransport,
				Timeout:       c.config.Timeout, // Inherit timeout
				CheckRedirect: c.httpClient.CheckRedirect, // Inherit redirect policy
			}
		} else {
			// Ensure the base client's transport is used (it might have ProxyFromEnvironment or nil)
			// This is implicitly handled by currentClient = c.httpClient and baseTransport default
		}

		c.domainManager.RecordRequestSent(domain)
		startTime := time.Now()
		resp, err = currentClient.Do(req) // Use the potentially proxy-configured client
		duration := time.Since(startTime)

		if err != nil {
			lastErr = fmt.Errorf("request to %s failed on attempt %d: %w", targetUrlStr, i+1, err)
			c.logger.Warnf("%s (duration: %s)", lastErr.Error(), duration)
			c.domainManager.RecordRequestResult(domain, false, 0, false, false) // Basic error recording
			// TODO: Implement smarter backoff with jitter for retries
			time.Sleep(time.Duration(1+i) * time.Second) // Simple incremental backoff
			continue
		}

		// Read body even if it's an error status code, as it might contain useful info
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close() // Close body immediately after reading
		if readErr != nil {
			lastErr = fmt.Errorf("error reading response body from %s (status %d): %w", targetUrlStr, resp.StatusCode, readErr)
			c.logger.Warnf("%s", lastErr.Error())
			c.domainManager.RecordRequestResult(domain, false, resp.StatusCode, false, false) // Record as failure
            // Decide if this is a retryable error or not
            if i < c.config.MaxRetries { // If retries are left
                time.Sleep(time.Duration(1+i) * time.Second)
                continue
            }
			return resp, nil, lastErr // Return response (if any) and error if all retries failed on read
		}

		resp.Body = io.NopCloser(bytes.NewBuffer(body)) // Replace body so it can be read again if needed

		// TODO: More sophisticated WAF/Rate Limit detection based on status code/body
		isWAF := resp.StatusCode == 403 || resp.StatusCode == 406 // Example WAF codes
		isRateLimit := resp.StatusCode == 429

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.logger.Debugf("Successfully fetched %s (status %d) on attempt %d (duration: %s)", targetUrlStr, resp.StatusCode, i+1, duration)
			c.domainManager.RecordRequestResult(domain, true, resp.StatusCode, false, false)
			return resp, body, nil
		}

		lastErr = fmt.Errorf("request to %s returned status %d on attempt %d", targetUrlStr, resp.StatusCode, i+1)
		c.logger.Warnf("%s (duration: %s)", lastErr.Error(), duration)
		c.domainManager.RecordRequestResult(domain, false, resp.StatusCode, isWAF, isRateLimit)

		// Decide if we should retry based on status code
		if !shouldRetryStatusCode(resp.StatusCode) || i == c.config.MaxRetries {
			return resp, body, lastErr // Return last response and error if not retryable or no retries left
		}

		// TODO: Implement smarter backoff with jitter for retries
		time.Sleep(time.Duration(1+i) * time.Second) // Simple incremental backoff
	}

	return resp, body, lastErr // Should be unreachable if MaxRetries >= 0, but as a fallback
}

// shouldRetryStatusCode determines if a request should be retried based on its HTTP status code.
func shouldRetryStatusCode(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	default:
		return false
	}
}

// GetBaseline establishes a baseline for a URL by making a normal request.
// It may or may not use a proxy depending on the testing strategy.
func (c *Client) GetBaseline(targetUrlStr string) (*http.Response, []byte, map[string][]string, error) {
	// For baseline, typically no custom headers are needed initially, unless testing specific known app behavior.
	c.logger.Debugf("Getting baseline for %s", targetUrlStr)
	resp, body, err := c.Get(targetUrlStr, nil)
	if err != nil {
		// If resp is not nil, it means we got a response but it was an error status.
		// We might still want to consider this part of a 'baseline' if the server is just erroring out.
		if resp != nil {
			return resp, body, resp.Header, fmt.Errorf("error getting baseline for %s (status %d): %w", targetUrlStr, resp.StatusCode, err)
		}
		return nil, nil, nil, fmt.Errorf("error getting baseline for %s: %w", targetUrlStr, err)
	}
	return resp, body, resp.Header, nil
}

// ProbeWithHeader sends a request with a specific header to test for unkeyed input reflection.
// It may or may not use a proxy depending on the testing strategy.
func (c *Client) ProbeWithHeader(targetUrlStr string, headerName string, headerValue string) (*http.Response, []byte, map[string][]string, error) {
	customHeaders := map[string]string{headerName: headerValue}
	c.logger.Debugf("Probing %s with header %s: %s", targetUrlStr, headerName, headerValue)
	resp, body, err := c.Get(targetUrlStr, customHeaders)
	if err != nil {
		if resp != nil {
			return resp, body, resp.Header, fmt.Errorf("error probing %s with header %s (status %d): %w", targetUrlStr, headerName, resp.StatusCode, err)
		}
		return nil, nil, nil, fmt.Errorf("error probing %s with header %s: %w", targetUrlStr, headerName, err)
	}
	return resp, body, resp.Header, nil
} 