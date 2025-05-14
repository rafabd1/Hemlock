package networking

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/rafabd1/Hemlock/internal/utils"
)

// Client represents an HTTP client for making requests.
type Client struct {
	httpClient *http.Client
	userAgent  string
	logger     utils.Logger
}

// ClientRequestData holds the necessary info to make a request.
// This helps in decoupling the client from specific core package structs if needed.
type ClientRequestData struct {
	URL           string
	CustomHeaders http.Header
	Method        string // e.g., "GET", "POST"
}

// ClientResponseData holds the necessary info from an HTTP response.
type ClientResponseData struct {
	Response    *http.Response // The raw *http.Response object
	Body        []byte
	RespHeaders http.Header    // A clone of the response headers
	Error       error
}

// NewClient creates a new HTTP Client.
// It takes timeout, userAgent, proxyURL string, and a logger as parameters.
func NewClient(timeout time.Duration, userAgent string, proxyURL string, logger utils.Logger) (*Client, error) {
	transport := &http.Transport{}

	if proxyURL != "" {
		parsedProxyURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy URL '%s': %w", proxyURL, err)
		}
		transport.Proxy = http.ProxyURL(parsedProxyURL)
	}
	// TODO: Consider InsecureSkipVerify option if needed later. 
	// Example: transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Requires import "crypto/tls"

	return &Client{
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse 
			},
		},
		userAgent: userAgent,
		logger:    logger,
	}, nil
}

// PerformRequest executes an HTTP request based on ClientRequestData.
// It returns ClientResponseData which encapsulates the response details or an error.
func (c *Client) PerformRequest(reqData ClientRequestData) ClientResponseData {
	var respData ClientResponseData

	if reqData.Method == "" {
		reqData.Method = http.MethodGet // Default to GET if not specified
	}

	c.logger.Debugf("[HTTP Client] Performing '%s' request to URL: %s", reqData.Method, reqData.URL)
	if len(reqData.CustomHeaders) > 0 {
		c.logger.Debugf("[HTTP Client] With custom headers: %v", reqData.CustomHeaders)
	}

	req, err := http.NewRequest(reqData.Method, reqData.URL, nil) 
	if err != nil {
		respData.Error = fmt.Errorf("failed to create request for %s: %w", reqData.URL, err)
		c.logger.Errorf("[HTTP Client] Error creating request for %s: %v", reqData.URL, err)
		return respData
	}

	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	if reqData.CustomHeaders != nil {
		for key, values := range reqData.CustomHeaders {
			if len(values) > 0 {
				req.Header.Set(key, values[0]) 
				for i := 1; i < len(values); i++ {
					req.Header.Add(key, values[i]) 
				}
			} else {
				req.Header.Del(key) 
			}
		}
	}

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		respData.Error = fmt.Errorf("failed to execute request to %s: %w", reqData.URL, err)
		c.logger.Warnf("[HTTP Client] Failed to execute request to %s: %v", reqData.URL, err)
		if httpResp != nil && httpResp.Body != nil {
			httpResp.Body.Close()
		}
		return respData
	}
	defer httpResp.Body.Close()

	respData.Response = httpResp 
	clonedHeaders := make(http.Header)
	for k, v := range httpResp.Header {
		clonedHeaders[k] = append([]string(nil), v...)
	}
	respData.RespHeaders = clonedHeaders

	bodyBytes, readErr := ioutil.ReadAll(httpResp.Body)
	if readErr != nil {
		if respData.Error == nil {
			respData.Error = fmt.Errorf("failed to read response body from %s: %w", reqData.URL, readErr)
		} 
		c.logger.Warnf("[HTTP Client] Failed to read response body from %s: %v", reqData.URL, readErr)
	}
	respData.Body = bodyBytes

	c.logger.Debugf("[HTTP Client] Response from %s: Status: %s, Body Size: %d bytes", reqData.URL, httpResp.Status, len(respData.Body))
	if c.loggerIsDebugEnabled() {
		keyRespHeaders := make(http.Header)
		if val := respData.RespHeaders.Get("Content-Type"); val != "" { keyRespHeaders.Set("Content-Type", val) }
		if val := respData.RespHeaders.Get("Cache-Control"); val != "" { keyRespHeaders.Set("Cache-Control", val) }
		if val := respData.RespHeaders.Get("X-Cache"); val != "" { keyRespHeaders.Set("X-Cache", val) }
		if val := respData.RespHeaders.Get("Age"); val != "" { keyRespHeaders.Set("Age", val) }
		c.logger.Debugf("[HTTP Client] Key response headers from %s: %v", reqData.URL, keyRespHeaders)
	}

	return respData
}

// loggerIsDebugEnabled is a helper to check if the logger is configured for debug output.
// This is a simplistic check; a more robust Logger interface might have a IsLevelEnabled(level) method.
func (c *Client) loggerIsDebugEnabled() bool {
	return true
} 