package networking

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// Client represents an HTTP client for making requests.
type Client struct {
	httpClient *http.Client
	userAgent  string
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
// It takes timeout, userAgent, and proxyURL string as parameters.
func NewClient(timeout time.Duration, userAgent string, proxyURL string) (*Client, error) {
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
	}, nil
}

// PerformRequest executes an HTTP request based on ClientRequestData.
// It returns ClientResponseData which encapsulates the response details or an error.
func (c *Client) PerformRequest(reqData ClientRequestData) ClientResponseData {
	var respData ClientResponseData

	if reqData.Method == "" {
		reqData.Method = http.MethodGet // Default to GET if not specified
	}

	req, err := http.NewRequest(reqData.Method, reqData.URL, nil) 
	if err != nil {
		respData.Error = fmt.Errorf("failed to create request for %s: %w", reqData.URL, err)
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
	}
	respData.Body = bodyBytes

	return respData
} 