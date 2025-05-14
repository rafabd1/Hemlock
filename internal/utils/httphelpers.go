package utils

import (
	"net/http"
	"net/url"
	"strings"
)

// GetDomainFromURL extracts the domain name from a URL string.
func GetDomainFromURL(urlString string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

// IsCacheable checks response headers to make a basic assessment of whether a response is likely cacheable.
// This is a simplified check; real cache behavior can be complex.
func IsCacheable(headers http.Header) bool {
	// Check Cache-Control
	cacheControl := headers.Get("Cache-Control")
	if cacheControl != "" {
		if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache") {
			return false
		}
		if strings.Contains(cacheControl, "public") || strings.Contains(cacheControl, "max-age") { // max-age > 0
			return true
		}
	}

	// Check Pragma (less common now, but for older servers)
	pragma := headers.Get("Pragma")
	if strings.Contains(pragma, "no-cache") {
		return false
	}

	// Check Expires (if in the future)
	expires := headers.Get("Expires")
	if expires != "" && expires != "0" && expires != "-1" {
		// TODO: Parse Expires date and compare with current time.
		// For simplicity now, assume if present and not 0/-1, it might be cacheable.
		return true 
	}

	// Check for specific cache HIT headers (e.g., X-Cache: HIT)
	xCache := headers.Get("X-Cache")
	if strings.Contains(strings.ToLower(xCache), "hit") {
		return true
	}
	cfCacheStatus := headers.Get("CF-Cache-Status") // Cloudflare
	if strings.ToUpper(cfCacheStatus) == "HIT" {
		return true
	}

	// Default: If no strong contra-indications, might be implicitly cacheable by some caches.
	// This is a very loose assumption and should be refined.
	return false // Or true, depending on how conservative we want to be initially.
}

// TODO: Add functions for parsing specific cache headers, generating unique payloads, etc. 