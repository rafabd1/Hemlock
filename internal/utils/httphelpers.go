package utils

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
		if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache") || strings.Contains(cacheControl, "private") {
			return false
		}
		if strings.Contains(cacheControl, "public") || strings.Contains(cacheControl, "max-age=") { // Ensure max-age has a value > 0 (actual parsing is more complex)
			// TODO: Parse max-age value to ensure it's > 0
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

// BodyContains checks if a byte slice (e.g., response body) contains a specific substring.
func BodyContains(body []byte, substring []byte) bool {
	if body == nil || substring == nil {
		return false
	}
	return bytes.Contains(body, substring)
}

// HeadersContain checks if any value of any header in the http.Header map contains a specific substring.
// This is a case-insensitive check for the substring within header values.
func HeadersContain(headers http.Header, substring string) bool {
	if headers == nil || substring == "" {
		return false
	}
	lowerSubstring := strings.ToLower(substring)
	for _, values := range headers {
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), lowerSubstring) {
				return true
			}
		}
	}
	return false
}

// IsCacheHit checks response headers for common indicators of a cache hit.
// This is a simplified check and real-world scenarios can be more complex with CDNs.
func IsCacheHit(headers http.Header) bool {
	if headers == nil {
		return false
	}
	// Common general cache headers
	xCache := strings.ToLower(headers.Get("X-Cache"))
	if strings.Contains(xCache, "hit") {
		return true
	}
	// CDN specific headers (examples)
	cfCacheStatus := strings.ToUpper(headers.Get("CF-Cache-Status")) // Cloudflare
	if cfCacheStatus == "HIT" || cfCacheStatus == "MISS" || cfCacheStatus == "EXPIRED" || cfCacheStatus == "UPDATING" || cfCacheStatus == "STALE" || cfCacheStatus == "REVALIDATED" { // Consider other statuses too
        if cfCacheStatus == "HIT" || cfCacheStatus == "REVALIDATED" { // REVALIDATED often means it served from cache after checking origin
             return true
        }
    }

	xCacheLookup := strings.ToLower(headers.Get("X-Cache-Lookup"))
	if strings.Contains(xCacheLookup, "hit") {
		return true
	}

	serverTiming := headers.Get("Server-Timing")
    if strings.Contains(strings.ToLower(serverTiming), "cdn-cache; desc=hit") { // General pattern some CDNs might use
        return true
    }
    if strings.Contains(strings.ToLower(serverTiming), "cdn-cache;desc=hit") { // Some CDNs use this variant
        return true
    }

	// Fastly: X-Served-By and X-Cache
	xServedBy := headers.Get("X-Served-By")
	if xServedBy != "" && strings.Contains(xCache, "hit") { // Fastly often uses X-Cache: HIT along with X-Served-By
		return true
	}

	// Akamai: X-Check-Cacheable (YES/NO), X-Cache (TCP_HIT, TCP_MISS, etc.)
	if strings.Contains(xCache, "tcp_hit") {
		return true
	}

	// Varnish: X-Varnish header (contains request ID, also X-Cache can be HIT/MISS)
	// Age header: If Age > 0, it was likely served from cache.
	if headers.Get("Age") != "" && headers.Get("Age") != "0" {
		// TODO: Parse Age to ensure it's a valid positive number
		return true
	}

	return false
}

// BodiesAreSimilar checks if two byte slices (response bodies) are similar based on a threshold.
// This is a placeholder for a more sophisticated diffing or similarity check (e.g., Levenshtein distance, Jaccard index on tokens).
// For now, it does a simple exact match if threshold is 1.0, or contains if threshold < 1.0 (very basic).
func BodiesAreSimilar(b1, b2 []byte, threshold float64) bool {
	if b1 == nil && b2 == nil {
		return true
	}
	if b1 == nil || b2 == nil {
		return false
	}
	if threshold >= 1.0 {
		return bytes.Equal(b1, b2)
	}
	if threshold <= 0.0 {
		return bytes.Contains(b1, b2) || bytes.Contains(b2, b1)
	}
	if bytes.Equal(b1, b2) { 
        return true
    }
	// fmt.Printf("Warning: BodiesAreSimilar actual fuzzy comparison for threshold %f not yet implemented. Defaulting to false unless bodies are equal.\n", threshold)
	return false
}

var (
	payloadCounter int32
	payloadRand    *rand.Rand
	payloadMu      sync.Mutex
)

func init() {
	// Initialize with a random seed for more varied payloads across runs, but determinism within a run for the counter part.
	payloadRand = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// GenerateUniquePayload creates a unique string for testing reflections.
// Example: hemlock-payload-123-aB7xZ
func GenerateUniquePayload(baseString string) string {
	atomic.AddInt32(&payloadCounter, 1)
	
	payloadMu.Lock()
	randomSuffix := make([]byte, 5)
	payloadRand.Read(randomSuffix) // Generate some random bytes
	payloadMu.Unlock()
	
	// Simple encoding for random bytes to make them more URL/Header friendly if needed, though not strictly necessary for this example.
	// Using hex for simplicity here.
	return fmt.Sprintf("%s-%d-%x", baseString, atomic.LoadInt32(&payloadCounter), randomSuffix)
}

// TODO: Add functions for parsing specific cache headers, generating unique payloads, etc. 