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

// IsCacheable checks HTTP response headers to determine if the content is likely cacheable.
// It considers Cache-Control, Pragma, and Expires headers.
// Returns true if cacheable, false otherwise.
func IsCacheable(resp *http.Response) bool {
	if resp == nil {
		return false
	}

	// Check Cache-Control header
	ccHeader := resp.Header.Get("Cache-Control")
	if ccHeader != "" {
		directives := strings.Split(ccHeader, ",")
		for _, directive := range directives {
			d := strings.ToLower(strings.TrimSpace(directive))
			// Explicitly non-cacheable directives
			if d == "no-store" || d == "no-cache" || d == "private" {
				return false
			}
			// If max-age is present and is 0, it's effectively not cacheable for fresh responses.
			if strings.HasPrefix(d, "max-age=") {
				if parts := strings.Split(d, "="); len(parts) == 2 {
					if parts[1] == "0" {
						return false
					}
				}
			}
		}
	}

	// Check Pragma header (less priority than Cache-Control)
	// According to RFC 7234, Cache-Control takes precedence over Pragma.
	// So, if Cache-Control is present and doesn't forbid caching, Pragma: no-cache might be ignored by modern caches.
	// However, some older caches might still honor it. For a conservative check, we can include it.
	if ccHeader == "" { // Only check Pragma if Cache-Control is not set or is inconclusive for "no-cache"
		pragmaHeader := resp.Header.Get("Pragma")
		if strings.ToLower(pragmaHeader) == "no-cache" {
			return false
		}
	}

	// Check Expires header (even less priority if Cache-Control: max-age is present)
	// An Expires date in the past means the content is stale.
	// If Cache-Control max-age is present, it usually overrides Expires.
	expiresHeader := resp.Header.Get("Expires")
	if expiresHeader != "" {
		// Heuristic: if Cache-Control is missing or doesn't specify max-age, check Expires.
		hasMaxAge := false
		if ccHeader != "" {
			directives := strings.Split(ccHeader, ",")
			for _, directive := range directives {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(directive)), "max-age=") {
					hasMaxAge = true
					break
				}
			}
		}

		if !hasMaxAge {
			expiresTime, err := http.ParseTime(expiresHeader)
			if err == nil { // If parsing is successful
				// A common way to indicate "already expired" is '0' or '-1'.
				if expiresHeader == "0" || expiresHeader == "-1" {
					return false
				}
				if expiresTime.Before(time.Now()) {
					return false // Expired
				}
			} else {
				// If Expires is present but malformed, some caches might treat it as non-cacheable or expired.
				// For a conservative approach, we might consider it non-cacheable.
				// However, RFC 7234 states "A cache recipient MUST interpret invalid date formats, especially the value "0", as representing a time in the past (i.e., "already expired")."
				// So, if parse fails and it's not "0" or "-1", the behavior is less defined.
				// Let's assume malformed (and not 0/-1) doesn't strictly mean "do not cache" unless it parses to past.
				// For simplicity, if it's not 0 or -1 and fails to parse, we don't make a strong "false" claim here,
				// letting other conditions (like absence of positive caching headers) decide.
			}
		}
	}
	
	// Check Vary header for Vary: *
	varyHeader := resp.Header.Get("Vary")
	if varyHeader == "*" {
		return false
	}


	// Default to true if no explicit non-cacheable directives are found.
	// This assumes that if a response doesn't say "don't cache", it might be cached by some intermediary proxy,
	// especially if it has cache-friendly status codes (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).
	// A more advanced version could also check the status code.
	return true
}

// BodyContains checks if a substring is present in a byte slice (e.g., response body).
func BodyContains(body []byte, substring []byte) bool {
	if body == nil || substring == nil {
		return false
	}
	return bytes.Contains(body, substring)
}

// HeadersContain checks if a substring is present in any of the values of the provided HTTP headers.
// It performs a case-insensitive check for the substring within header values.
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

// IsCacheHit checks HTTP response headers for common indicators of a cache hit.
// It looks at headers like X-Cache, CF-Cache-Status, Age, and Server-Timing.
// Returns true if a cache hit is strongly indicated, false otherwise.
func IsCacheHit(resp *http.Response) bool {
	if resp == nil {
		return false
	}

	// Check X-Cache header (common)
	xCache := strings.ToLower(resp.Header.Get("X-Cache"))
	if strings.Contains(xCache, "hit") {
		// Also check it doesn't say miss, e.g. "miss, hit" or some other complex value
		if !strings.Contains(xCache, "miss") { // Simple check, could be more robust
			return true
		}
	}

	// Check X-Cache-Lookup header (common)
	xCacheLookup := strings.ToLower(resp.Header.Get("X-Cache-Lookup"))
	if strings.Contains(xCacheLookup, "hit") {
		if !strings.Contains(xCacheLookup, "miss") {
			return true
		}
	}

	// Check CF-Cache-Status header (Cloudflare)
	cfCacheStatus := strings.ToUpper(resp.Header.Get("CF-Cache-Status"))
	switch cfCacheStatus {
	case "HIT", "UPDATING", "REVALIDATED": // UPDATING and REVALIDATED often mean a hit while stale content is updated
		return true
	}

	// Check Age header
	// An Age header with a value > 0 indicates the response was served from cache.
	ageHeader := resp.Header.Get("Age")
	if ageHeader != "" {
		age, err := parseInt(ageHeader) // Helper to parse int safely
		if err == nil && age > 0 {
			return true
		}
	}

	// Check Server-Timing header for cdn-cache; desc=HIT or similar
	serverTiming := resp.Header.Get("Server-Timing")
	if serverTiming != "" {
		// Example: cdn-cache; desc=HIT, other-metric; dur=123
		// A more robust parser might be needed for complex Server-Timing values.
		lowerServerTiming := strings.ToLower(serverTiming)
		if strings.Contains(lowerServerTiming, "cdn-cache") || strings.Contains(lowerServerTiming, "edge-cache") {
			if strings.Contains(lowerServerTiming, "hit") || strings.Contains(lowerServerTiming, "desc=hit") {
				return true
			}
		}
	}

	// Add checks for other common cache headers if needed:
	// X-Cache-Status, X-Served-By-Cache-Status, X-Vercel-Cache, etc.
	// Example for a generic check (can be made more specific):
	otherCacheHeaders := []string{"X-Cache-Status", "X-Served-By-Cache-Status", "X-Vercel-Cache", "X-Proxy-Cache"}
	for _, hName := range otherCacheHeaders {
		hValue := strings.ToLower(resp.Header.Get(hName))
		if strings.Contains(hValue, "hit") {
			if !strings.Contains(hValue, "miss") { // Avoid cases like "TCP_MISS_HIT"
				return true
			}
		}
	}

	return false
}

// parseInt is a simple helper to parse a string to an int.
// Returns 0 and error if parsing fails.
func parseInt(s string) (int, error) {
	var i int
	_, err := fmt.Sscan(s, &i)
	return i, err
}

// BodiesAreSimilar checks if two byte slices (response bodies) are similar based on a threshold.
// threshold is a value between 0.0 (no similarity) and 1.0 (exact match).
// This is a basic implementation focusing on length and exact match for now.
// More sophisticated content similarity (e.g., Levenshtein distance, Jaccard index) can be added later.
func BodiesAreSimilar(bodyA []byte, bodyB []byte, threshold float64) bool {
	if threshold < 0.0 || threshold > 1.0 {
		// Invalid threshold, perhaps log a warning or default to a sane value (e.g., exact match)
		// For now, let's treat an invalid threshold as requiring an exact match for safety.
		threshold = 1.0
	}

	if bytes.Equal(bodyA, bodyB) {
		return true // Exact match is always similar
	}

	// If threshold requires exact match and they are not equal, return false.
	if threshold == 1.0 {
		return false
	}

	// Calculate length similarity
	lenA := len(bodyA)
	lenB := len(bodyB)

	if lenA == 0 && lenB == 0 {
		return true // Two empty bodies are similar
	}
	if lenA == 0 || lenB == 0 {
		// If one is empty and the other is not, similarity depends on threshold
		// e.g., if threshold is very low (e.g. 0.1), a small body vs empty might be considered similar.
		// For now, let's be a bit stricter: if one is empty, they are only similar if the other is also very small relative to threshold.
		// This logic can be refined. A simple approach: if one is empty, they are dissimilar unless threshold is 0.
		return threshold == 0.0 // Or handle based on the length of the non-empty body vs threshold needs
	}

	// Calculate length similarity
	var maxLen, minLen int
	if lenA > lenB {
		maxLen = lenA
		minLen = lenB
	} else {
		maxLen = lenB
		minLen = lenA
	}

	lengthSimilarity := float64(minLen) / float64(maxLen)

	if lengthSimilarity < threshold {
		return false // Length difference is too high, definitely not similar enough
	}

	// If we reach here, lengths are somewhat similar according to the threshold.
	// Now, for thresholds less than 1.0, we perform a basic content comparison on the common part.
	if threshold < 1.0 { // This was already checked, but good for clarity
		if minLen == 0 { // Both were empty, already handled by bytes.Equal or lenA == 0 && lenB == 0
			return true // Or false if threshold is >0 and one is empty - current logic: true if both 0,0
		}
		diffBytes := 0
		for i := 0; i < minLen; i++ {
			if bodyA[i] != bodyB[i] {
				diffBytes++
			}
		}
		// Similarity of the overlapping part (minLen)
		contentMatchRatio := float64(minLen-diffBytes) / float64(minLen)
		
		// The overall similarity could be a combination, but for now:
		// We already passed the lengthSimilarity check for the overall bodies.
		// Now, we check if the content of the common prefix (minLen) meets the threshold.
		return contentMatchRatio >= threshold
	}

	// This point should only be reached if threshold is 1.0 and bytes.Equal was false, 
	// or if threshold was < 1.0 but lengthSimilarity passed and then contentMatchRatio also passed.
	// If threshold is 1.0, it's already returned false. 
	// If threshold < 1.0, the decision is made by the contentMatchRatio comparison.
	// Thus, this is a fallback which implies an earlier condition should have caught it.
	// However, if lengthSimilarity >= threshold AND threshold < 1.0, AND contentMatchRatio < threshold, then it should be false.
	// The current structure returns true from `contentMatchRatio >= threshold` or proceeds.
	// Let's simplify: if it passed length similarity, the contentMatchRatio decides for threshold < 1.0.

	return false // Default fallback if no other condition for similarity is met.
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

// AnalyzeHeaderChanges compares critical headers between a baseline and a probe response,
// looking for changes influenced by a relevantToken (derived from an injected value).
// Currently focuses on the 'Location' header.
// Returns true and a description if a relevant change is found, otherwise false and an empty string.
func AnalyzeHeaderChanges(baselineHeaders http.Header, probeAHeaders http.Header, relevantToken string) (bool, string) {
	if probeAHeaders == nil || relevantToken == "" {
		return false, ""
	}

	// Check Location header in Probe A
	probeALocation := probeAHeaders.Get("Location")

	if probeALocation != "" && strings.Contains(probeALocation, relevantToken) {
		// Location header in Probe A contains the relevant token.
		// Now compare with baseline.
		baselineLocation := "" // Default if baseline has no Location header
		if baselineHeaders != nil {
			baselineLocation = baselineHeaders.Get("Location")
		}

		if probeALocation != baselineLocation {
			description := fmt.Sprintf("Location header changed from '%s' to '%s', influenced by token '%s'.", baselineLocation, probeALocation, relevantToken)
			return true, description
		}
	}

	// TODO: Extend to check other critical headers like Link, Refresh, Content-Security-Policy, Set-Cookie (for path/domain attributes influenced by token)

	return false, ""
}

// TODO: Add functions for parsing specific cache headers, generating unique payloads, etc. 