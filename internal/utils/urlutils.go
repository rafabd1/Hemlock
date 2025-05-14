package utils

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

// normalizeURL normalizes a URL for more effective deduplication.
// It converts the scheme and host to lowercase, removes 'www.' prefix from the host,
// and sorts query parameters.
func normalizeURL(rawURL string, logger Logger) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		logger.Debugf("Failed to parse URL for normalization: %s, error: %v", rawURL, err)
		return rawURL, err // Return original on parse error
	}

	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	host = strings.TrimPrefix(host, "www.")
	u.Host = host

	// Sort query parameters
	if u.RawQuery != "" {
		query := u.Query()
		sortedQuery := make(url.Values)
		var keys []string
		for k := range query {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			// Sort values for each key as well, for stricter normalization
			values := query[k]
			sort.Strings(values)
			for _, v := range values {
				sortedQuery.Add(k, v) // Add preserves order for multiple values of same key
			}
		}
		u.RawQuery = sortedQuery.Encode()
	}

	return u.String(), nil
}

// PreprocessURLs filters and deduplicates a list of URLs.
// - Normalizes URLs for better deduplication.
// - Removes exact duplicates after normalization.
// - Filters out URLs with specified (case-insensitive) file extensions.
func PreprocessURLs(rawURLs []string, ignoredExtensions []string, stripWWW bool, logger Logger) []string {
	if len(rawURLs) == 0 {
		return []string{}
	}

	processedURLs := make(map[string]bool)
	var resultURLs []string
	var lowerIgnoredExtensions []string
	for _, ext := range ignoredExtensions {
		lowerIgnoredExtensions = append(lowerIgnoredExtensions, strings.ToLower(ext))
	}

	logger.Infof("Starting preprocessing for %d raw URLs.", len(rawURLs))

	for _, rawURL := range rawURLs {
		u, err := url.Parse(rawURL)
		if err != nil {
			logger.Warnf("Skipping URL due to parse error during preprocessing: %s, error: %v", rawURL, err)
			continue
		}

		// Filter by extension
		ext := strings.ToLower(path.Ext(u.Path))
		isIgnored := false
		for _, ignoredExt := range lowerIgnoredExtensions {
			if ext == ignoredExt {
				isIgnored = true
				break
			}
		}
		if isIgnored {
			logger.Debugf("Filtering out URL %s due to ignored extension: %s", rawURL, ext)
			continue
		}

		// Normalize for deduplication
		// The stripWWW logic is now handled within normalizeURL's host processing if needed,
		// but the parameter can be kept if we want to make it more explicit or configurable elsewhere.
		// For now, normalizeURL will always trim 'www.' for consistent deduplication.
		normalizedURL, err := normalizeURL(rawURL, logger)
		if err != nil {
			// Already logged in normalizeURL, or could log again if we want specific context here
			// For simplicity, assume it's logged. We might still want to add the rawURL if it wasn't processed.
			// Let's add the non-normalized version if normalization fails to avoid losing it entirely,
			// unless the error from normalizeURL suggests it's fundamentally invalid.
			// Current normalizeURL returns original on parse error, so it's fine.
		}


		if _, exists := processedURLs[normalizedURL]; !exists {
			processedURLs[normalizedURL] = true
			resultURLs = append(resultURLs, rawURL) // Add the original URL that passed filters
		} else {
			logger.Debugf("Duplicate URL (after normalization) filtered out: %s (normalized to %s)", rawURL, normalizedURL)
		}
	}

	logger.Infof("Finished preprocessing. %d URLs remain after filtering and deduplication.", len(resultURLs))
	return resultURLs
}

// ExtractRelevantToken attempts to extract a meaningful token from an injected value.
// If the value parses as a URL with a hostname, the hostname is returned.
// Otherwise, the original value is returned.
func ExtractRelevantToken(injectedValue string) string {
	if injectedValue == "" {
		return ""
	}
	u, err := url.Parse(injectedValue)
	if err == nil && u != nil && u.Hostname() != "" {
		// It's a URL and has a hostname, return the hostname
		return u.Hostname()
	}
	// Not a URL with a clear hostname, or parsing failed; return the original value
	return injectedValue
} 