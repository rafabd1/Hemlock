package utils

import (
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/rafabd1/Hemlock/internal/config"
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

// PreprocessAndGroupURLs normalizes URLs, extracts base URLs, and groups their query parameters.
// It returns a map of base URLs to a list of their original query parameter sets,
// a sorted list of unique base URLs, the total count of query parameters found across all sets,
// and the count of base URLs that have parameters.
func PreprocessAndGroupURLs(rawURLs []string, cfg *config.Config, logger Logger) (map[string][]map[string]string, []string, int, int) {
	groupedParams := make(map[string][]map[string]string)
	baseURLExistence := make(map[string]struct{})
	var uniqueBaseURLs []string
	totalQueryParametersFound := 0
	baseURLsWithParamsCount := 0

	if logger == nil {
		// Provide a no-op logger if nil is passed to prevent panics
		logger = &NoOpLogger{}
	}

	// A filtragem por extensão foi removida para permitir testes em assets estáticos,
	// pois eles ainda podem ser vulneráveis a envenenamento de cache baseado em cabeçalho.

	for _, rawURL := range rawURLs {
		normalizedFullURL, err := normalizeURL(rawURL, logger) // Normalizes scheme, host, sorts params etc.
		if err != nil {
			logger.Warnf("Skipping URL due to normalization error: %s, error: %v", rawURL, err)
			continue
		}

		u, err := url.Parse(normalizedFullURL) // Parse the already normalized URL
		if err != nil {
			logger.Warnf("Skipping URL due to parse error after normalization: %s, error: %v", normalizedFullURL, err)
			continue
		}

		// --- New Path Grouping Logic ---
		originalPathForLog := u.Path
		var normalizedPathForGrouping string // Declarada sem inicialização imediata

		// Clean the path to handle redundant slashes and resolve '..' '.'
		cleanedPath := path.Clean(u.Path)

		// Ensure it starts with a slash if it's not empty
		if cleanedPath == "." || cleanedPath == "" { // Path.Clean can return "." for "/" or empty
			cleanedPath = "/"
		} else if !strings.HasPrefix(cleanedPath, "/") {
			cleanedPath = "/" + cleanedPath
		}
		
		pathSegments := strings.Split(strings.Trim(cleanedPath, "/"), "/")
		
		if len(pathSegments) > 1 { // Only truncate if there's more than one segment (e.g. /foo/bar, not /foo or /)
			// Get the parent directory
			normalizedPathForGrouping = path.Dir(cleanedPath)
			// Ensure it ends with a slash for consistency, unless it's the root path
			if normalizedPathForGrouping != "/" && !strings.HasSuffix(normalizedPathForGrouping, "/") {
				normalizedPathForGrouping += "/"
			}
		} else {
			// For root ("/") or single segment paths (e.g., "/segment"), use the cleaned path as is.
			// Ensure single segment paths also end with a slash if they are meant to represent a directory-like base.
			// Example: /segment -> /segment/
			// Root "/" should remain "/"
			if cleanedPath != "/" && !strings.HasSuffix(cleanedPath, "/") {
				normalizedPathForGrouping = cleanedPath + "/"
			} else {
				normalizedPathForGrouping = cleanedPath // Already ends with / or is "/"
			}
		}
		
		// path.Clean might remove the trailing slash from the root path if it was like "//".
		// Ensure root is always just "/"
		if normalizedPathForGrouping == "//" { // Should be handled by path.Clean but as a safeguard
			normalizedPathForGrouping = "/"
		}


		if normalizedPathForGrouping != originalPathForLog {
			logger.Debugf("Path for URL '%s' grouped under '%s' (original: '%s').", rawURL, normalizedPathForGrouping, originalPathForLog)
		}
		u.Path = normalizedPathForGrouping // Use this path for base URL construction
		// --- End of New Path Grouping Logic ---

		// Construct base URL (scheme + host + path)
		baseURL := &url.URL{
			Scheme: u.Scheme,
			Host:   u.Host,
			Path:   u.Path, // Path is now the grouped path
		}
		baseString := baseURL.String()

		queryParamsMap := make(map[string]string)
		originalURLParsed, parseErr := url.Parse(rawURL) // Parse the original rawURL again for its original query params
		if parseErr == nil {
			for k, v := range originalURLParsed.Query() {
				if len(v) > 0 {
					queryParamsMap[k] = v[0] // Taking only the first value for simplicity
				}
			}
		} else {
			logger.Warnf("Could not parse original rawURL '%s' again for query params: %v", rawURL, parseErr)
		}


		if _, exists := baseURLExistence[baseString]; !exists {
			baseURLExistence[baseString] = struct{}{}
			uniqueBaseURLs = append(uniqueBaseURLs, baseString)
		}
		// Store the original query parameters associated with this (potentially new) baseString
		groupedParams[baseString] = append(groupedParams[baseString], queryParamsMap)
	}

	sort.Strings(uniqueBaseURLs)

	// Deduplicate parameter sets for each base URL and count parameters
	tempGroupedParams := make(map[string][]map[string]string)
	for base, paramSets := range groupedParams {
		dedupedSets := []map[string]string{}
		seenSets := make(map[string]struct{})
		currentBaseHasParams := false
		for _, pSet := range paramSets {
			var paramKeys []string
			for k := range pSet {
				paramKeys = append(paramKeys, k)
			}
			sort.Strings(paramKeys)
			var canonicalParts []string
			for _, k := range paramKeys {
				canonicalParts = append(canonicalParts, k+"="+pSet[k])
			}
			canonicalString := strings.Join(canonicalParts, "&")

			if _, seen := seenSets[canonicalString]; !seen {
				seenSets[canonicalString] = struct{}{}
				dedupedSets = append(dedupedSets, pSet)
				if len(pSet) > 0 {
					totalQueryParametersFound += len(pSet)
					currentBaseHasParams = true
				}
			}
		}
		tempGroupedParams[base] = dedupedSets
		if currentBaseHasParams {
			baseURLsWithParamsCount++
		}
	}
	groupedParams = tempGroupedParams // Update with deduped sets

	logger.Debugf("Preprocessed URLs. Found %d unique base URLs after filtering.", len(uniqueBaseURLs)) // Updated log to Debugf
	logger.Debugf("Total query parameters found across all unique sets: %d", totalQueryParametersFound)
	logger.Debugf("Number of base URLs with parameters: %d", baseURLsWithParamsCount)

	return groupedParams, uniqueBaseURLs, totalQueryParametersFound, baseURLsWithParamsCount
}

// NoOpLogger is a logger that performs no operations.
type NoOpLogger struct{}

func (l *NoOpLogger) Debugf(format string, args ...interface{}) {}
func (l *NoOpLogger) Infof(format string, args ...interface{})  {}
func (l *NoOpLogger) Warnf(format string, args ...interface{})  {}
func (l *NoOpLogger) Errorf(format string, args ...interface{}) {}
func (l *NoOpLogger) Fatalf(format string, args ...interface{}) {}
func (l *NoOpLogger) Successf(format string, args ...interface{}) {} 