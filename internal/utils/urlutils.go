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

// PreprocessAndGroupURLs normalizes URLs, extracts base URLs, and groups their query parameters.
// It returns a map of base URLs to a list of their original query parameter sets,
// a sorted list of unique base URLs, the total count of query parameters found across all sets,
// and the count of base URLs that have parameters.
func PreprocessAndGroupURLs(rawURLs []string, logger Logger) (map[string][]map[string]string, []string, int, int) {
	groupedParams := make(map[string][]map[string]string)
	baseURLExistence := make(map[string]struct{})
	var uniqueBaseURLs []string
	totalQueryParametersFound := 0
	baseURLsWithParamsCount := 0

	if logger == nil {
		// Provide a no-op logger if nil is passed to prevent panics
		logger = &NoOpLogger{}
	}

	// Define a default list of extensions to ignore for cache poisoning tests
	// TODO: This list could be made configurable in the future
	defaultIgnoredExtensions := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot", // Common web assets
		".map",                         // Source maps
		".xml", ".json", ".txt",       // Common data files (unless specifically targeted)
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", // Documents
		".zip", ".tar", ".gz", ".rar", // Archives
		".mp4", ".avi", ".mov", ".webm", // Video
		".mp3", ".wav", ".ogg", // Audio
		".ico",                                                        // Favicons
		".d.ts", ".ts", ".tsx", ".jsx", // TypeScript/JavaScript specific build/type files
		".vue", ".svelte", // Framework specific files
		// Consider adding more based on typical non-HTML, non-dynamic content
	}
	lowerIgnoredExtensions := make([]string, len(defaultIgnoredExtensions))
	for i, ext := range defaultIgnoredExtensions {
		lowerIgnoredExtensions[i] = strings.ToLower(ext)
	}

	for _, rawURL := range rawURLs {
		// Attempt to parse the raw URL early to check its extension first
		parsedForExtCheck, errExtCheck := url.Parse(rawURL)
		if errExtCheck != nil {
			logger.Warnf("Skipping URL due to initial parse error (for extension check): %s, error: %v", rawURL, errExtCheck)
			continue
		}

		// Filter by extension
		currentExtension := strings.ToLower(path.Ext(parsedForExtCheck.Path))
		if currentExtension != "" { // Only check if there is an extension
			isIgnored := false
			for _, ignoredExt := range lowerIgnoredExtensions {
				if currentExtension == ignoredExt {
					isIgnored = true
					break
				}
			}
			if isIgnored {
				logger.Debugf("Filtering out URL %s due to ignored extension: %s", rawURL, currentExtension)
				continue
			}
		}

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

		// Construct base URL (scheme + host + path)
		baseURL := &url.URL{
			Scheme: u.Scheme,
			Host:   u.Host,
			Path:   u.Path,
		}
		baseString := baseURL.String()

		queryParamsMap := make(map[string]string)
		originalURLParsed, parseErr := url.Parse(rawURL)
		if parseErr == nil {
			for k, v := range originalURLParsed.Query() {
				if len(v) > 0 {
					queryParamsMap[k] = v[0]
				}
			}
		}

		if _, exists := baseURLExistence[baseString]; !exists {
			baseURLExistence[baseString] = struct{}{}
			uniqueBaseURLs = append(uniqueBaseURLs, baseString)
		}
		groupedParams[baseString] = append(groupedParams[baseString], queryParamsMap)
	}

	sort.Strings(uniqueBaseURLs)

	// Deduplicate parameter sets and count parameters
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

	logger.Infof("Preprocessed URLs. Found %d unique base URLs after filtering.", len(uniqueBaseURLs)) // Updated log
	logger.Debugf("Total query parameters found across all unique sets: %d", totalQueryParametersFound)
	logger.Debugf("Number of base URLs with parameters: %d", baseURLsWithParamsCount)

	for _, base := range uniqueBaseURLs {
		logger.Debugf("Base URL: %s, has %d unique parameter sets.", base, len(groupedParams[base]))
	}

	return groupedParams, uniqueBaseURLs, totalQueryParametersFound, baseURLsWithParamsCount
}

// NoOpLogger is a logger that does nothing, useful for utility functions
// where a logger might not always be provided.
type NoOpLogger struct{}

func (l *NoOpLogger) Debugf(format string, args ...interface{}) {}
func (l *NoOpLogger) Infof(format string, args ...interface{})  {}
func (l *NoOpLogger) Warnf(format string, args ...interface{})  {}
func (l *NoOpLogger) Errorf(format string, args ...interface{}) {}
func (l *NoOpLogger) Fatalf(format string, args ...interface{}) {} 