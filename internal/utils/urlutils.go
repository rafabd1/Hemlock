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
	defaultIgnoredExtensions := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot", // Common web assets
		".map",                         // Source maps
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", // Documents
		".zip", ".tar", ".gz", ".rar", // Archives
		".mp4", ".avi", ".mov", ".webm", // Video
		".mp3", ".wav", ".ogg", // Audio
		".ico",                                                        // Favicons
		".css", // Stylesheets
		".js",  // JavaScript files
		".json", // JSON data files, often static or API responses not typically a direct target for this tool's header/param based WCP on base URL
		".txt", // Text files
		".xml", // XML files, including sitemaps etc.
		".d.ts", ".ts", ".tsx", // TypeScript/JavaScript specific build/type files
		".vue", ".svelte", // Framework specific files
	}
	lowerIgnoredExtensions := make([]string, len(defaultIgnoredExtensions))
	for i, ext := range defaultIgnoredExtensions {
		lowerIgnoredExtensions[i] = strings.ToLower(ext)
	}

	// Keywords that often precede dynamic content identifiers (like IDs or slugs)
	// These are used to normalize paths for grouping similar template URLs.
	genericKeywords := []string{
		// Content Types
		"article", "articles", "post", "posts", "blog", "news",
		"item", "items", "product", "products", "prd", "shop", "store",
		"doc", "docs", "document", "documents", "file", "files", "asset", "assets",
		"image", "images", "gallery", "photo", "photos", "video", "videos", "media",
		"event", "events", "release", "releases", "pr", // "pr" for pull request or press release pages

		// Structure & Navigation
		"category", "categories", "collection", "collections", "tag", "tags", "topic", "topics", "archive", "archives",
		"section", "sections", "page", "pages", "app", "module", "components", // "component" might be too generic alone for some frameworks
		"view", "show", "display", "browse",
		"detail", "details", "list", "listing",

		// User Related
		"user", "users", "profile", "profiles", "member", "members", "author", "authors", "account", "accounts", "customer", "customers",

		// Support & Info
		"kb", "knowledgebase", "faq", "help", "guide", "tutorial", "solution", "solutions", "support", // "support" added, use with path logic

		// Community & Interaction
		"thread", "threads", "forum", "forums", "comment", "comments", "discussion", "discussions", "issue", "issues",

		// Services & Actions
		"service", "services", "tool", "tools", "api", "job", "jobs", "task", "tasks",
		// "download", "upload", // Might be too specific or part of file names
		// "search", "query", // Often have query params, path itself might be stable

		// Location/Organization
		"location", "locations", "branch", "branches", "office", "offices", "department", "departments",

		// E-commerce / Generic
		"order", "orders", "id", "ref", "resource", "entity",
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
				// Only skip if it has an ignored extension AND no query parameters.
				if parsedForExtCheck.RawQuery == "" {
					logger.Debugf("URL '%s' skipped: ignored extension '%s' and no query parameters.", rawURL, currentExtension)
					continue
				} else {
					logger.Debugf("URL '%s' NOT skipped despite ignored extension '%s' because it has query parameters: '%s'", rawURL, currentExtension, parsedForExtCheck.RawQuery)
					// If it has query parameters, do not skip based on extension.
				}
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

		// --- Advanced Path Normalization ---
		originalPathForLog := u.Path
		pathNormalized := false

		pathSegments := strings.Split(strings.Trim(u.Path, "/"), "/")
		// Handle empty path or path with only "/" which results in pathSegments like [""]
		if len(pathSegments) == 1 && pathSegments[0] == "" {
			// This is a root path (e.g., "/"), no keyword normalization needed for segments.
		} else {
			for i, segment := range pathSegments {
				segLower := strings.ToLower(segment)
				for _, keyword := range genericKeywords {
					if segLower == keyword {
						// If this segment is a keyword AND it's not the last segment in the path
						// (meaning there is likely an ID or further sub-path after it)
						// OR if it IS the last segment BUT the keyword itself often represents a template base (e.g. /products/)
						// For now, sticking to the more conservative "not the last segment" to avoid over-truncating.
						// Consider a flag or more sophisticated logic if /products/ itself should be distinct from /products/item123.
						// The current goal is to group /products/item123 and /products/item456 into /products/ for phase 1 base URL checks.
						if i < len(pathSegments)-1 {
							// Normalize path to /path/to/.../keyword/
							// Reconstruct path up to and including the keyword segment
							// Ensure leading slash, and segments joined by slashes, plus a trailing slash.
							normalizedPath := "/" + strings.Join(pathSegments[:i+1], "/") + "/"
							// Use path.Clean to handle potential double slashes like "//" if a segment was empty,
							// and to ensure a canonical path representation.
							u.Path = path.Clean(normalizedPath)

							// path.Clean might remove the trailing slash if the path is just "/".
							// Ensure the trailing slash is present for consistency, unless it's the root path.
							if u.Path != "/" && !strings.HasSuffix(u.Path, "/") {
								u.Path += "/"
							}
							pathNormalized = true
							break // Keyword found and path normalized, exit keyword loop
						}
					}
				}
				if pathNormalized {
					break // Path normalized, exit path segment loop
				}
			}
		}
		
		if pathNormalized {
			logger.Debugf("Path for URL '%s' normalized from '%s' to '%s' for grouping.", rawURL, originalPathForLog, u.Path)
		}
		// --- End of Advanced Path Normalization ---


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