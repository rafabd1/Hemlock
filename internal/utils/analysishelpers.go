package utils

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// AnalyzeBodyChanges (Fase 2) compares probeABody against baselineBody, a relevantToken,
// and their respective base URLs. It looks for new or modified HTML links/resources in probeABody
// (compared to baselineBody) where the resolved URL contains the relevantToken in its hostname,
// and this hostname differs from the original baseline host.
func AnalyzeBodyChanges(probeABody []byte, baselineBody []byte, relevantToken string, probeAURLstring string, baselineOriginalURLstring string, logger Logger) (bool, string) {
	if len(probeABody) == 0 || relevantToken == "" || probeAURLstring == "" || baselineOriginalURLstring == "" {
		return false, ""
	}

	// It's possible baselineBody is nil if the baseline request failed but we still want to check probeA for absolute exploits.
	// However, for a comparative analysis, baselineBody is essential.
	// For now, this function assumes baselineBody is available for comparison.
	// If baselineBody is empty, linksInBaseline will be empty, and any token-influenced link in probeA will be treated as "new".

	parsedBaselineOriginalURL, err := url.Parse(baselineOriginalURLstring)
	if err != nil {
		logger.Warnf("AnalyzeBodyChanges: Failed to parse baselineOriginalURLstring '%s': %v", baselineOriginalURLstring, err)
		return false, ""
	}
	originalBaselineHost := parsedBaselineOriginalURL.Hostname()

	linksInProbeA := ExtractHTMLLinksAndResources(probeABody, probeAURLstring, logger)
	linksInBaseline := ExtractHTMLLinksAndResources(baselineBody, baselineOriginalURLstring, logger)

	for attrValA, resolvedURLstringA := range linksInProbeA {
		parsedURLA, err := url.Parse(resolvedURLstringA)
		if err != nil {
			// logger.Debugf("AnalyzeBodyChanges: Failed to parse resolved URL from Probe A '%s': %v", resolvedURLstringA, err)
			continue
		}
		hostA := parsedURLA.Hostname()

		if hostA != "" && strings.Contains(hostA, relevantToken) && hostA != originalBaselineHost {
			resolvedURLstringBaseline, existsInBaseline := linksInBaseline[attrValA]

			var description string
			found := false

			if !existsInBaseline {
				description = fmt.Sprintf("New HTML resource attribute '%s' (resolves to '%s' with hostname '%s' containing token '%s') found in Probe A. Original baseline host: '%s'.",
					attrValA, resolvedURLstringA, hostA, relevantToken, originalBaselineHost)
				found = true
			} else if resolvedURLstringA != resolvedURLstringBaseline {
				description = fmt.Sprintf("HTML resource attribute '%s' changed from '%s' in baseline to '%s' (with hostname '%s' containing token '%s') in Probe A. Original baseline host: '%s'.",
					attrValA, resolvedURLstringBaseline, resolvedURLstringA, hostA, relevantToken, originalBaselineHost)
				found = true
			}

			if found {
				logger.Infof("AnalyzeBodyChanges: %s", description)
				return true, description
			}
		}
	}

	return false, ""
}

// ExtractHTMLLinksAndResources parses an HTML body, extracts URLs from common attributes
// (href, src, action, formaction), and resolves them against a given baseURLstring.
// It returns a map where the key is the original attribute value and the value is the
// resolved absolute URL string.
func ExtractHTMLLinksAndResources(body []byte, baseURLstring string, logger Logger) map[string]string {
	result := make(map[string]string)
	if len(body) == 0 || baseURLstring == "" {
		return result
	}

	parsedBaseURL, err := url.Parse(baseURLstring)
	if err != nil {
		logger.Warnf("ExtractHTMLLinksAndResources: Failed to parse baseURLstring '%s': %v", baseURLstring, err)
		return result
	}

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		// Log this, as it might indicate non-HTML content or severely malformed HTML
		logger.Debugf("ExtractHTMLLinksAndResources: Failed to parse HTML body for base URL '%s': %v", baseURLstring, err)
		return result
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			targetAttrs := []string{"href", "src", "action", "formaction"} // Consider adding more like "data", "poster", "cite", "longdesc" if relevant for poisoning vectors
			for _, attrName := range targetAttrs {
				for _, attr := range n.Attr {
					if attr.Key == attrName {
						attrValueOriginal := attr.Val // Keep original value for map key
						attrValueTrimmed := strings.TrimSpace(attrValueOriginal)
						if attrValueTrimmed == "" {
							continue
						}

						// Try to parse the attribute value as a URL component
						uRawAttr, err := url.Parse(attrValueTrimmed)
						if err != nil {
							// logger.Debugf("ExtractHTMLLinksAndResources: Attribute '%s' value '%s' is not a valid URL component for base '%s': %v", attrName, attrValueTrimmed, baseURLstring, err)
							continue // Skip if attribute value itself is not a parseable URL structure
						}

						resolvedAttrURL := parsedBaseURL.ResolveReference(uRawAttr)
						result[attrValueOriginal] = resolvedAttrURL.String()
						break // Found the target attribute key for this tag, move to next attribute or node
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}

	f(doc)
	return result
}

// TODO: Implement more sophisticated DOM diffing or change analysis for Fase 2 of AnalyzeBodyChanges. 