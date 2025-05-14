package utils

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// AnalyzeBodyChanges (Fase 1) compares probeABody against a baseline URL and a relevantToken.
// It looks for the relevantToken appearing in the hostname of resolved URLs within
// common attributes (href, src, action, formaction) of probeABody, where this hostname
// differs from the baselineURL's original hostname.
// baselineMODIFIEDURL is the URL from which probeABody was fetched, used to resolve relative links.
func AnalyzeBodyChanges(probeABody []byte, relevantToken string, baselineMODIFIEDURL string, logger Logger) (bool, string) {
	if len(probeABody) == 0 || relevantToken == "" || baselineMODIFIEDURL == "" {
		return false, ""
	}

	parsedBaselineURL, err := url.Parse(baselineMODIFIEDURL)
	if err != nil {
		logger.Warnf("AnalyzeBodyChanges: Failed to parse baselineMODIFIEDURL '%s': %v", baselineMODIFIEDURL, err)
		return false, ""
	}
	originalHost := parsedBaselineURL.Hostname()

	doc, err := html.Parse(bytes.NewReader(probeABody))
	if err != nil {
		logger.Warnf("AnalyzeBodyChanges: Failed to parse probeABody HTML for URL '%s': %v", baselineMODIFIEDURL, err)
		return false, ""
	}

	var found bool
	var description string

	var f func(*html.Node)
	f = func(n *html.Node) {
		if found { // Optimization: if already found, no need to keep traversing
			return
		}

		if n.Type == html.ElementNode {
			targetAttrs := []string{"href", "src", "action", "formaction"}
			for _, attrName := range targetAttrs {
				for _, attr := range n.Attr {
					if attr.Key == attrName {
						attrValue := strings.TrimSpace(attr.Val)
						if attrValue == "" {
							continue
						}

						// Try to parse the attribute value as a URL component
						uRawAttr, err := url.Parse(attrValue)
						if err != nil {
							// logger.Debugf("AnalyzeBodyChanges: Failed to parse attribute value '%s' for URL '%s': %v", attrValue, baselineMODIFIEDURL, err)
							continue // Skip if attribute value itself is not a parseable URL structure
						}

						// Resolve it against the baselineMODIFIEDURL (which is probeA's URL)
						resolvedAttrURL := parsedBaselineURL.ResolveReference(uRawAttr)
						resolvedHost := resolvedAttrURL.Hostname()

						if resolvedHost != "" && strings.Contains(resolvedHost, relevantToken) {
							if resolvedHost != originalHost {
								logger.Infof("AnalyzeBodyChanges: Token '%s' found in resolved hostname '%s' (from attribute %s.%s='%s') which is different from original host '%s' for baseline URL '%s'.",
									relevantToken, resolvedHost, n.Data, attrName, attrValue, originalHost, baselineMODIFIEDURL)
								found = true
								description = fmt.Sprintf("Token '%s' found in attribute '%s' of tag '<%s>' resulting in a modified hostname '%s' (original host was '%s'). Attribute value: '%s'.",
									relevantToken, attrName, n.Data, resolvedHost, originalHost, attrValue)
								return // Found, stop this branch of recursion
							}
						}
						break // Found the target attribute key, move to next attribute or node
					}
				}
				if found { return }
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
			if found { // Propagate found signal up
				return
			}
		}
	}

	f(doc)

	return found, description
}

// TODO: Implement ExtractLinksAndResources for a more structured approach if needed later.
// TODO: Implement more sophisticated DOM diffing or change analysis for Fase 2 of AnalyzeBodyChanges. 