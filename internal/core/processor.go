package core

import (
	"fmt"
	// "bytes" // Will be needed for comparing bodies, etc.

	"github.com/rafabd1/Hemlock/internal/config"
	// "github.com/rafabd1/Hemlock/internal/networking" // For response types, if not abstracting enough
	"net/http" // For http.Header manipulation

	"github.com/rafabd1/Hemlock/internal/report"
	"github.com/rafabd1/Hemlock/internal/utils"
)

// ProbeData encapsulates the information from a single HTTP probe (request/response pair).
// This helps in passing around related data cleanly.
type ProbeData struct {
	URL            string
	RequestHeaders http.Header // Headers sent in the request for this probe
	Response       *http.Response    // The raw HTTP response
	Body           []byte            // The response body
	RespHeaders    http.Header       // Parsed response headers
	Error          error             // Any error encountered during this specific probe
}

// Processor handles the logic for analyzing HTTP responses to detect cache poisoning vulnerabilities.
// This includes checking for unkeyed inputs and reflected payloads.
type Processor struct {
	config *config.Config
	logger utils.Logger
	// Potentially add a list of known cache headers or patterns here if needed for IsCacheable checks.
}

// NewProcessor creates a new Processor instance.
func NewProcessor(cfg *config.Config, logger utils.Logger) *Processor {
	return &Processor{
		config: cfg,
		logger: logger,
	}
}

// AnalyzeProbes is the core detection logic.
// It takes data from a baseline request, a probe with a modified header (Probe A),
// and a subsequent cache check request (Probe B).
// It returns a Finding if a potential cache poisoning vulnerability is detected.
func (p *Processor) AnalyzeProbes(targetURL string, headerName string, injectedValue string, baseline ProbeData, probeA ProbeData, probeB ProbeData) (*report.Finding, error) {
	p.logger.Debugf("Processor analyzing probes for URL: %s, Header: %s, Value: %s", targetURL, headerName, injectedValue)

	// --- Basic Sanity Checks & Error Handling ---
	if baseline.Error != nil {
		// If baseline itself failed significantly, it's hard to compare.
		// The scheduler might have already logged this, but processor can also note it.
		p.logger.Warnf("Baseline probe for %s had an error: %v. Analysis might be unreliable.", targetURL, baseline.Error)
		// Depending on strategy, we might return early or try to proceed with caution.
	}
	if probeA.Error != nil {
		p.logger.Warnf("Probe A (header %s:%s) for %s had an error: %v.", headerName, injectedValue, targetURL, probeA.Error)
		// If Probe A fails, we can't know if the header had an effect.
		return nil, fmt.Errorf("probe A failed: %w", probeA.Error)
	}
	if probeB.Error != nil {
		p.logger.Warnf("Probe B (cache check for %s after header %s:%s) had an error: %v.", targetURL, headerName, injectedValue, probeB.Error)
		// If Probe B fails, we can't confirm caching behavior.
		return nil, fmt.Errorf("probe B failed: %w", probeB.Error)
	}

	// --- Heuristic 1: Unkeyed Header Input Leads to Content Reflection in Cache (Classic Poisoning) ---
	// Condition: 
	// 1. Probe A's response (with injected header) shows the injectedValue.
	// 2. Probe B's response (cache check, no injected header) ALSO shows injectedValue from Probe A.
	// 3. Probe B's response indicates a cache HIT (or is substantially similar to Probe A's cacheable response).

	reflectedInA_Body := utils.BodyContains(probeA.Body, []byte(injectedValue))
	reflectedInA_Headers := utils.HeadersContain(probeA.RespHeaders, injectedValue)

	if !reflectedInA_Body && !reflectedInA_Headers {
		p.logger.Debugf("Injected value '%s' for header '%s' not reflected in Probe A's response for %s.", injectedValue, headerName, targetURL)
		return nil, nil // Not reflected, so cannot be used for this type of poisoning
	}
	p.logger.Debugf("Injected value '%s' REFLECTED in Probe A for %s (Body: %t, Headers: %t).", injectedValue, targetURL, reflectedInA_Body, reflectedInA_Headers)

	// Now check Probe B (cache check)
	reflectedInB_Body := utils.BodyContains(probeB.Body, []byte(injectedValue))
	reflectedInB_Headers := utils.HeadersContain(probeB.RespHeaders, injectedValue)

	if reflectedInB_Body || reflectedInB_Headers {
		p.logger.Infof("POTENTIAL POISONING: Injected value '%s' from Probe A (header %s) found in Probe B (cache check) for %s.", injectedValue, headerName, targetURL)

		// Further check if Probe B was likely a cache hit from Probe A's response content.
		// This can be complex. Simplistic checks:
		// - Probe B has X-Cache: HIT (or similar CDN headers like CF-Cache-Status: HIT)
		// - Probe B's content is identical/very similar to Probe A's content (if Probe A was cacheable)
		probeB_isCacheHit := utils.IsCacheHit(probeB.RespHeaders)
		probeA_wasCacheable := utils.IsCacheable(probeA.RespHeaders)

		description := fmt.Sprintf("Header '%s' with value '%s' was reflected in the response. A subsequent request (Probe B) also contained this injected value.", headerName, injectedValue)
		evidence := fmt.Sprintf("Probe A reflected: Body=%t, Headers=%t. Probe B reflected: Body=%t, Headers=%t. Probe A cacheable: %t. Probe B cache HIT: %t.",
			reflectedInA_Body, reflectedInA_Headers, reflectedInB_Body, reflectedInB_Headers, probeA_wasCacheable, probeB_isCacheHit)

		if probeB_isCacheHit || (probeA_wasCacheable && utils.BodiesAreSimilar(probeA.Body, probeB.Body, 0.95)) {
			return &report.Finding{
				URL:           targetURL,
				Vulnerability: "Web Cache Poisoning via Unkeyed Header",
				Description:   description + " The cache appears to have served the poisoned content.",
				UnkeyedInput:  headerName,
				Payload:       injectedValue,
				Evidence:      evidence,
			}, nil
		} else {
			// Reflection seen in B, but cache HIT status is unclear. Could be a weaker finding or needs more checks.
			p.logger.Debugf("Value reflected in Probe B for %s, but cache HIT status is not definitive. Probe A cacheable: %t, Probe B cache HIT headers: %t", targetURL, probeA_wasCacheable, probeB_isCacheHit)
			// Potentially return a lower severity finding or just log for now
			return &report.Finding{
				URL:           targetURL,
				Vulnerability: "Potential Web Cache Deception/Poisoning (Unconfirmed Cache Hit)",
				Description:   description + " The cache HIT status for Probe B was not definitively confirmed, but reflection occurred.",
				UnkeyedInput:  headerName,
				Payload:       injectedValue,
				Evidence:      evidence,
			}, nil
		}
	}

	// --- Heuristic 2: Unkeyed Header Influences Other Cacheable Content (e.g., X-Forwarded-Host changing links) ---
	// Condition:
	// 1. Probe A's response (with injected header) differs significantly from Baseline's response in a way that's not just the direct reflection.
	//    (e.g., links in the page now point to evil.com because X-Forwarded-Host was set to evil.com)
	// 2. Probe B's response (cache check) matches Probe A's (different) response and indicates a cache HIT.
	// This requires more complex diffing of responses (HTML structure, specific header values like Location, etc.)
	p.logger.Debugf("Checking for indirect poisoning for %s with header %s... (TODO)", targetURL, headerName)

	// TODO: Implement differential analysis between baseline.Body/Headers and probeA.Body/Headers.
	// If differences are found (e.g., new links, changed resource URLs) that use `injectedValue` or a derivative:
	//   Then check if probeB.Body/Headers match probeA.Body/Headers and probeB indicates cache HIT.
	//   If so, this is a finding.

	p.logger.Debugf("No definitive cache poisoning vector found for %s with header %s by current heuristics.", targetURL, headerName)
	return nil, nil // No finding based on current simple heuristics
}

// Note: The following utility function stubs need to be implemented in the utils package (e.g., internal/utils/analysishelpers.go or httphelpers.go)
// func BodyContains(body []byte, substring []byte) bool { ... }
// func HeadersContain(headers http.Header, substring string) bool { ... }
// func IsCacheHit(headers http.Header) bool { ... }
// func BodiesAreSimilar(b1, b2 []byte, threshold float64) bool { ... } 