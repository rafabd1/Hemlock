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

	// Heuristic 1: Direct reflection of injectedValue
	if reflectedInA_Body || reflectedInA_Headers {
		p.logger.Debugf("Injected value '%s' REFLECTED in Probe A for %s (Body: %t, Headers: %t).", injectedValue, targetURL, reflectedInA_Body, reflectedInA_Headers)

		// Now check Probe B (cache check)
		reflectedInB_Body := utils.BodyContains(probeB.Body, []byte(injectedValue))
		reflectedInB_Headers := utils.HeadersContain(probeB.RespHeaders, injectedValue)

		if reflectedInB_Body || reflectedInB_Headers {
			p.logger.Infof("HEURISTIC 1: Injected value '%s' from Probe A (header %s) found in Probe B (cache check) for %s.", injectedValue, headerName, targetURL)

			probeB_isCacheHit := utils.IsCacheHit(probeB.Response)
			probeA_wasCacheable := utils.IsCacheable(probeA.Response)

			var reflectionLocationA, reflectionLocationB string
			if reflectedInA_Body { reflectionLocationA = "body" }
			if reflectedInA_Headers { 
				if reflectionLocationA != "" { reflectionLocationA += " and " }
				reflectionLocationA += "headers"
			}
			if reflectedInB_Body { reflectionLocationB = "body" }
			if reflectedInB_Headers { 
				if reflectionLocationB != "" { reflectionLocationB += " and " }
				reflectionLocationB += "headers"
			}
			
			description := fmt.Sprintf("Header '%s' with value '%s' was reflected in Probe A's %s. A subsequent request (Probe B) also contained this value in its %s.", 
				headerName, injectedValue, reflectionLocationA, reflectionLocationB)

			evidence := fmt.Sprintf("Probe A cacheable: %t. Probe B cache HIT indicated: %t.", probeA_wasCacheable, probeB_isCacheHit)

			if probeB_isCacheHit || (probeA_wasCacheable && utils.BodiesAreSimilar(probeA.Body, probeB.Body, 0.95)) {
				return &report.Finding{
					URL:           targetURL,
					Vulnerability: "Web Cache Poisoning via Unkeyed Header (Direct Reflection)",
					Description:   description + " The cache appears to have served the poisoned content.",
					UnkeyedInput:  headerName,
					Payload:       injectedValue,
					Evidence:      evidence,
				}, nil
			} else {
				return &report.Finding{
					URL:           targetURL,
					Vulnerability: "Potential Web Cache Deception (Direct Reflection, Unconfirmed Cache Hit)",
					Description:   description + " The cache HIT status for Probe B was not definitively confirmed, but reflection occurred.",
					UnkeyedInput:  headerName,
					Payload:       injectedValue,
					Evidence:      evidence,
				}, nil
			}
		} // End if reflectedInB_Body || reflectedInB_Headers
	} else { // Not reflected in Probe A body or headers
		p.logger.Debugf("Injected value '%s' for header '%s' not directly reflected in Probe A's response for %s. Proceeding to Heuristic 2.", injectedValue, headerName, targetURL)
		// No direct reflection, so Heuristic 1 does not apply. We continue to Heuristic 2.
	}

	// --- Heuristic 2: Unkeyed Header Influences Other Cacheable Content (e.g., X-Forwarded-Host changing links) ---
	p.logger.Debugf("HEURISTIC 2: Checking for indirect poisoning for %s with header %s...", targetURL, headerName)

	if baseline.Error != nil {
		p.logger.Warnf("HEURISTIC 2: Skipping for %s due to baseline probe error: %v", targetURL, baseline.Error)
		return nil, nil
	}
	
	probeA_wasCacheable := utils.IsCacheable(probeA.Response)
	if !probeA_wasCacheable {
		p.logger.Debugf("HEURISTIC 2: Probe A for %s not cacheable, skipping indirect poisoning check.", targetURL)
		return nil, nil
	}

	// TODO H2.1: Extract domain/relevant part from injectedValue if it's a URL (e.g., for X-Forwarded-Host)
	// relevantInjectedToken := utils.ExtractRelevantToken(injectedValue) 

	// TODO H2.2: Implement utils.AnalyzeHeaderChanges(baselineHeaders, probeAHeaders, relevantInjectedToken) (bool, string:changeDescription)
	// headerChanged, headerChangeDesc := utils.AnalyzeHeaderChanges(baseline.RespHeaders, probeA.RespHeaders, relevantInjectedToken)
	
	// TODO H2.3: Implement utils.AnalyzeBodyChanges(baselineBody, probeABody, relevantInjectedToken, baseline.URL) (bool, string:changeDescription)
	// bodyChanged, bodyChangeDesc := utils.AnalyzeBodyChanges(baseline.Body, probeA.Body, relevantInjectedToken, baseline.URL)

	// For now, let's assume we have placeholder booleans. Replace with actual function calls later.
	headerChanged, headerChangeDesc := false, ""
	bodyChanged, bodyChangeDesc := false, ""

	if headerChanged || bodyChanged {
		p.logger.Infof("HEURISTIC 2: Potential indirect influence by header '%s' on %s. Header changes: %t, Body changes: %t", headerName, targetURL, headerChanged, bodyChanged)

		probeB_isCacheHit := utils.IsCacheHit(probeB.Response)
		bodiesSimilar_AB := utils.BodiesAreSimilar(probeA.Body, probeB.Body, 0.98) // High similarity for cache hit confirmation

		if probeB_isCacheHit || bodiesSimilar_AB { // If Probe A was cacheable (checked above) and B is a hit or similar
			description := fmt.Sprintf("Header '%s' with value '%s' appears to have indirectly influenced the response content of Probe A.", headerName, injectedValue)
			if headerChanged {
				description += fmt.Sprintf(" Header change detected: %s.", headerChangeDesc)
			}
			if bodyChanged {
				description += fmt.Sprintf(" Body change detected: %s.", bodyChangeDesc)
			}
			description += " This influenced content was then found in Probe B, suggesting a cache poisoning vulnerability."

			evidence := fmt.Sprintf("Probe A cacheable: true. Probe B cache HIT indicated: %t. Probe A and B bodies similar: %t (threshold 0.98).", probeB_isCacheHit, bodiesSimilar_AB)

			return &report.Finding{
				URL:           targetURL,
				Vulnerability: "Web Cache Poisoning via Unkeyed Header (Indirect Influence)",
				Description:   description,
				UnkeyedInput:  headerName,
				Payload:       injectedValue,
				Evidence:      evidence,
			}, nil
		} else {
			p.logger.Debugf("HEURISTIC 2: Indirect influence detected in Probe A for %s, but Probe B (cache check) did not confirm cache hit of influenced content.", targetURL)
		}
	}

	p.logger.Debugf("No definitive cache poisoning vector found for %s with header %s by current heuristics.", targetURL, headerName)
	return nil, nil // No finding based on current simple heuristics
}

// Note: The following utility function stubs need to be implemented in the utils package (e.g., internal/utils/analysishelpers.go or httphelpers.go)
// func BodyContains(body []byte, substring []byte) bool { ... }
// func HeadersContain(headers http.Header, substring string) bool { ... }
// func IsCacheHit(headers http.Header) bool { ... }
// func BodiesAreSimilar(b1, b2 []byte, threshold float64) bool { ... } 