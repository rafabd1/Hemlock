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
func (p *Processor) AnalyzeProbes(targetURL string, inputType string, inputName string, injectedValue string, baseline ProbeData, probeA ProbeData, probeB ProbeData) (*report.Finding, error) {
	if p.config.VerbosityLevel >= 2 { // -vv
		p.logger.Debugf("[Processor] Analyzing probes for URL: %s, InputType: %s, InputName: %s, Value: %s", targetURL, inputType, inputName, injectedValue)
	}

	// --- Basic Sanity Checks & Error Handling ---
	if baseline.Error != nil {
		// If baseline itself failed significantly, it's hard to compare.
		// This is an execution error that impacts analysis.
		p.logger.Warnf("[Processor] Baseline probe for %s had an error: %v. Analysis might be unreliable.", targetURL, baseline.Error)
		// Depending on strategy, we might return early or try to proceed with caution.
	}
	if probeA.Error != nil {
		if p.config.VerbosityLevel >= 1 { // -v
			p.logger.Warnf("[Processor] Probe A (input %s:%s, type: %s) for %s had an error: %v.", inputName, injectedValue, inputType, targetURL, probeA.Error)
		}
		// If Probe A fails, we can't know if the header had an effect.
		return nil, fmt.Errorf("probe A failed: %w", probeA.Error) // Error returned to scheduler
	}
	if probeB.Error != nil {
		if p.config.VerbosityLevel >= 1 { // -v
			p.logger.Warnf("[Processor] Probe B (cache check for %s after input %s:%s, type: %s) had an error: %v.", targetURL, inputName, injectedValue, inputType, probeB.Error)
		}
		// If Probe B fails, we can't confirm caching behavior.
		return nil, fmt.Errorf("probe B failed: %w", probeB.Error) // Error returned to scheduler
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
		if p.config.VerbosityLevel >= 2 { // -vv
			p.logger.Debugf("[Processor] Injected value '%s' REFLECTED in Probe A for %s (Body: %t, Headers: %t).", injectedValue, targetURL, reflectedInA_Body, reflectedInA_Headers)
		}

		// Now check Probe B (cache check)
		reflectedInB_Body := utils.BodyContains(probeB.Body, []byte(injectedValue))
		reflectedInB_Headers := utils.HeadersContain(probeB.RespHeaders, injectedValue)

		if reflectedInB_Body || reflectedInB_Headers {
			if p.config.VerbosityLevel >= 1 { // -v
				p.logger.Infof("[Processor] HEURISTIC 1: Injected value '%s' from Probe A (input %s:%s, type: %s) found in Probe B (cache check) for %s.", injectedValue, inputName, inputType, targetURL)
			}

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
			
			description := fmt.Sprintf("Input '%s' (type: %s) with value '%s' was reflected in Probe A's %s. A subsequent request (Probe B) also contained this value in its %s.", 
				inputName, inputType, injectedValue, reflectionLocationA, reflectionLocationB)

			evidence := fmt.Sprintf("Probe A cacheable: %t. Probe B cache HIT indicated: %t.", probeA_wasCacheable, probeB_isCacheHit)

			if probeB_isCacheHit || (probeA_wasCacheable && utils.BodiesAreSimilar(probeA.Body, probeB.Body, 0.95)) {
				return &report.Finding{
					URL:           targetURL,
					Vulnerability: fmt.Sprintf("Web Cache Poisoning via Unkeyed %s (Direct Reflection)", inputType),
					Description:   description + " The cache appears to have served the poisoned content.",
					InputType:     inputType,
					InputName:     inputName,
					Payload:       injectedValue,
					Evidence:      evidence,
				}, nil
			} else {
				return &report.Finding{
					URL:           targetURL,
					Vulnerability: fmt.Sprintf("Potential Web Cache Deception via Unkeyed %s (Direct Reflection, Unconfirmed Cache Hit)", inputType),
					Description:   description + " The cache HIT status for Probe B was not definitively confirmed, but reflection occurred.",
					InputType:     inputType,
					InputName:     inputName,
					Payload:       injectedValue,
					Evidence:      evidence,
				}, nil
			}
		} // End if reflectedInB_Body || reflectedInB_Headers
	} else { // Not reflected in Probe A body or headers
		if p.config.VerbosityLevel >= 2 { // -vv
			p.logger.Debugf("[Processor] Injected value '%s' for input '%s' (type %s) not directly reflected in Probe A's response for %s. Proceeding to Heuristic 2.", injectedValue, inputName, inputType, targetURL)
		}
		// No direct reflection, so Heuristic 1 does not apply. We continue to Heuristic 2.
	}

	// --- Heuristic 2: Unkeyed Header Influences Other Cacheable Content (e.g., X-Forwarded-Host changing links) ---
	if p.config.VerbosityLevel >= 2 { // -vv
		p.logger.Debugf("[Processor] HEURISTIC 2: Checking for indirect poisoning for %s with input %s (type %s)...", targetURL, inputName, inputType)
	}

	if baseline.Error != nil {
		// Already logged with Warnf above if baseline.Error is not nil.
		// p.logger.Warnf("[Processor] HEURISTIC 2: Skipping for %s due to baseline probe error: %v", targetURL, baseline.Error)
		return nil, nil
	}
	
	probeA_wasCacheable := utils.IsCacheable(probeA.Response)
	if !probeA_wasCacheable {
		if p.config.VerbosityLevel >= 2 { // -vv
			p.logger.Debugf("[Processor] HEURISTIC 2: Probe A for %s (input %s, type %s) not cacheable, skipping indirect poisoning check.", targetURL, inputName, inputType)
		}
		return nil, nil
	}

	// Extract a relevant token from the injected value (e.g., hostname if it's a URL)
	relevantInjectedToken := utils.ExtractRelevantToken(injectedValue)
	if relevantInjectedToken == "" && injectedValue != "" { // If extraction yields nothing but original was something, use original
		relevantInjectedToken = injectedValue
	} else if injectedValue == "" { // if original injected value was empty, token is empty, skip. 
		if p.config.VerbosityLevel >= 2 { // -vv
			p.logger.Debugf("[Processor] HEURISTIC 2: Injected value and relevant token are empty for %s, skipping specific indirect checks.", targetURL)
		}
		// We might still want a generic diff later, but for token-based checks, this is a no-op.
		// For now, we will return, but a more advanced diff that doesn't rely on a token could go here.
		return nil, nil
	}

	if p.config.VerbosityLevel >= 2 { // -vv
		p.logger.Debugf("[Processor] HEURISTIC 2: Using relevant token '%s' (from injected value '%s') for indirect checks on %s.", relevantInjectedToken, injectedValue, targetURL)
	}

	// Analyze changes in headers between baseline and Probe A, potentially influenced by the token
	headerChanged, headerChangeDesc := utils.AnalyzeHeaderChanges(baseline.RespHeaders, probeA.RespHeaders, relevantInjectedToken)
	
	// Analyze changes in the body between baseline and Probe A, potentially influenced by the token
	bodyChanged, bodyChangeDesc := utils.AnalyzeBodyChanges(probeA.Body, baseline.Body, relevantInjectedToken, probeA.URL, baseline.URL, p.logger)

	if headerChanged || bodyChanged {
		if p.config.VerbosityLevel >= 1 { // -v
			p.logger.Infof("[Processor] HEURISTIC 2: Potential indirect influence by input '%s' (type %s) on %s. Header changes: %t (%s), Body changes: %t (%s)", 
				inputName, inputType, targetURL, headerChanged, headerChangeDesc, bodyChanged, bodyChangeDesc)
		}

		probeB_isCacheHit := utils.IsCacheHit(probeB.Response)
		bodiesSimilar_AB := utils.BodiesAreSimilar(probeA.Body, probeB.Body, 0.98) // High similarity for cache hit confirmation

		if probeB_isCacheHit || bodiesSimilar_AB { // If Probe A was cacheable (checked above) and B is a hit or similar
			description := fmt.Sprintf("Input '%s' (type %s) with value '%s' appears to have indirectly influenced the response content of Probe A.", inputName, inputType, injectedValue)
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
				Vulnerability: fmt.Sprintf("Web Cache Poisoning via Unkeyed %s (Indirect Influence)", inputType),
				Description:   description,
				InputType:     inputType,
				InputName:     inputName,
				Payload:       injectedValue,
				Evidence:      evidence,
			}, nil
		} else {
			if p.config.VerbosityLevel >= 2 { // -vv
				p.logger.Debugf("[Processor] HEURISTIC 2: Indirect influence detected in Probe A for %s, but Probe B (cache check) did not confirm cache hit of influenced content.", targetURL)
			}
		}
	}

	if p.config.VerbosityLevel >= 2 { // -vv
		p.logger.Debugf("[Processor] No definitive cache poisoning vector found for %s with input %s (type %s) by current heuristics.", targetURL, inputName, inputType)
	}
	return nil, nil // No finding based on current simple heuristics
}

// Note: The following utility function stubs need to be implemented in the utils package (e.g., internal/utils/analysishelpers.go or httphelpers.go)
// func BodyContains(body []byte, substring []byte) bool { ... }
// func HeadersContain(headers http.Header, substring string) bool { ... }
// func IsCacheHit(headers http.Header) bool { ... }
// func BodiesAreSimilar(b1, b2 []byte, threshold float64) bool { ... } 