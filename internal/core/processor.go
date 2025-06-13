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

	// --- Heuristic 3: Cache Deception Attack ---
	if inputType == "deception" {
		if p.config.VerbosityLevel >= 2 {
			p.logger.Debugf("[Processor H3] Starting Cache Deception analysis for %s. Test: '%s'", probeA.URL, inputName)
		}
		
		// Condição 1: A probe mutada (A) obteve uma resposta de erro (e.g., 404), enquanto a baseline não.
		probeA_isErrorStatus := probeA.Response != nil && probeA.Response.StatusCode >= 400
		baseline_isSuccessStatus := baseline.Response != nil && baseline.Response.StatusCode < 400

		if probeA_isErrorStatus && baseline_isSuccessStatus {
			// Condição 2: A resposta da probe A era cacheável.
			probeA_wasCacheable := utils.IsCacheable(probeA.Response)
			if !probeA_wasCacheable {
				if p.config.VerbosityLevel >= 2 {
					p.logger.Debugf("[Processor H3] Deception Probe A for %s resulted in error status %d, but was not cacheable. Skipping.", probeA.URL, probeA.Response.StatusCode)
				}
				return nil, nil // Not a vulnerability if the error page isn't cached.
			}

			// Condição 3: A probe de confirmação (B) também obteve a mesma resposta de erro.
			probeB_isSameErrorStatus := probeB.Response != nil && probeB.Response.StatusCode == probeA.Response.StatusCode

			if probeB_isSameErrorStatus {
				// Condição 4: A probe B indica um HIT de cache.
				probeB_isCacheHit := utils.IsCacheHit(probeB.Response)

				description := fmt.Sprintf("A request with a mutated path ('%s') resulted in a '%s' response, while the baseline was successful. This error response was cached.", probeA.URL, probeA.Response.Status)
				evidence := fmt.Sprintf("Baseline URL '%s' returned status %d. Mutated URL '%s' returned cacheable status %d. Confirmation request to mutated URL also returned %d and indicated a cache HIT: %t.",
					baseline.URL, baseline.Response.StatusCode, probeA.URL, probeA.Response.StatusCode, probeB.Response.StatusCode, probeB_isCacheHit)

				// A confirmação mais forte é um HIT de cache explícito.
				if probeB_isCacheHit {
					return &report.Finding{
						URL:           targetURL, // Report against the original non-mutated URL
						Vulnerability: "Web Cache Deception",
						Description:   description,
						InputType:     inputType,
						InputName:     inputName,    // e.g., "Backslash Suffix"
						Payload:       probeA.URL, // The payload is the mutated URL itself
						Evidence:      evidence,
						Status:        report.StatusConfirmed,
					}, nil
				}
			}
		}
		// Se a lógica de deception falhar, retornamos nil para permitir que outras heurísticas (se houver) rodem.
		return nil, nil // No deception finding
	}

	// --- Basic Sanity Checks & Error Handling ---
	if baseline.Error != nil {
		p.logger.Warnf("[Processor] Baseline probe for %s had an error: %v. Analysis might be unreliable.", targetURL, baseline.Error)
	}
	if probeA.Error != nil {
		if p.config.VerbosityLevel >= 1 { // -v
			p.logger.Warnf("[Processor] Probe A (input %s:%s, type: %s) for %s had an error: %v.", inputName, injectedValue, inputType, targetURL, probeA.Error)
		}
		return nil, fmt.Errorf("probe A failed: %w", probeA.Error)
	}
	if probeB.Error != nil {
		if p.config.VerbosityLevel >= 1 { // -v
			p.logger.Warnf("[Processor] Probe B (cache check for %s after input %s:%s, type: %s) had an error: %v.", targetURL, inputName, injectedValue, inputType, probeB.Error)
		}
		return nil, fmt.Errorf("probe B failed: %w", probeB.Error)
	}

	reflectedInA_Body := utils.BodyContains(probeA.Body, []byte(injectedValue))
	reflectedInA_Headers := utils.HeadersContain(probeA.RespHeaders, injectedValue)
	probeA_wasCacheable := utils.IsCacheable(probeA.Response) // Check cacheability of Probe A early
	var reflectedFinding *report.Finding

	// Log payload reflection in Probe A if it occurs
	if (reflectedInA_Body || reflectedInA_Headers) && p.config.VerbosityLevel >= 0 && !p.config.Silent {
		reflectionLocationA := getReflectionLocation(reflectedInA_Body, reflectedInA_Headers)

		logMessageFormat := "REFLECTED: Input '%s: %s' (type: %s) reflected in Probe A's %s for %s. Cacheable: %t"
		formattedMessage := fmt.Sprintf(logMessageFormat, inputName, injectedValue, inputType, reflectionLocationA, targetURL, probeA_wasCacheable)

		// Create a "Reflected" finding immediately. We might upgrade it to Potential or Confirmed later.
		reflectedFinding = &report.Finding{
			URL:           targetURL,
			Vulnerability: "Reflected Input",
			Description:   fmt.Sprintf("Input was reflected in the response from Probe A in the %s. This is informational and does not confirm caching.", reflectionLocationA),
			InputType:     inputType,
			InputName:     inputName,
			Payload:       injectedValue,
			Evidence:      fmt.Sprintf("Probe A was cacheable: %t.", probeA_wasCacheable),
			Status:        report.StatusReflected,
		}

		if !p.config.NoColor {
			// Constantes de cor de internal/utils/logger.go
			const colorBlue = "\033[34m"
			const colorReset = "\033[0m"
			formattedMessage = colorBlue + formattedMessage + colorReset
		}
		p.logger.Infof(formattedMessage) // Logger.Infof já adiciona seu próprio prefixo [INFO] colorido
	}

	// --- Heuristic 1: Unkeyed Header Input Leads to Content Reflection in Cache (Classic Poisoning) ---
	if reflectedInA_Body || reflectedInA_Headers {
		if p.config.VerbosityLevel >= 2 { // -vv
			p.logger.Debugf("[Processor H1] Injected value '%s' REFLECTED in Probe A for %s (Body: %t, Headers: %t). Cacheable: %t", injectedValue, targetURL, reflectedInA_Body, reflectedInA_Headers, probeA_wasCacheable)
		}

		// Now check Probe B (cache check)
		reflectedInB_Body := utils.BodyContains(probeB.Body, []byte(injectedValue))
		reflectedInB_Headers := utils.HeadersContain(probeB.RespHeaders, injectedValue)

		if reflectedInB_Body || reflectedInB_Headers {
			probeB_isCacheHit := utils.IsCacheHit(probeB.Response)

			var reflectionLocationB string
			if reflectedInB_Body { reflectionLocationB = "body" }
			if reflectedInB_Headers { 
				if reflectionLocationB != "" { reflectionLocationB += " and " }
				reflectionLocationB += "headers"
			}
			
			description := fmt.Sprintf("Input '%s' (type: %s) with value '%s' was reflected in Probe A. A subsequent request (Probe B) also contained this value in its %s.", 
				inputName, inputType, injectedValue, reflectionLocationB) // Location A já logada, aqui focamos na B

			evidence := fmt.Sprintf("Probe A cacheable: %t. Probe B cache HIT indicated: %t. Probe A reflected in: %s. Probe B reflected in: %s.", 
			    probeA_wasCacheable, probeB_isCacheHit, getReflectionLocation(reflectedInA_Body, reflectedInA_Headers), getReflectionLocation(reflectedInB_Body, reflectedInB_Headers))

			if probeB_isCacheHit || (probeA_wasCacheable && utils.BodiesAreSimilar(probeA.Body, probeB.Body, 0.95)) {
				return &report.Finding{
					URL:           targetURL,
					Vulnerability: fmt.Sprintf("Web Cache Poisoning via Unkeyed %s (Direct Reflection)", inputType),
					Description:   description + " The cache appears to have served the poisoned content.",
					InputType:     inputType,
					InputName:     inputName,
					Payload:       injectedValue,
					Evidence:      evidence,
					Status:        report.StatusConfirmed, // CONFIRMADO
				}, nil
			} else if probeA_wasCacheable { // Se Probe A era cacheável e houve reflexão em A e B, mas o HIT não foi claro
				return &report.Finding{
					URL:           targetURL,
					Vulnerability: fmt.Sprintf("Potential Unkeyed %s (Reflected in Cacheable Response)", inputType),
					Description:   description + " Payload reflected in cacheable Probe A and also in Probe B, but Probe B cache HIT status was not definitively confirmed.",
					InputType:     inputType,
					InputName:     inputName,
					Payload:       injectedValue,
					Evidence:      evidence,
					Status:        report.StatusPotential, // POTENCIAL
				}, nil
			}
		} // End if reflectedInB_Body || reflectedInB_Headers
	} else { 
		if p.config.VerbosityLevel >= 2 { // -vv
			p.logger.Debugf("[Processor H1] Injected value '%s' for input '%s' (type %s) not directly reflected in Probe A's response for %s. Proceeding to Heuristic 2.", injectedValue, inputName, inputType, targetURL)
		}
	}

	// --- Heuristic 2: Unkeyed Header Influences Other Cacheable Content (e.g., X-Forwarded-Host changing links) ---
	if p.config.VerbosityLevel >= 2 { // -vv
		p.logger.Debugf("[Processor H2] Checking for indirect poisoning for %s with input %s (type %s)...", targetURL, inputName, inputType)
	}

	if baseline.Error != nil {
		return nil, nil
	}
	
	// probeA_wasCacheable já calculado acima
	if !probeA_wasCacheable {
		if p.config.VerbosityLevel >= 2 { // -vv
			p.logger.Debugf("[Processor H2] Probe A for %s (input %s, type %s) not cacheable, skipping indirect poisoning check.", targetURL, inputName, inputType)
		}
		return nil, nil
	}

	relevantInjectedToken := utils.ExtractRelevantToken(injectedValue)
	if relevantInjectedToken == "" && injectedValue != "" { 
		relevantInjectedToken = injectedValue
	} else if injectedValue == "" {  
		if p.config.VerbosityLevel >= 2 { // -vv
			p.logger.Debugf("[Processor H2] Injected value and relevant token are empty for %s, skipping specific indirect checks.", targetURL)
		}
		return nil, nil
	}

	if p.config.VerbosityLevel >= 2 { // -vv
		p.logger.Debugf("[Processor H2] Using relevant token '%s' (from injected value '%s') for indirect checks on %s.", relevantInjectedToken, injectedValue, targetURL)
	}

	headerChanged, headerChangeDesc := utils.AnalyzeHeaderChanges(baseline.RespHeaders, probeA.RespHeaders, relevantInjectedToken)
	bodyChanged, bodyChangeDesc := utils.AnalyzeBodyChanges(probeA.Body, baseline.Body, relevantInjectedToken, probeA.URL, baseline.URL, p.logger)

	if headerChanged || bodyChanged {
		// Log de influência indireta em Probe A
		if p.config.VerbosityLevel >= 0 && !p.config.Silent {
			p.logger.Infof("INFLUENCE: Input '%s: %s' (type: %s) indirectly influenced Probe A for %s. Cacheable: %t. HdrChg: %t, BodyChg: %t", 
				inputName, injectedValue, inputType, targetURL, probeA_wasCacheable, headerChanged, bodyChanged)
		}
		if p.config.VerbosityLevel >= 1 { // -v
			p.logger.Infof("[Processor H2] Potential indirect influence by input '%s' (type %s) on %s. Header changes: %t (%s), Body changes: %t (%s)", 
				inputName, inputType, targetURL, headerChanged, headerChangeDesc, bodyChanged, bodyChangeDesc)
		}

		probeB_isCacheHit := utils.IsCacheHit(probeB.Response)
		bodiesSimilar_AB := utils.BodiesAreSimilar(probeA.Body, probeB.Body, 0.98) 

		description := fmt.Sprintf("Input '%s' (type %s) with value '%s' appears to have indirectly influenced the response content of Probe A.", inputName, inputType, injectedValue)
		if headerChanged {
			description += fmt.Sprintf(" Header change detected: %s.", headerChangeDesc)
		}
		if bodyChanged {
			description += fmt.Sprintf(" Body change detected: %s.", bodyChangeDesc)
		}
		
		evidence := fmt.Sprintf("Probe A cacheable: true. Probe B cache HIT indicated: %t. Probe A and B bodies similar: %t (threshold 0.98). Header change: %s. Body change: %s.", 
			probeB_isCacheHit, bodiesSimilar_AB, headerChangeDesc, bodyChangeDesc)

		if probeB_isCacheHit || (probeA_wasCacheable && bodiesSimilar_AB) { // Se Probe A era cacheável (já checado) e B é hit ou similar
			return &report.Finding{
				URL:           targetURL,
				Vulnerability: fmt.Sprintf("Web Cache Poisoning via Unkeyed %s (Indirect Influence)", inputType),
				Description:   description + " This influenced content was then found in Probe B, suggesting a cache poisoning vulnerability.",
				InputType:     inputType,
				InputName:     inputName,
				Payload:       injectedValue,
				Evidence:      evidence,
				Status:        report.StatusConfirmed, // CONFIRMADO
				}, nil
		} else if probeA_wasCacheable { // Influência em Probe A cacheável, mas Probe B não confirmou o HIT do conteúdo envenenado
			return &report.Finding{
				URL:           targetURL,
				Vulnerability: fmt.Sprintf("Potential Unkeyed %s (Indirect Influence, Unconfirmed Cache Hit)", inputType),
				Description:   description + " This influenced content from Probe A (which was cacheable) was not definitively found cached in Probe B.",
				InputType:     inputType,
				InputName:     inputName,
				Payload:       injectedValue,
				Evidence:      evidence,
				Status:        report.StatusPotential, // POTENCIAL
				}, nil
			}
		
	}

	// If we reach this point and haven't returned a Confirmed/Potential finding,
	// but we did find a reflection, return the Reflected finding.
	if reflectedFinding != nil {
		return reflectedFinding, nil
	}

	// Default: No vulnerability found by any heuristic
	if p.config.VerbosityLevel >= 2 { // -vv
		p.logger.Debugf("[Processor] No cache poisoning indicators found for %s with input '%s'", targetURL, inputName)
	}
	return nil, nil
}

// getReflectionLocation é uma função helper para formatar a string de localização da reflexão.
func getReflectionLocation(inBody bool, inHeaders bool) string {
	loc := ""
	if inBody { loc = "body" }
	if inHeaders {
		if loc != "" { loc += " and " }
		loc += "headers"
	}
	if loc == "" { loc = "none" } // Caso não haja reflexão (embora o contexto de chamada implique que houve)
	return loc
}

// As constantes StatusPotential e StatusConfirmed foram movidas para o pacote report.
// A tentativa de redefini-las aqui abaixo será removida. 