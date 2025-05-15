package core

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/networking"
	"github.com/rafabd1/Hemlock/internal/report"
	"github.com/rafabd1/Hemlock/internal/utils"
)

// ScanTaskResult holds the outcome of scanning a single URL.
// This might evolve to include more details or be part of the `report.Finding` itself.
type ScanTaskResult struct {
	URL     string
	Finding *report.Finding // nil if no finding
	Error   error
}

// Scheduler orchestrates the scanning process.
// It manages target URLs, headers to test, concurrency, and coordinates
// the HTTP client and processor to find vulnerabilities.
type Scheduler struct {
	config        *config.Config
	client        *networking.Client
	processor     *Processor
	domainManager *networking.DomainManager
	logger        utils.Logger
	findings      []*report.Finding
	wg            sync.WaitGroup
	mu            sync.Mutex // For thread-safe access to findings slice
}

// NewScheduler creates a new Scheduler instance.
func NewScheduler(cfg *config.Config, client *networking.Client, processor *Processor, dm *networking.DomainManager, logger utils.Logger) *Scheduler {
	return &Scheduler{
		config:        cfg,
		client:        client,
		processor:     processor,
		domainManager: dm,
		logger:        logger,
		findings:      make([]*report.Finding, 0),
		// wg and mu are initialized to their zero values, which is appropriate.
	}
}

// TODO: Implement StartScan() method that iterates targets and headers.
// TODO: Implement worker goroutine logic for performing probes (baseline, A, B) using the client.
// TODO: Implement conversion from networking.ClientResponseData to core.ProbeData.
// TODO: Implement logic to call processor.AnalyzeProbes and collect findings.
// TODO: Implement concurrency management using cfg.Concurrency and the WaitGroup.

// loadHeaders loads headers from the specified wordlist file.
func loadHeaders(filePath string, logger utils.Logger) ([]string, error) {
	if filePath == "" {
		logger.Warnf("No header wordlist file specified in config (CachePoisoning.HeadersToTestFile).")
		return []string{}, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open header wordlist file %s: %w", filePath, err)
	}
	defer file.Close()

	var headers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { // Ignore empty lines and comments
			headers = append(headers, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading header wordlist file %s: %w", filePath, err)
	}
	logger.Infof("Loaded %d headers from %s", len(headers), filePath)
	return headers, nil
}

// collectWorkerPoolOutputs listens to the worker pool's results and errors channels
// and forwards them or handles them appropriately.
// For now, it just logs errors from the worker pool itself (e.g., if a job func panics - though our jobs return errors).
func (s *Scheduler) collectWorkerPoolOutputs() {
	// Implementation needed
}

// buildBalancedWorkQueue prepares a list of URLs for processing, attempting to balance load across domains.
func (s *Scheduler) buildBalancedWorkQueue(urls []string) []string {
	// Implementation needed
	return nil
}

// Helper to create ProbeData from httpClient response
func makeProbeData(url string, reqHeaders http.Header, resp *http.Response, body []byte, err error) ProbeData {
	// Implementation needed
	return ProbeData{}
}

// Schedule starts the scanning process for the given URLs.
// It returns a channel where ScanTaskResult can be received.
func (s *Scheduler) Schedule(urls []string) <-chan ScanTaskResult {
	// Implementation needed
	return nil
}

func (s *Scheduler) closeResultsChan() {
	// Implementation needed
}

// Shutdown gracefully stops the scheduler and its worker pool.
func (s *Scheduler) Shutdown() {
	// Implementation needed
}

// buildProbeData converts networking.ClientResponseData to core.ProbeData.
func buildProbeData(url string, reqData networking.ClientRequestData, respData networking.ClientResponseData) ProbeData {
	// Note: core.ProbeData is defined in processor.go
	return ProbeData{
		URL:            url,
		RequestHeaders: reqData.CustomHeaders, // Assuming CustomHeaders were the ones sent for this specific probe
		Response:       respData.Response,
		Body:           respData.Body,
		RespHeaders:    respData.RespHeaders,
		Error:          respData.Error,
	}
}

// performRequestWithDomainManagement é um helper para encapsular a lógica de DomainManager.
func (s *Scheduler) performRequestWithDomainManagement(domain string, reqData networking.ClientRequestData) networking.ClientResponseData {
	canProceed, waitTime := s.domainManager.CanRequest(domain)
	for !canProceed {
		s.logger.Debugf("[Scheduler DM] Domínio '%s' requer espera de %s. Pausando goroutine.", domain, waitTime)
		time.Sleep(waitTime)
		canProceed, waitTime = s.domainManager.CanRequest(domain)
	}

	// Pode prosseguir
	s.logger.Debugf("[Scheduler DM] Procedendo com a requisição para o domínio '%s' (URL: %s)", domain, reqData.URL)
	respData := s.client.PerformRequest(reqData)
	s.domainManager.RecordRequestSent(domain) // Registra que a requisição foi feita

	// Analisa o resultado para possível bloqueio de domínio
	var statusCode int
	if respData.Response != nil {
		statusCode = respData.Response.StatusCode
	}
	s.domainManager.RecordRequestResult(domain, statusCode, respData.Error)

	return respData
}

// StartScan begins the scanning process based on the scheduler's configuration.
func (s *Scheduler) StartScan() []*report.Finding {
	s.logger.Infof("Preprocessing URLs...")
	groupedBaseURLsAndParams, uniqueBaseURLs := utils.PreprocessAndGroupURLs(s.config.Targets, s.logger)

	if len(uniqueBaseURLs) == 0 {
		s.logger.Warnf("No processable targets found after preprocessing. Aborting scan.")
		return s.findings
	}
	s.logger.Infof("Starting scan for %d unique base URLs.", len(uniqueBaseURLs))

	if len(s.config.HeadersToTest) == 0 && len(s.config.BasePayloads) == 0 && s.config.DefaultPayloadPrefix == "" {
		s.logger.Warnf("No headers to test and no base payloads/prefix configured. Aborting scan as no tests can be performed.")
		return s.findings
	}

	// Use a buffered channel as a semaphore to limit concurrency.
	concurrencyLimit := s.config.Concurrency
	if concurrencyLimit <= 0 {
		concurrencyLimit = 1 // Ensure at least one worker
	}
	semaphore := make(chan struct{}, concurrencyLimit)

	for _, baseURL := range uniqueBaseURLs {
		parsedBaseURL, errURLParse := url.Parse(baseURL)
		if errURLParse != nil {
			s.logger.Warnf("Falha ao parsear baseURL '%s': %v. Pulando este base URL.", baseURL, errURLParse)
			continue
		}
		baseDomain := parsedBaseURL.Hostname()

		paramSets := groupedBaseURLsAndParams[baseURL]
		if len(paramSets) == 0 { // Should technically not happen if PreprocessAndGroupURLs adds an empty map for parameter-less URLs
			paramSets = []map[string]string{{}} // Ensure at least one iteration for parameter-less base URLs
		}

		for _, currentParamSet := range paramSets {
			// Construct the target URL with its original parameters for this specific test iteration
			targetURLWithOriginalParams, err := constructURLWithParams(baseURL, currentParamSet)
			if err != nil {
				s.logger.Warnf("Failed to construct URL from base '%s' and params %v: %v. Skipping this param set.", baseURL, currentParamSet, err)
				continue
			}

			// Perform baseline request for this specific URL + param combination
			s.logger.Debugf("[Scheduler] Performing Baseline Request for URL: %s (Domain: %s)", targetURLWithOriginalParams, baseDomain)
			baselineReqData := networking.ClientRequestData{URL: targetURLWithOriginalParams, Method: "GET"}
			// Usa o helper com gerenciamento de domínio
			baselineRespData := s.performRequestWithDomainManagement(baseDomain, baselineReqData)
			baselineProbe := buildProbeData(targetURLWithOriginalParams, baselineReqData, baselineRespData)
			s.logger.Debugf("[Scheduler] Baseline Probe for %s - Status: %s, Body Size: %d, Error: %v", targetURLWithOriginalParams, getStatus(baselineProbe.Response), len(baselineProbe.Body), baselineProbe.Error)

			if baselineProbe.Error != nil {
				s.logger.Warnf("[Scheduler] Baseline request failed for URL %s: %v. Skipping probes for this target.", targetURLWithOriginalParams, baselineProbe.Error)
				continue // Skip to next paramSet or baseURL
			}
			if baselineProbe.Response == nil {
				s.logger.Warnf("[Scheduler] Baseline response is nil for URL %s, though no error reported. Skipping probes for this target.", targetURLWithOriginalParams)
				continue // Skip to next paramSet or baseURL
			}

			// Test Headers
			if len(s.config.HeadersToTest) > 0 {
				s.logger.Debugf("[Scheduler] Starting header tests for %s (Domain: %s)", targetURLWithOriginalParams, baseDomain)
				for _, headerName := range s.config.HeadersToTest {
					s.wg.Add(1)
					semaphore <- struct{}{}
					go func(urlToTest, currentHeaderName, domain string, baseProbe ProbeData) {
						defer s.wg.Done()
						defer func() { <-semaphore }()
						s.logger.Debugf("[Scheduler Worker] START HEADER TEST: URL=%s, Header=%s, Domain=%s", urlToTest, currentHeaderName, domain)

						injectedValue := utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix + "-header-" + currentHeaderName)
						s.logger.Debugf("[Scheduler Worker] Generated Injected Value for %s on %s: %s", currentHeaderName, urlToTest, injectedValue)

						// Probe A (with injected header)
						s.logger.Debugf("[Scheduler Worker] Performing Probe A for URL: %s, Header: %s, Value: %s", urlToTest, currentHeaderName, injectedValue)
						probeAReqHeaders := http.Header{currentHeaderName: []string{injectedValue}}
						probeAReqData := networking.ClientRequestData{URL: urlToTest, Method: "GET", CustomHeaders: probeAReqHeaders}
						probeARespData := s.performRequestWithDomainManagement(domain, probeAReqData)
						probeAProbe := buildProbeData(urlToTest, probeAReqData, probeARespData)
						s.logger.Debugf("[Scheduler Worker] Probe A for %s (Header: %s) - Status: %s, Body Size: %d, Error: %v", urlToTest, currentHeaderName, getStatus(probeAProbe.Response), len(probeAProbe.Body), probeAProbe.Error)
						if probeAProbe.Error != nil {
							s.logger.Warnf("[Scheduler Worker] Probe A request failed for URL %s, Header %s: %v. Analysis may be incomplete.", urlToTest, currentHeaderName, probeAProbe.Error)
						}

						// Probe B (cache check - sent after Probe A)
						s.logger.Debugf("[Scheduler Worker] Performing Probe B (cache check) for URL: %s (after Header: %s test)", urlToTest, currentHeaderName)
						probeBReqData := networking.ClientRequestData{URL: urlToTest, Method: "GET"}
						probeBRespData := s.performRequestWithDomainManagement(domain, probeBReqData)
						probeBProbe := buildProbeData(urlToTest, probeBReqData, probeBRespData)
						s.logger.Debugf("[Scheduler Worker] Probe B for %s (after Header: %s test) - Status: %s, Body Size: %d, Error: %v", urlToTest, currentHeaderName, getStatus(probeBProbe.Response), len(probeBProbe.Body), probeBProbe.Error)
						if probeBProbe.Error != nil {
							s.logger.Warnf("[Scheduler Worker] Probe B request failed for URL %s, Header %s: %v. Analysis may be incomplete.", urlToTest, currentHeaderName, probeBProbe.Error)
						}

						s.logger.Debugf("[Scheduler Worker] Analyzing probes for URL: %s, InputType: Header, InputName: %s, InjectedValue: %s", urlToTest, currentHeaderName, injectedValue)
						// TODO: Modify AnalyzeProbes signature to accept inputType and inputName
						finding, err := s.processor.AnalyzeProbes(urlToTest, "header", currentHeaderName, injectedValue, baseProbe, probeAProbe, probeBProbe)
						if err != nil {
							s.logger.Warnf("[Scheduler Worker] Processor error for URL %s, Header %s: %v", urlToTest, currentHeaderName, err)
						}
						if finding != nil {
							s.mu.Lock()
							s.findings = append(s.findings, finding)
							s.mu.Unlock()
							s.logger.Infof("[Scheduler Worker] VULNERABILITY DETECTED: %s on %s via HEADER %s (Payload: %s)", finding.Vulnerability, urlToTest, currentHeaderName, injectedValue)
						}
						s.logger.Debugf("[Scheduler Worker] END HEADER TEST: URL=%s, Header=%s", urlToTest, currentHeaderName)
					}(targetURLWithOriginalParams, headerName, baseDomain, baselineProbe)
				}
			}

			// Test URL Parameters
			// Use s.config.BasePayloads or generate from s.config.DefaultPayloadPrefix
			payloadsToTest := s.config.BasePayloads
			if len(payloadsToTest) == 0 && s.config.DefaultPayloadPrefix != "" {
				// If BasePayloads is empty but prefix is set, generate a few sample payloads for params
				// This is a placeholder; a more robust approach for param-specific payloads might be needed.
				payloadsToTest = append(payloadsToTest, utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix+"-paramval1"))
				// payloadsToTest = append(payloadsToTest, utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix+"-paramval2"))
			}

			if len(payloadsToTest) > 0 {
				for paramName, originalParamValue := range currentParamSet {
					for _, paramPayload := range payloadsToTest {
						s.wg.Add(1)
						semaphore <- struct{}{}
						go func(urlToTestWithOriginalParams, currentParamName, currentOriginalParamValue, currentParamPayload, domain string, baseProbe ProbeData) {
							defer s.wg.Done()
							defer func() { <-semaphore }()
							s.logger.Debugf("[Scheduler Worker] START PARAM TEST: URL=%s, Param=%s, Payload=%s, Domain=%s", urlToTestWithOriginalParams, currentParamName, currentParamPayload, domain)

							// Probe A (with injected parameter value)
							probeAURLForParamTest, err := modifyURLQueryParam(urlToTestWithOriginalParams, currentParamName, currentParamPayload)
							if err != nil {
								s.logger.Warnf("[Scheduler Worker] Failed to build Probe A URL for param test on %s (param %s): %v", urlToTestWithOriginalParams, currentParamName, err)
								return
							}
							s.logger.Debugf("[Scheduler Worker] Performing Probe A for Param Test. URL: %s", probeAURLForParamTest)
							probeAParamReqData := networking.ClientRequestData{URL: probeAURLForParamTest, Method: "GET"}
							probeAParamRespData := s.performRequestWithDomainManagement(domain, probeAParamReqData)
							probeAParamProbe := buildProbeData(probeAURLForParamTest, probeAParamReqData, probeAParamRespData)
							s.logger.Debugf("[Scheduler Worker] Probe A for Param Test %s (Param: %s) - Status: %s, Body Size: %d, Error: %v", urlToTestWithOriginalParams, currentParamName, getStatus(probeAParamProbe.Response), len(probeAParamProbe.Body), probeAParamProbe.Error)
							if probeAParamProbe.Error != nil {
								s.logger.Warnf("[Scheduler Worker] Probe A (param test) request failed for URL %s, Param %s: %v. Analysis may be incomplete.", urlToTestWithOriginalParams, currentParamName, probeAParamProbe.Error)
							}

							// Probe B (cache check - original URL with original params)
							s.logger.Debugf("[Scheduler Worker] Performing Probe B (cache check) for Param Test. URL: %s (after Param: %s test)", urlToTestWithOriginalParams, currentParamName)
							probeBParamReqData := networking.ClientRequestData{URL: urlToTestWithOriginalParams, Method: "GET"}
							probeBParamRespData := s.performRequestWithDomainManagement(domain, probeBParamReqData)
							probeBParamProbe := buildProbeData(urlToTestWithOriginalParams, probeBParamReqData, probeBParamRespData)
							s.logger.Debugf("[Scheduler Worker] Probe B for Param Test %s (after Param: %s test) - Status: %s, Body Size: %d, Error: %v", urlToTestWithOriginalParams, currentParamName, getStatus(probeBParamProbe.Response), len(probeBParamProbe.Body), probeBParamProbe.Error)
							if probeBParamProbe.Error != nil {
								s.logger.Warnf("[Scheduler Worker] Probe B (param test) request failed for URL %s, Param %s: %v. Analysis may be incomplete.", urlToTestWithOriginalParams, currentParamName, probeBParamProbe.Error)
							}

							s.logger.Debugf("[Scheduler Worker] Analyzing probes for URL: %s, InputType: Parameter, InputName: %s, InjectedValue: %s", urlToTestWithOriginalParams, currentParamName, currentParamPayload)
							// TODO: Modify AnalyzeProbes signature
							finding, err := s.processor.AnalyzeProbes(urlToTestWithOriginalParams, "parameter", currentParamName, currentParamPayload, baseProbe, probeAParamProbe, probeBParamProbe)
							if err != nil {
								s.logger.Warnf("[Scheduler Worker] Processor error for URL %s, Param %s: %v", urlToTestWithOriginalParams, currentParamName, err)
							}
							if finding != nil {
								s.mu.Lock()
								s.findings = append(s.findings, finding)
								s.mu.Unlock()
								s.logger.Infof("[Scheduler Worker] VULNERABILITY DETECTED: %s on %s via PARAMETER %s (Payload: %s)", finding.Vulnerability, urlToTestWithOriginalParams, currentParamName, currentParamPayload)
							}
							s.logger.Debugf("[Scheduler Worker] END PARAM TEST: URL=%s, Param=%s", urlToTestWithOriginalParams, currentParamName)
						}(targetURLWithOriginalParams, paramName, originalParamValue, paramPayload, baseDomain, baselineProbe)
					}
				}
			}
		}
	}

	s.wg.Wait()
	s.logger.Infof("Scan completed. Found %d potential vulnerabilities.", len(s.findings))
	return s.findings
}

// Helper function to safely get status from a potentially nil response
func getStatus(resp *http.Response) string {
	if resp == nil {
		return "N/A (No Response)"
	}
	return resp.Status
}

// Helper function to construct a URL string from a base URL and a map of query parameters.
func constructURLWithParams(baseURL string, params map[string]string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse base URL '%s': %w", baseURL, err)
	}
	if len(params) == 0 {
		return u.String(), nil
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Helper function to modify a single query parameter in a URL string.
func modifyURLQueryParam(originalURL string, paramNameToModify string, newParamValue string) (string, error) {
	u, err := url.Parse(originalURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse original URL '%s': %w", originalURL, err)
	}
	q := u.Query()
	q.Set(paramNameToModify, newParamValue) // Set the new value for the specified parameter
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// TODO: Implement StartScan() method that iterates targets and headers.
// TODO: Implement worker goroutine logic for performing probes (baseline, A, B) using the client.
// TODO: Implement conversion from networking.ClientResponseData to core.ProbeData.
// TODO: Implement logic to call processor.AnalyzeProbes and collect findings.
// TODO: Implement concurrency management using cfg.Concurrency and the WaitGroup. 