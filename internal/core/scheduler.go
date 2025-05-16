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
	uniqueDomainCount int      // To store the count of unique domains being scanned
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
		// wg, mu, and uniqueDomainCount are initialized to their zero values, which is appropriate.
	}
}

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
	logger.Debugf("Loaded %d headers from %s", len(headers), filePath) // Changed from Infof to Debugf
	return headers, nil
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

// performRequestWithDomainManagement is a helper to encapsulate DomainManager logic.
func (s *Scheduler) performRequestWithDomainManagement(domain string, reqData networking.ClientRequestData) networking.ClientResponseData {
	canProceed, waitTime := s.domainManager.CanRequest(domain)
	for !canProceed {
		s.logger.Debugf("[Scheduler DM] Domain '%s' requires waiting %s. Pausing goroutine.", domain, waitTime)
		time.Sleep(waitTime)
		canProceed, waitTime = s.domainManager.CanRequest(domain)
	}

	// Can proceed
	s.logger.Debugf("[Scheduler DM] Proceeding with request to domain '%s' (URL: %s)", domain, reqData.URL)
	respData := s.client.PerformRequest(reqData)
	s.domainManager.RecordRequestSent(domain) // Record that the request was made

	// Analyze result for possible domain blocking
	var statusCode int
	if respData.Response != nil {
		statusCode = respData.Response.StatusCode
	}
	s.domainManager.RecordRequestResult(domain, statusCode, respData.Error)

	return respData
}

// StartScan begins the scanning process based on the scheduler's configuration.
// It now returns the list of findings and the count of unique base URLs (domains) processed.
func (s *Scheduler) StartScan() ([]*report.Finding, int) {
	s.logger.Infof("Preprocessing URLs...")
	groupedBaseURLsAndParams, uniqueBaseURLs := utils.PreprocessAndGroupURLs(s.config.Targets, s.logger)
	s.uniqueDomainCount = len(uniqueBaseURLs) // Store for main.go to access if needed, or just return

	if s.uniqueDomainCount == 0 {
		s.logger.Warnf("No processable targets found after preprocessing. Aborting scan.")
		return s.findings, 0
	}
	s.logger.Infof("Preprocessing complete. %d unique base URLs (domains) will be scanned.", s.uniqueDomainCount)

	if len(s.config.HeadersToTest) == 0 && len(s.config.BasePayloads) == 0 && s.config.DefaultPayloadPrefix == "" {
		s.logger.Warnf("No headers to test and no base payloads/prefix configured. Aborting scan as no tests can be performed.")
		return s.findings, s.uniqueDomainCount
	}

	// Use a buffered channel as a semaphore to limit concurrency.
	concurrencyLimit := s.config.Concurrency
	if concurrencyLimit <= 0 {
		concurrencyLimit = 1 // Ensure at least one worker
	}
	semaphore := make(chan struct{}, concurrencyLimit)
	s.logger.Infof("Starting scan with %d concurrent workers.", concurrencyLimit)

	for i, baseURL := range uniqueBaseURLs {
		parsedBaseURL, errURLParse := url.Parse(baseURL)
		if errURLParse != nil {
			s.logger.Warnf("[Scan %d/%d] Failed to parse baseURL '%s': %v. Skipping this base URL.", i+1, s.uniqueDomainCount, baseURL, errURLParse)
			continue
		}
		baseDomain := parsedBaseURL.Hostname()
		paramSets := groupedBaseURLsAndParams[baseURL]
		if len(paramSets) == 0 { 
			paramSets = []map[string]string{{}} 
		}
		s.logger.Infof("[Scan %d/%d] Processing Base URL: %s (Domain: %s) - %d parameter set(s) to test.", i+1, s.uniqueDomainCount, baseURL, baseDomain, len(paramSets))

		for _, currentParamSet := range paramSets {
			// Construct the target URL with its original parameters for this specific test iteration
			targetURLWithOriginalParams, err := constructURLWithParams(baseURL, currentParamSet)
			if err != nil {
				s.logger.Warnf("Failed to construct URL from base '%s' and params %v: %v. Skipping this param set.", baseURL, currentParamSet, err)
				continue
			}

			// Perform baseline request for this specific URL + param combination
			s.logger.Debugf("[Baseline] Requesting: %s (Domain: %s)", targetURLWithOriginalParams, baseDomain)
			baselineReqData := networking.ClientRequestData{URL: targetURLWithOriginalParams, Method: "GET"}
			baselineRespData := s.performRequestWithDomainManagement(baseDomain, baselineReqData)
			baselineProbe := buildProbeData(targetURLWithOriginalParams, baselineReqData, baselineRespData)
			s.logger.Debugf("[Baseline] Response for %s - Status: %s, Body Size: %d, Error: %v", targetURLWithOriginalParams, getStatus(baselineProbe.Response), len(baselineProbe.Body), baselineProbe.Error)

			if baselineProbe.Error != nil {
				s.logger.Warnf("[Baseline Failed] URL %s: %v. Skipping probes for this target.", targetURLWithOriginalParams, baselineProbe.Error)
				continue 
			}
			if baselineProbe.Response == nil {
				s.logger.Warnf("[Baseline Invalid] Response is nil for URL %s, though no error reported. Skipping probes.", targetURLWithOriginalParams)
				continue 
			}

			// Test Headers
			if len(s.config.HeadersToTest) > 0 {
				s.logger.Debugf("[Header Tests] Starting for %s (Domain: %s), %d headers to test.", targetURLWithOriginalParams, baseDomain, len(s.config.HeadersToTest))
				for _, headerName := range s.config.HeadersToTest {
					s.wg.Add(1)
					semaphore <- struct{}{}
					go func(urlToTest, currentHeaderName, domain string, baseProbe ProbeData) {
						defer s.wg.Done()
						defer func() { <-semaphore }()
						s.logger.Debugf("[Worker] Test: Header '%s' on %s", currentHeaderName, urlToTest)

						injectedValue := utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix + "-header-" + currentHeaderName)
						// Probe A (with injected header)
						probeAReqHeaders := http.Header{currentHeaderName: []string{injectedValue}}
						probeAReqData := networking.ClientRequestData{URL: urlToTest, Method: "GET", CustomHeaders: probeAReqHeaders}
						probeARespData := s.performRequestWithDomainManagement(domain, probeAReqData)
						probeAProbe := buildProbeData(urlToTest, probeAReqData, probeARespData)
						s.logger.Debugf("[Worker] Probe A for %s (Header: '%s') - Status: %s, Error: %v", urlToTest, currentHeaderName, getStatus(probeAProbe.Response), probeAProbe.Error)
						if probeAProbe.Error != nil {
							s.logger.Warnf("[Worker] Probe A Failed: URL %s, Header '%s': %v. Analysis may be incomplete.", urlToTest, currentHeaderName, probeAProbe.Error)
						}

						// Probe B (cache check - sent after Probe A)
						probeBReqData := networking.ClientRequestData{URL: urlToTest, Method: "GET"}
						probeBRespData := s.performRequestWithDomainManagement(domain, probeBReqData)
						probeBProbe := buildProbeData(urlToTest, probeBReqData, probeBRespData)
						s.logger.Debugf("[Worker] Probe B for %s (after Header: '%s' test) - Status: %s, Error: %v", urlToTest, currentHeaderName, getStatus(probeBProbe.Response), probeBProbe.Error)
						if probeBProbe.Error != nil {
							s.logger.Warnf("[Worker] Probe B Failed: URL %s, Header '%s': %v. Analysis may be incomplete.", urlToTest, currentHeaderName, probeBProbe.Error)
						}

						finding, errAnalyse := s.processor.AnalyzeProbes(urlToTest, "header", currentHeaderName, injectedValue, baseProbe, probeAProbe, probeBProbe)
						if errAnalyse != nil {
							s.logger.Warnf("[Processor Error] URL %s, Header '%s': %v", urlToTest, currentHeaderName, errAnalyse)
						}
						if finding != nil {
							s.mu.Lock()
							s.findings = append(s.findings, finding)
							s.mu.Unlock()
							s.logger.Infof("🎯 [VULNERABILITY DETECTED] Type: %s | URL: %s | Via: Header '%s' | Payload: %s | Details: %s", finding.Vulnerability, urlToTest, currentHeaderName, injectedValue, finding.Description)
						}
					}(targetURLWithOriginalParams, headerName, baseDomain, baselineProbe)
				}
			}

			// Test URL Parameters
			payloadsToTest := s.config.BasePayloads
			if len(payloadsToTest) == 0 && s.config.DefaultPayloadPrefix != "" {
				payloadsToTest = append(payloadsToTest, utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix+"-paramval1"))
			}

			if len(payloadsToTest) > 0 && len(currentParamSet) > 0 {
				s.logger.Debugf("[Param Tests] Starting for %s (Domain: %s), %d params, %d payloads per param.", targetURLWithOriginalParams, baseDomain, len(currentParamSet), len(payloadsToTest))
				for paramName, originalParamValue := range currentParamSet {
					for _, paramPayload := range payloadsToTest {
						s.wg.Add(1)
						semaphore <- struct{}{}
						go func(urlBase, currentParamName, currentOriginalParamValue, currentParamPayload, domain string, baseProbe ProbeData, originalParams map[string]string) {
							defer s.wg.Done()
							defer func() { <-semaphore }()
							s.logger.Debugf("[Worker] Test: Param '%s=%s' on base %s", currentParamName, currentParamPayload, urlBase)
							
							// Construct URL for Probe A with the modified parameter
							probeAURL, errProbeAURL := modifyURLQueryParam(urlBase, currentParamName, currentParamPayload)
							if errProbeAURL != nil {
								s.logger.Warnf("[Worker] Failed to construct Probe A URL for param test (%s=%s) on %s: %v", currentParamName, currentParamPayload, urlBase, errProbeAURL)
								return
							}

							// Probe A (with injected parameter value)
							probeAReqData := networking.ClientRequestData{URL: probeAURL, Method: "GET"}
							probeARespData := s.performRequestWithDomainManagement(domain, probeAReqData)
							probeAProbe := buildProbeData(probeAURL, probeAReqData, probeARespData)
							s.logger.Debugf("[Worker] Probe A for %s (Param '%s=%s') - Status: %s, Error: %v", probeAURL, currentParamName, currentParamPayload, getStatus(probeAProbe.Response), probeAProbe.Error)
							if probeAProbe.Error != nil {
								s.logger.Warnf("[Worker] Probe A Failed: URL %s, Param '%s=%s': %v. Analysis may be incomplete.", probeAURL, currentParamName, currentParamPayload, probeAProbe.Error)
							}

							// Construct URL for Probe B (original parameters)
							probeBURL, errProbeBURL := constructURLWithParams(urlBase, originalParams)
							if errProbeBURL != nil {
								s.logger.Warnf("[Worker] Failed to construct Probe B URL for param test (original params) on %s: %v", urlBase, errProbeBURL)
								return // Cannot perform cache check if original URL can't be reconstructed
							}
							probeBReqData := networking.ClientRequestData{URL: probeBURL, Method: "GET"}
							probeBRespData := s.performRequestWithDomainManagement(domain, probeBReqData)
							probeBProbe := buildProbeData(probeBURL, probeBReqData, probeBRespData)
							s.logger.Debugf("[Worker] Probe B for %s (after Param '%s=%s' test) - Status: %s, Error: %v", probeBURL, currentParamName, currentParamPayload, getStatus(probeBProbe.Response), probeBProbe.Error)
							if probeBProbe.Error != nil {
								s.logger.Warnf("[Worker] Probe B Failed: URL %s, Param '%s=%s': %v. Analysis may be incomplete.", probeBURL, currentParamName, currentParamPayload, probeBProbe.Error)
							}

							finding, errAnalyseParam := s.processor.AnalyzeProbes(probeAURL, "param", currentParamName, currentParamPayload, baseProbe, probeAProbe, probeBProbe)
							if errAnalyseParam != nil {
								s.logger.Warnf("[Processor Error] URL %s, Param '%s=%s': %v", probeAURL, currentParamName, currentParamPayload, errAnalyseParam)
							}
							if finding != nil {
								s.mu.Lock()
								s.findings = append(s.findings, finding)
								s.mu.Unlock()
								s.logger.Infof("🎯 [VULNERABILITY DETECTED] Type: %s | URL: %s | Via: Param '%s' | Payload: %s | Details: %s", finding.Vulnerability, probeAURL, currentParamName, currentParamPayload, finding.Description)
							}
						}(baseURL, paramName, originalParamValue, paramPayload, baseDomain, baselineProbe, currentParamSet)
					}
				}
			}
		} // End loop currentParamSet
	} // End loop uniqueBaseURLs

	s.wg.Wait() // Wait for all goroutines to finish
	s.logger.Infof("All scan tasks completed.")
	return s.findings, s.uniqueDomainCount
}

// getStatus is a helper to safely get the status string from a response.
func getStatus(resp *http.Response) string {
	if resp == nil {
		return "[No Response]"
	}
	return resp.Status
}

// constructURLWithParams reconstructs a URL string from a base URL and a map of query parameters.
func constructURLWithParams(baseURL string, params map[string]string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// modifyURLQueryParam takes a URL string, a parameter name, and a new value for that parameter.
// It returns a new URL string with the parameter modified or added.
// If the parameter already exists, its value is replaced.
// If it doesn't exist, it's added.
func modifyURLQueryParam(originalURL string, paramNameToModify string, newParamValue string) (string, error) {
	u, err := url.Parse(originalURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse original URL '%s': %w", originalURL, err)
	}

	queryValues := u.Query()                      // Get a copy of the query parameters
	queryValues.Set(paramNameToModify, newParamValue) // Set the new value for the target parameter
	u.RawQuery = queryValues.Encode()               // Re-encode the query parameters

	return u.String(), nil
}