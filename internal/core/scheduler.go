package core

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

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
	config    *config.Config
	client    *networking.Client
	processor *Processor // Uses Processor from internal/core/processor.go
	logger    utils.Logger
	findings  []*report.Finding
	wg        sync.WaitGroup
	mu        sync.Mutex // For thread-safe access to findings slice
}

// NewScheduler creates a new Scheduler instance.
func NewScheduler(cfg *config.Config, client *networking.Client, processor *Processor, logger utils.Logger) *Scheduler {
	return &Scheduler{
		config:    cfg,
		client:    client,
		processor: processor,
		logger:    logger,
		findings:  make([]*report.Finding, 0),
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

// StartScan begins the scanning process based on the scheduler's configuration.
func (s *Scheduler) StartScan() []*report.Finding {
	s.logger.Infof("Starting scan with %d targets and %d headers to test.", len(s.config.Targets), len(s.config.HeadersToTest))
	s.logger.Debugf("Concurrency level set to: %d", s.config.Concurrency)
	s.logger.Debugf("Request timeout set to: %s", s.config.RequestTimeout.String())

	if len(s.config.Targets) == 0 {
		s.logger.Warnf("No targets configured. Aborting scan.")
		return s.findings
	}
	if len(s.config.HeadersToTest) == 0 {
		s.logger.Warnf("No headers to test configured. Aborting scan.")
		return s.findings
	}

	// Use a buffered channel as a semaphore to limit concurrency.
	concurrencyLimit := s.config.Concurrency
	if concurrencyLimit <= 0 {
		concurrencyLimit = 1 // Ensure at least one worker
	}
	semaphore := make(chan struct{}, concurrencyLimit)

	for _, targetURL := range s.config.Targets {
		for _, headerName := range s.config.HeadersToTest {
			s.wg.Add(1)                   // Increment WaitGroup counter
			semaphore <- struct{}{}         // Acquire a spot in the semaphore

			go func(url, header string) {
				defer s.wg.Done()               // Decrement counter when goroutine finishes
				defer func() { <-semaphore }() // Release the spot in the semaphore

				s.logger.Debugf("Worker starting: URL=%s, Header=%s", url, header)

				// 1. Baseline Request
				baselineReqData := networking.ClientRequestData{URL: url, Method: "GET"}
				baselineRespData := s.client.PerformRequest(baselineReqData)
				baselineProbe := buildProbeData(url, baselineReqData, baselineRespData)

				if baselineProbe.Error != nil {
					s.logger.Warnf("Baseline request failed for URL %s: %v. Skipping probes for this header.", url, baselineProbe.Error)
					return
				}
				if baselineProbe.Response == nil { // Should not happen if error is nil, but good practice
					s.logger.Warnf("Baseline response is nil for URL %s, though no error reported. Skipping probes for this header.", url)
					return
				}

				injectedValue := utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix + "-" + header)

				// 2. Probe A (with injected header)
				probeAReqHeaders := http.Header{header: []string{injectedValue}}
				probeAReqData := networking.ClientRequestData{URL: url, Method: "GET", CustomHeaders: probeAReqHeaders}
				probeARespData := s.client.PerformRequest(probeAReqData)
				probeAProbe := buildProbeData(url, probeAReqData, probeARespData)

				if probeAProbe.Error != nil {
					s.logger.Warnf("Probe A request failed for URL %s, Header %s: %v. Analysis may be incomplete.", url, header, probeAProbe.Error)
					// We might still proceed to Probe B and analysis, as the processor handles probe errors.
				}

				// 3. Probe B (cache check - sent after Probe A)
				// TODO: Consider a small delay here if cache propagation is a concern, though hard to generalize.
				// time.Sleep(50 * time.Millisecond)
				probeBReqData := networking.ClientRequestData{URL: url, Method: "GET"} // No special headers for this probe
				probeBRespData := s.client.PerformRequest(probeBReqData)
				probeBProbe := buildProbeData(url, probeBReqData, probeBRespData)

				if probeBProbe.Error != nil {
					s.logger.Warnf("Probe B request failed for URL %s, Header %s (after Probe A): %v. Analysis may be incomplete.", url, header, probeBProbe.Error)
				}

				// Analyze with Processor
				s.logger.Debugf("Analyzing probes for URL: %s, Header: %s, Value: %s", url, header, injectedValue)
				finding, err := s.processor.AnalyzeProbes(url, header, injectedValue, baselineProbe, probeAProbe, probeBProbe)
				if err != nil {
					s.logger.Warnf("Processor error during analysis for URL %s, Header %s: %v", url, header, err)
				}

				if finding != nil {
					s.mu.Lock()
					s.findings = append(s.findings, finding)
					s.mu.Unlock()
					s.logger.Infof("VULNERABILITY DETECTED: %s on %s with header %s (Payload: %s)", finding.Vulnerability, url, header, injectedValue)
				}

			}(targetURL, headerName)
		}
	}

	s.wg.Wait() // Wait for all goroutines to finish
	s.logger.Infof("Scan completed. Found %d potential vulnerabilities.", len(s.findings))
	return s.findings
}

// TODO: Implement StartScan() method that iterates targets and headers.
// TODO: Implement worker goroutine logic for performing probes (baseline, A, B) using the client.
// TODO: Implement conversion from networking.ClientResponseData to core.ProbeData.
// TODO: Implement logic to call processor.AnalyzeProbes and collect findings.
// TODO: Implement concurrency management using cfg.Concurrency and the WaitGroup. 