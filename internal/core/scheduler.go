package core

import (
	"bufio"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/networking"
	"github.com/rafabd1/Hemlock/internal/report"
	"github.com/rafabd1/Hemlock/internal/utils"
)

// TargetURLJob struct defines a unit of work for a worker.
// It contains the specific URL (with parameters) to be tested and its base domain.
type TargetURLJob struct {
	URLString      string            // The full URL with specific parameters for this job
	BaseDomain     string
	OriginalParams map[string]string // The params that formed this specific URLString
	Retries        int               // Number of times this job has been attempted
	NextAttemptAt  time.Time         // Time after which this job can be retried
}

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

	jobQueue      chan TargetURLJob // Primary queue for new jobs
	retryQueue    chan TargetURLJob // Queue for jobs that need retrying
	activeJobs    int32             // Counter for all active jobs (main + retry)
	maxRetries    int               // From config
	doneChan      chan struct{}       // Signals all processing is complete
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
		maxRetries:    cfg.MaxRetries, // Store maxRetries from config
		doneChan:      make(chan struct{}),
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
	if !canProceed {
		s.logger.Debugf("[Scheduler DM] Domain '%s' requires initial wait of %s. Pausing goroutine.", domain, waitTime)
	}
	for !canProceed {
		time.Sleep(waitTime)
		canProceed, waitTime = s.domainManager.CanRequest(domain)
		if !canProceed {
			// Optional: Log subsequent waits if needed, but less frequently or with different wording
			s.logger.Debugf("[Scheduler DM] Domain '%s' still waiting, next check after %s.", domain, waitTime)
		}
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
// It now returns only the list of findings. Counts for summary are handled in main.go.
func (s *Scheduler) StartScan() []*report.Finding {
	s.logger.Infof("Scheduler: Initializing scan...")
	groupedBaseURLsAndParams, uniqueBaseURLs, _, _ := utils.PreprocessAndGroupURLs(s.config.Targets, s.logger)

	if len(uniqueBaseURLs) == 0 {
		s.logger.Warnf("Scheduler: No processable targets. Aborting scan.")
		return s.findings
	}

	var initialJobs []TargetURLJob
	for _, baseURL := range uniqueBaseURLs {
		parsedBase, _ := url.Parse(baseURL) // Error already handled by PreprocessAndGroupURLs
		baseDomain := parsedBase.Hostname()
		paramSets := groupedBaseURLsAndParams[baseURL]
		for _, paramSet := range paramSets {
			actualTargetURL, _ := constructURLWithParams(baseURL, paramSet) // Error unlikely if Preprocess worked
			initialJobs = append(initialJobs, TargetURLJob{URLString: actualTargetURL, BaseDomain: baseDomain, OriginalParams: paramSet})
		}
	}

	if len(initialJobs) == 0 {
		s.logger.Warnf("Scheduler: No testable URL jobs created. Aborting scan.")
		return s.findings
	}
	s.logger.Infof("Scheduler: Created %d distinct URL jobs to process.", len(initialJobs))

	concurrencyLimit := s.config.Concurrency
	if concurrencyLimit <= 0 { concurrencyLimit = 1 }

	s.jobQueue = make(chan TargetURLJob, len(initialJobs))
	s.retryQueue = make(chan TargetURLJob, len(initialJobs)) // Buffer size can be tuned
	atomic.StoreInt32(&s.activeJobs, int32(len(initialJobs)))

	// Start the retry manager
	go s.retryManager()

	// Populate the initial job queue
	for _, job := range initialJobs {
		s.jobQueue <- job
	}
	// close(s.jobQueue) // Don't close yet, retryManager might add to it

	s.logger.Infof("Scheduler: Starting %d workers for %d initial jobs.", concurrencyLimit, len(initialJobs))

	for i := 0; i < concurrencyLimit; i++ {
		s.wg.Add(1)
		go func(workerID int) {
			defer s.wg.Done()
			s.logger.Debugf("[Worker %d] Started.", workerID)
			for job := range s.jobQueue {
				s.processURLJob(workerID, job)
			}
			s.logger.Debugf("[Worker %d] Exiting (jobQueue closed).", workerID)
		}(i)
	}

	// Wait for all active jobs to complete (including retries)
	<-s.doneChan

	s.wg.Wait() // Ensure all worker goroutines have finished
	s.logger.Infof("Scheduler: All scan tasks and workers completed.")
	return s.findings
}

// retryManager monitors the retryQueue and reschedules jobs.
func (s *Scheduler) retryManager() {
	for job := range s.retryQueue {
		waitTime := time.Until(job.NextAttemptAt)
		if waitTime > 0 {
			s.logger.Debugf("[RetryManager] Job for %s sleeping for %v before re-queueing.", job.URLString, waitTime)
			time.Sleep(waitTime)
		}
		s.logger.Debugf("[RetryManager] Re-queueing job for %s (attempt %d).", job.URLString, job.Retries+1)
		s.jobQueue <- job // Add back to the main job queue
	}
	s.logger.Infof("[RetryManager] Exiting (retryQueue closed).")
}

// processURLJob is executed by each worker.
func (s *Scheduler) processURLJob(workerID int, job TargetURLJob) {
	s.logger.Infof("[Worker %d] Processing URL: %s (Attempt %d)", workerID, job.URLString, job.Retries+1)

	// 1. Check with DomainManager if we can proceed with this domain
	canProceed, domainWaitTime := s.domainManager.CanRequest(job.BaseDomain)
	if !canProceed {
		s.logger.Debugf("[Worker %d] Domain %s busy/standby. Re-queueing job for %s after %v.", workerID, job.BaseDomain, job.URLString, domainWaitTime)
		job.Retries++
		if job.Retries < s.maxRetries {
			job.NextAttemptAt = time.Now().Add(domainWaitTime)
			s.retryQueue <- job
		} else {
			s.logger.Warnf("[Worker %d] Job for %s discarded after %d retries (blocked by domain).", workerID, job.URLString, job.Retries)
			s.decrementActiveJobs()
		}
		return
	}
	s.domainManager.RecordRequestSent(job.BaseDomain) // Record before the baseline request

	// 2. Perform baseline request
	baselineReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"}
	baselineRespData := s.client.PerformRequest(baselineReqData) // Direct client call
	s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(baselineRespData.Response), baselineRespData.Error)

	if baselineRespData.Error != nil || statusCodeFromResponse(baselineRespData.Response) == 429 {
		s.logger.Warnf("[Worker %d] Baseline for %s failed (Status: %d, Err: %v). Retrying job.",
			workerID, job.URLString, statusCodeFromResponse(baselineRespData.Response), baselineRespData.Error)
		job.Retries++
		if job.Retries < s.maxRetries {
			backoffDuration := calculateBackoff(job.Retries, s.config.InitialStandbyDuration, s.config.MaxStandbyDuration, s.config.StandbyDurationIncrement)
			job.NextAttemptAt = time.Now().Add(backoffDuration)
			s.retryQueue <- job
		} else {
			s.logger.Warnf("[Worker %d] Baseline for %s discarded after %d retries.", workerID, job.URLString, job.Retries)
			s.decrementActiveJobs()
		}
		return
	}

	baselineProbe := buildProbeData(job.URLString, baselineReqData, baselineRespData)
	if baselineProbe.Response == nil {
		s.logger.Warnf("[Worker %d] Baseline Invalid (nil response) for %s. Discarding job.", workerID, job.URLString)
		s.decrementActiveJobs()
		return
	}
	s.logger.Debugf("[Worker %d] Baseline for %s successful.", workerID, job.URLString)

	// 3. Test Headers
	if len(s.config.HeadersToTest) > 0 {
		s.logger.Debugf("[Worker %d] Starting Header Tests for %s (%d headers).", workerID, job.URLString, len(s.config.HeadersToTest))
		for _, headerName := range s.config.HeadersToTest {
			// Check DomainManager before each probe for this header
			canProbeA, probeADelay := s.domainManager.CanRequest(job.BaseDomain)
			if !canProbeA {
				s.logger.Debugf("[Worker %d] Header Test (%s) for %s delayed by DomainManager. Re-queueing job after %v.", workerID, headerName, job.URLString, probeADelay)
				job.Retries++
				if job.Retries < s.maxRetries {
					job.NextAttemptAt = time.Now().Add(probeADelay) // Use DM suggested delay
					s.retryQueue <- job
				} else {
					s.logger.Warnf("[Worker %d] Job for %s discarded during header test (%s) after %d retries (DM delay).", workerID, job.URLString, headerName, job.Retries)
					s.decrementActiveJobs()
				}
				return // Return from processURLJob, job will be retried
			}
			s.domainManager.RecordRequestSent(job.BaseDomain)
			injectedValue := utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix + "-header-" + headerName)
			probeAReqHeaders := http.Header{headerName: []string{injectedValue}}
			probeAReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", CustomHeaders: probeAReqHeaders}
			probeARespData := s.client.PerformRequest(probeAReqData)
			s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeARespData.Response), probeARespData.Error)
			probeAProbe := buildProbeData(job.URLString, probeAReqData, probeARespData)
			s.logger.Debugf("[Worker %d] Probe A (Header: '%s') for %s - Status: %s, Error: %v", workerID, headerName, job.URLString, getStatus(probeAProbe.Response), probeAProbe.Error)

			if statusCodeFromResponse(probeARespData.Response) == 429 { // Handle 429 for Probe A
				s.logger.Warnf("[Worker %d] Probe A (Header: '%s') for %s got 429. Re-queueing job.", workerID, headerName, job.URLString)
				job.Retries++
				if job.Retries < s.maxRetries {
					// DomainManager's RecordRequestResult already set standby. Get that standby time.
					_, standbyTime := s.domainManager.IsStandby(job.BaseDomain)
					job.NextAttemptAt = standbyTime
					s.retryQueue <- job
				} else {
					s.logger.Warnf("[Worker %d] Job for %s discarded during Probe A (Header: '%s') after %d retries (429).", workerID, job.URLString, headerName, job.Retries)
					s.decrementActiveJobs()
				}
				return // Return from processURLJob, job will be retried
			}

			// Probe B
			canProbeB, probeBDelay := s.domainManager.CanRequest(job.BaseDomain)
			if !canProbeB {
				s.logger.Debugf("[Worker %d] Header Test Probe B (%s) for %s delayed by DM. Re-queueing job after %v.", workerID, headerName, job.URLString, probeBDelay)
				job.Retries++
				if job.Retries < s.maxRetries {
					job.NextAttemptAt = time.Now().Add(probeBDelay)
					s.retryQueue <- job
				} else {
					s.logger.Warnf("[Worker %d] Job for %s discarded during header test Probe B (%s) after %d retries (DM delay).", workerID, job.URLString, headerName, job.Retries)
					s.decrementActiveJobs()
				}
				return
			}
			s.domainManager.RecordRequestSent(job.BaseDomain)
			probeBReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"}
			probeBRespData := s.client.PerformRequest(probeBReqData)
			s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeBRespData.Response), probeBRespData.Error)
			probeBProbe := buildProbeData(job.URLString, probeBReqData, probeBRespData)
			s.logger.Debugf("[Worker %d] Probe B (Header: '%s') for %s - Status: %s, Error: %v", workerID, headerName, job.URLString, getStatus(probeBProbe.Response), probeBProbe.Error)

			if statusCodeFromResponse(probeBRespData.Response) == 429 { // Handle 429 for Probe B
				s.logger.Warnf("[Worker %d] Probe B (Header: '%s') for %s got 429. Re-queueing job.", workerID, headerName, job.URLString)
				job.Retries++
				if job.Retries < s.maxRetries {
					_, standbyTime := s.domainManager.IsStandby(job.BaseDomain)
					job.NextAttemptAt = standbyTime
					s.retryQueue <- job
				} else {
					s.logger.Warnf("[Worker %d] Job for %s discarded during Probe B (Header: '%s') after %d retries (429).", workerID, job.URLString, headerName, job.Retries)
					s.decrementActiveJobs()
				}
				return
			}

			// Analyze Probes if both were successful (or at least not 429 that caused a job retry)
			if probeAProbe.Error == nil && probeBProbe.Error == nil { // Basic check, can be refined
				finding, errAnalyse := s.processor.AnalyzeProbes(job.URLString, "header", headerName, injectedValue, baselineProbe, probeAProbe, probeBProbe)
				if errAnalyse != nil {
					s.logger.Warnf("[Worker %d] Processor Error (Header: '%s') for URL %s: %v", workerID, headerName, job.URLString, errAnalyse)
				}
				if finding != nil {
					s.mu.Lock()
					s.findings = append(s.findings, finding)
					s.mu.Unlock()
					s.logger.Infof("🎯 [VULN by Worker %d] Type: %s | URL: %s | Via: Header '%s' | Details: %s", workerID, finding.Vulnerability, job.URLString, headerName, finding.Description)
				}
			} else {
				s.logger.Debugf("[Worker %d] Skipping analysis for header '%s' on %s due to probe errors not causing job retry.", workerID, headerName, job.URLString)
			}
		} // End loop headers
	}

	// 4. Test URL Parameters (similar structure to header tests)
	payloadsToTest := s.config.BasePayloads
	if len(payloadsToTest) == 0 && s.config.DefaultPayloadPrefix != "" {
		payloadsToTest = append(payloadsToTest, utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix+"-paramval"))
	}

	if len(payloadsToTest) > 0 && len(job.OriginalParams) > 0 {
		s.logger.Debugf("[Worker %d] Starting Parameter Tests for %s (%d params, %d payloads per param).", workerID, job.URLString, len(job.OriginalParams), len(payloadsToTest))
		for paramName := range job.OriginalParams {
			for _, paramPayload := range payloadsToTest {
				// Check DomainManager before Probe A for this param
				canProbeParamA, paramProbeADelay := s.domainManager.CanRequest(job.BaseDomain)
				if !canProbeParamA {
					s.logger.Debugf("[Worker %d] Param Test (%s) for %s delayed. Re-queueing job after %v.", workerID, paramName, job.URLString, paramProbeADelay)
					job.Retries++
					if job.Retries < s.maxRetries {
						job.NextAttemptAt = time.Now().Add(paramProbeADelay)
						s.retryQueue <- job
					} else {
						s.logger.Warnf("[Worker %d] Job for %s discarded (param %s retry limit).", workerID, job.URLString, paramName)
						s.decrementActiveJobs()
					}
					return // Return from processURLJob
				}
				s.domainManager.RecordRequestSent(job.BaseDomain)
				probeAURL, errProbeAURL := modifyURLQueryParam(job.URLString, paramName, paramPayload)
				if errProbeAURL != nil {
					s.logger.Warnf("[Worker %d] Failed to construct Probe A URL for param test (%s=%s): %v", workerID, paramName, paramPayload, errProbeAURL)
					continue // Skip this payload test
				}
				probeAReqData := networking.ClientRequestData{URL: probeAURL, Method: "GET"}
				probeARespData := s.client.PerformRequest(probeAReqData)
				s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeARespData.Response), probeARespData.Error)
				probeAProbe := buildProbeData(probeAURL, probeAReqData, probeARespData)
				s.logger.Debugf("[Worker %d] Probe A (Param '%s=%s') for %s - Status: %s, Error: %v", workerID, paramName, paramPayload, probeAURL, getStatus(probeAProbe.Response), probeAProbe.Error)

				if statusCodeFromResponse(probeARespData.Response) == 429 { // Handle 429 for Param Probe A
					s.logger.Warnf("[Worker %d] Probe A (Param '%s') for %s got 429. Re-queueing job.", workerID, paramName, probeAURL)
					job.Retries++
					if job.Retries < s.maxRetries {
						_, standbyTime := s.domainManager.IsStandby(job.BaseDomain)
						job.NextAttemptAt = standbyTime
						s.retryQueue <- job
					} else {
						s.logger.Warnf("[Worker %d] Job for %s discarded (Param '%s' Probe A 429 retry limit).", workerID, probeAURL, paramName)
						s.decrementActiveJobs()
					}
					return // Return from processURLJob
				}

				// Probe B for param test
				canProbeParamB, paramProbeBDelay := s.domainManager.CanRequest(job.BaseDomain)
				if !canProbeParamB {
					s.logger.Debugf("[Worker %d] Param Test Probe B (%s) for %s delayed. Re-queueing job after %v.", workerID, paramName, job.URLString, paramProbeBDelay)
					job.Retries++
					if job.Retries < s.maxRetries {
						job.NextAttemptAt = time.Now().Add(paramProbeBDelay)
						s.retryQueue <- job
					} else {
						s.logger.Warnf("[Worker %d] Job for %s discarded (param %s Probe B retry limit).", workerID, job.URLString, paramName)
						s.decrementActiveJobs()
					}
					return
				}
				s.domainManager.RecordRequestSent(job.BaseDomain)
				probeBReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"}
				probeBRespData := s.client.PerformRequest(probeBReqData)
				s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeBRespData.Response), probeBRespData.Error)
				probeBProbe := buildProbeData(job.URLString, probeBReqData, probeBRespData)
				s.logger.Debugf("[Worker %d] Probe B (Param '%s=%s') for %s - Status: %s, Error: %v", workerID, paramName, paramPayload, job.URLString, getStatus(probeBProbe.Response), probeBProbe.Error)

				if statusCodeFromResponse(probeBRespData.Response) == 429 { // Handle 429 for Param Probe B
					s.logger.Warnf("[Worker %d] Probe B (Param '%s') for %s got 429. Re-queueing job.", workerID, paramName, job.URLString)
					job.Retries++
					if job.Retries < s.maxRetries {
						_, standbyTime := s.domainManager.IsStandby(job.BaseDomain)
						job.NextAttemptAt = standbyTime
						s.retryQueue <- job
					} else {
						s.logger.Warnf("[Worker %d] Job for %s discarded (Param '%s' Probe B 429 retry limit).", workerID, job.URLString, paramName)
						s.decrementActiveJobs()
					}
					return
				}

				// Analyze Probes for param test
				if probeAProbe.Error == nil && probeBProbe.Error == nil {
					finding, errAnalyseParam := s.processor.AnalyzeProbes(probeAURL, "param", paramName, paramPayload, baselineProbe, probeAProbe, probeBProbe)
					if errAnalyseParam != nil {
						s.logger.Warnf("[Worker %d] Processor Error (Param '%s=%s') for URL %s: %v", workerID, paramName, paramPayload, probeAURL, errAnalyseParam)
					}
					if finding != nil {
						s.mu.Lock()
						s.findings = append(s.findings, finding)
						s.mu.Unlock()
						s.logger.Infof("🎯 [VULN by Worker %d] Type: %s | URL: %s | Via: Param '%s' | Payload: %s | Details: %s", workerID, finding.Vulnerability, probeAURL, paramName, paramPayload, finding.Description)
					}
				} else {
					s.logger.Debugf("[Worker %d] Skipping analysis for param '%s' on %s due to probe errors not causing job retry.", workerID, paramName, job.URLString)
				}
			} // End loop payloadsToTest
		} // End loop job.OriginalParams
	}

	s.logger.Debugf("[Worker %d] Successfully finished all tests for job: %s", workerID, job.URLString)
	s.decrementActiveJobs() // Job fully completed (no unhandled errors/retries led to early exit)
}

func (s *Scheduler) decrementActiveJobs() {
	if atomic.AddInt32(&s.activeJobs, -1) == 0 {
		s.logger.Infof("All active jobs completed. Closing job queues.")
		close(s.jobQueue)   // Safe to close now, no new jobs will be added by retryManager if activeJobs is 0
		close(s.retryQueue) // retryManager will exit
		close(s.doneChan)   // Signal StartScan to unblock
	}
}

func statusCodeFromResponse(resp *http.Response) int {
	if resp == nil { return 0 }
	return resp.StatusCode
}

// calculateBackoff calculates an exponential backoff duration for job retries.
// It uses the number of retries and configuration parameters for initial, max, and increment durations.
// Note: This backoff is for the JOB retry, not directly for domain standby which is handled by DomainManager.
func calculateBackoff(retries int, initialDuration, maxDuration, incrementStep time.Duration) time.Duration {
	if retries <= 0 {
		return initialDuration // Should not happen if called after at least one retry increment
	}

	// Exponential backoff: initialDuration * (2^(retries-1))
	// We use a multiplier that increases, e.g., 1, 2, 4, 8 for retries 1, 2, 3, 4
	backoffFactor := math.Pow(2, float64(retries-1))
	delay := time.Duration(float64(initialDuration) * backoffFactor)

	// If an increment step is defined and it's the first real retry (retries = 1, so backoffFactor = 1, delay = initialDuration)
	// and initialDuration itself is less than a typical increment, we might want to ensure at least one incrementStep.
	// However, the current formula should naturally scale it up.
	// Let's ensure it doesn't exceed maxDuration.
	if delay > maxDuration {
		delay = maxDuration
	}

	// Ensure it's at least the initial duration (or a minimum sensible value if initial is very small)
	if delay < initialDuration && initialDuration > 0 { // If initialDuration is 0, this would be an issue
        delay = initialDuration
    } else if delay <= 0 { // Fallback if initialDuration was 0 or negative
        delay = time.Second * 10 // Default to a small sensible delay
    }

	return delay
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