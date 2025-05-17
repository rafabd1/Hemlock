package core

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
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
	if !canProceed && s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("[Scheduler DM] Domain '%s' requires initial wait of %s. Pausing goroutine.", domain, waitTime)
	}
	for !canProceed {
		time.Sleep(waitTime)
		canProceed, waitTime = s.domainManager.CanRequest(domain)
		if !canProceed && s.config.VerbosityLevel >= 2 { // -vv
			// Optional: Log subsequent waits if needed, but less frequently or with different wording
			s.logger.Debugf("[Scheduler DM] Domain '%s' still waiting, next check after %s.", domain, waitTime)
		}
	}

	// Can proceed
	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("[Scheduler DM] Proceeding with request to domain '%s' (URL: %s)", domain, reqData.URL)
	}
	s.domainManager.RecordRequestSent(domain) // Record that the request was made
	respData := s.client.PerformRequest(reqData)

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
	s.logger.Debugf("Scheduler: Initializing scan...")
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

	concurrencyLimit := s.config.Concurrency
	if concurrencyLimit <= 0 { concurrencyLimit = 1 }

	s.jobQueue = make(chan TargetURLJob, len(initialJobs))
	s.retryQueue = make(chan TargetURLJob, len(initialJobs)*2) // Allow more space for retries
	atomic.StoreInt32(&s.activeJobs, int32(len(initialJobs)))

	// Start the retry manager as a method of scheduler
	go s.manageRetries()

	// Populate the initial job queue
	for _, job := range initialJobs {
		s.jobQueue <- job
	}

	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("Scheduler: Starting %d workers for %d initial jobs.", concurrencyLimit, len(initialJobs))
	}

	for i := 0; i < concurrencyLimit; i++ {
		s.wg.Add(1)
		go func(workerID int) {
			defer s.wg.Done()
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[Worker %d] Started.", workerID)
			}
			for job := range s.jobQueue {
				s.processURLJob(workerID, job)
			}
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[Worker %d] Exiting (jobQueue closed).", workerID)
			}
		}(i)
	}

	<-s.doneChan // Wait for all active jobs (including retries managed by manageRetries) to complete

	s.wg.Wait() // Ensure all worker goroutines have finished
	s.logger.Infof("Scheduler: All scan tasks and workers completed.")
	return s.findings
}

// manageRetries is a goroutine that monitors the retryQueue.
// It waits for a job's NextAttemptAt, then checks with DomainManager before re-queueing to the main jobQueue.
func (s *Scheduler) manageRetries() {
	for job := range s.retryQueue { // Loop until retryQueue is closed by decrementActiveJobs
		waitDuration := time.Until(job.NextAttemptAt)
		if waitDuration > 0 {
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[RetryManager] Job for %s (attempt %d) waiting for %v before re-evaluation.", job.URLString, job.Retries+1, waitDuration)
			}
			time.Sleep(waitDuration)
		}

		if s.config.VerbosityLevel >= 2 { // -vv
			s.logger.Debugf("[RetryManager] Re-evaluating job for %s (attempt %d) for domain %s.", job.URLString, job.Retries+1, job.BaseDomain)
		}
		canProceedNow, furtherDelay := s.domainManager.CanRequest(job.BaseDomain)

		if canProceedNow {
			// Log based on verbosity level
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[RetryManager] Domain %s clear. Re-queueing job for %s to main queue.", job.BaseDomain, job.URLString)
			} else if s.config.VerbosityLevel >= 1 { // -v
				s.logger.Infof("[RetryManager] Domain %s clear. Re-queueing job for %s to main queue.", job.BaseDomain, job.URLString)
			}
			s.jobQueue <- job // Send to main job queue for workers
		} else {
			job.NextAttemptAt = time.Now().Add(furtherDelay)
			// Log based on verbosity level
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[RetryManager] Domain %s still busy/RPS limited. Job for %s to retry after %v (NextAttemptAt: %s). Returning to retry queue.",
					job.BaseDomain, job.URLString, furtherDelay, job.NextAttemptAt.Format(time.RFC3339))
			} else if s.config.VerbosityLevel >= 1 { // -v
				s.logger.Infof("[RetryManager] Domain %s still busy/RPS limited. Job for %s to retry after %v (NextAttemptAt: %s). Returning to retry queue.",
					job.BaseDomain, job.URLString, furtherDelay, job.NextAttemptAt.Format(time.RFC3339))
			}
			s.retryQueue <- job
		}
	}
	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("[RetryManager] Exiting (retryQueue closed).")
	}
}

// processURLJob is where individual URL processing, baseline requests, and probe tests happen.
func (s *Scheduler) processURLJob(workerID int, job TargetURLJob) {
	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("[Worker %d] Processing URL: %s (Attempt %d)", workerID, job.URLString, job.Retries+1)
	}

	// Check with DomainManager before any request for this job
	canProceed, domainWaitTime := s.domainManager.CanRequest(job.BaseDomain)
	if !canProceed {
		if s.config.VerbosityLevel >= 1 { // -v
			s.logger.Infof("[Worker %d] Job for %s re-queued (domain %s busy). Will retry after %v.", workerID, job.URLString, job.BaseDomain, domainWaitTime)
		}
		job.Retries++
		if job.Retries < s.maxRetries {
			job.NextAttemptAt = time.Now().Add(domainWaitTime)
			s.retryQueue <- job
		} else {
			if s.config.VerbosityLevel >= 1 { // -v
				s.logger.Warnf("[Worker %d] Job for %s DISCARDED for domain %s after %d retries (DM limit).", workerID, job.URLString, job.BaseDomain, job.Retries)
			}
			s.decrementActiveJobs()
		}
		return
	}
	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("[Worker %d] Domain %s clear, proceeding with baseline for %s", workerID, job.BaseDomain, job.URLString)
	}
	s.domainManager.RecordRequestSent(job.BaseDomain) // Record before making the request

	baselineReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"}
	baselineRespData := s.client.PerformRequest(baselineReqData) // Does not use performRequestWithDomainManagement, as DM check is done above
	s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(baselineRespData.Response), baselineRespData.Error)

	// Log baseline result *after* it's done, if verbose
	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("[Worker %d] Baseline for %s - Status: %s, Error: %v",
			workerID, job.URLString, getStatus(baselineRespData.Response), baselineRespData.Error)
	}

	// Handle baseline request failure or 429
	if baselineRespData.Error != nil || statusCodeFromResponse(baselineRespData.Response) == 429 {
		statusCode := statusCodeFromResponse(baselineRespData.Response)
		errMsg := "request failed"
		if baselineRespData.Error != nil {
			errMsg = baselineRespData.Error.Error()
		}

		if statusCode == 429 {
			if s.config.VerbosityLevel >= 1 { // -v
				s.logger.Infof("[Worker %d] Baseline for %s received 429 (Too Many Requests). Domain %s standby triggered by DomainManager. Re-queueing to retry.", workerID, job.URLString, job.BaseDomain)
			}
		} else { // Other errors
			if s.config.VerbosityLevel >= 1 { // -v
				s.logger.Warnf("[Worker %d] Baseline for %s failed (Status: %d, Err: %s). Re-queueing to retry.",
					workerID, job.URLString, statusCode, errMsg)
			}
		}

		job.Retries++
		if job.Retries < s.maxRetries {
			var retryDelayDuration time.Duration
			var nextAttemptAbsoluteTime time.Time

			if statusCode == 429 {
				_, standbyEndTime := s.domainManager.IsStandby(job.BaseDomain) // IsStandby returns (bool, time.Time)
				nextAttemptAbsoluteTime = standbyEndTime
				retryDelayDuration = time.Until(standbyEndTime)
				if retryDelayDuration < 0 { // Fallback if somehow standbyEndTime is in the past
					retryDelayDuration = s.config.InitialStandbyDuration
					nextAttemptAbsoluteTime = time.Now().Add(retryDelayDuration)
					if s.config.VerbosityLevel >= 2 { // -vv
						s.logger.Debugf("[Worker %d] Fallback retry delay for %s due to negative duration from IsStandby. Using: %v", workerID, job.URLString, retryDelayDuration)
					}
				}
			} else {
				// For non-429 errors, use standard backoff
				retryDelayDuration = calculateBackoff(job.Retries, s.config.InitialStandbyDuration, s.config.MaxStandbyDuration, s.config.StandbyDurationIncrement)
				nextAttemptAbsoluteTime = time.Now().Add(retryDelayDuration)
			}
			job.NextAttemptAt = nextAttemptAbsoluteTime

			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[Worker %d] Baseline for %s will retry after %v (NextAttemptAt: %s)", workerID, job.URLString, retryDelayDuration, job.NextAttemptAt.Format(time.RFC3339))
			}
			s.retryQueue <- job
		} else {
			if s.config.VerbosityLevel >= 1 { // -v
				s.logger.Warnf("[Worker %d] Baseline for %s DISCARDED after %d retries.", workerID, job.URLString, job.Retries)
			}
			s.decrementActiveJobs()
		}
		return // Critical: return here to avoid processing with a failed baseline
	}

	// Baseline was successful (not an error, not a 429 that led to a return)
	baselineProbe := buildProbeData(job.URLString, baselineReqData, baselineRespData)
	if baselineProbe.Response == nil { // Should not happen if error check above is thorough
		s.logger.Errorf("[Worker %d] CRITICAL: Baseline Invalid (nil response) for %s after successful HTTP req. Discarding job.", workerID, job.URLString)
		s.decrementActiveJobs()
		return
	}
	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("[Worker %d] Baseline for %s successful. Proceeding to probes.", workerID, job.URLString)
	}

	// --- Test Headers ---
	if len(s.config.HeadersToTest) > 0 {
		if s.config.VerbosityLevel >= 2 { // -vv
			s.logger.Debugf("[Worker %d] Starting Header Tests for %s (%d headers).", workerID, job.URLString, len(s.config.HeadersToTest))
		}
		for _, headerName := range s.config.HeadersToTest {
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[Worker %d] Testing Header '%s' for %s", workerID, headerName, job.URLString)
			}

			// Probe A (with injected header)
			canProbeA, probeADelay := s.domainManager.CanRequest(job.BaseDomain)
			if !canProbeA {
				if s.config.VerbosityLevel >= 1 { // -v
					s.logger.Infof("[Worker %d] Header Test (Probe A for '%s') for %s re-queued (domain %s busy). Will retry after %v.", workerID, headerName, job.URLString, job.BaseDomain, probeADelay)
				}
				job.Retries++
				if job.Retries < s.maxRetries {
					job.NextAttemptAt = time.Now().Add(probeADelay)
					s.retryQueue <- job
				} else {
					if s.config.VerbosityLevel >= 1 { // -v
						s.logger.Warnf("[Worker %d] Job for %s DISCARDED during header test (Probe A for '%s') after %d retries (DM limit).", workerID, job.URLString, headerName, job.Retries)
					}
					s.decrementActiveJobs()
				}
				return // Return from processURLJob for this job, it's re-queued or discarded
			}
			s.domainManager.RecordRequestSent(job.BaseDomain)
			injectedValue := utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix + "-header-" + headerName)
			probeAReqHeaders := http.Header{headerName: []string{injectedValue}}
			probeAReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", CustomHeaders: probeAReqHeaders}
				probeARespData := s.client.PerformRequest(probeAReqData)
			s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeARespData.Response), probeARespData.Error)
			probeAProbe := buildProbeData(job.URLString, probeAReqData, probeARespData)

			if s.config.VerbosityLevel >= 2 { // -vv, log *after* attempt
				s.logger.Debugf("[Worker %d] Probe A (Header: '%s') for %s - Status: %s, Error: %v", workerID, headerName, job.URLString, getStatus(probeAProbe.Response), probeAProbe.Error)
			}

			if statusCodeFromResponse(probeARespData.Response) == 429 {
				if s.config.VerbosityLevel >= 1 { // -v
					s.logger.Infof("[Worker %d] Probe A (Header: '%s') for %s got 429. Domain %s standby by DM. Re-queueing to retry.", workerID, headerName, job.URLString, job.BaseDomain)
				}
				job.Retries++
				if job.Retries < s.maxRetries {
					var retryDelayDuration time.Duration
					var nextAttemptAbsoluteTime time.Time
					_, standbyEndTime := s.domainManager.IsStandby(job.BaseDomain)
					nextAttemptAbsoluteTime = standbyEndTime
					retryDelayDuration = time.Until(standbyEndTime)
					if retryDelayDuration < 0 {
						retryDelayDuration = s.config.InitialStandbyDuration
						nextAttemptAbsoluteTime = time.Now().Add(retryDelayDuration)
						if s.config.VerbosityLevel >= 2 { // -vv
							s.logger.Debugf("[Worker %d] Fallback retry delay for Probe A Header %s on %s due to negative duration. Using: %v", workerID, headerName, job.URLString, retryDelayDuration)
						}
					}
					job.NextAttemptAt = nextAttemptAbsoluteTime
					if s.config.VerbosityLevel >= 2 { // -vv
						s.logger.Debugf("[Worker %d] Probe A for %s (Header: '%s') got 429. Will retry after %v (NextAttemptAt: %s)", workerID, job.URLString, headerName, retryDelayDuration, job.NextAttemptAt.Format(time.RFC3339))
					}
					s.retryQueue <- job
				} else {
					if s.config.VerbosityLevel >= 1 { // -v
						s.logger.Warnf("[Worker %d] Job for %s DISCARDED during Probe A (Header: '%s') after %d retries (429).", workerID, job.URLString, headerName, job.Retries)
					}
					s.decrementActiveJobs()
				}
				return // Return from processURLJob
			}

			// Probe B (original request, no injected header, for comparison)
			canProbeB, probeBDelay := s.domainManager.CanRequest(job.BaseDomain)
			if !canProbeB {
				if s.config.VerbosityLevel >= 1 { // -v
					s.logger.Infof("[Worker %d] Header Test (Probe B for '%s') for %s re-queued (domain %s busy). Will retry after %v.", workerID, headerName, job.URLString, job.BaseDomain, probeBDelay)
				}
				job.Retries++
				if job.Retries < s.maxRetries {
					job.NextAttemptAt = time.Now().Add(probeBDelay)
					s.retryQueue <- job
				} else {
					if s.config.VerbosityLevel >= 1 { // -v
						s.logger.Warnf("[Worker %d] Job for %s DISCARDED during header test (Probe B for '%s') after %d retries (DM delay).", workerID, job.URLString, headerName, job.Retries)
					}
					s.decrementActiveJobs()
				}
				return // Return from processURLJob
			}
			s.domainManager.RecordRequestSent(job.BaseDomain)
			probeBReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"} // Original request
				probeBRespData := s.client.PerformRequest(probeBReqData)
			s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeBRespData.Response), probeBRespData.Error)
			probeBProbe := buildProbeData(job.URLString, probeBReqData, probeBRespData)

			if s.config.VerbosityLevel >= 2 { // -vv, log *after* attempt
				s.logger.Debugf("[Worker %d] Probe B (Header: '%s') for %s - Status: %s, Error: %v", workerID, headerName, job.URLString, getStatus(probeBProbe.Response), probeBProbe.Error)
			}

			if statusCodeFromResponse(probeBRespData.Response) == 429 {
				if s.config.VerbosityLevel >= 1 { // -v
					s.logger.Infof("[Worker %d] Probe B (Header: '%s') for %s got 429. Domain %s standby by DM. Re-queueing to retry.", workerID, headerName, job.URLString, job.BaseDomain)
				}
				job.Retries++
				if job.Retries < s.maxRetries {
					var retryDelayDuration time.Duration
					var nextAttemptAbsoluteTime time.Time
					_, standbyEndTime := s.domainManager.IsStandby(job.BaseDomain)
					nextAttemptAbsoluteTime = standbyEndTime
					retryDelayDuration = time.Until(standbyEndTime)
					if retryDelayDuration < 0 {
						retryDelayDuration = s.config.InitialStandbyDuration
						nextAttemptAbsoluteTime = time.Now().Add(retryDelayDuration)
						if s.config.VerbosityLevel >= 2 { // -vv
							s.logger.Debugf("[Worker %d] Fallback retry delay for Probe B Header %s on %s due to negative duration. Using: %v", workerID, headerName, job.URLString, retryDelayDuration)
						}
					}
					job.NextAttemptAt = nextAttemptAbsoluteTime
					if s.config.VerbosityLevel >= 2 { // -vv
						s.logger.Debugf("[Worker %d] Probe B for %s (Header: '%s') got 429. Will retry after %v (NextAttemptAt: %s)", workerID, job.URLString, headerName, retryDelayDuration, job.NextAttemptAt.Format(time.RFC3339))
					}
					s.retryQueue <- job
				} else {
					if s.config.VerbosityLevel >= 1 { // -v
						s.logger.Warnf("[Worker %d] Job for %s DISCARDED during Probe B (Header: '%s') after %d retries (429).", workerID, job.URLString, headerName, job.Retries)
					}
					s.decrementActiveJobs()
				}
				return // Return from processURLJob
			}

			// Analyze probes only if both were successful (no error and not a 429 that caused a return for *this specific test cycle*)
			if probeAProbe.Error == nil && probeBProbe.Error == nil &&
				(probeAProbe.Response != nil && probeAProbe.Response.StatusCode != 429) &&
				(probeBProbe.Response != nil && probeBProbe.Response.StatusCode != 429) {
				finding, errAnalyse := s.processor.AnalyzeProbes(job.URLString, "header", headerName, injectedValue, baselineProbe, probeAProbe, probeBProbe)
				if errAnalyse != nil {
					// Log internal processor errors, but not as a "vulnerability"
					s.logger.Errorf("[Worker %d] Processor Error (Header: '%s') for URL %s: %v", workerID, headerName, job.URLString, errAnalyse)
				}
				if finding != nil {
					s.mu.Lock()
					s.findings = append(s.findings, finding)
					s.mu.Unlock()
					// Log vulnerability finding (normal mode)
					s.logger.Infof("🎯 VULNERABILITY [Worker %d] Type: %s | URL: %s | Via: Header '%s' | Payload: '%s' | Details: %s",
						workerID, finding.Vulnerability, job.URLString, headerName, injectedValue, finding.Description)
				}
			} else if s.config.VerbosityLevel >= 2 { // -vv , log if skipping due to earlier probe issues not leading to retry/return
				s.logger.Debugf("[Worker %d] Skipping analysis for header '%s' on %s due to earlier probe errors/status not causing job retry/return for this test cycle.", workerID, headerName, job.URLString)
			}
		} // End loop over headersToTest
	}

	// --- Test URL Parameters ---
	payloadsToTest := s.config.BasePayloads
	if len(payloadsToTest) == 0 && s.config.DefaultPayloadPrefix != "" { // Ensure there's at least one payload if a prefix is set
		payloadsToTest = append(payloadsToTest, utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix+"-paramval"))
	}

	if len(payloadsToTest) > 0 && len(job.OriginalParams) > 0 {
		if s.config.VerbosityLevel >= 2 { // -vv
			s.logger.Debugf("[Worker %d] Starting Parameter Tests for %s (%d params, %d payloads per param).", workerID, job.URLString, len(job.OriginalParams), len(payloadsToTest))
		}
		for paramName := range job.OriginalParams { // Iterate over a copy or keys of original params
			for _, paramPayload := range payloadsToTest {
				if s.config.VerbosityLevel >= 2 { // -vv
					s.logger.Debugf("[Worker %d] Testing Param '%s=%s' for %s", workerID, paramName, paramPayload, job.URLString)
				}

				// Probe A (with modified parameter)
				canProbeParamA, paramProbeADelay := s.domainManager.CanRequest(job.BaseDomain)
				if !canProbeParamA {
					if s.config.VerbosityLevel >= 1 { // -v
						s.logger.Infof("[Worker %d] Param Test (Probe A for '%s=%s') for %s re-queued (domain %s busy). Will retry after %v.", workerID, paramName, paramPayload, job.URLString, job.BaseDomain, paramProbeADelay)
					}
					job.Retries++
					if job.Retries < s.maxRetries {
						job.NextAttemptAt = time.Now().Add(paramProbeADelay)
						s.retryQueue <- job
					} else {
						if s.config.VerbosityLevel >= 1 { // -v
							s.logger.Warnf("[Worker %d] Job for %s DISCARDED (param '%s=%s' retry limit - DM).", workerID, job.URLString, paramName, paramPayload)
						}
						s.decrementActiveJobs()
					}
					return // Return from processURLJob
				}
				s.domainManager.RecordRequestSent(job.BaseDomain)
				probeAURL, errProbeAURL := modifyURLQueryParam(job.URLString, paramName, paramPayload)
				if errProbeAURL != nil {
					s.logger.Errorf("[Worker %d] CRITICAL: Failed to construct Probe A URL for param test ('%s=%s'): %v. Skipping this param test.", workerID, paramName, paramPayload, errProbeAURL)
					continue // Skip this specific payload test
				}
				probeAParamReqData := networking.ClientRequestData{URL: probeAURL, Method: "GET"}
				probeAParamRespData := s.client.PerformRequest(probeAParamReqData)
				s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeAParamRespData.Response), probeAParamRespData.Error)
				probeAParamProbe := buildProbeData(probeAURL, probeAParamReqData, probeAParamRespData)

				if s.config.VerbosityLevel >= 2 { // -vv, log *after* attempt
					s.logger.Debugf("[Worker %d] Probe A (Param '%s=%s') for %s - Status: %s, Error: %v", workerID, paramName, paramPayload, probeAURL, getStatus(probeAParamProbe.Response), probeAParamProbe.Error)
				}

				if statusCodeFromResponse(probeAParamRespData.Response) == 429 {
					if s.config.VerbosityLevel >= 1 { // -v
						s.logger.Infof("[Worker %d] Probe A (Param '%s=%s') for %s got 429. Domain %s standby by DM. Re-queueing to retry.", workerID, paramName, paramPayload, probeAURL, job.BaseDomain)
					}
					job.Retries++
					if job.Retries < s.maxRetries {
						var retryDelayDuration time.Duration
						var nextAttemptAbsoluteTime time.Time
						_, standbyEndTime := s.domainManager.IsStandby(job.BaseDomain)
						nextAttemptAbsoluteTime = standbyEndTime
						retryDelayDuration = time.Until(standbyEndTime)
						if retryDelayDuration < 0 {
							retryDelayDuration = s.config.InitialStandbyDuration
							nextAttemptAbsoluteTime = time.Now().Add(retryDelayDuration)
							if s.config.VerbosityLevel >= 2 { // -vv
							s.logger.Debugf("[Worker %d] Fallback retry delay for Probe A Param %s=%s on %s due to negative duration. Using: %v", workerID, paramName, paramPayload, probeAURL, retryDelayDuration)
							}
						}
						job.NextAttemptAt = nextAttemptAbsoluteTime
						if s.config.VerbosityLevel >= 2 { // -vv
							s.logger.Debugf("[Worker %d] Probe A for %s (Param '%s=%s') got 429. Will retry after %v (NextAttemptAt: %s)", workerID, probeAURL, paramName, paramPayload, retryDelayDuration, job.NextAttemptAt.Format(time.RFC3339))
						}
						s.retryQueue <- job
					} else {
						if s.config.VerbosityLevel >= 1 { // -v
							s.logger.Warnf("[Worker %d] Job for %s DISCARDED (Param '%s=%s' Probe A 429 retry limit).", workerID, probeAURL, paramName, paramPayload)
						}
						s.decrementActiveJobs()
					}
					return // Return from processURLJob
				}

				// Probe B for param test (original URL, for comparison)
				canProbeParamB, paramProbeBDelay := s.domainManager.CanRequest(job.BaseDomain)
				if !canProbeParamB {
					if s.config.VerbosityLevel >= 1 { // -v
						s.logger.Infof("[Worker %d] Param Test (Probe B for '%s=%s') for %s re-queued (domain %s busy). Will retry after %v.", workerID, paramName, paramPayload, job.URLString, job.BaseDomain, paramProbeBDelay)
					}
					job.Retries++
					if job.Retries < s.maxRetries {
						job.NextAttemptAt = time.Now().Add(paramProbeBDelay)
						s.retryQueue <- job
					} else {
						if s.config.VerbosityLevel >= 1 { // -v
							s.logger.Warnf("[Worker %d] Job for %s DISCARDED (param '%s=%s' Probe B retry limit - DM).", workerID, job.URLString, paramName, paramPayload)
						}
						s.decrementActiveJobs()
					}
					return // Return from processURLJob
				}
				s.domainManager.RecordRequestSent(job.BaseDomain)
				probeBParamReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"} // Original URL
				probeBParamRespData := s.client.PerformRequest(probeBParamReqData)
				s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeBParamRespData.Response), probeBParamRespData.Error)
				probeBParamProbe := buildProbeData(job.URLString, probeBParamReqData, probeBParamRespData)

				if s.config.VerbosityLevel >= 2 { // -vv, log *after* attempt
					s.logger.Debugf("[Worker %d] Probe B (Param '%s=%s') for %s - Status: %s, Error: %v", workerID, paramName, paramPayload, job.URLString, getStatus(probeBParamProbe.Response), probeBParamProbe.Error)
				}

				if statusCodeFromResponse(probeBParamRespData.Response) == 429 {
					if s.config.VerbosityLevel >= 1 { // -v
						s.logger.Infof("[Worker %d] Probe B (Param '%s=%s') for %s got 429. Domain %s standby by DM. Re-queueing to retry.", workerID, paramName, paramPayload, job.URLString, job.BaseDomain)
					}
					job.Retries++
					if job.Retries < s.maxRetries {
						var retryDelayDuration time.Duration
						var nextAttemptAbsoluteTime time.Time
						_, standbyEndTime := s.domainManager.IsStandby(job.BaseDomain)
						nextAttemptAbsoluteTime = standbyEndTime
						retryDelayDuration = time.Until(standbyEndTime)
						if retryDelayDuration < 0 {
							retryDelayDuration = s.config.InitialStandbyDuration
							nextAttemptAbsoluteTime = time.Now().Add(retryDelayDuration)
							if s.config.VerbosityLevel >= 2 { // -vv
							s.logger.Debugf("[Worker %d] Fallback retry delay for Probe B Param %s=%s on %s due to negative duration. Using: %v", workerID, paramName, paramPayload, job.URLString, retryDelayDuration)
							}
						}
						job.NextAttemptAt = nextAttemptAbsoluteTime
						if s.config.VerbosityLevel >= 2 { // -vv
							s.logger.Debugf("[Worker %d] Probe B for %s (Param '%s=%s') got 429. Will retry after %v (NextAttemptAt: %s)", workerID, job.URLString, paramName, paramPayload, retryDelayDuration, job.NextAttemptAt.Format(time.RFC3339))
						}
						s.retryQueue <- job
					} else {
						if s.config.VerbosityLevel >= 1 { // -v
							s.logger.Warnf("[Worker %d] Job for %s DISCARDED (Param '%s=%s' Probe B 429 retry limit).", workerID, job.URLString, paramName, paramPayload)
						}
						s.decrementActiveJobs()
					}
					return // Return from processURLJob
				}

				// Analyze probes only if both were successful
				if probeAParamProbe.Error == nil && probeBParamProbe.Error == nil &&
					(probeAParamProbe.Response != nil && probeAParamProbe.Response.StatusCode != 429) &&
					(probeBParamProbe.Response != nil && probeBParamProbe.Response.StatusCode != 429) {
					finding, errAnalyseParam := s.processor.AnalyzeProbes(probeAURL, "param", paramName, paramPayload, baselineProbe, probeAParamProbe, probeBParamProbe)
					if errAnalyseParam != nil {
						s.logger.Errorf("[Worker %d] Processor Error (Param '%s=%s') for URL %s: %v", workerID, paramName, paramPayload, probeAURL, errAnalyseParam)
					}
					if finding != nil {
						s.mu.Lock()
						s.findings = append(s.findings, finding)
						s.mu.Unlock()
						// Log vulnerability finding (normal mode)
						s.logger.Infof("🎯 VULNERABILITY [Worker %d] Type: %s | URL: %s | Via: Param '%s' | Payload: '%s' | Details: %s",
							workerID, finding.Vulnerability, probeAURL, paramName, paramPayload, finding.Description)
					}
				} else if s.config.VerbosityLevel >= 2 { // -vv
					s.logger.Debugf("[Worker %d] Skipping analysis for param '%s=%s' on %s due to earlier probe errors/status.", workerID, paramName, paramPayload, job.URLString)
				}
			} // End loop over payloadsToTest
		} // End loop over OriginalParams
	}

	// If we reach here, all tests for the current job (baseline, headers, params) that didn't cause a 'return' have been attempted.
	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("[Worker %d] Successfully COMPLETED all tests for job: %s (Total Attempts: %d)", workerID, job.URLString, job.Retries+1)
	}
	s.decrementActiveJobs() // Mark this job as fully processed
}

func (s *Scheduler) decrementActiveJobs() {
	if atomic.AddInt32(&s.activeJobs, -1) == 0 {
		if s.config.VerbosityLevel >= 1 { // -v or -vv
			s.logger.Infof("All active jobs completed. Closing job queues.")
		} else { // Normal mode
			s.logger.Debugf("All active jobs completed. Closing job queues.") // Debug for normal, Info for verbose+
		}
		close(s.jobQueue)
		close(s.retryQueue)
		close(s.doneChan) // Signal StartScan to complete
	}
}

// statusCodeFromResponse safely gets the status code from an HTTP response.
func statusCodeFromResponse(resp *http.Response) int {
	if resp == nil {
		return 0 // Or a specific code indicating no response, like -1, if that helps distinguish
	}
	return resp.StatusCode
}

// calculateBackoff calculates an exponential backoff duration with jitter.
func calculateBackoff(retries int, initialDuration, maxDuration, incrementStep time.Duration) time.Duration {
	if retries <= 0 {
		return initialDuration
	}
	// Exponential backoff: initialDuration * 2^(retries-1)
	backoffFactor := math.Pow(2, float64(retries-1))
	delay := time.Duration(float64(initialDuration) * backoffFactor)

	// Add jitter: +/- 10% of the delay
	// jitter := time.Duration(float64(delay) * 0.1 * (rand.Float64()*2 - 1))
	// delay += jitter
	// Simpler increment for now, can re-add jitter if needed. Consider if incrementStep is still relevant with pure exponential.

	if delay > maxDuration {
		delay = maxDuration
	}
	if delay < initialDuration && initialDuration > 0 { // Ensure it's at least initial
		delay = initialDuration
	} else if delay <= 0 { // Fallback if calculation results in zero or negative
		delay = time.Second * 10 // Default fallback
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
	q := u.Query() // Returns a copy, so modifications are safe
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// modifyURLQueryParam takes a URL string, a parameter name, and a new value for that parameter.
// It returns the modified URL string or an error if parsing fails.
func modifyURLQueryParam(originalURL string, paramNameToModify string, newParamValue string) (string, error) {
	u, err := url.Parse(originalURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse original URL '%s': %w", originalURL, err)
	}
	queryValues := u.Query() // Returns a copy
	queryValues.Set(paramNameToModify, newParamValue)
	u.RawQuery = queryValues.Encode()
	return u.String(), nil
}