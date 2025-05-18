package core

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/networking"
	"github.com/rafabd1/Hemlock/internal/output"
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

	// jobQueue      chan TargetURLJob // REMOVED: Workers will pull from a queue managed by DomainConductor
	// retryQueue    chan TargetURLJob // REMOVED: DomainConductor handles retries
	domainConductor *DomainConductor    // NEW: Manages job flow per domain and retries
	workerJobQueue  chan TargetURLJob   // NEW: Queue from which workers will pull jobs, populated by DomainConductor
	
	activeJobs    int32             // Counter for all active jobs (main + retry)
	maxRetries    int               // From config
	doneChan      chan struct{}       // Signals all processing is complete (closed by DomainConductor)

	progressBar             *output.ProgressBar // Campo para a barra de progresso
	totalJobsForProgressBar int                 // Para armazenar o total de jobs para a barra
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
		// domainConductor will be initialized in StartScan or a dedicated init method if complex
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
			initialJobs = append(initialJobs, TargetURLJob{URLString: actualTargetURL, BaseDomain: baseDomain, OriginalParams: paramSet, NextAttemptAt: time.Now()}) // Initialize NextAttemptAt
		}
	}

	if len(initialJobs) == 0 {
		s.logger.Warnf("Scheduler: No testable URL jobs created. Aborting scan.")
		return s.findings
	}

	s.totalJobsForProgressBar = len(initialJobs)
	if s.totalJobsForProgressBar > 0 {
		s.progressBar = output.NewProgressBar(s.totalJobsForProgressBar, 40) // Width de 40
		s.progressBar.SetPrefix("Scanning: ") // Adiciona um prefixo
		s.progressBar.Start()
		defer func() {
			s.progressBar.Finalize()
			output.SetActiveProgressBar(nil) 
		}()
	}

	concurrencyLimit := s.config.Concurrency
	if concurrencyLimit <= 0 { concurrencyLimit = 1 }

	// s.jobQueue = make(chan TargetURLJob, s.totalJobsForProgressBar) // REMOVED
	// s.retryQueue = make(chan TargetURLJob, s.totalJobsForProgressBar*2) // REMOVED
	s.workerJobQueue = make(chan TargetURLJob, concurrencyLimit) // Workers pull from here
	atomic.StoreInt32(&s.activeJobs, int32(s.totalJobsForProgressBar))

	// Initialize and start DomainConductor
	// Ensure s.doneChan is created before passing to DomainConductor
	if s.doneChan == nil { // Should be initialized in NewScheduler
		s.doneChan = make(chan struct{})
	}
	s.domainConductor = NewDomainConductor(s.config, s.logger, s.domainManager, s.workerJobQueue, &s.activeJobs, s.doneChan, context.Background()) //TODO: Pass a proper parent context if available
	s.domainConductor.Start()
	defer s.domainConductor.Stop()

	// Populate the initial job queue via DomainConductor
	for _, job := range initialJobs {
		// s.jobQueue <- job // REMOVED
		s.domainConductor.SubmitExternalJobToConductor(job)
	}

	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("Scheduler: Starting %d workers for %d initial jobs (via DomainConductor).", concurrencyLimit, s.totalJobsForProgressBar)
	}

	// Goroutine to update progress bar
	if s.progressBar != nil {
		s.wg.Add(1) // Add to waitgroup for this goroutine
		go func() {
			defer s.wg.Done()
			progressTickChan := s.domainConductor.JobProgressTickChan()
			for {
				select {
				case _, ok := <-progressTickChan:
					if !ok { // Channel closed
						// Ensure final update after channel is closed
						currentActive := atomic.LoadInt32(&s.activeJobs)
						completedJobs := s.totalJobsForProgressBar - int(currentActive)
						s.progressBar.Update(completedJobs)
						return
					}
					// On tick, update progress
					currentActive := atomic.LoadInt32(&s.activeJobs)
					completedJobs := s.totalJobsForProgressBar - int(currentActive)
					s.progressBar.Update(completedJobs)
				case <-s.doneChan: // Scheduler is done, can also stop this goroutine
					// Ensure final update if doneChan closes before tickChan does for some reason
					currentActive := atomic.LoadInt32(&s.activeJobs)
					completedJobs := s.totalJobsForProgressBar - int(currentActive)
					s.progressBar.Update(completedJobs)
					return
				}
			}
		}()
	}

	for i := 0; i < concurrencyLimit; i++ {
		s.wg.Add(1)
		go func(workerID int) {
			defer s.wg.Done()
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[Worker %d] Started.", workerID)
			}
			// Workers now read from workerJobQueue populated by DomainConductor
			for job := range s.workerJobQueue { 
				s.processURLJob(workerID, job)
			}
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[Worker %d] Exiting (workerJobQueue closed).", workerID)
			}
		}(i)
	}

	<-s.doneChan // Wait for all active jobs (including retries managed by DomainConductor) to complete

	s.wg.Wait() // Ensure all worker goroutines have finished
	
	// Close workerJobQueue after workers and doneChan indicate completion
	// This must be done carefully to avoid sending to a closed channel if DomainConductor is still running
	// and workers have exited. It's safer if DomainConductor owns closing its output queue (workerJobQueue)
	// or if this is closed when s.doneChan is closed and wg is done.
	// For now, let's assume DomainConductor is stopped before this point, or it manages workerJobQueue closure.
	// The DomainConductor doesn't close workerJobQueue, scheduler does after workers are done.
	// For now, let's assume DomainConductor is stopped before this point, or it manages workerJobQueue closure.
	// The DomainConductor doesn't close workerJobQueue, scheduler does after workers are done.
	close(s.workerJobQueue)

	s.logger.Infof("Scheduler: All scan tasks and workers completed.")
	return s.findings
}

// processURLJob is where individual URL processing, baseline requests, and probe tests happen.
func (s *Scheduler) processURLJob(workerID int, job TargetURLJob) {
	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("[Worker %d] Processing URL: %s (Attempt %d)", workerID, job.URLString, job.Retries+1)
	}

	// DomainManager check is primarily handled by DomainConductor before dispatching.
	// However, a quick check here can prevent immediate re-queue if state changed rapidly.
	// This check might be removed if DomainConductor's dispatch is deemed sufficient.
	/*
	canProceedInitial, domainWaitTimeInitial := s.domainManager.CanRequest(job.BaseDomain)
	if !canProceedInitial {
		if s.config.VerbosityLevel >= 1 { // -v
			s.logger.Infof("[Worker %d] Job for %s (Domain: %s) immediately re-queued by worker due to DM state. Retry after %v.", workerID, job.URLString, job.BaseDomain, domainWaitTimeInitial)
		}
		job.Retries++ // Count this as an attempt by the worker that couldn't proceed
		if job.Retries < s.maxRetries {
			job.NextAttemptAt = time.Now().Add(domainWaitTimeInitial)
			s.domainConductor.SubmitJobToConductor(job)
		} else {
			if s.config.VerbosityLevel >= 1 { // -v
				s.logger.Warnf("[Worker %d] Job for %s (Domain: %s) DISCARDED by worker (DM limit pre-baseline) after %d retries.", workerID, job.URLString, job.BaseDomain, job.Retries)
			}
			s.domainConductor.DecrementActiveJobsAndSignalCompletion()
		}
		return
	}
	*/
	
	// Record request sent and result *for each HTTP call*. DomainManager handles rate limiting.
	// Baseline Request
	s.domainManager.RecordRequestSent(job.BaseDomain)
	baselineReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"}
	baselineRespData := s.client.PerformRequest(baselineReqData) 
	s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(baselineRespData.Response), baselineRespData.Error)

	if s.config.VerbosityLevel >= 2 { 
		s.logger.Debugf("[Worker %d] Baseline for %s - Status: %s, Error: %v",
			workerID, job.URLString, getStatus(baselineRespData.Response), baselineRespData.Error)
	}

	// Handle baseline request failure or 429 status code
	if baselineRespData.Error != nil || statusCodeFromResponse(baselineRespData.Response) == 429 {
		statusCode := statusCodeFromResponse(baselineRespData.Response)
		errMsg := "request failed"
		if baselineRespData.Error != nil {
			errMsg = baselineRespData.Error.Error() // Keep the original error message
		}

		logMsg := fmt.Sprintf("[Worker %d] Baseline for %s failed (Status: %d, Err: %s). ", workerID, job.URLString, statusCode, errMsg)
		if statusCode == 429 {
			logMsg += "Domain standby triggered by DM. "
		}
		logMsg += "Handing over to DomainConductor for outcome processing."
		
		if s.config.VerbosityLevel >= 1 {
			if statusCode == 429 { s.logger.Infof(logMsg) } else { s.logger.Warnf(logMsg) }
		}

		s.domainConductor.HandleJobOutcome(job, false, baselineRespData.Error, statusCode)
		return // Handled by DomainConductor
	}

	baselineProbe := buildProbeData(job.URLString, baselineReqData, baselineRespData)
	if baselineProbe.Response == nil { 
		s.logger.Errorf("[Worker %d] CRITICAL: Baseline Invalid (nil response) for %s. Discarding job.", workerID, job.URLString)
		s.domainConductor.DecrementActiveJobsAndSignalCompletion()
		return
	}
	if s.config.VerbosityLevel >= 2 { 
		s.logger.Debugf("[Worker %d] Baseline for %s successful. Proceeding to probes.", workerID, job.URLString)
	}

	// --- Test Headers ---
	if len(s.config.HeadersToTest) > 0 {
		if s.config.VerbosityLevel >= 2 { 
			s.logger.Debugf("[Worker %d] Starting Header Tests for %s (%d headers).", workerID, job.URLString, len(s.config.HeadersToTest))
		}
		for _, headerName := range s.config.HeadersToTest {
			// Check context before each significant operation (like a new header test cycle)
			if s.isSchedulerStopping() {
				s.logger.Infof("[Worker %d] Scheduler stopping, aborting further probes for job %s.", workerID, job.URLString)
				// If we abort mid-job, this job is technically not "completed".
				// Current logic: job is requeued or completed. If aborted, activeJobs count might be off.
				// For now, let worker finish its current job if it started, or abort cleanly.
				// If DomainConductor closes workerJobQueue, worker will exit.
				// This specific check is more for long-running probe loops.
				return 
			}

			if s.config.VerbosityLevel >= 2 { 
				s.logger.Debugf("[Worker %d] Testing Header '%s' for %s", workerID, headerName, job.URLString)
			}

			// Probe A (with injected header)
			// DomainManager interaction for CanRequest is now implicitly handled by DomainConductor's dispatch logic.
			// Worker assumes it's okay to proceed for a short burst of requests for this job.
			s.domainManager.RecordRequestSent(job.BaseDomain)
			injectedValue := utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix + "-header-" + headerName)
			probeAReqHeaders := http.Header{headerName: []string{injectedValue}}
			probeAReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", CustomHeaders: probeAReqHeaders}
			probeARespData := s.client.PerformRequest(probeAReqData)
			s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeARespData.Response), probeARespData.Error)
			probeAProbe := buildProbeData(job.URLString, probeAReqData, probeARespData)

			if s.config.VerbosityLevel >= 2 { 
				s.logger.Debugf("[Worker %d] Probe A (Header: '%s') for %s - Status: %s, Error: %v", workerID, headerName, job.URLString, getStatus(probeAProbe.Response), probeAProbe.Error)
			}

			// Handle 429 or other errors for Probe A
			if probeARespData.Error != nil || statusCodeFromResponse(probeARespData.Response) == 429 {
				statusCodeProbeA := statusCodeFromResponse(probeARespData.Response)
				if s.config.VerbosityLevel >= 1 { 
					s.logger.Warnf("[Worker %d] Probe A (Header: '%s') for %s failed (Status: %d, Error: %v). Handing to DomainConductor.", workerID, headerName, job.URLString, statusCodeProbeA, probeARespData.Error)
				}
				s.domainConductor.HandleJobOutcome(job, false, probeARespData.Error, statusCodeProbeA)
				return // Handled by DomainConductor
			}


			// Probe B (original request)
			s.domainManager.RecordRequestSent(job.BaseDomain)
			probeBReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"} 
			probeBRespData := s.client.PerformRequest(probeBReqData)
			s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeBRespData.Response), probeBRespData.Error)
			probeBProbe := buildProbeData(job.URLString, probeBReqData, probeBRespData)

			if s.config.VerbosityLevel >= 2 { 
				s.logger.Debugf("[Worker %d] Probe B (Header: '%s') for %s - Status: %s, Error: %v", workerID, headerName, job.URLString, getStatus(probeBProbe.Response), probeBProbe.Error)
			}

			// Handle 429 or other errors for Probe B
			if probeBRespData.Error != nil || statusCodeFromResponse(probeBRespData.Response) == 429 {
				statusCodeProbeB := statusCodeFromResponse(probeBRespData.Response)
				if s.config.VerbosityLevel >= 1 { 
					s.logger.Warnf("[Worker %d] Probe B (Header: '%s') for %s failed (Status: %d, Error: %v). Handing to DomainConductor.", workerID, headerName, job.URLString, statusCodeProbeB, probeBRespData.Error)
				}
				s.domainConductor.HandleJobOutcome(job, false, probeBRespData.Error, statusCodeProbeB)
				return // Handled by DomainConductor
			}

			// Analyze probes if both were successful (no error and not a 429 that caused a return)
			if probeAProbe.Response != nil && probeBProbe.Response != nil { // Errors handled above
				finding, errAnalyse := s.processor.AnalyzeProbes(job.URLString, "header", headerName, injectedValue, baselineProbe, probeAProbe, probeBProbe)
				if errAnalyse != nil {
					s.logger.Errorf("[Worker %d] Processor Error (Header: '%s') for URL %s: %v", workerID, headerName, job.URLString, errAnalyse)
				}
				if finding != nil {
					s.mu.Lock()
					s.findings = append(s.findings, finding)
					s.mu.Unlock()
					s.logger.Infof("🎯 VULNERABILITY [Worker %d] Type: %s | URL: %s | Via: Header '%s' | Payload: '%s' | Details: %s",
						workerID, finding.Vulnerability, job.URLString, headerName, injectedValue, finding.Description)
				}
			} else if s.config.VerbosityLevel >= 2 { 
				s.logger.Debugf("[Worker %d] Skipping analysis for header '%s' on %s due to earlier probe issues not causing job retry/return for this test cycle.", workerID, headerName, job.URLString)
			}
		} 
	}

	// --- Test URL Parameters ---
	payloadsToTest := s.config.BasePayloads
	if len(payloadsToTest) == 0 && s.config.DefaultPayloadPrefix != "" { 
		payloadsToTest = append(payloadsToTest, utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix+"-paramval"))
	}

	if len(payloadsToTest) > 0 && len(job.OriginalParams) > 0 {
		if s.config.VerbosityLevel >= 2 { 
			s.logger.Debugf("[Worker %d] Starting Parameter Tests for %s (%d params, %d payloads per param).", workerID, job.URLString, len(job.OriginalParams), len(payloadsToTest))
		}
		for paramName := range job.OriginalParams { 
			if s.isSchedulerStopping() { // Check context
				s.logger.Infof("[Worker %d] Scheduler stopping, aborting further param probes for job %s.", workerID, job.URLString)
				return
			}
			for _, paramPayload := range payloadsToTest {
				if s.config.VerbosityLevel >= 2 { 
					s.logger.Debugf("[Worker %d] Testing Param '%s=%s' for %s", workerID, paramName, paramPayload, job.URLString)
				}

				// Probe A (with modified parameter)
				s.domainManager.RecordRequestSent(job.BaseDomain)
				probeAURL, errProbeAURL := modifyURLQueryParam(job.URLString, paramName, paramPayload)
				if errProbeAURL != nil {
					s.logger.Errorf("[Worker %d] CRITICAL: Failed to construct Probe A URL for param test ('%s=%s'): %v. Skipping this param test.", workerID, paramName, paramPayload, errProbeAURL)
					continue 
				}
				probeAParamReqData := networking.ClientRequestData{URL: probeAURL, Method: "GET"}
				probeAParamRespData := s.client.PerformRequest(probeAParamReqData)
				s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeAParamRespData.Response), probeAParamRespData.Error)
				probeAParamProbe := buildProbeData(probeAURL, probeAParamReqData, probeAParamRespData)

				if s.config.VerbosityLevel >= 2 { 
					s.logger.Debugf("[Worker %d] Probe A (Param '%s=%s') for %s - Status: %s, Error: %v", workerID, paramName, paramPayload, probeAURL, getStatus(probeAParamProbe.Response), probeAParamProbe.Error)
				}

				// Handle 429 or other errors for Param Probe A
				if probeAParamRespData.Error != nil || statusCodeFromResponse(probeAParamRespData.Response) == 429 {
					statusCodeParamA := statusCodeFromResponse(probeAParamRespData.Response)
					if s.config.VerbosityLevel >= 1 { 
						s.logger.Warnf("[Worker %d] Probe A (Param '%s=%s') for %s failed (Status: %d, Error: %v). Handing to DomainConductor.", workerID, paramName, paramPayload, probeAURL, statusCodeParamA, probeAParamRespData.Error)
					}
					s.domainConductor.HandleJobOutcome(job, false, probeAParamRespData.Error, statusCodeParamA)
					return // Handled by DomainConductor
				}


				// Probe B for param test (original URL)
				s.domainManager.RecordRequestSent(job.BaseDomain)
				probeBParamReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"} 
				probeBParamRespData := s.client.PerformRequest(probeBParamReqData)
				s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(probeBParamRespData.Response), probeBParamRespData.Error)
				probeBParamProbe := buildProbeData(job.URLString, probeBParamReqData, probeBParamRespData)

				if s.config.VerbosityLevel >= 2 { 
					s.logger.Debugf("[Worker %d] Probe B (Param '%s=%s') for %s - Status: %s, Error: %v", workerID, paramName, paramPayload, job.URLString, getStatus(probeBParamProbe.Response), probeBParamProbe.Error)
				}

				// Handle 429 or other errors for Param Probe B
				if probeBParamRespData.Error != nil || statusCodeFromResponse(probeBParamRespData.Response) == 429 {
					statusCodeParamB := statusCodeFromResponse(probeBParamRespData.Response)
					if s.config.VerbosityLevel >= 1 { 
						s.logger.Warnf("[Worker %d] Probe B (Param '%s=%s') for %s failed (Status: %d, Error: %v). Handing to DomainConductor.", workerID, paramName, paramPayload, job.URLString, statusCodeParamB, probeBParamRespData.Error)
					}
					s.domainConductor.HandleJobOutcome(job, false, probeBParamRespData.Error, statusCodeParamB)
					return // Handled by DomainConductor
				}


				// Analyze probes if both were successful
				if probeAParamProbe.Response != nil && probeBParamProbe.Response != nil { // Errors handled
					finding, errAnalyseParam := s.processor.AnalyzeProbes(probeAURL, "param", paramName, paramPayload, baselineProbe, probeAParamProbe, probeBParamProbe)
					if errAnalyseParam != nil {
						s.logger.Errorf("[Worker %d] Processor Error (Param '%s=%s') for URL %s: %v", workerID, paramName, paramPayload, probeAURL, errAnalyseParam)
					}
					if finding != nil {
						s.mu.Lock()
						s.findings = append(s.findings, finding)
						s.mu.Unlock()
						s.logger.Infof("🎯 VULNERABILITY [Worker %d] Type: %s | URL: %s | Via: Param '%s' | Payload: '%s' | Details: %s",
							workerID, finding.Vulnerability, probeAURL, paramName, paramPayload, finding.Description)
					}
				} else if s.config.VerbosityLevel >= 2 { 
					s.logger.Debugf("[Worker %d] Skipping analysis for param '%s=%s' on %s due to earlier probe errors/status.", workerID, paramName, paramPayload, job.URLString)
				}
			} 
		} 
	}

	if s.config.VerbosityLevel >= 2 { 
		s.logger.Debugf("[Worker %d] Successfully COMPLETED all tests for job: %s (Total Scheduler Attempts: %d)", workerID, job.URLString, job.Retries+1)
	}
	s.domainConductor.HandleJobOutcome(job, true, nil, 0) // Job fully processed by this worker, wasSuccessful = true
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

// isSchedulerStopping checks if the scheduler's context (passed to DomainConductor) is done.
// This is a helper to allow workers to gracefully stop long probe loops.
func (s *Scheduler) isSchedulerStopping() bool {
	if s.domainConductor == nil || s.domainConductor.ctx == nil {
		return false // Not yet initialized or context not set
	}
	select {
	case <-s.domainConductor.ctx.Done():
		return true
	default:
		return false
	}
}