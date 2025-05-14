package core

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
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

// Scheduler manages the overall scanning process, including task distribution and concurrency.
// It will utilize the WorkerPool from utils.concurrency and interact with DomainManager and Client.
type Scheduler struct {
	// TODO: Add fields for DomainManager, Client, Processor, WorkerPool, logger, etc.
	httpClient    *networking.Client
	domainManager *networking.DomainManager
	processor     *Processor // TODO: Define and implement Processor
	// poisoner      *Poisoner  // TODO: Define and implement Poisoner for active attempts
	logger        utils.Logger
	workerPool    *utils.WorkerPool
	appConfig     *config.Config // Full app config for access to various settings

	// For managing task lifecycle and collecting results
	ctx          context.Context
	cancelFunc   context.CancelFunc
	resultsChan  chan ScanTaskResult
	shutdownOnce sync.Once
	waitGroup    sync.WaitGroup // To wait for all submitted tasks to be processed by workers
	headersToTest []string // Loaded headers from wordlist
}

// NewScheduler creates a new Scheduler instance.
func NewScheduler(appCfg *config.Config, httpClient *networking.Client, domainManager *networking.DomainManager, proc *Processor, logger utils.Logger) (*Scheduler, error) {
	ctx, cancel := context.WithCancel(context.Background()) // Main context for the scheduler's lifetime

	wp := utils.NewWorkerPool(ctx, appCfg.Workers.NumWorkers, appCfg.Workers.JobQueueSize)

	headers, err := loadHeaders(appCfg.CachePoisoning.HeadersToTestFile, logger)
	if err != nil {
		cancel() // Cancel context if scheduler setup fails
		wp.Shutdown() // Shutdown pool if setup fails
		return nil, fmt.Errorf("failed to load headers wordlist: %w", err)
	}
	if len(headers) == 0 {
		logger.Warnf("Headers wordlist at '%s' is empty or failed to load any headers.", appCfg.CachePoisoning.HeadersToTestFile)
		// Continue without headers to test, or make it a fatal error based on policy
	}

	s := &Scheduler{
		appConfig:     appCfg,
		httpClient:    httpClient,
		domainManager: domainManager,
		processor:     proc,
		logger:        logger,
		workerPool:    wp,
		ctx:           ctx,
		cancelFunc:    cancel,
		resultsChan:   make(chan ScanTaskResult, appCfg.Workers.JobQueueSize), // Buffer similar to worker pool queue
		headersToTest: headers,
	}

	go s.collectWorkerPoolOutputs() // Start collecting results and errors from worker pool
	return s, nil
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
	logger.Infof("Loaded %d headers from %s", len(headers), filePath)
	return headers, nil
}

// collectWorkerPoolOutputs listens to the worker pool's results and errors channels
// and forwards them or handles them appropriately.
// For now, it just logs errors from the worker pool itself (e.g., if a job func panics - though our jobs return errors).
func (s *Scheduler) collectWorkerPoolOutputs() {
	for {
		select {
		case err, ok := <-s.workerPool.Errors():
			if !ok { // Errors channel closed
				s.logger.Debugf("Scheduler: WorkerPool errors channel closed.")
				// If results is also closed, or we are sure no more results will come, we can exit
				// This needs careful handling to ensure all data is processed.
				return // Or check other channels
			}
			s.logger.Errorf("Error from worker pool (job execution error): %v", err)
			// A job itself should ideally return ScanTaskResult with its error, not error out the worker pool job func.
			// This path is more for unexpected panics or fundamental issues in job execution.

		case res, ok := <-s.workerPool.Results():
			if !ok { // Results channel closed
				s.logger.Debugf("Scheduler: WorkerPool results channel closed.")
				// This goroutine can exit if the errors channel is also closed.
				// However, the main path for scan results is via s.resultsChan, sent by tasks themselves.
				// This channel (`s.workerPool.Results()`) is for generic results if jobs are not ScanTask.
				return // Or check other channels
			}
			// This path is for generic results. Specific ScanTaskResults are sent directly by the task func.
			s.logger.Debugf("Generic result from worker pool: %v (should be ScanTaskResult ideally)", res)
			if scanResult, ok := res.(ScanTaskResult); ok {
				s.resultsChan <- scanResult
				s.waitGroup.Done() // Decrement for each task result processed
			} else {
				s.logger.Warnf("Received unexpected result type from worker pool: %T. Value: %v", res, res)
				s.waitGroup.Done() // Still decrement, as a task was processed, albeit with wrong result type
			}

		case <-s.ctx.Done(): // Scheduler itself is shutting down
			s.logger.Debugf("Scheduler: Context done, collector exiting.")
			return
		}
	}
}

// buildBalancedWorkQueue prepares a list of URLs for processing, attempting to balance load across domains.
func (s *Scheduler) buildBalancedWorkQueue(urls []string) []string {
	if len(urls) <= 1 {
		return urls
	}

	domains := make(map[string][]string)
	for _, u := range urls {
		domain, err := utils.GetDomainFromURL(u)
		if err != nil {
			s.logger.Warnf("Error parsing URL %s for domain balancing: %v", u, err)
			continue // Skip malformed URLs for balancing
		}
		domains[domain] = append(domains[domain], u)
	}

	var domainKeys []string
	for d := range domains {
		domainKeys = append(domainKeys, d)
	}
	// Sort domain keys to ensure a somewhat deterministic order for round-robin, though true randomness might be better for evasion
	sort.Strings(domainKeys)

	var balancedQueue []string
	maxLength := 0
	for _, dUrls := range domains {
		if len(dUrls) > maxLength {
			maxLength = len(dUrls)
		}
	}

	for i := 0; i < maxLength; i++ {
		for _, domainKey := range domainKeys {
			if i < len(domains[domainKey]) {
				balancedQueue = append(balancedQueue, domains[domainKey][i])
			}
		}
	}
	s.logger.Debugf("Built balanced work queue with %d URLs.", len(balancedQueue))
	return balancedQueue
}

// Helper to create ProbeData from httpClient response
func makeProbeData(url string, reqHeaders http.Header, resp *http.Response, body []byte, err error) ProbeData {
	pd := ProbeData{URL: url, RequestHeaders: reqHeaders, Error: err}
	if resp != nil {
		pd.Response = resp
		pd.RespHeaders = resp.Header
	}
	pd.Body = body // Assign body even if response is nil (e.g. if error occurred before response)
	return pd
}

// Schedule starts the scanning process for the given URLs.
// It returns a channel where ScanTaskResult can be received.
func (s *Scheduler) Schedule(urls []string) <-chan ScanTaskResult {
	s.logger.Infof("Scheduler starting with %d raw URLs and %d headers to test per URL.", len(urls), len(s.headersToTest))

	// Preprocess URLs: filter ignored extensions and deduplicate
	processedUrls := utils.PreprocessURLs(urls, s.appConfig.Input.IgnoredExtensions, true, s.logger) // stripWWW = true, as normalizeURL handles it

	if len(processedUrls) == 0 {
		s.logger.Warnf("No valid URLs to schedule after preprocessing.")
		s.closeResultsChan() // Close immediately if nothing to do
		return s.resultsChan
	}
	s.logger.Infof("%d URLs remain after preprocessing.", len(processedUrls))

	balancedUrls := s.buildBalancedWorkQueue(processedUrls)
	if len(balancedUrls) == 0 {
		s.logger.Warnf("No valid URLs to schedule after balancing (unexpected if preprocessing yielded URLs).")
		s.closeResultsChan()
		return s.resultsChan
	}

	// Each URL will generate N jobs, one for each header + 1 baseline
	// However, the waitGroup should count the number of *tasks* that produce a ScanTaskResult.
	// Each URL scan (which includes baseline + all header probes) is one such task.
	s.waitGroup.Add(len(balancedUrls))

	go func() {
		for _, urlStr := range balancedUrls {
			currentURL := urlStr

			job := func() (interface{}, error) { // This job now represents the entire scan for ONE URL
				s.logger.Debugf("Worker starting comprehensive scan for URL: %s", currentURL)
				
				// 1. Get Baseline
				baselineResp, baselineBody, baselineRespHeaders, bErr := s.httpClient.GetBaseline(currentURL)
				_ = baselineRespHeaders // Mark as used for linter
				baselineProbe := makeProbeData(currentURL, nil, baselineResp, baselineBody, bErr)
				if bErr != nil {
					s.logger.Warnf("Error getting baseline for %s: %v", currentURL, bErr)
					// Return a result indicating baseline failure for this URL, then this task is done.
					return ScanTaskResult{URL: currentURL, Error: fmt.Errorf("baseline failed for %s: %w", currentURL, bErr)}, nil
				}

				// 2. Iterate over headers wordlist
				if len(s.headersToTest) == 0 {
					s.logger.Debugf("No headers to test for URL: %s. Completing with baseline check only.", currentURL)
					return ScanTaskResult{URL: currentURL, Finding: nil, Error: nil}, nil // No specific finding if no headers are tested
				}

				for _, headerName := range s.headersToTest {
					if s.ctx.Err() != nil { // Check for scheduler shutdown before intensive work
						s.logger.Infof("Scheduler context cancelled during header testing for %s. Aborting further tests for this URL.", currentURL)
						return ScanTaskResult{URL: currentURL, Error: fmt.Errorf("scan aborted for %s due to scheduler shutdown", currentURL)}, nil
					}

					injectedValue := utils.GenerateUniquePayload("hemlock-" + headerName)
					probeAReqHeaders := http.Header{headerName: []string{injectedValue}}
					_ = probeAReqHeaders // Mark as used for linter if needed, or use directly in makeProbeData

					// Probe A (with injected header)
					probeAResp, probeABody, probeARespHeaders, paErr := s.httpClient.ProbeWithHeader(currentURL, headerName, injectedValue)
					_ = probeARespHeaders // Mark as used for linter
					probeAData := makeProbeData(currentURL, probeAReqHeaders, probeAResp, probeABody, paErr)
					if paErr != nil {
						s.logger.Warnf("Error in Probe A for %s with header %s: %v", currentURL, headerName, paErr)
						// Continue to next header, or report this specific header probe error?
						// For now, we log and continue. The processor will also see this error.
					}

					// Probe B (cache check, no injected header)
					// We must ensure Probe B is made *after* Probe A has completed and its response potentially cached.
					// The DomainManager should naturally handle delays if the same domain is hit quickly,
					// but a small explicit delay might sometimes be useful for cache propagation, though hard to generalize.
					// time.Sleep(50 * time.Millisecond) // Optional small delay
					probeBResp, probeBBody, probeBRespHeaders, pbErr := s.httpClient.GetBaseline(currentURL) // Get with no custom headers
					_ = probeBRespHeaders // Mark as used for linter
					probeBData := makeProbeData(currentURL, nil, probeBResp, probeBBody, pbErr)
					if pbErr != nil {
						s.logger.Warnf("Error in Probe B (cache check) for %s after header %s: %v", currentURL, headerName, pbErr)
					}

					// Analyze with Processor
					finding, procErr := s.processor.AnalyzeProbes(currentURL, headerName, injectedValue, baselineProbe, probeAData, probeBData)
					if procErr != nil {
						s.logger.Warnf("Processor error for %s with header %s: %v", currentURL, headerName, procErr)
						// Continue to next header, this specific probe analysis failed.
						// We don't return a ScanTaskResult here, as one will be returned at the end of the URL scan.
					}
					if finding != nil {
						s.logger.Infof("Finding reported by processor for %s with header %s!", currentURL, headerName)
						// If a finding is found, we can report it immediately for this URL and stop further header tests for this URL.
						return ScanTaskResult{URL: currentURL, Finding: finding, Error: nil}, nil
					}
				} // End of header iteration

				// If loop completes with no finding for any header
				s.logger.Debugf("No specific cache poisoning findings for URL: %s after testing all headers.", currentURL)
				return ScanTaskResult{URL: currentURL, Finding: nil, Error: nil}, nil
			}

			if err := s.workerPool.Submit(job); err != nil {
				s.logger.Warnf("Error submitting scan task for URL %s to worker pool: %v. Skipping URL.", currentURL, err)
				// Send an error result directly to resultsChan as the job won't run
				s.resultsChan <- ScanTaskResult{URL: currentURL, Error: fmt.Errorf("failed to submit scan task for %s: %w", currentURL, err)}
				s.waitGroup.Done() // Decrement as this task won't go through the normal result path
			}
		}
	}()

	go func() {
		s.waitGroup.Wait()
		s.logger.Infof("All %d URL scan tasks have been processed by workers.", len(balancedUrls)) // Log count of balanced (and thus processed) URLs
		s.closeResultsChan()
	}()

	return s.resultsChan
}

func (s *Scheduler) closeResultsChan() {
	s.shutdownOnce.Do(func() {
		close(s.resultsChan)
		s.logger.Debugf("Scheduler: Results channel closed.")
	})
}

// Shutdown gracefully stops the scheduler and its worker pool.
func (s *Scheduler) Shutdown() {
	s.logger.Infof("Scheduler shutting down...")
	s.cancelFunc()      // Signal all operations within scheduler to stop
	s.workerPool.Shutdown() // Shutdown the worker pool
	s.closeResultsChan()  // Ensure results chan is closed if not already
	s.logger.Infof("Scheduler shutdown complete.")
} 