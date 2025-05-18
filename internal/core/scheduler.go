package core

import (
	"container/list"
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

	// Novas filas e estruturas de gerenciamento
	masterJobQueue    chan TargetURLJob
	dispatchQueue     chan TargetURLJob             // Workers consomem daqui
	domainWaitQueues  map[string]*list.List       // Chave: BaseDomain, Valor: Lista de TargetURLJob
	domainWaitQueuesMu sync.Mutex                  // Mutex para proteger domainWaitQueues
	schedulerRetryPQ  *JobPriorityQueue         // Fila de prioridade para jobs em backoff do scheduler

	activeJobs    int32
	maxRetries    int
	doneChan      chan struct{} // Sinaliza que todos os jobs foram processados e queues estão vazias
	
	// Canais para gerenciar o ciclo de vida das goroutines do scheduler
	managerStopChan chan struct{} // Sinal para parar domainQueueManager e schedulerRetryManager

	progressBar             *output.ProgressBar
	totalJobsForProgressBar int
}

// NewScheduler creates a new Scheduler instance.
func NewScheduler(cfg *config.Config, client *networking.Client, processor *Processor, dm *networking.DomainManager, logger utils.Logger) *Scheduler {
	return &Scheduler{
		config:           cfg,
		client:           client,
		processor:        processor,
		domainManager:    dm,
		logger:           logger,
		findings:         make([]*report.Finding, 0),
		maxRetries:       cfg.MaxRetries,
		domainWaitQueues: make(map[string]*list.List),
		// schedulerRetryPQ será inicializado em StartScan
		doneChan:         make(chan struct{}),
		managerStopChan:  make(chan struct{}),
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
	s.logger.Debugf("Scheduler V2: Initializing scan...")
	groupedBaseURLsAndParams, uniqueBaseURLs, _, _ := utils.PreprocessAndGroupURLs(s.config.Targets, s.logger)

	if len(uniqueBaseURLs) == 0 {
		s.logger.Warnf("Scheduler: No processable targets. Aborting scan.")
		return s.findings
	}

	var initialJobs []TargetURLJob
	for _, baseURL := range uniqueBaseURLs {
		parsedBase, _ := url.Parse(baseURL)
		baseDomain := parsedBase.Hostname()
		paramSets := groupedBaseURLsAndParams[baseURL]
		for _, paramSet := range paramSets {
			actualTargetURL, _ := constructURLWithParams(baseURL, paramSet)
			initialJobs = append(initialJobs, TargetURLJob{URLString: actualTargetURL, BaseDomain: baseDomain, OriginalParams: paramSet})
		}
	}

	if len(initialJobs) == 0 {
		s.logger.Warnf("Scheduler: No testable URL jobs created. Aborting scan.")
		return s.findings
	}

	s.totalJobsForProgressBar = len(initialJobs)
	atomic.StoreInt32(&s.activeJobs, int32(s.totalJobsForProgressBar))

	if s.totalJobsForProgressBar > 0 {
		s.progressBar = output.NewProgressBar(s.totalJobsForProgressBar, 40)
		s.progressBar.SetPrefix("Scanning V2: ")
		s.progressBar.Start()
		defer func() {
			s.progressBar.Finalize()
			output.SetActiveProgressBar(nil)
		}()
	}

	concurrencyLimit := s.config.Concurrency
	if concurrencyLimit <= 0 { concurrencyLimit = 1 }

	// Inicializar filas com buffer apropriado
	s.masterJobQueue = make(chan TargetURLJob, len(initialJobs))
	s.dispatchQueue = make(chan TargetURLJob, concurrencyLimit*2) // Buffer para workers
	s.schedulerRetryPQ = NewJobPriorityQueue(len(initialJobs)) // Capacidade inicial

	// Iniciar goroutines gerenciadoras
	s.wg.Add(2) // Para domainQueueManager e schedulerRetryManager
	go s.domainQueueManager()
	go s.schedulerRetryManager()

	// Iniciar workers
	for i := 0; i < concurrencyLimit; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}

	// Popular masterJobQueue com jobs iniciais
	for _, job := range initialJobs {
		s.masterJobQueue <- job
	}
	// Fechar masterJobQueue APÓS todos os jobs iniciais serem enfileirados E 
	// APÓS a schedulerRetryManager ter uma chance de reenfileirar jobs.
	// Isso será gerenciado pelo doneChan e managerStopChan.

	<-s.doneChan // Esperar que todos os jobs sejam processados

	s.logger.Infof("Scheduler: All jobs processed. Signalling managers to stop...")
	close(s.managerStopChan) // Sinalizar para as goroutines gerenciadoras pararem

	s.wg.Wait() // Esperar que todas as goroutines (workers e managers) terminem
	s.logger.Infof("Scheduler: All scan tasks, workers, and managers completed.")
	return s.findings
}

// processURLJob is where individual URL processing, baseline requests, and probe tests happen.
// THIS ENTIRE FUNCTION (processURLJob) WILL BE REMOVED as its logic is being integrated into the new worker method.
/*
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
			s.retryQueue <- job // ERROR: s.retryQueue is V1
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

		if statusCode == 429 { // Specific handling for 429
			s.logger.Warnf("[Worker %d] Job for %s (baseline) got 429. Error: %s. Domain %s put on standby by DM.", workerID, job.URLString, errMsg, job.BaseDomain)
			// DomainManager already handles standby. Re-queue the job for a later attempt via retryQueue.
			job.Retries++
			if job.Retries < s.maxRetries {
				job.NextAttemptAt = time.Now().Add(s.domainManager.GetRetryAfter(job.BaseDomain)) // Use retry-after from DM
				s.logger.Infof("[Worker %d] Job for %s will be retried for 429 after %v.", workerID, job.URLString, time.Until(job.NextAttemptAt))
				s.retryQueue <- job // ERROR: s.retryQueue is V1
			} else {
				s.logger.Warnf("[Worker %d] Job for %s DISCARDED after %d retries (last was 429).", workerID, job.URLString, job.Retries)
				s.decrementActiveJobs()
			}
			return // Stop processing this job further in this attempt
		}

		// General error handling for baseline (non-429)
		job.Retries++
		if job.Retries < s.maxRetries {
			backoffDuration := calculateBackoff(job.Retries, s.config.InitialStandbyDuration, s.config.MaxStandbyDuration, s.config.StandbyDurationIncrement)
			job.NextAttemptAt = time.Now().Add(backoffDuration)
			s.logger.Infof("[Worker %d] Baseline for %s failed (Status: %d, Err: %s). Attempt %d/%d. Re-queueing after %v.",
				workerID, job.URLString, statusCode, errMsg, job.Retries, s.maxRetries, backoffDuration)
			s.retryQueue <- job // ERROR: s.retryQueue is V1
		} else {
			s.logger.Warnf("[Worker %d] Baseline for %s DISCARDED after %d retries. Last Error: %s", workerID, job.URLString, job.Retries, errMsg)
			s.decrementActiveJobs()
		}
		return // Stop processing this job further
	}

	// Baseline request successful
	baselineProbe := buildProbeData(job.URLString, baselineReqData, baselineRespData)

	// Test with modified headers (Probe A)
	for _, header := range s.config.HeadersToTest {
		// Check domain readiness before each probe request
		canProceedProbe, probeWaitTime := s.domainManager.CanRequest(job.BaseDomain)
		for !canProceedProbe {
			if s.config.VerbosityLevel >= 1 { // -v
				s.logger.Infof("[Worker %d] Job %s, Header Probe '%s': Domain %s busy. Waiting %v.", workerID, job.URLString, header.Name, job.BaseDomain, probeWaitTime)
			}
			time.Sleep(probeWaitTime)
			canProceedProbe, probeWaitTime = s.domainManager.CanRequest(job.BaseDomain)
		}
		s.domainManager.RecordRequestSent(job.BaseDomain)

		headerProbeReqData := networking.ClientRequestData{
			URL:           job.URLString,
			Method:        "GET", // Or from config if method varies
			CustomHeaders: map[string]string{header.Name: header.Value},
		}
		headerProbeRespData := s.client.PerformRequest(headerProbeReqData)
		s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(headerProbeRespData.Response), headerProbeRespData.Error)
		
		if headerProbeRespData.Error != nil || statusCodeFromResponse(headerProbeRespData.Response) == 429 {
			statusCode := statusCodeFromResponse(headerProbeRespData.Response)
			errMsg := "request failed"
			if headerProbeRespData.Error != nil {
				errMsg = headerProbeRespData.Error.Error()
			}
			s.logger.Warnf("[Worker %d] Header probe '%s:%s' for %s failed (Status: %d, Err: %s). Re-queueing job.", 
				workerID, header.Name, header.Value, job.URLString, statusCode, errMsg)
			job.Retries++
			if job.Retries < s.maxRetries {
				nextAttemptDelay := calculateBackoff(job.Retries, s.config.InitialStandbyDuration, s.config.MaxStandbyDuration, s.config.StandbyDurationIncrement)
				if statusCode == 429 {
					nextAttemptDelay = s.domainManager.GetRetryAfter(job.BaseDomain)
				}
				job.NextAttemptAt = time.Now().Add(nextAttemptDelay)
				s.retryQueue <- job // ERROR: s.retryQueue is V1
			} else {
				s.logger.Warnf("[Worker %d] Job for %s DISCARDED after %d retries (header probe failed).", workerID, job.URLString, job.Retries)
				s.decrementActiveJobs()
			}
			return // Stop processing this job further
		}
		headerProbeData := buildProbeData(job.URLString, headerProbeReqData, headerProbeRespData)
		if finding := s.processor.ProcessHeaderProbe(job.URLString, header, baselineProbe, headerProbeData); finding != nil {
			s.addFinding(finding)
		}
	}

	// Test with modified parameters (Probe B)
	for _, param := range s.config.ParametersToTest { // Assuming ParametersToTest is a list of {Name, Value} structs
		modifiedURL, err := modifyURLQueryParam(job.URLString, param.Name, param.Value)
		if err != nil {
			s.logger.Errorf("[Worker %d] Error modifying URL %s for param testing %s=%s: %v. Skipping param test.", workerID, job.URLString, param.Name, param.Value, err)
			continue
		}

		// Check domain readiness before each probe request
		canProceedProbe, probeWaitTime := s.domainManager.CanRequest(job.BaseDomain)
		for !canProceedProbe {
			if s.config.VerbosityLevel >= 1 { // -v
				s.logger.Infof("[Worker %d] Job %s, Param Probe '%s=%s': Domain %s busy. Waiting %v.", workerID, modifiedURL, param.Name, param.Value, job.BaseDomain, probeWaitTime)
			}
			time.Sleep(probeWaitTime)
			canProceedProbe, probeWaitTime = s.domainManager.CanRequest(job.BaseDomain)
		}
		s.domainManager.RecordRequestSent(job.BaseDomain)

		paramProbeReqData := networking.ClientRequestData{URL: modifiedURL, Method: "GET"}
		paramProbeRespData := s.client.PerformRequest(paramProbeReqData)
		s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(paramProbeRespData.Response), paramProbeRespData.Error)

		if paramProbeRespData.Error != nil || statusCodeFromResponse(paramProbeRespData.Response) == 429 {
			statusCode := statusCodeFromResponse(paramProbeRespData.Response)
			errMsg := "request failed"
			if paramProbeRespData.Error != nil {
				errMsg = paramProbeRespData.Error.Error()
			}
			s.logger.Warnf("[Worker %d] Param probe '%s=%s' for %s (URL: %s) failed (Status: %d, Err: %s). Re-queueing job.", 
				workerID, param.Name, param.Value, job.URLString, modifiedURL, statusCode, errMsg)
			job.Retries++
			if job.Retries < s.maxRetries {
				nextAttemptDelay := calculateBackoff(job.Retries, s.config.InitialStandbyDuration, s.config.MaxStandbyDuration, s.config.StandbyDurationIncrement)
				if statusCode == 429 {
					nextAttemptDelay = s.domainManager.GetRetryAfter(job.BaseDomain)
				}
				job.NextAttemptAt = time.Now().Add(nextAttemptDelay)
				s.retryQueue <- job // ERROR: s.retryQueue is V1
			} else {
				s.logger.Warnf("[Worker %d] Job for %s DISCARDED after %d retries (param probe failed).", workerID, job.URLString, job.Retries)
				s.decrementActiveJobs()
			}
			return // Stop processing this job further
		}
		paramProbeData := buildProbeData(modifiedURL, paramProbeReqData, paramProbeRespData)
		if finding := s.processor.ProcessParamProbe(job.URLString, param, baselineProbe, paramProbeData); finding != nil {
			s.addFinding(finding)
		}
	}

	s.decrementActiveJobs()
	if s.config.VerbosityLevel >= 1 { // -v
		s.logger.Infof("[Worker %d] Completed processing for job: %s. Remaining: %d", workerID, job.URLString, atomic.LoadInt32(&s.activeJobs))
	}
}
*/

// Lógica de decrementActiveJobs (ajustada se necessário)
func (s *Scheduler) decrementActiveJobs() {
	remainingJobs := atomic.AddInt32(&s.activeJobs, -1)
	if s.progressBar != nil {
		completedJobs := s.totalJobsForProgressBar - int(remainingJobs)
		s.progressBar.Update(completedJobs)
	}

	if remainingJobs == 0 {
		if s.config.VerbosityLevel >= 1 {
			s.logger.Infof("All active jobs completed. Closing doneChan.")
		} else {
			s.logger.Debugf("All active jobs completed. Closing doneChan.")
		}
		// Verifica se doneChan já está fechado para evitar pânico
		select {
		case <-s.doneChan:
			// Já fechado
		default:
			close(s.doneChan)
		}
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

// Esqueletos para as novas goroutines gerenciadoras e worker

func (s *Scheduler) domainQueueManager() {
	defer s.wg.Done()
	defer s.logger.Debugf("[DomainQueueManager] Exiting.")
	s.logger.Debugf("[DomainQueueManager] Started.")

	ticker := time.NewTicker(100 * time.Millisecond) 
	defer ticker.Stop()

	for {
		select {
		case <-s.managerStopChan:
			s.logger.Infof("[DomainQueueManager] Received stop signal. Processing remaining jobs in domainWaitQueues...")
			// Tentar despachar o que resta nas filas de espera do domínio uma última vez
			s.processDomainWaitQueues(true) // true para indicar que é uma tentativa final de drenagem
			// TODO: Considerar o que fazer com jobs que não puderam ser despachados aqui.
			// Poderiam ser explicitamente "descartados" e activeJobs decrementado se não forem mais ser processados.
			// Por ora, a lógica de decrementActiveJobs depende dos workers ou do schedulerRetryManager descartando.
			
			// Fechar dispatchQueue apenas se este manager for o único produtor restante para ela
			// e não houver mais jobs que possam ser adicionados por ele.
			// Isso é complexo se schedulerRetryManager também pode adicionar indiretamente.
			// O fechamento de dispatchQueue pode ser melhor gerenciado quando todos os workers terminam
			// e não há mais fontes de jobs.
			// Por agora, vamos deixar o fechamento da dispatchQueue para quando os workers terminarem (se o range sobre ela terminar).
			return
		case job, ok := <-s.masterJobQueue: // CORRIGIDO: espaço após case
			if !ok {
				s.logger.Debugf("[DomainQueueManager] masterJobQueue closed.")
				s.masterJobQueue = nil 
				// Se masterJobQueue está fechada, este manager ainda precisa processar domainWaitQueues
				// e eventualmente parar quando managerStopChan for fechado e não houver mais trabalho.
				continue
			}
			s.dispatchOrWait(job)

		case <-ticker.C:
			s.processDomainWaitQueues(false) // false para processamento normal
			// Verificar se não há mais fontes de jobs e as filas estão vazias para potencialmente parar antes
			// if s.masterJobQueue == nil && s.areAllDomainWaitQueuesEmpty() && s.schedulerRetryPQ.Len() == 0 {
			// 	s.logger.Infof("[DomainQueueManager] No more jobs from master, domain queues empty, and retry PQ empty. Requesting stop.")
			// 	// Este é um ponto onde poderíamos sinalizar para fechar doneChan se activeJobs também for 0.
			// 	// No entanto, o doneChan é fechado por decrementActiveJobs. Aqui só pararíamos este manager.
			// 	// close(s.managerStopChan) // Não, isso é muito cedo, pode haver retries.
			// }
		}
	}
}

func (s *Scheduler) dispatchOrWait(job TargetURLJob) {
	nextAvailableTime := s.domainManager.GetNextAvailableTime(job.BaseDomain)

	if time.Now().After(nextAvailableTime) || time.Now().Equal(nextAvailableTime) {
		// Tentar enviar para dispatchQueue sem bloquear
		select {
		case s.dispatchQueue <- job:
			if s.config.VerbosityLevel >= 2 {
				s.logger.Debugf("[DomainQueueManager] Job for %s dispatched immediately to worker queue.", job.URLString)
			}
		default:
			// dispatchQueue está cheia, colocar na fila de espera do domínio
			if s.config.VerbosityLevel >= 1 {
				s.logger.Infof("[DomainQueueManager] dispatchQueue full. Job for %s for domain %s sent to wait queue.", job.URLString, job.BaseDomain)
			}
			s.addToDomainWaitQueue(job)
		}
	} else {
		// Precisa esperar, colocar na fila de espera do domínio
		if s.config.VerbosityLevel >= 1 {
			delay := time.Until(nextAvailableTime)
			s.logger.Infof("[DomainQueueManager] Domain %s not ready for %s. Waiting for %v. Job sent to wait queue.", job.BaseDomain, job.URLString, delay)
		}
		s.addToDomainWaitQueue(job)
	}
}

func (s *Scheduler) addToDomainWaitQueue(job TargetURLJob) {
	s.domainWaitQueuesMu.Lock()
	defer s.domainWaitQueuesMu.Unlock()

	domainList, exists := s.domainWaitQueues[job.BaseDomain]
	if !exists {
		domainList = list.New()
		s.domainWaitQueues[job.BaseDomain] = domainList
	}
	domainList.PushBack(job)
	if s.config.VerbosityLevel >= 2 {
		s.logger.Debugf("[DomainQueueManager] Job for %s added to wait queue for domain %s (queue size: %d).", job.URLString, job.BaseDomain, domainList.Len())
	}
}

func (s *Scheduler) processDomainWaitQueues(draining bool) { // draining indica se estamos tentando limpar as filas antes de sair
	s.domainWaitQueuesMu.Lock()
	defer s.domainWaitQueuesMu.Unlock()

	for domain, domainList := range s.domainWaitQueues {
		if domainList.Len() == 0 {
			continue
		}

		// Verificar disponibilidade do domínio repetidamente enquanto houver jobs e o domínio estiver pronto
		for domainList.Len() > 0 {
			nextAvailableTime := s.domainManager.GetNextAvailableTime(domain) // Re-checar a cada job
			if !(time.Now().After(nextAvailableTime) || time.Now().Equal(nextAvailableTime)) {
				// Domínio não está pronto para o próximo job desta fila de espera
				if s.config.VerbosityLevel >= 2 && !draining { // Log menos frequente se estiver drenando
					delay := time.Until(nextAvailableTime)
					s.logger.Debugf("[DomainQueueManager] processDomainWaitQueues: Domain %s for job %s (wait queue) not ready. Needs %v.", domain, domainList.Front().Value.(TargetURLJob).URLString, delay)
				}
				break // Passa para o próximo domínio
			}

			// Domínio está pronto, tentar despachar o primeiro job da fila
			element := domainList.Front()
			job := element.Value.(TargetURLJob)

			select {
			case s.dispatchQueue <- job:
				domainList.Remove(element) // Remove da fila de espera APENAS se enviado com sucesso
				if s.config.VerbosityLevel >= 1 {
					s.logger.Infof("[DomainQueueManager] Job for %s (from %s wait queue) dispatched to worker. Remaining in wait queue: %d.", job.URLString, domain, domainList.Len())
				}
				// Após despachar um job, o lastRequestTime do domínio será atualizado pelo worker.
				// A próxima chamada a GetNextAvailableTime para este domínio refletirá isso.
				// Continuar no loop interno para ver se mais jobs deste domínio podem ser despachados AGORA
				// (se o RPS for alto e o tempo de processamento do worker for rápido).
			default:
				// dispatchQueue está cheia, não podemos despachar agora.
				if s.config.VerbosityLevel >= 1 && !draining {
					s.logger.Infof("[DomainQueueManager] dispatchQueue full while processing wait queue for domain %s. Will retry later.", domain)
				}
				break // Passa para o próximo domínio (ou sai do loop interno se este era o único job)
			}
		}
	}
}

// func (s *Scheduler) areAllDomainWaitQueuesEmpty() bool { ... } // (Implementar se necessário para shutdown gracioso)

// ... (schedulerRetryManager, worker - ainda precisam da lógica completa) ...
// ... (buildProbeData, etc.) ...

// Implementação esqueleto para schedulerRetryManager
func (s *Scheduler) schedulerRetryManager() {
	defer s.wg.Done()
	defer s.logger.Debugf("[SchedulerRetryManager] Exiting.")
	s.logger.Debugf("[SchedulerRetryManager] Started.")

	// Ticker para verificar a schedulerRetryPQ
	// A frequência pode ser dinâmica baseada no PeekNextTime()
	// ou um ticker fixo se PeekNextTime() for muito custoso para checar frequentemente.
	ticker := time.NewTicker(200 * time.Millisecond) // Ex: verificar a cada 200ms
	defer ticker.Stop()

	for {
		select {
		case <-s.managerStopChan:
			s.logger.Infof("[SchedulerRetryManager] Received stop signal. Processing remaining jobs in retry PQ...")
			// TODO: Decidir o que fazer com jobs restantes na PQ.
			//       Por agora, se não puderem ser reenfileirados imediatamente, serão perdidos.
			//       Uma opção é tentar reenfileirá-los uma última vez.
			for s.schedulerRetryPQ.Len() > 0 {
				job, ready := s.schedulerRetryPQ.GetNextJobIfReady()
				if !ready {
					break // Nenhum job pronto
				}
				s.logger.Debugf("[SchedulerRetryManager] Draining: Job for %s (retry %d) ready. Re-queueing to masterJobQueue.", job.URLString, job.Retries)
				// Tentar enviar para masterJobQueue sem bloquear. Se falhar, o job é perdido neste ponto do shutdown.
				// Isso é aceitável se o masterJobQueue não estiver sendo mais consumido ou estiver cheio.
				select {
				case s.masterJobQueue <- *job:
					// Job reenfileirado
				default:
					s.logger.Warnf("[SchedulerRetryManager] Draining: Failed to re-queue job for %s to masterJobQueue (full or closed). Job lost.", job.URLString)
					s.decrementActiveJobs() // Decrementar pois o job não será mais processado
				}
			}
			return
		case <-ticker.C:
			for {
				job, ready := s.schedulerRetryPQ.GetNextJobIfReady()
				if !ready {
					break // Nenhum job pronto agora
				}
				s.logger.Debugf("[SchedulerRetryManager] Job for %s (retry %d) ready. Re-queueing to masterJobQueue.", job.URLString, job.Retries)
				
				// Se masterJobQueue estiver nil (foi fechada e não está mais aceitando jobs),
				// então não podemos reenfileirar. Isso não deveria acontecer se managerStopChan
				// ainda não foi fechado e os workers ainda estão processando.
				// A masterJobQueue é fechada pelo chamador de StartScan APÓS doneChan e APÓS managerStopChan.
				// No entanto, se os workers pararem de consumir dispatchQueue, e domainQueueManager parar de produzir para dispatchQueue,
				// e masterJobQueue estiver cheia, isso pode bloquear.
				// Usar um select para evitar bloqueio indefinido se masterJobQueue estiver cheia.
				select {
				case s.masterJobQueue <- *job:
					// Job reenfileirado com sucesso
					if s.config.VerbosityLevel >= 1 {
						s.logger.Infof("[SchedulerRetryManager] Job for %s (retry %d) re-queued to masterJobQueue.", job.URLString, job.Retries)
					}
				default:
					// Não conseguiu reenfileirar (masterJobQueue cheia ou fechada).
					// Devolver para a retry PQ para tentar mais tarde.
					// Isso pode acontecer se a masterJobQueue estiver temporariamente cheia.
					// Adicionar um pequeno delay ou re-adicionar com o mesmo NextAttemptAt pode ser uma opção,
					// mas para evitar complexidade, vamos apenas logar e assumir que o próximo tick tentará novamente.
					// Se a masterJobQueue estiver consistentemente cheia, indica um problema de fluxo.
					s.logger.Warnf("[SchedulerRetryManager] Failed to re-queue job for %s to masterJobQueue. Will retry later.", job.URLString)
					s.schedulerRetryPQ.AddJob(*job) // Readicionar para tentar mais tarde
					// Para evitar um loop apertado se a masterJobQueue estiver sempre cheia, sair do loop interno
					// e esperar pelo próximo tick.
					goto nextTickerIteration
				}
			}
		nextTickerIteration:
		}
	}
}

// Implementação esqueleto para worker
func (s *Scheduler) worker(workerID int) {
	defer s.wg.Done()
	s.logger.Debugf("[Worker %d] Started.", workerID)

	for job := range s.dispatchQueue { // Consome da nova fila de despacho
		if s.config.VerbosityLevel >= 2 {
			s.logger.Debugf("[Worker %d] Processing URL: %s (Attempt %d, Total Active: %d)",
				workerID, job.URLString, job.Retries+1, atomic.LoadInt32(&s.activeJobs))
		}
		
		// Worker NÃO chama mais CanRequest diretamente para controle de taxa de domínio.
		// Assume que o job na dispatchQueue está pronto do ponto de vista do domínio (RPS).
		// O worker precisa, no entanto, registrar que o domínio foi usado.
		s.domainManager.RecordRequestSent(job.BaseDomain)

		// ----- INÍCIO DA LÓGICA DE PROCESSAMENTO DO JOB (SIMPLIFICADO) -----
		// Esta parte precisa ser completamente reimplementada com a lógica de baseline, probes A e B.
		// A lógica de retry abaixo é um exemplo e precisa ser integrada corretamente
		// com o resultado de cada etapa (baseline, probe header, probe param).

		// Exemplo: Realizar a requisição baseline
		baselineReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET"}
		// NOTA: performRequestWithDomainManagement NÃO deve ser usado aqui, pois o controle de taxa já foi feito.
		// Usar client.PerformRequest diretamente.
		baselineRespData := s.client.PerformRequest(baselineReqData)
		
		// Notificar DomainManager sobre o resultado (especialmente para 429)
		s.domainManager.RecordRequestResult(job.BaseDomain, statusCodeFromResponse(baselineRespData.Response), baselineRespData.Error)

		var currentErr error = baselineRespData.Error
		var currentStatusCode int = statusCodeFromResponse(baselineRespData.Response)
		
		// Lógica de Retry (Simplificada - precisa de integração com a máquina de estados de probes)
		// Se um erro que requer retry do SCHEDULER (ex: 429, ou erro de rede persistente)
		if currentErr != nil || currentStatusCode == 429 || currentStatusCode >= 500 {
			errMsg := "request failed"
			if currentErr != nil {
				errMsg = currentErr.Error()
			}

			if currentStatusCode == 429 {
				// DomainManager já foi notificado. O job deve ser reenfileirado via schedulerRetryPQ
				// para respeitar o novo standby do domínio.
				s.logger.Warnf("[Worker %d] Job for %s (baseline) got 429. Error: %s. Re-queueing for scheduler retry.", workerID, job.URLString, errMsg)
				job.Retries++ // Incrementar retries globais do job
				job.NextAttemptAt = s.domainManager.GetNextAvailableTime(job.BaseDomain) // CORRIGIDO: Usar GetNextAvailableTime
				if job.Retries < s.maxRetries {
					s.schedulerRetryPQ.AddJob(job)
				} else {
					s.logger.Warnf("[Worker %d] Job for %s DISCARDED after %d retries (last was 429).", workerID, job.URLString, job.Retries)
					s.decrementActiveJobs()
				}
				continue // Próximo job da dispatchQueue
			}

			// Outros erros (rede, 5xx)
			job.Retries++
			if job.Retries < s.maxRetries {
				job.NextAttemptAt = time.Now().Add(calculateBackoff(job.Retries, s.config.InitialStandbyDuration, s.config.MaxStandbyDuration, s.config.StandbyDurationIncrement))
				s.logger.Infof("[Worker %d] Baseline for %s failed (Status: %d, Err: %s). Attempt %d/%d. Re-queueing to schedulerRetryPQ after %v.",
					workerID, job.URLString, currentStatusCode, errMsg, job.Retries, s.maxRetries, time.Until(job.NextAttemptAt))
				s.schedulerRetryPQ.AddJob(job)
			} else {
				s.logger.Warnf("[Worker %d] Baseline for %s DISCARDED after %d retries. Last Status: %d, Error: %s", workerID, job.URLString, job.Retries, currentStatusCode, errMsg)
				s.decrementActiveJobs()
			}
			continue // Próximo job da dispatchQueue
		}

		// Se baseline foi bem-sucedido:
		// Aqui viria a lógica de processar o baselineRespData, construir ProbeData,
		// e então realizar as probes A (headers) e B (params).
		// Cada probe pode falhar e levar a uma lógica de retry similar à acima.
		// Se um probe específico falhar (ex: um header específico causa um erro),
		// e essa falha não for um 429 ou 5xx que afeta o domínio inteiro,
		// pode-se considerar um retry "local" do worker (ainda não implementado)
		// ou reenfileirar o job inteiro para o schedulerRetryPQ.
		// Por simplicidade agora, qualquer falha de probe que necessite retry
		// reenfileirará o job inteiro para schedulerRetryPQ.

		s.logger.Infof("[Worker %d] Baseline for %s successful (Status: %d). TODO: Implement probe logic.", workerID, job.URLString, currentStatusCode)

		// Placeholder para indicar que o job foi processado (mesmo que só o baseline)
		// A lógica real de decrementActiveJobs ocorreria após todas as probes e análises.
		// Se uma probe falhar e for para retry, NÃO decrementar aqui.
		
		// Por ora, se chegou aqui sem ir para retry, decrementamos.
		// ISSO PRECISA MUDAR: decrementActiveJobs só no final do processamento completo do job.
		s.decrementActiveJobs() 
		// ----- FIM DA LÓGICA DE PROCESSAMENTO DO JOB (SIMPLIFICADO) -----
	}
	s.logger.Debugf("[Worker %d] Exiting (dispatchQueue closed).", workerID)
}