package core

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"sync/atomic"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/networking"
	"github.com/rafabd1/Hemlock/internal/utils"
)

const (
	defaultDomainQueueSize          = 100 // Default size for individual domain job queues
	dispatchCheckInterval             = 50 * time.Millisecond // How often the dispatcher checks domains
	// Constants for backoff calculation (can be moved to config or utils if shared more widely)
	// These might be slightly different from scheduler's direct config if we want conductor to have its own nuance
	// For now, let's assume conductor can access these from the main config passed to it.
)

// DomainConductor manages the flow of jobs per domain, respecting DomainManager policies.
type DomainConductor struct {
	config        *config.Config
	logger        utils.Logger
	domainManager *networking.DomainManager
	workerJobQueue chan<- TargetURLJob // Workers pull jobs from this queue

	domainJobQueues map[string]chan TargetURLJob // Stores jobs per domain
	mu              sync.Mutex                   // Protects access to domainJobQueues map

	incomingJobs chan TargetURLJob // Jobs submitted by Scheduler or for retry
	
	activeJobs    *int32        // Pointer to the scheduler's active job counter
	schedulerDoneChan chan struct{} // Scheduler's done channel, closed when activeJobs reaches zero

	jobProgressTickChan chan struct{} // NEW: Signals scheduler to update progress bar

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDomainConductor creates a new DomainConductor.
func NewDomainConductor(
	cfg *config.Config,
	logger utils.Logger,
	dm *networking.DomainManager,
	workerJobQueue chan<- TargetURLJob,
	activeJobsCounter *int32,
	schedulerDoneChan chan struct{},
	parentCtx context.Context,
) *DomainConductor {
	ctx, cancel := context.WithCancel(parentCtx)
	return &DomainConductor{
		config:            cfg,
		logger:            logger,
		domainManager:     dm,
		workerJobQueue:    workerJobQueue,
		domainJobQueues:   make(map[string]chan TargetURLJob),
		incomingJobs:      make(chan TargetURLJob, cfg.Concurrency*2), // Buffer for incoming/retry jobs
		activeJobs:        activeJobsCounter,
		schedulerDoneChan: schedulerDoneChan,
		jobProgressTickChan: make(chan struct{}), // Initialize the new channel
		ctx:               ctx,
		cancel:            cancel,
	}
}

// JobProgressTickChan returns the channel that signals progress updates.
func (dc *DomainConductor) JobProgressTickChan() <-chan struct{} {
	return dc.jobProgressTickChan
}

// Start initiates the DomainConductor's internal goroutines for managing and dispatching jobs.
func (dc *DomainConductor) Start() {
	dc.logger.Infof("[DomainConductor] Starting...")
	dc.wg.Add(2) // One for processIncomingJobs, one for dispatchLoop
	go dc.processIncomingJobs()
	go dc.dispatchLoop()
	dc.logger.Infof("[DomainConductor] Started.")
}

// Stop gracefully shuts down the DomainConductor.
func (dc *DomainConductor) Stop() {
	dc.logger.Infof("[DomainConductor] Stopping...")
	dc.cancel() // Signal goroutines to stop

	dc.mu.Lock()
	// Close incomingJobs first to prevent new submissions during shutdown
	// Check if incomingJobs is not nil and not already closed
	if dc.incomingJobs != nil {
		// Perform a non-blocking check if it's closed to prevent double close panic
		select {
		case _, ok := <-dc.incomingJobs:
			if ok {
				// Channel is open and something was read (put it back if necessary or handle)
				// This case is complex for a simple check. For shutdown, just try to close.
				// A more robust way is a flag `isIncomingJobsClosed`
			}
		default:
			// Channel is empty or non-readable (could be closed)
		}
		// Assuming we need a flag or a more complex check to prevent double close.
		// For now, let's assume single call to Stop()
		close(dc.incomingJobs)
		dc.incomingJobs = nil // Mark as closed
	}

	// Close individual domain queues
	for domain, q := range dc.domainJobQueues {
		if q != nil {
			close(q)
		}
		delete(dc.domainJobQueues, domain)
	}
	dc.mu.Unlock()
	
	dc.wg.Wait() // Wait for all goroutines to finish

	// Close jobProgressTickChan after all goroutines that might send to it are done.
	// This is safe here because wg.Wait() ensures processIncomingJobs and dispatchLoop are finished.
	// DecrementActiveJobsAndSignalCompletion might be called by HandleJobOutcome, which can be called by workers.
	// However, workers should be finishing up if context is cancelled.
	// A truly safe way is to have a separate flag or ensure it's closed only once.
	dc.mu.Lock() // Protect access to jobProgressTickChan for closing
	if dc.jobProgressTickChan != nil {
		close(dc.jobProgressTickChan)
		dc.jobProgressTickChan = nil
	}
	dc.mu.Unlock()

	dc.logger.Infof("[DomainConductor] Stopped.")
}

// SubmitExternalJobToConductor is called by the Scheduler (for initial jobs) or potentially
// by a Worker if a job needs to be fully re-queued from an external perspective.
// It places the job into the DomainConductor's incomingJobs channel for processing.
func (dc *DomainConductor) SubmitExternalJobToConductor(job TargetURLJob) {
	// Check if dc.incomingJobs is not nil and not closed before sending
	dc.mu.Lock() // Protect access to dc.incomingJobs, especially if it can be set to nil in Stop
	targetChannel := dc.incomingJobs
	dc.mu.Unlock()

	if targetChannel == nil {
		dc.logger.Warnf("[DomainConductor] incomingJobs channel is nil, cannot submit job for URL %s. Pool likely stopped.", job.URLString)
		// If job was active, it needs to be accounted for.
		// This implies a job is being submitted after Stop() has been called and completed part of its cleanup.
		// This is a state that should ideally be prevented by the caller.
		// If this job *was* part of activeJobs, we might need to decrement here.
		// However, the design is that activeJobs are decremented when a job is *finished by the conductor/worker*.
		return
	}

	select {
	case targetChannel <- job:
		if dc.config.VerbosityLevel >= 2 {
			dc.logger.Debugf("[DomainConductor] Job for URL %s (Domain: %s, Retries: %d) submitted to incoming queue.", job.URLString, job.BaseDomain, job.Retries)
		}
	case <-dc.ctx.Done():
		dc.logger.Warnf("[DomainConductor] Context cancelled, could not submit job for URL %s to incoming queue.", job.URLString)
	}
}

// processIncomingJobs reads from the incomingJobs channel and routes jobs
// to their respective domain-specific queues.
func (dc *DomainConductor) processIncomingJobs() {
	defer dc.wg.Done()
	dc.logger.Debugf("[DomainConductor] Starting incoming job processor...")
	for {
		select {
		case job, ok := <-dc.incomingJobs:
			if !ok {
				dc.logger.Infof("[DomainConductor] Incoming jobs channel closed. Exiting processor.")
				return
			}
			dc.addJobToDomainQueue(job)
		case <-dc.ctx.Done():
			dc.logger.Infof("[DomainConductor] Context cancelled. Exiting incoming job processor.")
			return
		}
	}
}

// addJobToDomainQueue safely adds a job to the queue for its specific domain.
// It creates the queue if it doesn't exist.
func (dc *DomainConductor) addJobToDomainQueue(job TargetURLJob) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Check if context is done before trying to add, to prevent adding to queues during shutdown
	if dc.ctx.Err() != nil {
		dc.logger.Warnf("[DomainConductor] Context done, not adding job for %s to domain queue %s.", job.URLString, job.BaseDomain)
		return
	}

	queue, exists := dc.domainJobQueues[job.BaseDomain]
	if !exists {
		queue = make(chan TargetURLJob, defaultDomainQueueSize) 
		dc.domainJobQueues[job.BaseDomain] = queue
		if dc.config.VerbosityLevel >= 2 {
			dc.logger.Debugf("[DomainConductor] Created new job queue for domain: %s", job.BaseDomain)
		}
	}

	select {
	case queue <- job:
		if dc.config.VerbosityLevel >= 2 {
			dc.logger.Debugf("[DomainConductor] Added job for %s (Retries: %d) to queue for domain %s. Queue length: %d", job.URLString, job.Retries, job.BaseDomain, len(queue))
		}
	default:
		dc.logger.Warnf("[DomainConductor] Domain queue for %s is full. Job for %s could not be added. This might indicate a processing bottleneck or too many retries overwhelming a slow domain.", job.BaseDomain, job.URLString)
		// If a job cannot be added to a domain queue (e.g. full), it means the system is backlogged for that domain.
		// We should attempt to re-submit it to the incomingJobs queue to be re-evaluated later, possibly with a small delay.
		// This prevents losing the job and its associated activeJob count.
		go func(j TargetURLJob) {
			if dc.config.VerbosityLevel >= 1 {
				dc.logger.Infof("[DomainConductor] Re-submitting job %s for domain %s to main incoming queue due to full domain queue.", j.URLString, j.BaseDomain)
			}
			time.Sleep(100 * time.Millisecond) // Give some time for queues to potentially clear
			// Need to use the public SubmitExternalJobToConductor which handles shutdown checks
			dc.SubmitExternalJobToConductor(j)
		}(job)
	}
}

// dispatchLoop is the core of the DomainConductor. It periodically checks domain readiness
// and dispatches jobs from domain-specific queues to the main workerJobQueue.
func (dc *DomainConductor) dispatchLoop() {
	defer dc.wg.Done()
	dc.logger.Debugf("[DomainConductor] Starting dispatch loop...")
	ticker := time.NewTicker(dispatchCheckInterval) 
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dc.tryDispatchJobs()
		case <-dc.ctx.Done():
			dc.logger.Infof("[DomainConductor] Context cancelled. Exiting dispatch loop.")
			// Drain the ticker channel to prevent resource leak if Stop() is slow
			for range ticker.C { 
			}
			return
		}
	}
}

func (dc *DomainConductor) tryDispatchJobs() {
	dc.mu.Lock()
	domains := make([]string, 0, len(dc.domainJobQueues))
	for domain := range dc.domainJobQueues {
		domains = append(domains, domain)
	}
	dc.mu.Unlock()

	for _, domain := range domains {
		if dc.ctx.Err() != nil { // Check context before processing each domain
			return
		}

		dc.mu.Lock()
		domainQ, exists := dc.domainJobQueues[domain]
		if !exists || len(domainQ) == 0 {
			dc.mu.Unlock()
			continue
		}
		
		// Peek-like operation: try to receive without blocking indefinitely
		var job TargetURLJob
		var jobTaken bool
		select {
		case job = <-domainQ:
			jobTaken = true
		default:
			// No job immediately available from this domain's queue
			jobTaken = false
		}
		dc.mu.Unlock() // Unlock after accessing specific domain queue

		if !jobTaken {
			continue
		}

		canRequest, waitTime := dc.domainManager.CanRequest(domain)
		now := time.Now()

		if canRequest && now.After(job.NextAttemptAt) {
			select {
			case dc.workerJobQueue <- job:
				if dc.config.VerbosityLevel >= 2 {
					dc.logger.Debugf("[DomainConductor] Dispatched job for %s (Domain: %s) to worker queue.", job.URLString, domain)
				}
			default:
				dc.logger.Warnf("[DomainConductor] Worker job queue is full. Job for %s (Domain: %s) could not be dispatched. Re-queueing to domain.", job.URLString, domain)
				dc.requeueJobToDomain(job, "worker queue full") 
			}
		} else {
			if !canRequest && waitTime > 0 && job.NextAttemptAt.Before(now.Add(waitTime)) {
				job.NextAttemptAt = now.Add(waitTime)
				if dc.config.VerbosityLevel >=2 {
					dc.logger.Debugf("[DomainConductor] Job for %s (Domain: %s) not dispatched. DM requires wait: %s. Updated NextAttemptAt: %s", job.URLString, domain, waitTime, job.NextAttemptAt.Format(time.RFC3339))
				}
			} else if dc.config.VerbosityLevel >= 2 && !now.After(job.NextAttemptAt) {
				dc.logger.Debugf("[DomainConductor] Job for %s (Domain: %s) not dispatched. NextAttemptAt (%s) not yet reached.", job.URLString, domain, job.NextAttemptAt.Format(time.RFC3339))
			} else if dc.config.VerbosityLevel >= 2 && !canRequest {
				dc.logger.Debugf("[DomainConductor] Job for %s (Domain: %s) not dispatched. DomainManager returned CanRequest=false, waitTime=%s", job.URLString, domain, waitTime)
			}
			dc.requeueJobToDomain(job, "domain not ready or job not due") 
		}
	}
}

// requeueJobToDomain adds a job back to its domain queue.
func (dc *DomainConductor) requeueJobToDomain(job TargetURLJob, reason string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.ctx.Err() != nil {
		dc.logger.Warnf("[DomainConductor] Context done, not re-queuing job for %s (Reason: %s)", job.URLString, reason)
		// If context is done, this job was taken but not processed. It might be "lost" in terms of active count
		// if not handled elsewhere. However, activeJobs are decremented on definitive completion/discard.
		// This path implies the job might not be processed.
		// Consider if DecrementActiveJobsAndSignalCompletion should be called here if the job is truly abandoned.
		// For now, we assume that if ctx is done, workers will also stop and process their current jobs,
		// and the overall activeJobs count will eventually reconcile.
		return
	}
	
	queue, exists := dc.domainJobQueues[job.BaseDomain]
	if !exists {
		// This could happen if the domain queue was removed between taking the job and trying to re-queue
		// (e.g., if domainJobQueues are dynamically managed and a domain with no jobs is removed).
		// For robustness, recreate the queue or handle as a job to be submitted to incoming.
		dc.logger.Warnf("[DomainConductor] Domain queue for %s disappeared while trying to re-queue job %s. Recreating queue.", job.BaseDomain, job.URLString)
		queue = make(chan TargetURLJob, defaultDomainQueueSize)
		dc.domainJobQueues[job.BaseDomain] = queue
	}
	
	select {
	case queue <- job:
		if dc.config.VerbosityLevel >= 2 {
			dc.logger.Debugf("[DomainConductor] Re-queued job for %s (NextAttempt: %s, Reason: %s) to domain %s. Queue length: %d", job.URLString, job.NextAttemptAt.Format(time.RFC3339), reason, job.BaseDomain, len(queue))
		}
	default:
		dc.logger.Warnf("[DomainConductor] Domain queue for %s FULL during re-queue attempt for %s (Reason: %s). Submitting to incoming for retry.", job.BaseDomain, job.URLString, reason)
		// Non-blocking submission to avoid deadlock and allow conductor to proceed.
		// The job will re-enter the main flow.
		go func(j TargetURLJob) {
			time.Sleep(50 * time.Millisecond) 
			dc.SubmitExternalJobToConductor(j)
		}(job)
	}
}

// HandleJobOutcome is called by a Worker after it has processed a job (or a critical part of it).
// The worker informs the conductor about the outcome, and the conductor decides on retries or completion.
func (dc *DomainConductor) HandleJobOutcome(job TargetURLJob, wasSuccessful bool, failureError error, statusCode int) {
	if dc.ctx.Err() != nil {
		dc.logger.Warnf("[DomainConductor] Context done. Ignoring job outcome for %s.", job.URLString)
		// If context is done, the activeJobs counter might be left hanging if this job was the last one.
		// However, the main shutdown should handle this by waiting for workers.
		// If worker calls this AFTER context is done, it's a late report.
		return
	}

	if wasSuccessful {
		if dc.config.VerbosityLevel >= 1 {
			dc.logger.Infof("[DomainConductor] Job for %s completed successfully by worker. Decrementing active jobs.", job.URLString)
		}
		dc.DecrementActiveJobsAndSignalCompletion()
		return
	}

	// Job was not successful, attempt retry logic
	job.Retries++

	if dc.config.VerbosityLevel >= 1 {
		dc.logger.Warnf("[DomainConductor] Job for %s failed (Attempt %d/%d). Error: %v, Status: %d. Processing retry.", 
			job.URLString, job.Retries, dc.config.MaxRetries, failureError, statusCode)
	}

	if job.Retries < dc.config.MaxRetries {
		var retryDelayDuration time.Duration
		if statusCode == 429 { // Specific handling for 429
			_, standbyEndTime := dc.domainManager.IsStandby(job.BaseDomain)
			retryDelayDuration = time.Until(standbyEndTime)
			// Ensure a minimum positive delay, even if standby just ended or is slightly in the past due to timing.
			if retryDelayDuration < 0 { 
				retryDelayDuration = dc.config.ConductorMinPositiveRetryDelayAfter429 
			}
			if dc.config.VerbosityLevel >= 2 {
				dc.logger.Debugf("[DomainConductor] Job %s (429): Standby for domain %s until %s. Calculated retry delay: %s", job.URLString, job.BaseDomain, standbyEndTime.Format(time.RFC3339), retryDelayDuration)
			}
		} else { // General backoff for other errors
			retryDelayDuration = dc.calculateBackoffForConductor(job.Retries) 
		}
		job.NextAttemptAt = time.Now().Add(retryDelayDuration)

		if dc.config.VerbosityLevel >= 1 {
			dc.logger.Infof("[DomainConductor] Re-submitting job for %s (Domain: %s) for retry. Next attempt after %v (At: %s). Total attempts: %d.", 
				job.URLString, job.BaseDomain, retryDelayDuration, job.NextAttemptAt.Format(time.RFC3339), job.Retries)
		}
		dc.SubmitExternalJobToConductor(job) // Re-submit the updated job to the main flow
	} else {
		if dc.config.VerbosityLevel >= 1 {
			dc.logger.Warnf("[DomainConductor] Job for %s (Domain: %s) DISCARDED after %d retries. Error: %v, Status: %d. Decrementing active jobs.", 
				job.URLString, job.BaseDomain, job.Retries, failureError, statusCode)
		}
		dc.DecrementActiveJobsAndSignalCompletion()
	}
}

// calculateBackoffForConductor calculates an exponential backoff duration for the conductor.
// This is similar to the one in scheduler but uses conductor's config context.
func (dc *DomainConductor) calculateBackoffForConductor(retries int) time.Duration {
	// Uses config values directly accessible via dc.config
	if retries <= 0 {
		return dc.config.ConductorInitialRetryDelay 
	}
	
	// Exponential backoff: initialDuration * 2^(retries-1)
	initialDelay := dc.config.ConductorInitialRetryDelay 
	if initialDelay <= 0 { 
		dc.logger.Warnf("[DomainConductor] ConductorInitialRetryDelay is zero or negative (%.3fs), using fallback of 2s for backoff calculation.", initialDelay.Seconds())
		initialDelay = time.Second * 2 
	} // Fallback for initial backoff delay

	backoffFactor := math.Pow(2, float64(retries-1))
	delay := time.Duration(float64(initialDelay) * backoffFactor)

	// Cap at MaxStandbyDuration (or a specific MaxRetryBackoff if configured)
	maxBackoff := dc.config.ConductorMaxRetryBackoff 
	if maxBackoff <=0 { 
		dc.logger.Warnf("[DomainConductor] ConductorMaxRetryBackoff is zero or negative (%.3fs), using fallback of 60s for backoff calculation.", maxBackoff.Seconds())
		maxBackoff = time.Minute * 1 
	} // Fallback for max backoff

	if delay > maxBackoff {
		delay = maxBackoff
	}

	// Add some jitter to prevent thundering herd if many jobs retry simultaneously
	jitter := time.Duration(rand.Int63n(int64(delay / 5))) // Jitter up to 20% of the delay
	delay += jitter

	if delay < initialDelay && initialDelay > 0 {
		delay = initialDelay
	} else if delay <= 0 {
		dc.logger.Warnf("[DomainConductor] Calculated backoff delay is zero or negative (%.3fs), using fallback of 2s.", delay.Seconds())
		delay = time.Second * 2 // Absolute minimum fallback
	}
	return delay
}

// DecrementActiveJobsAndSignalCompletion is called by the DomainConductor
// when a job is definitively finished (successfully processed or all retries exhausted).
func (dc *DomainConductor) DecrementActiveJobsAndSignalCompletion() {
	// This function seems misplaced if it's intended to be called externally by Scheduler/Worker.
	// The DomainConductor should be the one making the call to atomic.AddInt32
	// when IT determines a job it was managing is truly finished (e.g. after retries it managed).
	// Let's rename or rethink its placement.
	// For now, assuming this is a utility that the Scheduler will call, passing its activeJobs.
	// The design doc implies DomainConductor handles retry and discards, then decrements.
	// So, this function should be internal to DomainConductor or called by it.
	
	// Let's make this an internal helper:
	// func (dc *DomainConductor) decrementSchedulerActiveJobs() { ... }
	// This will be called when DomainConductor discards a job after its own retry logic,
	// or when a worker signals a job is *completely* done (no more scheduler retries).

	// The current `TargetURLJob` has `Retries` field, which is for Scheduler-level retries.
	// DomainConductor will manage these.
	
	remainingJobs := atomic.AddInt32(dc.activeJobs, -1)
	if dc.config.VerbosityLevel >= 1 { // Changed to >=1 for better visibility
		dc.logger.Infof("[DomainConductor] Decremented active jobs. Remaining: %d", remainingJobs)
	}

	// Signal progress update
	// Ensure channel is not nil and not closed before sending (relevant during shutdown)
	dc.mu.Lock()
	tickChan := dc.jobProgressTickChan
	dc.mu.Unlock()
	if tickChan != nil {
		select {
		case tickChan <- struct{}{}:
		case <-dc.ctx.Done(): // Don't block if context is done
			dc.logger.Debugf("[DomainConductor] Context done, did not send progress tick.")
		}
	}

	if remainingJobs == 0 {
		dc.logger.Infof("[DomainConductor] All active jobs processed by conductor's scope. Signaling scheduler completion.")
		select {
		case <-dc.schedulerDoneChan:
			// Already closed
		default:
			close(dc.schedulerDoneChan)
		}
	} else if remainingJobs < 0 {
		dc.logger.Errorf("[DomainConductor] CRITICAL: Active jobs count went negative (%d). This indicates a bug in job lifecycle management.", remainingJobs)
		// To prevent further issues, if it goes negative, try to close doneChan if not already.
		select {
		case <-dc.schedulerDoneChan:
		default:
			close(dc.schedulerDoneChan)
		}
	}
} 