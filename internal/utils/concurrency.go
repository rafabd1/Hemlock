package utils

import (
	"context"
	"fmt"
	"sync"
)

// Job represents a function to be executed by a worker.
// It returns a generic interface{} result and an error.
type Job func() (interface{}, error)

// WorkerPool manages a pool of goroutines to perform tasks concurrently.
// Based on ARCHITECTURE_NETWORKING_CONCURRENCY.md.
type WorkerPool struct {
	numWorkers int
	jobQueue   chan Job
	results    chan interface{}
	errors     chan error
	ctx        context.Context
	cancel     context.CancelFunc // To signal workers to stop
	shutdownWg sync.WaitGroup   // To wait for all workers to finish during shutdown
	mu         sync.Mutex       // For protecting access to isClosed and jobQueue closing
	isClosed   bool
}

// NewWorkerPool creates and starts a new WorkerPool.
func NewWorkerPool(parentCtx context.Context, numWorkers int, queueSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(parentCtx)
	wp := &WorkerPool{
		numWorkers: numWorkers,
		jobQueue:   make(chan Job, queueSize),
		results:    make(chan interface{}, queueSize), // Buffered to prevent blocking sender if receiver is slow
		errors:     make(chan error, queueSize),     // Buffered for the same reason
		ctx:        ctx,
		cancel:     cancel,
	}

	wp.start()
	return wp
}

// start initializes the workers.
func (wp *WorkerPool) start() {
	wp.shutdownWg.Add(wp.numWorkers)
	for i := 0; i < wp.numWorkers; i++ {
		go wp.worker()
	}

	// Goroutine to clean up channels once all workers are done with current jobs after ctx is cancelled
	go func() {
		wp.shutdownWg.Wait() // Wait for all workers to signal they've exited their loops
		close(wp.results)    // Safe to close now
		close(wp.errors)     // Safe to close now
	}()
}

// worker is the internal function executed by each goroutine in the pool.
func (wp *WorkerPool) worker() {
	defer wp.shutdownWg.Done()
	// fmt.Printf("Worker starting\n") // For debugging
	for {
		select {
		case job, ok := <-wp.jobQueue:
			if !ok {
				// fmt.Printf("Worker: jobQueue closed, exiting.\n") // For debugging
				return // Job queue was closed, exit worker
			}
			// Execute the job
			// fmt.Printf("Worker processing job\n") // For debugging
			result, err := job()
			if err != nil {
				select {
				case wp.errors <- err:
				case <-wp.ctx.Done(): // If context is cancelled while trying to send error
					// fmt.Printf("Worker: context cancelled while sending error. Error: %v\n", err) // For debugging
					return
				}
			} else if result != nil { // Only send non-nil results
				select {
				case wp.results <- result:
				case <-wp.ctx.Done(): // If context is cancelled while trying to send result
					// fmt.Printf("Worker: context cancelled while sending result.\n", id) // For debugging
					return
				}
			}
		case <-wp.ctx.Done(): // Context was cancelled (e.g., by Shutdown)
			// fmt.Printf("Worker: context cancelled, exiting.\n") // For debugging
			return
		}
	}
}

// Submit adds a task to the job queue.
// Returns an error if the context is cancelled or the pool is closed and cannot accept new jobs.
func (wp *WorkerPool) Submit(job Job) error {
	wp.mu.Lock()
	if wp.isClosed {
		wp.mu.Unlock()
		return fmt.Errorf("worker pool is closed, cannot submit new jobs")
	}
	wp.mu.Unlock()

	select {
	case wp.jobQueue <- job:
		return nil
	case <-wp.ctx.Done():
		return wp.ctx.Err() // Pool is shutting down or parent context cancelled
	}
}

// Results returns a channel to read task results from.
func (wp *WorkerPool) Results() <-chan interface{} {
	return wp.results
}

// Errors returns a channel to read task errors from.
func (wp *WorkerPool) Errors() <-chan error {
	return wp.errors
}

// Shutdown gracefully shuts down the worker pool.
// It signals workers to stop, waits for them to finish current jobs, then closes job and result/error channels.
func (wp *WorkerPool) Shutdown() {
	wp.mu.Lock()
	if wp.isClosed {
		wp.mu.Unlock()
		return // Already shutdown
	}
	wp.isClosed = true
	close(wp.jobQueue) // Signal no more jobs will be sent, workers will exit after processing remaining jobs
	wp.mu.Unlock()

	wp.cancel() // Signal workers to stop processing new items from queue if they haven't picked one up
	// The goroutine started in `start()` will wait for `shutdownWg` and then close `results` and `errors` channels.
}

// TODO: Implement SimpleWorkerPool, BoundedSemaphore, etc., as per your architecture document if needed later. 