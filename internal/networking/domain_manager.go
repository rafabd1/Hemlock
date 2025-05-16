package networking

import (
	"fmt"
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config" // To access MinRequestDelayMs, DomainCooldownMs, DelayMs
	"github.com/rafabd1/Hemlock/internal/utils"
)

const (
	// DefaultDomainCooldownMs is the default cooldown period for a domain after being blocked.
	DefaultDomainCooldownMs = 60000 // 1 minute (formerly from config.DomainCooldownMs)
)

// DefaultStatusCodesToBlock lists HTTP status codes that should always trigger a domain cooldown.
var DefaultStatusCodesToBlock = []int{403, 429, 503} // (formerly from config.StatusCodesToBlock)

// DefaultStatusCodesToBlockOnError lists HTTP status codes that, if an error also occurs, trigger a domain cooldown.
var DefaultStatusCodesToBlockOnError = []int{} // (formerly from config.StatusCodesToBlockOnError)

// domainState stores the state of a specific domain.
type domainState struct {
	lastRequestTime     time.Time
	blockedUntil        time.Time
	consecutiveFailures int // Field to track consecutive failures
}

// DomainManager manages state and policies per domain,
// including rate limiting and blocking detection (WAF).
// It is crucial for the intelligent behavior of the tool in relation to specific domains.
type DomainManager struct {
	config       *config.Config // To read MinRequestDelayMs, DomainCooldownMs, DelayMs
	logger       utils.Logger
	domainStatus map[string]*domainState
	mu           sync.RWMutex // Protects access to domainStatus
}

// NewDomainManager creates a new instance of DomainManager.
func NewDomainManager(cfg *config.Config, logger utils.Logger) *DomainManager {
	return &DomainManager{
		config:       cfg,
		logger:       logger,
		domainStatus: make(map[string]*domainState),
	}
}

// getOrCreateDomainState retrieves or creates the state for a domain.
// Should be called with the appropriate lock (read or write) already acquired.
func (dm *DomainManager) getOrCreateDomainState(domain string) *domainState {
	ds, exists := dm.domainStatus[domain]
	if !exists {
		ds = &domainState{}
		dm.domainStatus[domain] = ds
	}
	return ds
}

// CanRequest checks if a request can be made to a domain.
// Returns true if it can, false otherwise, along with the necessary wait time.
func (dm *DomainManager) CanRequest(domain string) (bool, time.Duration) {
	dm.mu.RLock()
	// ds := dm.getOrCreateDomainState(domain) // Read, doesn't create if it doesn't exist under RLock
	// To ensure that getOrCreateDomainState can create, we need a write lock
	// or a double-check approach. Let's simplify for now and assume that
	// the state will be created on the first write (RecordRequestSent).
	// For CanRequest, if it doesn't exist, there are no restrictions yet.
	existingDs, exists := dm.domainStatus[domain]
	dm.mu.RUnlock() // Release RLock before a possible WLock

	if !exists { // If the domain hasn't been seen, can proceed without delay
		return true, 0
	}

	// Re-acquire RLock to safely read the existing state
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	ds := existingDs // Use the state we know exists

	now := time.Now()

	// 1. Check if the domain is blocked (cooldown)
	if ds.blockedUntil.After(now) {
		waitTime := ds.blockedUntil.Sub(now)
		dm.logger.Debugf("[DomainManager] Domain '%s' is in cooldown. Wait: %s", domain, waitTime)
		return false, waitTime
	}

	// 2. Check minimum delay between requests
	minDelay := time.Duration(dm.config.DelayMs) * time.Millisecond
	if ds.lastRequestTime.IsZero() { // First request to this domain (after any cooldown)
		return true, 0
	}

	timeSinceLastRequest := now.Sub(ds.lastRequestTime)
	if timeSinceLastRequest < minDelay {
		waitTime := minDelay - timeSinceLastRequest
		dm.logger.Debugf("[DomainManager] Minimum delay for '%s' not met. Wait: %s", domain, waitTime)
		return false, waitTime
	}

	return true, 0
}

// RecordRequestSent updates the timestamp of the last request for the domain.
func (dm *DomainManager) RecordRequestSent(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	ds.lastRequestTime = time.Now()
	dm.logger.Debugf("[DomainManager] Request recorded for '%s' at %s", domain, ds.lastRequestTime.Format(time.RFC3339))
}

// RecordRequestResult analyzes the result of a request and may block the domain if necessary.
func (dm *DomainManager) RecordRequestResult(domain string, statusCode int, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)

	blockDomain := false
	reason := ""

	if err != nil {
		ds.consecutiveFailures++
		dm.logger.Debugf("[DomainManager] Error in request to %s: %v. Consecutive failures: %d. Evaluating for cooldown.", domain, err, ds.consecutiveFailures)

		maxFailures := dm.config.MaxConsecutiveFailuresToBlock
		if maxFailures > 0 && ds.consecutiveFailures >= maxFailures {
			blockDomain = true
			reason = fmt.Sprintf("reached %d consecutive failures", ds.consecutiveFailures)
		} else if statusCode != 0 {
			// Check if this status code, in conjunction with an error, should block
			for _, codeToBlock := range DefaultStatusCodesToBlockOnError {
				if statusCode == codeToBlock {
					blockDomain = true
					reason = fmt.Sprintf("received status code %d with a network error", statusCode)
					break
				}
			}
		}
	} else {
		// No network error, reset consecutive failures
		ds.consecutiveFailures = 0

		// Check if this status code alone should block
		for _, codeToBlock := range DefaultStatusCodesToBlock {
			if statusCode == codeToBlock {
				blockDomain = true
				reason = fmt.Sprintf("received status code %d", statusCode)
				break
			}
		}
	}

	if blockDomain {
		dm.logger.Warnf("[DomainManager] Domain %s: %s. Applying cooldown.", domain, reason)
		dm.blockDomainInternal(domain, ds)
		ds.consecutiveFailures = 0 // Reset after blocking, regardless of the reason
	}
}

// blockDomainInternal is a helper to avoid code duplication and ensure the lock isn't re-acquired.
// Assumes the write lock dm.mu is already held.
func (dm *DomainManager) blockDomainInternal(domain string, ds *domainState) {
	cooldownDuration := time.Duration(DefaultDomainCooldownMs) * time.Millisecond
	ds.blockedUntil = time.Now().Add(cooldownDuration)
	dm.logger.Warnf("[DomainManager] Domain '%s' blocked until %s (cooldown: %s)", domain, ds.blockedUntil.Format(time.RFC3339), cooldownDuration)
}

// BlockDomain marks a domain as blocked for a specific duration.
// This is the public version that acquires the lock.
func (dm *DomainManager) BlockDomain(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	dm.blockDomainInternal(domain, ds)
	// ds.consecutiveFailures = 0 // Resetting failures here might also be a good idea if BlockDomain is called externally.
	                            // For now, RecordRequestResult handles the reset after blocking.
}

// IsBlocked checks if a domain is currently blocked and returns the expiration time of the block.
// Returns false if not blocked.
func (dm *DomainManager) IsBlocked(domain string) (bool, time.Time) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	ds, exists := dm.domainStatus[domain]
	if !exists || ds.blockedUntil.IsZero() || time.Now().After(ds.blockedUntil) {
		return false, time.Time{}
	}
	return true, ds.blockedUntil
}

// GetDomainStatus (optional) could provide insights into a domain's current state for reporting or debugging.
// func (dm *DomainManager) GetDomainStatus(domain string) (domainInfo, bool) { ... }