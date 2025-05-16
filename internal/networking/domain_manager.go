package networking

import (
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config" // To access MinRequestDelayMs, DomainCooldownMs, DelayMs
	"github.com/rafabd1/Hemlock/internal/utils"
)

// Default configuration values for DomainManager - these will eventually move to config.Config
const (
	DefaultInitialTargetRPS      = 1.0
	DefaultMinTargetRPS          = 0.5 // Minimum RPS after a hard block like 429
	DefaultMaxTargetRPS          = 10.0
	DefaultInitialStandbyDuration = 1 * time.Minute
	DefaultMaxStandbyDuration     = 5 * time.Minute
	DefaultStandbyDurationIncrement = 1 * time.Minute // How much to increase standby on repeated 429s
)

// DefaultStatusCodesToBlock lists HTTP status codes that should always trigger a domain cooldown/standby.
// We'll focus on 429 for now as per requirements.
var DefaultStatusCodesToBlock = []int{429} // Primarily 429 for standby

// DefaultStatusCodesToBlockOnError lists HTTP status codes that, if an error also occurs, trigger a domain cooldown.
var DefaultStatusCodesToBlockOnError = []int{} // (formerly from config.StatusCodesToBlockOnError)

// domainState stores the state of a specific domain.
type domainState struct {
	lastRequestTime     time.Time     // Timestamp of the last request *allowed* to this domain
	// blockedUntil        time.Time     // General cooldown, e.g., after consecutive errors (to be refined or replaced by RPS logic)
	consecutiveFailures int           // Counter for generic errors

	// Fields for dynamic rate limiting and standby
	TargetRPS             float64       // Current target requests per second
	StandbyUntil          time.Time     // If domain is in forced standby (e.g., after 429)
	CurrentStandbyDuration time.Duration // Duration for the *next* standby period
}

// DomainManager manages state and policies per domain,
// including rate limiting and blocking detection (WAF).
// It is crucial for the intelligent behavior of the tool in relation to specific domains.
type DomainManager struct {
	config       *config.Config // To read MinRequestDelayMs, DomainCooldownMs, DelayMs
	logger       utils.Logger
	domainStatus map[string]*domainState
	mu           sync.Mutex // Changed to sync.Mutex for simplicity with Lock/Unlock pattern
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
// Assumes the caller holds the lock.
func (dm *DomainManager) getOrCreateDomainState(domain string) *domainState {
	ds, exists := dm.domainStatus[domain]
	if !exists {
		ds = &domainState{
			TargetRPS:             dm.config.InitialTargetRPS,      // Use config value
			CurrentStandbyDuration: dm.config.InitialStandbyDuration, // Use config value
		}
		dm.domainStatus[domain] = ds
		dm.logger.Debugf("[DomainManager] Initialized state for domain '%s' with TargetRPS: %.2f, InitialStandby: %s", 
			domain, ds.TargetRPS, ds.CurrentStandbyDuration)
	}
	return ds
}

// CanRequest checks if a request can be made to a domain.
func (dm *DomainManager) CanRequest(domain string) (bool, time.Duration) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	ds := dm.getOrCreateDomainState(domain) 
	now := time.Now()

	// 1. Check if domain is in forced standby
	if ds.StandbyUntil.After(now) {
		waitTime := ds.StandbyUntil.Sub(now)
		dm.logger.Debugf("[DomainManager] CanRequest: Domain '%s' in STANDBY. Now: %s, StandbyUntil: %s. Wait: %s", 
			domain, now.Format(time.RFC3339), ds.StandbyUntil.Format(time.RFC3339), waitTime)
		return false, waitTime
	}

	// 2. Check rate limiting based on TargetRPS
	if ds.TargetRPS <= 0 { // Should use MinTargetRPS from config as absolute floor if this happens
		var effectiveRPS float64
		if dm.config.MinTargetRPS > 0 {
			effectiveRPS = dm.config.MinTargetRPS
		} else {
			effectiveRPS = 0.1 // A very small default if MinTargetRPS is not set or zero
		}
		dm.logger.Warnf("[DomainManager] CanRequest: Domain '%s' has invalid TargetRPS (%.2f). Using effective RPS: %.2f.", domain, ds.TargetRPS, effectiveRPS)
		ds.TargetRPS = effectiveRPS // Correct the state
	}
	
	requiredDelay := time.Duration(1.0/ds.TargetRPS * float64(time.Second))
	if !ds.lastRequestTime.IsZero() {
		timeSinceLastRequest := now.Sub(ds.lastRequestTime)
		if timeSinceLastRequest < requiredDelay {
			waitTime := requiredDelay - timeSinceLastRequest
			dm.logger.Debugf("[DomainManager] CanRequest: Domain '%s' TargetRPS (%.2f req/s => %.3fs delay) NOT met. LastReq: %s (%.3fs ago). Wait: %s", 
				domain, ds.TargetRPS, requiredDelay.Seconds(), ds.lastRequestTime.Format(time.RFC3339), timeSinceLastRequest.Seconds(), waitTime)
			return false, waitTime
		}
	}

	dm.logger.Debugf("[DomainManager] CanRequest: Domain '%s' ALLOWED. TargetRPS: %.2f. LastReq: %s. Now: %s", 
		domain, ds.TargetRPS, ds.lastRequestTime.Format(time.RFC3339), now.Format(time.RFC3339))
	return true, 0
}

// RecordRequestSent updates the timestamp of the last request *allowed* for the domain.
func (dm *DomainManager) RecordRequestSent(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	ds.lastRequestTime = time.Now()
	dm.logger.Debugf("[DomainManager] RecordRequestSent: Domain '%s' lastRequestTime updated to %s", domain, ds.lastRequestTime.Format(time.RFC3339))
}

// RecordRequestResult analyzes the result of a request.
func (dm *DomainManager) RecordRequestResult(domain string, statusCode int, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	now := time.Now()

	if statusCode == 429 {
		appliedStandbyDuration := ds.CurrentStandbyDuration
		ds.StandbyUntil = now.Add(appliedStandbyDuration)
		
		// Reduce RPS, ensuring it doesn't go below configured MinTargetRPS
		newRPS := ds.TargetRPS / 2 // Example: Halve RPS on 429
		if newRPS < dm.config.MinTargetRPS {
			newRPS = dm.config.MinTargetRPS
		}
		ds.TargetRPS = newRPS

		dm.logger.Warnf("[DomainManager] RecordRequestResult: Domain '%s' (Status 429). Applying standby for %s. StandbyUntil: %s. TargetRPS reduced to %.2f.", 
			domain, appliedStandbyDuration, ds.StandbyUntil.Format(time.RFC3339), ds.TargetRPS)
		
		// Increase standby duration for next time, up to MaxStandbyDuration from config
		ds.CurrentStandbyDuration += dm.config.StandbyDurationIncrement
		if ds.CurrentStandbyDuration > dm.config.MaxStandbyDuration {
			ds.CurrentStandbyDuration = dm.config.MaxStandbyDuration
		}
		dm.logger.Infof("[DomainManager] RecordRequestResult: Domain '%s' next standby duration increased to %s.", domain, ds.CurrentStandbyDuration)

		ds.consecutiveFailures = 0 
		return 
	}

	if err != nil {
		ds.consecutiveFailures++
		dm.logger.Debugf("[DomainManager] RecordRequestResult: Error for domain '%s': %v. Consecutive failures: %d.", domain, err, ds.consecutiveFailures)
		// TODO: Future: If consecutiveFailures reach a threshold, moderately decrease TargetRPS (dynamic rate limiting)
	} else {
		// Successful request (non-429 and no network error)
		ds.consecutiveFailures = 0
		// TODO: Future: If requests are consistently successful, gradually increase TargetRPS up to MaxTargetRPS from config
		// For now, just log success, RPS increase will be a future enhancement.
		dm.logger.Debugf("[DomainManager] RecordRequestResult: Successful request (status: %d, no error) for domain '%s'. Consecutive failures reset.", statusCode, domain)
	}
}

// BlockDomain is now primarily for external forceful blocking if ever needed, or can be removed.
// The main blocking logic for 429 is within RecordRequestResult.
// func (dm *DomainManager) BlockDomain(domain string) { ... }

// IsStandby checks if the domain is currently in a forced standby period.
func (dm *DomainManager) IsStandby(domain string) (bool, time.Time) {
	dm.mu.Lock() // Changed to Lock for consistency, as getOrCreate might be called if we add it here
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain) // Ensure state exists if called externally
	
	if ds.StandbyUntil.IsZero() || time.Now().After(ds.StandbyUntil) {
		dm.logger.Debugf("[DomainManager] IsStandby: Domain '%s' is NOT in standby.", domain)
		return false, time.Time{}
	}
	dm.logger.Debugf("[DomainManager] IsStandby: Domain '%s' IS in standby until %s.", domain, ds.StandbyUntil.Format(time.RFC3339))
	return true, ds.StandbyUntil
}

// GetDomainStatus (optional) could provide insights into a domain's current state for reporting or debugging.
// func (dm *DomainManager) GetDomainStatus(domain string) (domainInfo, bool) { ... }