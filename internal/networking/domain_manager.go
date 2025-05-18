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
	DefaultTransientErrorThreshold  = 3     // New: Threshold for transient errors
	DefaultRPSReductionFactorOnError = 0.9 // New: Factor to reduce RPS on hitting error threshold
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
	consecutiveSuccesses int           // New: Counter for successful requests
	transientErrorCount  int           // New: Counter for non-critical errors

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
			consecutiveSuccesses:  0,
			transientErrorCount:   0, // Initialize new field
		}
		dm.domainStatus[domain] = ds
		if dm.config.VerbosityLevel >= 2 { // -vv
			dm.logger.Debugf("[DomainManager] Initialized state for domain '%s' with TargetRPS: %.2f, InitialStandby: %s", 
				domain, ds.TargetRPS, ds.CurrentStandbyDuration)
		}
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
		if dm.config.VerbosityLevel >= 1 {
			dm.logger.Infof("[DomainManager] Domain '%s' in STANDBY. Waiting for %s. (StandbyUntil: %s)",
				domain, waitTime, ds.StandbyUntil.Format(time.RFC3339))
		}
		return false, waitTime
	}

	// 2. Check rate limiting based on TargetRPS
	if ds.TargetRPS <= 0 {
		dm.logger.Warnf("[DomainManager] CanRequest: Domain '%s' TargetRPS was %.2f. Resetting to MinTargetRPS (%.2f).", domain, ds.TargetRPS, dm.config.MinTargetRPS)
		ds.TargetRPS = dm.config.MinTargetRPS
	}
	if ds.TargetRPS < dm.config.MinTargetRPS {
		dm.logger.Warnf("[DomainManager] CanRequest: Domain '%s' TargetRPS (%.2f) was below configured MinTargetRPS (%.2f). Corrected.", domain, ds.TargetRPS, dm.config.MinTargetRPS)
		ds.TargetRPS = dm.config.MinTargetRPS
	}

	requiredDelay := time.Duration(1.0/ds.TargetRPS * float64(time.Second))
	if !ds.lastRequestTime.IsZero() {
		timeSinceLastRequest := now.Sub(ds.lastRequestTime)
		if timeSinceLastRequest < requiredDelay {
			waitTime := requiredDelay - timeSinceLastRequest
			if dm.config.VerbosityLevel >= 1 {
				dm.logger.Infof("[DomainManager] Domain '%s' TargetRPS limit (%.2f req/s => %.3fs delay) not met. LastReq: %.3fs ago. Waiting for %s.",
					domain, ds.TargetRPS, requiredDelay.Seconds(), timeSinceLastRequest.Seconds(), waitTime)
			}
			return false, waitTime
		}
	}

	if dm.config.VerbosityLevel >= 2 {
		dm.logger.Debugf("[DomainManager] CanRequest: Domain '%s' ALLOWED. TargetRPS: %.2f. LastReq: %s. Now: %s",
			domain, ds.TargetRPS, ds.lastRequestTime.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return true, 0
}

// RecordRequestSent updates the timestamp of the last request *allowed* for the domain.
func (dm *DomainManager) RecordRequestSent(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	ds.lastRequestTime = time.Now()
	if dm.config.VerbosityLevel >= 2 { 
		dm.logger.Debugf("[DomainManager] RecordRequestSent: Domain '%s' lastRequestTime updated to %s", domain, ds.lastRequestTime.Format(time.RFC3339))
	}
}

// RecordRequestResult analyzes the result of a request.
func (dm *DomainManager) RecordRequestResult(domain string, statusCode int, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	now := time.Now()

	// Determine the effective maximum RPS for this domain
	effectiveMaxRPS := config.DefaultMaxInternalRPS // Use internal default (e.g., 30 rps)
	if dm.config.MaxTargetRPS > 0 { // If user specified a limit via -l
		effectiveMaxRPS = dm.config.MaxTargetRPS
	}

	if statusCode == 429 {
		previousRPS := ds.TargetRPS
		appliedStandbyDuration := ds.CurrentStandbyDuration
		ds.StandbyUntil = now.Add(appliedStandbyDuration)
		
		newRPS := ds.TargetRPS / 2 // Example: Halve RPS on 429
		if newRPS < dm.config.MinTargetRPS {
			newRPS = dm.config.MinTargetRPS
		}
		ds.TargetRPS = newRPS
		ds.consecutiveSuccesses = 0 // Reset successes on 429
		ds.transientErrorCount = 0 // Reset transient errors on hard block
		ds.consecutiveFailures = 0 

		if dm.config.VerbosityLevel >= 1 { // -v
			dm.logger.Warnf("[DomainManager] Domain '%s' (Status 429). Previous RPS: %.2f. New RPS: %.2f. Applying standby for %s until %s.", 
				domain, previousRPS, ds.TargetRPS, appliedStandbyDuration, ds.StandbyUntil.Format(time.RFC3339))
		}
		
		// Increase standby duration for next time, up to MaxStandbyDuration from config
		ds.CurrentStandbyDuration += dm.config.StandbyDurationIncrement
		if ds.CurrentStandbyDuration > dm.config.MaxStandbyDuration {
			ds.CurrentStandbyDuration = dm.config.MaxStandbyDuration
		}
		dm.logger.Infof("[DomainManager] Domain '%s' next standby duration for 429s increased to %s.", domain, ds.CurrentStandbyDuration)

		return 
	}

	if err != nil {
		// Log antes de zerar consecutiveSuccesses
		if dm.config.VerbosityLevel >= 1 {
			dm.logger.Warnf("[DomainManager] Request error for domain '%s' (Current RPS: %.2f, ConsecutiveSuccesses before reset: %d, TransientErrors: %d/%d): %v.", 
				domain, ds.TargetRPS, ds.consecutiveSuccesses, ds.transientErrorCount, DefaultTransientErrorThreshold, err)
		}
		ds.consecutiveFailures++
		ds.transientErrorCount++
	} else {
		// Successful request (non-429 and no network error)
		ds.consecutiveFailures = 0
		ds.consecutiveSuccesses++

		if ds.consecutiveSuccesses >= config.DefaultSuccessThreshold {
			previousRPS := ds.TargetRPS
			newRPS := ds.TargetRPS + config.DefaultRPSIncrement
			if newRPS > effectiveMaxRPS {
				newRPS = effectiveMaxRPS
			}
			if newRPS > ds.TargetRPS { 
				ds.TargetRPS = newRPS
				ds.consecutiveSuccesses = 0 
				if dm.config.VerbosityLevel >= 1 {
					dm.logger.Infof("[DomainManager] Domain '%s' reached %d successes. TargetRPS increased from %.2f to %.2f (Configured Max: %.2f).", 
						domain, config.DefaultSuccessThreshold, previousRPS, ds.TargetRPS, effectiveMaxRPS)
				}
			} else if ds.TargetRPS < effectiveMaxRPS { 
			    ds.consecutiveSuccesses = 0 
				if dm.config.VerbosityLevel >= 2 { // Log only if verbose and RPS didn't change but could have
					dm.logger.Debugf("[DomainManager] Domain '%s' reached %d successes, but TargetRPS already at/near effectiveMaxRPS (%.2f). Resetting success count.", 
						domain, config.DefaultSuccessThreshold, ds.TargetRPS)
				}
			} else { // Already at effectiveMaxRPS
			    ds.consecutiveSuccesses = 0 // Still reset to require new successes for future adjustments
			    if dm.config.VerbosityLevel >= 2 {
			        dm.logger.Debugf("[DomainManager] Domain '%s' reached %d successes. TargetRPS (%.2f) already at effectiveMaxRPS (%.2f). Success count reset.", 
			            domain, config.DefaultSuccessThreshold, ds.TargetRPS, effectiveMaxRPS)
			    }
			}
		} 
		
		if dm.config.VerbosityLevel >= 2 { 
			dm.logger.Debugf("[DomainManager] Successful request (status: %d) for '%s'. Consecutive successes: %d/%d. Current RPS: %.2f", 
				statusCode, domain, ds.consecutiveSuccesses, config.DefaultSuccessThreshold, ds.TargetRPS)
		}
	}

	if ds.transientErrorCount >= DefaultTransientErrorThreshold {
		dm.logger.Warnf("[DomainManager] Domain '%s' reached transient error threshold (%d). Resetting consecutive successes and reducing RPS.", domain, DefaultTransientErrorThreshold)
		ds.consecutiveSuccesses = 0
		
		previousRPS := ds.TargetRPS
		ds.TargetRPS *= DefaultRPSReductionFactorOnError
		if ds.TargetRPS < dm.config.MinTargetRPS {
			ds.TargetRPS = dm.config.MinTargetRPS
		}
		if ds.TargetRPS != previousRPS && dm.config.VerbosityLevel >=1 {
			dm.logger.Infof("[DomainManager] Domain '%s' TargetRPS reduced from %.2f to %.2f due to transient errors.", domain, previousRPS, ds.TargetRPS)
		}
		ds.transientErrorCount = 0 // Reset counter after action
	}
}

// BlockDomain is now primarily for external forceful blocking if ever needed, or can be removed.
// The main blocking logic for 429 is within RecordRequestResult.
// func (dm *DomainManager) BlockDomain(domain string) { ... }

// IsStandby checks if the domain is currently in a forced standby period.
func (dm *DomainManager) IsStandby(domain string) (bool, time.Time) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	
	if ds.StandbyUntil.IsZero() || time.Now().After(ds.StandbyUntil) {
		if dm.config.VerbosityLevel >= 2 {
			dm.logger.Debugf("[DomainManager] IsStandby: Domain '%s' is NOT in standby.", domain)
		}
		return false, time.Time{}
	}
	if dm.config.VerbosityLevel >= 1 { // Changed to >=1 for better visibility
		dm.logger.Infof("[DomainManager] IsStandby: Domain '%s' IS in standby until %s.", domain, ds.StandbyUntil.Format(time.RFC3339))
	}
	return true, ds.StandbyUntil
}

// GetNextAvailableTime calculates the earliest time a request can be sent to the domain.
// It considers both standby and RPS limits.
func (dm *DomainManager) GetNextAvailableTime(domain string) time.Time {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	ds := dm.getOrCreateDomainState(domain)
	now := time.Now()

	var rpsNextAvailableTime time.Time
	if ds.TargetRPS <= 0 { // Safety for RPS, should be caught by CanRequest corrections too
		// If RPS is invalid, assume it can be tried now, relying on CanRequest/RecordRequestResult to fix RPS.
		// Or, more conservatively, set a small default delay.
		rpsNextAvailableTime = now // Or now.Add(smallDefaultDelayIfRPSError)
	} else {
		requiredDelay := time.Duration(1.0/ds.TargetRPS * float64(time.Second))
		if ds.lastRequestTime.IsZero() {
			rpsNextAvailableTime = now // No previous request, can go now (from RPS perspective)
		} else {
			rpsNextAvailableTime = ds.lastRequestTime.Add(requiredDelay)
		}
	}

	// Consider standby time
	standbyNextAvailableTime := ds.StandbyUntil // This is already an absolute time

	// The domain is available at the LATER of these two times
	nextAvailable := rpsNextAvailableTime
	if standbyNextAvailableTime.After(rpsNextAvailableTime) {
		nextAvailable = standbyNextAvailableTime
	}

	// If the calculated nextAvailable is in the past, it means it's available now.
	if nextAvailable.Before(now) {
		return now
	}
	return nextAvailable
}

// GetDomainStatus (optional) could provide insights into a domain's current state for reporting or debugging.
// func (dm *DomainManager) GetDomainStatus(domain string) (domainInfo, bool) { ... }