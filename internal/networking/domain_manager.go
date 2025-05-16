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
// Should be called with the appropriate lock (write) already acquired.
func (dm *DomainManager) getOrCreateDomainState(domain string) *domainState {
	ds, exists := dm.domainStatus[domain]
	if !exists {
		ds = &domainState{
			TargetRPS:             DefaultInitialTargetRPS,      // Initialize with default RPS
			CurrentStandbyDuration: DefaultInitialStandbyDuration, // Initialize standby duration
		}
		dm.domainStatus[domain] = ds
		dm.logger.Debugf("[DomainManager] Initialized state for domain '%s' with TargetRPS: %.2f", domain, ds.TargetRPS)
	}
	return ds
}

// CanRequest checks if a request can be made to a domain.
func (dm *DomainManager) CanRequest(domain string) (bool, time.Duration) {
	dm.mu.Lock() // Need write lock to ensure state creation if it doesn't exist
	ds := dm.getOrCreateDomainState(domain) // Ensures state exists
	dm.mu.Unlock()

	dm.mu.RLock() // Now use RLock for reading the state
	defer dm.mu.RUnlock()

	now := time.Now()

	// 1. Check if domain is in forced standby (e.g. after a 429)
	if ds.StandbyUntil.After(now) {
		waitTime := ds.StandbyUntil.Sub(now)
		dm.logger.Debugf("[DomainManager] Domain '%s' is in STANDBY. Wait: %s", domain, waitTime)
		return false, waitTime
	}

	// 2. Check rate limiting based on TargetRPS
	if ds.TargetRPS <= 0 { // Should not happen if MinTargetRPS is positive
		dm.logger.Warnf("[DomainManager] Domain '%s' has TargetRPS <= 0 (%.2f). Allowing request with default delay.", domain, ds.TargetRPS)
	} else {
		requiredDelay := time.Duration(1.0/ds.TargetRPS * float64(time.Second))
		if !ds.lastRequestTime.IsZero() {
			timeSinceLastRequest := now.Sub(ds.lastRequestTime)
			if timeSinceLastRequest < requiredDelay {
				waitTime := requiredDelay - timeSinceLastRequest
				dm.logger.Debugf("[DomainManager] Domain '%s' TargetRPS (%.2f req/s) not met. Wait: %s", domain, ds.TargetRPS, waitTime)
				return false, waitTime
			}
		}
	}

	// 3. Fallback to config.DelayMs if TargetRPS logic allows immediate request (e.g., first request)
	// This ensures the old DelayMs is still a minimum guard if RPS is very high or it's the first req.
	// However, the primary control should be TargetRPS.
	// For now, let's assume TargetRPS is the main controller.
	// The config.DelayMs can be seen as an initial seed for TargetRPS if desired, or a floor.

	return true, 0
}

// RecordRequestSent updates the timestamp of the last request *allowed* for the domain.
func (dm *DomainManager) RecordRequestSent(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	ds.lastRequestTime = time.Now()
	// dm.logger.Debugf("[DomainManager] Request recorded for '%s' at %s", domain, ds.lastRequestTime.Format(time.RFC3339))
}

// RecordRequestResult analyzes the result of a request.
func (dm *DomainManager) RecordRequestResult(domain string, statusCode int, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)

	if statusCode == 429 {
		dm.logger.Warnf("[DomainManager] Domain '%s' received status 429 (Too Many Requests). Applying standby.", domain)
		ds.StandbyUntil = time.Now().Add(ds.CurrentStandbyDuration)
		ds.TargetRPS = DefaultMinTargetRPS // Reduce RPS drastically
		dm.logger.Warnf("[DomainManager] Domain '%s' standby until %s. TargetRPS reduced to %.2f. Next standby will be for %s.", 
			domain, ds.StandbyUntil.Format(time.RFC3339), ds.TargetRPS, ds.CurrentStandbyDuration+DefaultStandbyDurationIncrement)
		
		// Increase standby duration for next time, up to a max
		ds.CurrentStandbyDuration += DefaultStandbyDurationIncrement
		if ds.CurrentStandbyDuration > DefaultMaxStandbyDuration {
			ds.CurrentStandbyDuration = DefaultMaxStandbyDuration
		}
		ds.consecutiveFailures = 0 // Reset failures after a 429 block
		return // Handled 429, no further processing for this result needed here for now
	}

	if err != nil {
		ds.consecutiveFailures++
		dm.logger.Debugf("[DomainManager] Error for domain %s: %v. Consecutive failures: %d.", domain, err, ds.consecutiveFailures)
		// TODO: Future: If consecutiveFailures reach a threshold, moderately decrease TargetRPS (dynamic rate limiting)
		// For now, we are removing the direct block by consecutive failures from config.
	} else {
		// Successful request (non-429 and no network error)
		ds.consecutiveFailures = 0
		dm.logger.Debugf("[DomainManager] Successful request recorded for domain %s (status: %d). Consecutive failures reset.", domain, statusCode)
		// TODO: Future: If requests are consistently successful, gradually increase TargetRPS up to DefaultMaxTargetRPS (dynamic rate limiting)
	}
}

// BlockDomain is now primarily for external forceful blocking if ever needed, or can be removed.
// The main blocking logic for 429 is within RecordRequestResult.
// func (dm *DomainManager) BlockDomain(domain string) { ... }

// IsStandby can be simplified or focused on the StandbyUntil status.
func (dm *DomainManager) IsStandby(domain string) (bool, time.Time) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	ds, exists := dm.domainStatus[domain]
	if !exists || ds.StandbyUntil.IsZero() || time.Now().After(ds.StandbyUntil) {
		return false, time.Time{}
	}
	return true, ds.StandbyUntil
}

// GetDomainStatus (optional) could provide insights into a domain's current state for reporting or debugging.
// func (dm *DomainManager) GetDomainStatus(domain string) (domainInfo, bool) { ... }