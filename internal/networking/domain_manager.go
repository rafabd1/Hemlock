package networking

import (
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config" // For DomainManagerConfig
	"github.com/rafabd1/Hemlock/internal/utils"
)

// DomainManager handles state and policies for specific domains (rate limiting, WAF detection, etc.).
// It is based on the DomainManager from your architecture document.
type DomainManager struct {
	mutex        sync.RWMutex
	domainStatus map[string]*domainInfo
	config       config.NetworkConfig // Explicitly using config.NetworkConfig
	logger       utils.Logger
	// TODO: Add fields for default MinRequestDelay, CooldownDuration, logger, etc.
}

type domainInfo struct {
	lastRequestTime    time.Time
	blockedUntil       time.Time
	consecutiveFailures int
	// TODO: Add more fine-grained stats if needed, e.g., total requests, success, specific error counts
}

const maxConsecutiveFailuresToBlock = 5 // Example: block after 5 consecutive failures

// NewDomainManager creates a new DomainManager.
func NewDomainManager(cfg config.NetworkConfig, logger utils.Logger) *DomainManager { // Explicitly using config.NetworkConfig
	return &DomainManager{
		domainStatus: make(map[string]*domainInfo),
		config:       cfg,
		logger:       logger,
	}
}

// getOrCreateDomainInfo retrieves or creates a domainInfo struct for a domain.
// This must be called with the dm.mutex already locked.
func (dm *DomainManager) getOrCreateDomainInfo(domain string) *domainInfo {
	di, exists := dm.domainStatus[domain]
	if !exists {
		di = &domainInfo{}
		dm.domainStatus[domain] = di
	}
	return di
}

// CanRequest checks if a request can be made to a domain based on its current state.
func (dm *DomainManager) CanRequest(domain string) bool {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	di, exists := dm.domainStatus[domain]
	if !exists {
		return true // No info yet, can request
	}

	if !di.blockedUntil.IsZero() && time.Now().Before(di.blockedUntil) {
		dm.logger.Debugf("Domain %s is blocked until %v", domain, di.blockedUntil)
		return false // Domain is currently blocked
	}

	minDelay := time.Duration(dm.config.MinRequestDelayMs) * time.Millisecond
	if !di.lastRequestTime.IsZero() && time.Since(di.lastRequestTime) < minDelay {
		dm.logger.Debugf("Rate limiting domain %s, last request was at %v, need to wait %v", domain, di.lastRequestTime, minDelay)
		return false // Rate limiting
	}

	return true
}

// RecordRequestSent updates the last request time for a domain.
func (dm *DomainManager) RecordRequestSent(domain string) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	di := dm.getOrCreateDomainInfo(domain)
	di.lastRequestTime = time.Now()
}

// RecordRequestResult updates the domain status based on the outcome of a request.
func (dm *DomainManager) RecordRequestResult(domain string, success bool, statusCode int, isWAFBlock bool, isRateLimitError bool) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	di := dm.getOrCreateDomainInfo(domain)

	if success {
		di.consecutiveFailures = 0
		// If a successful request happens, and the domain was blocked, unblock it.
		// This handles cases where a block might have been too aggressive or temporary conditions cleared.
		if !di.blockedUntil.IsZero() {
			dm.logger.Infof("Domain %s was blocked, but a successful request occurred. Unblocking.", domain)
			di.blockedUntil = time.Time{} // Clear block
		}
		return
	}

	// Handle failure
	di.consecutiveFailures++
	dm.logger.Debugf("Failure recorded for domain %s. Consecutive failures: %d. Status: %d, WAF: %t, RateLimit: %t",
		domain, di.consecutiveFailures, statusCode, isWAFBlock, isRateLimitError)

	cooldownDuration := time.Duration(dm.config.DomainCooldownMs) * time.Millisecond

	if isWAFBlock {
		dm.logger.Warnf("WAF detected for domain %s. Blocking for %v.", domain, cooldownDuration)
		di.blockedUntil = time.Now().Add(cooldownDuration)
		di.consecutiveFailures = 0 // Reset after explicit block
		return
	}

	if isRateLimitError { // e.g. HTTP 429
		dm.logger.Warnf("Rate limit error (e.g. HTTP 429) from domain %s. Blocking for %v.", domain, cooldownDuration)
		di.blockedUntil = time.Now().Add(cooldownDuration)
		di.consecutiveFailures = 0 // Reset after explicit block
		return
	}

	if di.consecutiveFailures >= maxConsecutiveFailuresToBlock {
		dm.logger.Warnf("Domain %s reached %d consecutive failures. Blocking for %v.", domain, di.consecutiveFailures, cooldownDuration)
		di.blockedUntil = time.Now().Add(cooldownDuration)
		di.consecutiveFailures = 0 // Reset counter after blocking
	}
}

// GetDomainStatus (optional) could provide insights into a domain's current state for reporting or debugging.
// func (dm *DomainManager) GetDomainStatus(domain string) (domainInfo, bool) { ... } 