package networking

import (
	// Será usado em etapas futuras
	"math"
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

// DomainBucket armazena o estado de um domínio específico usando um mecanismo de token bucket.
type DomainBucket struct {
	tokens                 float64   // Número atual de tokens disponíveis
	lastRefillTime         time.Time // Última vez que os tokens foram reabastecidos
	refillRate             float64   // Tokens adicionados por segundo (derivado de MaxTargetRPS)
	maxTokens              float64   // Capacidade máxima do bucket (derivado de MaxTargetRPS)
	lastRequestTime        time.Time // Timestamp da última requisição permitida para este domínio

	// Campos para standby explícito
	standbyUntil           time.Time     // Se o domínio está em cooldown forçado (ex: após 429)
	currentStandbyDuration time.Duration // Duração para o *próximo* período de standby
}

// refill atualiza os tokens no bucket com base no tempo passado desde a última recarga.
func (b *DomainBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(b.lastRefillTime)
	if elapsed <= 0 {
		return
	}
	tokensToAdd := elapsed.Seconds() * b.refillRate
	b.tokens = math.Min(b.maxTokens, b.tokens+tokensToAdd)
	b.lastRefillTime = now // Atualiza o tempo da última recarga, mesmo que tokensToAdd seja 0.
}

// DomainManager manages state and policies per domain,
// including rate limiting and blocking detection (WAF).
// It is crucial for the intelligent behavior of the tool in relation to specific domains.
type DomainManager struct {
	config       *config.Config // To read MinRequestDelayMs, DomainCooldownMs, DelayMs
	logger       utils.Logger
	domainStatus map[string]*DomainBucket
	mu           sync.Mutex // Changed to sync.Mutex for simplicity with Lock/Unlock pattern
}

// NewDomainManager creates a new instance of DomainManager.
func NewDomainManager(cfg *config.Config, logger utils.Logger) *DomainManager {
	return &DomainManager{
		config:       cfg,
		logger:       logger,
		domainStatus: make(map[string]*DomainBucket),
	}
}

// getOrCreateDomainBucket retrieves or creates the state for a domain.
// Assumes the caller holds the lock.
func (dm *DomainManager) getOrCreateDomainBucket(domain string) *DomainBucket {
	bucket, exists := dm.domainStatus[domain]
	if !exists {
		targetRate := dm.config.MaxTargetRPS
		if targetRate <= 0 { // Se -l 0 ou não especificado, usa o default interno.
			targetRate = config.DefaultMaxInternalRPS 
			if dm.config.VerbosityLevel >= 2 {
				dm.logger.Debugf("[DomainManager] MaxTargetRPS para '%s' não especificado (-l <= 0), usando DefaultMaxInternalRPS: %.2f req/s", domain, targetRate)
			}
		}
		if targetRate <= 0 { // Fallback adicional se DefaultMaxInternalRPS também for zero (improvável mas seguro)
		    targetRate = 1.0 // Garante uma taxa mínima positiva
		    dm.logger.Warnf("[DomainManager] TargetRate para '%s' resultou em zero ou negativo, usando fallback de 1.0 req/s", domain)
		}


		bucket = &DomainBucket{
			tokens:                 targetRate, // Começa com o balde cheio
			maxTokens:              targetRate,
			refillRate:             targetRate,
			lastRefillTime:         time.Now(),
			standbyUntil:           time.Time{}, // Zero value, não em standby
			currentStandbyDuration: dm.config.InitialStandbyDuration,
			lastRequestTime:        time.Time{}, // Inicializa lastRequestTime
		}
		dm.domainStatus[domain] = bucket
		if dm.config.VerbosityLevel >= 2 { // -vv
			dm.logger.Debugf("[DomainManager] Initialized bucket for domain '%s': MaxTokens=%.2f, RefillRate=%.2f/s, InitialStandbyDuration=%s",
				domain, bucket.maxTokens, bucket.refillRate, bucket.currentStandbyDuration)
		}
	}
	return bucket
}

// CanRequest checks if a request can be made to a domain based on standby status and token availability.
// If allowed, it consumes a token.
func (dm *DomainManager) CanRequest(domain string) (bool, time.Duration) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	bucket := dm.getOrCreateDomainBucket(domain)
	now := time.Now()

	// 1. Verificar standby explícito
	if bucket.standbyUntil.After(now) {
		waitTime := bucket.standbyUntil.Sub(now)
		if dm.config.VerbosityLevel >= 1 {
			dm.logger.Infof("[DomainManager] Domain '%s' in STANDBY. Waiting for %s. (StandbyUntil: %s)",
				domain, waitTime, bucket.standbyUntil.Format(time.RFC3339))
		}
		return false, waitTime
	}

	// 2. Reabastecer tokens
	bucket.refill() 

	// 3. Verificar disponibilidade de tokens
	if bucket.tokens >= 1.0 {
		bucket.tokens-- // Consome um token
		if dm.config.VerbosityLevel >= 2 {
			dm.logger.Debugf("[DomainManager] CanRequest: Domain '%s' ALLOWED. Token consumed. Tokens remaining: %.2f. RefillRate: %.2f/s",
				domain, bucket.tokens, bucket.refillRate)
		}
		return true, 0
	}

	// Sem tokens, calcular tempo de espera para o próximo token
	var waitTime time.Duration
	if bucket.refillRate > 0 {
		neededTokens := 1.0 - bucket.tokens // Quantos tokens (ou fração) faltam para chegar a 1.0
		if neededTokens <= 0 { neededTokens = 1.0 } // Garante que esperamos por pelo menos 1 token se os tokens forem >= 0 mas < 1
		waitTime = time.Duration(neededTokens/bucket.refillRate*float64(time.Second)) + 1*time.Millisecond // Pequeno buffer para garantir que o token esteja disponível
	} else {
		waitTime = time.Hour // Fallback para taxa de recarga zero
		dm.logger.Warnf("[DomainManager] Domain '%s' has zero refillRate. Wait time set to 1 hour.", domain)
	}
	
	if dm.config.VerbosityLevel >= 1 { 
		dm.logger.Infof("[DomainManager] Domain '%s' NO token available (%.2f tokens). RefillRate: %.2f/s. Waiting for %s.",
			domain, bucket.tokens, bucket.refillRate, waitTime)
	}
	return false, waitTime
}

// RecordRequestSent atualiza o timestamp da última requisição para o domínio.
// Com a lógica de token bucket, o papel principal desta função é registrar o tempo.
// O consumo do "direito" de fazer a requisição (token) já ocorreu em CanRequest.
func (dm *DomainManager) RecordRequestSent(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	bucket := dm.getOrCreateDomainBucket(domain)
	bucket.lastRequestTime = time.Now() 
	if dm.config.VerbosityLevel >= 2 { 
		dm.logger.Debugf("[DomainManager] RecordRequestSent: Domain '%s' lastRequestTime updated to %s. Current tokens: %.2f", 
			domain, bucket.lastRequestTime.Format(time.RFC3339), bucket.tokens)
	}
}

// RecordRequestResult analisa o resultado de uma requisição e atualiza o estado do domínio.
func (dm *DomainManager) RecordRequestResult(domain string, statusCode int, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	bucket := dm.getOrCreateDomainBucket(domain)
	now := time.Now()

	if statusCode == 429 {
		appliedStandbyDuration := bucket.currentStandbyDuration
		bucket.standbyUntil = now.Add(appliedStandbyDuration)
		
		previousTokens := bucket.tokens
		bucket.tokens = 0 // Zera os tokens para forçar espera pela recarga após o standby.

		if dm.config.VerbosityLevel >= 1 { 
			dm.logger.Warnf("[DomainManager] Domain '%s' (Status 429). Tokens zeroed (was %.2f). Applying standby for %s until %s.",
				domain, previousTokens, appliedStandbyDuration, bucket.standbyUntil.Format(time.RFC3339))
		}
		
		bucket.currentStandbyDuration += dm.config.StandbyDurationIncrement
		if bucket.currentStandbyDuration > dm.config.MaxStandbyDuration {
			bucket.currentStandbyDuration = dm.config.MaxStandbyDuration
		}
		dm.logger.Infof("[DomainManager] Domain '%s' next standby duration for 429s increased to %s.", domain, bucket.currentStandbyDuration)
		return
	}

	if err != nil {
		if dm.config.VerbosityLevel >= 1 {
			dm.logger.Warnf("[DomainManager] Request error for domain '%s' (Status: %d, Tokens: %.2f, RefillRate: %.2f/s): %v.",
				domain, statusCode, bucket.tokens, bucket.refillRate, err)
		}
	} else {
		if dm.config.VerbosityLevel >= 2 { 
			dm.logger.Debugf("[DomainManager] Successful request (status: %d) for '%s'. Tokens: %.2f. RefillRate: %.2f/s",
				statusCode, domain, bucket.tokens, bucket.refillRate)
		}
	}
}

// BlockDomain is now primarily for external forceful blocking if ever needed, or can be removed.
// The main blocking logic for 429 is within RecordRequestResult.
// func (dm *DomainManager) BlockDomain(domain string) { ... }

// IsStandby checks if the domain is currently in a forced standby period.
func (dm *DomainManager) IsStandby(domain string) (bool, time.Time) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	bucket := dm.getOrCreateDomainBucket(domain) 
	
	if bucket.standbyUntil.IsZero() || time.Now().After(bucket.standbyUntil) {
		if dm.config.VerbosityLevel >= 2 {
			dm.logger.Debugf("[DomainManager] IsStandby: Domain '%s' is NOT in standby.", domain)
		}
		return false, time.Time{}
	}
	if dm.config.VerbosityLevel >= 1 { 
		dm.logger.Infof("[DomainManager] IsStandby: Domain '%s' IS in standby until %s.", domain, bucket.standbyUntil.Format(time.RFC3339))
	}
	return true, bucket.standbyUntil
}

// GetDomainStatus (optional) could provide insights into a domain's current state for reporting or debugging.
// func (dm *DomainManager) GetDomainStatus(domain string) (domainInfo, bool) { ... }