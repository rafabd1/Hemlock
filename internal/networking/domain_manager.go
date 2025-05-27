package networking

import (
	"context" // Needed for errors.Is(err, context.DeadlineExceeded)
	"errors"  // Needed for errors.Is
	"math"
	"strings" // Needed for DNS error string checks
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config" // To access MinRequestDelayMs, DomainCooldownMs, DelayMs
	"github.com/rafabd1/Hemlock/internal/utils"
)

// Default configuration values for DomainManager specific logic (e.g. dynamic adjustments)
// These may be moved to config.Config in the future if they become user-configurable.
const (
	DefaultTransientErrorThreshold  = 3     // Threshold for transient errors before potentially reducing RPS
	DefaultRPSReductionFactorOnError = 0.9 // Factor to reduce RPS on hitting error threshold (e.g., newRPS = currentRPS * Factor)
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
	refillRate             float64   // Tokens adicionados por segundo (derivado de currentRPS)
	maxTokens              float64   // Capacidade máxima do bucket (derivado de currentRPS)
	lastRequestTime        time.Time // Timestamp da última requisição permitida para este domínio

	// Campos para standby explícito
	standbyUntil           time.Time     // Se o domínio está em cooldown forçado (ex: após 429)
	currentStandbyDuration time.Duration // Duração para o *próximo* período de standby

	// Campos para ajuste dinâmico de RPS no modo automático
	isAutoMode                 bool    // True se este bucket opera em modo de ajuste automático de RPS
	currentRPS               float64 // Taxa de RPS atual que está sendo tentada
	minRPS                   float64 // dm.config.MinTargetRPS
	maxRPSAuto               float64 // dm.config.DefaultMaxInternalRPS (teto para modo auto)
	consecutiveSuccesses       int     // Contador de sucessos para aumentar RPS
	consecutiveNonCriticalErrors int     // Contador de erros de servidor/rede graves para diminuir RPS
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
		targetRate := dm.config.MaxTargetRPS // Este é o -l X. Se 0, indica modo automático.
		isAuto := false
		var currentRate, minRate, maxAutoRate float64

		if targetRate <= 0 { // Modo Automático
			isAuto = true
			currentRate = dm.config.InitialTargetRPS
			minRate = dm.config.MinTargetRPS
			maxAutoRate = config.DefaultMaxInternalRPS // Usa o valor de config.go

			if currentRate <= 0 { // Fallback se InitialTargetRPS for inválido
				currentRate = 1.0
				dm.logger.Warnf("[DomainManager] AutoMode: InitialTargetRPS for '%s' was invalid, using fallback 1.0 req/s", domain)
			}
			if dm.config.VerbosityLevel >= 1 {
				dm.logger.Infof("[DomainManager] Domain '%s' entering AUTO rate limit mode. Initial: %.2f, Min: %.2f, MaxAuto: %.2f req/s",
					domain, currentRate, minRate, maxAutoRate)
			}
		} else { // Modo Manual (targetRate > 0)
			isAuto = false
			currentRate = targetRate // No modo manual, currentRPS é o targetRate fixo.
			minRate = targetRate     // Não há ajuste dinâmico, então min/max são o próprio targetRate.
			maxAutoRate = targetRate
			if dm.config.VerbosityLevel >= 1 {
				dm.logger.Infof("[DomainManager] Domain '%s' entering MANUAL rate limit mode: %.2f req/s", domain, currentRate)
			}
		}

		bucket = &DomainBucket{
			tokens:                 currentRate, // Começa com o balde cheio baseado no currentRate
			maxTokens:              currentRate,
			refillRate:             currentRate,
			lastRefillTime:         time.Now(),
			standbyUntil:           time.Time{},
			currentStandbyDuration: dm.config.InitialStandbyDuration,
			lastRequestTime:        time.Time{},

			isAutoMode:                 isAuto,
			currentRPS:               currentRate,
			minRPS:                   minRate,
			maxRPSAuto:               maxAutoRate,
			consecutiveSuccesses:       0,
			consecutiveNonCriticalErrors: 0,
		}
		dm.domainStatus[domain] = bucket
		if dm.config.VerbosityLevel >= 2 { // -vv
			dm.logger.Debugf("[DomainManager] Initialized bucket for domain '%s': Mode: %s, CurrentRPS=%.2f, RefillRate=%.2f/s, MinRPS=%.2f, MaxAutoRPS=%.2f, InitialStandbyDuration=%s",
				domain, Linz(isAuto, "AUTO", "MANUAL"), bucket.currentRPS, bucket.refillRate, bucket.minRPS, bucket.maxRPSAuto, bucket.currentStandbyDuration)
		}
	}
	return bucket
}

// Linz é uma função helper ternária para logging, substitua por lógica Go padrão se preferir.
func Linz(condition bool, trueVal, falseVal string) string {
	if condition {
		return trueVal
	}
	return falseVal
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

	// --- Tratamento específico para 429 (Rate Limit Explícito) ---
	if statusCode == 429 {
		appliedStandbyDuration := bucket.currentStandbyDuration
		bucket.standbyUntil = time.Now().Add(appliedStandbyDuration)
		previousTokens := bucket.tokens
		bucket.tokens = 0 // Zera os tokens para forçar espera pela recarga após o standby.

		if dm.config.VerbosityLevel >= 1 {
			dm.logger.Warnf("[DomainManager] Domain '%s' (Status 429). Tokens zeroed (was %.2f). Applying standby for %s until %s.",
				domain, previousTokens, appliedStandbyDuration, bucket.standbyUntil.Format(time.RFC3339))
		}

		// Aumentar a duração do próximo standby
		bucket.currentStandbyDuration += dm.config.StandbyDurationIncrement
		if bucket.currentStandbyDuration > dm.config.MaxStandbyDuration {
			bucket.currentStandbyDuration = dm.config.MaxStandbyDuration
		}
		dm.logger.Infof("[DomainManager] Domain '%s' next standby duration for 429s increased to %s.", domain, bucket.currentStandbyDuration)

		// No modo automático, resetar RPS para o mínimo após um 429.
		if bucket.isAutoMode {
			if bucket.currentRPS != bucket.minRPS { // Só logar se houver mudança
				dm.logger.Infof("[DomainManager] AUTO MODE: Domain '%s' (Status 429) - Resetting RPS from %.2f to MinRPS %.2f.",
					domain, bucket.currentRPS, bucket.minRPS)
				bucket.currentRPS = bucket.minRPS
				bucket.refillRate = bucket.currentRPS
				bucket.maxTokens = bucket.currentRPS // O balde deve ser capaz de conter tokens para a nova taxa
			}
		}
		bucket.consecutiveSuccesses = 0       // Resetar contadores
		bucket.consecutiveNonCriticalErrors = 0
		return // Tratamento de 429 concluído
	}

	// --- Lógica de Ajuste Dinâmico de RPS (Apenas para Modo Automático) ---
	if bucket.isAutoMode {
		isClientSideOrNetworkError := false
		if err != nil {
			// Verifica erros específicos do lado do cliente/rede
			// Adicionar "dial tcp" para capturar erros de conexão mais genéricos que não são timeouts ou DNS.
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
				(err.Error() != "" && (strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "lookup") || strings.Contains(err.Error(), "dial tcp"))) {
				isClientSideOrNetworkError = true
			}
		}

		if isClientSideOrNetworkError {
			// Erro do lado do cliente/rede: Logar, mas NÃO ajustar RPS nem contadores de RPS.
			if dm.config.VerbosityLevel >= 1 {
				dm.logger.Warnf("[DomainManager] AUTO MODE: Client-side/network error for domain '%s' (Status Code from client: %d, Err: %v). RPS %.2f NOT changed by this error.",
					domain, statusCode, err, bucket.currentRPS)
			}
			// Não resetamos consecutiveSuccesses, pois o servidor pode estar ok.
			// Não incrementamos consecutiveNonCriticalErrors, pois não é um erro de servidor 5xx.
		} else if err != nil {
			// err != nil, MAS NÃO é um erro de cliente/rede conhecido (acima).
			// Tratar como um problema que justifica a redução de RPS (ex: connection reset by peer, etc.)
			// pois pode indicar que o servidor está sobrecarregado ou rejeitando na taxa atual.
			dm.logger.Warnf("[DomainManager] AUTO MODE: Unclassified network error for domain '%s' (Status: %d, Err: %v). Treating as issue for RPS adjustment. CurrentRPS: %.2f",
				domain, statusCode, err, bucket.currentRPS)
			bucket.consecutiveSuccesses = 0 // Erro de rede quebra a sequência de sucessos.
			bucket.consecutiveNonCriticalErrors++

			if bucket.consecutiveNonCriticalErrors >= DefaultTransientErrorThreshold {
				if bucket.currentRPS > bucket.minRPS {
					oldRPS := bucket.currentRPS
					newRPS := bucket.currentRPS * DefaultRPSReductionFactorOnError
					bucket.currentRPS = math.Max(newRPS, bucket.minRPS)
					bucket.refillRate = bucket.currentRPS
					bucket.maxTokens = bucket.currentRPS
					dm.logger.Warnf("[DomainManager] AUTO MODE: Domain '%s' RPS reduced from %.2f to %.2f (Min: %.2f) after %d unclassified network/server errors.",
						domain, oldRPS, bucket.currentRPS, bucket.minRPS, bucket.consecutiveNonCriticalErrors)
					bucket.consecutiveNonCriticalErrors = 0 // Resetar após redução
				} else {
					bucket.consecutiveNonCriticalErrors = 0 // Já no mínimo, resetar.
					if dm.config.VerbosityLevel >= 2 { 
						dm.logger.Debugf("[DomainManager] AUTO MODE: Domain '%s' already at MinRPS (%.2f) despite unclassified network/server errors. Error counter reset.", domain, bucket.minRPS)
					}
				}
			}
		} else { // err == nil. A decisão é baseada apenas no statusCode.
			isServerError := statusCode >= 500 && statusCode <= 599
			if !isServerError { // Sucesso Genuíno (err é nil, statusCode não é 5xx)
				bucket.consecutiveNonCriticalErrors = 0 // Resetar contador de erros de SERVIDOR em sucesso
				bucket.consecutiveSuccesses++
				if dm.config.VerbosityLevel >= 2 { // -vv para log de contagem de sucesso
					dm.logger.Debugf("[DomainManager] AUTO MODE: Success for domain '%s'. Consecutive successes: %d/%d. CurrentRPS: %.2f",
						domain, bucket.consecutiveSuccesses, config.DefaultSuccessThreshold, bucket.currentRPS)
				}

				if bucket.consecutiveSuccesses >= config.DefaultSuccessThreshold {
					if bucket.currentRPS < bucket.maxRPSAuto {
						oldRPS := bucket.currentRPS
						newRPS := bucket.currentRPS + config.DefaultRPSIncrement
						bucket.currentRPS = math.Min(newRPS, bucket.maxRPSAuto)
						bucket.refillRate = bucket.currentRPS
						bucket.maxTokens = bucket.currentRPS
						dm.logger.Infof("[DomainManager] AUTO MODE: Domain '%s' RPS increased from %.2f to %.2f (Max: %.2f) after %d successes.",
							domain, oldRPS, bucket.currentRPS, bucket.maxRPSAuto, bucket.consecutiveSuccesses)
						bucket.consecutiveSuccesses = 0 // Resetar após aumento
					} else {
						bucket.consecutiveSuccesses = 0 // Já no máximo, resetar para evitar overflow
						if dm.config.VerbosityLevel >= 2 { // -vv para log de "já no máximo"
							dm.logger.Debugf("[DomainManager] AUTO MODE: Domain '%s' already at MaxAutoRPS (%.2f). Success counter reset.", domain, bucket.maxRPSAuto)
						}
					}
				}
			} else { // Erro de Servidor (5xx), e err era nil (pode acontecer se o client HTTP não retornar um err para 5xx)
				bucket.consecutiveSuccesses = 0 // Erro de servidor quebra a sequência de sucessos.
				bucket.consecutiveNonCriticalErrors++
				dm.logger.Warnf("[DomainManager] AUTO MODE: Server error (5xx) for domain '%s' (Status: %d, Err: nil). Consecutive server errors: %d/%d. CurrentRPS: %.2f",
					domain, statusCode, bucket.consecutiveNonCriticalErrors, DefaultTransientErrorThreshold, bucket.currentRPS)

				if bucket.consecutiveNonCriticalErrors >= DefaultTransientErrorThreshold {
					if bucket.currentRPS > bucket.minRPS {
						oldRPS := bucket.currentRPS
						newRPS := bucket.currentRPS * DefaultRPSReductionFactorOnError
						bucket.currentRPS = math.Max(newRPS, bucket.minRPS)
						bucket.refillRate = bucket.currentRPS
						bucket.maxTokens = bucket.currentRPS
						dm.logger.Warnf("[DomainManager] AUTO MODE: Domain '%s' RPS reduced from %.2f to %.2f (Min: %.2f) after %d server errors.",
							domain, oldRPS, bucket.currentRPS, bucket.minRPS, bucket.consecutiveNonCriticalErrors)
						bucket.consecutiveNonCriticalErrors = 0 // Resetar após redução
					} else {
						bucket.consecutiveNonCriticalErrors = 0 // Já no mínimo, resetar.
						if dm.config.VerbosityLevel >= 2 { // -vv para log de "já no mínimo" com erros de servidor
							dm.logger.Debugf("[DomainManager] AUTO MODE: Domain '%s' already at MinRPS (%.2f) despite repeated server errors. Error counter reset.", domain, bucket.minRPS)
						}
					}
				}
			}
		}
	} else { // Modo Manual - Apenas logar o resultado
		if err != nil {
			if dm.config.VerbosityLevel >= 1 {
				dm.logger.Warnf("[DomainManager] MANUAL MODE: Request error for domain '%s' (Status: %d, Tokens: %.2f, RefillRate: %.2f/s): %v.",
					domain, statusCode, bucket.tokens, bucket.refillRate, err)
			}
		} else if statusCode >= 400 { // Erros HTTP como 400, 401, 403, 404 etc.
			if dm.config.VerbosityLevel >= 1 { // Logar erros HTTP no modo manual se verbosidade for info ou debug
				dm.logger.Infof("[DomainManager] MANUAL MODE: HTTP error status %d for domain '%s'. Tokens: %.2f. RefillRate: %.2f/s",
					statusCode, domain, bucket.tokens, bucket.refillRate)
			}
		} else { // Sucesso (2xx, 3xx)
			if dm.config.VerbosityLevel >= 2 { // -vv
				dm.logger.Debugf("[DomainManager] MANUAL MODE: Successful request (status: %d) for '%s'. Tokens: %.2f. RefillRate: %.2f/s",
					statusCode, domain, bucket.tokens, bucket.refillRate)
			}
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