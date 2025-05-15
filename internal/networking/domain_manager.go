package networking

import (
	"net/http"
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/config" // Para acessar MinRequestDelayMs e DomainCooldownMs
	"github.com/rafabd1/Hemlock/internal/utils"
)

// domainState guarda o estado de um domínio específico.
type domainState struct {
	lastRequestTime     time.Time
	blockedUntil        time.Time
	consecutiveFailures int // Novo campo para rastrear falhas consecutivas
}

// DomainManager gerencia o estado e as políticas por domínio,
// incluindo rate limiting e detecção de bloqueios (WAF).
// É crucial para o comportamento inteligente da ferramenta em relação a domínios específicos.
type DomainManager struct {
	config       *config.Config // Para ler MinRequestDelayMs, DomainCooldownMs
	logger       utils.Logger
	domainStatus map[string]*domainState
	mu           sync.RWMutex // Protege o acesso ao domainStatus
}

// NewDomainManager cria uma nova instância do DomainManager.
func NewDomainManager(cfg *config.Config, logger utils.Logger) *DomainManager {
	return &DomainManager{
		config:       cfg,
		logger:       logger,
		domainStatus: make(map[string]*domainState),
	}
}

// getOrCreateDomainState recupera ou cria o estado para um domínio.
// Deve ser chamado com o lock apropriado (leitura ou escrita) já adquirido.
func (dm *DomainManager) getOrCreateDomainState(domain string) *domainState {
	ds, exists := dm.domainStatus[domain]
	if !exists {
		ds = &domainState{}
		dm.domainStatus[domain] = ds
	}
	return ds
}

// CanRequest verifica se uma requisição pode ser feita a um domínio.
// Retorna true se puder, false caso contrário, junto com o tempo de espera necessário.
func (dm *DomainManager) CanRequest(domain string) (bool, time.Duration) {
	dm.mu.RLock()
	ds := dm.getOrCreateDomainState(domain) // Leitura, não cria se não existir sob RLock
	// Para garantir que getOrCreateDomainState possa criar, precisamos de um lock de escrita
	// ou de uma abordagem de duplo check. Vamos simplificar por agora e assumir que 
	// o estado será criado na primeira escrita (RecordRequestSent).
	// Para CanRequest, se não existe, não há restrições ainda.
	existingDs, exists := dm.domainStatus[domain]
	dm.mu.RUnlock() // Liberar RLock antes de um possível WLock

	if !exists { // Se o domínio não foi visto, pode prosseguir sem delay
		return true, 0
	}

	// Re-adquirir RLock para ler o estado existente com segurança
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	ds = existingDs // Usar o estado que sabemos que existe

	now := time.Now()

	// 1. Verificar se o domínio está bloqueado (cooldown)
	if ds.blockedUntil.After(now) {
		waitTime := ds.blockedUntil.Sub(now)
		dm.logger.Debugf("[DomainManager] Domínio '%s' está em cooldown. Espere: %s", domain, waitTime)
		return false, waitTime
	}

	// 2. Verificar delay mínimo entre requisições
	minDelay := time.Duration(dm.config.MinRequestDelayMs) * time.Millisecond
	if ds.lastRequestTime.IsZero() { // Primeira requisição para este domínio (após qualquer cooldown)
		return true, 0
	}

	timeSinceLastRequest := now.Sub(ds.lastRequestTime)
	if timeSinceLastRequest < minDelay {
		waitTime := minDelay - timeSinceLastRequest
		dm.logger.Debugf("[DomainManager] Delay mínimo para '%s' não atingido. Espere: %s", domain, waitTime)
		return false, waitTime
	}

	return true, 0
}

// RecordRequestSent atualiza o timestamp da última requisição para o domínio.
func (dm *DomainManager) RecordRequestSent(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	ds.lastRequestTime = time.Now()
	dm.logger.Debugf("[DomainManager] Requisição registrada para '%s' em %s", domain, ds.lastRequestTime.Format(time.RFC3339))
}

// RecordRequestResult analisa o resultado de uma requisição e pode bloquear o domínio se necessário.
func (dm *DomainManager) RecordRequestResult(domain string, statusCode int, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)

	if err != nil {
		ds.consecutiveFailures++
		dm.logger.Debugf("[DomainManager] Erro na requisição para %s: %v. Falhas consecutivas: %d. Avaliando para cooldown.", domain, err, ds.consecutiveFailures)

		// Se atingir o limite de falhas consecutivas (a ser configurado, por ex, em cfg.MaxConsecutiveFailuresToBlock)
		// Vamos usar um valor fixo por agora, ex: 3, e depois tornar configurável.
		// TODO: Adicionar cfg.MaxConsecutiveFailuresToBlock e cfg.StatusCodesToBlockOnError
		maxFailures := dm.config.MaxConsecutiveFailuresToBlock // Supondo que este campo exista na config
		if maxFailures <= 0 { // Se não configurado ou desabilitado, usar um default interno ou não bloquear por falhas consecutivas
			maxFailures = 3 // Default interno se não configurado
		}

		if ds.consecutiveFailures >= maxFailures {
			dm.logger.Warnf("[DomainManager] Domínio %s atingiu %d falhas consecutivas. Aplicando cooldown.", domain, ds.consecutiveFailures)
			dm.blockDomainInternal(domain, ds) // Chama helper interno que já tem o lock
			ds.consecutiveFailures = 0        // Resetar após bloquear
		} else if statusCode != 0 && (statusCode == http.StatusForbidden || statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable) {
			// Se houve um erro de rede *mas* também temos um status code problemático (raro, mas possível se o erro for na leitura do corpo após receber headers)
			dm.logger.Warnf("[DomainManager] Erro na requisição para %s mas com status code %d. Aplicando cooldown.", domain, statusCode)
			dm.blockDomainInternal(domain, ds)
			ds.consecutiveFailures = 0
		}
		return // Importante: retornar após tratar o erro
	}

	// Se err == nil (requisição HTTP em si foi bem sucedida, temos um status code)
	// Resetar falhas consecutivas se a requisição foi bem sucedida (mesmo que não seja 2xx, mas não um erro de rede)
	ds.consecutiveFailures = 0 

	if statusCode == http.StatusForbidden || statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable {
		dm.logger.Warnf("[DomainManager] Status code %d recebido de %s. Aplicando cooldown.", statusCode, domain)
		dm.blockDomainInternal(domain, ds)
	}
	// Poderíamos adicionar lógica para outros status codes se necessário, ou contadores para status codes específicos.
}

// blockDomainInternal é um helper para evitar duplicação de código e garantir que o lock não seja re-adquirido.
// Assume que o lock de escrita dm.mu já está mantido.
func (dm *DomainManager) blockDomainInternal(domain string, ds *domainState) {
	cooldownDuration := time.Duration(dm.config.DomainCooldownMs) * time.Millisecond
	ds.blockedUntil = time.Now().Add(cooldownDuration)
	dm.logger.Warnf("[DomainManager] Domínio '%s' bloqueado até %s (cooldown: %s)", domain, ds.blockedUntil.Format(time.RFC3339), cooldownDuration)
}

// BlockDomain marca um domínio como bloqueado por uma duração específica.
// Esta é a versão pública que adquire o lock.
func (dm *DomainManager) BlockDomain(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	ds := dm.getOrCreateDomainState(domain)
	dm.blockDomainInternal(domain, ds)
	// ds.consecutiveFailures = 0 // Resetar falhas aqui também pode ser uma boa ideia, se BlockDomain for chamada externamente.
	                            // Por ora, RecordRequestResult cuida do reset após o bloqueio.
}

// IsBlocked verifica se um domínio está atualmente bloqueado e retorna o tempo de expiração do bloqueio.
// Retorna false se não estiver bloqueado.
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