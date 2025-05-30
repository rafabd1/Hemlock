package core

import (
	"time"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/networking" // Required for DomainBucketState
	"github.com/rafabd1/Hemlock/internal/report"
)

// ResumePhase define as fases possíveis do scan para o estado de resumo.
type ResumePhase string

const (
	PhaseUnknown         ResumePhase = "Unknown"
	Phase1Cacheability   ResumePhase = "Phase1Cacheability"
	Phase2Probing        ResumePhase = "Phase2Probing"
	PhaseComplete        ResumePhase = "PhaseComplete"
)

// ResumeState armazena o estado completo de um scan para permitir a retomada.
type ResumeState struct {
	HemlockVersion     string                             `json:"hemlock_version"`
	Timestamp          time.Time                          `json:"timestamp"`
	OriginalConfig     *config.Config                     `json:"original_config"`

	CurrentScanPhase   ResumePhase                        `json:"current_scan_phase"`

	// Dados da Fase 1
	// uniqueBaseURLsProcessedInPhase1: Base URLs que já passaram pelo processCacheabilityCheckJob (completamente, incluindo retries).
	// O resultado (cacheável ou não) está em ConfirmedCacheableBaseURLs.
	UniqueBaseURLsProcessedInPhase1 map[string]bool                `json:"unique_base_urls_processed_in_phase1"`
	ConfirmedCacheableBaseURLs    map[string]bool                `json:"confirmed_cacheable_base_urls"` // Conteúdo de s.confirmedCacheableBaseURLs

	// Dados da Fase 2
	// Phase2JobsCompleted: Job.URLString -> true, se o job da fase 2 foi completamente processado.
	Phase2JobsCompleted           map[string]bool                `json:"phase2_jobs_completed"`

	// Resultados Acumulados
	Findings                      []*report.Finding                `json:"findings"`

	// Estado do DomainManager
	// Usaremos o DomainBucketState definido em networking, que precisa ser exportável.
	DomainManagerStatus           map[string]networking.DomainBucketState `json:"domain_manager_status"`

	// Contadores da Barra de Progresso e Globais
	// Fase 1 (Barra de Progresso baseada em jobs)
	ProgressBarPhase1TotalJobs     int    `json:"progress_bar_phase1_total_jobs"`
	ProgressBarPhase1CompletedJobs int    `json:"progress_bar_phase1_completed_jobs"`
	// Fase 2 (Barra de Progresso baseada em probes)
	ProgressBarPhase2TotalProbes      int    `json:"progress_bar_phase2_total_probes"`     // Estimativa total
	ProgressBarPhase2CompletedProbes  uint64 `json:"progress_bar_phase2_completed_probes"` // s.completedProbesInPhase.Load()
	
	TotalProbesExecutedGlobal uint64 `json:"total_probes_executed_global"` // s.totalProbesExecutedGlobal.Load()

	// Jobs que estavam explicitamente na pendingJobsQueue ou no heap do feeder no momento do save.
	// Estes são jobs que foram agendados mas ainda não pegos por um worker ou ainda esperando retry/DM.
	// Ao carregar, estes podem ser diretamente reenfileirados, após verificar se já não foram completados
	// por outra lógica (ex: se o job original já consta como completed).
	// Para uma primeira versão, podemos não salvar estes explicitamente e, em vez disso,
	// reconstruir a lista de jobs pendentes a partir do que *não* foi completado.
	// PendingJobsFromQueue []TargetURLJob `json:"pending_jobs_from_queue,omitempty"`
	// PendingJobsFromFeederHeap []TargetURLJob `json:"pending_jobs_from_feeder_heap,omitempty"`
} 