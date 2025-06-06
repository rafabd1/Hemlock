package core

import (
	"container/heap"
	"context"
	"errors" // Added for errors.Is
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rafabd1/Hemlock/internal/config"
	"github.com/rafabd1/Hemlock/internal/networking"
	"github.com/rafabd1/Hemlock/internal/output"
	"github.com/rafabd1/Hemlock/internal/report"
	"github.com/rafabd1/Hemlock/internal/utils"
)

// JobType defines the type of work a TargetURLJob represents.
type JobType string

const (
	// JobTypeCacheabilityCheck indicates a job to check if a base URL is cacheable.
	JobTypeCacheabilityCheck JobType = "CacheabilityCheck"
	// JobTypeFullProbe indicates a job to perform full header/parameter probes on a cacheable URL.
	JobTypeFullProbe JobType = "FullProbe"
)

// TargetURLJob struct defines a unit of work for a worker.
// It contains the specific URL (with parameters) to be tested and its base domain.
type TargetURLJob struct {
	URLString      string            // For CacheabilityCheck: base URL. For FullProbe: full URL with params.
	BaseDomain     string
	OriginalParams map[string]string // Relevant for FullProbe type, empty/nil for CacheabilityCheck.
	Retries        int               // Number of times this job has been attempted
	NextAttemptAt  time.Time         // Time after which this job can be retried
	JobType        JobType           // Type of job
}

// ScanTaskResult holds the outcome of scanning a single URL.
// This might evolve to include more details or be part of the `report.Finding` itself.
type ScanTaskResult struct {
	URL     string
	Finding *report.Finding // nil if no finding
	Error   error
}

// HeapItem representa um item na priority queue (min-heap) do jobFeederLoop.
// Contém o job e o tempo para sua próxima tentativa, usado para priorização.
// Index é necessário para heap.Fix e heap.Remove.
type HeapItem struct {
	Job           TargetURLJob
	NextAttemptAt time.Time // Prioridade do heap, quanto menor (mais cedo), maior a prioridade
	Index         int       // O índice do item na heap.
}

// JobPriorityQueue implementa heap.Interface para HeapItems.
// É um min-heap baseado em NextAttemptAt.
type JobPriorityQueue []*HeapItem

func (pq JobPriorityQueue) Len() int { return len(pq) }

func (pq JobPriorityQueue) Less(i, j int) bool {
	// Queremos Pop para nos dar o menor (mais antigo) NextAttemptAt.
	return pq[i].NextAttemptAt.Before(pq[j].NextAttemptAt)
}

func (pq JobPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}

// Push adiciona um HeapItem à fila.
func (pq *JobPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*HeapItem)
	item.Index = n
	*pq = append(*pq, item)
}

// Pop remove e retorna o HeapItem com a menor NextAttemptAt (maior prioridade) da fila.
func (pq *JobPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // Evita memory leak
	item.Index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// update modifica a prioridade e o valor de um HeapItem na fila.
// Não é diretamente usado pelo jobFeederLoop atual, mas é uma função padrão para heaps.
// func (pq *JobPriorityQueue) update(item *HeapItem, job TargetURLJob, nextAttemptAt time.Time) {
// 	heap.Remove(pq, item.Index)
// 	item.Job = job
// 	item.NextAttemptAt = nextAttemptAt
// 	heap.Push(pq, item)
// }

// Scheduler orchestrates the scanning process.
// It manages target URLs, headers to test, concurrency, and coordinates
// the HTTP client and processor to find vulnerabilities.
type Scheduler struct {
	config        *config.Config
	client        *networking.Client
	processor     *Processor
	domainManager *networking.DomainManager
	logger        utils.Logger
	findings      []*report.Finding
	wg            sync.WaitGroup
	mu            sync.Mutex // For thread-safe access to findings slice

	workerJobQueue chan TargetURLJob // Queue from which workers will pull jobs
	pendingJobsQueue chan TargetURLJob // NEW: Queue for jobs waiting for NextAttemptAt or DomainManager approval

	activeJobs    int32         // Counter for all active jobs (main + retry)
	maxRetries    int           // From config
	doneChan      chan struct{}   // Signals all processing is complete
	closeDoneChanOnce sync.Once // Garante que doneChan seja fechado apenas uma vez

	progressBar             *output.ProgressBar
	totalJobsForProgressBar int // This will now represent the total for the *current phase* being displayed
	completedJobsInPhaseForBar int // Counter for jobs completed in the current phase for progress bar

	totalProbesExecutedGlobal atomic.Uint64 // Contador global de todas as probes
	completedProbesInPhase    atomic.Uint64 // Contador de probes para a barra da FASE ATUAL (Fase 2)

	ctx    context.Context
	cancel context.CancelFunc

	// Fields for two-phase scanning
	confirmedCacheableBaseURLs map[string]bool // Stores base URLs confirmed as cacheable
	phase1CompletionWg         sync.WaitGroup    // WaitGroup for cacheability check phase
}

// NewScheduler creates a new Scheduler instance.
func NewScheduler(cfg *config.Config, client *networking.Client, processor *Processor, dm *networking.DomainManager, logger utils.Logger) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		config:        cfg,
		client:        client,
		processor:     processor,
		domainManager: dm,
		logger:        logger,
		findings:      make([]*report.Finding, 0),
		maxRetries:    cfg.MaxRetries,
		doneChan:      make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// buildProbeData converts networking.ClientResponseData to core.ProbeData.
func buildProbeData(url string, reqData networking.ClientRequestData, respData networking.ClientResponseData) ProbeData {
	return ProbeData{
		URL:            url,
		RequestHeaders: reqData.CustomHeaders,
		Response:       respData.Response,
		Body:           respData.Body,
		RespHeaders:    respData.RespHeaders,
		Error:          respData.Error,
	}
}

// performRequestWithDomainManagement is a helper to encapsulate DomainManager logic.
// Esta função pode ser simplificada ou incorporada diretamente no worker, 
// pois o worker agora chamará CanRequest antes de processar o job.
func (s *Scheduler) performRequestWithDomainManagement(domain string, reqData networking.ClientRequestData) networking.ClientResponseData {
	// A lógica de CanRequest e waitTime será movida para o worker antes de chamar processURLJob.
	// Esta função agora apenas registra e executa a requisição.
	s.domainManager.RecordRequestSent(domain) 
	respData := s.client.PerformRequest(reqData)
	s.domainManager.RecordRequestResult(domain, statusCodeFromResponse(respData.Response), respData.Error)
	return respData
}

// StartScan begins the scanning process based on the scheduler's configuration.
func (s *Scheduler) StartScan() []*report.Finding {
	s.logger.Debugf("Scheduler: Initializing scan...")
	groupedBaseURLsAndParams, uniqueBaseURLs, _, _ := utils.PreprocessAndGroupURLs(s.config.Targets, s.config, s.logger)

	// Defer para limpeza finalíssima da última instância da barra e contexto do scheduler
	defer func() {
		if s.progressBar != nil { // Se alguma barra foi criada em algum momento
			s.progressBar.Finalize()
		}
		output.SetActiveProgressBar(nil) // Garante que nenhuma barra fique como global no final
		s.cancel()                       // Cancela o contexto principal do scheduler
	}()

	if len(uniqueBaseURLs) == 0 {
		s.logger.Warnf("Scheduler: No processable targets. Aborting scan.")
		return s.findings
	}

	// Inicializar canais ANTES de iniciar jobFeederLoop
	// A capacidade exata de pendingQueueBufferSize será definida mais tarde, quando soubermos o total da Fase 1.
	// Por enquanto, um buffer razoável para workerJobQueue.
	concurrencyLimit := s.config.Concurrency
	if concurrencyLimit <= 0 { concurrencyLimit = 1 }
	s.workerJobQueue = make(chan TargetURLJob, concurrencyLimit)
	// pendingJobsQueue será inicializado após calcularmos os jobs da Fase 1 ou um total preliminar.

	// --- PHASE 1: Cacheability Checks ---
	s.logger.Infof("Scheduler: Starting Phase 1 - Cacheability Checks for %d unique base URLs.", len(uniqueBaseURLs))
	s.confirmedCacheableBaseURLs = make(map[string]bool)
	
	var phase1Jobs []TargetURLJob
	for _, baseURL := range uniqueBaseURLs {
		parsedBase, err := url.Parse(baseURL)
		if err != nil {
			s.logger.Warnf("Scheduler: Failed to parse base URL '%s' for cacheability check: %v. Skipping.", baseURL, err)
			continue
		}
		phase1Jobs = append(phase1Jobs, TargetURLJob{
			URLString:  baseURL,
			BaseDomain: parsedBase.Hostname(),
			JobType:    JobTypeCacheabilityCheck,
			NextAttemptAt: time.Now(),
		})
	}

	s.phase1CompletionWg.Add(len(phase1Jobs)) // Adiciona ao WaitGroup ANTES de iniciar workers ou enfileirar

	// Inicializa pendingJobsQueue e workers DEPOIS de saber len(phase1Jobs)
	pendingQueueBufferSizePhase1 := len(phase1Jobs) + concurrencyLimit // concurrencyLimit já definido
	if pendingQueueBufferSizePhase1 < 100 {pendingQueueBufferSizePhase1 = 100}
	s.pendingJobsQueue = make(chan TargetURLJob, pendingQueueBufferSizePhase1)

	for i := 0; i < concurrencyLimit; i++ {
		s.wg.Add(1)
		go s.worker(i) 
	}
	
	if len(phase1Jobs) > 0 {
		atomic.AddInt32(&s.activeJobs, int32(len(phase1Jobs))) // INCREMENTA activeJobs para Fase 1
		for _, job := range phase1Jobs {
			s.pendingJobsQueue <- job
		}
	} else {
		s.logger.Warnf("Scheduler: No jobs created for Phase 1 (Cacheability Check).")
		// Se não houver jobs na Fase 1, a goroutine orquestradora (que espera phase1CompletionWg)
		// será liberada imediatamente se len(phase1Jobs) for 0 e Add(0) foi chamado.
		// Ela então procederá para a Fase 2 ou finalizará.
	}
	
	// Configuração da barra da Fase 1
	s.totalJobsForProgressBar = len(phase1Jobs) // Total for Phase 1 progress bar
	s.completedJobsInPhaseForBar = 0            // Reset for Phase 1

	if s.totalJobsForProgressBar > 0 && !s.config.Silent { // Initialize progress bar here for Phase 1
		s.progressBar = output.NewProgressBar(s.totalJobsForProgressBar, 40)
		s.progressBar.SetPrefix("Phase 1/2 (Cache Checks): ")
		s.progressBar.Start()
	} else if !s.config.Silent { // Handle case where Phase 1 has 0 jobs but we still might want a bar for Phase 2
		s.progressBar = output.NewProgressBar(0, 40) // Start with 0, will be reset
		s.progressBar.SetPrefix("Phase 1/2 (Cache Checks): ")
		s.progressBar.Start()
	}
	
	// Start jobFeederLoop and workers
	s.wg.Add(1) // For feeder
	go s.jobFeederLoop()

	// Goroutine to manage transition to Phase 2
	s.wg.Add(1) // For this orchestrating goroutine
		go func() {
			defer s.wg.Done()

		s.phase1CompletionWg.Wait() // Wait for all Phase 1 jobs to complete

		// Captura a instância da barra da Fase 1 ANTES de qualquer coisa da Fase 2
		progressBarPhase1 := s.progressBar

		// Parar e limpar a barra da Fase 1
		if progressBarPhase1 != nil {
			progressBarPhase1.Stop()
		}

		// DEBUG LOGS IMEDIATAMENTE APÓS A FASE 1 COMPLETAR
		s.mu.Lock()
		numCacheable := len(s.confirmedCacheableBaseURLs)
		s.mu.Unlock()
		initialActiveJobsAfterPhase1 := atomic.LoadInt32(&s.activeJobs)
		s.logger.Debugf("[Orchestrator-Debug] After Phase 1 Wait: numCacheable=%d, initialActiveJobsAfterPhase1=%d", 
			numCacheable, initialActiveJobsAfterPhase1)

		s.logger.Infof("Scheduler: Phase 1 (Cacheability Check) COMPLETED. Found %d cacheable base URLs.", numCacheable)

		var phase2Jobs []TargetURLJob
		if numCacheable > 0 {
			for _, baseURL := range uniqueBaseURLs {
				s.mu.Lock()
				isBaseCacheable := s.confirmedCacheableBaseURLs[baseURL]
				s.mu.Unlock()

				if isBaseCacheable {
					paramSets := groupedBaseURLsAndParams[baseURL]
					parsedBase, _ := url.Parse(baseURL)
					baseDomain := parsedBase.Hostname()
					
					if s.config.EnableParamFuzzing {
						// Se fuzzing está habilitado, ele lida com URLs com e sem params.
						if len(paramSets) == 0 { // Sem params originais, mas fuzzing habilitado
							actualTargetURL, _ := constructURLWithParams(baseURL, make(map[string]string))
							phase2Jobs = append(phase2Jobs, TargetURLJob{
								URLString:      actualTargetURL, // Testará headers na URL base + fuzzing de novos params
								BaseDomain:     baseDomain,
								OriginalParams: make(map[string]string),
								JobType:        JobTypeFullProbe,
									NextAttemptAt:  time.Now(),
							})
						} else { // Com params originais E fuzzing habilitado
							for _, paramSet := range paramSets {
								actualTargetURL, _ := constructURLWithParams(baseURL, paramSet)
									phase2Jobs = append(phase2Jobs, TargetURLJob{
										URLString:      actualTargetURL, // Testará params originais + headers + fuzzing de novos params
										BaseDomain:     baseDomain,
										OriginalParams: paramSet,
										JobType:        JobTypeFullProbe,
										NextAttemptAt:  time.Now(),
									})
							}
						}
					} else { // EnableParamFuzzing é FALSE
						// Testes de header estão habilitados por padrão (s.config.DisableHeaderTests é false)
						// Queremos:
						// 1. Um job para a URL base (sem query params) para testar headers.
						// 2. Se a URL original tinha parâmetros, um job adicional para a URL com seus parâmetros originais, também para testar headers.

						// Job para a URL base (sem query params) - sempre criar se testes de header estiverem habilitados
						if !s.config.DisableHeaderTests {
							// A `baseURL` de uniqueBaseURLs já é scheme + host + path (sem query params da URL original)
							urlForBaseHeaderTest := baseURL
							phase2Jobs = append(phase2Jobs, TargetURLJob{
								URLString:      urlForBaseHeaderTest,
								BaseDomain:     baseDomain,
								OriginalParams: make(map[string]string), // Indica que este job é para a base nua
								JobType:        JobTypeFullProbe,
								NextAttemptAt:  time.Now(),
							})
						}

						// Jobs adicionais para cada conjunto de parâmetros originais, se houver.
						// Estes testarão headers na URL completa (com seus respectivos params).
						if len(paramSets) > 0 {
							for _, paramSet := range paramSets {
								if len(paramSet) > 0 { // Só se o conjunto de parâmetros não for vazio
									actualTargetURL, _ := constructURLWithParams(baseURL /* scheme+host+path */, paramSet /* query */)
									phase2Jobs = append(phase2Jobs, TargetURLJob{
										URLString:      actualTargetURL,
										BaseDomain:     baseDomain,
										OriginalParams: paramSet, // Mantém os params originais para este job
										JobType:        JobTypeFullProbe,
										NextAttemptAt:  time.Now(),
									})
								}
							}
						}
					}
				}
			}
		}
		
		// Incrementar activeJobs para Fase 2 ANTES de enfileirar
		if len(phase2Jobs) > 0 {
			atomic.AddInt32(&s.activeJobs, int32(len(phase2Jobs)))
		}

		// MAIS DEBUG LOGS ANTES DA DECISÃO DA FASE 2
		finalActiveJobsBeforePhase2Queue := atomic.LoadInt32(&s.activeJobs)
		s.logger.Debugf("[Orchestrator-Debug] Before Phase 2 queueing: len(phase2Jobs)=%d, finalActiveJobsBeforePhase2Queue=%d, EnableParamFuzzing: %v", 
			len(phase2Jobs), finalActiveJobsBeforePhase2Queue, s.config.EnableParamFuzzing)
		// Mostrar os paramSets se verbosidade -vv
		if s.config.VerbosityLevel >= 2 && numCacheable > 0 {
			countLogged := 0
			for baseURLScanned, isActuallyCacheable := range s.confirmedCacheableBaseURLs { // Iterar sobre o mapa de cacheáveis
				if isActuallyCacheable && countLogged < 5 { // Logar para até 5 cacheáveis
					paramSetsForThisURL := groupedBaseURLsAndParams[baseURLScanned]
					s.logger.Debugf("[Orchestrator-Debug] For confirmed cacheable baseURL '%s', found %d paramSets in groupedBaseURLsAndParams.", baseURLScanned, len(paramSetsForThisURL))
					for i, ps := range paramSetsForThisURL {
						s.logger.Debugf("[Orchestrator-Debug]   ParamSet %d for %s: %v", i, baseURLScanned, ps)
					}
					countLogged++
				}
			}
		}

		// Calcular o total estimado de probes para a Fase 2
		estimatedTotalProbesInPhase2 := 0
		if len(phase2Jobs) > 0 {
			numBasePayloads := len(s.config.BasePayloads)
			if numBasePayloads == 0 && s.config.DefaultPayloadPrefix != "" { // Lógica de fallback para payloads
				numBasePayloads = 1
			}

			if !s.config.DisableHeaderTests {
				estimatedTotalProbesInPhase2 += len(phase2Jobs) * len(s.config.HeadersToTest)
			}
			if s.config.EnableParamFuzzing {
				estimatedTotalProbesInPhase2 += len(phase2Jobs) * len(s.config.ParamsToFuzz) * numBasePayloads
				for _, job := range phase2Jobs { // Adicionar contagem para params originais apenas se fuzzing habilitado
					if len(job.OriginalParams) > 0 {
						estimatedTotalProbesInPhase2 += len(job.OriginalParams) * numBasePayloads
					}
				}
			} else {
			    // Se o fuzzing de params está desabilitado, contamos apenas os params originais não vazios
			    for _, job := range phase2Jobs {
			        if len(job.OriginalParams) > 0 {
			            estimatedTotalProbesInPhase2 += len(job.OriginalParams) * numBasePayloads
			        }
			    }
			}
		}
		if estimatedTotalProbesInPhase2 == 0 && len(phase2Jobs) > 0 {
		    // Se há jobs na Fase 2, mas nenhuma probe foi estimada (ex: apenas headers desabilitados e fuzzing desabilitado sem params originais),
		    // usar o número de jobs da Fase 2 para a barra, para não ficar em 0.
		    estimatedTotalProbesInPhase2 = len(phase2Jobs)
		}

		s.logger.Infof("Scheduler: Starting Phase 2 - Full Probing with %d jobs (estimated %d probes).", len(phase2Jobs), estimatedTotalProbesInPhase2)
		
		// Configuração da barra da Fase 2
		if len(phase2Jobs) > 0 && !s.config.Silent {
			s.totalJobsForProgressBar = estimatedTotalProbesInPhase2 // Total para a barra da Fase 2
			s.completedProbesInPhase.Store(0) // Resetar contador de probes para a Fase 2
			s.progressBar = output.NewProgressBar(s.totalJobsForProgressBar, 40) 
			s.progressBar.SetPrefix("Phase 2 - Probing: ")
			// s.completedJobsInPhaseForBar = 0 // Não é mais usado para Fase 2
			s.progressBar.Start()
		} else if progressBarPhase1 != nil { 
			// Se não há jobs na Fase 2, mas havia uma barra na Fase 1 (que já foi parada),
			// garante que nenhuma barra esteja como global.
			output.SetActiveProgressBar(nil)
		} else {
			// Se não havia barra na Fase 1 e não há jobs na Fase 2
			output.SetActiveProgressBar(nil)
		}

		if len(phase2Jobs) > 0 {
			// atomic.AddInt32(&s.activeJobs, int32(len(phase2Jobs))) // ESTA LINHA É A REDUNDANTE E SERÁ REMOVIDA
			for _, job := range phase2Jobs {
				s.pendingJobsQueue <- job
			}
		} else {
			// Se não há jobs na fase 2, e fase 1 também já terminou
			// Não fechar s.doneChan aqui. Deixar que decrementActiveJobs cuide disso
			// quando o último job da Fase 1 (ou qualquer job que ainda exista) termine.
			// Se activeJobs já é 0 aqui, decrementActiveJobs já o teria fechado ou o fechará em breve.
			s.logger.Debugf("[Orchestrator-Debug] No Phase 2 jobs to enqueue. activeJobs currently: %d", atomic.LoadInt32(&s.activeJobs))
			// if atomic.LoadInt32(&s.activeJobs) == 0 {  // LÓGICA DE FECHAMENTO REMOVIDA DAQUI
			// 	s.logger.Infof("Scheduler: No Phase 1 or Phase 2 jobs to run. Signaling completion via orchestrator.")
			// 	s.closeDoneChanOnce.Do(func() {
			// 		close(s.doneChan)
			// 	})
			// }
		}

		// INICIAR GOROUTINE DE MONITORAMENTO PARA FECHAR s.doneChan QUANDO activeJobs == 0
		s.wg.Add(1) // Adicionar ao WaitGroup principal do scheduler para esta goroutine de monitoramento
		go func() {
			defer s.wg.Done()
			for {
				// Verificar periodicamente ou usar um canal se quiser ser mais reativo
				// Para simplicidade, um loop de polling com sleep curto.
				time.Sleep(100 * time.Millisecond) 
				currentJobs := atomic.LoadInt32(&s.activeJobs)
				if currentJobs == 0 {
					s.logger.Debugf("[SchedulerMonitor] All active jobs processed (count is 0). Signaling completion.") // Mudado para Debugf
					s.closeDoneChanOnce.Do(func() {
						close(s.doneChan)
					})
					return // Sair da goroutine de monitoramento
				} else if currentJobs < 0 {
					s.logger.Errorf("[SchedulerMonitor] CRITICAL: Active jobs count went negative (%d). Signaling completion to avoid deadlock.", currentJobs)
					s.closeDoneChanOnce.Do(func() {
						close(s.doneChan)
					})
					return // Sair da goroutine de monitoramento
				}
				// Opcional: Adicionar um log de depuração aqui para ver currentJobs periodicamente se verbosidade alta
				if s.config.VerbosityLevel >= 2 {
					s.logger.Debugf("[SchedulerMonitor] Active jobs: %d. Waiting for 0 to complete.", currentJobs)
				}
			}
		}()

	}() // End of orchestrator goroutine

	// Main wait for all jobs (Phase 1 + Phase 2) to complete
	<-s.doneChan

	s.logger.Debugf("Scheduler: All scan tasks, workers, and job feeder completed.") // Mudado para Debugf
	return s.findings
}

// jobFeederLoop é uma goroutine que pega jobs da pendingJobsQueue,
// espera por job.NextAttemptAt se necessário (usando um min-heap),
// verifica a permissão do DomainManager, e então envia para workerJobQueue.
func (s *Scheduler) jobFeederLoop() {
	defer s.wg.Done()
	defer close(s.workerJobQueue)

	if s.config.VerbosityLevel >= 1 {
		s.logger.Infof("[JobFeeder] Started.")
	}

	waitingJobsHeap := new(JobPriorityQueue)
	heap.Init(waitingJobsHeap)

	var timer *time.Timer
	scheduleNextWakeup := func() {
		if timer != nil {
			timer.Stop() // Parar timer anterior para evitar que dispare desnecessariamente
		}
		if waitingJobsHeap.Len() == 0 {
			// Nenhum job esperando, não precisa de timer por enquanto.
			// O loop será acordado por novos jobs da pendingJobsQueue ou pelo s.ctx.Done().
			if s.config.VerbosityLevel >= 2 {
				s.logger.Debugf("[JobFeeder] Heap is empty. Timer not set.")
			}
			return
		}

		nextJobTime := (*waitingJobsHeap)[0].NextAttemptAt
		waitTime := time.Until(nextJobTime)

		if waitTime <= 0 {
			// O próximo job já está pronto ou deveria estar.
			// Disparar imediatamente (ou quase) para processá-lo.
			// Usar um timer pequeno para evitar busy-loop, mas permitir processamento imediato.
			waitTime = 1 * time.Millisecond 
			if s.config.VerbosityLevel >= 2 {
				s.logger.Debugf("[JobFeeder] Next job in heap is ready or past due. Setting short timer.")
			}
		} else {
			if s.config.VerbosityLevel >= 2 {
				s.logger.Debugf("[JobFeeder] Next job in heap at %s. Setting timer for %s.", nextJobTime.Format(time.RFC3339), waitTime)
			}
		}
		timer = time.NewTimer(waitTime)
	}
	defer func() { // Garante que o timer seja parado se o loop sair
		if timer != nil {
			timer.Stop()
		}
	}()
	scheduleNextWakeup() // Agendar o primeiro wakeup (se houver algo no heap, o que não haverá inicialmente)

	for {
		var timerChan <-chan time.Time
		if timer != nil {
			timerChan = timer.C
		}

		select {
		case job, ok := <-s.pendingJobsQueue:
			if !ok { // pendingJobsQueue foi fechada
				if s.config.VerbosityLevel >= 1 {
					s.logger.Infof("[JobFeeder] pendingJobsQueue closed. Processing remaining jobs in heap and exiting.")
				}
				// Processar o que resta no heap antes de sair
				for waitingJobsHeap.Len() > 0 {
					item := heap.Pop(waitingJobsHeap).(*HeapItem)

					// VERIFICAR SE O DOMÍNIO FOI DESCARTADO (NOVO - para jobs do heap no final)
					if s.domainManager.IsDomainDiscarded(item.Job.BaseDomain) {
						s.logger.Warnf("[JobFeeder] Job %s for DISCARDED domain %s (from heap drain). Discarding job and compensating progress.", item.Job.URLString, item.Job.BaseDomain)
						s.handleDiscardedDomainJob(item.Job)
						continue // Pular para o próximo item do heap
					}

					if time.Now().Before(item.NextAttemptAt) {
						// Se o job ainda não está pronto, esperar por ele.
						// Ou, alternativamente, descartar se o contexto estiver feito.
						select {
						case <-time.After(time.Until(item.NextAttemptAt)):
						case <-s.ctx.Done():
							s.logger.Infof("[JobFeeder] Context done while draining heap (job %s). Discarding.", item.Job.URLString)
			s.decrementActiveJobs()
							continue
		}
	}
					s.trySendToWorkerOrRequeue(item.Job, waitingJobsHeap)
	}
				return // Sai do jobFeederLoop
			}

	if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[JobFeeder] Received job %s (for %s, next attempt at %s) from pendingJobsQueue. Adding to heap.",
					job.URLString, job.BaseDomain, job.NextAttemptAt.Format(time.RFC3339))
			}

			// VERIFICAR SE O DOMÍNIO FOI DESCARTADO (NOVO - para jobs da pendingJobsQueue)
			if s.domainManager.IsDomainDiscarded(job.BaseDomain) {
				s.logger.Warnf("[JobFeeder] Job %s for DISCARDED domain %s (from pendingJobsQueue). Discarding job and compensating progress.", job.URLString, job.BaseDomain)
				s.handleDiscardedDomainJob(job)
				// Não adiciona ao heap, apenas continua para o próximo select
			} else {
			heap.Push(waitingJobsHeap, &HeapItem{Job: job, NextAttemptAt: job.NextAttemptAt})
			scheduleNextWakeup()
			}

		case <-timerChan:
			if s.config.VerbosityLevel >= 2 {
				s.logger.Debugf("[JobFeeder] Timer fired. Processing ready jobs from heap.")
			}
			for waitingJobsHeap.Len() > 0 && !(*waitingJobsHeap)[0].NextAttemptAt.After(time.Now()) {
				item := heap.Pop(waitingJobsHeap).(*HeapItem)

				// VERIFICAR SE O DOMÍNIO FOI DESCARTADO (NOVO - para jobs do heap via timer)
				if s.domainManager.IsDomainDiscarded(item.Job.BaseDomain) {
					s.logger.Warnf("[JobFeeder] Job %s for DISCARDED domain %s (from heap timer). Discarding job and compensating progress.", item.Job.URLString, item.Job.BaseDomain)
					s.handleDiscardedDomainJob(item.Job)
					continue // Pular para o próximo item do heap que está pronto
				}

				s.trySendToWorkerOrRequeue(item.Job, waitingJobsHeap)
			}
			scheduleNextWakeup()

		case <-s.ctx.Done():
			if s.config.VerbosityLevel >= 1 {
				s.logger.Infof("[JobFeeder] Scheduler context done. Exiting loop.")
			}
			// Não precisa drenar o heap aqui, pois os jobs ativos já teriam sido decrementados
			// ou os workers serão interrompidos. Os jobs no heap não foram "pegos" por um worker.
			// No entanto, é preciso garantir que activeJobs seja decrementado para jobs que estavam no heap
			// e não chegaram a ser processados.
			// A lógica de decremento deve ser mais precisa, talvez no momento em que o job é *descartado*.
			// Por agora, vamos confiar que o decremento ocorre em handleJobOutcome ou se o worker não pega.
			// Se um job está no heap e o scheduler para, ele não foi realmente "ativo" no sentido de processamento.
			// A contagem inicial de activeJobs é baseada nos jobs *iniciais totais*.
			// Se o jobFeeder os descarta antes de ir para um worker, o activeJobs deve ser decrementado.

			// Vamos limpar o heap e decrementar para cada job que estava lá.
			for waitingJobsHeap.Len() > 0 {
				item := heap.Pop(waitingJobsHeap).(*HeapItem)
				s.logger.Infof("[JobFeeder] Context done. Discarding job %s from heap and decrementing active jobs.", item.Job.URLString)
				s.decrementActiveJobs() // DECREMENTAR AQUI - Job estava no heap, nunca foi para worker
			}
			return
		}
	}
}

// trySendToWorkerOrRequeue é um helper para o jobFeederLoop.
// Tenta obter permissão do DomainManager e enviar para workerJobQueue.
// Se não for possível, recoloca no heap com um novo NextAttemptAt.
func (s *Scheduler) trySendToWorkerOrRequeue(job TargetURLJob, pq *JobPriorityQueue) {
	// Adicionada verificação de descarte de domínio aqui também, como uma dupla checagem
	// ou caso a lógica de chamada mude. Se o job chegou aqui, ele já deveria ter passado
	// pela verificação no loop principal do jobFeederLoop.
	if s.domainManager.IsDomainDiscarded(job.BaseDomain) {
		s.logger.Warnf("[JobFeeder/trySend] Job %s for DISCARDED domain %s. Discarding instead of sending/re-queuing.", job.URLString, job.BaseDomain)
		s.handleDiscardedDomainJob(job) // Lida com a compensação de progresso e decremento
		return
	}

	can, waitTimeDM := s.domainManager.CanRequest(job.BaseDomain)
	now := time.Now()

	if can {
					if s.config.VerbosityLevel >= 2 { // -vv
			s.logger.Debugf("[JobFeeder] DomainManager allows job %s for %s. Attempting to send to workerJobQueue.", job.URLString, job.BaseDomain)
		}
		// Tentar enviar para o workerJobQueue, mas não bloquear indefinidamente.
		// Usar um select com s.ctx.Done() para permitir cancelamento.
		select {
		case s.workerJobQueue <- job:
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[JobFeeder] Job %s sent to workerJobQueue.", job.URLString)
			}
			return // Sucesso
		case <-s.ctx.Done():
			if s.config.VerbosityLevel >= 1 {
				s.logger.Infof("[JobFeeder] Scheduler context done while trying to send job %s to workerJobQueue. Decrementing active jobs.", job.URLString)
			}
			s.decrementActiveJobs() // Job não foi enviado, e não será reenfileirado aqui pois o contexto acabou
			return
		// Se workerJobQueue estiver cheia, este select bloquearia.
		// Para evitar bloqueio aqui e tornar o feeder mais responsivo a s.ctx.Done e novos jobs,
		// podemos usar um send não-bloqueante ou um send com timeout curto.
		// Se falhar, reenfileiramos no heap.
		// Exemplo com envio não-bloqueante:
		// default: 
		//  s.logger.Warnf("[JobFeeder] workerJobQueue full when trying to send job %s. Re-queuing to heap.", job.URLString)
		//  job.NextAttemptAt = now.Add(100 * time.Millisecond) // Pequeno delay para tentar novamente
		//  heap.Push(pq, &HeapItem{Job: job, NextAttemptAt: job.NextAttemptAt})
		//  return
		// A abordagem atual de bloqueio no send para workerJobQueue é aceitável se o s.ctx.Done() o interromper.
		}
		} else {
		// Se CanRequest retornar false, pode ser devido a standby normal OU porque o domínio foi descartado
		// (já que CanRequest agora checa bucket.discarded).
		// Se o domínio foi descartado, IsDomainDiscarded retornará true, e o waitTimeDM será enorme.
		if s.domainManager.IsDomainDiscarded(job.BaseDomain) {
			s.logger.Warnf("[JobFeeder/trySend] Domain %s for job %s is DISCARDED. Discarding job instead of re-queuing for long wait.", job.BaseDomain, job.URLString)
			s.handleDiscardedDomainJob(job)
			return
		}

		job.NextAttemptAt = now.Add(waitTimeDM)
		if s.config.VerbosityLevel >= 1 {
			s.logger.Infof("[JobFeeder] DomainManager denied job %s for %s. Re-queuing to heap for %s (NextAttemptAt: %s).",
				job.URLString, job.BaseDomain, waitTimeDM, job.NextAttemptAt.Format(time.RFC3339))
		}
		heap.Push(pq, &HeapItem{Job: job, NextAttemptAt: job.NextAttemptAt})
	}
}

// worker é a nova função que será chamada como goroutine para cada worker.
// Ele pegará jobs da workerJobQueue.
func (s *Scheduler) worker(workerID int) {
	defer s.wg.Done()
	if s.config.VerbosityLevel >= 2 {
		s.logger.Debugf("[Worker %03d] Started.", workerID)
	}

	for job := range s.workerJobQueue { 
		if s.isSchedulerStopping() { 
			s.logger.Infof("[Worker %03d] Scheduler context done. Job %s (type: %s, read from queue) will not be processed. Decrementing active jobs.", workerID, job.URLString, job.JobType)
			// If job was for phase 1, ensure its Wg is also handled if it was acquired but not processed.
			// However, decrementActiveJobs is the main concern here for overall completion.
			s.decrementActiveJobs() 
			// If it's a phase 1 job that was popped but not processed, its phase1Wg.Done() won't be called.
			// This could lead to a deadlock if all workers exit like this.
			// Solution: if job type is CacheabilityCheck, call s.phase1CompletionWg.Done() here if the job isn't processed.
			// This needs careful handling to avoid double Done() calls.
			// Simpler: Let jobFeeder handle not sending jobs if context is done.
			// If a job is ALREADY taken by a worker when context is done, the worker should attempt to finish it or fail fast.
			// The current s.isJobContextDone checks within process functions should handle this.
			// For now, this early exit in worker + decrement should be okay if jobs are short-lived.
			// A more robust solution might involve a per-job context passed to process functions.
			// The current jobCtx in process functions IS derived from s.ctx, so they will terminate.
			return // Exit worker if scheduler is stopping
	}

		if s.config.VerbosityLevel >= 2 { // -vv
			s.logger.Debugf("[Worker %03d] Received job %s (Type: %s, For: %s) from jobFeeder.", 
				workerID, job.URLString, job.JobType, job.BaseDomain)
		}

		switch job.JobType {
		case JobTypeCacheabilityCheck:
			s.processCacheabilityCheckJob(workerID, job)
		case JobTypeFullProbe:
			s.processURLJob(workerID, job) // This is the existing function for detailed probes
		default:
			s.logger.Errorf("[Worker %03d] Unknown job type '%s' for URL %s. Discarding job.", workerID, job.JobType, job.URLString)
			s.decrementActiveJobs() // Ensure counter is decremented for unknown job types
		}
	}

	if s.config.VerbosityLevel >= 2 {
		s.logger.Debugf("[Worker %03d] Exiting (workerJobQueue closed).", workerID)
	}
}

// processCacheabilityCheckJob performs two requests to a base URL to determine if it's cacheable.
func (s *Scheduler) processCacheabilityCheckJob(workerID int, initialJob TargetURLJob) {
	// Este job da Fase 1 será concluído (e s.phase1CompletionWg.Done() chamado)
	// após todas as tentativas internas ou sucesso.

	var job = initialJob // Copia para modificar retries localmente, embora não usemos job.Retries aqui
	var finalError error
	var isCacheable bool // Mantida para armazenar o resultado da verificação

	// O job da Fase 1 é finalizado aqui, então decrementamos o activeJobs e o wg da Fase 1.
	defer func() {
		s.phase1CompletionWg.Done() // Sinaliza que este job da Fase 1 está concluído.
		s.decrementActiveJobs()     // Decrementa o contador global de jobs do scheduler.
		if finalError != nil {
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Warnf("[Worker %03d] [CacheCheck] Job %s for %s FAILED (within defer after all retries). Error: %v. (Debug details)", workerID, job.JobType, job.URLString, finalError)
			} else if s.config.VerbosityLevel == 1 { // -v
				s.logger.Warnf("[Worker %03d] [CacheCheck] Job %s for %s FAILED (within defer after all retries). Error: %v", workerID, job.JobType, job.URLString, finalError)
			}
			// No log for verbosityLevel == 0 (normal mode) for final job failure in defer
		}
	}()

	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if s.isSchedulerStopping() { // Verifica o contexto principal do scheduler
			s.logger.Warnf("[Worker %03d] [CacheCheck] Scheduler stopping. Aborting job %s.", workerID, job.URLString)
			finalError = fmt.Errorf("scheduler stopping: %w", s.ctx.Err())
			return // Sai da função, o defer cuidará do Done/decrement
		}

		jobCtx, cancelJobCtx := context.WithCancel(s.ctx) // Contexto para esta tentativa

		if s.config.VerbosityLevel >= 1 {
			s.logger.Debugf("[Worker %03d] [CacheCheck] Processing URL: %s (Internal Attempt %d/%d, Original Scheduler Retries for job: %d)",
				workerID, job.URLString, attempt+1, s.maxRetries+1, initialJob.Retries)
		}

		// --- Probe 0 (First Baseline) ---
		if s.config.VerbosityLevel >= 2 {
			s.logger.Debugf("[Worker %03d] [CacheCheck] %s: Performing Probe 0...", workerID, job.URLString)
		}
		reqCtxProbe0, cancelReqCtxProbe0 := context.WithTimeout(jobCtx, s.config.RequestTimeout)
		probe0ReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxProbe0}
		probe0RespData := s.performRequestWithDomainManagement(job.BaseDomain, probe0ReqData)
		cancelReqCtxProbe0()

		if s.isJobContextDone(jobCtx) { // Check jobCtx specifically for this attempt
			s.logger.Warnf("[Worker %03d] [CacheCheck] %s aborted after Probe 0 (job context done: %v).", workerID, job.URLString, jobCtx.Err())
			finalError = fmt.Errorf("job context done after Probe 0: %w", jobCtx.Err())
			cancelJobCtx() // Ensure jobCtx is cancelled
			// Não retorna imediatamente, permite que o loop de retry decida
		}

		if finalError == nil && (probe0RespData.Error != nil || statusCodeFromResponse(probe0RespData.Response) == 429) {
			statusCode := statusCodeFromResponse(probe0RespData.Response)
			errMsg := "Probe 0 request failed"
			if probe0RespData.Error != nil {
				errMsg = probe0RespData.Error.Error()
				finalError = probe0RespData.Error
			} else {
				finalError = fmt.Errorf("probe 0 got status code %d", statusCode)
			}
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[Worker %03d] [CacheCheck] Probe 0 for %s failed (Status: %d, Err: %s). Attempt %d/%d. Detailed debug.", workerID, job.URLString, statusCode, errMsg, attempt+1, s.maxRetries+1)
			} else if s.config.VerbosityLevel == 1 { // -v
				s.logger.Infof("[Worker %03d] [CacheCheck] Probe 0 for %s failed (Status: %d, Err: %s). Attempt %d/%d. Will retry.", workerID, job.URLString, statusCode, errMsg, attempt+1, s.maxRetries+1)
			}
			// No log for verbosityLevel == 0 (normal mode) for individual probe failure
			// Continue to retry logic below
		} else if finalError == nil { // Probe 0 OK
			probe0Data := buildProbeData(job.URLString, probe0ReqData, probe0RespData)
			if probe0Data.Response == nil {
				finalError = fmt.Errorf("probe 0 response was nil for %s", job.URLString)
				s.logger.Errorf("[Worker %03d] [CacheCheck] CRITICAL: %v", workerID, finalError)
				// Continue to retry logic
			} else {
				// --- Probe 0.1 (Second Baseline for Cache Hit Confirmation) ---
				time.Sleep(250 * time.Millisecond) // Aumentado de 50ms para 250ms
				if s.isJobContextDone(jobCtx) {
					s.logger.Warnf("[Worker %03d] [CacheCheck] %s aborted before Probe 0.1 (job context done: %v).", workerID, job.URLString, jobCtx.Err())
					finalError = fmt.Errorf("job context done before Probe 0.1: %w", jobCtx.Err())
					// Continue to retry logic
				}

				if finalError == nil {
					if s.config.VerbosityLevel >= 2 {
						s.logger.Debugf("[Worker %03d] [CacheCheck] %s: Performing Probe 0.1...", workerID, job.URLString)
					}
					reqCtxProbe01, cancelReqCtxProbe01 := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probe01ReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxProbe01}
					probe01RespData := s.performRequestWithDomainManagement(job.BaseDomain, probe01ReqData)
					cancelReqCtxProbe01()

					if s.isJobContextDone(jobCtx) {
						s.logger.Warnf("[Worker %03d] [CacheCheck] %s aborted after Probe 0.1 (job context done: %v).", workerID, job.URLString, jobCtx.Err())
						finalError = fmt.Errorf("job context done after Probe 0.1: %w", jobCtx.Err())
						// Continue to retry logic
					}

					if finalError == nil && (probe01RespData.Error != nil || statusCodeFromResponse(probe01RespData.Response) == 429) {
						statusCode := statusCodeFromResponse(probe01RespData.Response)
						errMsg := "Probe 0.1 request failed"
						if probe01RespData.Error != nil {
							errMsg = probe01RespData.Error.Error()
							finalError = probe01RespData.Error
						} else {
							finalError = fmt.Errorf("probe 0.1 got status code %d", statusCode)
						}
						if s.config.VerbosityLevel >= 2 { // -vv
							s.logger.Debugf("[Worker %03d] [CacheCheck] Probe 0.1 for %s failed (Status: %d, Err: %s). Attempt %d/%d. Detailed debug.", workerID, job.URLString, statusCode, errMsg, attempt+1, s.maxRetries+1)
						} else if s.config.VerbosityLevel == 1 { // -v
							s.logger.Infof("[Worker %03d] [CacheCheck] Probe 0.1 for %s failed (Status: %d, Err: %s). Attempt %d/%d. Will retry.", workerID, job.URLString, statusCode, errMsg, attempt+1, s.maxRetries+1)
						}
						// No log for verbosityLevel == 0 (normal mode)
						// Continue to retry logic
					} else if finalError == nil { // Probe 0.1 OK
						probe01Data := buildProbeData(job.URLString, probe01ReqData, probe01RespData)
						if probe01Data.Response == nil {
							finalError = fmt.Errorf("probe 0.1 response was nil for %s", job.URLString)
							s.logger.Errorf("[Worker %03d] [CacheCheck] CRITICAL: %v", workerID, finalError)
							// Continue to retry logic
						} else {
							// --- Analyze for Cacheability ---
							isCacheable = s.isActuallyCacheableHelper(probe0Data, probe01Data)
							s.mu.Lock()
							s.confirmedCacheableBaseURLs[job.URLString] = isCacheable // Store result regardless
							s.mu.Unlock()

							// logLevelFn := s.logger.Infof // Removido pois não é mais necessário com Successf
							// if s.config.VerbosityLevel < 1 { // If not at least -v, use Debugf for non-cacheable
							// 	logLevelFn = s.logger.Debugf
							// }

							if isCacheable {
								// Log CACHEABLE usando o novo Successf (que aparece se log LevelInfo estiver ativo)
								s.logger.Successf("[Worker %03d] [CacheCheck] URL %s CACHEABLE.", workerID, job.URLString)
							} else {
								// Para URLs NÃO CACHEÁVEIS, manter o log apenas para níveis de verbosidade mais altos
								if s.config.VerbosityLevel >= 2 { // -vv (debug)
									s.logger.Debugf("[Worker %03d] [CacheCheck] URL %s determined to be NOT cacheable (Attempt %d).", workerID, job.URLString, attempt+1)
								} else if s.config.VerbosityLevel == 1 { // -v (info)
									s.logger.Infof("[Worker %03d] [CacheCheck] URL %s determined to be NOT cacheable (Attempt %d).", workerID, job.URLString, attempt+1)
								}
								// No log para verbosityLevel == 0 (normal) se NÃO for cacheável
							}
							// Se chegou aqui, a determinação foi feita (cacheável ou não)
							finalError = nil // Success, pois o processo de checagem em si foi concluído
							cancelJobCtx()
							return // Success for this job, defer will handle Done/decrement
						}
					}
				}
			}
		}
		cancelJobCtx() // Cancel context for this failed attempt

		// If finalError is set, it means this attempt failed.
		if finalError != nil {
			if attempt < s.maxRetries {
				backoffDuration := s.calculateBackoffForRetry(attempt + 1) // Backoff based on current attempt number
				if s.config.VerbosityLevel >= 2 { // -vv
					s.logger.Debugf("[Worker %03d] [CacheCheck] Attempt %d for %s failed. Retrying after %s. (Debug)", workerID, attempt+1, job.URLString, backoffDuration)
				} else if s.config.VerbosityLevel == 1 { // -v
					s.logger.Infof("[Worker %03d] [CacheCheck] Attempt %d for %s failed. Retrying after %s.", workerID, attempt+1, job.URLString, backoffDuration)
				}
				// No log for verbosityLevel == 0 (normal mode)
				select {
				case <-time.After(backoffDuration):
					finalError = nil // Reset error for next attempt
					continue       // Next iteration of the retry loop
				case <-s.ctx.Done(): // If the main scheduler context is done during backoff
					s.logger.Warnf("[Worker %03d] [CacheCheck] Scheduler stopped during backoff for %s. Error: %v", workerID, job.URLString, s.ctx.Err())
					finalError = fmt.Errorf("scheduler stopped during backoff: %w", s.ctx.Err())
					return // Exit function, defer will handle
				}
			} else {
				// All retries exhausted for this job
				if s.config.VerbosityLevel >= 2 { // -vv
					s.logger.Warnf("[Worker %03d] [CacheCheck] All %d retries failed for %s. Final error: %v. Job DISCARDED. (Debug details)", workerID, s.maxRetries+1, job.URLString, finalError)
				} else if s.config.VerbosityLevel == 1 { // -v
					s.logger.Warnf("[Worker %03d] [CacheCheck] All %d retries failed for %s. Final error: %v. Job DISCARDED.", workerID, s.maxRetries+1, job.URLString, finalError)
				}
				// No log for verbosityLevel == 0 (normal mode) for job discard
				// finalError is already set
				return // Exit function, defer will handle
			}
		}
	}
	// Should not be reached if logic is correct, loop should exit via return or continue.
	// However, if it's reached, finalError might reflect the last attempt's state.
}

// isActuallyCacheableHelper determines if a URL is effectively cacheable for poisoning tests.
func (s *Scheduler) isActuallyCacheableHelper(probe0 ProbeData, probe01 ProbeData) bool {
	// Basic check: Was the first response generally cacheable by its headers?
	if !utils.IsCacheable(probe0.Response) {
		if s.config.VerbosityLevel >= 2 {
			s.logger.Debugf("[CacheCheckHelper] Probe 0 for %s not cacheable by its own headers.", probe0.URL)
		}
		return false
	}

	// Did the second response indicate a cache hit according to headers?
	hitByHeaders := utils.IsCacheHit(probe01.Response)
	if !hitByHeaders {
		if s.config.VerbosityLevel >= 2 {
			s.logger.Debugf("[CacheCheckHelper] Probe 0.1 for %s did not indicate a cache HIT by headers (IsCacheHit returned false).", probe01.URL)
		}
		return false
	}

	// If headers indicate a HIT, further check ETag and Last-Modified consistency.
	etag0 := probe0.RespHeaders.Get("ETag")
	etag01 := probe01.RespHeaders.Get("ETag")
	if etag0 != "" && etag01 != "" && etag0 != etag01 {
		if s.config.VerbosityLevel >= 1 { // -v
			s.logger.Warnf("[CacheCheckHelper] URL %s indicated cache HIT by headers, but ETags differ. Probe0 ETag: '%s', Probe0.1 ETag: '%s'. Treating as NOT reliably cacheable.", probe0.URL, etag0, etag01)
		}
		return false
	}

	lastModified0 := probe0.RespHeaders.Get("Last-Modified")
	lastModified01 := probe01.RespHeaders.Get("Last-Modified")
	if lastModified0 != "" && lastModified01 != "" && lastModified0 != lastModified01 {
		if s.config.VerbosityLevel >= 1 { // -v
			s.logger.Warnf("[CacheCheckHelper] URL %s indicated cache HIT by headers, but Last-Modified dates differ. Probe0 Last-Mod: '%s', Probe0.1 Last-Mod: '%s'. Treating as NOT reliably cacheable.", probe0.URL, lastModified0, lastModified01)
		}
		return false
	}
	
	// Are the bodies similar enough? (Assuming a HIT should serve identical/very similar content)
	// This helps filter out cases where a 'HIT' might be indicated but content changes (e.g., anti-CSRF tokens in page)
	// For cache poisoning, we need the *poisoned* static content to be served.
	// Using a high similarity threshold.
	if !utils.BodiesAreSimilar(probe0.Body, probe01.Body, 0.98) { // 98% similarity
		if s.config.VerbosityLevel >= 1 { // -v
			s.logger.Warnf("[CacheCheckHelper] URL %s indicated cache HIT by headers and consistent ETag/Last-Modified (if present), but bodies differ significantly. Treating as not reliably cacheable for tests.", probe0.URL)
		}
		return false
	}
	
	// Could also check if key headers like Content-Type, Content-Length are consistent if needed.

	if s.config.VerbosityLevel >= 2 {
		s.logger.Debugf("[CacheCheckHelper] URL %s deemed cacheable: Probe0 cacheable headers, Probe0.1 HIT by headers, ETag/Last-Modified consistent (if present), bodies similar.", probe0.URL)
	}
	return true
}

// calculateEstimatedProbesForJob calcula o número estimado de probes para um TargetURLJob específico.
// Esta função é usada para compensar a barra de progresso se um job for abortado.
func calculateEstimatedProbesForJob(job TargetURLJob, cfg *config.Config, logger utils.Logger) int {
	if job.JobType != JobTypeFullProbe {
		// CacheabilityCheck jobs podem ser considerados como 1 ou 2 probes dependendo da definição,
		// mas a compensação da barra é mais crítica para FullProbe.
		// Para CacheabilityCheck, o decrementActiveJobs e o phase1CompletionWg.Done() já cuidam do progresso da Fase 1.
		return 0
	}

	estimatedProbes := 0
	numBasePayloads := len(cfg.BasePayloads)
	if numBasePayloads == 0 && cfg.DefaultPayloadPrefix != "" {
		numBasePayloads = 1
	}

	// Header probes
	if !cfg.DisableHeaderTests && len(cfg.HeadersToTest) > 0 {
		estimatedProbes += len(cfg.HeadersToTest) // Cada header testado resulta em uma chamada a AnalyzeProbes
	}

	// Original parameter probes
	// Só contamos se o fuzzing de parâmetros estiver habilitado (pois só assim OriginalParams são testados desta forma)
	// E se houver parâmetros originais.
	if cfg.EnableParamFuzzing && len(job.OriginalParams) > 0 && numBasePayloads > 0 {
		estimatedProbes += len(job.OriginalParams) * numBasePayloads
	}

	// Fuzzed parameter probes
	if cfg.EnableParamFuzzing && len(cfg.ParamsToFuzz) > 0 && numBasePayloads > 0 {
		estimatedProbes += len(cfg.ParamsToFuzz) * numBasePayloads
	}

	// Se, após todos os cálculos, estimatedProbes for 0 para um JobTypeFullProbe,
	// isso pode indicar uma configuração onde nenhum teste específico de probe seria executado
	// (ex: headers desabilitados, sem params originais, e fuzzing de params desabilitado ou sem wordlist/payloads).
	// A lógica de criação de jobs da Fase 2 deve, idealmente, não criar tais jobs.
	// Mas, como uma salvaguarda para a barra de progresso, se tal job existir e for "processado":
	if estimatedProbes == 0 && job.JobType == JobTypeFullProbe {
		// Logar isso pode ser útil para depuração de configuração.
		logger.Debugf("Calculated 0 probes for a FullProbe job: %s. This URL might not have any specific probe actions based on current config (e.g., no headers to test, no params for active fuzzing modes). Setting to 1 for progress bar.", job.URLString)
		return 1 // Considera-se que o "processamento" do job em si é uma unidade de trabalho.
	}

	return estimatedProbes
}

// processURLJob is where individual URL processing, baseline requests, and probe tests happen.
// Agora assume que CanRequest já foi chamado e foi bem-sucedido, e NextAttemptAt já foi verificado.
func (s *Scheduler) processURLJob(workerID int, job TargetURLJob) {
	s.logger.Debugf("[Worker %03d] processURLJob START for %s. Scheduler's cfg.VerbosityLevel: %d, len(cfg.HeadersToTest): %d, cfg.ProbeConcurrency: %d", 
		workerID, job.URLString, s.config.VerbosityLevel, len(s.config.HeadersToTest), s.config.ProbeConcurrency)

	jobCtx, cancelJob := context.WithCancel(s.ctx)
	defer cancelJob()

	// Variáveis para controle de falhas e aborto deste job específico
	jobProcessingFailures := &atomic.Int32{}
	jobAbortedByConsecutiveFailures := &atomic.Bool{}
	probesActuallyCompletedForThisJob := &atomic.Uint64{}
	estimatedProbesForThisJob := calculateEstimatedProbesForJob(job, s.config, s.logger)

	var probeSemaphore chan struct{}
	if s.config.ProbeConcurrency > 0 {
		probeSemaphore = make(chan struct{}, s.config.ProbeConcurrency)
				} else {
		s.logger.Warnf("[Worker %03d] ProbeConcurrency é <= 0 (%d) para job %s, usando fallback de 1. Isso não deveria acontecer.", workerID, s.config.ProbeConcurrency, job.URLString)
		probeSemaphore = make(chan struct{}, 1)
	}

	if s.config.VerbosityLevel >= 1 {
		s.logger.Debugf("[Worker %03d] Processing URL: %s (Attempt %d). Job context linked to scheduler context. Probe concurrency for this job: %d. Estimated probes for this job: %d.",
			workerID, job.URLString, job.Retries+1, s.config.ProbeConcurrency, estimatedProbesForThisJob)
	}

	s.logger.Debugf("[Worker %03d] Job %s: Performing baseline request...", workerID, job.URLString)
	baselineStartTime := time.Now()

	reqCtxBaseline, cancelReqBaseline := context.WithTimeout(jobCtx, s.config.RequestTimeout)
	baselineReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxBaseline}
	baselineRespData := s.performRequestWithDomainManagement(job.BaseDomain, baselineReqData)
	cancelReqBaseline()

	baselineDuration := time.Since(baselineStartTime)
	s.logger.Debugf("[Worker %03d] Job %s: Baseline request completed in %s. Status: %s, Error: %v",
		workerID, job.URLString, baselineDuration, getStatus(baselineRespData.Response), baselineRespData.Error)

	// Imediatamente após o baseline, verificar se o job foi cancelado externamente ou pelo baseline.
	if s.isJobContextDone(jobCtx) { // Verifica jobCtx, que pode ter sido cancelado por s.ctx ou cancelJob()
		s.logger.Warnf("[Worker %03d] Job for %s aborted (context done after baseline call, reason: %v).", workerID, job.URLString, jobCtx.Err())
		// Se abortado aqui, nenhuma probe foi feita. A compensação será `estimatedProbesForThisJob`.
		if estimatedProbesForThisJob > 0 && job.JobType == JobTypeFullProbe {
			s.logger.Debugf("[Worker %03d] Compensating %d estimated probes for aborted job %s (baseline phase).", workerID, estimatedProbesForThisJob, job.URLString)
			s.completedProbesInPhase.Add(uint64(estimatedProbesForThisJob))
			if s.progressBar != nil {
				s.progressBar.Update(int(s.completedProbesInPhase.Load()))
			}
		}
		s.handleJobOutcome(job, false, fmt.Errorf("job processing aborted after baseline: %w", jobCtx.Err()), 0)
		return
	}

	if baselineRespData.Error != nil || statusCodeFromResponse(baselineRespData.Response) == 429 {
		statusCode := statusCodeFromResponse(baselineRespData.Response)
		errMsg := "request failed"
		errToReport := baselineRespData.Error
		if errToReport == nil {
			errToReport = fmt.Errorf("baseline request resulted in status code %d", statusCode)
		}

		logMsg := fmt.Sprintf("[Worker %03d] Baseline for %s failed (Status: %d, Err: %s). ", workerID, job.URLString, statusCode, errMsg)
		if statusCode == 429 {
			logMsg += "Domain standby triggered by DM. "
		}
		if s.config.VerbosityLevel >= 1 {
			if statusCode == 429 { s.logger.Infof(logMsg) } else { s.logger.Warnf(logMsg) }
		}
		// Se o baseline falhar, compensar todas as probes estimadas se for um job da Fase 2
		if estimatedProbesForThisJob > 0 && job.JobType == JobTypeFullProbe {
			s.logger.Debugf("[Worker %03d] Compensating %d estimated probes for job %s due to baseline failure.", workerID, estimatedProbesForThisJob, job.URLString)
			s.completedProbesInPhase.Add(uint64(estimatedProbesForThisJob))
			if s.progressBar != nil {
				s.progressBar.Update(int(s.completedProbesInPhase.Load()))
			}
		}
		s.handleJobOutcome(job, false, errToReport, statusCode)
		return
	}

	baselineProbe := buildProbeData(job.URLString, baselineReqData, baselineRespData)
	if baselineProbe.Response == nil { 
		s.logger.Errorf("[Worker %03d] CRITICAL: Baseline Invalid (nil response) for %s. Discarding job.", workerID, job.URLString)
		if estimatedProbesForThisJob > 0 && job.JobType == JobTypeFullProbe {
			s.logger.Debugf("[Worker %03d] Compensating %d estimated probes for job %s due to nil baseline response.", workerID, estimatedProbesForThisJob, job.URLString)
			s.completedProbesInPhase.Add(uint64(estimatedProbesForThisJob))
			if s.progressBar != nil {
				s.progressBar.Update(int(s.completedProbesInPhase.Load()))
			}
		}
		s.handleJobOutcome(job, false, fmt.Errorf("baseline response was nil"), 0)
		return
	}
	if s.config.VerbosityLevel >= 2 { 
		s.logger.Debugf("[Worker %03d] Baseline for %s successful. Proceeding to probes.", workerID, job.URLString)
	}

	// --- Test Headers --- 
	if !s.config.DisableHeaderTests && len(s.config.HeadersToTest) > 0 {
		if s.config.VerbosityLevel >= 1 {
			s.logger.Debugf("[Worker %03d] Starting Header Tests for %s (%d headers, %d concurrent probes).", workerID, job.URLString, len(s.config.HeadersToTest), s.config.ProbeConcurrency)
		}
		headersToTest := s.config.HeadersToTest
		var headerWg sync.WaitGroup
		headerFindingsChan := make(chan *report.Finding, len(headersToTest))

		for _, headerName := range headersToTest {
			if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
				s.logger.Warnf("[Worker %03d] Job for %s aborted (context done or max failures reached) before launching all header tests. Header '%s' skipped.", workerID, job.URLString, headerName)
				break // Exit header test loop
			}
			headerWg.Add(1)
			probeSemaphore <- struct{}{}
			go func(hn string) {
				defer headerWg.Done()
				defer func() { <-probeSemaphore }()

				if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
					s.logger.Debugf("[Worker %03d] Header test %s for %s skipped due to job abortion/context done.", workerID, hn, job.URLString)
					return
				}

				injectedValue := utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix + "-header-" + hn)
				if s.config.VerbosityLevel >= 1 {
					s.logger.Debugf("[Worker %03d] Testing Header '%s' with value '%s' for %s", workerID, hn, injectedValue, job.URLString)
				}

				// Probe A
				if s.config.VerbosityLevel >= 1 {
					s.logger.Debugf("[Worker %03d] Header Test: %s - Probe A - URL: %s", workerID, hn, job.URLString)
				}
				reqCtxProbeA, cancelReqProbeA := context.WithTimeout(jobCtx, s.config.RequestTimeout)
				probeAReqHeaders := http.Header{hn: []string{injectedValue}}
				probeAReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", CustomHeaders: probeAReqHeaders, Ctx: reqCtxProbeA}
				probeARespData := s.performRequestWithDomainManagement(job.BaseDomain, probeAReqData)
				cancelReqProbeA()

				if s.config.VerbosityLevel >= 1 {
					s.logger.Debugf("[Worker %03d] Header Test: %s - Probe A Result - Status: %s, Error: %v", workerID, hn, getStatus(probeARespData.Response), probeARespData.Error)
				}

				if s.handleProbeNetworkFailure(workerID, job.URLString, "Header Probe A", hn, probeARespData, jobProcessingFailures, jobAbortedByConsecutiveFailures, jobCtx, cancelJob) {
					return // Network failure threshold reached or 429, job aborted
				}
				if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) { return } // Double check


				// Probe B
				if s.config.VerbosityLevel >= 1 {
					s.logger.Debugf("[Worker %03d] Header Test: %s - Probe B - URL: %s", workerID, hn, job.URLString)
				}
				reqCtxProbeB, cancelReqProbeB := context.WithTimeout(jobCtx, s.config.RequestTimeout)
				probeBReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxProbeB}
				probeBRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeBReqData)
				cancelReqProbeB()

				if s.config.VerbosityLevel >= 1 {
					s.logger.Debugf("[Worker %03d] Header Test: %s - Probe B Result - Status: %s, Error: %v", workerID, hn, getStatus(probeBRespData.Response), probeBRespData.Error)
				}

				if s.handleProbeNetworkFailure(workerID, job.URLString, "Header Probe B", hn, probeBRespData, jobProcessingFailures, jobAbortedByConsecutiveFailures, jobCtx, cancelJob) {
					return // Network failure threshold reached or 429, job aborted
				}
				if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) { return } // Double check


				probeAProbe := buildProbeData(job.URLString, probeAReqData, probeARespData)
				probeBProbe := buildProbeData(job.URLString, probeBReqData, probeBRespData)

				if probeAProbe.Response != nil && probeBProbe.Response != nil {
					// Check again before analysis, as network ops might have taken time
					if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
						s.logger.Debugf("[Worker %03d] Header Analysis for %s on %s skipped due to job abortion/context done.", workerID, hn, job.URLString)
						return
					}
					s.totalProbesExecutedGlobal.Add(1)
					probesActuallyCompletedForThisJob.Add(1)
					if job.JobType == JobTypeFullProbe && s.progressBar != nil {
						currentCompletedGlobalProbes := s.completedProbesInPhase.Add(1)
						s.progressBar.Update(int(currentCompletedGlobalProbes))
					}
					finding, errAnalyse := s.processor.AnalyzeProbes(job.URLString, "header", hn, injectedValue, baselineProbe, probeAProbe, probeBProbe)
					if errAnalyse != nil {
						s.logger.Errorf("[Worker %03d] Processor Error (Header: '%s') for URL %s: %v", workerID, hn, job.URLString, errAnalyse)
					}
					if finding != nil {
						headerFindingsChan <- finding
					}
				}
			}(headerName)
		}
		headerWg.Wait() // Wait for all header goroutines to finish
			close(headerFindingsChan)
		for finding := range headerFindingsChan {
					s.mu.Lock()
					s.findings = append(s.findings, finding)
					s.mu.Unlock()
			logMessage := fmt.Sprintf("Type: %s | URL: %s | Via: Header '%s' | Payload: '%s' | Details: %s",
				finding.Vulnerability, finding.URL, finding.InputName, finding.Payload, finding.Description)
			if finding.Status == report.StatusConfirmed {
				// ... (logging for confirmed)
				prefix := "🎯 CONFIRMED VULNERABILITY [Worker %03d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorGreen = " [32m"
					const colorReset = " [0m"
					formattedMessage = colorGreen + formattedMessage + colorReset
				}
				s.logger.Infof(formattedMessage)
			} else if finding.Status == report.StatusPotential {
				// ... (logging for potential)
				prefix := "⚠️ POTENTIALLY VULNERABLE [Worker %03d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorYellow = " [33m"
					const colorReset = " [0m"
					formattedMessage = colorYellow + formattedMessage + colorReset
				}
				s.logger.Warnf(formattedMessage)
			}
		}
	}

	// --- Test URL Parameters (Original) ---
	payloadsToTest := s.config.BasePayloads
	if len(payloadsToTest) == 0 && s.config.DefaultPayloadPrefix != "" {
		payloadsToTest = append(payloadsToTest, utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix+"-paramval"))
	}

	if s.config.EnableParamFuzzing && len(payloadsToTest) > 0 && len(job.OriginalParams) > 0 {
		if s.config.VerbosityLevel >= 1 {
			s.logger.Debugf("[Worker %03d] Starting Original Parameter Value Tests for %s (%d params, %d payloads per param, %d concurrent probes).",
				workerID, job.URLString, len(job.OriginalParams), len(payloadsToTest), s.config.ProbeConcurrency)
		}
		paramsToTestKeys := make([]string, 0, len(job.OriginalParams))
		for paramName := range job.OriginalParams {
			paramsToTestKeys = append(paramsToTestKeys, paramName)
		}
		var paramWg sync.WaitGroup
		paramFindingsChan := make(chan *report.Finding, len(paramsToTestKeys)*len(payloadsToTest))

		for _, paramName := range paramsToTestKeys {
			if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
				s.logger.Warnf("[Worker %03d] Job for %s aborted. Original param test '%s' skipped.", workerID, job.URLString, paramName)
				break
			}
			for _, paramPayload := range payloadsToTest {
				if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
					s.logger.Warnf("[Worker %03d] Job for %s aborted. Original param test '%s=%s' skipped.", workerID, job.URLString, paramName, paramPayload)
					break 
				}
				paramWg.Add(1)
					probeSemaphore <- struct{}{}
				go func(pn, pp string) {
					defer paramWg.Done()
						defer func() { <-probeSemaphore }()

						if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
							s.logger.Debugf("[Worker %03d] Original param test %s=%s for %s skipped (job aborted/ctx done).", workerID, pn, pp, job.URLString)
						return
					}

						if s.config.VerbosityLevel >= 1 {
							s.logger.Debugf("[Worker %03d] Testing Original Param '%s=%s' for %s", workerID, pn, pp, job.URLString)
					}
					probeAURL, errProbeAURL := modifyURLQueryParam(job.URLString, pn, pp)
				if errProbeAURL != nil {
							s.logger.Errorf("[Worker %03d] CRITICAL: Failed to construct Probe A URL for original param test ('%s=%s'): %v. Skipping.", workerID, pn, pp, errProbeAURL)
						return
					}

					// Probe A
						if s.config.VerbosityLevel >= 1 {
							s.logger.Debugf("[Worker %03d] Original Param Test: %s=%s - Probe A - URL: %s", workerID, pn, pp, probeAURL)
						}
					reqCtxParamProbeA, cancelReqParamProbeA := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probeAParamReqData := networking.ClientRequestData{URL: probeAURL, Method: "GET", Ctx: reqCtxParamProbeA}
					probeAParamRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeAParamReqData)
					cancelReqParamProbeA()

						if s.config.VerbosityLevel >= 1 {
							s.logger.Debugf("[Worker %03d] Original Param Test: %s=%s - Probe A Result - Status: %s, Error: %v", workerID, pn, pp, getStatus(probeAParamRespData.Response), probeAParamRespData.Error)
						}

						if s.handleProbeNetworkFailure(workerID, probeAURL, "Original Param Probe A", fmt.Sprintf("%s=%s", pn, pp), probeAParamRespData, jobProcessingFailures, jobAbortedByConsecutiveFailures, jobCtx, cancelJob) {
						return
					}
						if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) { return }

						// Probe B
						if s.config.VerbosityLevel >= 1 {
							s.logger.Debugf("[Worker %03d] Original Param Test: %s=%s - Probe B - URL: %s", workerID, pn, pp, job.URLString) // Using job.URLString for Probe B
						}
					reqCtxParamProbeB, cancelReqParamProbeB := context.WithTimeout(jobCtx, s.config.RequestTimeout)
							probeBParamReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxParamProbeB} // Original URL for Probe B
					probeBParamRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeBParamReqData)
					cancelReqParamProbeB()

						if s.config.VerbosityLevel >= 1 {
							s.logger.Debugf("[Worker %03d] Original Param Test: %s=%s - Probe B Result - Status: %s, Error: %v", workerID, pn, pp, getStatus(probeBParamRespData.Response), probeBParamRespData.Error)
						}

						if s.handleProbeNetworkFailure(workerID, job.URLString, "Original Param Probe B", fmt.Sprintf("%s=%s", pn, pp), probeBParamRespData, jobProcessingFailures, jobAbortedByConsecutiveFailures, jobCtx, cancelJob) {
						return
					}
						if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) { return }

						probeAParamProbe := buildProbeData(probeAURL, probeAParamReqData, probeAParamRespData)
				probeBParamProbe := buildProbeData(job.URLString, probeBParamReqData, probeBParamRespData)

					if probeAParamProbe.Response != nil && probeBParamProbe.Response != nil {
							if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
								s.logger.Debugf("[Worker %03d] Original Param Analysis for %s=%s on %s skipped (job aborted/ctx done).", workerID, pn, pp, job.URLString)
								return
							}
							s.totalProbesExecutedGlobal.Add(1)
							probesActuallyCompletedForThisJob.Add(1)
							if job.JobType == JobTypeFullProbe && s.progressBar != nil {
								currentCompletedGlobalProbes := s.completedProbesInPhase.Add(1)
								s.progressBar.Update(int(currentCompletedGlobalProbes))
							}
						finding, errAnalyseParam := s.processor.AnalyzeProbes(probeAURL, "param", pn, pp, baselineProbe, probeAParamProbe, probeBParamProbe)
						if errAnalyseParam != nil {
								s.logger.Errorf("[Worker %03d] Processor Error (Original Param '%s=%s') for URL %s: %v", workerID, pn, pp, probeAURL, errAnalyseParam)
						}
						if finding != nil {
								paramFindingsChan <- finding
						}
					}
					}(paramName, paramPayload)
			}
				if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) { // Check after inner loop too
					break
		}
		}
			paramWg.Wait()
			close(paramFindingsChan)
		for finding := range paramFindingsChan {
			// ... (logging for findings)
						s.mu.Lock()
						s.findings = append(s.findings, finding)
						s.mu.Unlock()
			logMessage := fmt.Sprintf("Type: %s | URL: %s | Via: Param '%s' | Payload: '%s' | Details: %s",
				finding.Vulnerability, finding.URL, finding.InputName, finding.Payload, finding.Description)
			if finding.Status == report.StatusConfirmed {
				prefix := "🎯 CONFIRMED VULNERABILITY [Worker %03d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorGreen = " [32m"
					const colorReset = " [0m"
					formattedMessage = colorGreen + formattedMessage + colorReset
				}
				s.logger.Infof(formattedMessage)
			} else if finding.Status == report.StatusPotential {
				prefix := "⚠️ POTENTIALLY VULNERABLE [Worker %03d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorYellow = " [33m"
					const colorReset = " [0m"
					formattedMessage = colorYellow + formattedMessage + colorReset
				}
				s.logger.Warnf(formattedMessage)
			}
		}
	}

	// --- Test NEW Parameters from Fuzzing Wordlist ---
	if s.config.EnableParamFuzzing && len(s.config.ParamsToFuzz) > 0 && len(payloadsToTest) > 0 {
		if s.config.VerbosityLevel >= 1 {
			s.logger.Debugf("[Worker %03d] Starting Fuzzed Parameter Tests for %s (%d fuzzed params, %d payloads per param, %d concurrent probes).",
				workerID, job.URLString, len(s.config.ParamsToFuzz), len(payloadsToTest), s.config.ProbeConcurrency)
		}
		var fuzzedParamWg sync.WaitGroup
		fuzzedParamFindingsChan := make(chan *report.Finding, len(s.config.ParamsToFuzz)*len(payloadsToTest))

		for _, paramNameToFuzz := range s.config.ParamsToFuzz {
			if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
				s.logger.Warnf("[Worker %03d] Job for %s aborted. Fuzzed param test '%s' skipped.", workerID, job.URLString, paramNameToFuzz)
				break
			}
			for _, paramPayloadValue := range payloadsToTest {
				if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
					s.logger.Warnf("[Worker %03d] Job for %s aborted. Fuzzed param test '%s=%s' skipped.", workerID, job.URLString, paramNameToFuzz, paramPayloadValue)
					break
				}
				fuzzedParamWg.Add(1)
				probeSemaphore <- struct{}{}
				go func(pnFuzz, ppVal string) {
					defer fuzzedParamWg.Done()
					defer func() { <-probeSemaphore }()

					if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
						s.logger.Debugf("[Worker %03d] Fuzzed param test %s=%s for %s skipped (job aborted/ctx done).", workerID, pnFuzz, ppVal, job.URLString)
		return
					}

		if s.config.VerbosityLevel >= 1 { 
						s.logger.Debugf("[Worker %03d] Testing Fuzzed Param '%s=%s' for %s", workerID, pnFuzz, ppVal, job.URLString)
					}
					probeAFuzzedURL, errProbeAFuzzURL := addQueryParamToURL(job.URLString, pnFuzz, ppVal)
					if errProbeAFuzzURL != nil {
						s.logger.Errorf("[Worker %03d] CRITICAL: Failed to construct Probe A URL for fuzzed param test ('%s=%s'): %v. Skipping.", workerID, pnFuzz, ppVal, errProbeAFuzzURL)
						return
					}

					// Probe A
					if s.config.VerbosityLevel >= 1 {
						s.logger.Debugf("[Worker %03d] Fuzzed Param Test: %s=%s - Probe A - URL: %s", workerID, pnFuzz, ppVal, probeAFuzzedURL)
					}
					reqCtxFuzzedProbeA, cancelReqFuzzedProbeA := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probeAFuzzedReqData := networking.ClientRequestData{URL: probeAFuzzedURL, Method: "GET", Ctx: reqCtxFuzzedProbeA}
					probeAFuzzedRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeAFuzzedReqData)
					cancelReqFuzzedProbeA()

					if s.config.VerbosityLevel >= 1 {
						s.logger.Debugf("[Worker %03d] Fuzzed Param Test: %s=%s - Probe A Result - Status: %s, Error: %v", workerID, pnFuzz, ppVal, getStatus(probeAFuzzedRespData.Response), probeAFuzzedRespData.Error)
					}

					if s.handleProbeNetworkFailure(workerID, probeAFuzzedURL, "Fuzzed Param Probe A", fmt.Sprintf("%s=%s", pnFuzz, ppVal), probeAFuzzedRespData, jobProcessingFailures, jobAbortedByConsecutiveFailures, jobCtx, cancelJob) {
						return
					}
					if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) { return }

					// Probe B
					if s.config.VerbosityLevel >= 1 {
						s.logger.Debugf("[Worker %03d] Fuzzed Param Test: %s=%s - Probe B - URL: %s", workerID, pnFuzz, ppVal, job.URLString) // Using job.URLString for Probe B
					}
					reqCtxFuzzedProbeB, cancelReqFuzzedProbeB := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probeBFuzzedReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxFuzzedProbeB} // Original URL for Probe B
					probeBFuzzedRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeBFuzzedReqData)
					cancelReqFuzzedProbeB()

					if s.config.VerbosityLevel >= 1 {
						s.logger.Debugf("[Worker %03d] Fuzzed Param Test: %s=%s - Probe B Result - Status: %s, Error: %v", workerID, pnFuzz, ppVal, getStatus(probeBFuzzedRespData.Response), probeBFuzzedRespData.Error)
					}

					if s.handleProbeNetworkFailure(workerID, job.URLString, "Fuzzed Param Probe B", fmt.Sprintf("%s=%s", pnFuzz, ppVal), probeBFuzzedRespData, jobProcessingFailures, jobAbortedByConsecutiveFailures, jobCtx, cancelJob) {
						return
					}
					if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) { return }

					probeAFuzzedProbe := buildProbeData(probeAFuzzedURL, probeAFuzzedReqData, probeAFuzzedRespData)
					probeBFuzzedProbe := buildProbeData(job.URLString, probeBFuzzedReqData, probeBFuzzedRespData)

					if probeAFuzzedProbe.Response != nil && probeBFuzzedProbe.Response != nil {
						if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) {
							s.logger.Debugf("[Worker %03d] Fuzzed Param Analysis for %s=%s on %s skipped (job aborted/ctx done).", workerID, pnFuzz, ppVal, job.URLString)
							return
						}
						s.totalProbesExecutedGlobal.Add(1)
						probesActuallyCompletedForThisJob.Add(1)
						if job.JobType == JobTypeFullProbe && s.progressBar != nil {
							currentCompletedGlobalProbes := s.completedProbesInPhase.Add(1)
							s.progressBar.Update(int(currentCompletedGlobalProbes))
						}
						finding, errAnalyseFuzzed := s.processor.AnalyzeProbes(probeAFuzzedURL, "fuzzed_param", pnFuzz, ppVal, baselineProbe, probeAFuzzedProbe, probeBFuzzedProbe)
						if errAnalyseFuzzed != nil {
							s.logger.Errorf("[Worker %03d] Processor Error (Fuzzed Param '%s=%s') for URL %s: %v", workerID, pnFuzz, ppVal, probeAFuzzedURL, errAnalyseFuzzed)
						}
						if finding != nil {
							fuzzedParamFindingsChan <- finding
						}
					}
				}(paramNameToFuzz, paramPayloadValue)
			}
			if jobAbortedByConsecutiveFailures.Load() || s.isJobContextDone(jobCtx) { // Check after inner loop too
				break
			}
		}
		fuzzedParamWg.Wait()
		close(fuzzedParamFindingsChan)
		for finding := range fuzzedParamFindingsChan {
			// ... (logging for findings)
			s.mu.Lock()
			s.findings = append(s.findings, finding)
			s.mu.Unlock()
			logMessage := fmt.Sprintf("Type: %s | URL: %s | Via: Fuzzed Param '%s' | Payload: '%s' | Details: %s",
				finding.Vulnerability, finding.URL, finding.InputName, finding.Payload, finding.Description)
			if finding.Status == report.StatusConfirmed {
				prefix := "🎯 CONFIRMED VULNERABILITY [Worker %03d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorGreen = " [32m"
					const colorReset = " [0m"
					formattedMessage = colorGreen + formattedMessage + colorReset
				}
				s.logger.Infof(formattedMessage)
			} else if finding.Status == report.StatusPotential {
				prefix := "⚠️ POTENTIALLY VULNERABLE [Worker %03d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorYellow = " [33m"
					const colorReset = " [0m"
					formattedMessage = colorYellow + formattedMessage + colorReset
				}
				s.logger.Warnf(formattedMessage)
			}
		}
	}

	// Finalizar job e compensar barra de progresso se necessário
	finalJobStatusError := jobCtx.Err() // Check if job context was cancelled (e.g., timeout, external stop)
	jobWasExplicitlyAbortedByFailures := jobAbortedByConsecutiveFailures.Load()

	if jobWasExplicitlyAbortedByFailures {
		if finalJobStatusError == nil { // If not already set by context cancellation
			finalJobStatusError = fmt.Errorf("job aborted after %d consecutive network failures", s.config.MaxRetries)
		}
		s.logger.Warnf("[Worker %03d] Job for %s explicitly aborted due to repeated network failures.", workerID, job.URLString)
	}

	if finalJobStatusError != nil || jobWasExplicitlyAbortedByFailures { // Job did not complete successfully
		// If a FullProbe job was aborted, the probes it didn't run should not count towards "completed" for the bar.
		// Probes that *did* run before abortion would have already incremented s.completedProbesInPhase.
		// Therefore, we remove the explicit compensation logic here that was causing the progress bar to exceed 100%.
		/*
			if job.JobType == JobTypeFullProbe { // Only compensate for Phase 2 FullProbe jobs
				probesDoneCount := probesActuallyCompletedForThisJob.Load()
				probesToCompensate := estimatedProbesForThisJob - int(probesDoneCount)

				if probesToCompensate > 0 {
					s.logger.Debugf("[Worker %03d] Job %s did not complete all probes (done: %d, estimated: %d). Compensating %d probes in progress bar.",
						workerID, job.URLString, probesDoneCount, estimatedProbesForThisJob, probesToCompensate)
					s.completedProbesInPhase.Add(uint64(probesToCompensate))
					if s.progressBar != nil {
						s.progressBar.Update(int(s.completedProbesInPhase.Load()))
					}
				}
			}
		*/
		s.handleJobOutcome(job, false, finalJobStatusError, 0) // statusCode 0 as it's a general job failure
	} else {
		// Job completou todas as suas operações sem ser abortado por falhas ou contexto.
		if s.config.VerbosityLevel >= 1 { 
			s.logger.Infof("[Worker %03d] Successfully COMPLETED all tests for job: %s (Total Scheduler Attempts: %d)", workerID, job.URLString, job.Retries+1)
		}
		s.handleJobOutcome(job, true, nil, 0)
	}
}

// handleProbeNetworkFailure é um helper para processURLJob para lidar com falhas de rede em probes.
// Retorna true se o job deve ser abortado (falha crítica ou 429), false caso contrário.
func (s *Scheduler) handleProbeNetworkFailure(
	workerID int,
	targetURL string, // URL da probe específica
	probeName string, // Ex: "Header Probe A", "Param Probe B for X=Y"
	inputIdentifier string, // Ex: "X-Forwarded-Host", "param_name"
	respData networking.ClientResponseData,
	jobFailures *atomic.Int32,
	jobAborted *atomic.Bool,
	jobCtx context.Context, // Added
	cancelJobFunc context.CancelFunc,
) bool {
	// If the job's main context is already done (e.g. scheduler shutting down, or *this job* was cancelled),
	// treat this probe as effectively cancelled.
	if s.isJobContextDone(jobCtx) { // Check jobCtx passed in
		// Log that the probe is terminating due to job context being done.
		// Don't increment jobFailures for this, as it's a consequence, not a new cause.
		if s.config.VerbosityLevel >= 2 { // -vv
			s.logger.Debugf("[Worker %03d] Probe %s for '%s' on %s is stopping because job context is done (Error: %v).",
				workerID, probeName, inputIdentifier, targetURL, jobCtx.Err())
		}
		// We return true to signal that this probe's execution path should terminate.
		// If jobAborted wasn't set yet but jobCtx is done due to an external cancel,
		// this path doesn't set jobAborted, which is correct.
		return true
	}

	statusCode := statusCodeFromResponse(respData.Response)

	// Check for genuine network/server errors OR 429
	isNetworkOrServerError := respData.Error != nil || (statusCode >= 500 && statusCode <= 599)
	isRateLimitError := statusCode == 429

	if isNetworkOrServerError {
		// If the error is context.Canceled, it might be because cancelJobFunc was called earlier.
		// If jobAborted is already true, then this context.Canceled is a symptom. Don't count it as a new failure.
		if errors.Is(respData.Error, context.Canceled) && jobAborted.Load() {
			if s.config.VerbosityLevel >= 2 { // -vv
				s.logger.Debugf("[Worker %03d] Probe %s for '%s' on %s received context.Canceled error; job already marked for abortion. Not counted as new failure.",
					workerID, probeName, inputIdentifier, targetURL)
			}
			return true // Signal to stop this probe's execution; job abortion is in progress.
		}

		// This is a new, genuine failure. We log it, but we no longer abort the entire job based on a threshold of probe failures.
		// The job-level retry/discard logic is handled by handleJobOutcome based on critical failures (e.g., baseline failure).
		jobFailures.Add(1) // We can still count them for potential future heuristics, but it won't trigger an abort here.
		errMsgLog := ""
		if respData.Error != nil {
			errMsgLog = respData.Error.Error()
		} else {
			errMsgLog = fmt.Sprintf("status code %d", statusCode)
		}

		if s.config.VerbosityLevel >= 1 {
			s.logger.Warnf("[Worker %03d] %s for '%s' on %s failed (Error: %s). This individual probe will not be analyzed, but the job will continue with other probes.",
				workerID, probeName, inputIdentifier, targetURL, errMsgLog)
		}

		// REMOVED: Logic to abort the job after s.config.MaxRetries consecutive probe failures.
		// if currentFailures > int32(s.config.MaxRetries) { ... }
		
		return true // Return true to indicate this specific probe's execution path should terminate, but without cancelling the parent job context.

	} else if isRateLimitError {
		// A 429 error occurred. Let the DomainManager handle it.
		// Stop this probe, but the job will continue/be re-queued.
		if s.config.VerbosityLevel >= 2 { // Only log this for -vv
			s.logger.Debugf("[Worker %03d] Probe %s for '%s' on %s got 429. This probe is stopped, and DomainManager will place the domain on standby. The job will be re-queued later.",
				workerID, probeName, inputIdentifier, targetURL)
		}
		
		// REMOVED: Logic that immediately aborted the job on a 429.

		return true // Signal to stop this probe's execution path.
	}

	// If not a network/server error and not a 429 (e.g., 200 OK, 404, 403 etc.)
	// Reset the consecutive failure counter for this job.
	jobFailures.Store(0)
	return false // No need to abort the job based on *this specific probe's outcome*. Probe was successful or failed in a way that doesn't count towards consecutive failures.
}

// statusCodeFromResponse safely gets the status code from an HTTP response.
func statusCodeFromResponse(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

// calculateBackoff calculates an exponential backoff duration with jitter.
// Esta função será usada por handleJobOutcome.
func (s *Scheduler) calculateBackoffForRetry(retries int) time.Duration {
	if retries <= 0 {
		return s.config.ConductorInitialRetryDelay // Usar config do scheduler, que pode ser ajustado
	}
	initialDelay := s.config.ConductorInitialRetryDelay
	if initialDelay <= 0 { initialDelay = time.Second * 1}

	backoffFactor := math.Pow(2, float64(retries-1))
	delay := time.Duration(float64(initialDelay) * backoffFactor)

	maxBackoff := s.config.ConductorMaxRetryBackoff
	if maxBackoff <= 0 { maxBackoff = time.Minute * 1}

	if delay > maxBackoff {
		delay = maxBackoff
	}

	jitter := time.Duration(rand.Int63n(int64(delay / 5))) 
	delay += jitter

	if delay < initialDelay && initialDelay > 0 {
		delay = initialDelay
	} else if delay <= 0 {
		delay = time.Second * 2
	}
	return delay
}

// getStatus is a helper to safely get the status string from a response.
func getStatus(resp *http.Response) string {
	if resp == nil {
		return "[No Response]"
	}
	return resp.Status
}

// constructURLWithParams reconstructs a URL string from a base URL and a map of query parameters.
func constructURLWithParams(baseURL string, params map[string]string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// modifyURLQueryParam takes a URL string, a parameter name, and a new value for that parameter.
func modifyURLQueryParam(originalURL string, paramNameToModify string, newParamValue string) (string, error) {
	u, err := url.Parse(originalURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse original URL '%s': %w", originalURL, err)
	}
	queryValues := u.Query()
	queryValues.Set(paramNameToModify, newParamValue)
	u.RawQuery = queryValues.Encode()
	return u.String(), nil
}

// isSchedulerStopping verifica se o contexto do job foi cancelado.
// O contexto principal do scheduler (s.ctx) será usado para o loop de workers.
func (s *Scheduler) isSchedulerStopping() bool { 
	select {
	case <-s.ctx.Done(): // Verifica o contexto principal do scheduler
		return true
	default:
		return false
	}
}

// Novo helper para verificar se o contexto específico do job foi cancelado
func (s *Scheduler) isJobContextDone(jobCtx context.Context) bool {
	select {
	case <-jobCtx.Done():
		return true
	default:
		return false
	}
}

// handleJobOutcome é a nova função no Scheduler para lidar com o resultado de um job.
func (s *Scheduler) handleJobOutcome(job TargetURLJob, wasSuccessful bool, failureError error, statusCode int) {
	if wasSuccessful {
		s.decrementActiveJobs()
		return
	}

	job.Retries++
	if s.config.VerbosityLevel >= 1 {
		s.logger.Warnf("[Scheduler] Job for %s failed (Attempt %d/%d). Error: %v, Status: %d. Processing retry/discard.", 
			job.URLString, job.Retries, s.maxRetries, failureError, statusCode)
	}

	if job.Retries < s.maxRetries {
		retryDelayDuration := s.calculateBackoffForRetry(job.Retries) 
		job.NextAttemptAt = time.Now().Add(retryDelayDuration)

		if s.config.VerbosityLevel >= 1 {
			s.logger.Infof("[Scheduler] Re-queuing job %s to pendingJobsQueue. Next attempt after %v (At: %s). Total attempts: %d.", 
				job.URLString, retryDelayDuration, job.NextAttemptAt.Format(time.RFC3339), job.Retries)
		}
		// Enviar para pendingJobsQueue em vez de workerJobQueue diretamente.
		select {
		case s.pendingJobsQueue <- job:
			// Job enviado para o feeder para gerenciamento.
		case <-s.ctx.Done():
			s.logger.Warnf("[Scheduler] Context done while trying to re-queue job %s to pendingJobsQueue. Job may be lost.", job.URLString)
		    s.decrementActiveJobs() // Se o contexto acabou, decrementar pois o job não será mais processado pelo feeder.
		default:
			// Se pendingJobsQueue estiver cheia (improvável com buffer grande, mas possível).
			s.logger.Errorf("[Scheduler] CRITICAL: pendingJobsQueue full when trying to re-queue job %s. Job DISCARDED. Retries %d.", job.URLString, job.Retries)
			s.decrementActiveJobs() // Job perdido, mas precisamos decrementar.
		}
	} else {
		if s.config.VerbosityLevel >= 1 {
			s.logger.Warnf("[Scheduler] Job for %s DISCARDED after %d retries. Error: %v, Status: %d.", 
				job.URLString, job.Retries, failureError, statusCode)
		}
		s.decrementActiveJobs()
	}
}

// decrementActiveJobs é um helper para decrementar activeJobs e checar conclusão.
func (s *Scheduler) decrementActiveJobs() {
	remainingJobs := atomic.AddInt32(&s.activeJobs, -1)
	if s.config.VerbosityLevel >= 1 {
		s.logger.Infof("[Scheduler] Decremented active jobs. Remaining: %d", remainingJobs)
	}

	// A barra da Fase 1 (contagem de URLs) é atualizada aqui.
	// A barra da Fase 2 (contagem de probes) é atualizada em processURLJob.
	if s.progressBar != nil && s.progressBar.GetPrefixForDebug() == "Phase 1/2 (Cache Checks): " { 
		s.completedJobsInPhaseForBar++
		s.progressBar.Update(s.completedJobsInPhaseForBar)
	}

	// NÃO FECHAR s.doneChan AQUI. A GOROUTINE DE MONITORAMENTO CUIDARÁ DISSO.
}

// handleDiscardedDomainJob lida com o descarte de um job devido ao seu domínio ter sido descartado.
func (s *Scheduler) handleDiscardedDomainJob(job TargetURLJob) {
	s.decrementActiveJobs() // Sempre decrementa o contador geral de jobs ativos.

	if job.JobType == JobTypeCacheabilityCheck { // Job da Fase 1
		s.phase1CompletionWg.Done() // Sinaliza que este job da Fase 1 está concluído.
		// Atualiza a barra de progresso da Fase 1
		if s.progressBar != nil && s.progressBar.GetPrefixForDebug() == "Phase 1/2 (Cache Checks): " {
			s.completedJobsInPhaseForBar++
			s.progressBar.Update(s.completedJobsInPhaseForBar)
		}
	} else if job.JobType == JobTypeFullProbe { // Job da Fase 2
		estimatedProbes := calculateEstimatedProbesForJob(job, s.config, s.logger)
		if estimatedProbes > 0 {
			s.logger.Debugf("[Scheduler] Compensating %d estimated probes for job %s of discarded domain %s.",
				estimatedProbes, job.URLString, job.BaseDomain)
			s.completedProbesInPhase.Add(uint64(estimatedProbes))
			if s.progressBar != nil && s.progressBar.GetPrefixForDebug() == "Phase 2 - Probing: " { // Garante que é a barra da Fase 2
				s.progressBar.Update(int(s.completedProbesInPhase.Load()))
			}
		}
	}
}

// Helper function to add a query parameter to a URL string without mutating original parts
func addQueryParamToURL(originalURL string, paramName string, paramValue string) (string, error) {
	u, err := url.Parse(originalURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse original URL '%s': %w", originalURL, err)
	}
	queryValues := u.Query() // Get a copy of existing query parameters
	queryValues.Add(paramName, paramValue) // Use Add to allow multiple params with same name if needed, though Set is fine for fuzzing one at a time
	u.RawQuery = queryValues.Encode()
	return u.String(), nil
}