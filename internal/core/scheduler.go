package core

import (
	"container/heap"
	"context"
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

	totalProbesExecuted atomic.Uint64 // NOVO: Contador para probes executadas

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
	groupedBaseURLsAndParams, uniqueBaseURLs, _, _ := utils.PreprocessAndGroupURLs(s.config.Targets, s.logger)

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
					// DEBUG LOG: Mostrar os paramSets para uma URL base cacheável
					if s.config.VerbosityLevel >= 2 { // -vv
						s.logger.Debugf("[Orchestrator-Debug] For cacheable baseURL '%s', found %d paramSets.", baseURL, len(paramSets))
						for i, ps := range paramSets {
							s.logger.Debugf("[Orchestrator-Debug]   ParamSet %d: %v", i, ps)
						}
					}
					parsedBase, _ := url.Parse(baseURL) 
					baseDomain := parsedBase.Hostname()
					for _, paramSet := range paramSets {
						actualTargetURL, _ := constructURLWithParams(baseURL, paramSet)
						phase2Jobs = append(phase2Jobs, TargetURLJob{
							URLString:      actualTargetURL,
							BaseDomain:     baseDomain,
							OriginalParams: paramSet,
							JobType:        JobTypeFullProbe,
							NextAttemptAt:  time.Now(),
						})
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
		s.logger.Debugf("[Orchestrator-Debug] Before Phase 2 queueing: len(phase2Jobs)=%d, finalActiveJobsBeforePhase2Queue=%d", 
			len(phase2Jobs), finalActiveJobsBeforePhase2Queue)
		// Mostrar os paramSets se verbosidade -vv
		if s.config.VerbosityLevel >= 2 && numCacheable > 0 {
			for baseURLScanned := range s.confirmedCacheableBaseURLs { // CORRIGIDO: for baseURLScanned
				paramSetsForThisURL := groupedBaseURLsAndParams[baseURLScanned]
				s.logger.Debugf("[Orchestrator-Debug] For confirmed cacheable baseURL '%s', found %d paramSets in groupedBaseURLsAndParams.", baseURLScanned, len(paramSetsForThisURL))
				for i, ps := range paramSetsForThisURL {
					s.logger.Debugf("[Orchestrator-Debug]   ParamSet %d for %s: %v", i, baseURLScanned, ps)
				}
			}
		}

		s.logger.Infof("Scheduler: Starting Phase 2 - Full Probing with %d jobs.", len(phase2Jobs))
		
		// Configuração da barra da Fase 2
		if len(phase2Jobs) > 0 && !s.config.Silent {
			s.progressBar = output.NewProgressBar(len(phase2Jobs), 40) // s.progressBar é agora a da Fase 2
			s.progressBar.SetPrefix("Phase 2 - Probing: ")
			s.completedJobsInPhaseForBar = 0
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
					s.logger.Infof("[SchedulerMonitor] All active jobs processed (count is 0). Signaling completion.")
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

	s.logger.Infof("Scheduler: All scan tasks, workers, and job feeder completed.")
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
			heap.Push(waitingJobsHeap, &HeapItem{Job: job, NextAttemptAt: job.NextAttemptAt})
			scheduleNextWakeup()

		case <-timerChan:
			if s.config.VerbosityLevel >= 2 {
				s.logger.Debugf("[JobFeeder] Timer fired. Processing ready jobs from heap.")
			}
			for waitingJobsHeap.Len() > 0 && !(*waitingJobsHeap)[0].NextAttemptAt.After(time.Now()) {
				item := heap.Pop(waitingJobsHeap).(*HeapItem)
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
		s.logger.Debugf("[Worker %d] Started.", workerID)
	}

	for job := range s.workerJobQueue { 
		if s.isSchedulerStopping() { 
			s.logger.Infof("[Worker %d] Scheduler context done. Job %s (type: %s, read from queue) will not be processed. Decrementing active jobs.", workerID, job.URLString, job.JobType)
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
			s.logger.Debugf("[Worker %d] Received job %s (Type: %s, For: %s) from jobFeeder.", 
				workerID, job.URLString, job.JobType, job.BaseDomain)
		}

		switch job.JobType {
		case JobTypeCacheabilityCheck:
			s.processCacheabilityCheckJob(workerID, job)
		case JobTypeFullProbe:
			s.processURLJob(workerID, job) // This is the existing function for detailed probes
		default:
			s.logger.Errorf("[Worker %d] Unknown job type '%s' for URL %s. Discarding job.", workerID, job.JobType, job.URLString)
			s.decrementActiveJobs() // Ensure counter is decremented for unknown job types
		}
	}

	if s.config.VerbosityLevel >= 2 {
		s.logger.Debugf("[Worker %d] Exiting (workerJobQueue closed).", workerID)
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
				s.logger.Warnf("[Worker %d] [CacheCheck] Job %s for %s FAILED (within defer after all retries). Error: %v. (Debug details)", workerID, job.JobType, job.URLString, finalError)
			} else if s.config.VerbosityLevel == 1 { // -v
				s.logger.Warnf("[Worker %d] [CacheCheck] Job %s for %s FAILED (within defer after all retries). Error: %v", workerID, job.JobType, job.URLString, finalError)
			}
			// No log for verbosityLevel == 0 (normal mode) for final job failure in defer
		}
	}()

	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if s.isSchedulerStopping() { // Verifica o contexto principal do scheduler
			s.logger.Warnf("[Worker %d] [CacheCheck] Scheduler stopping. Aborting job %s.", workerID, job.URLString)
			finalError = fmt.Errorf("scheduler stopping: %w", s.ctx.Err())
			return // Sai da função, o defer cuidará do Done/decrement
		}

		jobCtx, cancelJobCtx := context.WithCancel(s.ctx) // Contexto para esta tentativa

		if s.config.VerbosityLevel >= 1 {
			s.logger.Debugf("[Worker %d] [CacheCheck] Processing URL: %s (Internal Attempt %d/%d, Original Scheduler Retries for job: %d)",
				workerID, job.URLString, attempt+1, s.maxRetries+1, initialJob.Retries)
		}

		// --- Probe 0 (First Baseline) ---
		if s.config.VerbosityLevel >= 2 {
			s.logger.Debugf("[Worker %d] [CacheCheck] %s: Performing Probe 0...", workerID, job.URLString)
		}
		reqCtxProbe0, cancelReqCtxProbe0 := context.WithTimeout(jobCtx, s.config.RequestTimeout)
		probe0ReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxProbe0}
		probe0RespData := s.performRequestWithDomainManagement(job.BaseDomain, probe0ReqData)
		cancelReqCtxProbe0()

		if s.isJobContextDone(jobCtx) { // Check jobCtx specifically for this attempt
			s.logger.Warnf("[Worker %d] [CacheCheck] %s aborted after Probe 0 (job context done: %v).", workerID, job.URLString, jobCtx.Err())
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
				s.logger.Debugf("[Worker %d] [CacheCheck] Probe 0 for %s failed (Status: %d, Err: %s). Attempt %d/%d. Detailed debug.", workerID, job.URLString, statusCode, errMsg, attempt+1, s.maxRetries+1)
			} else if s.config.VerbosityLevel == 1 { // -v
				s.logger.Infof("[Worker %d] [CacheCheck] Probe 0 for %s failed (Status: %d, Err: %s). Attempt %d/%d. Will retry.", workerID, job.URLString, statusCode, errMsg, attempt+1, s.maxRetries+1)
			}
			// No log for verbosityLevel == 0 (normal mode) for individual probe failure
			// Continue to retry logic below
		} else if finalError == nil { // Probe 0 OK
			probe0Data := buildProbeData(job.URLString, probe0ReqData, probe0RespData)
			if probe0Data.Response == nil {
				finalError = fmt.Errorf("probe 0 response was nil for %s", job.URLString)
				s.logger.Errorf("[Worker %d] [CacheCheck] CRITICAL: %v", finalError)
				// Continue to retry logic
			} else {
				// --- Probe 0.1 (Second Baseline for Cache Hit Confirmation) ---
				time.Sleep(50 * time.Millisecond)
				if s.isJobContextDone(jobCtx) {
					s.logger.Warnf("[Worker %d] [CacheCheck] %s aborted before Probe 0.1 (job context done: %v).", workerID, job.URLString, jobCtx.Err())
					finalError = fmt.Errorf("job context done before Probe 0.1: %w", jobCtx.Err())
					// Continue to retry logic
				}

				if finalError == nil {
					if s.config.VerbosityLevel >= 2 {
						s.logger.Debugf("[Worker %d] [CacheCheck] %s: Performing Probe 0.1...", workerID, job.URLString)
					}
					reqCtxProbe01, cancelReqCtxProbe01 := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probe01ReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxProbe01}
					probe01RespData := s.performRequestWithDomainManagement(job.BaseDomain, probe01ReqData)
					cancelReqCtxProbe01()

					if s.isJobContextDone(jobCtx) {
						s.logger.Warnf("[Worker %d] [CacheCheck] %s aborted after Probe 0.1 (job context done: %v).", workerID, job.URLString, jobCtx.Err())
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
							s.logger.Debugf("[Worker %d] [CacheCheck] Probe 0.1 for %s failed (Status: %d, Err: %s). Attempt %d/%d. Detailed debug.", workerID, job.URLString, statusCode, errMsg, attempt+1, s.maxRetries+1)
						} else if s.config.VerbosityLevel == 1 { // -v
							s.logger.Infof("[Worker %d] [CacheCheck] Probe 0.1 for %s failed (Status: %d, Err: %s). Attempt %d/%d. Will retry.", workerID, job.URLString, statusCode, errMsg, attempt+1, s.maxRetries+1)
						}
						// No log for verbosityLevel == 0 (normal mode)
						// Continue to retry logic
					} else if finalError == nil { // Probe 0.1 OK
						probe01Data := buildProbeData(job.URLString, probe01ReqData, probe01RespData)
						if probe01Data.Response == nil {
							finalError = fmt.Errorf("probe 0.1 response was nil for %s", job.URLString)
							s.logger.Errorf("[Worker %d] [CacheCheck] CRITICAL: %v", finalError)
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
								s.logger.Successf("[Worker %d] [CacheCheck] URL %s CACHEABLE.", workerID, job.URLString)
							} else {
								// Para URLs NÃO CACHEÁVEIS, manter o log apenas para níveis de verbosidade mais altos
								if s.config.VerbosityLevel >= 2 { // -vv (debug)
									s.logger.Debugf("[Worker %d] [CacheCheck] URL %s determined to be NOT cacheable (Attempt %d).", workerID, job.URLString, attempt+1)
								} else if s.config.VerbosityLevel == 1 { // -v (info)
									s.logger.Infof("[Worker %d] [CacheCheck] URL %s determined to be NOT cacheable (Attempt %d).", workerID, job.URLString, attempt+1)
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
					s.logger.Debugf("[Worker %d] [CacheCheck] Attempt %d for %s failed. Retrying after %s. (Debug)", workerID, attempt+1, job.URLString, backoffDuration)
				} else if s.config.VerbosityLevel == 1 { // -v
					s.logger.Infof("[Worker %d] [CacheCheck] Attempt %d for %s failed. Retrying after %s.", workerID, attempt+1, job.URLString, backoffDuration)
				}
				// No log for verbosityLevel == 0 (normal mode)
				select {
				case <-time.After(backoffDuration):
					finalError = nil // Reset error for next attempt
					continue       // Next iteration of the retry loop
				case <-s.ctx.Done(): // If the main scheduler context is done during backoff
					s.logger.Warnf("[Worker %d] [CacheCheck] Scheduler stopped during backoff for %s. Error: %v", workerID, job.URLString, s.ctx.Err())
					finalError = fmt.Errorf("scheduler stopped during backoff: %w", s.ctx.Err())
					return // Exit function, defer will handle
				}
			} else {
				// All retries exhausted for this job
				if s.config.VerbosityLevel >= 2 { // -vv
					s.logger.Warnf("[Worker %d] [CacheCheck] All %d retries failed for %s. Final error: %v. Job DISCARDED. (Debug details)", workerID, s.maxRetries+1, job.URLString, finalError)
				} else if s.config.VerbosityLevel == 1 { // -v
					s.logger.Warnf("[Worker %d] [CacheCheck] All %d retries failed for %s. Final error: %v. Job DISCARDED.", workerID, s.maxRetries+1, job.URLString, finalError)
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

	// Did the second response indicate a cache hit?
	hit := utils.IsCacheHit(probe01.Response)
	if !hit {
		if s.config.VerbosityLevel >= 2 {
			s.logger.Debugf("[CacheCheckHelper] Probe 0.1 for %s did not indicate a cache HIT.", probe01.URL)
		}
		// Optionally, even if no explicit HIT, if bodies are identical and Probe0 was cacheable,
		// some might consider it "implicitly cached" or behaving as such.
		// For now, let's be stricter and require a HIT signal.
		return false
	}
	
	// Are the bodies similar enough? (Assuming a HIT should serve identical/very similar content)
	// This helps filter out cases where a 'HIT' might be indicated but content changes (e.g., anti-CSRF tokens in page)
	// For cache poisoning, we need the *poisoned* static content to be served.
	// Using a high similarity threshold.
	if !utils.BodiesAreSimilar(probe0.Body, probe01.Body, 0.98) { // 98% similarity
		if s.config.VerbosityLevel >= 1 { // -v
			s.logger.Warnf("[CacheCheckHelper] URL %s indicated cache HIT on Probe 0.1, but bodies differ significantly from Probe 0. Treating as not reliably cacheable for tests.", probe0.URL)
		}
		return false
	}
	
	// Could also check if key headers like Content-Type, Content-Length are consistent if needed.

	if s.config.VerbosityLevel >= 2 {
		s.logger.Debugf("[CacheCheckHelper] URL %s deemed cacheable: Probe0 cacheable headers, Probe0.1 HIT, bodies similar.", probe0.URL)
	}
	return true
}

// processURLJob is where individual URL processing, baseline requests, and probe tests happen.
// Agora assume que CanRequest já foi chamado e foi bem-sucedido, e NextAttemptAt já foi verificado.
func (s *Scheduler) processURLJob(workerID int, job TargetURLJob) {
	s.logger.Debugf("[Worker %d] processURLJob START for %s. Scheduler's cfg.VerbosityLevel: %d, len(cfg.HeadersToTest): %d, cfg.ProbeConcurrency: %d",
		workerID, job.URLString, s.config.VerbosityLevel, len(s.config.HeadersToTest), s.config.ProbeConcurrency)

	jobCtx, cancelJob := context.WithCancel(s.ctx)
	defer cancelJob()

	var probeSemaphore chan struct{}
	if s.config.ProbeConcurrency > 0 {
		probeSemaphore = make(chan struct{}, s.config.ProbeConcurrency)
	} else {
		s.logger.Warnf("[Worker %d] ProbeConcurrency é <= 0 (%d) para job %s, usando fallback de 1. Isso não deveria acontecer.", workerID, s.config.ProbeConcurrency, job.URLString)
		probeSemaphore = make(chan struct{}, 1)
	}

	if s.config.VerbosityLevel >= 1 {
		s.logger.Debugf("[Worker %d] Processing URL: %s (Attempt %d). Job context linked to scheduler context. Probe concurrency for this job: %d",
			workerID, job.URLString, job.Retries+1, s.config.ProbeConcurrency)
	}

	s.logger.Debugf("[Worker %d] Job %s: Performing baseline request...", workerID, job.URLString)
	baselineStartTime := time.Now()

	reqCtxBaseline, cancelReqBaseline := context.WithTimeout(jobCtx, s.config.RequestTimeout)
	baselineReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxBaseline}
	baselineRespData := s.performRequestWithDomainManagement(job.BaseDomain, baselineReqData)
	cancelReqBaseline()

	baselineDuration := time.Since(baselineStartTime)
	s.logger.Debugf("[Worker %d] Job %s: Baseline request completed in %s. Status: %s, Error: %v",
		workerID, job.URLString, baselineDuration, getStatus(baselineRespData.Response), baselineRespData.Error)

	select {
	case <-jobCtx.Done():
		s.logger.Warnf("[Worker %d] Job for %s aborted (context done after baseline call, reason: %v).", workerID, job.URLString, jobCtx.Err())
		s.handleJobOutcome(job, false, fmt.Errorf("job processing timed out or was aborted after baseline: %w", jobCtx.Err()), 0)
		return
	default:
	}

	if baselineRespData.Error != nil || statusCodeFromResponse(baselineRespData.Response) == 429 {
		statusCode := statusCodeFromResponse(baselineRespData.Response)
		errMsg := "request failed"
		if baselineRespData.Error != nil {
			errMsg = baselineRespData.Error.Error()
		}
		logMsg := fmt.Sprintf("[Worker %d] Baseline for %s failed (Status: %d, Err: %s). ", workerID, job.URLString, statusCode, errMsg)
		if statusCode == 429 {
			logMsg += "Domain standby triggered by DM. "
		}
		if s.config.VerbosityLevel >= 1 {
			if statusCode == 429 { s.logger.Infof(logMsg) } else { s.logger.Warnf(logMsg) }
		}
		s.handleJobOutcome(job, false, baselineRespData.Error, statusCode)
		return
	}

	baselineProbe := buildProbeData(job.URLString, baselineReqData, baselineRespData)
	if baselineProbe.Response == nil {
		s.logger.Errorf("[Worker %d] CRITICAL: Baseline Invalid (nil response) for %s. Discarding job.", workerID, job.URLString)
		s.handleJobOutcome(job, false, fmt.Errorf("baseline response was nil"), 0)
		return
	}
	if s.config.VerbosityLevel >= 2 {
		s.logger.Debugf("[Worker %d] Baseline for %s successful. Proceeding to probes.", workerID, job.URLString)
	}

	// --- Test Headers ---
	if !s.config.DisableHeaderTests && len(s.config.HeadersToTest) > 0 {
		if s.config.VerbosityLevel >= 1 {
			s.logger.Debugf("[Worker %d] Starting Header Tests for %s (%d headers, %d concurrent probes).", workerID, job.URLString, len(s.config.HeadersToTest), s.config.ProbeConcurrency)
		}
		headersToTest := s.config.HeadersToTest
		var headerWg sync.WaitGroup
		headerFindingsChan := make(chan *report.Finding, len(headersToTest))

		for _, headerName := range headersToTest {
			if s.isJobContextDone(jobCtx) {
				s.logger.Warnf("[Worker %d] Job for %s aborted (context done before launching all header tests, reason: %v).", workerID, job.URLString, jobCtx.Err())
				break // Exit header test loop if job context is done
			}
			headerWg.Add(1)
			probeSemaphore <- struct{}{}
			go func(hn string) {
				defer headerWg.Done()
				defer func() { <-probeSemaphore }()
				if s.isJobContextDone(jobCtx) {
					s.logger.Debugf("[Worker %d] Job context done before starting header test %s for %s. Skipping.", workerID, hn, job.URLString)
					return
				}
				injectedValue := utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix + "-header-" + hn)
				if s.config.VerbosityLevel >= 1 {
					s.logger.Debugf("[Worker %d] Testing Header '%s' with value '%s' for %s", workerID, hn, injectedValue, job.URLString)
				}
				reqCtxProbeA, cancelReqProbeA := context.WithTimeout(jobCtx, s.config.RequestTimeout)
				probeAReqHeaders := http.Header{hn: []string{injectedValue}}
				probeAReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", CustomHeaders: probeAReqHeaders, Ctx: reqCtxProbeA}
				probeARespData := s.performRequestWithDomainManagement(job.BaseDomain, probeAReqData)
				cancelReqProbeA()
				if s.isJobContextDone(jobCtx) { return }
				if probeARespData.Error != nil || statusCodeFromResponse(probeARespData.Response) == 429 {
					if statusCodeFromResponse(probeARespData.Response) == 429 {
						s.logger.Warnf("[Worker %d] Probe A (Header: '%s') for %s got 429. Domain %s may go into standby. Aborting further probes for this job via cancelJob().", workerID, hn, job.URLString, job.BaseDomain)
						cancelJob() 
						return
					}
					if s.config.VerbosityLevel >= 1 {
						s.logger.Warnf("[Worker %d] Probe A (Header: '%s') for %s failed (Status: %d, Error: %v). Skipping this header test.", workerID, hn, job.URLString, statusCodeFromResponse(probeARespData.Response), probeARespData.Error)
					}
					return
				}
				probeAProbe := buildProbeData(job.URLString, probeAReqData, probeARespData)
				reqCtxProbeB, cancelReqProbeB := context.WithTimeout(jobCtx, s.config.RequestTimeout)
				probeBReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxProbeB}
				probeBRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeBReqData)
				cancelReqProbeB()
				if s.isJobContextDone(jobCtx) { return }
				if probeBRespData.Error != nil || statusCodeFromResponse(probeBRespData.Response) == 429 {
					if statusCodeFromResponse(probeBRespData.Response) == 429 {
						s.logger.Warnf("[Worker %d] Probe B (Header: '%s') for %s got 429. Domain %s may go into standby. Aborting further probes for this job via cancelJob().", workerID, hn, job.URLString, job.BaseDomain)
						cancelJob()
						return
					}
					if s.config.VerbosityLevel >= 1 {
						s.logger.Warnf("[Worker %d] Probe B (Header: '%s') for %s failed (Status: %d, Error: %v). Skipping this header test.", workerID, hn, job.URLString, statusCodeFromResponse(probeBRespData.Response), probeBRespData.Error)
					}
					return
				}
				probeBProbe := buildProbeData(job.URLString, probeBReqData, probeBRespData)
				if probeAProbe.Response != nil && probeBProbe.Response != nil {
					s.totalProbesExecuted.Add(1)
					finding, errAnalyse := s.processor.AnalyzeProbes(job.URLString, "header", hn, injectedValue, baselineProbe, probeAProbe, probeBProbe)
					if errAnalyse != nil {
						s.logger.Errorf("[Worker %d] Processor Error (Header: '%s') for URL %s: %v", workerID, hn, job.URLString, errAnalyse)
					}
					if finding != nil {
						headerFindingsChan <- finding
					}
				}
			}(headerName)
		}
		go func() {
			headerWg.Wait()
			close(headerFindingsChan)
		}()
		for finding := range headerFindingsChan {
			s.mu.Lock()
			s.findings = append(s.findings, finding)
			s.mu.Unlock()
			logMessage := fmt.Sprintf("Type: %s | URL: %s | Via: Header '%s' | Payload: '%s' | Details: %s",
				finding.Vulnerability, finding.URL, finding.InputName, finding.Payload, finding.Description)
			if finding.Status == report.StatusConfirmed {
				prefix := "🎯 CONFIRMED VULNERABILITY [Worker %d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorGreen = "\033[32m"
					const colorReset = "\033[0m"
					formattedMessage = colorGreen + formattedMessage + colorReset
				}
				s.logger.Infof(formattedMessage)
			} else if finding.Status == report.StatusPotential {
				prefix := "⚠️ POTENTIALLY VULNERABLE [Worker %d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorYellow = "\033[33m"
					const colorReset = "\033[0m"
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
			s.logger.Debugf("[Worker %d] Starting Original Parameter Value Tests for %s (%d params, %d payloads per param, %d concurrent probes).",
				workerID, job.URLString, len(job.OriginalParams), len(payloadsToTest), s.config.ProbeConcurrency)
		}
		paramsToTestKeys := make([]string, 0, len(job.OriginalParams))
		for paramName := range job.OriginalParams {
			paramsToTestKeys = append(paramsToTestKeys, paramName)
		}
		var paramWg sync.WaitGroup
		paramFindingsChan := make(chan *report.Finding, len(paramsToTestKeys)*len(payloadsToTest))

		for _, paramName := range paramsToTestKeys {
			if s.isJobContextDone(jobCtx) {
				s.logger.Warnf("[Worker %d] Job for %s aborted (context done before launching all original param tests, reason: %v).", workerID, job.URLString, jobCtx.Err())
				break // Exit original param test loop
			}
			for _, paramPayload := range payloadsToTest {
				if s.isJobContextDone(jobCtx) {
					s.logger.Warnf("[Worker %d] Job for %s aborted (context done during inner original param payload loop, reason: %v).", workerID, job.URLString, jobCtx.Err())
					break // Break from this inner loop; the outer loop will also check and break.
				}
				paramWg.Add(1)
				probeSemaphore <- struct{}{}
				go func(pn, pp string) {
					defer paramWg.Done()
					defer func() { <-probeSemaphore }()
					if s.isJobContextDone(jobCtx) {
						s.logger.Debugf("[Worker %d] Job context done before starting original param test %s=%s for %s. Skipping.", workerID, pn, pp, job.URLString)
						return
					}
					if s.config.VerbosityLevel >= 1 {
						s.logger.Debugf("[Worker %d] Testing Original Param '%s=%s' for %s", workerID, pn, pp, job.URLString)
					}
					probeAURL, errProbeAURL := modifyURLQueryParam(job.URLString, pn, pp)
					if errProbeAURL != nil {
						s.logger.Errorf("[Worker %d] CRITICAL: Failed to construct Probe A URL for original param test ('%s=%s'): %v. Skipping.", workerID, pn, pp, errProbeAURL)
						return
					}
					reqCtxParamProbeA, cancelReqParamProbeA := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probeAParamReqData := networking.ClientRequestData{URL: probeAURL, Method: "GET", Ctx: reqCtxParamProbeA}
					probeAParamRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeAParamReqData)
					cancelReqParamProbeA()
					if s.isJobContextDone(jobCtx) { return }
					if probeAParamRespData.Error != nil || statusCodeFromResponse(probeAParamRespData.Response) == 429 {
						if statusCodeFromResponse(probeAParamRespData.Response) == 429 {
							s.logger.Warnf("[Worker %d] Probe A (Original Param '%s=%s') for %s got 429. Domain %s may go into standby. Aborting job.", workerID, pn, pp, probeAURL, job.BaseDomain)
							cancelJob() 
							return
						}
						if s.config.VerbosityLevel >= 1 {
							s.logger.Warnf("[Worker %d] Probe A (Original Param '%s=%s') for %s failed (Status: %d, Error: %v). Skipping.", workerID, pn, pp, probeAURL, statusCodeFromResponse(probeAParamRespData.Response), probeAParamRespData.Error)
						}
						return
					}
					probeAParamProbe := buildProbeData(probeAURL, probeAParamReqData, probeAParamRespData)
					reqCtxParamProbeB, cancelReqParamProbeB := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probeBParamReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxParamProbeB}
					probeBParamRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeBParamReqData)
					cancelReqParamProbeB()
					if s.isJobContextDone(jobCtx) { return }
					if probeBParamRespData.Error != nil || statusCodeFromResponse(probeBParamRespData.Response) == 429 {
						if statusCodeFromResponse(probeBParamRespData.Response) == 429 {
							s.logger.Warnf("[Worker %d] Probe B (Original Param '%s=%s', original URL %s) got 429. Domain %s may go into standby. Aborting job.", workerID, pn, pp, job.URLString, job.BaseDomain)
							cancelJob()
							return
						}
						if s.config.VerbosityLevel >= 1 {
							s.logger.Warnf("[Worker %d] Probe B (Original Param '%s=%s', original URL %s) failed (Status: %d, Error: %v). Skipping.", workerID, pn, pp, job.URLString, statusCodeFromResponse(probeBParamRespData.Response), probeBParamRespData.Error)
						}
						return
					}
					probeBParamProbe := buildProbeData(job.URLString, probeBParamReqData, probeBParamRespData)
					if probeAParamProbe.Response != nil && probeBParamProbe.Response != nil {
						s.totalProbesExecuted.Add(1)
						finding, errAnalyseParam := s.processor.AnalyzeProbes(probeAURL, "param", pn, pp, baselineProbe, probeAParamProbe, probeBParamProbe)
						if errAnalyseParam != nil {
							s.logger.Errorf("[Worker %d] Processor Error (Original Param '%s=%s') for URL %s: %v", workerID, pn, pp, probeAURL, errAnalyseParam)
						}
						if finding != nil {
							paramFindingsChan <- finding
						}
					}
				}(paramName, paramPayload)
			}
		}
		go func() {
			paramWg.Wait()
			close(paramFindingsChan)
		}()
		for finding := range paramFindingsChan {
			s.mu.Lock()
			s.findings = append(s.findings, finding)
			s.mu.Unlock()
			logMessage := fmt.Sprintf("Type: %s | URL: %s | Via: Param '%s' | Payload: '%s' | Details: %s",
				finding.Vulnerability, finding.URL, finding.InputName, finding.Payload, finding.Description)
			if finding.Status == report.StatusConfirmed {
				prefix := "🎯 CONFIRMED VULNERABILITY [Worker %d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorGreen = "\033[32m"
					const colorReset = "\033[0m"
					formattedMessage = colorGreen + formattedMessage + colorReset
				}
				s.logger.Infof(formattedMessage)
			} else if finding.Status == report.StatusPotential {
				prefix := "⚠️ POTENTIALLY VULNERABLE [Worker %d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorYellow = "\033[33m"
					const colorReset = "\033[0m"
					formattedMessage = colorYellow + formattedMessage + colorReset
				}
				s.logger.Warnf(formattedMessage)
			}
		}
	}

	// --- Test NEW Parameters from Fuzzing Wordlist ---
	if s.config.EnableParamFuzzing && len(s.config.ParamsToFuzz) > 0 && len(payloadsToTest) > 0 {
		if s.config.VerbosityLevel >= 1 {
			s.logger.Debugf("[Worker %d] Starting Fuzzed Parameter Tests for %s (%d fuzzed params, %d payloads per param, %d concurrent probes).",
				workerID, job.URLString, len(s.config.ParamsToFuzz), len(payloadsToTest), s.config.ProbeConcurrency)
		}
		var fuzzedParamWg sync.WaitGroup
		fuzzedParamFindingsChan := make(chan *report.Finding, len(s.config.ParamsToFuzz)*len(payloadsToTest))

		for _, paramNameToFuzz := range s.config.ParamsToFuzz {
			if s.isJobContextDone(jobCtx) {
				s.logger.Warnf("[Worker %d] Job for %s aborted (context done before launching all fuzzed param tests, reason: %v).", workerID, job.URLString, jobCtx.Err())
				break // Exit fuzzed param test loop
			}
			for _, paramPayloadValue := range payloadsToTest {
				if s.isJobContextDone(jobCtx) {
					s.logger.Warnf("[Worker %d] Job for %s aborted (context done during inner fuzzed param payload loop, reason: %v).", workerID, job.URLString, jobCtx.Err())
					break // Break from this inner loop; the outer loop will also check and break.
				}
				fuzzedParamWg.Add(1)
				probeSemaphore <- struct{}{}
				go func(pnFuzz, ppVal string) {
					defer fuzzedParamWg.Done()
					defer func() { <-probeSemaphore }()
					if s.isJobContextDone(jobCtx) {
						s.logger.Debugf("[Worker %d] Job context done before starting fuzzed param test %s=%s for %s. Skipping.", workerID, pnFuzz, ppVal, job.URLString)
						return
					}
					if s.config.VerbosityLevel >= 1 {
						s.logger.Debugf("[Worker %d] Testing Fuzzed Param '%s=%s' for %s", workerID, pnFuzz, ppVal, job.URLString)
					}
					probeAFuzzedURL, errProbeAFuzzURL := addQueryParamToURL(job.URLString, pnFuzz, ppVal)
					if errProbeAFuzzURL != nil {
						s.logger.Errorf("[Worker %d] CRITICAL: Failed to construct Probe A URL for fuzzed param test ('%s=%s'): %v. Skipping.", workerID, pnFuzz, ppVal, errProbeAFuzzURL)
						return
					}
					reqCtxFuzzedProbeA, cancelReqFuzzedProbeA := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probeAFuzzedReqData := networking.ClientRequestData{URL: probeAFuzzedURL, Method: "GET", Ctx: reqCtxFuzzedProbeA}
					probeAFuzzedRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeAFuzzedReqData)
					cancelReqFuzzedProbeA()
					if s.isJobContextDone(jobCtx) { return }
					if probeAFuzzedRespData.Error != nil || statusCodeFromResponse(probeAFuzzedRespData.Response) == 429 {
						if statusCodeFromResponse(probeAFuzzedRespData.Response) == 429 {
							s.logger.Warnf("[Worker %d] Probe A (Fuzzed Param '%s=%s') for %s got 429. Domain %s may go into standby. Aborting job.", workerID, pnFuzz, ppVal, probeAFuzzedURL, job.BaseDomain)
							cancelJob()
							return
						}
						if s.config.VerbosityLevel >= 1 {
							s.logger.Warnf("[Worker %d] Probe A (Fuzzed Param '%s=%s') for %s failed (Status: %d, Error: %v). Skipping.", workerID, pnFuzz, ppVal, probeAFuzzedURL, statusCodeFromResponse(probeAFuzzedRespData.Response), probeAFuzzedRespData.Error)
						}
						return
					}
					probeAFuzzedProbe := buildProbeData(probeAFuzzedURL, probeAFuzzedReqData, probeAFuzzedRespData)
					reqCtxFuzzedProbeB, cancelReqFuzzedProbeB := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probeBFuzzedReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxFuzzedProbeB}
					probeBFuzzedRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeBFuzzedReqData)
					cancelReqFuzzedProbeB()
					if s.isJobContextDone(jobCtx) { return }
					if probeBFuzzedRespData.Error != nil || statusCodeFromResponse(probeBFuzzedRespData.Response) == 429 {
						if statusCodeFromResponse(probeBFuzzedRespData.Response) == 429 {
							s.logger.Warnf("[Worker %d] Probe B (Fuzzed Param '%s=%s', original URL %s) got 429. Domain %s may go into standby. Aborting job.", workerID, pnFuzz, ppVal, job.URLString, job.BaseDomain)
							cancelJob()
							return
						}
						if s.config.VerbosityLevel >= 1 {
							s.logger.Warnf("[Worker %d] Probe B (Fuzzed Param '%s=%s', original URL %s) failed (Status: %d, Error: %v). Skipping.", workerID, pnFuzz, ppVal, job.URLString, statusCodeFromResponse(probeBFuzzedRespData.Response), probeBFuzzedRespData.Error)
						}
						return
					}
					probeBFuzzedProbe := buildProbeData(job.URLString, probeBFuzzedReqData, probeBFuzzedRespData)
					if probeAFuzzedProbe.Response != nil && probeBFuzzedProbe.Response != nil {
						s.totalProbesExecuted.Add(1)
						finding, errAnalyseFuzzed := s.processor.AnalyzeProbes(probeAFuzzedURL, "fuzzed_param", pnFuzz, ppVal, baselineProbe, probeAFuzzedProbe, probeBFuzzedProbe)
						if errAnalyseFuzzed != nil {
							s.logger.Errorf("[Worker %d] Processor Error (Fuzzed Param '%s=%s') for URL %s: %v", workerID, pnFuzz, ppVal, probeAFuzzedURL, errAnalyseFuzzed)
						}
						if finding != nil {
							fuzzedParamFindingsChan <- finding
						}
					}
				}(paramNameToFuzz, paramPayloadValue)
			}
		}
		go func() {
			fuzzedParamWg.Wait()
			close(fuzzedParamFindingsChan)
		}()
		for finding := range fuzzedParamFindingsChan {
			s.mu.Lock()
			s.findings = append(s.findings, finding)
			s.mu.Unlock()
			logMessage := fmt.Sprintf("Type: %s | URL: %s | Via: Fuzzed Param '%s' | Payload: '%s' | Details: %s",
				finding.Vulnerability, finding.URL, finding.InputName, finding.Payload, finding.Description)
			if finding.Status == report.StatusConfirmed {
				prefix := "🎯 CONFIRMED VULNERABILITY [Worker %d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorGreen = "\033[32m"
					const colorReset = "\033[0m"
					formattedMessage = colorGreen + formattedMessage + colorReset
				}
				s.logger.Infof(formattedMessage)
			} else if finding.Status == report.StatusPotential {
				prefix := "⚠️ POTENTIALLY VULNERABLE [Worker %d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					const colorYellow = "\033[33m"
					const colorReset = "\033[0m"
					formattedMessage = colorYellow + formattedMessage + colorReset
				}
				s.logger.Warnf(formattedMessage)
			}
		}
	}

	select {
	case <-jobCtx.Done():
		s.logger.Warnf("[Worker %d] Job for %s aborted (context done just before completion, reason: %v).", workerID, job.URLString, jobCtx.Err())
		s.handleJobOutcome(job, false, fmt.Errorf("job processing timed out or was aborted before completion: %w", jobCtx.Err()), 0)
		return
	default:
		if s.config.VerbosityLevel >= 1 {
			s.logger.Infof("[Worker %d] Successfully COMPLETED all tests for job: %s (Total Scheduler Attempts: %d)", workerID, job.URLString, job.Retries+1)
		}
		s.handleJobOutcome(job, true, nil, 0)
	}
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

	if s.progressBar != nil {
		s.completedJobsInPhaseForBar++
		s.progressBar.Update(s.completedJobsInPhaseForBar)
	}

	// NÃO FECHAR s.doneChan AQUI. A GOROUTINE ORQUESTRADORA CUIDARÁ DISSO.
	// if remainingJobs == 0 {
	// 	s.logger.Infof("[Scheduler] All active jobs processed. Signaling completion.")
	// 	s.closeDoneChanOnce.Do(func() {
	// 		close(s.doneChan)
	// 	})
	// } else if remainingJobs < 0 {
	// 	s.logger.Errorf("[Scheduler] CRITICAL: Active jobs count went negative (%d). This indicates a bug.", remainingJobs)
	// 	s.closeDoneChanOnce.Do(func() {
	// 		close(s.doneChan) // Força o fechamento para evitar bloqueio infinito
	// 	})
	// }
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