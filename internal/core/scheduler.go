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

// TargetURLJob struct defines a unit of work for a worker.
// It contains the specific URL (with parameters) to be tested and its base domain.
type TargetURLJob struct {
	URLString      string            // The full URL with specific parameters for this job
	BaseDomain     string
	OriginalParams map[string]string // The params that formed this specific URLString
	Retries        int               // Number of times this job has been attempted
	NextAttemptAt  time.Time         // Time after which this job can be retried
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

	progressBar             *output.ProgressBar
	totalJobsForProgressBar int

	totalProbesExecuted atomic.Uint64 // NOVO: Contador para probes executadas

	ctx    context.Context
	cancel context.CancelFunc
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

	defer s.cancel()

	if len(uniqueBaseURLs) == 0 {
		s.logger.Warnf("Scheduler: No processable targets. Aborting scan.")
		return s.findings
	}

	var initialJobs []TargetURLJob
	for _, baseURL := range uniqueBaseURLs {
		parsedBase, _ := url.Parse(baseURL)
		baseDomain := parsedBase.Hostname()
		paramSets := groupedBaseURLsAndParams[baseURL]
		for _, paramSet := range paramSets {
			actualTargetURL, _ := constructURLWithParams(baseURL, paramSet)
			initialJobs = append(initialJobs, TargetURLJob{URLString: actualTargetURL, BaseDomain: baseDomain, OriginalParams: paramSet, NextAttemptAt: time.Now()})
		}
	}

	if len(initialJobs) == 0 {
		s.logger.Warnf("Scheduler: No testable URL jobs created. Aborting scan.")
		return s.findings
	}

	s.totalJobsForProgressBar = len(initialJobs)
	if s.totalJobsForProgressBar > 0 && !s.config.Silent {
		s.progressBar = output.NewProgressBar(s.totalJobsForProgressBar, 40)
		
		// Definir o prefixo da barra de progresso - AGORA APENAS COM INDICADOR DE SCANNING
		s.progressBar.SetPrefix("Scanning: ") // Será preenchido dinamicamente com Probes/s
		
		s.progressBar.Start()
		defer func() {
			s.progressBar.Finalize()
			output.SetActiveProgressBar(nil)
		}()
	}

	concurrencyLimit := s.config.Concurrency
	if concurrencyLimit <= 0 { concurrencyLimit = 1 }

	// Define um buffer grande para pendingJobsQueue, pois ela pode acumular jobs temporariamente.
	// O tamanho pode ser igual ao total de jobs + workers para segurança, ou um múltiplo.
	pendingQueueBufferSize := s.totalJobsForProgressBar + concurrencyLimit
	if pendingQueueBufferSize < 100 { // Garante um buffer mínimo razoável
	    pendingQueueBufferSize = 100
	}
	s.pendingJobsQueue = make(chan TargetURLJob, pendingQueueBufferSize) 
	s.workerJobQueue = make(chan TargetURLJob, concurrencyLimit) // workerJobQueue pode ter buffer menor, pois o feeder controla o fluxo
	atomic.StoreInt32(&s.activeJobs, int32(s.totalJobsForProgressBar))

	// Inicia o jobFeederLoop
	s.wg.Add(1)
	go s.jobFeederLoop()

	// Popula a PENDING job queue com os jobs iniciais.
	// O jobFeederLoop irá então pegá-los e enviá-los para workerJobQueue quando apropriado.
	for _, job := range initialJobs {
		s.pendingJobsQueue <- job 
	}

	if s.config.VerbosityLevel >= 2 { // -vv
		s.logger.Debugf("Scheduler: Starting %d workers. %d initial jobs sent to pendingJobsQueue. JobFeederLoop started.", concurrencyLimit, s.totalJobsForProgressBar)
	}

	// Goroutine para atualizar barra de progresso
	if s.progressBar != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ticker := time.NewTicker(500 * time.Millisecond) // Intervalo de atualização da barra
			defer ticker.Stop()

			var lastProbes uint64 = 0
			lastTickTime := time.Now() // Tempo da última atualização do PPS
			currentPPS := 0.0          // PPS atual

			// Formato base do prefixo - Simplificado
			const basePrefix = "Scanning" // Removido Concurrency e RateLimitString

			for {
				select {
				case <-ticker.C:
					now := time.Now()
					currentTotalProbes := s.totalProbesExecuted.Load()
					
					deltaProbes := currentTotalProbes - lastProbes
					deltaTime := now.Sub(lastTickTime).Seconds()

					if deltaTime > 0 {
						currentPPS = float64(deltaProbes) / deltaTime
					} else {
						currentPPS = 0 // Evita divisão por zero se o tick for muito rápido ou o tempo não avançar
					}

					lastProbes = currentTotalProbes
					lastTickTime = now

					currentActiveJobs := atomic.LoadInt32(&s.activeJobs)
					completedJobs := s.totalJobsForProgressBar - int(currentActiveJobs)
					
					// Atualiza o prefixo com o Probes/s calculado
					s.progressBar.SetPrefix(fmt.Sprintf("%s (Probes/s: %.1f): ", basePrefix, currentPPS))
					s.progressBar.Update(completedJobs)

				case <-s.doneChan: 
					currentActive := atomic.LoadInt32(&s.activeJobs)
					completedJobs := s.totalJobsForProgressBar - int(currentActive)
					// Última atualização do prefixo e da barra
					finalPPS := 0.0
					deltaTimeOnDone := time.Since(lastTickTime).Seconds() // Usa o lastTickTime original do loop
					if deltaTimeOnDone > 0 {
						finalPPS = float64(s.totalProbesExecuted.Load()-lastProbes) / deltaTimeOnDone
					}
					s.progressBar.SetPrefix(fmt.Sprintf("%s (Final Probes/s: %.1f): ", basePrefix, finalPPS))
					s.progressBar.Update(completedJobs) 
					return
				case <-s.ctx.Done(): 
				    s.logger.Debugf("[ProgressBar] Scheduler context done, stopping progress bar updater.")
				    return
				}
			}
		}()
	}

	for i := 0; i < concurrencyLimit; i++ {
		s.wg.Add(1)
		go s.worker(i) 
	}

	<-s.doneChan

	// 3. Fechar pendingJobsQueue PRIMEIRO.
	// Isso sinaliza ao jobFeederLoop que não haverá mais jobs novos ou reenfileirados.
	// O jobFeederLoop irá então processar o que resta em pendingJobsQueue, depois fechará
	// workerJobQueue e terminará sua própria goroutine (chamando s.wg.Done()).
	if s.config.VerbosityLevel >= 1 {
	    s.logger.Infof("[Scheduler] All jobs processed according to activeJobs. Closing pendingJobsQueue to signal jobFeeder to complete.")
	}
	close(s.pendingJobsQueue)

	// 4. Espera por todas as goroutines (workers, jobFeederLoop, progressBar updater) terminarem.
	//    - Workers terminarão quando workerJobQueue for fechada pelo jobFeederLoop.
	//    - JobFeederLoop terminará após pendingJobsQueue ser fechada e ele processar o restante.
	//    - ProgressBar updater terminará quando s.doneChan ou s.ctx.Done() ocorrer.
	if s.config.VerbosityLevel >= 1 {
	    s.logger.Infof("[Scheduler] Waiting for all goroutines to complete (Wait Group)...")
	}
	s.wg.Wait() 

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
			s.logger.Infof("[Worker %d] Scheduler context done. Job %s (read from queue) will not be processed. Decrementing active jobs.", workerID, job.URLString)
			s.decrementActiveJobs() // DECREMENTAR AQUI (Cenário C)
			// Não precisa `continue` ou `return` aqui se a intenção é apenas processar os jobs que já estão no buffer de workerJobQueue
			// e então sair quando o canal for fechado. 
			// No entanto, se o scheduler está parando, é melhor sair do loop do worker para liberar recursos mais rapidamente.
			// Se isSchedulerStopping() for true, o jobFeederLoop também deve parar e fechar workerJobQueue, o que terminará este loop.
			// A ação mais segura é retornar aqui para garantir que o worker pare se o contexto for cancelado.
		return
	}

		if s.config.VerbosityLevel >= 2 { // -vv
			s.logger.Debugf("[Worker %d] Received job %s (for %s) from jobFeeder. Proceeding to processURLJob.", 
				workerID, job.URLString, job.BaseDomain)
		}
		s.processURLJob(workerID, job)
	}

	if s.config.VerbosityLevel >= 2 {
		s.logger.Debugf("[Worker %d] Exiting (workerJobQueue closed).", workerID)
	}
}


// processURLJob is where individual URL processing, baseline requests, and probe tests happen.
// Agora assume que CanRequest já foi chamado e foi bem-sucedido, e NextAttemptAt já foi verificado.
func (s *Scheduler) processURLJob(workerID int, job TargetURLJob) {
	// DEBUG: Log inicial para verificar config dentro do scheduler para este job
	s.logger.Debugf("[Worker %d] processURLJob START for %s. Scheduler's cfg.VerbosityLevel: %d, len(cfg.HeadersToTest): %d, cfg.ProbeConcurrency: %d", 
		workerID, job.URLString, s.config.VerbosityLevel, len(s.config.HeadersToTest), s.config.ProbeConcurrency)

	jobCtx, cancelJob := context.WithCancel(s.ctx)
	defer cancelJob()

	// Semáforo para controlar a concorrência de todas as probes (headers e params) para esta URL.
	// Só criar se ProbeConcurrency > 0, o que é garantido pela validação da config.
	var probeSemaphore chan struct{}
	if s.config.ProbeConcurrency > 0 { // Embora validado, uma checagem extra não faz mal.
		probeSemaphore = make(chan struct{}, s.config.ProbeConcurrency)
				} else {
		// Fallback para concorrência mínima de 1 se por algum motivo chegou aqui com valor inválido.
		// Isso não deve acontecer devido à config.Validate().
		s.logger.Warnf("[Worker %d] ProbeConcurrency é <= 0 (%d) para job %s, usando fallback de 1. Isso não deveria acontecer.", workerID, s.config.ProbeConcurrency, job.URLString)
		probeSemaphore = make(chan struct{}, 1)
	}

	if s.config.VerbosityLevel >= 1 { // -v ou superior para estes logs
		s.logger.Debugf("[Worker %d] Processing URL: %s (Attempt %d). Job context linked to scheduler context. Probe concurrency for this job: %d",
			workerID, job.URLString, job.Retries+1, s.config.ProbeConcurrency)
	}

	s.logger.Debugf("[Worker %d] Job %s: Performing baseline request...", workerID, job.URLString)
	baselineStartTime := time.Now()

	// Timeout para a requisição individual
	reqCtxBaseline, cancelReqBaseline := context.WithTimeout(jobCtx, s.config.RequestTimeout)
	baselineReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxBaseline}
	baselineRespData := s.performRequestWithDomainManagement(job.BaseDomain, baselineReqData)
	cancelReqBaseline() // Cancelar contexto da requisição individual

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
	if len(s.config.HeadersToTest) > 0 {
		if s.config.VerbosityLevel >= 1 { // -v ou superior
			s.logger.Debugf("[Worker %d] Starting Header Tests for %s (%d headers, %d concurrent probes).", workerID, job.URLString, len(s.config.HeadersToTest), s.config.ProbeConcurrency)
		}

		headersToTest := s.config.HeadersToTest
		var headerWg sync.WaitGroup
		headerFindingsChan := make(chan *report.Finding, len(headersToTest)) // Buffer para não bloquear envio

		for _, headerName := range headersToTest {
			select {
			case <-jobCtx.Done():
				s.logger.Warnf("[Worker %d] Job for %s aborted (context done before launching all header tests, reason: %v).",
					workerID, job.URLString, jobCtx.Err())
				goto endHeaderTests // Pular para o final dos testes de header
			default:
			}

			headerWg.Add(1)
			probeSemaphore <- struct{}{} // Adquire slot no semáforo

			go func(hn string) {
				defer headerWg.Done()
				defer func() { <-probeSemaphore }() // Libera slot no semáforo

				if s.isJobContextDone(jobCtx) {
					s.logger.Debugf("[Worker %d] Job context done before starting header test %s for %s. Skipping.", workerID, hn, job.URLString)
					return
				}

				injectedValue := utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix + "-header-" + hn)
				if s.config.VerbosityLevel >= 1 { // -v ou superior
					s.logger.Debugf("[Worker %d] Testing Header '%s' with value '%s' for %s", workerID, hn, injectedValue, job.URLString)
				}

				// Probe A
				reqCtxProbeA, cancelReqProbeA := context.WithTimeout(jobCtx, s.config.RequestTimeout)
				probeAReqHeaders := http.Header{hn: []string{injectedValue}}
				probeAReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", CustomHeaders: probeAReqHeaders, Ctx: reqCtxProbeA}
				probeARespData := s.performRequestWithDomainManagement(job.BaseDomain, probeAReqData)
				cancelReqProbeA()

				if s.isJobContextDone(jobCtx) { return }
				if probeARespData.Error != nil || statusCodeFromResponse(probeARespData.Response) == 429 {
					// Não reenfileirar o job inteiro aqui, apenas registrar e pular este header específico.
					// A falha de um subset de probes não deve necessariamente matar o job inteiro, a menos que seja 429.
					if statusCodeFromResponse(probeARespData.Response) == 429 {
						s.logger.Warnf("[Worker %d] Probe A (Header: '%s') for %s got 429. Domain %s may go into standby. Aborting further probes for this job via cancelJob().", workerID, hn, job.URLString, job.BaseDomain)
						cancelJob() // Cancelar o contexto do job inteiro em caso de 429
						return
					}
					if s.config.VerbosityLevel >= 1 { // MOVER LOG PARA NÍVEL -v
					    s.logger.Warnf("[Worker %d] Probe A (Header: '%s') for %s failed (Status: %d, Error: %v). Skipping this header test.", workerID, hn, job.URLString, statusCodeFromResponse(probeARespData.Response), probeARespData.Error)
				    }
					return // Pular para o próximo header
				}
				probeAProbe := buildProbeData(job.URLString, probeAReqData, probeARespData)

				// Probe B
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
					if s.config.VerbosityLevel >= 1 { // MOVER LOG PARA NÍVEL -v
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
						headerFindingsChan <- finding // Envia o finding (Confirmed ou Potential)
					}
				}
			}(headerName)
		}

		// Goroutine para esperar todos os testes de header e fechar o canal de findings
		go func() {
			headerWg.Wait()
			close(headerFindingsChan)
		}()

		// Coletar findings dos testes de header e logar de acordo com o Status
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
					// Constantes de cor de internal/utils/logger.go
					const colorGreen = "\033[32m"
					const colorReset = "\033[0m"
					formattedMessage = colorGreen + formattedMessage + colorReset
				}
				s.logger.Infof(formattedMessage) // Logger.Infof já adiciona seu próprio prefixo [INFO] colorido
			} else if finding.Status == report.StatusPotential {
				prefix := "⚠️ POTENTIALLY VULNERABLE [Worker %d] "
				formattedMessage := fmt.Sprintf(prefix+logMessage, workerID)
				if !s.config.NoColor {
					// Constantes de cor de internal/utils/logger.go
					const colorYellow = "\033[33m"
					const colorReset = "\033[0m"
					formattedMessage = colorYellow + formattedMessage + colorReset
				}
				s.logger.Warnf(formattedMessage) // Logger.Warnf já adiciona seu próprio prefixo [WARN] colorido
			}
		}
	}
endHeaderTests: // Rótulo para goto em caso de cancelamento do jobCtx

	// --- Test URL Parameters ---
	payloadsToTest := s.config.BasePayloads
	if len(payloadsToTest) == 0 && s.config.DefaultPayloadPrefix != "" {
		payloadsToTest = append(payloadsToTest, utils.GenerateUniquePayload(s.config.DefaultPayloadPrefix+"-paramval"))
	}

	if len(payloadsToTest) > 0 && len(job.OriginalParams) > 0 {
		if s.config.VerbosityLevel >= 1 { // -v ou superior
			s.logger.Debugf("[Worker %d] Starting Parameter Tests for %s (%d params, %d payloads per param, %d concurrent probes).",
				workerID, job.URLString, len(job.OriginalParams), len(payloadsToTest), s.config.ProbeConcurrency)
		}

		paramsToTestKeys := make([]string, 0, len(job.OriginalParams))
		for paramName := range job.OriginalParams {
			paramsToTestKeys = append(paramsToTestKeys, paramName)
		}

		var paramWg sync.WaitGroup
		paramFindingsChan := make(chan *report.Finding, len(paramsToTestKeys)*len(payloadsToTest)) // Buffer para todos os possíveis findings

		for _, paramName := range paramsToTestKeys {
			for _, paramPayload := range payloadsToTest {
				select {
				case <-jobCtx.Done():
					s.logger.Warnf("[Worker %d] Job for %s aborted (context done before launching all param tests, reason: %v).",
						workerID, job.URLString, jobCtx.Err())
					goto endParamTests // Pular para o final dos testes de parâmetro
				default:
				}

				paramWg.Add(1)
				probeSemaphore <- struct{}{} // Adquire slot no semáforo

				go func(pn, pp string) {
					defer paramWg.Done()
					defer func() { <-probeSemaphore }() // Libera slot no semáforo

					if s.isJobContextDone(jobCtx) {
						s.logger.Debugf("[Worker %d] Job context done before starting param test %s=%s for %s. Skipping.", workerID, pn, pp, job.URLString)
						return
					}

					if s.config.VerbosityLevel >= 1 { // -v ou superior
						s.logger.Debugf("[Worker %d] Testing Param '%s=%s' for %s", workerID, pn, pp, job.URLString)
					}

					probeAURL, errProbeAURL := modifyURLQueryParam(job.URLString, pn, pp)
				if errProbeAURL != nil {
						s.logger.Errorf("[Worker %d] CRITICAL: Failed to construct Probe A URL for param test ('%s=%s'): %v. Skipping this param test.", workerID, pn, pp, errProbeAURL)
						return
					}

					// Probe A
					reqCtxParamProbeA, cancelReqParamProbeA := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probeAParamReqData := networking.ClientRequestData{URL: probeAURL, Method: "GET", Ctx: reqCtxParamProbeA}
					probeAParamRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeAParamReqData)
					cancelReqParamProbeA()

					if s.isJobContextDone(jobCtx) { return }
					if probeAParamRespData.Error != nil || statusCodeFromResponse(probeAParamRespData.Response) == 429 {
				if statusCodeFromResponse(probeAParamRespData.Response) == 429 {
							s.logger.Warnf("[Worker %d] Probe A (Param '%s=%s') for %s got 429. Domain %s may go into standby. Aborting further probes for this job via cancelJob().", workerID, pn, pp, probeAURL, job.BaseDomain)
							cancelJob() // Cancelar o contexto do job inteiro em caso de 429
							return
						}
						if s.config.VerbosityLevel >= 1 { // MOVER LOG PARA NÍVEL -v
						    s.logger.Warnf("[Worker %d] Probe A (Param '%s=%s') for %s failed (Status: %d, Error: %v). Skipping this param test.", workerID, pn, pp, probeAURL, statusCodeFromResponse(probeAParamRespData.Response), probeAParamRespData.Error)
					    }
						return
					}
					probeAParamProbe := buildProbeData(probeAURL, probeAParamReqData, probeAParamRespData)

					// Probe B (usa a URL original do job, não a probeAURL)
					reqCtxParamProbeB, cancelReqParamProbeB := context.WithTimeout(jobCtx, s.config.RequestTimeout)
					probeBParamReqData := networking.ClientRequestData{URL: job.URLString, Method: "GET", Ctx: reqCtxParamProbeB}
					probeBParamRespData := s.performRequestWithDomainManagement(job.BaseDomain, probeBParamReqData)
					cancelReqParamProbeB()

					if s.isJobContextDone(jobCtx) { return }
					if probeBParamRespData.Error != nil || statusCodeFromResponse(probeBParamRespData.Response) == 429 {
						if statusCodeFromResponse(probeBParamRespData.Response) == 429 {
							s.logger.Warnf("[Worker %d] Probe B (Param '%s=%s', original URL %s) for %s got 429. Domain %s may go into standby. Aborting further probes for this job via cancelJob().", workerID, pn, pp, job.URLString, job.BaseDomain)
							cancelJob()
							return
						}
						if s.config.VerbosityLevel >= 1 { // MOVER LOG PARA NÍVEL -v
						    s.logger.Warnf("[Worker %d] Probe B (Param '%s=%s', original URL %s) for %s failed (Status: %d, Error: %v). Skipping this param test.", workerID, pn, pp, job.URLString, job.BaseDomain, statusCodeFromResponse(probeBParamRespData.Response), probeBParamRespData.Error)
					    }
						return
					}
				probeBParamProbe := buildProbeData(job.URLString, probeBParamReqData, probeBParamRespData)

					if probeAParamProbe.Response != nil && probeBParamProbe.Response != nil {
						s.totalProbesExecuted.Add(1)
						// Para AnalyzeProbes com parâmetros, a URL da Probe A (modificada) é mais relevante que a job.URLString original
						// se a vulnerabilidade se manifesta através da URL modificada.
						finding, errAnalyseParam := s.processor.AnalyzeProbes(probeAURL, "param", pn, pp, baselineProbe, probeAParamProbe, probeBParamProbe)
						if errAnalyseParam != nil {
							s.logger.Errorf("[Worker %d] Processor Error (Param '%s=%s') for URL %s: %v", workerID, pn, pp, probeAURL, errAnalyseParam)
						}
						if finding != nil {
							paramFindingsChan <- finding // Envia o finding (Confirmed ou Potential)
						}
					}
				}(paramName, paramPayload) // Passar cópias para a goroutine
			}
		}

		// Goroutine para esperar todos os testes de parâmetro e fechar o canal de findings
		go func() {
			paramWg.Wait()
			close(paramFindingsChan)
		}()

		// Coletar findings dos testes de parâmetro e logar de acordo com o Status
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
endParamTests: // Rótulo para goto em caso de cancelamento do jobCtx

	select {
	case <-jobCtx.Done():
		s.logger.Warnf("[Worker %d] Job for %s aborted (context done just before completion, reason: %v).", workerID, job.URLString, jobCtx.Err())
		s.handleJobOutcome(job, false, fmt.Errorf("job processing timed out or was aborted before completion: %w", jobCtx.Err()), 0)
		return
		default:
		if s.config.VerbosityLevel >= 1 { 
			s.logger.Infof("[Worker %d] Successfully COMPLETED all tests for job: %s (Total Scheduler Attempts: %d)", workerID, job.URLString, job.Retries+1)
		}
		s.handleJobOutcome(job, true, nil, 0) // Nova função
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
		// Atualiza a barra de progresso aqui também
		completedJobs := s.totalJobsForProgressBar - int(remainingJobs)
		s.progressBar.Update(completedJobs)
	}

	if remainingJobs == 0 {
		s.logger.Infof("[Scheduler] All active jobs processed. Signaling completion.")
		select {
		case <-s.doneChan:
			// Already closed
		default:
			close(s.doneChan)
		}
	} else if remainingJobs < 0 {
		s.logger.Errorf("[Scheduler] CRITICAL: Active jobs count went negative (%d). This indicates a bug.", remainingJobs)
		select {
		case <-s.doneChan:
		default:
			close(s.doneChan) // Força o fechamento para evitar bloqueio infinito
		}
	}
}