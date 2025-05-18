package core

import (
	"container/heap"
	"time"
)

// pqItem é um item na fila de prioridade para TargetURLJob.
type pqItem struct {
	job          TargetURLJob // O job em si
	priorityTime time.Time    // O tempo usado para priorizar (NextAttemptAt)
	index        int          // O índice do item na heap.
}

// JobPriorityQueue implementa heap.Interface e guarda pqItems.
type JobPriorityQueue []*pqItem

func (pq JobPriorityQueue) Len() int { return len(pq) }

func (pq JobPriorityQueue) Less(i, j int) bool {
	return pq[i].priorityTime.Before(pq[j].priorityTime)
}

func (pq JobPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

// Push adiciona um item à heap.
func (pq *JobPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*pqItem)
	item.index = n
	*pq = append(*pq, item)
}

// Pop remove e retorna o item de menor prioridade (mais cedo NextAttemptAt).
func (pq *JobPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // Evita vazamento de memória
	item.index = -1 // Para segurança
	*pq = old[0 : n-1]
	return item
}

// NewJobPriorityQueue cria uma JobPriorityQueue.
func NewJobPriorityQueue(capacity int) *JobPriorityQueue {
	pq := make(JobPriorityQueue, 0, capacity)
	heap.Init(&pq) // Inicializa a heap
	return &pq
}

// AddJob adiciona um TargetURLJob à fila de prioridade.
func (pq *JobPriorityQueue) AddJob(job TargetURLJob) {
	heap.Push(pq, &pqItem{job: job, priorityTime: job.NextAttemptAt})
}

// GetNextJobIfReady retorna o próximo job se NextAttemptAt dele já passou ou é agora.
// Retorna nil, false se a fila estiver vazia ou nenhum job estiver pronto.
func (pq *JobPriorityQueue) GetNextJobIfReady() (*TargetURLJob, bool) {
	if pq.Len() == 0 {
		return nil, false
	}
	// Espia o item com menor NextAttemptAt (topo da min-heap)
	nextItem := (*pq)[0]
	if time.Now().After(nextItem.priorityTime) || time.Now().Equal(nextItem.priorityTime) {
		item := heap.Pop(pq).(*pqItem)
		return &item.job, true
	}
	return nil, false
}

// PeekNextTime retorna o NextAttemptAt do próximo job na fila sem removê-lo.
// Retorna time.Time{} e false se a fila estiver vazia.
func (pq *JobPriorityQueue) PeekNextTime() (time.Time, bool) {
	if pq.Len() == 0 {
		return time.Time{}, false
	}
	return (*pq)[0].priorityTime, true
} 