package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rafabd1/Hemlock/internal/utils" // Ajustado para o path do Hemlock
)

// activeProgressBar é uma referência global para a ProgressBar atualmente ativa.
// Isso permite que o logger (ou outros componentes) interaja com ela facilmente.
var (
	globalActiveProgressBar *ProgressBar
	progressBarMu           sync.Mutex
)

// SetActiveProgressBar define a barra de progresso global.
// Deve ser chamado pelo Scheduler ao iniciar a barra.
func SetActiveProgressBar(pb *ProgressBar) {
	progressBarMu.Lock()
	defer progressBarMu.Unlock()
	globalActiveProgressBar = pb
	if pb != nil && pb.IsTerminal() { // Registra callbacks se a barra for real e terminal
		utils.RegisterLogCallbacks(pb.MoveForLog, pb.ShowAfterLog)
	} else {
		utils.UnregisterLogCallbacks() // Garante que não haja callbacks se não houver barra ativa/terminal
	}
}

// GetActiveProgressBar retorna a barra de progresso global ativa.
// Usado pelo Logger para coordenar a saída.
func GetActiveProgressBar() *ProgressBar {
	progressBarMu.Lock()
	defer progressBarMu.Unlock()
	return globalActiveProgressBar
}

type ProgressBar struct {
    total            int
    current          int
    width            int
    refresh          time.Duration
    startTime        time.Time
    mu               sync.Mutex
    done             chan struct{}
    writer           io.Writer
    autoRefresh      bool
    isActive         bool
    spinner          int
    spinnerChars     []string
    prefix           string
    suffix           string
    isTerminal       bool // Determinado internamente, não precisa ser exportado no construtor
    renderPaused     bool
    outputControl    chan struct{}
}

func NewProgressBar(total int, width int) *ProgressBar {
    // utils.IsTerminal agora está em internal/utils/system.go
    isTTY := utils.IsTerminal(os.Stderr.Fd())
    
    return &ProgressBar{
        total:         total,
        current:       0,
        width:         width,
        refresh:       250 * time.Millisecond,
        // startTime será setado em Start()
        done:          make(chan struct{}),
        writer:        os.Stderr, // Logs para Stderr por padrão
        isActive:      false,
        spinnerChars:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
        prefix:        "",
        suffix:        "",
        isTerminal:    isTTY,
        renderPaused:  false,
        outputControl: make(chan struct{}, 1), // Buffer de 1 para evitar bloqueio em requestRender
    }
}

func (pb *ProgressBar) Start() {
    pb.mu.Lock()
    if pb.isActive {
        pb.mu.Unlock()
        return
    }
    
    pb.startTime = time.Now()
    pb.isActive = true
    pb.autoRefresh = pb.isTerminal
    pb.mu.Unlock()
    
    // Registra esta instância da barra como ativa globalmente E registra seus callbacks no logger
    SetActiveProgressBar(pb) 

    tc := GetTerminalController()
    tc.SetProgressBarActive(true)
    
    if pb.isTerminal { 
        go pb.outputManager()
        pb.requestRender()

        go func() {
            defer func() {
                if r := recover(); r != nil {
                    fmt.Fprintf(os.Stderr, "\nRecovered from panic in progress bar auto-refresh: %v\n", r)
                }
            }()
            
            ticker := time.NewTicker(pb.refresh)
            defer ticker.Stop()
            
            for {
                select {
                case <-pb.done:
                    return
                case <-ticker.C:
                    pb.mu.Lock()
                    isGloballyActive := pb.isActive 
                    pb.mu.Unlock()
                    
                    if isGloballyActive { 
                        pb.requestRender()
                    }
                }
            }
        }()
    }
}

func (pb *ProgressBar) outputManager() {
    for {
        select {
        case <-pb.done:
            return
        case <-pb.outputControl:
            pb.mu.Lock()
            shouldRender := pb.isActive && !pb.renderPaused && pb.isTerminal
            pb.mu.Unlock()
            
            if shouldRender {
                pb.actualRender()
            }
        case <-time.After(1 * time.Second): // Timeout para verificar se deve sair
            pb.mu.Lock()
            isActive := pb.isActive
            pb.mu.Unlock()
            
            if !isActive {
                return // Sai do outputManager se a barra não está mais ativa
            }
        }
    }
}

func (pb *ProgressBar) requestRender() {
    pb.mu.Lock()
    // Só envia para outputControl se estiver ativo, não pausado, e for terminal
    isActiveAndWantRender := pb.isActive && !pb.renderPaused && pb.isTerminal
    pb.mu.Unlock()
    
    if (isActiveAndWantRender) {
        select {
        case pb.outputControl <- struct{}{}: // Tenta enviar para o canal
        default: // Não bloqueia se o canal estiver cheio (outro render já solicitado)
        }
    }
}

func (pb *ProgressBar) Stop() {
    pb.mu.Lock()
    
    if !pb.isActive {
        pb.mu.Unlock()
        return
    }
    
    pb.isActive = false
    
    select {
    case <-pb.done:
    default:
        close(pb.done)
    }
    
    // Limpa a referência global e desregistra callbacks
    // Isso deve acontecer antes de liberar o mutex para evitar race conditions
    // se outra barra for iniciada rapidamente.
    // No entanto, SetActiveProgressBar(nil) deve ser chamado pelo Scheduler
    // ou por um wrapper de gerenciamento de barra de progresso.
    // Por agora, vamos desregistrar aqui para garantir limpeza.
    // Idealmente, o componente que "possui" a barra (Scheduler) a desregistra.
    // Se a barra está parando, ela não é mais a "ativa global".
    // Vamos assumir que o Scheduler chamará SetActiveProgressBar(nil) ao final do scan.
    // Por segurança, desregistramos os callbacks aqui.
    utils.UnregisterLogCallbacks()

    pb.mu.Unlock()
    
    tc := GetTerminalController()
    tc.SetProgressBarActive(false)
    
    time.Sleep(20 * time.Millisecond) 
    
    if pb.isTerminal {
        pb.clearBar() 
    }
    // Após parar, a barra não é mais a "ativa global".
    // SetActiveProgressBar(nil) deve ser chamado pelo gerenciador da barra.
    // Para garantir, se esta barra era a globalActiveProgressBar, nós a limpamos.
    progressBarMu.Lock()
    if globalActiveProgressBar == pb {
        globalActiveProgressBar = nil
        // utils.UnregisterLogCallbacks() // Já feito acima ou deve ser feito pelo SetActiveProgressBar(nil)
    }
    progressBarMu.Unlock()
}

// Finalize é uma forma mais completa de parar e limpar.
func (pb *ProgressBar) Finalize() {
    pb.Stop() // Chama Stop para toda a lógica de parada
    
    pb.mu.Lock()
    // Drena o outputControl para garantir que outputManager não fique preso
    if pb.outputControl != nil {
        select {
        case <-pb.outputControl:
        default:
        }
        // Não feche pb.outputControl se outputManager ainda puder estar lendo dele.
        // A lógica de saída do outputManager com base em pb.isActive e pb.done é mais segura.
    }
    // pb.outputControl = nil // Não é necessário nil se for usado corretamente
    pb.mu.Unlock()
    
    if pb.isTerminal {
        // Garante que a linha seja limpa e o cursor esteja no início
        // tc := GetTerminalController() // Já obtido em Stop()
        // tc.BeginOutput() // Garante exclusividade para a limpeza final
        // fmt.Fprint(pb.writer, "\033[2K\r") // Limpa e volta ao início
        // tc.EndOutput()
        // fmt.Fprintln(pb.writer) // Adiciona uma nova linha final para o próximo output não sobrescrever
    }
}

func (pb *ProgressBar) Update(current int) {
    pb.mu.Lock()
    pb.current = current
    // Se não for auto-refresh (não terminal), ou se estiver pausado, não solicita render aqui.
    // O auto-refresh (ticker) cuidará disso para terminais.
    // Para não-terminais, um render pode ser forçado se necessário, mas geralmente não é desejado.
    // A lógica original era: shouldRender := !pb.autoRefresh && !pb.renderPaused
    // Mas se não for terminal (autoRefresh = false), não queremos renderizar de qualquer forma.
    pb.mu.Unlock()
    
    // A atualização é apenas de dados; o render é solicitado pelo ticker ou explicitamente
    // se não for autoRefresh e não pausado.
    // Para simplificar, deixamos o ticker lidar com isso se for terminal.
    // Se não for terminal, a barra não será mostrada de qualquer maneira.
    if pb.isTerminal && pb.isActive && !pb.renderPaused { // Solicita um render se for terminal e ativo
        pb.requestRender()
    }
}

func (pb *ProgressBar) SetPrefix(prefix string) {
    pb.mu.Lock()
    pb.prefix = prefix
    pb.mu.Unlock()
}

func (pb *ProgressBar) SetSuffix(suffix string) {
    pb.mu.Lock()
    pb.suffix = suffix
    pb.mu.Unlock()
}

// SetTotalAndReset permite redefinir o total da barra de progresso,
// zerar a contagem atual e reiniciar o tempo para cálculo do ETA.
// Útil para barras de progresso multifásicas.
func (pb *ProgressBar) SetTotalAndReset(newTotal int) {
	pb.mu.Lock()
	pb.total = newTotal
	pb.current = 0
	pb.startTime = time.Now() // Reinicia o tempo para o cálculo do ETA da nova fase
	pb.mu.Unlock()
	// Força um render para mostrar a barra resetada se estiver ativa
	if pb.isTerminal && pb.isActive && !pb.renderPaused {
		pb.requestRender()
	}
}

// PauseRender impede temporariamente que a barra seja redesenhada.
func (pb *ProgressBar) PauseRender() {
    pb.mu.Lock()
    pb.renderPaused = true
    // Limpa a barra ao pausar para não deixar uma barra estática enquanto logs são impressos.
    // Isso será feito por MoveForLog.
    pb.mu.Unlock()
}

// ResumeRender permite que a barra seja redesenhada novamente.
func (pb *ProgressBar) ResumeRender() {
    pb.mu.Lock()
    wasRenderPaused := pb.renderPaused
    pb.renderPaused = false
    pb.mu.Unlock()
    
    if wasRenderPaused && pb.isTerminal { // Só renderiza se estava pausado e é terminal
        pb.requestRender()
    }
}

func (pb *ProgressBar) actualRender() {
    pb.mu.Lock()
    
    // Verificações redundantes, mas seguras
    if !pb.isActive || !pb.isTerminal || pb.renderPaused {
        pb.mu.Unlock()
        return
    }
    
    pb.spinner = (pb.spinner + 1) % len(pb.spinnerChars)
    
    currentTotal := pb.total
    currentProgress := pb.current
    if currentTotal == 0 { // Evita divisão por zero se total for 0 (ex: nenhum job)
        currentProgress = 0 // Garante 0% se total for 0
    }

    percent := 0.0
    if currentTotal > 0 {
        percent = float64(currentProgress) / float64(currentTotal) * 100
    }
    
    elapsed := time.Since(pb.startTime)
    
    var etaStr string
    if currentProgress > 0 && currentProgress < currentTotal {
        eta := time.Duration(float64(elapsed) * float64(currentTotal-currentProgress) / float64(currentProgress))
        etaStr = formatDuration(eta)
    } else if currentProgress >= currentTotal && currentTotal > 0 { // Concluído
        etaStr = "Done"
    } else { // currentProgress == 0 ou total == 0
        etaStr = "N/A"
    }
    
    completedWidth := 0
    if currentTotal > 0 {
        completedWidth = int(float64(pb.width) * float64(currentProgress) / float64(currentTotal))
    }
    if completedWidth > pb.width {
        completedWidth = pb.width
    }
    if completedWidth < 0 {
        completedWidth = 0
    }
    
    bar := strings.Repeat("█", completedWidth) + strings.Repeat("░", pb.width-completedWidth)
    
    status := fmt.Sprintf("%s%s [%s] %d/%d (%.2f%%) | Elapsed: %s | ETA: %s %s",
        pb.prefix,
        pb.spinnerChars[pb.spinner],
        bar,
        currentProgress, currentTotal,
        percent,
        formatDuration(elapsed),
        etaStr,
        pb.suffix,
    )
    
    // Não precisamos de lastPrintedChars se sempre usamos \033[2K\r
    // pb.lastPrintedChars = len(status) 
    pb.mu.Unlock()
    
    // DEBUG: Temporarily log to understand flickering
    // fmt.Fprintf(os.Stderr, "[DEBUG PB RENDER] Instance: %p, Prefix: '%s', Current: %d, Total: %d, IsActive: %t, Paused: %t, Spinner: %s\n", pb, pb.prefix, currentProgress, currentTotal, pb.isActive, pb.renderPaused, pb.spinnerChars[pb.spinner])

    tc := GetTerminalController()
    tc.BeginOutput() // Bloqueia outros logs
    fmt.Fprint(pb.writer, "\033[2K\r"+status) // Limpa linha, volta ao início, imprime status
    tc.EndOutput()   // Libera para outros logs
}

// MoveForLog é chamado pelo logger ANTES de imprimir um log.
// Ele pausa o render da barra e limpa a linha do terminal.
func (pb *ProgressBar) MoveForLog() {
    pb.mu.Lock()
    isActiveAndTerminal := pb.isActive && pb.isTerminal
    pb.renderPaused = true // Pausa o auto-refresh e renders explícitos
    pb.mu.Unlock()
    
    if isActiveAndTerminal {
        // Drena o outputControl para cancelar qualquer render pendente
        select {
        case <-pb.outputControl:
        default:
        }
        
        tc := GetTerminalController()
        tc.BeginOutput() // Garante que esta escrita seja atômica em relação a outros logs/barra
        fmt.Fprint(pb.writer, "\033[2K\r") // Limpa a linha
        tc.EndOutput()
        // time.Sleep(1 * time.Millisecond) // Pequena pausa, pode não ser necessária
    }
}

// ShowAfterLog é chamado pelo logger DEPOIS de imprimir um log.
// Ele retoma o render da barra e força um re-render imediato.
func (pb *ProgressBar) ShowAfterLog() {
    pb.mu.Lock()
    wasRenderPaused := pb.renderPaused // Verifica se estava realmente pausado por MoveForLog
    isActiveAndTerminal := pb.isActive && pb.isTerminal
    pb.renderPaused = false // Sempre reativa o render
    pb.mu.Unlock()
    
    if wasRenderPaused && isActiveAndTerminal {
        // time.Sleep(1 * time.Millisecond) // Pequena pausa
        pb.requestRender() // Solicita um render para redesenhar a barra imediatamente
    }
}

func (pb *ProgressBar) clearBar() {
    if pb.isTerminal {
        // Este clearBar é geralmente para quando a barra é parada permanentemente.
        tc := GetTerminalController()
        tc.BeginOutput()
        fmt.Fprint(pb.writer, "\033[2K\r")
        tc.EndOutput()
    }
}

func (pb *ProgressBar) IsTerminal() bool {
    pb.mu.Lock()
    defer pb.mu.Unlock()
    return pb.isTerminal
}

func formatDuration(d time.Duration) string {
    d = d.Round(time.Second)
    s := d.Seconds()
    if s < 0 { s = 0 } // Evita durações negativas na exibição

    if s < 60 {
        return fmt.Sprintf("%.0fs", s)
    }
    
    m := int(s/60) % 60
    h := int(s/3600)
    sRemaining := int(s) % 60

    if h < 1 {
        return fmt.Sprintf("%dm%02ds", m, sRemaining)
    }
    
    return fmt.Sprintf("%dh%02dm%02ds", h, m, sRemaining)
}

func (pb *ProgressBar) GetPrefixForDebug() string {
    pb.mu.Lock()
    defer pb.mu.Unlock()
    return pb.prefix
} 