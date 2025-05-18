package utils

import (
	"fmt"
	"os"
	"path/filepath"
	// Para uma implementação real e portável de IsTerminal,
	// considere usar uma biblioteca como "github.com/mattn/go-isatty".
	// Exemplo:
	// import "github.com/mattn/go-isatty"
)

// IsTerminal checks if the given file descriptor is a terminal.
// ATENÇÃO: Esta é uma implementação placeholder para desenvolvimento.
// Em um sistema Unix-like, você poderia usar syscalls ou go-isatty.
// Em Windows, go-isatty é a melhor abordagem.
// Para este exemplo, vamos assumir que é sempre um terminal se não estiver no modo 'noColor' ou 'silent',
// o que é uma heurística muito simples e pode precisar de refinamento.
// A ProgressBar fornecida já tem sua própria lógica isTerminal baseada em os.Stderr.Fd().
func IsTerminal(fd uintptr) bool {
	// Implementação placeholder:
	// Se precisar de uma verificação mais robusta aqui que não dependa da ProgressBar,
	// use go-isatty:
	// return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
	
	// Por enquanto, vamos deixar a lógica principal de detecção de terminal
	// para a própria ProgressBar, que já usa utils.IsTerminal (que vamos renomear/mover).
	// Esta função aqui pode não ser diretamente usada se a ProgressBar já tem sua chamada.
	// O código da ProgressBar que você forneceu já chama utils.IsTerminal(os.Stderr.Fd()).
	// Vamos garantir que essa função exista e funcione.
	// Para simplificar, vou criar esta como a real e a ProgressBar vai usá-la.
	
	// Tentativa de implementação básica para Unix-like (pode não compilar/funcionar no Windows sem 'unix')
	// e será comentada para garantir que o código seja executável sem dependências complexas agora.
	/*
	   package main

	   import (
	   	"golang.org/x/sys/unix"
	   	"os"
	   )

	   func main() {
	   	if _, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS); err == nil {
	   		println("stdout is a terminal")
	   	}
	   }
	*/

	// Simplesmente retornando true por enquanto para que a barra tente operar.
	// A lógica `isTTY` dentro da ProgressBar fará a verificação real.
	// Este arquivo system.go pode ser usado para outras funcs do sistema no futuro.
	fileInfo, _ := os.Stdout.Stat()
    return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// EnsureFilepathExists cria o diretório para um dado path de arquivo se ele não existir.
// Retirado de config.go para evitar ciclos de importação se utils precisar dele.
func EnsureFilepathExists(filePath string) error {
	dir := filepath.Dir(filePath)
	if dir == "." || dir == "" { // Se não há diretório (arquivo na raiz) ou erro, não faz nada
		return nil
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0750); err != nil { // Permissões rwxr-x---
			// Adicionar log aqui seria bom, mas utils não deve importar logger para evitar ciclos.
			// O chamador pode logar.
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
} 