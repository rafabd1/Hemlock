package input

import (
	"bufio"
	"os"
)

// Reader handles reading URLs from various sources like files or stdin.
type Reader struct {
	// TODO: Add fields if necessary, e.g., for logger.
}

// NewReader creates a new Reader.
func NewReader() *Reader {
	return &Reader{}
}

// ReadURLsFromFile reads URLs line by line from a specified file.
func (r *Reader) ReadURLsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	return urls, scanner.Err()
}

// ReadURLsFromStdin reads URLs line by line from standard input.
func (r *Reader) ReadURLsFromStdin() ([]string, error) {
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	return urls, scanner.Err()
} 