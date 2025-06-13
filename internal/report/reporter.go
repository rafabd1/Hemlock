package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Status constants for Findings
const (
	StatusConfirmed = "Confirmed"
	StatusPotential = "Potential"
	StatusReflected = "Reflected"
)

// Finding represents a detected potential cache poisoning vulnerability.
// Nota: Os campos json refletem o estilo snake_case comum em muitas APIs/ferramentas.
type Finding struct {
	URL             string `json:"url"`
	Vulnerability   string `json:"vulnerability_type"` // e.g., "Unkeyed Header Input", "Reflected Payload in Cache"
	Description     string `json:"description"`
	InputType       string `json:"input_type,omitempty"`    // "header" or "parameter"
	InputName       string `json:"input_name,omitempty"`      // e.g., "X-Forwarded-Host" or "param_name"
	Payload         string `json:"payload,omitempty"`
	Evidence        string `json:"evidence,omitempty"`      // Could be a snippet of the response or specific headers
	Status          string `json:"status"`                 // "Confirmed", "Potential"
	// TODO: Add more fields as needed, e.g., Severity, Request/Response diffs
}

// GenerateReport outputs all recorded findings in the configured format.
// It takes a slice of *Finding pointers, the output path (stdout if empty), and format ("json" or "text").
func GenerateReport(findings []*Finding, outputPath string, format string) error {
	outputWriter := os.Stdout
	var err error

	if outputPath != "" {
		outputWriter, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create report file '%s': %w", outputPath, err)
		}
		defer outputWriter.Close()
		// Não logar aqui sobre onde será salvo, o main.go já faz isso.
	} else {
		// Não logar aqui sobre stdout, o main.go já faz isso.
	}

	if len(findings) == 0 {
		// Só imprimir esta mensagem se a saída for para stdout e o formato for texto.
		// Se for para arquivo, a ausência de conteúdo no arquivo já indica isso.
		// Se for JSON para stdout, uma lista vazia [] já indica isso.
		if outputPath == "" && strings.ToLower(format) == "text" {
			fmt.Fprintln(outputWriter, "No vulnerabilities or potential issues found.")
		}
		return nil
	}

	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(outputWriter)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(findings)
		if err != nil {
			return fmt.Errorf("failed to encode findings to JSON: %w", err)
		}
	case "text":
		foundConfirmed := false
		foundPotential := false
		foundReflected := false
		for _, finding := range findings {
			if finding.Status == StatusConfirmed {
				foundConfirmed = true
				_, err := fmt.Fprintf(outputWriter, "%s -> Vulnerable (Type: %s, Via: %s '%s', Payload: '%s')\n", 
					finding.URL, finding.Vulnerability, finding.InputType, finding.InputName, finding.Payload)
				if err != nil { return fmt.Errorf("error writing confirmed finding to report: %w", err) }
			} else if finding.Status == StatusPotential {
				foundPotential = true
				// Para 'Potential', a Description e Evidence podem ser mais úteis que o tipo de Vulnerability genérico.
				// A evidência já contém "Probe A cacheable: %t. Probe B cache HIT indicated: %t..."
				_, err := fmt.Fprintf(outputWriter, "%s -> Potentially Vulnerable (Input: %s '%s', Payload: '%s', Reason: %s, Evidence: %s)\n", 
					finding.URL, finding.InputType, finding.InputName, finding.Payload, finding.Description, finding.Evidence)
				if err != nil { return fmt.Errorf("error writing potential finding to report: %w", err) }
			} else if finding.Status == StatusReflected {
				foundReflected = true
				_, err := fmt.Fprintf(outputWriter, "%s -> Reflected Payload (Input: %s '%s', Payload: '%s', Description: %s)\n",
					finding.URL, finding.InputType, finding.InputName, finding.Payload, finding.Description)
				if err != nil { return fmt.Errorf("error writing reflected finding to report: %w", err) }
			}
		}
		if !foundConfirmed && !foundPotential && !foundReflected { // Caso todos os findings fossem de um status desconhecido (improvável)
		    fmt.Fprintln(outputWriter, "No recognized vulnerabilities or potential issues found.")
		}
	default:
		return fmt.Errorf("unsupported report format: %s. Supported formats are 'json' and 'text'", format)
	}
	return nil
}

// TODO: Remove the Reporter struct and its methods (NewReporter, AddFinding) if not used by the new simplified flow.
// For now, they are kept to avoid breaking other parts if they were hypothetically used elsewhere, 
// but the primary function will be GenerateReport.

// Reporter handles the generation and output of scan results.
type Reporter struct {
	// TODO: Add fields for output format (JSON, CSV, text), output file, logger.
}

// NewReporter creates a new Reporter.
func NewReporter(/* config */) *Reporter {
	return &Reporter{}
}

// AddFinding records a new finding.
func (r *Reporter) AddFinding(finding Finding) {
	// TODO: Store finding (e.g., in a slice)
	fmt.Printf("[VULN] URL: %s, Type: %s, Input: %s, Payload: %s\n", finding.URL, finding.Vulnerability, finding.InputName, finding.Payload)
}

// GenerateReport outputs all recorded findings in the configured format.
func (r *Reporter) GenerateReport(findings []Finding, outputPath string, format string) error {
	// TODO: Implement report generation for different formats (JSON, text, CSV)
	// Example for JSON to stdout if outputPath is empty, or to file
	outputWriter := os.Stdout
	var err error
	if outputPath != "" {
		outputWriter, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create report file: %w", err)
		}
		defer outputWriter.Close()
	}

	if format == "json" {
		encoder := json.NewEncoder(outputWriter)
		encoder.SetIndent("", "  ")
		return encoder.Encode(findings)
	}

	// Default to simple text format
	for _, finding := range findings {
		_, err := fmt.Fprintf(outputWriter, "URL: %s\nType: %s\nDescription: %s\nInput: %s\nPayload: %s\nEvidence: %s\n---\n",
			finding.URL, finding.Vulnerability, finding.Description, finding.InputName, finding.Payload, finding.Evidence)
		if err != nil {
			return err
		}
	}
	return nil
} 