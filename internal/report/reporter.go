package report

import (
	"encoding/json"
	"fmt"
	"os"
)

// Finding represents a detected potential cache poisoning vulnerability.
type Finding struct {
	URL             string `json:"url"`
	Vulnerability   string `json:"vulnerability_type"` // e.g., "Unkeyed Header Input", "Reflected Payload in Cache"
	Description     string `json:"description"`
	UnkeyedInput    string `json:"unkeyed_input,omitempty"` // e.g., "X-Forwarded-Host"
	Payload         string `json:"payload,omitempty"`
	Evidence        string `json:"evidence,omitempty"`       // Could be a snippet of the response or specific headers
	// TODO: Add more fields as needed, e.g., Severity, Request/Response diffs
}

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
	fmt.Printf("[VULN] URL: %s, Type: %s, Input: %s, Payload: %s\n", finding.URL, finding.Vulnerability, finding.UnkeyedInput, finding.Payload)
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
			finding.URL, finding.Vulnerability, finding.Description, finding.UnkeyedInput, finding.Payload, finding.Evidence)
		if err != nil {
			return err
		}
	}
	return nil
} 