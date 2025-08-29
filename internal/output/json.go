package output

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sharmajidotdev/netra/pkg/types"
)

// JSONOutput represents the JSON output structure
type JSONOutput struct {
	Schema      string          `json:"$schema"`
	Version     string          `json:"version"`
	Timestamp   string          `json:"timestamp"`
	Scanner     ScannerInfo     `json:"scanner"`
	Statistics  types.Stats     `json:"statistics"`
	RiskSummary RiskSummary     `json:"risk_summary"`
	Findings    []types.Finding `json:"findings"`
}

// ScannerInfo represents scanner metadata
type ScannerInfo struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Rules   []string `json:"enabled_rules"`
	Options Options  `json:"options"`
}

// RiskSummary represents risk statistics
type RiskSummary struct {
	TotalFindings  int            `json:"total_findings"`
	BySeverity     map[string]int `json:"by_severity"`
	ByCategory     map[string]int `json:"by_category"`
	Validated      int            `json:"validated_findings"`
	FalsePositives int            `json:"false_positives"`
}

// ToJSON converts scan results to enhanced JSON format
func ToJSON(res *types.Result, version string, opts *Options) ([]byte, error) {
	// Calculate risk summary
	summary := calculateRiskSummary(res.Findings)

	// Build output structure
	output := JSONOutput{
		Schema:    "https://raw.githubusercontent.com/sharmajidotdev/netra/main/schema/output.json",
		Version:   "1.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Scanner: ScannerInfo{
			Name:    "Netra",
			Version: version,
			Rules:   getEnabledRules(),
			Options: *opts,
		},
		Statistics:  res.Stats,
		RiskSummary: summary,
		Findings:    res.Findings,
	}

	// Marshal with indentation
	return json.MarshalIndent(output, "", "  ")
}

// WriteJSON outputs scan results in JSON format
func WriteJSON(result *types.Result, version string, opts *Options) error {
	output := map[string]interface{}{
		"version": version,
		"results": result,
	}

	if opts != nil {
		output["scan_config"] = opts
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

// calculateRiskSummary generates risk statistics
func calculateRiskSummary(findings []types.Finding) RiskSummary {
	summary := RiskSummary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
	}

	for _, f := range findings {
		// Count by severity
		summary.BySeverity[f.Severity]++

		// Count by category
		summary.ByCategory[f.Category]++

		// Count validated findings
		if f.ValidatedAt != nil {
			summary.Validated++
			if !f.IsValid {
				summary.FalsePositives++
			}
		}
	}

	return summary
}

// getEnabledRules returns the list of enabled detection rules
func getEnabledRules() []string {
	// TODO: Get this from rules configuration
	return []string{
		"aws-access-key",
		"aws-secret-key",
		"github-token",
		"google-api-key",
		"slack-token",
		"generic-api-key",
		"private-key",
		"password-in-code",
	}
}
