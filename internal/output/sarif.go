package output

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sharmajidotdev/netra/pkg/types"
)

// SARIFOutput represents the SARIF output format
type SARIFOutput struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run represents a SARIF run
type Run struct {
	Tool        Tool         `json:"tool"`
	Results     []Result     `json:"results"`
	Invocations []Invocation `json:"invocations"`
}

// Tool represents the scanning tool
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver represents the tool driver
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

// Rule represents a SARIF rule
type Rule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription Message           `json:"shortDescription"`
	FullDescription  Message           `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

// Message represents a SARIF message
type Message struct {
	Text string `json:"text"`
}

// Result represents a SARIF result
type Result struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    Message                `json:"message"`
	Locations  []Location             `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// Location represents a SARIF location
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation represents a SARIF physical location
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

// ArtifactLocation represents a SARIF artifact location
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region represents a SARIF region
type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// Invocation represents a SARIF invocation
type Invocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUtc        string `json:"startTimeUtc"`
	EndTimeUtc          string `json:"endTimeUtc"`
}

// ToSARIF converts scan results to SARIF format
func ToSARIF(scanResults *types.Result, toolVersion string) ([]byte, error) {
	// Create SARIF structure
	sarif := SARIFOutput{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "Netra",
						Version:        toolVersion,
						InformationURI: "https://github.com/sharmajidotdev/netra",
						Rules:          buildRules(),
					},
				},
				Results: convertFindings(scanResults.Findings),
				Invocations: []Invocation{
					{
						ExecutionSuccessful: true,
						StartTimeUtc:        time.Now().Add(-time.Duration(scanResults.Stats.Duration) * time.Millisecond).UTC().Format(time.RFC3339),
						EndTimeUtc:          time.Now().UTC().Format(time.RFC3339),
					},
				},
			},
		},
	}

	// Marshal to JSON
	return json.MarshalIndent(sarif, "", "  ")
}

// buildRules creates SARIF rules from predefined rules
func buildRules() []Rule {
	return []Rule{
		{
			ID:   "aws-access-key",
			Name: "AWS Access Key Detection",
			ShortDescription: Message{
				Text: "Detects AWS Access Key IDs in code",
			},
			FullDescription: Message{
				Text: "AWS credentials should not be stored in code. Use environment variables or AWS credential providers instead.",
			},
			Properties: map[string]string{
				"security-severity": "9.0",
				"category":          "secret",
				"type":              "credential",
			},
		},
		// Add more rules here...
	}
}

// convertFindings converts findings to SARIF results
func convertFindings(findings []types.Finding) []Result {
	results := make([]Result, 0, len(findings))

	for _, f := range findings {
		level := "warning"
		if f.Severity == "HIGH" {
			level = "error"
		} else if f.Severity == "LOW" {
			level = "note"
		}

		results = append(results, Result{
			RuleID: f.RuleID,
			Level:  level,
			Message: Message{
				Text: fmt.Sprintf("Found %s: %s", f.SecretType, f.Reason),
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: f.File,
						},
						Region: Region{
							StartLine:   f.Line,
							StartColumn: f.Column,
							EndLine:     f.Line,
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"category":    f.Category,
				"confidence":  f.Confidence,
				"entropy":     f.Entropy,
				"is_valid":    f.IsValid,
				"validated":   f.ValidatedAt != nil,
				"secret_hash": f.Hash,
			},
		})
	}

	return results
}
