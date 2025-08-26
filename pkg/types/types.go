package types

// Finding represents a detected secret
type Finding struct {
	ID         string   `json:"id"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	SecretType string   `json:"secret_type"`
	Detector   string   `json:"detector"`
	Confidence string   `json:"confidence"`
	Validity   string   `json:"validity"`
	Reason     string   `json:"reason,omitempty"`
	Matches    []string `json:"matches,omitempty"`
}

// Result holds scan results
type Result struct {
	Findings []Finding `json:"findings"`
	Stats    Stats     `json:"stats"`
}

// Stats holds scan statistics
type Stats struct {
	FilesScanned int `json:"files_scanned"`
	Findings     int `json:"findings"`
	DurationMs   int `json:"duration_ms"`
}
