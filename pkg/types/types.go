package types

import (
	"time"
)

// Finding represents a detected secret
type Finding struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	File        string                 `json:"file"`
	Line        int                    `json:"line"`
	Column      int                    `json:"column"`
	Secret      string                 `json:"secret"`
	Context     string                 `json:"context"`
	SecretType  string                 `json:"secret_type"`
	Detector    string                 `json:"detector"`
	Entropy     float64                `json:"entropy,omitempty"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	ValidatedAt *time.Time             `json:"validated_at,omitempty"`
	IsValid     bool                   `json:"is_valid"`
	Reason      string                 `json:"reason,omitempty"`
	Matches     []string               `json:"matches,omitempty"`
	Hash        string                 `json:"hash"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Stats tracks scanning statistics
type Stats struct {
	FilesScanned   int32         `json:"files_scanned"`
	FilesSkipped   int32         `json:"files_skipped"`
	BytesScanned   int64         `json:"bytes_scanned"`
	Findings       int32         `json:"findings"`
	Duration       int64         `json:"duration"`
	ValidationTime time.Duration `json:"validation_time,omitempty"`
}

// Result holds scan results
type Result struct {
	Findings []Finding `json:"findings"`
	Stats    Stats     `json:"stats"`
}

// ScanConfig holds configuration for scanning
type ScanConfig struct {
	MaxDepth       int      `json:"max_depth"`
	SkipGit        bool     `json:"skip_git"`
	SkipVendor     bool     `json:"skip_vendor"`
	Threads        int      `json:"threads"`
	MinEntropy     float64  `json:"min_entropy"`
	MaxFileSize    int64    `json:"max_file_size"`
	AllowedExts    []string `json:"allowed_extensions"`
	IgnorePatterns []string `json:"ignore_patterns"`
	UseGitIgnore   bool     `json:"use_gitignore"`
	UseDotEnv      bool     `json:"use_dotenv"`
	ContextLines   int      `json:"context_lines"`
}

// Rule defines a secret detection rule
type Rule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Pattern        string   `json:"pattern"`
	Examples       []string `json:"examples"`
	Validators     []string `json:"validators"`
	FalsePositives []string `json:"false_positives"`
	MinEntropy     float64  `json:"min_entropy"`
	MaxOccurrences int      `json:"max_occurrences"`
	Disabled       bool     `json:"disabled"`
}

// MLConfig holds configuration for machine learning
type MLConfig struct {
	Enabled     bool    `json:"enabled"`
	Provider    string  `json:"provider"`
	Model       string  `json:"model"`
	APIKey      string  `json:"api_key"`
	MaxTokens   int     `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
	Threshold   float64 `json:"threshold"`
	CacheSize   int     `json:"cache_size"`
}

// ValidationConfig holds configuration for secret validation
type ValidationConfig struct {
	Enabled   bool          `json:"enabled"`
	Timeout   time.Duration `json:"timeout"`
	Retries   int           `json:"retries"`
	Proxy     string        `json:"proxy"`
	RateLimit int           `json:"rate_limit"`
}
