package config

// ScannerConfig contains scanner-specific configuration
type ScannerConfig struct {
	MaxDepth    int
	Threads     int
	MaxFileSize int64
	SkipGit     bool
	SkipVendor  bool
	Excludes    []string
	ExitOn      string
}

// LLMConfig contains LLM-specific configuration
type LLMConfig struct {
	Provider string
	Model    string
	APIKey   string
	Explain  bool
}
