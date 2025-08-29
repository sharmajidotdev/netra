package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	var errors []string

	// Validate scan settings
	if c.Scan.MaxDepth < 1 {
		errors = append(errors, "scan.max_depth must be greater than 0")
	}
	if c.Scan.Threads < 1 {
		errors = append(errors, "scan.threads must be greater than 0")
	}
	if c.Scan.MaxFileSize < 1 {
		errors = append(errors, "scan.max_file_size must be greater than 0")
	}
	if !isValidExitOn(c.Scan.ExitOn) {
		errors = append(errors, "scan.exit_on must be one of: high, medium, low")
	}

	// Validate output settings
	if !isValidOutputFormat(c.Output.Format) {
		errors = append(errors, "output.format must be one of: json, sarif, human")
	}

	// Validate LLM settings
	if c.LLM.Enabled {
		if !isValidLLMProvider(c.LLM.Provider) {
			errors = append(errors, "llm.provider must be one of: openai")
		}
		if c.LLM.Model == "" {
			errors = append(errors, "llm.model is required when llm is enabled")
		}
	}

	// Validate custom patterns
	for i, pattern := range c.Rules.CustomPatterns {
		if pattern.Name == "" {
			errors = append(errors, fmt.Sprintf("rules.custom_patterns[%d].name is required", i))
		}
		if pattern.Pattern == "" {
			errors = append(errors, fmt.Sprintf("rules.custom_patterns[%d].pattern is required", i))
		}
		if pattern.Confidence < 0 || pattern.Confidence > 100 {
			errors = append(errors, fmt.Sprintf("rules.custom_patterns[%d].confidence must be between 0 and 100", i))
		}
		if !isValidSeverity(pattern.Severity) {
			errors = append(errors, fmt.Sprintf("rules.custom_patterns[%d].severity must be one of: high, medium, low", i))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("invalid configuration:\n- %s", strings.Join(errors, "\n- "))
	}

	return nil
}

// Normalize normalizes the configuration values
func (c *Config) Normalize() {
	// Normalize scan settings
	c.Scan.ExitOn = strings.ToLower(c.Scan.ExitOn)

	// Normalize excludes paths
	for i, exclude := range c.Scan.Excludes {
		c.Scan.Excludes[i] = filepath.Clean(exclude)
	}

	// Normalize output format
	c.Output.Format = strings.ToLower(c.Output.Format)

	// Normalize LLM settings
	c.LLM.Provider = strings.ToLower(c.LLM.Provider)

	// Normalize custom pattern settings
	for i := range c.Rules.CustomPatterns {
		c.Rules.CustomPatterns[i].Severity = strings.ToLower(c.Rules.CustomPatterns[i].Severity)
		c.Rules.CustomPatterns[i].SecretType = strings.TrimSpace(c.Rules.CustomPatterns[i].SecretType)
	}
}

// Helper functions for validation
func isValidExitOn(level string) bool {
	level = strings.ToLower(level)
	return level == "high" || level == "medium" || level == "low"
}

func isValidOutputFormat(format string) bool {
	format = strings.ToLower(format)
	return format == "json" || format == "sarif" || format == "human"
}

func isValidLLMProvider(provider string) bool {
	provider = strings.ToLower(provider)
	return provider == "openai"
}

func isValidSeverity(severity string) bool {
	severity = strings.ToLower(severity)
	return severity == "high" || severity == "medium" || severity == "low"
}

// ToScannerConfig converts the config to scanner configuration options
func (c *Config) ToScannerConfig() *ScannerConfig {
	return &ScannerConfig{
		MaxDepth:    c.Scan.MaxDepth,
		Threads:     c.Scan.Threads,
		MaxFileSize: c.Scan.MaxFileSize,
		SkipGit:     c.Scan.SkipGit,
		SkipVendor:  c.Scan.SkipVendor,
		Excludes:    c.Scan.Excludes,
		ExitOn:      c.Scan.ExitOn,
	}
}

// ToLLMConfig converts the config to LLM configuration options
func (c *Config) ToLLMConfig() *LLMConfig {
	if !c.LLM.Enabled {
		return nil
	}

	return &LLMConfig{
		Provider: c.LLM.Provider,
		Model:    c.LLM.Model,
		APIKey:   c.LLM.APIKey,
		Explain:  c.LLM.Explain,
	}
}
