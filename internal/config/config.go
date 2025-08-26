package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the complete configuration structure
type Config struct {
	// Scan settings
	Scan struct {
		MaxDepth    int      `yaml:"max_depth"`
		Threads     int      `yaml:"threads"`
		MaxFileSize int64    `yaml:"max_file_size"`
		SkipGit     bool     `yaml:"skip_git"`
		SkipVendor  bool     `yaml:"skip_vendor"`
		ExitOn      string   `yaml:"exit_on"`
		Excludes    []string `yaml:"excludes"`
	} `yaml:"scan"`

	// Output settings
	Output struct {
		Format string `yaml:"format"` // json, sarif, human
	} `yaml:"output"`

	// LLM settings
	LLM struct {
		Enabled  bool   `yaml:"enabled"`
		Provider string `yaml:"provider"`
		Model    string `yaml:"model"`
		APIKey   string `yaml:"api_key"`
		Explain  bool   `yaml:"explain"`
	} `yaml:"llm"`

	// Rules settings
	Rules struct {
		CustomPatterns []struct {
			Name       string `yaml:"name"`
			Pattern    string `yaml:"pattern"`
			Confidence int    `yaml:"confidence"`
			SecretType string `yaml:"type"`
			Severity   string `yaml:"severity"`
		} `yaml:"custom_patterns"`
	} `yaml:"rules"`
}

// DefaultConfig returns a config with default values
func DefaultConfig() *Config {
	cfg := &Config{}

	// Default scan settings
	cfg.Scan.MaxDepth = 10
	cfg.Scan.Threads = 4
	cfg.Scan.MaxFileSize = 1024 * 1024 // 1MB
	cfg.Scan.SkipGit = true
	cfg.Scan.SkipVendor = true
	cfg.Scan.ExitOn = "high"
	cfg.Scan.Excludes = []string{
		".git/",
		"node_modules/",
		"vendor/",
		"*.min.js",
		"*.min.css",
	}

	// Default output settings
	cfg.Output.Format = "human"

	// Default LLM settings
	cfg.LLM.Provider = "openai"
	cfg.LLM.Model = "gpt-4"
	cfg.LLM.Enabled = false
	cfg.LLM.Explain = false

	return cfg
}

// Load loads configuration from a file
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Parse YAML
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Normalize values
	cfg.Normalize()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadOrDefault loads configuration from a file if it exists,
// otherwise returns default configuration
func LoadOrDefault(path string) (*Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}

	cfg, err := Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}

	return cfg, nil
}

// Save saves the configuration to a file
func (c *Config) Save(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	// Marshal config to YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	return nil
}
