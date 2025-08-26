package config

// Config holds scanner config (stub)
type Config struct {
	Excludes []string
	Patterns []string
}

// Load loads config from file path (stub)
func Load(path string) (*Config, error) {
	return &Config{}, nil
}
