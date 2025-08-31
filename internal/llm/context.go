package llm

import (
	"context"

	"github.com/sharmajidotdev/netra/pkg/types"
)

// ContextKey is a type for context keys to avoid collisions
type ContextKey int

const (
	// ConfigKey is the context key for MLConfig
	ConfigKey ContextKey = iota
)

// GetConfigFromContext returns the MLConfig from the context if it exists
func GetConfigFromContext(ctx context.Context) (*types.MLConfig, bool) {
	config, ok := ctx.Value(ConfigKey).(*types.MLConfig)
	return config, ok
}
