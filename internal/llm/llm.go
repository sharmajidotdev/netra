package llm

import (
	"context"

	"github.com/sharmajidotdev/netra/pkg/types"
)

// Filter applies LLM filtering (stub)
func Filter(ctx context.Context, in []types.Finding, explain bool) []types.Finding {
	// TODO: Call OpenAI or local model
	return in
}
