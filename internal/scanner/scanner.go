package scanner

import (
	"context"

	"github.com/sharmajidotdev/netra/pkg/types"
)

// Scanner is the main struct for scanning
type Scanner struct{}

// New creates a new scanner
func New() *Scanner {
	return &Scanner{}
}

// Scan runs a scan on provided inputs
func (s *Scanner) Scan(ctx context.Context, inputs ...string) (*types.Result, error) {
	// TODO: Implement scanning pipeline
	return &types.Result{}, nil
}
