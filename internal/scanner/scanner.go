package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/sharmajidotdev/netra/internal/llm"
	"github.com/sharmajidotdev/netra/pkg/types"
)

// Scanner is the main struct for scanning
type Scanner struct {
	config     *types.ScanConfig
	mlConfig   *types.MLConfig
	valConfig  *types.ValidationConfig
	rules      []types.Rule
	workers    int
	bufferSize int
	stats      *types.Stats
}

// Option is a function type for scanner configuration
type Option func(*Scanner)

// WithConfig sets the scanner configuration
func WithConfig(config *types.ScanConfig) Option {
	return func(s *Scanner) {
		s.config = config
	}
}

// WithMLConfig sets the ML configuration
func WithMLConfig(config *types.MLConfig) Option {
	return func(s *Scanner) {
		s.mlConfig = config
	}
}

// WithValidationConfig sets the validation configuration
func WithValidationConfig(config *types.ValidationConfig) Option {
	return func(s *Scanner) {
		s.valConfig = config
	}
}

// WithRules sets the detection rules
func WithRules(rules []types.Rule) Option {
	return func(s *Scanner) {
		s.rules = rules
	}
}

// New creates a new scanner with options
func New(opts ...Option) *Scanner {
	s := &Scanner{
		config: &types.ScanConfig{
			MaxDepth:     10,
			SkipGit:      true,
			SkipVendor:   true,
			Threads:      4,
			MinEntropy:   4.5,
			MaxFileSize:  1024 * 1024, // 1MB
			ContextLines: 3,
		},
		workers:    4,
		bufferSize: 1000,
		stats:      newStats(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Scan runs a scan on provided inputs
func (s *Scanner) Scan(ctx context.Context, inputs ...string) (*types.Result, error) {
	start := time.Now()
	result := &types.Result{
		Stats: types.Stats{},
	}

	// Create channels for worker pool
	jobs := make(chan string, s.bufferSize)
	results := make(chan []types.Finding, s.bufferSize)
	errChan := make(chan error, 1)

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, jobs, results, errChan)
	}

	// Send jobs to workers
	go func() {
		defer close(jobs)
		for _, input := range inputs {
			select {
			case jobs <- input:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	var allFindings []types.Finding
	for findings := range results {
		allFindings = append(allFindings, findings...)
		result.Stats.Findings += len(findings)
	}

	// Check for errors
	select {
	case err := <-errChan:
		return nil, err
	default:
	}

	// Apply LLM validation if enabled
	if s.mlConfig != nil && s.mlConfig.Enabled && len(allFindings) > 0 {
		validationStart := time.Now()
		allFindings = llm.Filter(ctx, allFindings, true)
		result.Stats.ValidationTime = time.Since(validationStart)
	}

	result.Findings = allFindings

	// Update stats
	result.Stats.DurationMs = int(time.Since(start).Milliseconds())

	return result, nil
}

// worker processes files from the jobs channel
func (s *Scanner) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan string, results chan<- []types.Finding, errChan chan<- error) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case file, ok := <-jobs:
			if !ok {
				return
			}

			findings, err := s.scanFile(ctx, file)
			if err != nil {
				select {
				case errChan <- err:
				default:
				}
				return
			}

			if len(findings) > 0 {
				results <- findings
			}
		}
	}
}

// initStats initializes scanner statistics
func (s *Scanner) initStats() {
	s.stats = newStats()
	s.stats.reset()
}
