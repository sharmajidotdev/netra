package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sharmajidotdev/netra/internal/detect"
	"github.com/sharmajidotdev/netra/internal/llm"
	"github.com/sharmajidotdev/netra/internal/logger"
	"github.com/sharmajidotdev/netra/pkg/types"
)

// scanFile processes a single file for secrets
func (s *Scanner) scanFile(ctx context.Context, path string) ([]types.Finding, error) {
	logger.Debug("Scanning file: %s", path)

	// Check if file should be skipped
	if s.shouldSkipFile(path) {
		logger.Debug("Skipping file: %s", path)
		s.stats.addFileSkipped()
		return nil, nil
	}

	// Open file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()

	// Get file info
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %s: %w", path, err)
	}

	// Skip if file is too large
	if info.Size() > s.config.MaxFileSize {
		s.stats.addFileSkipped()
		return nil, nil
	}

	// Update stats
	s.stats.addFileScanned()
	s.stats.addBytesScanned(info.Size())

	var findings []types.Finding

	// Process file line by line
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check context for early termination
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Run regex detectors
		if matches := detect.Line(path, lineNum, line); len(matches) > 0 {
			findings = append(findings, matches...)
		}

		// Run entropy detection
		if matches := detect.EntropyCheck(path, lineNum, line); len(matches) > 0 {
			findings = append(findings, matches...)
		}
	}

	if err := scanner.Err(); err != nil {
		return findings, fmt.Errorf("error scanning file %s: %w", path, err)
	}

	// If LLM validation is enabled, validate findings
	if s.mlConfig != nil && s.mlConfig.Enabled && len(findings) > 0 {
		findings = s.validateWithLLM(ctx, findings)
	}

	return findings, nil
}

// shouldSkipFile checks if a file should be skipped based on configuration
func (s *Scanner) shouldSkipFile(path string) bool {
	// Skip directories
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return true
	}

	// Get relative path
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))

	// Skip git directories
	if s.config.SkipGit && (strings.Contains(path, ".git/") || base == ".git") {
		return true
	}

	// Skip vendor directories
	if s.config.SkipVendor && (strings.Contains(path, "vendor/") || strings.Contains(path, "node_modules/")) {
		return true
	}

	// Skip by extension if allowed extensions are specified
	if len(s.config.AllowedExts) > 0 {
		allowed := false
		for _, allowedExt := range s.config.AllowedExts {
			if strings.EqualFold(ext, allowedExt) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true
		}
	}

	// Skip by ignore patterns
	for _, pattern := range s.config.IgnorePatterns {
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}

	return false
}

// validateWithLLM uses LLM to validate and explain findings
func (s *Scanner) validateWithLLM(ctx context.Context, findings []types.Finding) []types.Finding {
	if len(findings) == 0 {
		return findings
	}

	logger.Info("Validating %d findings with LLM", len(findings))

	// Get LLM to validate findings
	// Always include explanations for better context and analysis
	validatedFindings := llm.Filter(ctx, findings, true)

	logger.Debug("LLM validation complete. %d findings after validation", len(validatedFindings))
	return validatedFindings
}
