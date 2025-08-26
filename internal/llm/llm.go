package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sharmajidotdev/netra/pkg/types"
)

// Validator handles LLM-based secret validation
type Validator struct {
	config    *types.MLConfig
	client    *http.Client
	cache     map[string]*ValidationResult
	cacheLock sync.RWMutex
}

// ValidationResult represents an LLM validation result
type ValidationResult struct {
	IsSecret    bool    `json:"is_secret"`
	Confidence  float64 `json:"confidence"`
	Explanation string  `json:"explanation"`
	Timestamp   time.Time
}

// OpenAIResponse represents the response from OpenAI API
type OpenAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// New creates a new LLM validator
func New(config *types.MLConfig) *Validator {
	return &Validator{
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: make(map[string]*ValidationResult),
	}
}

// Filter applies LLM filtering to findings
func Filter(ctx context.Context, in []types.Finding, explain bool) []types.Finding {
	// Create default config if none provided
	config := &types.MLConfig{
		Enabled:     true,
		Provider:    "openai",
		Model:       "gpt-4",
		MaxTokens:   1000,
		Temperature: 0.1,
		Threshold:   0.8,
		CacheSize:   1000,
	}

	// Create validator
	v := New(config)

	// Validate findings
	if err := v.ValidateFindings(ctx, in); err != nil {
		// Log error but continue with original findings
		fmt.Printf("LLM validation failed: %v\n", err)
		return in
	}

	// Filter findings based on validation results
	var filtered []types.Finding
	for _, f := range in {
		if !explain && !f.IsValid {
			continue
		}
		filtered = append(filtered, f)
	}

	return filtered
}

// ValidateFindings validates a batch of findings using LLM
func (v *Validator) ValidateFindings(ctx context.Context, findings []types.Finding) error {
	// Process findings in batches to reduce API calls
	batchSize := 5
	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}

		batch := findings[i:end]
		if err := v.processBatch(ctx, batch); err != nil {
			return fmt.Errorf("batch validation failed: %w", err)
		}
	}
	return nil
}

// processBatch validates a batch of findings
func (v *Validator) processBatch(ctx context.Context, findings []types.Finding) error {
	prompt := v.buildPrompt(findings)

	// Check cache first
	cacheKey := fmt.Sprintf("%x", prompt)
	if result := v.getCached(cacheKey); result != nil {
		v.applyValidationResult(findings, result)
		return nil
	}

	result, err := v.callLLM(ctx, prompt)
	if err != nil {
		return err
	}

	// Cache the result
	v.cacheResult(cacheKey, result)

	// Apply validation results
	v.applyValidationResult(findings, result)

	return nil
}

// buildPrompt creates a prompt for the LLM
func (v *Validator) buildPrompt(findings []types.Finding) string {
	var buf strings.Builder

	buf.WriteString("Analyze each potential secret and determine if it's a real secret or a false positive.\n")
	buf.WriteString("For each finding, consider:\n")
	buf.WriteString("1. The secret's pattern and entropy\n")
	buf.WriteString("2. The context where it appears\n")
	buf.WriteString("3. Whether it matches known patterns for secrets\n")
	buf.WriteString("4. If it could be test/example data\n\n")

	for i, f := range findings {
		buf.WriteString(fmt.Sprintf("Finding %d:\n", i+1))
		buf.WriteString(fmt.Sprintf("- Type: %s\n", f.SecretType))
		buf.WriteString(fmt.Sprintf("- Value: %s\n", f.Secret))
		buf.WriteString(fmt.Sprintf("- Context: %s\n", f.Context))
		buf.WriteString(fmt.Sprintf("- File: %s:%d\n\n", f.File, f.Line))
	}

	buf.WriteString("\nFor each finding, respond in JSON format with:\n")
	buf.WriteString("{\n  \"findings\": [\n    {\n")
	buf.WriteString("      \"is_secret\": true/false,\n")
	buf.WriteString("      \"confidence\": 0.0-1.0,\n")
	buf.WriteString("      \"explanation\": \"reason\"\n    }\n  ]\n}")

	return buf.String()
}

// callLLM makes the API call to the LLM service
func (v *Validator) callLLM(ctx context.Context, prompt string) (*ValidationResult, error) {
	// Prepare the request based on the provider
	var url string
	var reqBody interface{}

	switch v.config.Provider {
	case "openai":
		url = "https://api.openai.com/v1/chat/completions"
		reqBody = map[string]interface{}{
			"model": v.config.Model,
			"messages": []map[string]string{
				{
					"role":    "system",
					"content": "You are a security expert analyzing potential secrets in code.",
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
			"temperature": v.config.Temperature,
			"max_tokens":  v.config.MaxTokens,
		}
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", v.config.Provider)
	}

	// Marshal request body
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", v.config.APIKey))

	// Make request
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var openAIResp OpenAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&openAIResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse the JSON response from the LLM
	var result struct {
		Findings []ValidationResult `json:"findings"`
	}

	if err := json.Unmarshal([]byte(openAIResp.Choices[0].Message.Content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	// Return the first result (we'll process one batch at a time)
	if len(result.Findings) == 0 {
		return nil, fmt.Errorf("no validation results returned")
	}

	return &result.Findings[0], nil
}

// getCached retrieves a cached validation result
func (v *Validator) getCached(key string) *ValidationResult {
	v.cacheLock.RLock()
	defer v.cacheLock.RUnlock()

	if result, ok := v.cache[key]; ok {
		// Check if cache entry is still valid
		if time.Since(result.Timestamp) < time.Hour {
			return result
		}
		// Remove expired entry
		delete(v.cache, key)
	}
	return nil
}

// cacheResult stores a validation result in cache
func (v *Validator) cacheResult(key string, result *ValidationResult) {
	v.cacheLock.Lock()
	defer v.cacheLock.Unlock()

	result.Timestamp = time.Now()
	v.cache[key] = result

	// Cleanup old entries if cache is too large
	if len(v.cache) > v.config.CacheSize {
		var oldestKey string
		oldestTime := time.Now()

		for k, r := range v.cache {
			if r.Timestamp.Before(oldestTime) {
				oldestTime = r.Timestamp
				oldestKey = k
			}
		}
		delete(v.cache, oldestKey)
	}
}

// applyValidationResult updates findings with LLM validation results
func (v *Validator) applyValidationResult(findings []types.Finding, result *ValidationResult) {
	for i := range findings {
		findings[i].IsValid = result.IsSecret
		findings[i].Confidence = result.Confidence
		findings[i].Reason = result.Explanation
		findings[i].ValidatedAt = &result.Timestamp
	}
}
