package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/sharmajidotdev/netra/pkg/types"
)

const (
	minTokenLength = 8
	maxTokenLength = 100
	baseEntropy    = 3.5 // Minimum entropy for basic strings
	highEntropy    = 4.5 // Threshold for high-entropy strings
)

var (
	// tokenPattern matches potential secret tokens
	tokenPattern = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{8,100}`)

	// commonWords to filter out
	commonWords = map[string]bool{
		"function": true,
		"return":   true,
		"import":   true,
		"export":   true,
		"const":    true,
		"static":   true,
		"class":    true,
		"public":   true,
		"private":  true,
	}
)

// EntropyResult holds entropy calculation results
type EntropyResult struct {
	Token     string
	Entropy   float64
	Base64    bool
	Hex       bool
	CharTypes int
}

// EntropyCheck checks tokens for high entropy
func EntropyCheck(file string, line int, text string) []types.Finding {
	var findings []types.Finding

	// Extract potential tokens
	tokens := tokenPattern.FindAllString(text, -1)

	for _, token := range tokens {
		// Skip if token is too short or too long
		if len(token) < minTokenLength || len(token) > maxTokenLength {
			continue
		}

		// Skip common words
		if commonWords[strings.ToLower(token)] {
			continue
		}

		// Calculate entropy and characteristics
		result := analyzeToken(token)

		// Skip if entropy is too low
		if result.Entropy < baseEntropy {
			continue
		}

		// Determine confidence based on entropy and characteristics
		confidence := calculateConfidence(result)
		if confidence < 0.5 {
			continue
		}

		// Generate finding hash
		hash := sha256.Sum256([]byte(token))

		findings = append(findings, types.Finding{
			ID:         generateID(file, line, token),
			File:       file,
			Line:       line,
			Secret:     token,
			SecretType: "High Entropy String",
			Detector:   "entropy",
			Category:   "Unknown",
			Severity:   getSeverity(result.Entropy),
			Entropy:    result.Entropy,
			Confidence: confidence,
			Hash:       hex.EncodeToString(hash[:]),
			Metadata: map[string]interface{}{
				"base64":    result.Base64,
				"hex":       result.Hex,
				"charTypes": result.CharTypes,
			},
		})
	}

	return findings
}

// analyzeToken performs detailed analysis of a token
func analyzeToken(token string) EntropyResult {
	result := EntropyResult{
		Token:   token,
		Entropy: calculateEntropy(token),
	}

	// Check if it could be base64
	result.Base64 = isBase64Like(token)

	// Check if it could be hex
	result.Hex = isHexLike(token)

	// Count different character types
	result.CharTypes = countCharTypes(token)

	return result
}

// isBase64Like checks if a string looks like base64
func isBase64Like(s string) bool {
	// Base64 usually ends with = or == padding
	if strings.HasSuffix(s, "=") || strings.HasSuffix(s, "==") {
		return true
	}

	// Check if string only contains base64 chars
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*$`)
	return base64Pattern.MatchString(s)
}

// isHexLike checks if a string looks like hex
func isHexLike(s string) bool {
	hexPattern := regexp.MustCompile(`^[A-Fa-f0-9]*$`)
	return hexPattern.MatchString(s)
}

// countCharTypes counts different types of characters
func countCharTypes(s string) int {
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	count := 0
	if hasUpper {
		count++
	}
	if hasLower {
		count++
	}
	if hasDigit {
		count++
	}
	if hasSpecial {
		count++
	}
	return count
}

// calculateConfidence returns a confidence score between 0 and 1
func calculateConfidence(result EntropyResult) float64 {
	var score float64

	// Base score from entropy
	if result.Entropy >= highEntropy {
		score += 0.4
	} else if result.Entropy >= baseEntropy {
		score += 0.2
	}

	// Bonus for character diversity
	score += float64(result.CharTypes) * 0.1

	// Bonus for looking like base64/hex
	if result.Base64 {
		score += 0.2
	}
	if result.Hex {
		score += 0.1
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// getSeverity returns severity level based on entropy
func getSeverity(entropy float64) string {
	switch {
	case entropy >= highEntropy:
		return "HIGH"
	case entropy >= baseEntropy:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
