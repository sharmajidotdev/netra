package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"

	"github.com/sharmajidotdev/netra/pkg/types"
)

var defaultRules = []types.Rule{
	{
		ID:          "aws-access-key",
		Name:        "AWS Access Key ID",
		Description: "AWS Access Key ID",
		Severity:    "HIGH",
		Category:    "Cloud Credentials",
		Pattern:     `(?i)AKIA[0-9A-Z]{16}`,
		Examples: []string{
			"AKIAIOSFODNN7EXAMPLE",
		},
		MinEntropy: 3.5,
	},
	{
		ID:          "aws-secret-key",
		Name:        "AWS Secret Access Key",
		Description: "AWS Secret Access Key",
		Severity:    "HIGH",
		Category:    "Cloud Credentials",
		Pattern:     `(?i)[0-9a-zA-Z/+]{40}`,
		Examples: []string{
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		MinEntropy: 4.3,
	},
	{
		ID:          "github-pat",
		Name:        "GitHub Personal Access Token",
		Description: "GitHub Personal Access Token",
		Severity:    "HIGH",
		Category:    "Version Control",
		Pattern:     `(?i)ghp_[0-9a-zA-Z]{36}`,
		Examples: []string{
			"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
		},
		MinEntropy: 4.0,
	},
	{
		ID:          "google-api-key",
		Name:        "Google API Key",
		Description: "Google API Key",
		Severity:    "HIGH",
		Category:    "Cloud Credentials",
		Pattern:     `(?i)AIza[0-9A-Za-z\\-_]{35}`,
		Examples: []string{
			"AIzaSyBNLrJhOMz6idD05pzfn5lCXXXXXXXXXXX",
		},
		MinEntropy: 3.8,
	},
	{
		ID:          "slack-token",
		Name:        "Slack Token",
		Description: "Slack API Token or Webhook URL",
		Severity:    "HIGH",
		Category:    "API Tokens",
		Pattern:     `xox[baprs]-([0-9a-zA-Z]{10,48})?`,
		Examples: []string{
			"xoxb-123456789012-345678901234-aBcDeFgHiJkLmNoPqRsTuVwX",
		},
		MinEntropy: 4.0,
	},
	{
		ID:          "generic-api-key",
		Name:        "Generic API Key",
		Description: "Generic API Key Pattern",
		Severity:    "MEDIUM",
		Category:    "API Tokens",
		Pattern:     `(?i)(api[_-]?key|apikey|token)(['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{32,64})['\"]?)`,
		Examples: []string{
			"api_key: abcd1234efgh5678ijkl9012mnop3456qrst7890",
		},
		MinEntropy: 3.5,
	},
	{
		ID:          "private-key",
		Name:        "Private Key",
		Description: "Private Key File or Content",
		Severity:    "HIGH",
		Category:    "Cryptographic",
		Pattern:     `-----BEGIN ((RSA|DSA|EC|PGP) )?PRIVATE KEY( BLOCK)?-----`,
		Examples: []string{
			"-----BEGIN RSA PRIVATE KEY-----",
		},
		MinEntropy: 0, // Not applicable for header detection
	},
	{
		ID:          "password-in-code",
		Name:        "Hardcoded Password",
		Description: "Password in Code or Config",
		Severity:    "HIGH",
		Category:    "Authentication",
		Pattern:     `(?i)(password|passwd|pwd)(['\"]?\s*[:=]\s*['\"]?([^'\"\s]{8,32})['\"]?)`,
		Examples: []string{
			"password = 'super_secret123'",
		},
		MinEntropy: 3.0,
	},
}

// detector holds compiled regex patterns
type detector struct {
	rule    types.Rule
	pattern *regexp.Regexp
}

var detectors []detector

func init() {
	// Compile all regex patterns
	for _, rule := range defaultRules {
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}
		detectors = append(detectors, detector{
			rule:    rule,
			pattern: pattern,
		})
	}
}

// Line runs regex checks on a line
func Line(file string, line int, text string) []types.Finding {
	var findings []types.Finding

	for _, d := range detectors {
		matches := d.pattern.FindAllStringSubmatch(text, -1)
		if len(matches) == 0 {
			continue
		}

		for _, match := range matches {
			secret := match[0]
			if len(match) > 1 {
				secret = match[len(match)-1] // Use the last capture group
			}

			// Calculate entropy and hash
			entropy := calculateEntropy(secret)
			if entropy < d.rule.MinEntropy && d.rule.MinEntropy > 0 {
				continue
			}

			hash := sha256.Sum256([]byte(secret))

			findings = append(findings, types.Finding{
				ID:         generateID(file, line, secret),
				RuleID:     d.rule.ID,
				File:       file,
				Line:       line,
				Secret:     secret,
				SecretType: d.rule.Name,
				Detector:   "regex",
				Category:   d.rule.Category,
				Severity:   d.rule.Severity,
				Entropy:    entropy,
				Hash:       hex.EncodeToString(hash[:]),
				Matches:    []string{secret},
			})
		}
	}

	return findings
}

// generateID creates a unique ID for a finding
func generateID(file string, line int, secret string) string {
	data := []byte(file + string(line) + secret)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes only
}

// calculateEntropy calculates Shannon entropy for a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * (logN(p, 2))
	}

	return entropy
}

// logN returns the logarithm of x in given base b
func logN(x, b float64) float64 {
	if x <= 0 {
		return 0
	}
	return math.Log(x) / math.Log(b)
}
