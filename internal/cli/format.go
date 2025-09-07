package cli

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/sharmajidotdev/netra/pkg/types"
)

var (
	// Color outputs
	red     = color.New(color.FgRed).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	blue    = color.New(color.FgBlue).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
)

// formatHumanOutput formats findings for human-readable output
func formatHumanOutput(finding *types.Finding) string {
	var b strings.Builder

	// Format severity with color
	var severityColor func(a ...interface{}) string
	switch strings.ToUpper(finding.Severity) {
	case "HIGH":
		severityColor = red
	case "MEDIUM":
		severityColor = yellow
	case "LOW":
		severityColor = blue
	default:
		severityColor = green
	}

	// Build the output
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("🔍 %s secret found in %s\n",
		severityColor(finding.Severity),
		magenta(finding.File)))

	b.WriteString(fmt.Sprintf("   Location: %s:%d\n", finding.File, finding.Line))
	b.WriteString(fmt.Sprintf("   Type: %s\n", finding.SecretType))
	b.WriteString(fmt.Sprintf("   Category: %s\n", finding.Category))

	if finding.ValidatedAt != nil {
		if finding.IsValid {
			b.WriteString(fmt.Sprintf("   Validation: %s (%.2f%% confidence)\n",
				red("✗ Likely Real Secret"),
				finding.Confidence*100))
		} else {
			b.WriteString(fmt.Sprintf("   Validation: %s (%.2f%% confidence)\n",
				green("✓ Likely False Positive"),
				finding.Confidence*100))
		}

		if finding.Reason != "" {
			b.WriteString(fmt.Sprintf("   Reasoning: %s\n", finding.Reason))
		}
	}

	// Show context if available
	if finding.Context != "" {
		b.WriteString("\n   Context:\n")
		b.WriteString(fmt.Sprintf("   %s\n", finding.Context))
	}

	return b.String()
}

// showProgressBar displays a progress bar during scanning
func showProgressBar(current, total int) {
	const width = 40
	if total == 0 {
		total = 1 // Avoid division by zero
	}

	filled := int(float64(current) / float64(total) * float64(width))
	if filled > width {
		filled = width
	}

	empty := width - filled

	fmt.Printf("\r[%s%s] %d/%d files",
		strings.Repeat("=", filled),
		strings.Repeat(" ", empty),
		current,
		total)
}

// showSummary displays a summary of the scan results
func showSummary(result *types.Result) {
	fmt.Printf("\n\n📊 Scan Summary:\n")
	// TODO : stats enable karo
	fmt.Printf("   Files Scanned: %d\n", result.Stats.FilesScanned)
	fmt.Printf("   Files Skipped: %d\n", result.Stats.FilesSkipped)
	fmt.Printf("   Secrets Found: %s\n", red(result.Stats.Findings))
	fmt.Printf("   Duration: %.2fs\n", float64(result.Stats.Duration)/1000)

	if result.Stats.ValidationTime > 0 {
		fmt.Printf("   Validation Time: %.2fs\n", result.Stats.ValidationTime.Seconds())
	}

	// Group findings by severity
	high, medium, low := 0, 0, 0
	for _, f := range result.Findings {
		switch strings.ToUpper(f.Severity) {
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}

	// TODO : stats enable karo
	if result.Stats.Findings > 0 {
		fmt.Printf("\n   By Severity:\n")
		if high > 0 {
			fmt.Printf("   - %s: %d\n", red("HIGH"), high)
		}
		if medium > 0 {
			fmt.Printf("   - %s: %d\n", yellow("MEDIUM"), medium)
		}
		if low > 0 {
			fmt.Printf("   - %s: %d\n", blue("LOW"), low)
		}
	}
}

// showBanner displays the tool banner
func showBanner() {
	banner := `
    _   __         __                 
   / | / /  ___   / /_   _____  ____ 
  /  |/ /  / _ \ / __/  / ___/ / __ \/
 / /|  /  /  __// /_   / /    / /_/ / 
/_/ |_/   \___/ \__/  /_/     \__,_/  
                                      
                          
`
	fmt.Print(blue(banner))
	fmt.Println(magenta("Secret Scanner v1.0.0"))
	fmt.Println("Copyright (c) 2025")
	fmt.Println()
}
