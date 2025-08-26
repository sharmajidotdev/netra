package output

import (
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

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
	bold    = color.New(color.Bold).SprintFunc()
)

const findingTemplate = `
{{.Marker}} {{.ColoredSeverity}} secret found in {{.ColoredFile}}
   Location: {{.File}}:{{.Line}}
   Type: {{.SecretType}}
   Category: {{.Category}}
{{if .IsValidated}}   Validation: {{.ValidationStatus}} ({{printf "%.2f%%" .Confidence}})
{{if .Reason}}   Reasoning: {{.Reason}}{{end}}{{end}}
{{if .Context}}
   Context:
{{.Context}}{{end}}
`

// FindingData holds template data for a finding
type FindingData struct {
	*types.Finding
	Marker           string
	ColoredSeverity  string
	ColoredFile      string
	IsValidated      bool
	ValidationStatus string
}

// WriteHuman prints findings in a human-readable format with colors and formatting
func WriteHuman(res *types.Result, showBanner bool) error {
	if showBanner {
		writeBanner()
	}

	tmpl, err := template.New("finding").Parse(findingTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if len(res.Findings) == 0 {
		fmt.Println(green("✓ No secrets found"))
	} else {
		// Process findings
		for _, f := range res.Findings {
			data := prepareFindingData(&f)
			if err := tmpl.Execute(os.Stdout, data); err != nil {
				return fmt.Errorf("failed to execute template: %w", err)
			}
		}
	}

	// Print summary
	writeSummary(res)
	return nil
}

// prepareFindingData prepares finding data for the template
func prepareFindingData(f *types.Finding) *FindingData {
	var severityColor func(a ...interface{}) string
	switch strings.ToUpper(f.Severity) {
	case "HIGH":
		severityColor = red
	case "MEDIUM":
		severityColor = yellow
	case "LOW":
		severityColor = blue
	default:
		severityColor = green
	}

	data := &FindingData{
		Finding:     f,
		Marker:      "🔍",
		ColoredFile: magenta(f.File),
		IsValidated: f.ValidatedAt != nil,
	}

	data.ColoredSeverity = severityColor(f.Severity)

	if data.IsValidated {
		if f.IsValid {
			data.ValidationStatus = red("✗ Likely Real Secret")
		} else {
			data.ValidationStatus = green("✓ Likely False Positive")
		}
	}

	return data
}

// writeBanner prints the tool banner
func writeBanner() {
	banner := `
    _   __    __           
   / | / /___/ /__________ 
  /  |/ / __  / ___/ ___/ 
 / /|  / /_/ / /  / /     
/_/ |_/\__,_/_/  /_/      
                          
`
	fmt.Print(blue(banner))
	fmt.Printf("%s %s\n", magenta("Secret Scanner"), magenta("v1.0.0"))
	fmt.Printf("Copyright (c) %d\n\n", time.Now().Year())
}

// writeSummary prints scan summary
func writeSummary(res *types.Result) {
	fmt.Printf("\n📊 %s\n", bold("Scan Summary:"))
	fmt.Printf("   Files Scanned: %d\n", res.Stats.FilesScanned)
	fmt.Printf("   Files Skipped: %d\n", res.Stats.FilesSkipped)
	fmt.Printf("   Secrets Found: %s\n", red(fmt.Sprintf("%d", res.Stats.Findings)))
	fmt.Printf("   Duration: %.2fs\n", float64(res.Stats.DurationMs)/1000)

	if res.Stats.ValidationTime > 0 {
		fmt.Printf("   Validation Time: %.2fs\n", res.Stats.ValidationTime.Seconds())
	}

	// Group findings by severity
	high, medium, low := 0, 0, 0
	for _, f := range res.Findings {
		switch strings.ToUpper(f.Severity) {
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}

	if res.Stats.Findings > 0 {
		fmt.Printf("\n   %s\n", bold("By Severity:"))
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
