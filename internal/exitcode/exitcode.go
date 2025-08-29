package exitcode

// Exit codes
const (
	Success         = 0
	Error           = 1
	ConfigError     = 2
	ScanError       = 3
	ValidationError = 4
)

// Severity levels
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// ExitLevel represents the level at which to exit with non-zero code
type ExitLevel int

const (
	ExitOnHigh ExitLevel = iota
	ExitOnMedium
	ExitOnLow
)

// ParseExitLevel converts a string to ExitLevel
func ParseExitLevel(level string) ExitLevel {
	switch level {
	case High:
		return ExitOnHigh
	case Medium:
		return ExitOnMedium
	case Low:
		return ExitOnLow
	default:
		return ExitOnHigh // Default to high for safety
	}
}

// ShouldExit determines if we should exit with error based on finding severity and configured exit level
func ShouldExit(findingSeverity string, configuredLevel ExitLevel) bool {
	severityLevel := ParseExitLevel(findingSeverity)

	// If finding severity is higher or equal to configured level, exit with error
	return severityLevel <= configuredLevel
}

// GetHighestSeverity returns the highest severity from a list of findings
func GetHighestSeverity(findings []string) string {
	highest := Low

	for _, severity := range findings {
		switch severity {
		case High:
			return High // Can return immediately as nothing is higher
		case Medium:
			highest = Medium
		}
	}

	return highest
}
