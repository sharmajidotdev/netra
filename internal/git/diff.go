package git

// Hunk represents a changed line from a git diff
type Hunk struct {
	File   string
	LineNo int
	Text   string
}

// ParseUnifiedDiff parses a diff file (stub)
func ParseUnifiedDiff(path string) ([]Hunk, error) {
	// TODO: Implement diff parsing
	return []Hunk{}, nil
}
