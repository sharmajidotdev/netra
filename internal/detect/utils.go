package detect

// makeID creates a unique ID for a finding
func makeID(file string, line int, rule string) string {
	return file + ":" + rule
}
