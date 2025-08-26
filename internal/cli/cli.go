package cli

import (
	"fmt"
	"os"
)

// Options holds CLI flags (expand later)
type Options struct {
	Inputs   []string
	Json     bool
	Human    bool
	LLM      bool
	Explain  bool
	Sarif    bool
	ExitOn   string
	DiffFile string
}

// Execute is the entrypoint for CLI handling
func Execute() {
	// TODO: Replace with real flag parsing (cobra/pflag)
	fmt.Println("netra: CLI not implemented yet")
	os.Exit(0)
}
