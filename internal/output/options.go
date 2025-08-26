package output

// Options represents the output formatting options
type Options struct {
	LLM        bool
	MaxDepth   int
	Threads    int
	MaxSize    int64
	SkipGit    bool
	SkipVendor bool
}
