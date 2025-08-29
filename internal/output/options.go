package output

// Options represents the output formatting options
type Options struct {
	LLM        bool  `json:"llm_enabled"`
	MaxDepth   int   `json:"max_depth"`
	Threads    int   `json:"threads"`
	MaxSize    int64 `json:"max_file_size"`
	SkipGit    bool  `json:"skip_git"`
	SkipVendor bool  `json:"skip_vendor"`
}
