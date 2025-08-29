package git

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DiffRange represents a git diff range
type DiffRange struct {
	FromCommit string
	ToCommit   string
}

// DiffFile represents a changed file in a git diff
type DiffFile struct {
	Path     string
	Content  string
	IsBinary bool
	Lines    []DiffLine
}

// DiffLine represents a changed line in a git diff
type DiffLine struct {
	Number  int
	Content string
	Type    DiffType // Added, Deleted, or Context
}

// DiffType represents the type of change in a diff line
type DiffType int

const (
	Added DiffType = iota
	Deleted
	Context
)

// GetDiffFromFile reads diff content from a file
func GetDiffFromFile(path string) ([]*DiffFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading diff file: %w", err)
	}
	return ParseDiff(string(data))
}

// GetDiffBetweenCommits gets diff between two commits
func GetDiffBetweenCommits(repoPath, fromCommit, toCommit string) ([]*DiffFile, error) {
	cmd := exec.Command("git", "-C", repoPath, "diff", fromCommit, toCommit)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("getting git diff: %w", err)
	}
	return ParseDiff(string(output))
}

// GetStagedDiff gets diff of staged changes
func GetStagedDiff(repoPath string) ([]*DiffFile, error) {
	cmd := exec.Command("git", "-C", repoPath, "diff", "--cached")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("getting staged diff: %w", err)
	}
	return ParseDiff(string(output))
}

// ParseDiff parses git diff output into structured format
func ParseDiff(diff string) ([]*DiffFile, error) {
	var files []*DiffFile
	var currentFile *DiffFile

	scanner := bufio.NewScanner(strings.NewReader(diff))
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "diff --git ") {
			// Start of a new file
			if currentFile != nil {
				files = append(files, currentFile)
			}
			currentFile = &DiffFile{}
			continue
		}

		if currentFile == nil {
			continue
		}

		if strings.HasPrefix(line, "--- ") {
			// Old file path
			continue
		}

		if strings.HasPrefix(line, "+++ ") {
			// New file path
			path := strings.TrimPrefix(line, "+++ b/")
			currentFile.Path = path
			continue
		}

		if strings.HasPrefix(line, "@@ ") {
			// Hunk header
			lineNum = parseHunkHeader(line)
			continue
		}

		if len(line) > 0 {
			diffLine := DiffLine{
				Number:  lineNum,
				Content: line[1:], // Remove the first character (+, -, or space)
			}

			switch line[0] {
			case '+':
				diffLine.Type = Added
				lineNum++
			case '-':
				diffLine.Type = Deleted
			case ' ':
				diffLine.Type = Context
				lineNum++
			}

			currentFile.Lines = append(currentFile.Lines, diffLine)
		}
	}

	if currentFile != nil {
		files = append(files, currentFile)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning diff: %w", err)
	}

	return files, nil
}

// parseHunkHeader parses the @@ line to get the starting line number
func parseHunkHeader(header string) int {
	// Example: "@@ -1,7 +1,6 @@"
	parts := strings.Split(header, " ")
	if len(parts) < 2 {
		return 1
	}

	newLinePart := strings.TrimPrefix(parts[2], "+")
	lineNum := strings.Split(newLinePart, ",")[0]
	num := 1
	fmt.Sscanf(lineNum, "%d", &num)
	return num
}

// IsGitRepo checks if the given path is a git repository
func IsGitRepo(path string) bool {
	gitPath := filepath.Join(path, ".git")
	info, err := os.Stat(gitPath)
	return err == nil && info.IsDir()
}

// IsInGitRepo checks if the given path is inside a git repository
func IsInGitRepo(path string) (string, bool) {
	current := path
	for {
		if IsGitRepo(current) {
			return current, true
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", false
}
