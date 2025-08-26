package scanner

import (
	"strings"

	"github.com/sharmajid16/netra/internal/git"
	"github.com/sharmajid16/netra/pkg/types"
)

// DiffScanner scans git diffs for secrets
type DiffScanner struct {
	scanner *Scanner
}

// NewDiffScanner creates a new DiffScanner
func NewDiffScanner(opts ...Option) *DiffScanner {
	return &DiffScanner{
		scanner: New(opts...),
	}
}

// ScanDiffFile scans a git diff file for secrets
func (ds *DiffScanner) ScanDiffFile(path string) (*types.Result, error) {
	files, err := git.GetDiffFromFile(path)
	if err != nil {
		return nil, err
	}
	return ds.scanDiffFiles(files)
}

// ScanStagedChanges scans staged git changes for secrets
func (ds *DiffScanner) ScanStagedChanges(repoPath string) (*types.Result, error) {
	files, err := git.GetStagedDiff(repoPath)
	if err != nil {
		return nil, err
	}
	return ds.scanDiffFiles(files)
}

// ScanCommitRange scans changes between two commits for secrets
func (ds *DiffScanner) ScanCommitRange(repoPath, fromCommit, toCommit string) (*types.Result, error) {
	files, err := git.GetDiffBetweenCommits(repoPath, fromCommit, toCommit)
	if err != nil {
		return nil, err
	}
	return ds.scanDiffFiles(files)
}

// scanDiffFiles scans a list of diff files for secrets
func (ds *DiffScanner) scanDiffFiles(files []*git.DiffFile) (*types.Result, error) {
	result := &types.Result{
		Stats: &types.Stats{},
	}

	for _, file := range files {
		// Skip binary files
		if file.IsBinary {
			result.Stats.FilesSkipped++
			continue
		}

		// Reconstruct the content from added/context lines
		var content strings.Builder
		lineMap := make(map[int]int) // Maps file line numbers to content line numbers
		currentLine := 1

		for _, line := range file.Lines {
			if line.Type != git.Deleted {
				lineMap[line.Number] = currentLine
				content.WriteString(line.Content)
				content.WriteRune('\n')
				currentLine++
			}
		}

		// Scan the reconstructed content
		findings, err := ds.scanner.scanContent(file.Path, content.String())
		if err != nil {
			return nil, err
		}

		// Update line numbers based on the diff
		for i := range findings {
			if newLine, ok := lineMap[findings[i].Line]; ok {
				findings[i].Line = newLine
			}
		}

		result.Findings = append(result.Findings, findings...)
		result.Stats.FilesScanned++
	}

	return result, nil
}
