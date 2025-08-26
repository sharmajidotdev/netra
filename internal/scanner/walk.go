package scanner

import "os"

// listFiles walks files in input paths (stub for now)
func listFiles(inputs []string, excludes []string) ([]string, error) {
	// TODO: Implement proper file walking
	for _, i := range inputs {
		if _, err := os.Stat(i); err != nil {
			return nil, err
		}
	}
	return inputs, nil
}
