package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	commit  = "unknown"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Netra v%s (%s)\n", version, commit)
	},
}

// rulesCmd represents the rules command
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage detection rules",
}

// listRulesCmd represents the rules list command
var listRulesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available detection rules",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Implement rules listing
		fmt.Println("Available rules:")
		fmt.Println("  - AWS Access Key")
		fmt.Println("  - AWS Secret Key")
		fmt.Println("  - GitHub Personal Access Token")
		fmt.Println("  - Google API Key")
		fmt.Println("  - Slack Token")
		fmt.Println("  - Generic API Key")
		fmt.Println("  - Private Key")
		fmt.Println("  - Password in Code")
	},
}

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate [path]",
	Short: "Validate a configuration file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: Implement config validation
		fmt.Printf("Validating configuration file: %s\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(validateCmd)

	rulesCmd.AddCommand(listRulesCmd)
}
