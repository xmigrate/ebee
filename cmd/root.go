package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ebee",
	Short: "eBPF CLI tool for system monitoring and analysis",
	Long: `ebee is a command-line tool that leverages eBPF (extended Berkeley Packet Filter) 
to provide real-time system monitoring and analysis capabilities.

Examples:
  ebee rmdetect                    # Monitor file deletions
  ebee execsnoop                   # Monitor process executions
  ebee --help                      # Show help information`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Global flags can be added here
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
}
