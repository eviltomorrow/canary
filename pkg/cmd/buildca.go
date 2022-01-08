package cmd

import "github.com/spf13/cobra"

var buildCaCmd = &cobra.Command{
	Use:   "build-ca",
	Short: "Build a ca ceritificate",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {
	rootCmd.AddCommand(buildCaCmd)
}
