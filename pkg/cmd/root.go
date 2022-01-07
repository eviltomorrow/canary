package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "robber-account",
	Short: "",
	Long:  "  \r\nRobber-account service is running",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {
	rootCmd.CompletionOptions = cobra.CompletionOptions{
		DisableDefaultCmd: true,
	}
}

func NewClient() {

}

func NewServer() {

}
