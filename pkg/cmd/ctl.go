package cmd

import (
	"github.com/spf13/cobra"
)

var ctlCmd = &cobra.Command{
	Use:   "canary-ctl",
	Short: "",
	Long:  "  \r\nCanary-ctl is client",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	ctlCmd.CompletionOptions = cobra.CompletionOptions{
		DisableDefaultCmd: true,
	}
}

func NewClient() {
	isServer = false
	cobra.CheckErr(ctlCmd.Execute())
}
