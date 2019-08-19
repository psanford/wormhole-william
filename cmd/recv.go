package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var recvCommand = cobra.Command{
	Use:   "recv [code]",
	Short: "Receive a text message, file, or directory...",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Recv using code %s\n", args[0])
	},
}
