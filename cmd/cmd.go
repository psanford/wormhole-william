package cmd

import (
	"os"

	"github.com/psanford/wormhole-william/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "wormhole-william",
	Short:   "Create a wormhole and transfer files through it.",
	Version: version.AgentVersion,
	Long: `Create a (magic) Wormhole and communicate through it.

  Wormholes are created by speaking the same magic CODE in two different
  places at the same time. Wormholes are secure against anyone who doesn't
  use the same code.`,
}

var (
	relayURL        string
	verify          bool
	hideProgressBar bool
)

func Execute() error {
	rootCmd.PersistentFlags().StringVar(&relayURL, "relay-url", "", "rendezvous relay to use")
	if relayURL == "" {
		relayURL = os.Getenv("WORMHOLE_RELAY_URL")
	}

	rootCmd.AddCommand(recvCommand())
	rootCmd.AddCommand(sendCommand())
	rootCmd.AddCommand(completionCommand())
	return rootCmd.Execute()
}
