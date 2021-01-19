package cmd

import (
	"os"

	"github.com/psanford/wormhole-william/version"
	"github.com/urfave/cli/v2"
)

var (
	relayURL        string
	verify          bool
	hideProgressBar bool
)

func Run() error {
	app := &cli.App{
		Name:    "wormhole-william",
		Usage:   "Create a wormhole and transfer files through it.",
		Version: version.AgentVersion,
		Description: `Create a (magic) Wormhole and communicate through it.
		
		  Wormholes are created by speaking the same magic CODE in two different
		  places at the same time.  Wormholes are secure against anyone who doesn't
		  use the same code.`,
		Flags: []cli.Flag{&cli.StringFlag{
			Name:        "relay-url",
			Usage:       "rendezvous relay to use",
			Destination: &relayURL,
		}},
		Commands: []*cli.Command{sendCommand(), recvCommand()},
	}

	if relayURL == "" {
		relayURL = os.Getenv("WORMHOLE_RELAY_URL")
	}

	return app.Run(os.Args)
}
