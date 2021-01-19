package main

import (
	"fmt"
	"os"

	"github.com/psanford/wormhole-william/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
