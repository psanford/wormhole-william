package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/psanford/wormhole-william/wormhole"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <code>\n", os.Args[0])
		os.Exit(1)
	}

	code := os.Args[1]

	c := wormhole.NewClient()

	ctx := context.Background()
	msg, err := c.RecvText(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("got message:")
	fmt.Println(msg)
}
