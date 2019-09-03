package main

import (
	"context"
	"fmt"
	"io"
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

	var c wormhole.Client

	ctx := context.Background()
	fileInfo, err := c.Receive(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("got msg: %+v\n", fileInfo)

	_, err = io.Copy(os.Stdout, fileInfo)
	if err != nil {
		log.Fatal("readfull  error", err)
	}
}
