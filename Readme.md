wormhole-william
================

wormhole-william is a go (golang) implementation of [magic wormhole](https://magic-wormhole.readthedocs.io/en/latest/). The goal is to be compatible with the [python magic wormhole cli tool](https://github.com/warner/magic-wormhole).

Currently, wormhole-william supports:
- sending and receiving text over the wormhole protocol
- sending and receiving files over the transit protocol
- sending and receiving directories over the transit protocol

## Docs

https://godoc.org/github.com/psanford/wormhole-william/wormhole

## Usage

Sending text:
```
package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/psanford/wormhole-william/wormhole"
)

func sendText() {
	var c wormhole.Client

	msg := "Dillinger-entertainer"

	ctx := context.Background()

	code, status, err := c.SendText(ctx, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("On the other computer, please run: wormhole receive")
	fmt.Printf("Wormhole code is: %s\n", code)

	s := <-status

	if s.Error != nil {
		log.Fatalf("Send error: %s", s.Error)
	} else if s.OK {
		fmt.Println("OK!")
	} else {
		log.Fatalf("Hmm not ok but also not error")
	}
}

func recvText(code string) {
	var c wormhole.Client

	var c wormhole.Client

	ctx := context.Background()
	msg, err := c.RecvText(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("got message:")
	fmt.Println(msg)
}
```

See the examples directory for working examples of how to use the API to send and receive text, files and directories.

## API status

The API is still experimental and so is subject to breaking changes.
