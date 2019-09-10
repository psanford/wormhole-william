wormhole-william
================

wormhole-william is a go (golang) implementation of [magic wormhole](https://magic-wormhole.readthedocs.io/en/latest/). It provides secure end-to-end encrypted file transfers between computers. The endpoints are connected using the same "wormhole code".

wormhole-william is compatible with the official [python magic wormhole cli tool](https://github.com/warner/magic-wormhole).

Currently, wormhole-william supports:
- sending and receiving text over the wormhole protocol
- sending and receiving files over the transit protocol
- sending and receiving directories over the transit protocol

## Docs

https://godoc.org/github.com/psanford/wormhole-william/wormhole

## CLI Usage

```
$ ./wormhole-william send --help
Send a text message, file, or directory...

Usage:
  wormhole-william send [WHAT] [flags]

Flags:
      --code string       human-generated code phrase
  -c, --code-length int   length of code (in bytes/words)
  -h, --help              help for send
      --hide-progress     supress progress-bar display
  -v, --verify            display verification string (and wait for approval)

Global Flags:
      --relay-url string   rendezvous relay to use


$ ./wormhole-william receive --help
Receive a text message, file, or directory...

Usage:
  wormhole-william receive [code] [flags]

Aliases:
  receive, recv

Flags:
  -h, --help            help for receive
      --hide-progress   supress progress-bar display
  -v, --verify          display verification string (and wait for approval)

Global Flags:
      --relay-url string   rendezvous relay to use
```

## Building the CLI tool

wormhole-william uses go modules so it requires a version of the go tool chain >= 1.11. If you are using a version of go that supports modules you can clone the repo outside of your GOPATH and do a `go build` in the top level directory.

To just install via the go tool run:

```
go get -u github.com/psanford/wormhole-william
```

If you have go 1.12+ installed you can fetch/build/run with a single command:

```
GO111MODULE=on go run github.com/psanford/wormhole-william receive
```

## API Usage

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


	if s.OK {
		fmt.Println("OK!")
	} else {
		log.Fatalf("Send error: %s", s.Error)
	}
}

func recvText(code string) {
	var c wormhole.Client

	ctx := context.Background()
	msg, err := c.Receive(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	if msg.Type != wormhole.TransferText {
		log.Fatalf("Expected a text message but got type %s", msg.Type)
	}

	msgBody, err := ioutil.ReadAll(msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("got message:")
	fmt.Println(msgBody)
}
```

See the [cli tool](https://github.com/psanford/wormhole-william/tree/master/cmd) and [examples](https://github.com/psanford/wormhole-william/tree/master/examples) directory for working examples of how to use the API to send and receive text, files and directories.
