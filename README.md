# wormhole

wormhole is a Go (golang) implementation of [magic wormhole](https://magic-wormhole.readthedocs.io/en/latest/). It provides secure end-to-end encrypted file transfers between computers. The endpoints are connected using the same "wormhole code".

wormhole is compatible with the official [python magic wormhole cli tool](https://github.com/warner/magic-wormhole).

Currently, wormhole supports:
- sending and receiving text over the wormhole protocol
- sending and receiving files over the transit protocol
- sending and receiving directories over the transit protocol

## Docs

https://pkg.go.dev/github.com/konamata/wormhole/wormhole?tab=doc

## CLI Usage

```
$ wormhole send --help
Send a text message, file, or directory...

Usage:
  wormhole send [WHAT] [flags]

Flags:
      --code string       human-generated code phrase
  -c, --code-length int   length of code (in bytes/words)
  -h, --help              help for send
      --hide-progress     suppress progress-bar display
  -v, --verify            display verification string (and wait for approval)

Global Flags:
      --relay-url string   rendezvous relay to use


$ wormhole receive --help
Receive a text message, file, or directory...

Usage:
  wormhole receive [code] [flags]

Aliases:
  receive, recv

Flags:
  -h, --help            help for receive
      --hide-progress   suppress progress-bar display
  -v, --verify          display verification string (and wait for approval)

Global Flags:
      --relay-url string   rendezvous relay to use
```

### CLI tab completion

The wormhole CLI supports shell completion, including completing the receive code.
To enable shell completion follow the instructions from `wormhole shell-completion -h`.


## Building the CLI tool

wormhole uses go modules so it requires a version of the go tool chain >= 1.11. If you are using a version of go that supports modules you can clone the repo outside of your GOPATH and do a `go build` in the top level directory.

To just install via the go tool run:

```
go install github.com/konamata/wormhole@latest
```

## API Usage

Sending text:

```go
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/konamata/wormhole/wormhole"
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

See the [cli tool](https://github.com/konamata/wormhole/tree/master/cmd) and [examples](https://github.com/konamata/wormhole/tree/master/examples) directory for working examples of how to use the API to send and receive text, files and directories.

## Third Party Users of Wormhole William

- [rymdport](https://github.com/Jacalz/rymdport): A cross-platform Magic Wormhole graphical user interface
- [riftshare](https://github.com/achhabra2/riftshare): Desktop filesharing app
- [termshark](https://github.com/gcla/termshark): A terminal UI for tshark
- [tmux-wormhole](https://github.com/gcla/tmux-wormhole): tmux wormhole integration
- [wormhole-mobile](https://github.com/konamata/wormhole-mobile): Android wormhole app
