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
		fmt.Fprintf(os.Stderr, "usage: %s <file>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	var c wormhole.Client

	ctx := context.Background()
	code, status, err := c.SendFile(ctx, filename, f)
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
