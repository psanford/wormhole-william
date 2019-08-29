package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/psanford/wormhole-william/wormhole"
)

func main() {
	var c wormhole.Client

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Text to send: ")
	msg, _ := reader.ReadString('\n')

	msg = msg[:len(msg)-1]

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
