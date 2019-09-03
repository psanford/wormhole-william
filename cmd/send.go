package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/psanford/wormhole-william/wormhole"
	"github.com/spf13/cobra"
)

var sendCommand = cobra.Command{
	Use:   "send [WHAT]",
	Short: "Send a text message, file, or directory...",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			sendText()
		} else if len(args) > 1 {
			bail("Too many arguments")
		}

		stat, err := os.Stat(args[0])
		if err != nil {
			bail("Failed to read %s: %s", args[0], err)
		}

		if stat.IsDir() {
			sendDir(args[0])
		} else {
			sendFile(args[0])
		}
	},
}

func sendFile(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		bail("Failed to open %s: %s", filename, err)
	}

	var c wormhole.Client

	ctx := context.Background()
	code, status, err := c.SendFile(ctx, filename, f)
	if err != nil {
		bail("Error sending message: %s", err)
	}

	fmt.Println("On the other computer, please run: wormhole receive")
	fmt.Printf("Wormhole code is: %s\n", code)

	s := <-status

	if s.OK {
		fmt.Println("file sent")
	} else {
		bail("Send error: %s", s.Error)
	}
}

func sendDir(dirpath string) {
	dirpath = strings.TrimSuffix(dirpath, "/")

	stat, err := os.Stat(dirpath)
	if err != nil {
		log.Fatal(err)
	}

	if !stat.IsDir() {
		log.Fatalf("%s is not a directory", dirpath)
	}

	prefix, dirname := filepath.Split(dirpath)

	var entries []wormhole.DirectoryEntry

	filepath.Walk(dirpath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		relPath := strings.TrimPrefix(path, prefix)

		entries = append(entries, wormhole.DirectoryEntry{
			Path: relPath,
			Mode: info.Mode(),
			Reader: func() (io.ReadCloser, error) {
				return os.Open(path)
			},
		})

		return nil
	})

	var c wormhole.Client

	ctx := context.Background()
	code, status, err := c.SendDirectory(ctx, dirname, entries)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("On the other computer, please run: wormhole receive")
	fmt.Printf("Wormhole code is: %s\n", code)

	s := <-status

	if s.OK {
		fmt.Println("directory sent")
	} else {
		bail("Send error: %s", s.Error)
	}
}

func sendText() {
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
	fmt.Println("On the other computer, please run: wormhole receive (or wormhole-william recv)")
	fmt.Printf("Wormhole code is: %s\n", code)

	s := <-status

	if s.Error != nil {
		log.Fatalf("Send error: %s", s.Error)
	} else if s.OK {
		fmt.Println("text message sent")
	} else {
		log.Fatalf("Hmm not ok but also not error")
	}
}
