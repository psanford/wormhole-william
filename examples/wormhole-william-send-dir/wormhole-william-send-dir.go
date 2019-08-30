package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/psanford/wormhole-william/wormhole"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <directory>\n", os.Args[0])
		os.Exit(1)
	}

	dirpath := os.Args[1]

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

	if s.Error != nil {
		log.Fatalf("Send error: %s", s.Error)
	} else if s.OK {
		fmt.Println("OK!")
	} else {
		log.Fatalf("Hmm not ok but also not error")
	}
}
