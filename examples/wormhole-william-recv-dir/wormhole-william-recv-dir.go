package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zip"
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
	msg, err := c.Receive(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("got msg: %+v\n", msg)

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	tmpFile, err := ioutil.TempFile(wd, msg.Name+".zip.tmp")
	if err != nil {
		log.Fatal(err)
	}

	defer tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	n, err := io.Copy(tmpFile, msg)
	if err != nil {
		log.Fatal("readfull  error", err)
	}

	zr, err := zip.NewReader(tmpFile, n)
	if err != nil {
		log.Fatalf("Read zip error: %s", err)
	}

	dirName := filepath.Join(wd, msg.Name)
	for _, zf := range zr.File {
		p, err := filepath.Abs(filepath.Join(dirName, zf.Name))
		if err != nil {
			log.Fatalf("Failes to calculate file path ABS: %s", err)
		}

		if !strings.HasPrefix(p, dirName) {
			log.Fatalf("Dangerous filename detected: %s", zf.Name)
		}

		rc, err := zf.Open()
		if err != nil {
			log.Fatalf("Failed to open file in zip: %s %s", zf.Name, err)
		}

		dir := filepath.Dir(p)
		err = os.MkdirAll(dir, 0777)
		if err != nil {
			log.Fatalf("Failed to mkdirall %s: %s", dir, err)
		}

		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zf.Mode())
		if err != nil {
			log.Fatalf("Failed to open %s: %s", p, err)
		}

		_, err = io.Copy(f, rc)
		if err != nil {
			log.Fatalf("Failed to write to %s: %s", p, err)
		}

		err = f.Close()
		if err != nil {
			log.Fatalf("Error closing %s: %s", p, err)
		}

		rc.Close()
	}
}
