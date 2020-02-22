// +build ignore

// This is a tool to assist with building release artifacts.
//
// Instructions for cutting a new release:
// - Update version/version.go
// - Make new git tag
// - Run: go run build_release.go

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type target struct {
	goos  string
	garch string
}

func (t *target) binaryName() string {
	tmpl := "wormhole-william-%s-%s%s"
	ext := ""
	if t.goos == "windows" {
		ext = ".exe"
	}

	return fmt.Sprintf(tmpl, t.goos, t.garch, ext)
}

var targets = []target{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"windows", "386"},
	{"freebsd", "amd64"},
}

func main() {
	os.MkdirAll("release", 0777)

	for _, t := range targets {
		cmd := exec.Command("go", "build", "-o", filepath.Join("release", t.binaryName()))
		env := []string{"GOOS=" + t.goos, "GARCH=" + t.garch, "GO111MODULE=on"}
		cmd.Env = append(os.Environ(), env...)

		fmt.Printf("run: %s %s %s\n", strings.Join(env, " "), cmd.Path, strings.Join(cmd.Args, " "))

		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %s err: %s, out: %s\n", t.goos, t.garch, err, out)
			os.Exit(1)
		}
	}
}
