// +build ignore

// This is a tool to assist with building release artifacts.
// It is run automatically from github actions to produce the
// artifacts.
//
// Instructions for cutting a new release:
// - Update version/version.go
// - Make new git tag (e.g. v1.0.x)
// - Push tag to github
// - Github release.yml action will `go run build_release.go` at that tag

package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/psanford/wormhole-william/version"
)

var ignoreTagMismatch = flag.Bool("ignore-tag-mismatch", false, "Don't check if current tag matches in code version")

func main() {
	flag.Parse()
	if !*ignoreTagMismatch {
		checkTagMatchesVersion()
	}
	os.MkdirAll("release", 0777)

	for _, t := range targets {
		cmd := exec.Command("go", "build", "-trimpath", "-o", filepath.Join("release", t.binaryName()))
		env := []string{"GOOS=" + t.goos, "GOARCH=" + t.garch, "GO111MODULE=on"}
		if t.goarm != "" {
			env = append(env, "GOARM="+t.goarm)
		}
		cmd.Env = append(os.Environ(), env...)

		fmt.Printf("run: %s %s %s\n", strings.Join(env, " "), cmd.Path, strings.Join(cmd.Args[1:], " "))

		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %s err: %s, out: %s\n", t.goos, t.garch, err, out)
			os.Exit(1)
		}
	}
}

func checkTagMatchesVersion() {
	codeVersion := version.AgentVersion
	headSha := gitCmd("rev-parse", "HEAD")
	tagSha := gitCmd("rev-parse", codeVersion)
	if headSha != tagSha {
		log.Fatalf("Tag for %s does not match HEAD ref: HEAD:%s TAG:%s", codeVersion, headSha, tagSha)
	}
}

func gitCmd(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		log.Fatalf("git %s failed: %s", args, err)
	}
	return string(bytes.TrimSpace(out))
}

type target struct {
	goos  string
	garch string
	goarm string
}

func (t *target) binaryName() string {
	ext := ""
	if t.goos == "windows" {
		ext = ".exe"
	}

	tmpl := "wormhole-william-%s-%s%s%s"
	return fmt.Sprintf(tmpl, t.goos, t.garch, t.goarm, ext)
}

var targets = []target{
	{"linux", "amd64", ""},
	{"linux", "arm64", ""},
	{"linux", "arm", "5"},
	{"linux", "arm", "6"},
	{"linux", "arm", "7"},
	{"darwin", "amd64", ""},
	{"windows", "386", ""},
	{"freebsd", "amd64", ""},
}
