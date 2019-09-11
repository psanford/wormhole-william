// +build ignore

// This is a tool to assist with tagging versions correctly.
// It updates version/version.go and produces the commands
// to run for git.
//
// To run: go run tag_version.go

package main

import (
	"flag"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/psanford/wormhole-william/version"
)

var updateMajor = flag.Bool("major", false, "update major component")
var updateMinor = flag.Bool("minor", false, "update minor component")
var updatePatch = flag.Bool("patch", true, "update patch component")

func main() {
	flag.Parse()

	err := exec.Command("git", "diff", "--quiet").Run()
	if err != nil {
		log.Fatalf("Cannot run tag_version with pending changes to your working directory: %s", err)
	}

	v := version.AgentVersion

	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		log.Fatalf("Unexpected version format %s", v)
	}

	majorStr := parts[0]
	if majorStr[0] != 'v' {
		log.Fatalf("Unexpected version format (major) %s", v)
	}
	major, err := strconv.Atoi(majorStr[1:])
	if err != nil {
		panic(err)
	}

	minorStr := parts[1]
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		panic(err)
	}

	patchStr := parts[2]
	patch, err := strconv.Atoi(patchStr)
	if err != nil {
		panic(err)
	}

	if *updateMajor {
		major++
		minor = 0
		patch = 0
	} else if *updateMinor {
		minor++
		patch = 0
	} else if *updatePatch {
		patch++
	} else {
		log.Fatal("No update flag specified")
	}

	newVersion := fmt.Sprintf("v%d.%d.%d", major, minor, patch)

	fmt.Printf("newVersion: %s\n", newVersion)

	out, err := exec.Command("gofmt", "-w", "-r", fmt.Sprintf("\"%s\" -> \"%s\"", v, newVersion), "version/version.go").CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to gofmt: %s, %s", err, out)
	}

	fmt.Println("Run:\n")
	fmt.Println("go test ./... &&\\")
	fmt.Printf("git add version/version.go && git commit -m \"Bump version %s => %s\" &&\\\n", v, newVersion)
	fmt.Printf("git tag %s\n", newVersion)

	fmt.Println("\nThen:\n")
	fmt.Println("git push --tags")
}
