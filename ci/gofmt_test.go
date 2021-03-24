// +build ci

package ci

import (
	"bytes"
	"go/format"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGofmt(t *testing.T) {
	var (
		needsFormatting []string
		checkedFiles    int
	)

	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if path == ".git" {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		formatted, err := format.Source(content)
		if err != nil {
			return err
		}

		if !bytes.Equal(content, formatted) {
			needsFormatting = append(needsFormatting, strings.TrimPrefix(path, ".."))
		}

		checkedFiles++

		return nil
	})

	if err != nil {
		t.Error(err)
	}

	if len(needsFormatting) > 0 {
		t.Fatalf("The following files are not properlery gofmt'ed: %v", needsFormatting)
	}

	if checkedFiles < 20 {
		t.Fatalf("Expected to check at least 20 files but only checked %d", checkedFiles)
	}
}
