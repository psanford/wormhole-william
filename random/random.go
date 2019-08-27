package random

import (
	"crypto/rand"
	"fmt"
	"io"
)

// SideID returns a string appropate for use
// as the Side ID for a client.
func SideID() string {
	return Hex(5)
}

// Hex generates secure random bytes of byteCount long
// and returns that in hex encoded string format
func Hex(byteCount int) string {
	buf := make([]byte, byteCount)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("%x", buf)
}
