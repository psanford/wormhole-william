package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"io"
)

// RandSideID returns a string appropate for use
// as the Side ID for a client.
func RandSideID() string {
	return RandHex(5)
}

// RandHex generates secure random bytes of byteCount long
// and returns that in hex encoded string format
func RandHex(byteCount int) string {
	buf := make([]byte, byteCount)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(buf)
}

func RandNonce() [NonceSize]byte {
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	return nonce
}

const NonceSize = 24
