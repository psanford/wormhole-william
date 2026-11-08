package integergroup

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
)

func expandArbitraryElementSeed(data []byte, numbytes int) ([]byte, error) {
	info := []byte("SPAKE2 arbitrary element")
	hkdfReader := hkdf.New(sha256.New, data, []byte(""), info)
	expandedData := make([]byte, numbytes)
	n, err := io.ReadFull(hkdfReader, expandedData)

	if err != nil {
		return nil, err
	}

	if n != numbytes {
		return nil, fmt.Errorf(
			"Failed to read %d bytes, only read: %d bytes", numbytes, n)
	}

	return expandedData, nil
}

func unbiasedRandRange(start, stop *big.Int) (*big.Int, error) {
	var maxVal big.Int
	maxVal.Sub(stop, start)

	return rand.Int(rand.Reader, &maxVal)
}
