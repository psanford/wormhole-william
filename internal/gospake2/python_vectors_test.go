package gospake2

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

// Exchanges recorded from python-spake2 0.9 (what the wormhole CLI uses),
// chosen so that an element's 32-byte little-endian encoding ends in a zero
// byte: our own message in one, the shared element K in the other.
var pythonSymmetricVectors = []struct {
	zeroTopByte, password, scalar, ourMsg, peerMsg, key string
}{
	{"key", "208-guitarist-revenge", "6485487357952699380016374735734548472177072072108719038839059370176415877568", "535ee9833f7279eef47b7e995294fa79602ceed04e2492101746c162b98e703324", "538c54f616367e705af5bb6f2f8ddf9890b4519c8fcb462c13bd45acf51e79c7f5", "ad2d9dc1ae62eabdc784a84f75abd1fcd598661763690f7cfa20bdb2651c04ef"},
	{"message", "315-guitarist-revenge", "927706291011165667635425598714659712457778887641391835826577945044718856476", "53c2b9a067e3f394e92b8712a1ac9d4ccdea39ec0451b8b7aea4a8ca442fc98900", "5318c176811ba455aee0bbf26549723750b50df3e851f3f78010a1a449bf286feb", "61e5392e02947f8247bacbf26a57af364b852f3e8c2669a7dce7e6674d684bdd"},
}

func TestSymmetricMatchesPythonWithZeroTopByte(t *testing.T) {
	for _, v := range pythonSymmetricVectors {
		t.Run(v.zeroTopByte, func(t *testing.T) {
			x, _ := new(big.Int).SetString(v.scalar, 10)
			s := SPAKE2Symmetric(NewPassword(v.password), NewIdentityS("lothar.com/wormhole/text-or-file-xfer"))
			s.setXyScalar(x)
			if got := hex.EncodeToString(s.Start()); got != v.ourMsg {
				t.Fatalf("message = %s, want %s", got, v.ourMsg)
			}
			peer, _ := hex.DecodeString(v.peerMsg)
			key, err := s.Finish(peer)
			if err != nil {
				t.Fatal(err)
			}
			if want, _ := hex.DecodeString(v.key); !bytes.Equal(key, want) {
				t.Fatalf("key = %x, want %s", key, v.key)
			}
		})
	}
}
