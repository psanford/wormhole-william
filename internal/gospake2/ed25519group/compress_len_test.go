package ed25519group

import (
	"math/big"
	"testing"
)

func TestElementToBytesIsAlways32Bytes(t *testing.T) {
	var e Ed25519
	short := 0
	for k := int64(1); k <= 2000; k++ {
		p := e.BasePointMult(big.NewInt(k)).(ExtendedPoint)
		a := p.ToAffine()
		if len(a.Compress()) != 32 {
			short++
		}
	}
	if short != 0 {
		t.Fatalf("%d of 2000 points encoded to fewer than 32 bytes", short)
	}
}
