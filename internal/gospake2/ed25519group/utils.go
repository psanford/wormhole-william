package ed25519group

import (
	"math/big"
)

func reverse(a []byte) {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
}

func xrecover(y *big.Int) *big.Int {
	var xx, yy, yyM1, dyy, dyy1, invdyy1 big.Int

	// y*y - 1
	yy.Mul(y, y)
	yyM1.Sub(&yy, big.NewInt(1))

	// d * y *y + 1
	dyy.Mul(D, &yy)
	dyy1.Add(&dyy, big.NewInt(1))
	invdyy1.ModInverse(&dyy1, Q)

	// x^2 = y^2 - 1 * (d*y^2 + 1)^-1
	xx.Mul(&yyM1, &invdyy1)

	var grpSqrt, qp3 big.Int

	// (Q +3) .. 8
	qp3.Add(Q, big.NewInt(3))
	grpSqrt.Div(&qp3, big.NewInt(8))

	// x = sqrt(xx) == xx ^ (Q+3) // 8 mod Q
	x := new(big.Int)
	x.Exp(&xx, &grpSqrt, Q)

	// (x*x - xx) % Q == 0
	var xAX, xAxMxx, resMod big.Int
	xAX.Mul(x, x)
	xAxMxx.Sub(&xAX, &xx)
	resMod.Mod(&xAxMxx, Q)

	if resMod.Cmp(big.NewInt(0)) != 0 {
		var xI big.Int
		xI.Mul(x, I)
		x.Mod(&xI, Q)
	}

	if !IsEven(x) {
		x.Sub(Q, x)
	}

	return x

}

// IsEven returns true if x is even and false otherwise
func IsEven(x *big.Int) bool {
	even := new(big.Int)
	// x&1 == 0 for even 1 for odd
	even.And(x, big.NewInt(1))
	if even.Cmp(big.NewInt(0)) == 0 {
		return true
	}

	return false
}
