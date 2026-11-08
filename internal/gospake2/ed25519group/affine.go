package ed25519group

import (
	"fmt"
	"math/big"
)

// AffinePoint is original representation of points on twisted edwards curve
type AffinePoint struct {
	X, Y *big.Int
}

// NotOnCurve is error emmited when the point got is not on the curve
type NotOnCurve struct{}

func (n *NotOnCurve) Error() string {
	return "decoded point is not on curve"
}

// NewAffinePoint creates new affine point with big integer's given in string
// format and of provided base.
func NewAffinePoint(x, y string, base int) AffinePoint {
	X := new(big.Int)
	Y := new(big.Int)

	X.SetString(x, base)
	Y.SetString(y, base)

	return AffinePoint{X, Y}
}

func (a AffinePoint) String() string {
	return fmt.Sprintf("X: %s\nY: %s\n", a.X, a.Y)
}

// ToExtended converts AffinePoint to ExtendedPoint representation
func (a *AffinePoint) ToExtended() ExtendedPoint {
	X := new(big.Int)
	Y := new(big.Int)
	T := new(big.Int)
	xy := new(big.Int)

	X.Mod(a.X, Q)
	Y.Mod(a.Y, Q)

	Z := big.NewInt(1)

	// T = x*y % Q
	xy.Mul(a.X, a.Y)
	T.Mod(xy, Q)

	return ExtendedPoint{X, Y, Z, T}

}

// IsOnCurve returns true if the given point is on curve
func (a *AffinePoint) IsOnCurve() bool {
	x, y := a.X, a.Y
	var mxx, xx, yy, mxxpyy, dxxyy, xxyy, minusX big.Int

	// -x
	minusX.Neg(x)
	// -x *x
	mxx.Mul(&minusX, x)

	// x*x
	xx.Mul(x, x)

	// y*y
	yy.Mul(y, y)

	// -x*x + y*y
	mxxpyy.Add(&mxx, &yy)

	// x^2*y^2
	xxyy.Mul(&xx, &yy)

	// dx^2y^2
	dxxyy.Mul(D, &xxyy)

	var equation big.Int
	// -x^2 + y^2 - 1 - dx^2y^2
	equation.Sub(mxxpyy.Sub(&mxxpyy, big.NewInt(1)), &dxxyy)

	var result big.Int
	result.Mod(&equation, Q)
	// Point is on curve if -x^2 + y^2 - 1 - dx^2y^2 % Q == 0
	if result.Cmp(big.NewInt(0)) == 0 {
		return true
	}

	return false
}

// Compress encodes the Affine Point into 32 byte little-endian b255 is the sign
func (a *AffinePoint) Compress() []byte {
	x, y := a.X, a.Y

	result := new(big.Int)
	if !IsEven(x) {
		// We need y += 1 << 255
		var lsh big.Int
		lsh.Lsh(big.NewInt(1), 255)
		result.Add(y, &lsh)

	} else {
		result = y
	}

	resultBytes := result.Bytes()
	reverse(resultBytes)
	return resultBytes
}

// Decompress reconstructs the AffinePoint from given 32 byte which is
// considered as Y co-ordinate compressed using Compress function above
func (a *AffinePoint) Decompress(s []byte) error {
	var clamp, oneShift big.Int

	// (1 << 255) - 1
	oneShift.Lsh(big.NewInt(1), 255)
	clamp.Sub(&oneShift, big.NewInt(1))

	// TODO check if bytes is more than 32 then we should throw error
	b := make([]byte, len(s))
	copy(b, s)

	// Reversing is not required?. If I reverse the test fails may be
	// because big.Int represents alredy in big endian?.
	reverse(b)

	unclamped := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)

	unclamped.SetBytes(b)
	y.And(unclamped, &clamp)

	x = xrecover(y)
	var isXEven big.Int

	isXEven.And(x, big.NewInt(1))
	unclamped.And(unclamped, &oneShift)

	if isXEven.Cmp(unclamped) != 0 {
		x.Sub(Q, x)
	}

	a.X = x
	a.Y = y

	if !a.IsOnCurve() {
		return &NotOnCurve{}
	}

	return nil
}
