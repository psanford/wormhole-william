package ed25519group

import (
	"math/big"
)

func q() *big.Int {
	q := new(big.Int)
	v := new(big.Int)

	// Calculate 2^255
	v.Exp(big.NewInt(2), big.NewInt(255), nil)

	// calculate 2^255 - 19
	q.Sub(v, big.NewInt(19))
	return q
}

func l() *big.Int {
	l := new(big.Int)
	v := new(big.Int)
	s := new(big.Int)

	// Calculate 2^252
	v.Exp(big.NewInt(2), big.NewInt(252), nil)

	// Value to add to v to get o
	s.SetString("27742317777372353535851937790883648493", 0)

	l.Add(v, s)
	return l
}

func d() *big.Int {
	d := new(big.Int)
	inv12166 := new(big.Int)

	inv12166.ModInverse(big.NewInt(121666), Q)
	// d = -121665 * inv(121666)
	d.Mul(big.NewInt(-121665), inv12166)
	return d
}

func by() *big.Int {
	fiveInv := new(big.Int)
	fiveInv.ModInverse(big.NewInt(5), Q)

	// By = 4 * inv(5)
	by := new(big.Int)
	by.Mul(big.NewInt(4), fiveInv)
	return by
}

func bx() *big.Int {
	return xrecover(By)
}

func i() *big.Int {
	q := new(big.Int)
	q.Sub(Q, big.NewInt(1))
	q.Div(q, big.NewInt(4))

	i := new(big.Int)
	i.Exp(big.NewInt(2), q, Q)
	return i
}

func b() AffinePoint {
	x := new(big.Int)
	y := new(big.Int)
	x.Mod(Bx, Q)
	y.Mod(By, Q)
	return AffinePoint{x, y}
}

func base() ExtendedPoint {
	return B.ToExtended()
}

func extendedZero() ExtendedPoint {
	z := AffinePoint{big.NewInt(0), big.NewInt(1)}
	return z.ToExtended()
}

func twoD() *big.Int {
	twoD := new(big.Int)
	twoD.Mul(big.NewInt(2), D)
	return twoD
}

var (
	// Q is the order of group which is 2^255 - 19
	Q = q()

	// L is the order of subgroup which is 2^252 + 27742317777372353535851937790883648493
	L = l()

	// D is a constant TODO: fix the documentation
	D = d()

	// 2*D calculated to speed things up a bit
	d2 = twoD()

	// By is y co-ordinate of base point
	By = by()

	// Bx is X co-ordinate of the base point
	Bx = bx()

	// I is constant TODO fix the documentation
	I = i()

	// B is curve base point (generator point) in Affine form
	B = b()

	// Base is curve base point (generator point) in extended form
	Base = base()

	// Zero is identity element in extended co-ordinate system
	Zero = extendedZero()
)
