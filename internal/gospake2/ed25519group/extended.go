package ed25519group

import (
	"bytes"
	"fmt"
	"math/big"
	group "salsa.debian.org/vasudev/gospake2/groups"
)

// ExtendedPoint represents co-ordinate on twisted edwards curve derived from Affine Points
type ExtendedPoint struct {
	X, Y, Z, T *big.Int
}

// NewExtendedPoint creates ExtendedPoint with given x,y,z,t arguments as string
// and base of the integer
func NewExtendedPoint(x, y, z, t string, base int) ExtendedPoint {
	X := new(big.Int)
	Y := new(big.Int)
	Z := new(big.Int)
	T := new(big.Int)

	X.SetString(x, base)
	Y.SetString(y, base)
	Z.SetString(z, base)
	T.SetString(t, base)

	return ExtendedPoint{X, Y, Z, T}
}

func (e ExtendedPoint) String() string {
	return fmt.Sprintf("X: %s\nY: %s\nZ: %s\nT: %s\n", e.X,
		e.Y, e.Z, e.T)
}

// ToAffine converts ExtendedPoint back to AffinePoint representation
func (e *ExtendedPoint) ToAffine() AffinePoint {
	zinv := new(big.Int).ModInverse(e.Z, Q)

	X := new(big.Int).Mul(e.X, zinv)
	X.Mod(X, Q)

	Y := new(big.Int).Mul(e.Y, zinv)
	Y.Mod(Y, Q)

	return AffinePoint{X, Y}
}

// Double doubles given extended point. Given point P this function returns 2P.
// This is dbl-2008-hwcd implementation
// from http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
func (e ExtendedPoint) Double() ExtendedPoint {
	X1, Y1, Z1 := e.X, e.Y, e.Z

	// A = (X1 * X1)
	A := new(big.Int).Mul(X1, X1)

	// B = (Y1*Y1)
	B := new(big.Int).Mul(Y1, Y1)

	// C = (2*Z1*Z1)
	// twoZ.Mul(Z1, Z1)
	C := new(big.Int).Mul(big.NewInt(2), Z1)
	C.Mul(C, Z1)

	// D = (-A) % Q
	D := new(big.Int).Mod(new(big.Int).Neg(A), Q)

	// J = (X1+Y1) % Q
	J := new(big.Int).Add(X1, Y1)
	J.Mod(J, Q)

	// E = (J*J-A-B) % Q
	E := new(big.Int).Mul(J, J)
	E.Sub(E, A)
	E.Sub(E, B)
	E.Mod(E, Q)

	// G = (D+B) % Q
	G := new(big.Int).Add(D, B)
	G.Mod(G, Q)

	// F = (G - C) % Q
	F := new(big.Int).Sub(G, C)
	F.Mod(F, Q)

	// H = (D - B) % Q
	H := new(big.Int).Sub(D, B)
	H.Mod(H, Q)

	// X3 = (E*F) % Q
	X3 := new(big.Int).Mul(E, F)
	X3.Mod(X3, Q)

	// Y3 = (G*H) % Q
	Y3 := new(big.Int).Mul(G, H)
	Y3.Mod(Y3, Q)

	// Z3 = (F*G) % Q
	Z3 := new(big.Int).Mul(F, G)
	Z3.Mod(Z3, Q)

	// T3 = (E*H) % Q
	T3 := new(big.Int).Mul(E, H)
	T3.Mod(T3, Q)

	a := ExtendedPoint{X3, Y3, Z3, T3}
	return a
}

// Cmp compares 2 points in CompressedEdwardsY (i.e. 32 byte format representing
// Y co-ordinate) form and returns integer. The result will be 0 if e == other, -1
// if e < other and +1 if e > other
func (e *ExtendedPoint) Cmp(other *ExtendedPoint) int {
	a := e.ToAffine()
	b := other.ToAffine()

	aBytes := a.Compress()
	bBytes := b.Compress()

	return bytes.Compare(aBytes, bBytes)
}

// Add implements the group.Element interface and adds 2 ExtendedPoint and
// returns the resulting point as type Element
func (e ExtendedPoint) Add(b group.Element) group.Element {
	other := b.(ExtendedPoint)
	result := AddUnified(&e, &other)
	return result
}

// ScalarMult multiplies given scalar to point on elliptic curve and returns the
// resutling point
func (e ExtendedPoint) ScalarMult(s *big.Int) group.Element {
	result := e.ScalarMultFast(s)
	return result
}

// AddUnified adds 2 extended co-ordinates and returns resulting extended co-ordinate.
// This is implemented using  add-2008-hwcd-3. It is slightly slower than
// add-2008-hwcd-4 but is unified and is safe for general purpose addition
func AddUnified(a, b *ExtendedPoint) ExtendedPoint {
	x1, y1, z1, t1 := a.X, a.Y, a.Z, a.T
	x2, y2, z2, t2 := b.X, b.Y, b.Z, b.T

	// A = ((Y1-X1)*(Y2-X2)) % Q
	A := new(big.Int).Mul(new(big.Int).Sub(y1, x1), new(big.Int).Sub(y2, x2))
	A.Mod(A, Q)

	// B = ((Y1+X1)*(Y2+X2)) % Q
	B := new(big.Int).Mul(new(big.Int).Add(y1, x1), new(big.Int).Add(y2, x2))
	B.Mod(B, Q)

	// C = T1*(2*d)*T2 % Q
	C := new(big.Int).Mul(t1, d2)
	C.Mul(C, t2)
	C.Mod(C, Q)

	// D = Z1*2*Z2 % Q
	D := new(big.Int).Mul(z1, big.NewInt(2))
	D.Mul(D, z2)
	D.Mod(D, Q)

	// E = (B-A) % Q
	E := new(big.Int).Sub(B, A)
	E.Mod(E, Q)

	// F = (D-C) % Q
	F := new(big.Int).Sub(D, C)
	F.Mod(F, Q)

	// G = (D+C) % Q
	G := new(big.Int).Add(D, C)
	G.Mod(G, Q)

	// H = (B+A) % Q
	H := new(big.Int).Add(B, A)
	H.Mod(H, Q)

	// X3 = (E*H) % Q
	X3 := new(big.Int).Mul(E, F)
	X3.Mod(X3, Q)

	// Y3 = (G*H) % Q
	Y3 := new(big.Int).Mul(G, H)
	Y3.Mod(Y3, Q)

	// Z3 = (F*G) % Q
	Z3 := new(big.Int).Mul(F, G)
	Z3.Mod(Z3, Q)

	// T3 = (E*H) % Q
	T3 := new(big.Int).Mul(E, H)
	T3.Mod(T3, Q)

	return ExtendedPoint{X3, Y3, Z3, T3}
}

// AddNonUnified adds 2 point on elliptic curve and returns the resulting
// extended co-ordinate. This is based on add-2008-hwcd-4 and only for a != b.
// This is 10% faster than Add and safe to use in ScalarMult if points of order
// 1/2/4/8 are not used
func AddNonUnified(a, b *ExtendedPoint) ExtendedPoint {
	x1, y1, z1, t1 := a.X, a.Y, a.Z, a.T
	x2, y2, z2, t2 := b.X, b.Y, b.Z, b.T

	// A = ((Y1-X1)*(Y2+X2)) % Q
	A := new(big.Int).Mul(new(big.Int).Sub(y1, x1), new(big.Int).Add(y2, x2))
	A.Mod(A, Q)

	// B = ((Y1+X1)*(Y2-X2)) % Q
	B := new(big.Int).Mul(new(big.Int).Add(y1, x1), new(big.Int).Sub(y2, x2))
	B.Mod(B, Q)

	// C = (Z1*2*T2) % Q
	C := new(big.Int).Mul(z1, big.NewInt(2))
	C.Mul(C, t2)
	C.Mod(C, Q)

	// D = (T1*2*Z2) % Q
	D := new(big.Int).Mul(t1, big.NewInt(2))
	D.Mul(D, z2)
	D.Mod(D, Q)

	// E = (D+C) % Q
	E := new(big.Int).Add(D, C)
	E.Mod(E, Q)

	// F = (B-A) % Q
	F := new(big.Int).Sub(B, A)
	F.Mod(F, Q)

	// G = (B+A) % Q
	G := new(big.Int).Add(B, A)
	G.Mod(G, Q)

	// H = (D-C) % Q
	H := new(big.Int).Sub(D, C)
	H.Mod(H, Q)

	// X3 = (E*F) % Q
	x3 := new(big.Int).Mul(E, F)
	x3.Mod(x3, Q)

	// Y3 = (G*H) % Q
	y3 := new(big.Int).Mul(G, H)
	y3.Mod(y3, Q)

	// Z3 = (F*G) % Q
	z3 := new(big.Int).Mul(F, G)
	z3.Mod(z3, Q)

	// T3 = (E*H) % Q
	t3 := new(big.Int).Mul(E, H)
	t3.Mod(t3, Q)

	return ExtendedPoint{x3, y3, z3, t3}
}

// ScalarMultSlow multiplies a scalar (Integer) to the point on elliptic curve
// (Extended Co-ordinate) and reutns the resulting point. This form is slightly
// slower, but tolerates arbitrary points, including those which are not in the
// main 1*L subgroup. This includes points of order 1 (the neutral element
// Zero), 2, 4, 6, 8
func (e *ExtendedPoint) ScalarMultSlow(s *big.Int) ExtendedPoint {
	if s.Cmp(big.NewInt(0)) == 0 {
		return Zero
	}

	if s.Cmp(big.NewInt(1)) == 0 {
		return *e
	}

	var result ExtendedPoint
	if IsEven(s) {
		// If scalar is even we recursively call scalarmult with n/2 and
		// then double the result.
		result = e.ScalarMultSlow(new(big.Int).Rsh(s, 1))
		result = result.Double()
	} else {
		// We decrement the scalar and recursively call scalarmult with
		// it then we add the result with point
		result = e.ScalarMultSlow(new(big.Int).Sub(s, big.NewInt(1)))
		result = AddUnified(&result, e)
	}

	return result
}

// ScalarMultFast multiplies a scalar (Integer) to the point on elliptic curve
// (Extended Co-ordinate) and reutns the resulting point. This form only works
// properly when given points that are member of the main 1*L subgroup. It will
// give incorrect answers when called with the points of order 1/2/4/6/8,
// including point Zero.
func (e *ExtendedPoint) ScalarMultFast(s *big.Int) ExtendedPoint {
	if s.Cmp(big.NewInt(0)) == 0 {
		return Zero
	}

	if s.Cmp(big.NewInt(1)) == 0 {
		return *e
	}

	var result ExtendedPoint
	if IsEven(s) {
		// If scalar is even we recursively call scalarmult with n/2 and
		// then double the result.
		result = e.ScalarMultFast(new(big.Int).Rsh(s, 1))
		result = result.Double()
	} else {
		// We decrement the scalar and recursively call scalarmult with
		// it then we add the result with point

		result = e.ScalarMultFast(new(big.Int).Sub(s, big.NewInt(1)))
		result = AddNonUnified(&result, e)
	}

	return result
}

// Negate negates given point e and returns -e
func (e ExtendedPoint) Negate() group.Element {
	var negatedPoint ExtendedPoint
	var X, T big.Int
	X.Sub(Q, e.X)
	T.Sub(Q, e.T)

	negatedPoint.X = &X
	negatedPoint.Y = e.Y
	negatedPoint.Z = e.Z
	negatedPoint.T = &T

	return negatedPoint
}
