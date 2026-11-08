package integergroup

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	group "salsa.debian.org/vasudev/gospake2/groups"
)

// IntegerGroup defines multiplicative group on integer
type IntegerGroup struct {
	params *GroupParameters
}

func (i IntegerGroup) isMember(ele IntegerElement) bool {
	element := i
	if !element.params.equal(ele.params) {
		return false
	}

	result := new(big.Int)
	result.Exp(ele.e, element.params.q, element.params.p)
	if result.Cmp(big.NewInt(1)) == 0 {
		return true
	}

	return false
}

// Order returns the subgroup order for the integer group
func (i IntegerGroup) Order() *big.Int {
	return i.params.q
}

// RandomScalar returns a random scalar which is in the group
func (i IntegerGroup) RandomScalar() (*big.Int, error) {
	group := i.params
	return unbiasedRandRange(big.NewInt(0), group.q)
}

// PasswordToScalar expands given password bytes into a integer belonging to the group
func (i IntegerGroup) PasswordToScalar(pw []byte) *big.Int {
	group := i.params
	info := []byte("SPAKE2 pw")
	// Expand the password bytes to ScalarSize + 16
	hkdfReader := hkdf.New(sha256.New, pw, []byte(""), info)
	expanded := make([]byte, group.scalarSize+16)
	io.ReadFull(hkdfReader, expanded)

	expandedPw := new(big.Int)
	expandedPw.SetBytes(expanded)
	return expandedPw.Mod(expandedPw, group.q)
}

// ElementToBytes converts given big integer element of the group to bytes
func (i IntegerGroup) ElementToBytes(x group.Element) []byte {
	element := x.(IntegerElement)
	return element.e.Bytes()
}

// ElementFromBytes converts given byte slice into element of integer group i.
// In case element is either identity or does not belong to zero error is
// returned. Resulting element should satisfy condition e^q mod p where q is
// order of subgroup and p is the prime number which is order of group
func (i IntegerGroup) ElementFromBytes(b []byte) (group.Element, error) {
	grp := i.params
	if len(b) != grp.elementSizeBytes {
		return nil, fmt.Errorf("Length of bytes supplied is not sufficient for the group element creation\nLength: %d, bytes: %d\n",
			grp.elementSizeBytes, len(b))
	}

	x := new(big.Int)
	x.SetBytes(b)

	if x.Cmp(big.NewInt(0)) == 0 || x.Cmp(big.NewInt(0)) == -1 || x.Cmp(grp.p) == 1 {
		return nil, fmt.Errorf("Alleged element not in the field")
	}

	element := IntegerElement{params: grp, e: x}
	if !i.isMember(element) {
		return nil, fmt.Errorf("Element is not in the right group")
	}

	return element, nil
}

// Add adds 2 group element. Since this is multiplicative add operation is
// actually multiplication.
// Note: Caller should take care that other element is of same group function
// itself does not do this check as its written for implementing group interface
// of gospake2
func (i IntegerGroup) Add(a, b group.Element) group.Element {
	return a.Add(b)
}

// ScalarMult is repeatedly multiplying group element g with scalar x which is
// equivalaent to element^x mod p in multiplicative group of prime order p
func (i IntegerGroup) ScalarMult(e group.Element, s *big.Int) group.Element {
	return e.ScalarMult(s)
}

// BasePointMult multiplies given scalar to generator of the multiplicative
// group.In this case the result is g^x mod p where g is generator of the
// integer group and p is prime order of the group.
func (i IntegerGroup) BasePointMult(s *big.Int) group.Element {
	base := IntegerElement{params: i.params, e: i.params.g}
	return base.ScalarMult(s)
}

func (i IntegerGroup) arbitraryElement(seed []byte) (*big.Int, error) {
	processedSeed, err := expandArbitraryElementSeed(seed,
		i.params.elementSizeBytes)
	if err != nil {
		return nil, err
	}

	// The larger (non-prime-order) group (Zp*) we are using has order p-1.
	// The smaller (prime-order) subgroup has order q. Subgroup order always
	// divides the larger  group order. so r*q = p-1 for some integer r. If
	// h is an arbitrary element of the larger group Zp*, then e=h^r will be
	// element of the subgroup. If h is selected uniformly at random, so
	// will e and nobody will know its discrete log. We enforce this for
	// pre-selected parameters by choosing h as the output of a hash function.
	r := new(big.Int)
	pMinus1 := new(big.Int)
	pMinus1.Sub(i.params.p, big.NewInt(1))
	r.Div(pMinus1, i.params.q)

	h := new(big.Int)
	h.SetBytes(processedSeed)
	h.Mod(h, i.params.p)

	result := h.Exp(h, r, i.params.p)
	element := IntegerElement{params: i.params, e: result}
	if !i.isMember(element) {
		return nil, fmt.Errorf("Generated arbitrary element is not part of the group")
	}

	return result, nil
}

// ConstM returns the element M from the integer group i used in SPAKE2 caclulation
func (i IntegerGroup) ConstM() group.Element {

	element, err := i.arbitraryElement([]byte("M"))
	if err != nil {
		panic(err)
	}

	return IntegerElement{params: i.params, e: element}
}

// ConstN returns the element N from integer group i used in SPAKE2 calculation
func (i IntegerGroup) ConstN() group.Element {

	element, err := i.arbitraryElement([]byte("N"))
	if err != nil {
		panic(err)
	}

	return IntegerElement{params: i.params, e: element}
}

// ConstS returns the element S from integer group i used in SPAKE2 symmetric
// mode caclulation
func (i IntegerGroup) ConstS() group.Element {
	element, err := i.arbitraryElement([]byte("symmetric"))
	if err != nil {
		panic(err)
	}

	return IntegerElement{params: i.params, e: element}
}

// ElementSize returns the group element size in bytes
func (i IntegerGroup) ElementSize() int {
	return i.params.elementSizeBytes
}
