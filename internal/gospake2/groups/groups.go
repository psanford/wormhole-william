package groups

import (
	"math/big"
)

// Element represents the operation that needs to be satisfied by Group element.
type Element interface {
	Add(other Element) Element
	ScalarMult(s *big.Int) Element
	Negate() Element
}

// Group defines methods that needs to be implemented by the number / elliptic
// curve group which is used to implement SPAKE2 algorithm
type Group interface {
	// These functions are not really group operations but they are needed
	// to get the required group Element's needed for calculation of SPAKE2
	ConstM() Element
	ConstN() Element
	ConstS() Element

	// This operation is needed to get a random integer in the group
	RandomScalar() (*big.Int, error)

	// This operation is for converting user password to a group element
	PasswordToScalar(pw []byte) *big.Int

	// These operations are group operations
	BasePointMult(s *big.Int) Element
	Add(a, b Element) Element
	ScalarMult(a Element, s *big.Int) Element

	ElementToBytes(e Element) []byte
	ElementFromBytes([]byte) (Element, error)

	// This operation should return size of the group
	ElementSize() int

	// This operation returns order of subgroup
	Order() *big.Int
}
