package gospake2

import (
	"math/big"
)

// Group defines methods that needs to be implemented by the number / elliptic
// curve group which is used to implement SPAKE2 algorithm
type Group interface {
	// These functions are not really group operations but they are needed
	// to get the required group Element's needed for calculation of SPAKE2
	ConstM() interface{}
	ConstN() interface{}
	ConstS() interface{}

	// This operation is needed to get a random integer in the group
	RandomScalar() (*big.Int, error)

	// This operation is for converting user password to a group element
	PasswordToScalar(pw []byte) *big.Int

	// These operations convert a group element to bytes and from bytes
	ElementToBytes(ele interface{}) []byte
	ElementFromBytes(b []byte) (interface{}, error)

	// These operations are group operations
	BasePointMult(s *big.Int) interface{}
	Add(other interface{}) interface{}
	ScalarMult(s *big.Int) interface{}
	Negate() interface{}

	// This operation should return size of the group
	ElementSize() int
}
