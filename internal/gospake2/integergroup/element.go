package integergroup

import (
	"math/big"
	group "salsa.debian.org/vasudev/gospake2/groups"
)

// IntegerElement represents integer of specific multiplicative group.
type IntegerElement struct {
	params *GroupParameters
	e      *big.Int
}

// Add is actually multiplication mod `p` where `p` is order of the
// multiplicative group
func (i IntegerElement) Add(other group.Element) group.Element {
	a := i.e
	b := other.(IntegerElement).e

	if !i.params.equal(other.(IntegerElement).params) {
		panic("You can't add elements of 2 different groups")
	}

	result := new(big.Int).Mul(a, b)

	return group.Element(IntegerElement{params: i.params, e: result.Mod(result, i.params.p)})
}

// ScalarMult for multiplicative group is g^s mod p where `g` is group generator
// and p is order of the group
func (i IntegerElement) ScalarMult(s *big.Int) group.Element {
	reducedS := new(big.Int).Mod(s, i.params.q)
	return group.Element(IntegerElement{params: i.params, e: new(big.Int).Exp(i.e, reducedS, i.params.p)})
}

// Negate return negated representation of given element.
func (i IntegerElement) Negate() group.Element {
	return group.Element(IntegerElement{params: i.params, e: new(big.Int).Neg(i.e)})
}
