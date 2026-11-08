package integergroup

import (
	"math/big"
)

// GroupParameters defines a cyclic abelian group
type GroupParameters struct {
	p, q, g                                       *big.Int
	elementSizeBytes, elementSizeBits, scalarSize int
}

func (i *GroupParameters) equal(other *GroupParameters) bool {
	if (i.p.Cmp(other.p) != 0) &&
		(i.q.Cmp(other.q) != 0) &&
		(i.g.Cmp(other.g) != 0) {
		return false
	}
	return true
}
