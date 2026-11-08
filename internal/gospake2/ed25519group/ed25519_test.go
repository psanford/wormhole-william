package ed25519group

import (
	"math/big"
	group "salsa.debian.org/vasudev/gospake2/groups"
	"testing"
)

func TestPasswdToScalar(t *testing.T) {
	var e Ed25519
	var expected, expectedEmpty big.Int
	expected.SetString("3515301705789368674385125653994241092664323519848410154015274772661223168839", 10)
	expanded := e.PasswordToScalar([]byte("password"))

	if expanded.Cmp(&expected) != 0 {
		t.Errorf("Calculated password scalar is not same as expected: %s", expanded.Text(10))
	}

	empty := e.PasswordToScalar([]byte(""))
	expectedEmpty.SetString("5903805652715255267876771601091460535270217721801767442107988230147766983311", 10)
	if empty.Cmp(&expectedEmpty) != 0 {
		t.Errorf("Calculated empty password scalar is not same as expected: %s", empty.Text(10))
	}
}

func TestMath(t *testing.T) {
	var g Ed25519
	sb := g.BasePointMult
	e0 := sb(big.NewInt(0)).(ExtendedPoint)
	if e0.Cmp(&Zero) != 0 {
		t.Errorf("ScalarMultiplication by 0 should result in identity element\n")
	}

	e1 := sb(big.NewInt(1)).(ExtendedPoint)
	e2 := sb(big.NewInt(2)).(ExtendedPoint)
	a1 := g.Add(group.Element(e1), group.Element(e0)).(ExtendedPoint)
	if a1.Cmp(&e1) != 0 {
		t.Errorf("Element multiplied by Identity should be same as original\n")
	}

	a2 := g.Add(group.Element(e1), group.Element(e1)).(ExtendedPoint)
	if a2.Cmp(&e2) != 0 {
		t.Errorf("Multipying by n should be same as adding element to itself n times\n")
	}

	em1 := sb(new(big.Int).Sub(g.Order(), big.NewInt(1))).(ExtendedPoint)
	am1 := sb(big.NewInt(-1)).(ExtendedPoint)
	if em1.Cmp(&am1) != 0 {
		t.Errorf("Scalar multiplication by subgroup order - 1 is same as multiplying by -1\n")
		t.Errorf("em1: %x\n", g.ElementToBytes(group.Element(em1)))
		t.Errorf("am1: %x\n", g.ElementToBytes(group.Element(am1)))
	}

	ez := g.Add(group.Element(em1), group.Element(e1)).(ExtendedPoint)
	if ez.Cmp(&Zero) != 0 {
		t.Errorf("Element added to its inverse should result in identity\n")
	}

	order := new(big.Int)
	order.Set(g.Order())
	az := g.ScalarMult(group.Element(e1), order).(ExtendedPoint)
	if az.Cmp(&Zero) != 0 {
		t.Errorf("Multiplying an element with group order should result in identity element\n")
	}

	ne1 := group.Element(e1).Negate().(ExtendedPoint)
	a0 := g.Add(group.Element(e1), group.Element(ne1)).(ExtendedPoint)
	if a0.Cmp(&Zero) != 0 {
		t.Errorf("Addition of e1 + (-e1) should result in identity element\n")
	}
}

func TestToAndFromBytes(t *testing.T) {
	var g Ed25519
	base := group.Element(Base)
	baseBytes := g.ElementToBytes(base)
	reconstructed, err := g.ElementFromBytes(baseBytes)
	if err != nil {
		t.Errorf("Failed to construct the element back from bytes")
	}

	reconstructedElement := reconstructed.(ExtendedPoint)
	if reconstructedElement.Cmp(&Base) != 0 {
		t.Errorf("Reconstructed element is not same as original")
	}

	r, _ := g.RandomScalar()
	rand := g.BasePointMult(r)
	randb := g.ElementToBytes(rand)
	reconstructed, err = g.ElementFromBytes(randb)
	if err != nil {
		t.Errorf("Failed to construct the element back from bytes")
	}

	reconstructedElement = reconstructed.(ExtendedPoint)
	randElement := rand.(ExtendedPoint)
	if reconstructedElement.Cmp(&randElement) != 0 {
		t.Errorf("Reconstructed element is not same as original")
	}
}
