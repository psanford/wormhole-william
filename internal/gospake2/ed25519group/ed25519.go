package ed25519group

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	group "salsa.debian.org/vasudev/gospake2/groups"
)

const (
	// ScalarSize is size of the scalar in bits
	ScalarSize = 32
)

// Ed25519 is a group over twisted Edwards curve
type Ed25519 struct{}

// Order returns the order of subgroup of twisted edward curve ed25519
func (e Ed25519) Order() *big.Int {
	return L
}

// ConstM returns the constant M used in SPAKE2 calculation
// Value returned by this function is calculated using following python code
// from python-spake2 module
//    from spake2.parameters.ed25519 import ParamsEd25519
//    from spake2.ed25519_basic import bytes_to_scalar
//    bytes_to_scalar(ParamsEd25519.M.to_bytes())
func (e Ed25519) ConstM() group.Element {

	m := NewExtendedPoint("56927089134650063917108264664726782351583691551656041986296774399829515120240",
		"4273663985902953537518572410120541466713201368243102219170551487669255820528",
		"3019557911857780367029612192681275477478659077138347675647838966310936799421",
		"30034378042466364018178932642530167244395743925559566289112169194594775869140",
		10)
	return m

}

// ConstN returns the constant N used in SPAKE2 calculation
// Value returned by this function is calculated using following python code
// from python-spake2 module
//    from spake2.parameters.ed25519 import ParamsEd25519
//    from spake2.ed25519_basic import bytes_to_scalar
//    bytes_to_scalar(ParamsEd25519.N.to_bytes())
func (e Ed25519) ConstN() group.Element {
	n := NewExtendedPoint("15903238113875359836900376779791899664561194955980904569164235593617176720895",
		"38024333869928680745616530565069024418801734790741445043615018844805300807425",
		"19865594709797356539814216106712420255842877653312222892641643090092808334004",
		"31228972998347013731195513321728481851166844425765317033740319161801934792068",
		10)
	return n
}

// ConstS returns the constant S used in SPAKE2 calculation in symmetric mode
// Value returned by this function is calculated using following python code
// from python-spake2 module
//    from spake2.parameters.ed25519 import ParamsEd25519
//    from spake2.ed25519_basic import bytes_to_scalar
//    bytes_to_scalar(ParamsEd25519.S.to_bytes())
func (e Ed25519) ConstS() group.Element {
	s := NewExtendedPoint("42960444209218251544344527087824519707974677500306009565627609123593631169755",
		"39430222967524752293884418340292706746154554371772410286106694871784341014053",
		"39384960708242416826086440334018324235929961014064821563580123476539164913194",
		"14959893256546603199215104820949085243491259409365557319805432854865987719354", 10)
	return s
}

// RandomScalar returns a random scalar which is on curve. For reducing bias to
// safe level function reads extra 256 bits and then reduces point to curve.
func (e Ed25519) RandomScalar() (*big.Int, error) {
	// Reduce bias to safe level by generating 256 extra bits
	b := make([]byte, 64)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	oversized := new(big.Int)
	oversized.SetBytes(b)
	return oversized.Mod(oversized, e.Order()), nil
}

// PasswordToScalar expands given password bytes to ScalarSize + 16 and then
// reduces result to curve order.and returns big.Int resulting from the final
// bytes.
func (e Ed25519) PasswordToScalar(pw []byte) *big.Int {
	info := []byte("SPAKE2 pw")
	// Expand the password bytes to ScalarSize + 16
	hkdfReader := hkdf.New(sha256.New, pw, []byte(""), info)
	expanded := make([]byte, ScalarSize+16)
	io.ReadFull(hkdfReader, expanded)

	expandedPw := new(big.Int)
	expandedPw.SetBytes(expanded)
	return expandedPw.Mod(expandedPw, L)
}

// BasePointMult multiplies given scalar s to Base point of the curve and
// returns the result as big.Int
func (e Ed25519) BasePointMult(s *big.Int) group.Element {
	result := e.ScalarMult(Base, s)
	return result
}

// ScalarMult multiples given point with scalar and returns the result
func (e Ed25519) ScalarMult(a group.Element, s *big.Int) group.Element {
	// First let's reduce s to curve order, this is important in case if we
	// pass negated value
	s.Mod(s, L)
	if s.Cmp(big.NewInt(0)) == 0 {
		return Zero
	}

	extendedPoint := a.(ExtendedPoint)
	result := extendedPoint.ScalarMult(s)
	return result
}

// ElementToBytes convert Ed25519 point to array of bytes
func (e Ed25519) ElementToBytes(i group.Element) []byte {
	extendedE := i.(ExtendedPoint)
	affineE := extendedE.ToAffine()
	return affineE.Compress()
}

// ElementFromBytes creates Ed25519 group element from given byte slice
func (e Ed25519) ElementFromBytes(b []byte) (group.Element, error) {
	var affinePoint AffinePoint
	affinePoint.Decompress(b)

	extendedPoint := affinePoint.ToExtended()
	if extendedPoint.Cmp(&Zero) == 0 {
		return nil, fmt.Errorf("Element is zero")
	}

	isingroup := extendedPoint.ScalarMult(L).(ExtendedPoint)
	if isingroup.Cmp(&Zero) != 0 {
		return nil, fmt.Errorf("Element is not in right group")
	}

	return extendedPoint, nil

}

// Add adds other point  to point e on curve and returns the result of addition
func (e Ed25519) Add(a, b group.Element) group.Element {
	result := a.Add(b)
	return result
}

// ElementSize returns the size of group element in bytes
func (e Ed25519) ElementSize() int {
	return ScalarSize
}
