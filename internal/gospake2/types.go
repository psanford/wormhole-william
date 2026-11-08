// Copyright 2021 Vasudev Kamath. All rights reserved. Use of this code is
// governed by either the MIT License or the GNU General Public License v3
// or later. The license text can be found in the LICENSE file.

package gospake2

// Password is type for passing password to SPAKE2 calculation.
type Password struct {
	password []byte
}

// NewPassword is factory function for creating password type from given
// password string.
func NewPassword(password string) Password {
	return Password{[]byte(password)}
}

// FromBytes initializes given Password p with pw bytes
func (p *Password) FromBytes(pw []byte) {
	p.password = make([]byte, len(pw))
	copy(p.password, pw)
}

// ToBytes converts the Password type to byte slice
func (p *Password) ToBytes() []byte {
	return p.password
}

// IdentityA is type for passing identity of side A to SPAKE2 calculation
type IdentityA struct {
	ida []byte
}

// NewIdentityA is factory function for creating IdentityA type from given
// identity string.
func NewIdentityA(identity string) IdentityA {
	return IdentityA{[]byte(identity)}
}

// FromBytes initializes i with given id bytes
func (i *IdentityA) FromBytes(id []byte) {
	i.ida = make([]byte, len(id))
	copy(i.ida, id)
}

// ToBytes converts the IdentityA type to byte slice
func (i *IdentityA) ToBytes() []byte {
	return i.ida
}

// IdentityB is type for passing identity of side B to SPAKE2 calculation
type IdentityB struct {
	idb []byte
}

// NewIdentityB is a factory function for creating IdentityB type from given
// identity string
func NewIdentityB(identity string) IdentityB {
	return IdentityB{[]byte(identity)}
}

// FromBytes initializes i with given id bytes
func (i *IdentityB) FromBytes(id []byte) {
	i.idb = make([]byte, len(id))
	copy(i.idb, id)
}

// ToBytes converts the IdentityB type to byte slice
func (i *IdentityB) ToBytes() []byte {
	return i.idb
}

// IdentityS is type for passing identity to SPAKE2 calculation in symmetric mode
type IdentityS struct {
	ids []byte
}

// NewIdentityS is a factory function for creating IdentityS type from given
// identity string.
func NewIdentityS(identity string) IdentityS {
	return IdentityS{[]byte(identity)}
}

// FromBytes initializes i with given id bytes
func (i *IdentityS) FromBytes(id []byte) {
	i.ids = make([]byte, len(id))
	copy(i.ids, id)
}

// ToBytes converts the IdentityS type to byte slice
func (i *IdentityS) ToBytes() []byte {
	return i.ids
}
