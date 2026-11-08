// Copyright 2021 Vasudev Kamath. All rights reserved. Use of this code is
// governed by either the MIT License or the GNU General Public License v3
// or later. The license text can be found in the LICENSE file.

/*Package gospake2 implements SPAKE2, password authenticated key exchange (PAKE)
algorithm. This allows 2 parties who have weak shared password to safely
derive a strong shared secret and build encrypted+authenticated communication
channel between them.

Refer "Simple Password-Based Encrypted Key Exchange Protocols" by  Michel
Abdalla and David Pointcheval for more details.
http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf

This package only implements the calculation of exchange message which we
need to send to other side (X* , Y* or S) and deriving key from the exchanged
message.

This package does not implement any groups for the operation, instead it relies
on package ed25519group and integergroup. This package by default uses
ed25519group as it is the default group used in Python implementation.
*/
package gospake2

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"

	ed25519 "salsa.debian.org/vasudev/gospake2/ed25519group"
	group "salsa.debian.org/vasudev/gospake2/groups"
)

var (
	sideA = 0x41
	sideB = 0x42
	sideS = 0x53
)

// userSide interface to mimick the userSide enum from Rust
type userSide interface {
	identity() byte
}

// userSideA indicates side_a in SPAKE2 algorithm in asymmetric mode
type userSideA struct{}

// userSideB indicates side_b in SPAKE2 algorithm in asymmetric mode
type userSideB struct{}

// userSideS indicates side_s in SPAKE2 algorithm in symmetric mode
type userSideS struct{}

// identity for SideA returns rune A
func (a userSideA) identity() byte {
	return byte(sideA)
}

// identity for SideB returns rune B
func (b userSideB) identity() byte {
	return byte(sideB)
}

// identity for S returns rune S
func (s userSideS) identity() byte {
	return byte(sideS)
}

// Ensure all the sides implement side interface
var (
	_ userSide = userSideA{}
	_ userSide = userSideB{}
	_ userSide = userSideS{}
)

// SPAKE2 holds the parameters needed for SPAKE2 algorithm. It is returned by
// Start function and needed to be used to finish the key derivation after
// initial message are exchanged.
type SPAKE2 struct {
	side                 userSide
	xyScalar             *big.Int
	password             Password
	idA                  IdentityA
	idB                  IdentityB
	idS                  IdentityS
	message              []byte
	passwordScalar       *big.Int
	blinding, unblinding group.Element
	group                group.Group
}

// SetGroup sets the mathematical group used for SPAKE2 calculation to group
// choosen by user. By default ed25519group is used  by this package. This
// function also sets the group parameter needed for mathematical calculation.
func (s *SPAKE2) SetGroup(grp group.Group) {
	s.group = grp

	// We need to change everything as we are changing the basic group itself
	s.passwordScalar = grp.PasswordToScalar(s.password.ToBytes())

	s.xyScalar, _ = grp.RandomScalar()

	// We need to check side and set blinding unblinding
	switch int(s.side.identity()) {
	case sideA:
		s.blinding = grp.ConstM()
		s.unblinding = grp.ConstN()
	case sideB:
		s.blinding = grp.ConstN()
		s.unblinding = grp.ConstM()
	case sideS:
		s.blinding = grp.ConstS()
		s.unblinding = grp.ConstS()
	}
}

func newAsymmetric(side userSide, password Password, idA IdentityA, idB IdentityB) SPAKE2 {
	var spake SPAKE2
	spake.side = side

	spake.password = password
	spake.idA = idA
	spake.idB = idB

	spake.SetGroup(group.Group(ed25519.Ed25519{}))

	return spake
}

func newSymmetric(password Password, idS IdentityS) SPAKE2 {
	var spake SPAKE2
	spake.side = userSideS{}
	spake.idS = idS
	spake.password = password

	spake.SetGroup(group.Group(ed25519.Ed25519{}))

	return spake
}

// SPAKE2A initiate SPAKE2 state for side A. This function should be called by
// side A to start SPAKE2 calculation
func SPAKE2A(password Password, idA IdentityA, idB IdentityB) SPAKE2 {
	spakea := newAsymmetric(userSideA{}, password, idA, idB)
	return spakea
}

// SPAKE2B initiate SPAKE2 state for side B. This function should be called by
// side B to start SPAKE2 calculation
func SPAKE2B(password Password, idA IdentityA, idB IdentityB) SPAKE2 {
	spakeb := newAsymmetric(userSideB{}, password, idA, idB)
	return spakeb
}

// SPAKE2Symmetric initiates SPAKE2 state for symmetric mode. This function
// should be called by both side to start the SPAKE2 calculation
func SPAKE2Symmetric(password Password, idS IdentityS) SPAKE2 {
	spakes := newSymmetric(password, idS)
	return spakes
}

// Helper function for tests to check internal working of code
func (s *SPAKE2) setXyScalar(n *big.Int) {
	s.xyScalar.Set(n)
}

// Start does first part of SPAKE2 calculation, that is calculation of PAKE
// message which is sent to the other side. This function's operation is defined
// mathematically as follows.
//
// Integer Group
//
//     Side A  x <-Zp X <- g^x; X* <- X*M^pw
//     Side B  y <-Zp Y <- g^y; Y* <- Y*N^pw
//
// Elliptic Curve Group
//
//     Side A x <- Ed25519 X <- B*x; X* <- X + M*pw
//     Side B y <- Ed25519 Y <- B*y; Y* <- Y + N*pw
//
// Calculated X* and Y* are byte slices in little-endian format.
//
// Here pw is the scalar obtained by mapping password to group. In this case
// function first expands password by group element size + 16 byte using HKDF
// function and reduces it to the group by doing a modulo group order.
//
// Thoguh algorithm does not speak about format of exchange message, the return
// value of this function contains first byte as side which will be 'A' or 'B'
// or 'S' depending on the Asymmetric or Symmetric mode followed by X*/Y*
// calculated using above formula. This allows to check from which side the
// message came during key derivation phase.
func (s *SPAKE2) Start() []byte {

	// X = B*x + M*pw - A
	// Y = B*y + N*pw - B
	// Symmetric = B*s + S*pw
	m1 := s.group.Add(s.group.BasePointMult(s.xyScalar), s.group.ScalarMult(s.blinding, s.passwordScalar))
	m1Bytes := s.group.ElementToBytes(m1)

	// Store our variable in state which can be used to thwart the
	// reflection attacks
	s.message = make([]byte, len(m1Bytes))
	copy(s.message, m1Bytes)

	messageAndSide := make([]byte, s.group.ElementSize()+1)
	messageAndSide[0] = s.side.identity()
	copy(messageAndSide[1:], m1Bytes)

	return messageAndSide

}

func transcriptAsymmetric(password Password, idA IdentityA, idB IdentityB, first, second, key []byte) []byte {
	transcript := make([]byte, (3*32 + (3 * len(key))))

	// Key and Exchange messages from group have same byte size
	elementSize := len(key)

	passwordHash := sha256.Sum256(password.ToBytes())
	idAHash := sha256.Sum256(idA.ToBytes())
	idBHash := sha256.Sum256(idB.ToBytes())

	copy(transcript[0:32], passwordHash[:])
	copy(transcript[32:64], idAHash[:])
	copy(transcript[64:96], idBHash[:])

	firstOffsetEnd := 96 + elementSize
	secondOffsetEnd := firstOffsetEnd + elementSize
	keyEnd := secondOffsetEnd + elementSize

	copy(transcript[96:firstOffsetEnd], first)
	copy(transcript[firstOffsetEnd:secondOffsetEnd], second)
	copy(transcript[secondOffsetEnd:keyEnd], key)

	transcriptHash := sha256.Sum256(transcript)
	return transcriptHash[:]

}

func transcriptSymmetric(password Password, idS IdentityS, msgU, msgV, key []byte) []byte {
	transcript := make([]byte, (2*32 + (3 * len(key))))

	passwordHash := sha256.Sum256(password.ToBytes())
	idSHash := sha256.Sum256(idS.ToBytes())

	elementSize := len(key)

	copy(transcript[:32], passwordHash[:])
	copy(transcript[32:64], idSHash[:])

	firstOffsetEnd := 64 + elementSize
	secondOffsetEnd := firstOffsetEnd + elementSize
	keyEnd := secondOffsetEnd + elementSize

	if bytes.Compare(msgU, msgV) == -1 {
		// If msgU < msgV
		copy(transcript[64:firstOffsetEnd], msgU)
		copy(transcript[firstOffsetEnd:secondOffsetEnd], msgV)
	} else {
		copy(transcript[64:firstOffsetEnd], msgV)
		copy(transcript[firstOffsetEnd:secondOffsetEnd], msgU)
	}

	copy(transcript[secondOffsetEnd:keyEnd], key)

	transcriptHash := sha256.Sum256(transcript)
	return transcriptHash[:]
}

func generateKey(side userSide, password Password, idA IdentityA, idB IdentityB, idS IdentityS, msgU, msgV, key []byte) []byte {
	if side.identity() == byte(sideA) || side.identity() == byte(sideB) {
		return transcriptAsymmetric(password, idA, idB, msgU, msgV, key)
	}
	return transcriptSymmetric(password, idS, msgU, msgV, key)

}

// Finish completes SPAKE2 calculation and derives the session key. It takes
// exchange message which is coming from the other side. Function will raise
// error if the side of inbound message and current side are same. It will also
// raise an error
// Mathematical operation of this function is as shown below.
//
// Integer Group
//
//     Side A: Ka <- (Y*/N^pw)^x
//     Side B: Kb <- (X*/M^pw)^y
//
// Eliptic Curve Group Ed25519
//
//     Side A: Ka <- (Y* + N*-pw)*x
//     Side B: Kb <- (X + M*-pw)*y
//
// Due to mathematical properties SKa will be same as SKb which will be used as
// shared secret by both parties to setup encrypted-authenticated channel.
//
// Key Derivation
//
// Final key in SPAKE2 calculation is actually Hash of session identification,
// which is transcript of conversation between the two parties. Transcript in
// the SPAKE2 paper is defined as (A,B, X*, Y*, K, pw) where K is Ka or Kb but
// that should be same for both side. So mathematically key is defined as
// follows
//
//      H(A,B,X*, Y*, K, pw)
//
// In this implementation instead of using identities and password directly
// calculates their SHA256 hash and uses it in transcript.
//
// Ed25519 Group example transcript
//
// For Ed25519 since element size is 32 bytes transcript size will be either 192
// bytes (6 * 32) or 160 bytes (5 * 32) depending on if we are using Asymmetric
// or Symmetric mode. Below is sample representation of transcript for Ed25519 group
//
// Transcript Symmetric mode
//
//  0..31   -> SHA256(password)
//  32..63  -> SHA256(idA)
//  64..95  -> SHA256(idB)
//  96..127 ->  mA
//  128..159 -> mB
//  160..191 -> K
//
// Transcript for Symmetric mode
//  0..31   -> SHA256(password)
//  32..63  -> SHA256(id)
//  64..95  -> m1 or m2
//  96..127 -> m2 or m1
//  128..159 -> K
//
// In symmetric mode since we do not know which is the exchange message from
// which side we sort both slices m1 and m2 and use it. i.e if m1 < m2 then (m1,
// m2) else (m2, m1)
// Final key is the SHA256 of the above transcript.
//
// TODO Corrupt exchange message needs to be handled
func (s *SPAKE2) Finish(msg []byte) ([]byte, error) {
	otherSide := msg[0]
	inbound := msg[1:]
	// This is X/Y or S (not ConstS)
	inboundElement, inerr := s.group.ElementFromBytes(inbound)
	if inerr != nil {
		return nil, inerr
	}

	if bytes.Equal(s.message, inbound) {
		err := NewError(ReflectionAttempt, "Reflection attack  detected. Aborting")
		return nil, &err
	}

	if otherSide == byte(sideA) {
		if s.side.identity() == byte(sideA) {
			err := NewError(BadSide, fmt.Sprintf("I'm side A was expecting pake from side B, but got from %c", otherSide))
			return nil, &err
		} else if s.side.identity() == byte(sideS) {
			err := NewError(BadSide, fmt.Sprintf("I'm in symmetric mode but got side %c", otherSide))
			return nil, &err
		}
	} else if otherSide == byte(sideB) {
		if s.side.identity() == byte(sideB) {
			err := NewError(BadSide, fmt.Sprintf("I'm side B was expceting pake from side A but got from %c", otherSide))
			return nil, &err
		} else if s.side.identity() == byte(sideS) {
			err := NewError(BadSide, fmt.Sprintf("I'm in symmetric mode but got side %c", otherSide))
			return nil, &err
		}
	}

	minuspw := new(big.Int)
	minuspw.Neg(s.passwordScalar)

	// (Y+N*(-pw))*x
	// (X+M*(-pw))*y
	// (s+S*(-pw))*scalar
	key := s.group.ScalarMult(s.group.Add(inboundElement, s.group.ScalarMult(s.unblinding, minuspw)), s.xyScalar)
	keyBytes := s.group.ElementToBytes(key)

	if s.side.identity() == byte(sideA) {
		return generateKey(userSideA{}, s.password, s.idA, s.idB, s.idS, s.message, inbound, keyBytes), nil
	} else if s.side.identity() == byte(sideB) {
		return generateKey(userSideB{}, s.password, s.idA, s.idB, s.idS, inbound, s.message, keyBytes), nil
	} else {
		return generateKey(userSideS{}, s.password, s.idA, s.idB, s.idS, s.message, inbound, keyBytes), nil
	}
}
