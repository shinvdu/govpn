/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2016 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package govpn

import (
	"cypherpunks.ru/govpn/aont"
	"cypherpunks.ru/govpn/cnw"
)

const (
	EnclessEnlargeSize = aont.HSize + aont.RSize*cnw.EnlargeFactor
)

// Confidentiality preserving (but encryptionless) encoding.
//
// It uses Chaffing-and-Winnowing technology (it is neither
// encryption nor steganography) over All-Or-Nothing-Transformed data.
// nonce is 64-bit nonce. Output data will be EnclessEnlargeSize larger.
// It also consumes 64-bits of entropy.
func EnclessEncode(authKey *[32]byte, nonce, in []byte) ([]byte, error) {
	r := new([aont.RSize]byte)
	var err error
	if _, err = Rand.Read(r[:]); err != nil {
		return nil, err
	}
	aonted, err := aont.Encode(r, in)
	if err != nil {
		return nil, err
	}
	chaffLen := aont.RSize * cnw.EnlargeFactor
	total := chaffLen + len(aonted) - aont.RSize
	// Leave room for the 8-byte nonce (or handshake IDtag) appended by
	// callers, so that append does not reallocate and copy the packet.
	out := make([]byte, total, total+NonceSize)
	if err = cnw.ChaffInto(
		out[:chaffLen], authKey, nonce, aonted[:aont.RSize],
	); err != nil {
		return nil, err
	}
	copy(out[chaffLen:], aonted[aont.RSize:])
	SliceZero(aonted[:aont.RSize])
	return out, nil
}

// Decode EnclessEncode-ed data.
func EnclessDecode(authKey *[32]byte, nonce, in []byte) ([]byte, error) {
	var winnowed [aont.RSize]byte
	if err := cnw.WinnowInto(
		winnowed[:], authKey, nonce,
		in[:aont.RSize*cnw.EnlargeFactor],
	); err != nil {
		return nil, err
	}
	out, err := aont.DecodeParts(
		winnowed[:], in[aont.RSize*cnw.EnlargeFactor:],
	)
	SliceZero(winnowed[:])
	if err != nil {
		return nil, err
	}
	return out, nil
}
