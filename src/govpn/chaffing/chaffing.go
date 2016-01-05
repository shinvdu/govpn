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

// Chaffing-and-Winnowing.
//
// This package implements Chaffing-and-Winnowing technology
// (http://people.csail.mit.edu/rivest/chaffing-980701.txt).
//
// It outputs two Poly1305 MACs for each bit of input data: one valid,
// and other is not. MACs sequence is following:
//
//     MAC of 1st byte, 1st bit, 0 possible value
//     MAC of 1st byte, 1st bit, 1 possible value
//     MAC of 1st byte, 2nd bit, 0 possible value
//     MAC of 1st byte, 2nd bit, 1 possible value
//     ...
//
// MAC is taken over the "V" string for the valid (enabled) bit value
// and over "I" for invalid one.
//
// Poly1305 uses 256-bit one-time key. We generate it using XSalsa20.
//
//     MACKey = XSalsa20(authKey, nonce, 0x00...)
//     nonce = prefix || byte-num || bit-val
//     bit-val = (0x00|0x01) || 0x00... || bit sequence number
//
// 64-bit prefix is explicitly provided during the chaffing. byte-num is
// big-endian 64-bit byte's sequence number. So 24-bit nonces for
// XSalsa20 will be the following:
//
//     prefix || 0x0000000000000000 || 0x0000000000000000
//     prefix || 0x0000000000000000 || 0x0100000000000000
//     prefix || 0x0000000000000000 || 0x0000000000000001
//     prefix || 0x0000000000000000 || 0x0100000000000001
//     prefix || 0x0000000000000000 || 0x0000000000000002
//     prefix || 0x0000000000000000 || 0x0100000000000002
//     ...
//     prefix || 0x0000000000000001 || 0x0000000000000000
//     prefix || 0x0000000000000001 || 0x0100000000000000
package chaffing

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
)

const (
	EnlargeFactor = 16 * poly1305.TagSize
)

var (
	markInvld []byte = []byte("I")
	markValid []byte = []byte("V")
	macZero   []byte = make([]byte, 32)
)

func zero(macKey *[32]byte) {
	for i := 0; i < 32; i++ {
		macKey[i] = 0
	}
}

// Chaff the data. noncePrfx is 64-bit nonce. Output data will be much
// larger: 256 bytes for each input byte.
func Chaff(authKey *[32]byte, noncePrfx, in []byte) []byte {
	out := make([]byte, len(in)*EnlargeFactor)
	macKey := new([32]byte)
	nonce := make([]byte, 24)
	copy(nonce[:8], noncePrfx)
	var i int
	var v byte
	tag := new([16]byte)
	for n, b := range in {
		binary.BigEndian.PutUint64(nonce[8:16], uint64(n))
		for i = 0; i < 8; i++ {
			v = b >> uint8(i) & 1
			nonce[23] = byte(i)
			nonce[16] = 0
			salsa20.XORKeyStream(macKey[:], macZero, nonce, authKey)
			if v == 0 {
				poly1305.Sum(tag, markValid, macKey)
			} else {
				poly1305.Sum(tag, markInvld, macKey)
			}
			copy(out[poly1305.TagSize*(n*16+i*2):], tag[:])
			nonce[16] = 1
			salsa20.XORKeyStream(macKey[:], macZero, nonce, authKey)
			if v == 1 {
				poly1305.Sum(tag, markValid, macKey)
			} else {
				poly1305.Sum(tag, markInvld, macKey)
			}
			copy(out[poly1305.TagSize*(n*16+i*2+1):], tag[:])
		}
	}
	zero(macKey)
	return out
}

// Winnow the data.
func Winnow(authKey *[32]byte, noncePrfx, in []byte) ([]byte, error) {
	if len(in)%EnlargeFactor != 0 {
		return nil, errors.New("Invalid data size")
	}
	out := make([]byte, len(in)/EnlargeFactor)
	macKey := new([32]byte)
	defer zero(macKey)
	nonce := make([]byte, 24)
	copy(nonce[:8], noncePrfx)
	tag := new([16]byte)
	var i int
	var is0 bool
	var is1 bool
	var v byte
	for n := 0; n < len(out); n++ {
		binary.BigEndian.PutUint64(nonce[8:16], uint64(n))
		v = 0
		for i = 0; i < 8; i++ {
			is0 = false
			is1 = false
			nonce[23] = byte(i)
			nonce[16] = 0
			salsa20.XORKeyStream(macKey[:], macZero, nonce, authKey)
			poly1305.Sum(tag, markValid, macKey)
			is0 = subtle.ConstantTimeCompare(
				tag[:],
				in[poly1305.TagSize*(n*16+i*2):poly1305.TagSize*(n*16+i*2+1)],
			) == 1
			nonce[16] = 1
			salsa20.XORKeyStream(macKey[:], macZero, nonce, authKey)
			poly1305.Sum(tag, markValid, macKey)
			is1 = subtle.ConstantTimeCompare(
				tag[:],
				in[poly1305.TagSize*(n*16+i*2+1):poly1305.TagSize*(n*16+i*2+2)],
			) == 1
			if is0 == is1 {
				return nil, errors.New("Invalid authenticator received")
			}
			if is1 {
				v = v | 1<<uint8(i)
			}
		}
		out[n] = v
	}
	return out, nil
}
