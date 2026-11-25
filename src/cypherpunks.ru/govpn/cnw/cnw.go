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
//	MAC of 1st byte, 1st bit, 0 possible value
//	MAC of 1st byte, 1st bit, 1 possible value
//	MAC of 1st byte, 2nd bit, 0 possible value
//	MAC of 1st byte, 2nd bit, 1 possible value
//	...
//
// If bit value is 0, then first MAC is taken over "1" and the second
// one is over "0". If bit value is 1, then first is taken over "0" and
// second is over "1".
//
// Poly1305 uses 256-bit one-time key. We generate it using XSalsa20 for
// for the whole byte at once (16 MACs).
//
//	MACKey1, MACKey2, ... = XSalsa20(authKey, nonce, 0x00...)
//	nonce = prefix || 0x00... || big endian byte number
package cnw

import (
	"encoding/binary"
	"errors"
	"math/bits"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20/salsa"
)

const (
	EnlargeFactor = 16 * poly1305.TagSize
)

// Read-only all-zero input buffer used to extract Salsa20 keystream
// without having to zero a scratch buffer after every block.
var zeroKeys [8 * 64]byte

func zero(in []byte) {
	for i := 0; i < len(in); i++ {
		in[i] = 0
	}
}

// tags1 computes Poly1305 authenticators of the one-byte messages "0"
// and "1" for a single 32-byte one-time key.
//
// Poly1305 pads the final partial block with 0x01, so the corresponding
// little-endian block values are 0x130 and 0x131.  Hence
//
//	h    = 0x130 * r mod (2^130-5)
//	tag0 = low128(h + s)
//	tag1 = low128((h + r) mod (2^130-5) + s)
//
// One modular multiplication yields both tags, instead of four generic
// Poly1305 invocations.  This is the hot path of Chaff/Winnow.
func tags1(key []byte) (t0lo, t0hi, t1lo, t1hi uint64) {
	r0 := binary.LittleEndian.Uint64(key[0:8]) & 0x0FFFFFFC0FFFFFFF
	r1 := binary.LittleEndian.Uint64(key[8:16]) & 0x0FFFFFFC0FFFFFFC
	s0 := binary.LittleEndian.Uint64(key[16:24])
	s1 := binary.LittleEndian.Uint64(key[24:32])

	// h = 0x130 * r as c0 + c1<<64 + c2<<128.
	hi, lo := bits.Mul64(0x130, r0)
	p1hi, p1lo := bits.Mul64(0x130, r1)
	c0 := lo
	c1, carry := bits.Add64(hi, p1lo, 0)
	c2 := p1hi + carry

	// Reduce modulo p = 2^130-5: value >> 130 contributes 5*that to
	// the low 130 bits.
	k := c2 >> 2
	var c1c, c2c uint64
	h0, c1c := bits.Add64(c0, 5*k, 0)
	h1, c2c := bits.Add64(c1, 0, c1c)
	h2 := (c2 & 3) + c2c
	h0, h1, h2 = subP(h0, h1, h2)

	t0lo, t0loCarry := bits.Add64(h0, s0, 0)
	t0hi, _ = bits.Add64(h1, s1, t0loCarry)

	r0h, rcarry := bits.Add64(h0, r0, 0)
	r1h, rcarry2 := bits.Add64(h1, r1, rcarry)
	r2h := h2 + rcarry2
	r0h, r1h, _ = subP(r0h, r1h, r2h)
	t1lo, t1loCarry := bits.Add64(r0h, s0, 0)
	t1hi, _ = bits.Add64(r1h, s1, t1loCarry)
	return
}

// subP conditionally subtracts p = 2^130-5 once, in constant time.
func subP(h0, h1, h2 uint64) (uint64, uint64, uint64) {
	const (
		p0 = 0xFFFFFFFFFFFFFFFB
		p1 = 0xFFFFFFFFFFFFFFFF
		p2 = 3
	)
	d0, b := bits.Sub64(h0, p0, 0)
	d1, b := bits.Sub64(h1, p1, b)
	d2, b := bits.Sub64(h2, p2, b)
	mask := b - 1 // all ones when no borrow (h >= p)
	return h0 ^ ((h0 ^ d0) & mask),
		h1 ^ ((h1 ^ d1) & mask),
		h2 ^ ((h2 ^ d2) & mask)
}

// ceq returns 1 if the two 128-bit values are equal, 0 otherwise,
// without data-dependent branches.
func ceq(alo, ahi, blo, bhi uint64) uint64 {
	x := (alo ^ blo) | (ahi ^ bhi)
	return ((x | -x) >> 63) ^ 1
}

// chaff writes len(in)*EnlargeFactor bytes into out.
func chaff(authKey *[32]byte, noncePrfx, in, out []byte) {
	var keys [8 * 64]byte
	var hNonce [16]byte
	var subKey [32]byte
	var ctr [16]byte
	copy(hNonce[:8], noncePrfx)
	// XSalsa20's subkey depends only on noncePrfx; derive it once per
	// packet instead of once per input byte.
	salsa.HSalsa20(&subKey, &hNonce, authKey, &salsa.Sigma)
	for n, b := range in {
		binary.BigEndian.PutUint64(ctr[:8], uint64(n))
		salsa.XORKeyStream(keys[:], zeroKeys[:], &ctr, &subKey)
		for i := 0; i < 8; i++ {
			v := (b >> uint8(i)) & 1
			k1 := keys[64*i : 64*i+32]
			k2 := keys[64*i+32 : 64*i+64]
			a0lo, a0hi, a1lo, a1hi := tags1(k1)
			b0lo, b0hi, b1lo, b1hi := tags1(k2)
			mask := uint64(0) - uint64(v)
			off := n*256 + i*32
			// v == 0: [tag1, tag0]; v == 1: [tag0, tag1].
			binary.LittleEndian.PutUint64(
				out[off:off+8],
				a1lo^((a0lo^a1lo)&mask),
			)
			binary.LittleEndian.PutUint64(
				out[off+8:off+16],
				a1hi^((a0hi^a1hi)&mask),
			)
			binary.LittleEndian.PutUint64(
				out[off+16:off+24],
				b0lo^((b0lo^b1lo)&mask),
			)
			binary.LittleEndian.PutUint64(
				out[off+24:off+32],
				b0hi^((b0hi^b1hi)&mask),
			)
		}
	}
	zero(keys[:])
	zero(subKey[:])
}

// winnow writes len(in)/EnlargeFactor bytes into out or returns an
// authentication error.
func winnow(authKey *[32]byte, noncePrfx, in, out []byte) error {
	var keys [8 * 64]byte
	var hNonce [16]byte
	var subKey [32]byte
	var ctr [16]byte
	copy(hNonce[:8], noncePrfx)
	salsa.HSalsa20(&subKey, &hNonce, authKey, &salsa.Sigma)
	for n := 0; n < len(out); n++ {
		binary.BigEndian.PutUint64(ctr[:8], uint64(n))
		salsa.XORKeyStream(keys[:], zeroKeys[:], &ctr, &subKey)
		var v byte
		for i := 0; i < 8; i++ {
			a0lo, a0hi, a1lo, a1hi := tags1(keys[64*i : 64*i+32])
			b0lo, b0hi, b1lo, b1hi := tags1(keys[64*i+32 : 64*i+64])
			off := n*256 + i*32
			s1lo := binary.LittleEndian.Uint64(in[off : off+8])
			s1hi := binary.LittleEndian.Uint64(in[off+8 : off+16])
			s2lo := binary.LittleEndian.Uint64(in[off+16 : off+24])
			s2hi := binary.LittleEndian.Uint64(in[off+24 : off+32])
			is01 := ceq(s1lo, s1hi, a1lo, a1hi)
			is00 := ceq(s1lo, s1hi, a0lo, a0hi)
			is11 := ceq(s2lo, s2hi, b1lo, b1hi)
			is10 := ceq(s2lo, s2hi, b0lo, b0hi)
			if is01&is10|is00&is11 == 0 {
				zero(keys[:])
				zero(subKey[:])
				return errors.New("Invalid authenticator received")
			}
			v |= byte(is11) << uint8(i)
		}
		out[n] = v
	}
	zero(keys[:])
	zero(subKey[:])
	return nil
}

// Chaff the data. noncePrfx is 64-bit nonce. Output data will be much
// larger: 256 bytes for each input byte.
func Chaff(authKey *[32]byte, noncePrfx, in []byte) []byte {
	out := make([]byte, len(in)*EnlargeFactor)
	chaff(authKey, noncePrfx, in, out)
	return out
}

// ChaffInto is like Chaff, but writes into dst, which must have exactly
// len(in)*EnlargeFactor bytes.  It allows callers to avoid a temporary
// allocation and copy.
func ChaffInto(dst []byte, authKey *[32]byte, noncePrfx, in []byte) error {
	if len(dst) != len(in)*EnlargeFactor {
		return errors.New("Invalid destination size")
	}
	chaff(authKey, noncePrfx, in, dst)
	return nil
}

// Winnow the data.
func Winnow(authKey *[32]byte, noncePrfx, in []byte) ([]byte, error) {
	if len(in)%EnlargeFactor != 0 {
		return nil, errors.New("Invalid data size")
	}
	out := make([]byte, len(in)/EnlargeFactor)
	if err := winnow(authKey, noncePrfx, in, out); err != nil {
		return nil, err
	}
	return out, nil
}

// WinnowInto is like Winnow, but writes into dst, which must have exactly
// len(in)/EnlargeFactor bytes.
func WinnowInto(dst []byte, authKey *[32]byte, noncePrfx, in []byte) error {
	if len(in)%EnlargeFactor != 0 || len(dst) != len(in)/EnlargeFactor {
		return errors.New("Invalid data size")
	}
	return winnow(authKey, noncePrfx, in, dst)
}
