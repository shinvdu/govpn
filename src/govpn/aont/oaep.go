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

// All-Or-Nothing-Transform, based on OAEP.
//
// This package implements OAEP (Optimal Asymmetric Encryption Padding)
// (http://cseweb.ucsd.edu/~mihir/papers/oaep.html)
// used there as All-Or-Nothing-Transformation
// (http://theory.lcs.mit.edu/~cis/pubs/rivest/fusion.ps).
// We do not fix OAEP parts lengths, instead we add hash-based
// checksum like in SAEP+
// (http://crypto.stanford.edu/~dabo/abstracts/saep.html).
//
// AONT takes 128-bit random r, data M to be encoded and produce the
// package PKG:
//
//     PKG = P1 || P2
//      P1 = HKDF(BLAKE2b, r) XOR (M || BLAKE2b(r || M)) ||
//      P2 = BLAKE2b(P1) XOR r
package aont

import (
	"crypto/subtle"
	"errors"

	"github.com/dchest/blake2b"
	"golang.org/x/crypto/hkdf"
)

const (
	HSize = 32
	RSize = 16
)

// Encode the data, produce AONT package. Data size will be larger than
// the original one for 48 bytes.
func Encode(r *[RSize]byte, in []byte) ([]byte, error) {
	out := make([]byte, len(in)+HSize+RSize)
	hr := hkdf.New(blake2b.New512, r[:], nil, nil)
	if _, err := hr.Read(out[:len(in)+HSize]); err != nil {
		return nil, err
	}
	var i int
	for i = 0; i < len(in); i++ {
		out[i] ^= in[i]
	}
	h := blake2b.New256()
	h.Write(r[:])
	h.Write(in)
	for _, b := range h.Sum(nil) {
		out[i] ^= b
		i++
	}
	h.Reset()
	h.Write(out[:i])
	for _, b := range h.Sum(nil)[:RSize] {
		out[i] = b ^ r[i-len(in)-HSize]
		i++
	}
	return out, nil
}

// Decode the data from AONT package. Data size will be smaller than the
// original one for 48 bytes.
func Decode(in []byte) ([]byte, error) {
	if len(in) < HSize+RSize {
		return nil, errors.New("Too small input buffer")
	}
	h := blake2b.New256()
	h.Write(in[:len(in)-RSize])
	out := make([]byte, len(in)-RSize)
	for i, b := range h.Sum(nil)[:RSize] {
		out[i] = b ^ in[len(in)-RSize+i]
	}
	h.Reset()
	h.Write(out[:RSize])
	hr := hkdf.New(blake2b.New512, out[:RSize], nil, nil)
	if _, err := hr.Read(out); err != nil {
		return nil, err
	}
	for i := 0; i < len(out); i++ {
		out[i] ^= in[i]
	}
	h.Write(out[:len(out)-HSize])
	if subtle.ConstantTimeCompare(h.Sum(nil), out[len(out)-HSize:]) != 1 {
		return nil, errors.New("Invalid checksum")
	}
	return out[:len(out)-HSize], nil
}
