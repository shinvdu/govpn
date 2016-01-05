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
	"testing"
)

func TestHandshakeSymmetric(t *testing.T) {
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(DefaultM, DefaultT, DefaultP, &peerId)
	conf.Verifier = v
	conf.DSAPriv = v.PasswordApply("does not matter")
	hsS := NewHandshake("server", Dummy{&ciphertext}, conf)
	hsC := HandshakeStart("client", Dummy{&ciphertext}, conf)
	hsS.Server(ciphertext)
	hsC.Client(ciphertext)
	if hsS.Server(ciphertext) == nil {
		t.Fail()
	}
	if hsC.Client(ciphertext) == nil {
		t.Fail()
	}
}

func TestHandshakeNoiseSymmetric(t *testing.T) {
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(DefaultM, DefaultT, DefaultP, &peerId)
	conf.Verifier = v
	conf.DSAPriv = v.PasswordApply("does not matter")
	conf.Noise = true
	hsS := NewHandshake("server", Dummy{&ciphertext}, conf)
	hsC := HandshakeStart("client", Dummy{&ciphertext}, conf)
	hsS.Server(ciphertext)
	hsC.Client(ciphertext)
	if hsS.Server(ciphertext) == nil {
		t.Fail()
	}
	if hsC.Client(ciphertext) == nil {
		t.Fail()
	}
	conf.Noise = false
}
func TestHandshakeEnclessSymmetric(t *testing.T) {
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(DefaultM, DefaultT, DefaultP, &peerId)
	conf.Verifier = v
	conf.DSAPriv = v.PasswordApply("does not matter")
	conf.EncLess = true
	conf.Noise = true
	hsS := NewHandshake("server", Dummy{&ciphertext}, conf)
	hsC := HandshakeStart("client", Dummy{&ciphertext}, conf)
	hsS.Server(ciphertext)
	hsC.Client(ciphertext)
	if hsS.Server(ciphertext) == nil {
		t.Fail()
	}
	if hsC.Client(ciphertext) == nil {
		t.Fail()
	}
	conf.EncLess = false
	conf.Noise = false
}
