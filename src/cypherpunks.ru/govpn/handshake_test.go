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
	"sync"
	"testing"
)

func TestHandshakeConcurrentZero(t *testing.T) {
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerId)
	conf := &PeerConf{
		Id:       &testPeerId,
		MTU:      MTUDefault,
		Timeout:  testConf.Timeout,
		Verifier: v,
		DSAPriv:  v.PasswordApply("does not matter"),
	}
	hs := NewHandshake("server", Dummy{nil}, conf)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		hs.Zero()
	}()
	garbage := make([]byte, 256)
	for i := 0; i < 20; i++ {
		hs.Server(garbage)
		hs.LastPingTime()
	}
	wg.Wait()
	hs.Zero()
}

func TestHandshakeMalformedStages(t *testing.T) {
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerId)
	conf := &PeerConf{
		Id:       &testPeerId,
		MTU:      MTUDefault,
		Timeout:  testConf.Timeout,
		Verifier: v,
		DSAPriv:  v.PasswordApply("does not matter"),
		Encless:  true,
		Noise:    true,
	}
	msgSize := EnclessEnlargeSize + MTUDefault

	// Server: a malformed first message leaves rNonce set but key nil.
	// A following message must be rejected, not panic on the nil key.
	hsS := NewHandshake("server", Dummy{nil}, conf)
	if hsS.Server(make([]byte, msgSize)) != nil {
		t.Fatal("malformed first message accepted")
	}
	if hsS.Server(make([]byte, msgSize)) != nil {
		t.Fatal("malformed second message accepted")
	}

	// Client: a valid first half sets key but the second half fails,
	// leaving rClient nil.  A following final-stage message must not
	// dereference the nil rClient.
	hsC := HandshakeStart("client", Dummy{nil}, conf)
	firstHalf, err := EnclessEncode(
		hsC.dsaPubH, hsC.rNonceNext(1), make([]byte, MTUDefault),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondHalf := make([]byte, EnclessEnlargeSize+MTUDefault-NonceSize)
	data := append(firstHalf, secondHalf...)
	data = append(data, make([]byte, 8)...)
	if hsC.Client(data) != nil {
		t.Fatal("malformed server reply accepted")
	}
	if hsC.Client(make([]byte, msgSize)) != nil {
		t.Fatal("message after partial handshake accepted")
	}
}

func TestHandshakeMinNoiseMTU(t *testing.T) {
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerId)
	for _, encless := range []bool{false, true} {
		conf := &PeerConf{
			Id:       &testPeerId,
			MTU:      MTUMinNoise,
			Timeout:  testConf.Timeout,
			Verifier: v,
			DSAPriv:  v.PasswordApply("does not matter"),
			Noise:    true,
			Encless:  encless,
		}
		hsS := NewHandshake("server", Dummy{&testCt}, conf)
		hsC := HandshakeStart("client", Dummy{&testCt}, conf)
		hsS.Server(testCt)
		hsC.Client(testCt)
		if hsS.Server(testCt) == nil {
			t.Fatalf("encless=%v: server handshake failed", encless)
		}
		if hsC.Client(testCt) == nil {
			t.Fatalf("encless=%v: client handshake failed", encless)
		}
	}
}

func TestHandshakeSymmetric(t *testing.T) {
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerId)
	testConf.Verifier = v
	testConf.DSAPriv = v.PasswordApply("does not matter")
	hsS := NewHandshake("server", Dummy{&testCt}, testConf)
	hsC := HandshakeStart("client", Dummy{&testCt}, testConf)
	hsS.Server(testCt)
	hsC.Client(testCt)
	if hsS.Server(testCt) == nil {
		t.Fail()
	}
	if hsC.Client(testCt) == nil {
		t.Fail()
	}
}

func TestHandshakeNoiseSymmetric(t *testing.T) {
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerId)
	testConf.Verifier = v
	testConf.DSAPriv = v.PasswordApply("does not matter")
	testConf.Noise = true
	hsS := NewHandshake("server", Dummy{&testCt}, testConf)
	hsC := HandshakeStart("client", Dummy{&testCt}, testConf)
	hsS.Server(testCt)
	hsC.Client(testCt)
	if hsS.Server(testCt) == nil {
		t.Fail()
	}
	if hsC.Client(testCt) == nil {
		t.Fail()
	}
	testConf.Noise = false
}
func TestHandshakeEnclessSymmetric(t *testing.T) {
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerId)
	testConf.Verifier = v
	testConf.DSAPriv = v.PasswordApply("does not matter")
	testConf.Encless = true
	testConf.Noise = true
	hsS := NewHandshake("server", Dummy{&testCt}, testConf)
	hsC := HandshakeStart("client", Dummy{&testCt}, testConf)
	hsS.Server(testCt)
	hsC.Client(testCt)
	if hsS.Server(testCt) == nil {
		t.Fail()
	}
	if hsC.Client(testCt) == nil {
		t.Fail()
	}
	testConf.Encless = false
	testConf.Noise = false
}
