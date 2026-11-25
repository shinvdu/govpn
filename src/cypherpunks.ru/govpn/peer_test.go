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
	"testing/quick"
	"time"
)

var (
	testPeer   *Peer
	testPt     []byte
	testCt     []byte
	testPeerId PeerId
	testConf   *PeerConf
)

type Dummy struct {
	dst *[]byte
}

func (d Dummy) Write(b []byte) (int, error) {
	if d.dst != nil {
		*d.dst = b
	}
	return len(b), nil
}

func init() {
	id := new([IDSize]byte)
	testPeerId = PeerId(*id)
	testConf = &PeerConf{
		Id:      &testPeerId,
		MTU:     MTUDefault,
		Timeout: time.Second * time.Duration(TimeoutDefault),
	}
	testPeer = newPeer(true, "foo", Dummy{&testCt}, testConf, new([SSize]byte))
	testPt = make([]byte, 789)
}

func TestTransportSymmetric(t *testing.T) {
	peerd := newPeer(true, "foo", Dummy{nil}, testConf, new([SSize]byte))
	f := func(payload []byte) bool {
		if len(payload) == 0 {
			return true
		}
		testPeer.EthProcess(payload)
		return peerd.PktProcess(testCt, Dummy{nil}, true)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestTransportSymmetricNoise(t *testing.T) {
	peerd := newPeer(true, "foo", Dummy{nil}, testConf, new([SSize]byte))
	testPeer.NoiseEnable = true
	peerd.NoiseEnable = true
	f := func(payload []byte) bool {
		if len(payload) == 0 {
			return true
		}
		testPeer.EthProcess(payload)
		return peerd.PktProcess(testCt, Dummy{nil}, true)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
	testPeer.NoiseEnable = true
}

func TestTransportSymmetricEncless(t *testing.T) {
	peerd := newPeer(true, "foo", Dummy{nil}, testConf, new([SSize]byte))
	testPeer.Encless = true
	testPeer.NoiseEnable = true
	peerd.Encless = true
	peerd.NoiseEnable = true
	f := func(payload []byte) bool {
		if len(payload) == 0 {
			return true
		}
		testPeer.EthProcess(payload)
		return peerd.PktProcess(testCt, Dummy{nil}, true)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
	testPeer.NoiseEnable = false
	testPeer.Encless = false
}

func BenchmarkEnc(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testPeer.EthProcess(testPt)
	}
}

func BenchmarkDec(b *testing.B) {
	testPeer = newPeer(true, "foo", Dummy{&testCt}, testConf, new([SSize]byte))
	testPeer.EthProcess(testPt)
	testPeer = newPeer(true, "foo", Dummy{nil}, testConf, new([SSize]byte))
	orig := make([]byte, len(testCt))
	copy(orig, testCt)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testPeer.nonceInit = false
		testPeer.nonceWindow = [5]uint64{}
		testPeer.nonceLatest = 0
		copy(testCt, orig)
		if !testPeer.PktProcess(testCt, Dummy{nil}, true) {
			b.Fail()
		}
	}
}

func TestMaxPayload(t *testing.T) {
	conf := &PeerConf{Id: &testPeerId, MTU: MTUDefault, Timeout: testConf.Timeout}
	plain := newPeer(true, "foo", Dummy{nil}, conf, new([SSize]byte))
	if got := plain.maxPayload(); got != MTUDefault-1 {
		t.Fatalf("plain maxPayload = %d, want %d", got, MTUDefault-1)
	}
	noisyConf := &PeerConf{
		Id: &testPeerId, MTU: MTUDefault, Timeout: testConf.Timeout, Noise: true,
	}
	noisy := newPeer(true, "foo", Dummy{nil}, noisyConf, new([SSize]byte))
	if got := noisy.maxPayload(); got != MTUDefault-25 {
		t.Fatalf("noise maxPayload = %d, want %d", got, MTUDefault-25)
	}
	enclessConf := &PeerConf{
		Id: &testPeerId, MTU: MTUDefault, Timeout: testConf.Timeout,
		Noise: true, Encless: true,
	}
	encless := newPeer(true, "foo", Dummy{nil}, enclessConf, new([SSize]byte))
	if got := encless.maxPayload(); got != MTUDefault-9 {
		t.Fatalf("encless maxPayload = %d, want %d", got, MTUDefault-9)
	}
}

func TestNonceWindow(t *testing.T) {
	var p Peer
	if !p.nonceAccept(2) {
		t.Fatal("first serial rejected")
	}
	if !p.nonceAccept(6) {
		t.Fatal("forward jump rejected")
	}
	if !p.nonceAccept(4) {
		t.Fatal("out-of-order serial rejected")
	}
	if p.nonceAccept(4) {
		t.Fatal("duplicate serial accepted")
	}
	if !p.nonceAccept(0) {
		t.Fatal("old serial within window rejected")
	}
	if p.nonceAccept(0) {
		t.Fatal("old duplicate serial accepted")
	}
	// Jump beyond the window: all previous serials become stale.
	if !p.nonceAccept(300) {
		t.Fatal("large forward jump rejected")
	}
	if p.nonceAccept(6) {
		t.Fatal("serial older than window accepted")
	}
	if !p.nonceAccept(300 - 256) {
		t.Fatal("boundary serial rejected")
	}
	if p.nonceAccept(300 - 258) {
		t.Fatal("serial beyond boundary accepted")
	}
}

func TestEthProcessRejectsOversized(t *testing.T) {
	conf := &PeerConf{
		Id: &testPeerId, MTU: MTUDefault, Timeout: testConf.Timeout, Noise: true,
	}
	var written int
	peer := newPeer(true, "foo", writerFunc(func(b []byte) (int, error) {
		written++
		return len(b), nil
	}), conf, new([SSize]byte))
	peer.EthProcess(make([]byte, MTUDefault-25))
	if written != 1 {
		t.Fatalf("max-sized packet not sent, written=%d", written)
	}
	peer.EthProcess(make([]byte, MTUDefault-24))
	if written != 1 {
		t.Fatalf("oversized packet was sent, written=%d", written)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func BenchmarkEncNoiseMTU(b *testing.B) {
	conf := &PeerConf{
		Id: &testPeerId, MTU: MTUDefault, Timeout: testConf.Timeout,
		Noise: true,
	}
	peer := newPeer(true, "foo", Dummy{nil}, conf, new([SSize]byte))
	payload := make([]byte, peer.maxPayload())
	Rand.Read(payload)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peer.EthProcess(payload)
	}
}

func BenchmarkEnclessEncodeMTU(b *testing.B) {
	nonce := make([]byte, NonceSize)
	data := make([]byte, MTUDefault-9)
	Rand.Read(nonce)
	Rand.Read(data)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EnclessEncode(testKey, nonce, data)
	}
}

func BenchmarkEnclessDecodeMTU(b *testing.B) {
	nonce := make([]byte, NonceSize)
	data := make([]byte, MTUDefault-9)
	Rand.Read(nonce)
	Rand.Read(data)
	encoded, _ := EnclessEncode(testKey, nonce, data)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EnclessDecode(testKey, nonce, encoded)
	}
}

func TestTransportBigger(t *testing.T) {
	tmp := make([]byte, MTUMax*4)
	Rand.Read(tmp)
	testPeer.PktProcess(tmp, Dummy{nil}, true)
}
