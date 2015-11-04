package govpn

import (
	"testing"
	"time"
)

var (
	peer       *Peer
	plaintext  []byte
	ciphertext []byte
	peerId     *PeerId
	conf       *PeerConf
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
	MTU = 1500
	id := new([IDSize]byte)
	peerId := PeerId(*id)
	conf = &PeerConf{
		Id:      &peerId,
		Timeout: time.Second * time.Duration(TimeoutDefault),
		Noise:   false,
		CPR:     0,
	}
	peer = newPeer(true, "foo", Dummy{&ciphertext}, conf, new([SSize]byte))
	plaintext = make([]byte, 789)
}

func BenchmarkEnc(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peer.EthProcess(plaintext)
	}
}

func BenchmarkDec(b *testing.B) {
	peer = newPeer(true, "foo", Dummy{&ciphertext}, conf, new([SSize]byte))
	peer.EthProcess(plaintext)
	peer = newPeer(true, "foo", Dummy{nil}, conf, new([SSize]byte))
	orig := make([]byte, len(ciphertext))
	copy(orig, ciphertext)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peer.nonceBucket0 = make(map[uint64]struct{}, 1)
		peer.nonceBucket1 = make(map[uint64]struct{}, 1)
		copy(ciphertext, orig)
		if !peer.PktProcess(ciphertext, Dummy{nil}, true) {
			b.Fail()
		}
	}
}
