package govpn

import (
	"testing"
	"time"
)

var (
	peer       *Peer
	plaintext  []byte
	ready      chan struct{}
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

func (d Dummy) Reorderable() bool {
	return true
}

func init() {
	MTU = 1500
	peerId, _ = IDDecode("ffffffffffffffffffffffffffffffff")
	conf = &PeerConf{
		Id:          peerId,
		Timeout:     time.Second * time.Duration(TimeoutDefault),
		NoiseEnable: false,
		CPR:         0,
	}
	peer = newPeer(true, "foo", Dummy{&ciphertext}, conf, new([SSize]byte))
	plaintext = make([]byte, 789)
	ready = make(chan struct{})
	go func() {
		for {
			<-ready
		}
	}()
}

func BenchmarkEnc(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peer.NonceOur = 128
		peer.EthProcess(plaintext, ready)
	}
}

func BenchmarkDec(b *testing.B) {
	peer.EthProcess(plaintext, ready)
	peer = newPeer(true, "foo", Dummy{nil}, conf, new([SSize]byte))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peer.nonceBucket0 = make(map[uint64]struct{}, 1)
		peer.nonceBucket1 = make(map[uint64]struct{}, 1)
		if !peer.PktProcess(ciphertext, Dummy{nil}, ready) {
			b.Fail()
		}
	}
}
