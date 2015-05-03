package govpn

import (
	"net"
	"testing"
	"time"
)

var (
	peer       *Peer
	plaintext  []byte
	ready      chan struct{}
	dummy      = &Dummy{}
	ciphertext []byte
	addr       *net.UDPAddr
	peerId     *PeerId
	conf       *PeerConf
)

func init() {
	MTU = 1500
	addr, _ = net.ResolveUDPAddr("udp", "[::1]:1")
	peerId = IDDecode("ffffffffffffffffffffffffffffffff")
	conf = &PeerConf{
		Id:          peerId,
		Timeout:     time.Second * time.Duration(TimeoutDefault),
		Noncediff:   1,
		NoiseEnable: false,
		CPR:         0,
	}
	peer = newPeer(addr, conf, 128, new([SSize]byte))
	plaintext = make([]byte, 789)
	ready = make(chan struct{})
	go func() {
		for {
			<-ready
		}
	}()
}

type Dummy struct{}

func (d *Dummy) WriteTo(b []byte, addr net.Addr) (int, error) {
	ciphertext = b
	return len(b), nil
}

func (d *Dummy) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func BenchmarkEnc(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peer.NonceOur = 128
		peer.EthProcess(plaintext, dummy, ready)
	}
}

func BenchmarkDec(b *testing.B) {
	peer.EthProcess(plaintext, dummy, ready)
	peer = newPeer(addr, conf, 128, new([SSize]byte))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !peer.UDPProcess(ciphertext, dummy, ready) {
			b.Fail()
		}
	}
}
