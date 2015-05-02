package govpn

import (
	"net"
	"testing"
)

var (
	peer       *Peer
	plaintext  []byte
	ready      chan struct{}
	dummy      = &Dummy{}
	ciphertext []byte
	addr       *net.UDPAddr
	peerId     *PeerId
)

func init() {
	MTU = 1500
	addr, _ = net.ResolveUDPAddr("udp", "[::1]:1")
	peerId = IDDecode("ffffffffffffffffffffffffffffffff")
	peer = newPeer(addr, *peerId, 128, new([KeySize]byte))
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
	peer = newPeer(addr, *peerId, 128, new([KeySize]byte))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !peer.UDPProcess(ciphertext, dummy, ready) {
			b.Fail()
		}
	}
}
