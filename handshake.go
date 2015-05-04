/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2015 Sergey Matveev <stargrave@stargrave.org>

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
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/salsa20/salsa"
	"golang.org/x/crypto/xtea"
)

const (
	RSize = 8
	SSize = 32
)

type Handshake struct {
	addr     *net.UDPAddr
	LastPing time.Time
	Conf     *PeerConf
	dsaPubH  *[ed25519.PublicKeySize]byte
	key      *[32]byte
	rNonce   *[RSize]byte
	dhPriv   *[32]byte    // own private DH key
	rServer  *[RSize]byte // random string for authentication
	rClient  *[RSize]byte
	sServer  *[SSize]byte // secret string for main key calculation
	sClient  *[SSize]byte
}

func keyFromSecrets(server, client []byte) *[SSize]byte {
	k := new([SSize]byte)
	for i := 0; i < SSize; i++ {
		k[i] = server[i] ^ client[i]
	}
	return k
}

// Apply HSalsa20 function for data. Used to hash public keys.
func HApply(data *[32]byte) {
	salsa.HSalsa20(data, new([16]byte), data, &salsa.Sigma)
}

// Zero handshake's memory state
func (h *Handshake) Zero() {
	if h.rNonce != nil {
		sliceZero(h.rNonce[:])
	}
	if h.dhPriv != nil {
		sliceZero(h.dhPriv[:])
	}
	if h.key != nil {
		sliceZero(h.key[:])
	}
	if h.dsaPubH != nil {
		sliceZero(h.dsaPubH[:])
	}
	if h.rServer != nil {
		sliceZero(h.rServer[:])
	}
	if h.rClient != nil {
		sliceZero(h.rClient[:])
	}
	if h.sServer != nil {
		sliceZero(h.sServer[:])
	}
	if h.sClient != nil {
		sliceZero(h.sClient[:])
	}
}

func (h *Handshake) rNonceNext(count uint64) []byte {
	nonce := make([]byte, RSize)
	nonceCurrent, _ := binary.Uvarint(h.rNonce[:])
	binary.PutUvarint(nonce, nonceCurrent+count)
	return nonce
}

func dhKeypairGen() (*[32]byte, *[32]byte) {
	priv := new([32]byte)
	pub := new([32]byte)
	repr := new([32]byte)
	reprFound := false
	for !reprFound {
		if _, err := rand.Read(priv[:]); err != nil {
			panic("Can not read random for DH private key")
		}
		reprFound = extra25519.ScalarBaseMult(pub, repr, priv)
	}
	return priv, repr
}

func dhKeyGen(priv, pub *[32]byte) *[32]byte {
	key := new([32]byte)
	curve25519.ScalarMult(key, priv, pub)
	HApply(key)
	return key
}

// Create new handshake state.
func HandshakeNew(addr *net.UDPAddr, conf *PeerConf) *Handshake {
	state := Handshake{
		addr:     addr,
		LastPing: time.Now(),
		Conf:     conf,
	}
	state.dsaPubH = new([ed25519.PublicKeySize]byte)
	copy(state.dsaPubH[:], state.Conf.DSAPub[:])
	HApply(state.dsaPubH)
	return &state
}

// Generate ID tag from client identification and data.
func idTag(id *PeerId, data []byte) []byte {
	ciph, err := xtea.NewCipher(id[:])
	if err != nil {
		panic(err)
	}
	enc := make([]byte, xtea.BlockSize)
	ciph.Encrypt(enc, data[:xtea.BlockSize])
	return enc
}

// Start handshake's procedure from the client. It is the entry point
// for starting the handshake procedure. You have to specify outgoing
// conn address, remote's addr address, our own peer configuration.
// First handshake packet will be sent immediately.
func HandshakeStart(conf *PeerConf, conn *net.UDPConn, addr *net.UDPAddr) *Handshake {
	state := HandshakeNew(addr, conf)

	var dhPubRepr *[32]byte
	state.dhPriv, dhPubRepr = dhKeypairGen()

	state.rNonce = new([RSize]byte)
	if _, err := rand.Read(state.rNonce[:]); err != nil {
		panic("Can not read random for handshake nonce")
	}
	enc := make([]byte, 32)
	salsa20.XORKeyStream(enc, dhPubRepr[:], state.rNonce[:], state.dsaPubH)
	data := append(state.rNonce[:], enc...)
	data = append(data, idTag(state.Conf.Id, state.rNonce[:])...)
	if _, err := conn.WriteTo(data, addr); err != nil {
		panic(err)
	}
	return state
}

// Process handshake message on the server side.
// This function is intended to be called on server's side.
// Our outgoing conn connection and received data are required.
// If this is the final handshake message, then new Peer object
// will be created and used as a transport. If no mutually
// authenticated Peer is ready, then return nil.
func (h *Handshake) Server(conn *net.UDPConn, data []byte) *Peer {
	// R + ENC(H(DSAPub), R, El(CDHPub)) + IDtag
	if len(data) == 48 && h.rNonce == nil {
		// Generate DH keypair
		var dhPubRepr *[32]byte
		h.dhPriv, dhPubRepr = dhKeypairGen()

		h.rNonce = new([RSize]byte)
		copy(h.rNonce[:], data[:RSize])

		// Decrypt remote public key and compute shared key
		cDHRepr := new([32]byte)
		salsa20.XORKeyStream(
			cDHRepr[:],
			data[RSize:RSize+32],
			h.rNonce[:],
			h.dsaPubH,
		)
		cDH := new([32]byte)
		extra25519.RepresentativeToPublicKey(cDH, cDHRepr)
		h.key = dhKeyGen(h.dhPriv, cDH)

		encPub := make([]byte, 32)
		salsa20.XORKeyStream(encPub, dhPubRepr[:], h.rNonceNext(1), h.dsaPubH)

		// Generate R* and encrypt them
		h.rServer = new([RSize]byte)
		if _, err := rand.Read(h.rServer[:]); err != nil {
			panic("Can not read random for handshake random key")
		}
		h.sServer = new([SSize]byte)
		if _, err := rand.Read(h.sServer[:]); err != nil {
			panic("Can not read random for handshake shared key")
		}
		encRs := make([]byte, RSize+SSize)
		salsa20.XORKeyStream(encRs, append(h.rServer[:], h.sServer[:]...), h.rNonce[:], h.key)

		// Send that to client
		if _, err := conn.WriteTo(
			append(encPub, append(encRs, idTag(h.Conf.Id, encPub)...)...), h.addr); err != nil {
			panic(err)
		}
		h.LastPing = time.Now()
	} else
	// ENC(K, R+1, RS + RC + SC + Sign(DSAPriv, K)) + IDtag
	if len(data) == 120 && h.rClient == nil {
		// Decrypted Rs compare rServer
		dec := make([]byte, RSize+RSize+SSize+ed25519.SignatureSize)
		salsa20.XORKeyStream(
			dec,
			data[:RSize+RSize+SSize+ed25519.SignatureSize],
			h.rNonceNext(1),
			h.key,
		)
		if subtle.ConstantTimeCompare(dec[:RSize], h.rServer[:]) != 1 {
			log.Println("Invalid server's random number with", h.addr)
			return nil
		}
		sign := new([ed25519.SignatureSize]byte)
		copy(sign[:], dec[RSize+RSize+SSize:])
		if !ed25519.Verify(h.Conf.DSAPub, h.key[:], sign) {
			log.Println("Invalid signature from", h.addr)
			return nil
		}

		// Send final answer to client
		enc := make([]byte, RSize)
		salsa20.XORKeyStream(enc, dec[RSize:RSize+RSize], h.rNonceNext(2), h.key)
		if _, err := conn.WriteTo(append(enc, idTag(h.Conf.Id, enc)...), h.addr); err != nil {
			panic(err)
		}

		// Switch peer
		peer := newPeer(
			h.addr,
			h.Conf,
			0,
			keyFromSecrets(h.sServer[:], dec[RSize+RSize:RSize+RSize+SSize]))
		h.LastPing = time.Now()
		return peer
	} else {
		log.Println("Invalid handshake message from", h.addr)
	}
	return nil
}

// Process handshake message on the client side.
// This function is intended to be called on client's side.
// Our outgoing conn connection, authentication
// key and received data are required.
// If this is the final handshake message, then new Peer object
// will be created and used as a transport. If no mutually
// authenticated Peer is ready, then return nil.
func (h *Handshake) Client(conn *net.UDPConn, data []byte) *Peer {
	switch len(data) {
	case 80: // ENC(H(DSAPub), R+1, El(SDHPub)) + ENC(K, R, RS + SS) + IDtag
		if h.key != nil {
			log.Println("Invalid handshake stage from", h.addr)
			return nil
		}

		// Decrypt remote public key and compute shared key
		sDHRepr := new([32]byte)
		salsa20.XORKeyStream(sDHRepr[:], data[:32], h.rNonceNext(1), h.dsaPubH)
		sDH := new([32]byte)
		extra25519.RepresentativeToPublicKey(sDH, sDHRepr)
		h.key = dhKeyGen(h.dhPriv, sDH)

		// Decrypt Rs
		decRs := make([]byte, RSize+SSize)
		salsa20.XORKeyStream(decRs, data[SSize:32+RSize+SSize], h.rNonce[:], h.key)
		h.rServer = new([RSize]byte)
		copy(h.rServer[:], decRs[:RSize])
		h.sServer = new([SSize]byte)
		copy(h.sServer[:], decRs[RSize:])

		// Generate R* and signature and encrypt them
		h.rClient = new([RSize]byte)
		if _, err := rand.Read(h.rClient[:]); err != nil {
			panic("Can not read random for handshake random key")
		}
		h.sClient = new([SSize]byte)
		if _, err := rand.Read(h.sClient[:]); err != nil {
			panic("Can not read random for handshake shared key")
		}
		sign := ed25519.Sign(h.Conf.DSAPriv, h.key[:])

		enc := make([]byte, RSize+RSize+SSize+ed25519.SignatureSize)
		salsa20.XORKeyStream(enc,
			append(h.rServer[:],
				append(h.rClient[:],
					append(h.sClient[:], sign[:]...)...)...), h.rNonceNext(1), h.key)

		// Send that to server
		if _, err := conn.WriteTo(append(enc, idTag(h.Conf.Id, enc)...), h.addr); err != nil {
			panic(err)
		}
		h.LastPing = time.Now()
	case 16: // ENC(K, R+2, RC) + IDtag
		if h.key == nil {
			log.Println("Invalid handshake stage from", h.addr)
			return nil
		}

		// Decrypt rClient
		dec := make([]byte, RSize)
		salsa20.XORKeyStream(dec, data[:RSize], h.rNonceNext(2), h.key)
		if subtle.ConstantTimeCompare(dec, h.rClient[:]) != 1 {
			log.Println("Invalid client's random number with", h.addr)
			return nil
		}

		// Switch peer
		peer := newPeer(h.addr, h.Conf, 1, keyFromSecrets(h.sServer[:], h.sClient[:]))
		h.LastPing = time.Now()
		return peer
	default:
		log.Println("Invalid handshake message from", h.addr)
	}
	return nil
}
