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

package main

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/netip"
	"runtime"

	"cypherpunks.ru/govpn"
)

type UDPSender struct {
	conn *net.UDPConn
	addr netip.AddrPort
}

func (c UDPSender) Write(data []byte) (int, error) {
	return c.conn.WriteToUDPAddrPort(data, c.addr)
}

type handshakeTask struct {
	addr netip.AddrPort
	data []byte
}

const handshakeQueueSize = 256

var (
	udpConn  *net.UDPConn
	hsQueues []chan handshakeTask
)

// addrHash is a cheap allocation-free hash used for flow-cache slots
// and to keep packets from the same address on the same handshake
// worker.
func addrHash(ap netip.AddrPort) uint32 {
	ip := ap.Addr().As16()
	h := binary.LittleEndian.Uint64(ip[0:8]) * 0x9E3779B97F4A7C15
	h ^= binary.LittleEndian.Uint64(ip[8:16])
	h ^= uint64(ap.Port()) * 0x9E3779B97F4A7C15
	h ^= h >> 29
	return uint32(h)
}

func startUDP() {
	bind, err := net.ResolveUDPAddr("udp", *bindAddr)
	if err != nil {
		log.Fatalln("Can not resolve bind address:", err)
	}
	conn, err := net.ListenUDP("udp", bind)
	if err != nil {
		log.Fatalln("Can not listen on UDP:", err)
	}
	udpConn = conn
	log.Println("Listening on UDP:" + *bindAddr)

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	hsWorkers := 4
	if hsWorkers > workers {
		hsWorkers = workers
	}
	hsQueues = make([]chan handshakeTask, hsWorkers)
	for i := range hsQueues {
		hsQueues[i] = make(chan handshakeTask, handshakeQueueSize)
		go handshakeWorker(hsQueues[i])
	}

	// Several concurrent readers: the cost of a packet (syscall,
	// decryption, TAP write) is paid inline, without spawning a
	// goroutine per packet and without an artificial two-buffer limit
	// per peer.
	for i := 0; i < workers; i++ {
		go udpReader()
	}
}

func udpReader() {
	buf := make(
		[]byte,
		govpn.EnclessEnlargeSize+govpn.MTUMax+govpn.NonceSize,
	)
	var cache flowCache
	for {
		n, addr, err := udpConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Println("Unexpected error when receiving", err)
			continue
		}
		if n == 0 {
			continue
		}

		if ps := cache.lookup(addr); ps != nil {
			ps.peer.PktProcess(buf[:n], ps.tap, true)
			continue
		}

		// Unknown peer: this can only be handshake traffic (or a late
		// packet from a disappeared peer).  Handshakes are rare, have
		// to be validated against the identity cache, and are better
		// processed off the data path.
		data := make([]byte, n)
		copy(data, buf[:n])
		q := hsQueues[int(addrHash(addr)%uint32(len(hsQueues)))]
		select {
		case q <- handshakeTask{addr: addr, data: data}:
		default:
			log.Println("Handshake queue is full, dropping packet from", addr)
		}
	}
}

func handshakeWorker(q chan handshakeTask) {
	for task := range q {
		handleUDPHandshake(task.addr, task.data)
	}
}

func handleUDPHandshake(addr netip.AddrPort, data []byte) {
	// Data packets can be queued just before the peer is registered
	// (the final handshake message and the first payload packets may
	// arrive back-to-back).  Re-check the peer table before treating
	// the packet as handshake traffic.
	peersLock.RLock()
	ps := peers[addr]
	peersLock.RUnlock()
	if ps != nil {
		ps.peer.PktProcess(data, ps.tap, true)
		return
	}

	hsLock.RLock()
	hs, exists := handshakes[addr]
	hsLock.RUnlock()
	if exists {
		peer := hs.Server(data)
		if peer == nil {
			return
		}
		log.Println("Peer handshake finished:", addr, peer.Id.String())
		hs.Zero()
		hsLock.Lock()
		delete(handshakes, addr)
		hsLock.Unlock()
		udpSwitchPeer(addr, peer)
		return
	}

	peerId := idsCache.Find(data)
	if peerId == nil {
		// Registration may have completed while we were scanning.
		peersLock.RLock()
		ps = peers[addr]
		peersLock.RUnlock()
		if ps != nil {
			ps.peer.PktProcess(data, ps.tap, true)
			return
		}
		log.Println("Unknown identity from:", addr)
		return
	}
	conf := confGet(*peerId)
	if conf == nil {
		log.Println("Unable to get peer configuration:", peerId.String())
		return
	}
	hs = govpn.NewHandshake(
		addr.String(),
		UDPSender{conn: udpConn, addr: addr},
		conf,
	)
	hs.Server(data)
	hsLock.Lock()
	handshakes[addr] = hs
	hsLock.Unlock()
}

func udpSwitchPeer(addr netip.AddrPort, peer *govpn.Peer) {
	peersByIdLock.RLock()
	addrPrev, exists := peersById[*peer.Id]
	peersByIdLock.RUnlock()
	if exists {
		peersLock.Lock()
		old := peers[addrPrev]
		if old == nil {
			peersLock.Unlock()
			udpNewPeer(addr, peer)
			return
		}
		old.terminate()
		ps := &PeerState{
			peer:       peer,
			tap:        old.tap,
			terminator: make(chan struct{}, 1),
		}
		go peerReady(*ps)
		peersByIdLock.Lock()
		kpLock.Lock()
		delete(peers, addrPrev)
		delete(knownPeers, old.peer.Addr)
		peers[addr] = ps
		knownPeers[peer.Addr] = &peer
		peersById[*peer.Id] = addr
		peersLock.Unlock()
		peersByIdLock.Unlock()
		kpLock.Unlock()
		peersChanged()
		log.Println("Rehandshake processed:", peer.Id.String())
		return
	}
	udpNewPeer(addr, peer)
}

func udpNewPeer(addr netip.AddrPort, peer *govpn.Peer) {
	ifaceName, err := callUp(peer.Id, peer.Addr)
	if err != nil {
		return
	}
	tap, err := govpn.TAPListen(ifaceName, peer.MTU)
	if err != nil {
		log.Println("Unable to create TAP:", err)
		return
	}
	ps := &PeerState{
		peer:       peer,
		tap:        tap,
		terminator: make(chan struct{}, 1),
	}
	go peerReady(*ps)
	peersLock.Lock()
	peersByIdLock.Lock()
	kpLock.Lock()
	peers[addr] = ps
	knownPeers[peer.Addr] = &peer
	peersById[*peer.Id] = addr
	peersLock.Unlock()
	peersByIdLock.Unlock()
	kpLock.Unlock()
	peersChanged()
	log.Println("Peer created:", peer.Id.String())
}
