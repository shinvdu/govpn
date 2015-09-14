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

package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"time"

	"govpn"
)

func startTCP() {
	bind, err := net.ResolveTCPAddr("tcp", *bindAddr)
	if err != nil {
		log.Fatalln("Can not resolve bind address:", err)
	}
	listener, err := net.ListenTCP("tcp", bind)
	if err != nil {
		log.Fatalln("Can not listen on TCP:", err)
	}
	log.Println("Listening on TCP", *bindAddr)
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				log.Println("Error accepting TCP:", err)
				continue
			}
			go handleTCP(conn)
		}
	}()
}

func handleTCP(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	buf := make([]byte, govpn.MTU)
	var n int
	var err error
	var prev int
	var hs *govpn.Handshake
	var ps *PeerState
	var peer *govpn.Peer
	var tap *govpn.TAP
	var conf *govpn.PeerConf
	for {
		if prev == govpn.MTU {
			break
		}
		conn.SetReadDeadline(time.Now().Add(time.Duration(govpn.TimeoutDefault) * time.Second))
		n, err = conn.Read(buf[prev:])
		if err != nil {
			// Either EOFed or timeouted
			break
		}
		prev += n
		peerId := govpn.IDsCache.Find(buf[:prev])
		if peerId == nil {
			continue
		}
		if hs == nil {
			conf = peerId.Conf()
			if conf == nil {
				log.Println("Can not get peer configuration:", peerId.String())
				break
			}
			hs = govpn.NewHandshake(addr, conn, conf)
		}
		peer = hs.Server(buf[:prev])
		prev = 0
		if peer == nil {
			continue
		}
		hs.Zero()
		peersByIdLock.RLock()
		addrPrev, exists := peersById[*peer.Id]
		peersByIdLock.RUnlock()
		if exists {
			peersLock.RLock()
			tap = peers[addrPrev].tap
			ps = &PeerState{
				peer:       peer,
				tap:        tap,
				terminator: peers[addrPrev].terminator,
			}
			peersLock.RUnlock()
			ps.terminator <- struct{}{}
			peersLock.Lock()
			peersByIdLock.Lock()
			kpLock.Lock()
			delete(peers, addrPrev)
			delete(knownPeers, addrPrev)
			delete(peersById, *peer.Id)
			peers[addr] = ps
			knownPeers[addr] = &peer
			peersById[*peer.Id] = addr
			peersLock.Unlock()
			peersByIdLock.Unlock()
			kpLock.Unlock()
			go peerReady(*ps)
			log.Println("Rehandshake finished:", peer.Id.String())
		} else {
			ifaceName, err := callUp(peer.Id)
			if err != nil {
				break
			}
			tap, err = govpn.TAPListen(ifaceName)
			if err != nil {
				log.Println("Unable to create TAP:", err)
				break
			}
			ps = &PeerState{
				peer:       peer,
				tap:        tap,
				terminator: make(chan struct{}, 1),
			}
			go peerReady(*ps)
			peersLock.Lock()
			peersByIdLock.Lock()
			kpLock.Lock()
			peers[addr] = ps
			peersById[*peer.Id] = addr
			knownPeers[addr] = &peer
			peersLock.Unlock()
			peersByIdLock.Unlock()
			kpLock.Unlock()
			log.Println("New peer:", peer.Id.String())
		}
		break
	}
	if hs != nil {
		hs.Zero()
	}
	if peer == nil {
		return
	}

	nonceExpectation := make([]byte, govpn.NonceSize)
	binary.BigEndian.PutUint64(nonceExpectation, peer.NonceExpect)
	peer.NonceCipher.Encrypt(nonceExpectation, nonceExpectation)
	prev = 0
	var i int
	for {
		if prev == govpn.MTU {
			break
		}
		conn.SetReadDeadline(time.Now().Add(conf.Timeout))
		n, err = conn.Read(buf[prev:])
		if err != nil {
			// Either EOFed or timeouted
			break
		}
		prev += n
	CheckMore:
		if prev < govpn.MinPktLength {
			continue
		}
		i = bytes.Index(buf[:prev], nonceExpectation)
		if i == -1 {
			continue
		}
		if !peer.PktProcess(buf[:i+govpn.NonceSize], tap, false) {
			break
		}
		binary.BigEndian.PutUint64(nonceExpectation, peer.NonceExpect)
		peer.NonceCipher.Encrypt(nonceExpectation, nonceExpectation)
		copy(buf, buf[i+govpn.NonceSize:prev])
		prev = prev - i - govpn.NonceSize
		goto CheckMore
	}
	peer.Zero()
}
