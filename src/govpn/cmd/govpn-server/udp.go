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
	"log"
	"net"

	"govpn"
)

type UDPSender struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (c UDPSender) Write(data []byte) (int, error) {
	return c.conn.WriteToUDP(data, c.addr)
}

var (
	// Buffers for UDP parallel processing
	udpBufs chan []byte = make(chan []byte, 1<<8)
)

func startUDP() {
	bind, err := net.ResolveUDPAddr("udp", *bindAddr)
	if err != nil {
		log.Fatalln("Can not resolve bind address:", err)
	}
	conn, err := net.ListenUDP("udp", bind)
	if err != nil {
		log.Fatalln("Can not listen on UDP:", err)
	}
	log.Println("Listening on UDP", *bindAddr)
	udpBufs <- make([]byte, govpn.MTU)
	go func() {
		var buf []byte
		var raddr *net.UDPAddr
		var addr string
		var n int
		var err error
		var ps *PeerState
		var hs *govpn.Handshake
		var addrPrev string
		var exists bool
		var peerId *govpn.PeerId
		var peer *govpn.Peer
		var conf *govpn.PeerConf
		for {
			buf = <-udpBufs

			n, raddr, err = conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			addr = raddr.String()

			peersLock.RLock()
			ps, exists = peers[addr]
			peersLock.RUnlock()
			if !exists {
				goto CheckHandshake
			}
			go func(ps *govpn.Peer, tap *govpn.TAP, buf []byte, n int) {
				peer.PktProcess(buf[:n], tap, true)
				udpBufs <- buf
			}(ps.peer, ps.tap, buf, n)
			continue
		CheckHandshake:
			hsLock.RLock()
			hs, exists = handshakes[addr]
			hsLock.RUnlock()
			if !exists {
				goto CheckID
			}
			peer = hs.Server(buf[:n])
			if peer == nil {
				goto Finished
			}

			log.Println("Peer handshake finished:", addr)
			hs.Zero()
			hsLock.Lock()
			delete(handshakes, addr)
			hsLock.Unlock()

			go func() {
				udpBufs <- make([]byte, govpn.MTU)
				udpBufs <- make([]byte, govpn.MTU)
			}()
			peersByIdLock.RLock()
			addrPrev, exists = peersById[*peer.Id]
			peersByIdLock.RUnlock()
			if exists {
				peersLock.RLock()
				ps = &PeerState{
					peer:       peer,
					tap:        peers[addrPrev].tap,
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
				go func(ps PeerState) {
					peerReady(ps)
					<-udpBufs
					<-udpBufs
				}(*ps)
				log.Println("Rehandshake finished:", peer.Id.String())
			} else {
				go func(addr string, peer *govpn.Peer) {
					ifaceName, err := callUp(peer.Id)
					if err != nil {
						return
					}
					tap, err := govpn.TAPListen(ifaceName)
					if err != nil {
						log.Println("Unable to create TAP:", err)
						return
					}
					ps = &PeerState{
						peer:       peer,
						tap:        tap,
						terminator: make(chan struct{}, 1),
					}
					go func(ps PeerState) {
						peerReady(ps)
						<-udpBufs
						<-udpBufs
					}(*ps)
					peersLock.Lock()
					peersByIdLock.Lock()
					kpLock.Lock()
					peers[addr] = ps
					knownPeers[addr] = &peer
					peersById[*peer.Id] = addr
					peersLock.Unlock()
					peersByIdLock.Unlock()
					kpLock.Unlock()
					log.Println("New peer:", peer.Id.String())
				}(addr, peer)
			}
			goto Finished
		CheckID:
			peerId = govpn.IDsCache.Find(buf[:n])
			if peerId == nil {
				log.Println("Unknown identity from:", addr)
				goto Finished
			}
			conf = peerId.Conf()
			if conf == nil {
				log.Println("Can not get peer configuration:", peerId.String())
				goto Finished
			}
			hs = govpn.NewHandshake(
				addr,
				UDPSender{conn: conn, addr: raddr},
				conf,
			)
			hs.Server(buf[:n])
			hsLock.Lock()
			handshakes[addr] = hs
			hsLock.Unlock()
		Finished:
			udpBufs <- buf
		}
	}()
}
