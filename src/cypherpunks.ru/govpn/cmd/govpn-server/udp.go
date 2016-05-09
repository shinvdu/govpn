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
	"log"
	"net"

	"cypherpunks.ru/govpn"
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
	govpn.BothPrintf(`[udp-listen bind="%s"]`, *bindAddr)

	udpBufs <- make([]byte, govpn.MTUMax)
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
				govpn.Printf(`[receive-failed bind="%s" err="%s"]`, *bindAddr, err)
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

			govpn.Printf(
				`[handshake-completed bind="%s" addr="%s" peer="%s"]`,
				*bindAddr, addr, peerId.String(),
			)
			hs.Zero()
			hsLock.Lock()
			delete(handshakes, addr)
			hsLock.Unlock()

			go func() {
				udpBufs <- make([]byte, govpn.MTUMax)
				udpBufs <- make([]byte, govpn.MTUMax)
			}()
			peersByIdLock.RLock()
			addrPrev, exists = peersById[*peer.Id]
			peersByIdLock.RUnlock()
			if exists {
				peersLock.Lock()
				peers[addrPrev].terminator <- struct{}{}
				ps = &PeerState{
					peer:       peer,
					tap:        peers[addrPrev].tap,
					terminator: make(chan struct{}),
				}
				go func(ps PeerState) {
					govpn.PeerTapProcessor(ps.peer, ps.tap, ps.terminator)
					<-udpBufs
					<-udpBufs
				}(*ps)
				peersByIdLock.Lock()
				kpLock.Lock()
				delete(peers, addrPrev)
				delete(knownPeers, addrPrev)
				peers[addr] = ps
				knownPeers[addr] = &peer
				peersById[*peer.Id] = addr
				peersLock.Unlock()
				peersByIdLock.Unlock()
				kpLock.Unlock()
				govpn.Printf(
					`[rehandshake-completed bind="%s" peer="%s"]`,
					*bindAddr, peer.Id.String(),
				)
			} else {
				go func(addr string, peer *govpn.Peer) {
					ifaceName, err := callUp(peer.Id, peer.Addr)
					if err != nil {
						return
					}
					tap, err := govpn.TAPListen(ifaceName, peer.MTU)
					if err != nil {
						govpn.Printf(
							`[tap-failed bind="%s" peer="%s" err="%s"]`,
							*bindAddr, peer.Id.String(), err,
						)
						return
					}
					ps = &PeerState{
						peer:       peer,
						tap:        tap,
						terminator: make(chan struct{}),
					}
					go func(ps PeerState) {
						govpn.PeerTapProcessor(ps.peer, ps.tap, ps.terminator)
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
					govpn.Printf(`[peer-created bind="%s" peer="%s"]`, *bindAddr, peer.Id.String())
				}(addr, peer)
			}
			goto Finished
		CheckID:
			peerId = idsCache.Find(buf[:n])
			if peerId == nil {
				govpn.Printf(`[identity-unknown bind="%s" addr="%s"]`, *bindAddr, addr)
				goto Finished
			}
			conf = confs[*peerId]
			if conf == nil {
				govpn.Printf(
					`[conf-get-failed bind="%s" peer="%s"]`,
					*bindAddr, peerId.String(),
				)
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
