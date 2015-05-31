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

// Simple secure free software virtual private network daemon.
package main

import (
	"bytes"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"time"

	"govpn"
)

var (
	bindAddr  = flag.String("bind", "[::]:1194", "Bind to address")
	peersPath = flag.String("peers", "peers", "Path to peers keys directory")
	stats     = flag.String("stats", "", "Enable stats retrieving on host:port")
	mtu       = flag.Int("mtu", 1452, "MTU for outgoing packets")
	egdPath   = flag.String("egd", "", "Optional path to EGD socket")
)

type PeerReadyEvent struct {
	peer  *govpn.Peer
	iface string
}

type PeerState struct {
	peer      *govpn.Peer
	tap       *govpn.TAP
	sink      chan []byte
	ready     chan struct{}
	terminate chan struct{}
}

func NewPeerState(peer *govpn.Peer, iface string) *PeerState {
	tap, sink, ready, terminate, err := govpn.TAPListen(iface, peer.Timeout, peer.CPR)
	if err != nil {
		log.Println("Unable to create Eth", err)
		return nil
	}
	state := PeerState{
		peer:      peer,
		tap:       tap,
		sink:      sink,
		ready:     ready,
		terminate: terminate,
	}
	return &state
}

type EthEvent struct {
	peer  *govpn.Peer
	data  []byte
	ready chan struct{}
}

func main() {
	flag.Parse()
	timeout := time.Second * time.Duration(govpn.TimeoutDefault)
	var err error
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	govpn.MTU = *mtu
	govpn.PeersInit(*peersPath)

	if *egdPath != "" {
		log.Println("Using", *egdPath, "EGD")
		govpn.EGDInit(*egdPath)
	}

	bind, err := net.ResolveUDPAddr("udp", *bindAddr)
	if err != nil {
		log.Fatalln("Can not resolve bind address:", err)
	}
	conn, err := net.ListenUDP("udp", bind)
	if err != nil {
		log.Fatalln("Can listen on UDP:", err)
	}
	udpSink, udpReady := govpn.ConnListenUDP(conn)

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)

	hsHeartbeat := time.Tick(timeout)
	go func() { <-hsHeartbeat }()

	var addr string
	var state *govpn.Handshake
	var peerState *PeerState
	var peer *govpn.Peer
	var exists bool
	states := make(map[string]*govpn.Handshake)
	peers := make(map[string]*PeerState)
	peerReadySink := make(chan PeerReadyEvent)
	knownPeers := govpn.KnownPeers(make(map[string]**govpn.Peer))
	var peerReady PeerReadyEvent
	var udpPkt govpn.UDPPkt
	var ethEvent EthEvent
	var peerId *govpn.PeerId
	var peerConf *govpn.PeerConf
	var handshakeProcessForce bool
	ethSink := make(chan EthEvent)

	log.Println(govpn.VersionGet())
	log.Println("Max MTU on TAP interface:", govpn.TAPMaxMTU())
	if *stats != "" {
		log.Println("Stats are going to listen on", *stats)
		statsPort, err := net.Listen("tcp", *stats)
		if err != nil {
			log.Fatalln("Can not listen on stats port:", err)
		}
		go govpn.StatsProcessor(statsPort, &knownPeers)
	}
	log.Println("Server started")

MainCycle:
	for {
		select {
		case <-termSignal:
			break MainCycle
		case <-hsHeartbeat:
			now := time.Now()
			for addr, hs := range states {
				if hs.LastPing.Add(timeout).Before(now) {
					log.Println("Deleting handshake state", addr)
					hs.Zero()
					delete(states, addr)
				}
			}
			for addr, state := range peers {
				if state.peer.LastPing.Add(timeout).Before(now) {
					log.Println("Deleting peer", state.peer)
					delete(peers, addr)
					delete(knownPeers, addr)
					downPath := path.Join(
						govpn.PeersPath,
						state.peer.Id.String(),
						"down.sh",
					)
					go govpn.ScriptCall(downPath, state.tap.Name)
					state.terminate <- struct{}{}
					state.peer.Zero()
				}
			}
		case peerReady = <-peerReadySink:
			for addr, state := range peers {
				if state.tap.Name != peerReady.iface {
					continue
				}
				delete(peers, addr)
				delete(knownPeers, addr)
				state.terminate <- struct{}{}
				state.peer.Zero()
				break
			}
			addr = peerReady.peer.Addr.String()
			state := NewPeerState(peerReady.peer, peerReady.iface)
			if state == nil {
				continue
			}
			peers[addr] = state
			knownPeers[addr] = &peerReady.peer
			states[addr].Zero()
			delete(states, addr)
			log.Println("Registered interface", peerReady.iface, "with peer", peer)
			go func(state *PeerState) {
				for data := range state.sink {
					ethSink <- EthEvent{
						peer:  state.peer,
						data:  data,
						ready: state.ready,
					}
				}
			}(state)
		case ethEvent = <-ethSink:
			if s, exists := peers[ethEvent.peer.Addr.String()]; !exists || s.peer != ethEvent.peer {
				continue
			}
			ethEvent.peer.EthProcess(ethEvent.data, conn, ethEvent.ready)
		case udpPkt = <-udpSink:
			if udpPkt.Addr == nil {
				udpReady <- struct{}{}
				continue
			}
			addr = udpPkt.Addr.String()
			handshakeProcessForce = false
		HandshakeProcess:
			if _, exists = peers[addr]; handshakeProcessForce || !exists {
				peerId = govpn.IDsCache.Find(udpPkt.Data)
				if peerId == nil {
					log.Println("Unknown identity from", addr)
					udpReady <- struct{}{}
					continue
				}
				peerConf = peerId.Conf()
				if peerConf == nil {
					log.Println("Can not get peer configuration", peerId.String())
					udpReady <- struct{}{}
					continue
				}
				state, exists = states[addr]
				if !exists {
					state = govpn.HandshakeNew(udpPkt.Addr, peerConf)
					states[addr] = state
				}
				peer = state.Server(conn, udpPkt.Data)
				if peer != nil {
					log.Println("Peer handshake finished", peer)
					if _, exists = peers[addr]; exists {
						go func() {
							peerReadySink <- PeerReadyEvent{peer, peers[addr].tap.Name}
						}()
					} else {
						go func() {
							upPath := path.Join(govpn.PeersPath, peer.Id.String(), "up.sh")
							result, err := govpn.ScriptCall(upPath, "")
							if err != nil {
								return
							}
							sepIndex := bytes.Index(result, []byte{'\n'})
							if sepIndex < 0 {
								sepIndex = len(result)
							}
							ifaceName := string(result[:sepIndex])
							peerReadySink <- PeerReadyEvent{peer, ifaceName}
						}()
					}
				}
				if !handshakeProcessForce {
					udpReady <- struct{}{}
				}
				continue
			}
			peerState, exists = peers[addr]
			if !exists {
				udpReady <- struct{}{}
				continue
			}
			// If it fails during processing, then try to work with it
			// as with handshake packet
			if !peerState.peer.UDPProcess(udpPkt.Data, peerState.tap, udpReady) {
				handshakeProcessForce = true
				goto HandshakeProcess
			}
		}
	}
}
