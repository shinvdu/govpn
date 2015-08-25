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
	proto     = flag.String("proto", "udp", "Protocol to use: udp, tcp or all")
	peersPath = flag.String("peers", "peers", "Path to peers keys directory")
	stats     = flag.String("stats", "", "Enable stats retrieving on host:port")
	proxy     = flag.String("proxy", "", "Enable HTTP proxy on host:port")
	mtu       = flag.Int("mtu", 1452, "MTU for outgoing packets")
	egdPath   = flag.String("egd", "", "Optional path to EGD socket")
)

type Pkt struct {
	addr  string
	conn  govpn.RemoteConn
	data  []byte
	ready chan struct{}
}

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
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)
	log.Println(govpn.VersionGet())

	govpn.MTU = *mtu
	govpn.PeersInit(*peersPath)

	if *egdPath != "" {
		log.Println("Using", *egdPath, "EGD")
		govpn.EGDInit(*egdPath)
	}

	sink := make(chan Pkt)
	switch *proto {
	case "udp":
		startUDP(sink)
	case "tcp":
		startTCP(sink)
	case "all":
		startUDP(sink)
		startTCP(sink)
	default:
		log.Fatalln("Unknown protocol specified")
	}

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)

	hsHeartbeat := time.Tick(timeout)
	go func() { <-hsHeartbeat }()

	var state *govpn.Handshake
	var peerState *PeerState
	var peer *govpn.Peer
	var exists bool
	states := make(map[string]*govpn.Handshake)
	peers := make(map[string]*PeerState)
	peerReadySink := make(chan PeerReadyEvent)
	knownPeers := govpn.KnownPeers(make(map[string]**govpn.Peer))
	var peerReady PeerReadyEvent
	var pkt Pkt
	var ethEvent EthEvent
	var peerId *govpn.PeerId
	var peerConf *govpn.PeerConf
	var handshakeProcessForce bool
	ethSink := make(chan EthEvent)

	log.Println("Max MTU on TAP interface:", govpn.TAPMaxMTU())
	if *stats != "" {
		log.Println("Stats are going to listen on", *stats)
		statsPort, err := net.Listen("tcp", *stats)
		if err != nil {
			log.Fatalln("Can not listen on stats port:", err)
		}
		go govpn.StatsProcessor(statsPort, &knownPeers)
	}
	if *proxy != "" {
		go proxyStart(sink)
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
			state := NewPeerState(peerReady.peer, peerReady.iface)
			if state == nil {
				continue
			}
			peers[peerReady.peer.Addr] = state
			knownPeers[peerReady.peer.Addr] = &peerReady.peer
			states[peerReady.peer.Addr].Zero()
			delete(states, peerReady.peer.Addr)
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
			if s, exists := peers[ethEvent.peer.Addr]; !exists || s.peer != ethEvent.peer {
				continue
			}
			ethEvent.peer.EthProcess(ethEvent.data, ethEvent.ready)
		case pkt = <-sink:
			if pkt.data == nil {
				pkt.ready <- struct{}{}
				continue
			}
			handshakeProcessForce = false
		HandshakeProcess:
			if _, exists = peers[pkt.addr]; handshakeProcessForce || !exists {
				peerId = govpn.IDsCache.Find(pkt.data)
				if peerId == nil {
					log.Println("Unknown identity from", pkt.addr)
					pkt.ready <- struct{}{}
					continue
				}
				peerConf = peerId.Conf()
				if peerConf == nil {
					log.Println("Can not get peer configuration", peerId.String())
					pkt.ready <- struct{}{}
					continue
				}
				state, exists = states[pkt.addr]
				if !exists {
					state = govpn.HandshakeNew(pkt.addr, pkt.conn, peerConf)
					states[pkt.addr] = state
				}
				peer = state.Server(pkt.data)
				if peer != nil {
					log.Println("Peer handshake finished", peer)
					if _, exists = peers[pkt.addr]; exists {
						go func() {
							peerReadySink <- PeerReadyEvent{
								peer, peers[pkt.addr].tap.Name,
							}
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
					pkt.ready <- struct{}{}
				}
				continue
			}
			peerState, exists = peers[pkt.addr]
			if !exists {
				pkt.ready <- struct{}{}
				continue
			}
			// If it fails during processing, then try to work with it
			// as with handshake packet
			if !peerState.peer.PktProcess(pkt.data, peerState.tap, pkt.ready) {
				handshakeProcessForce = true
				goto HandshakeProcess
			}
		}
	}
}
