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
	"bytes"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"cypherpunks.ru/govpn"
)

type PeerState struct {
	peer       *govpn.Peer
	terminator chan struct{}
	tap        *govpn.TAP
}

// terminate asks the peer processing goroutine to stop.  The channel is
// buffered and the send never blocks: a peer may already be terminated
// (or terminating) concurrently.
func (ps *PeerState) terminate() {
	select {
	case ps.terminator <- struct{}{}:
	default:
	}
}

var (
	handshakes map[netip.AddrPort]*govpn.Handshake = make(map[netip.AddrPort]*govpn.Handshake)
	hsLock     sync.RWMutex

	peers     map[netip.AddrPort]*PeerState = make(map[netip.AddrPort]*PeerState)
	peersLock sync.RWMutex

	peersById     map[govpn.PeerId]netip.AddrPort = make(map[govpn.PeerId]netip.AddrPort)
	peersByIdLock sync.RWMutex

	knownPeers govpn.KnownPeers
	kpLock     sync.RWMutex

	// peersGeneration is bumped whenever the peer table changes, so
	// per-reader flow caches can be invalidated without taking locks
	// on every packet.
	peersGeneration atomic.Uint64
)

func peersChanged() { peersGeneration.Add(1) }

type flowCache struct {
	entries [256]struct {
		addr  netip.AddrPort
		ps    *PeerState
		stamp uint64
	}
}

// lookup returns the peer for addr, using a small direct-mapped cache.
// Cache entries are invalidated by peersGeneration, which is bumped on
// every peer-table mutation.
func (c *flowCache) lookup(addr netip.AddrPort) *PeerState {
	gen := peersGeneration.Load()
	e := &c.entries[addrHash(addr)%256]
	if e.stamp == gen && e.addr == addr {
		return e.ps
	}
	peersLock.RLock()
	ps := peers[addr]
	peersLock.RUnlock()
	e.addr = addr
	e.ps = ps
	e.stamp = gen
	return ps
}

// addrPortOf converts a net.Addr to an allocation-free comparable key.
func addrPortOf(n net.Addr) netip.AddrPort {
	switch a := n.(type) {
	case *net.UDPAddr:
		return a.AddrPort()
	case *net.TCPAddr:
		return a.AddrPort()
	}
	ap, err := netip.ParseAddrPort(n.String())
	if err != nil {
		log.Println("Unable to parse remote address", n, err)
		return netip.AddrPort{}
	}
	return ap
}

func peerReady(ps PeerState) {
	heartbeat := time.NewTicker(ps.peer.Timeout)
Processor:
	for {
		select {
		case <-heartbeat.C:
			ps.peer.EthProcess(nil)
		case <-ps.terminator:
			break Processor
		case data, ok := <-ps.tap.Sink:
			if !ok {
				break Processor
			}
			ps.peer.EthProcess(data)
		}
	}
	ps.peer.Zero()
	heartbeat.Stop()
}

func callUp(peerId *govpn.PeerId, remoteAddr string) (string, error) {
	conf := confGet(*peerId)
	if conf == nil {
		return "", errors.New("no configuration for peer")
	}
	ifaceName := conf.Iface
	if conf.Up != "" {
		result, err := govpn.ScriptCall(conf.Up, ifaceName, remoteAddr)
		if err != nil {
			log.Println("Script", conf.Up, "call failed", err)
			return "", err
		}
		if ifaceName == "" {
			sepIndex := bytes.Index(result, []byte{'\n'})
			if sepIndex < 0 {
				sepIndex = len(result)
			}
			ifaceName = string(result[:sepIndex])
		}
	}
	if ifaceName == "" {
		log.Println("Can not obtain interface name for", *peerId)
	}
	return ifaceName, nil
}
