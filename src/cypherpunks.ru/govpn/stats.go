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

package govpn

import (
	"encoding/json"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	RWTimeout = 10 * time.Second
)

// KnownPeers is a concurrency-safe set of peers exposed through the
// stats endpoint.
type KnownPeers struct {
	l sync.RWMutex
	m map[string]*Peer
}

func NewKnownPeers() *KnownPeers {
	return &KnownPeers{m: make(map[string]*Peer)}
}

func (kp *KnownPeers) Set(addr string, peer *Peer) {
	kp.l.Lock()
	kp.m[addr] = peer
	kp.l.Unlock()
}

func (kp *KnownPeers) Delete(addr string) {
	kp.l.Lock()
	delete(kp.m, addr)
	kp.l.Unlock()
}

func (kp *KnownPeers) Snapshot() []*Peer {
	if kp == nil {
		return nil
	}
	kp.l.RLock()
	list := make([]*Peer, 0, len(kp.m))
	for _, peer := range kp.m {
		if peer != nil {
			list = append(list, peer)
		}
	}
	kp.l.RUnlock()
	return list
}

// PeerStats is a point-in-time snapshot of a peer's observable fields,
// taken under both peer locks so that the stats endpoint never races
// with the packet paths.
type PeerStats struct {
	BytesIn         uint64
	BytesOut        uint64
	BytesPayloadIn  uint64
	BytesPayloadOut uint64
	FramesIn        uint64
	FramesOut       uint64
	FramesUnauth    uint64
	FramesDup       uint64
	HeartbeatRecv   uint64
	HeartbeatSent   uint64

	Addr        string
	Id          *PeerId
	NoiseEnable bool
	CPR         int
	Encless     bool
	MTU         int

	Established time.Time
	LastPing    time.Time
	LastSent    time.Time
}

func (p *Peer) statsSnapshot() *PeerStats {
	p.BusyT.Lock()
	p.BusyR.Lock()
	s := &PeerStats{
		BytesIn:         atomic.LoadUint64(&p.BytesIn),
		BytesOut:        atomic.LoadUint64(&p.BytesOut),
		BytesPayloadIn:  p.BytesPayloadIn,
		BytesPayloadOut: p.BytesPayloadOut,
		FramesIn:        p.FramesIn,
		FramesOut:       p.FramesOut,
		FramesUnauth:    p.FramesUnauth,
		FramesDup:       p.FramesDup,
		HeartbeatRecv:   p.HeartbeatRecv,
		HeartbeatSent:   p.HeartbeatSent,
		Addr:            p.Addr,
		Id:              p.Id,
		NoiseEnable:     p.NoiseEnable,
		CPR:             p.CPR,
		Encless:         p.Encless,
		MTU:             p.MTU,
		Established:     p.Established,
		LastPing:        p.LastPing,
		LastSent:        p.LastSent,
	}
	p.BusyR.Unlock()
	p.BusyT.Unlock()
	return s
}

// StatsProcessor is assumed to be run in background. It accepts
// connection on statsPort, reads anything one send to them and show
// information about known peers in serialized JSON format.
func StatsProcessor(statsPort net.Listener, peers *KnownPeers) {
	var conn net.Conn
	var err error
	var data []byte
	buf := make([]byte, 2<<8)
	for {
		conn, err = statsPort.Accept()
		if err != nil {
			log.Println("Error during accepting connection", err.Error())
			continue
		}
		conn.SetDeadline(time.Now().Add(RWTimeout))
		conn.Read(buf)
		conn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n"))
		peerList := peers.Snapshot()
		stats := make([]*PeerStats, 0, len(peerList))
		for _, peer := range peerList {
			if peer != nil {
				stats = append(stats, peer.statsSnapshot())
			}
		}
		data, err = json.Marshal(stats)
		if err != nil {
			panic(err)
		}
		conn.Write(data)
		conn.Close()
	}
}
