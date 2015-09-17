package main

import (
	"bytes"
	"path"
	"sync"
	"time"

	"govpn"
)

type PeerState struct {
	peer       *govpn.Peer
	terminator chan struct{}
	tap        *govpn.TAP
}

var (
	handshakes map[string]*govpn.Handshake = make(map[string]*govpn.Handshake)
	hsLock     sync.RWMutex

	peers     map[string]*PeerState = make(map[string]*PeerState)
	peersLock sync.RWMutex

	peersById     map[govpn.PeerId]string = make(map[govpn.PeerId]string)
	peersByIdLock sync.RWMutex

	knownPeers govpn.KnownPeers
	kpLock     sync.RWMutex
)

func peerReady(ps PeerState) {
	var data []byte
	heartbeat := time.NewTicker(ps.peer.Timeout)
Processor:
	for {
		select {
		case <-heartbeat.C:
			ps.peer.EthProcess(nil)
		case <-ps.terminator:
			break Processor
		case data = <-ps.tap.Sink:
			ps.peer.EthProcess(data)
		}
	}
	close(ps.terminator)
	ps.peer.Zero()
	heartbeat.Stop()
}

func callUp(peerId *govpn.PeerId) (string, error) {
	upPath := path.Join(govpn.PeersPath, peerId.String(), "up.sh")
	result, err := govpn.ScriptCall(upPath, "")
	if err != nil {
		return "", err
	}
	sepIndex := bytes.Index(result, []byte{'\n'})
	if sepIndex < 0 {
		sepIndex = len(result)
	}
	ifaceName := string(result[:sepIndex])
	return ifaceName, nil
}
