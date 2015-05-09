package govpn

import (
	"encoding/json"
	"log"
	"net"
	"time"
)

const (
	RWTimeout = 10 * time.Second
)

type KnownPeers map[string]**Peer

// StatsProcessor is assumed to be run in background. It accepts
// connection on statsPort, reads anything one send to them and show
// information about known peers in serialized JSON format. peers
// argument is a reference to the map with references to the peers as
// values. Map is used here because of ease of adding and removing
// elements in it.
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
		var peersList []*Peer
		for _, peer := range *peers {
			peersList = append(peersList, *peer)
		}
		data, err = json.Marshal(peersList)
		if err != nil {
			panic(err)
		}
		conn.Write(data)
		conn.Close()
	}
}
