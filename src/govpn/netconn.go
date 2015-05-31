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

package govpn

import (
	"net"
	"time"
)

type UDPPkt struct {
	Addr *net.UDPAddr
	Data []byte
}

// Create UDP listening goroutine.
// This function takes already listening UDP socket and a buffer where
// all UDP packet data will be saved, channel where information about
// remote address and number of written bytes are stored, and a channel
// used to tell that buffer is ready to be overwritten.
func ConnListenUDP(conn *net.UDPConn) (chan UDPPkt, chan struct{}) {
	buf := make([]byte, MTU)
	sink := make(chan UDPPkt)
	sinkReady := make(chan struct{})
	go func(conn *net.UDPConn) {
		var n int
		var addr *net.UDPAddr
		var err error
		for {
			<-sinkReady
			conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err = conn.ReadFromUDP(buf)
			if err != nil {
				// This is needed for ticking the timeouts counter outside
				sink <- UDPPkt{nil, nil}
				continue
			}
			sink <- UDPPkt{addr, buf[:n]}
		}
	}(conn)
	sinkReady <- struct{}{}
	return sink, sinkReady
}
