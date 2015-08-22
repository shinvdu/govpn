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
	"time"

	"govpn"
)

type UDPSender struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (c UDPSender) Write(data []byte) (int, error) {
	return c.conn.WriteToUDP(data, c.addr)
}

func startUDP() chan Pkt {
	bind, err := net.ResolveUDPAddr("udp", *bindAddr)
	ready := make(chan struct{})
	if err != nil {
		log.Fatalln("Can not resolve bind address:", err)
	}
	lconn, err := net.ListenUDP("udp", bind)
	if err != nil {
		log.Fatalln("Can not listen on UDP:", err)
	}
	sink := make(chan Pkt)
	go func() {
		buf := make([]byte, govpn.MTU)
		var n int
		var raddr *net.UDPAddr
		var err error
		for {
			<-ready
			lconn.SetReadDeadline(time.Now().Add(time.Second))
			n, raddr, err = lconn.ReadFromUDP(buf)
			if err != nil {
				sink <- Pkt{ready: ready}
				continue
			}
			sink <- Pkt{
				raddr.String(),
				UDPSender{lconn, raddr},
				buf[:n],
				ready,
			}
		}
	}()
	ready <- struct{}{}
	return sink
}
