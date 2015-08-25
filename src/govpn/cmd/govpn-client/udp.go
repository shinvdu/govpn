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
}

func (c UDPSender) Write(data []byte) (int, error) {
	return c.conn.Write(data)
}

func (c UDPSender) Reorderable() bool {
	return true
}

func startUDP() (govpn.RemoteConn, chan []byte, chan struct{}) {
	remote, err := net.ResolveUDPAddr("udp", *remoteAddr)
	if err != nil {
		log.Fatalln("Can not resolve remote address:", err)
	}
	c, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		log.Fatalln("Can not listen on UDP:", err)
	}
	sink := make(chan []byte)
	ready := make(chan struct{})
	go func() {
		buf := make([]byte, govpn.MTU)
		var n int
		var err error
		for {
			<-ready
			c.SetReadDeadline(time.Now().Add(time.Second))
			n, err = c.Read(buf)
			if err != nil {
				sink <- nil
				continue
			}
			sink <- buf[:n]
		}
	}()
	ready <- struct{}{}
	return UDPSender{c}, sink, ready
}
