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
	"encoding/binary"
	"io"
	"log"
	"net"

	"govpn"
)

// TCPSender prepends size prefix to each outgoing packet.
type TCPSender struct {
	conn *net.TCPConn
}

func (c TCPSender) Write(data []byte) (int, error) {
	size := make([]byte, 2)
	binary.BigEndian.PutUint16(size, uint16(len(data)))
	return c.conn.Write(append(size, data...))
}

func startTCP() (io.Writer, chan []byte, chan struct{}) {
	remote, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		log.Fatalln("Can not resolve remote address:", err)
	}
	c, err := net.DialTCP("tcp", nil, remote)
	conn := TCPSender{c}
	if err != nil {
		log.Fatalln("Can not connect TCP:", err)
	}
	sink := make(chan []byte)
	ready := make(chan struct{})
	go handleTCP(c, sink, ready)
	go func() { ready <- struct{}{} }()
	return conn, sink, ready
}

func handleTCP(conn *net.TCPConn, sink chan []byte, ready chan struct{}) {
	var err error
	var n int
	var sizeNbuf int
	sizeBuf := make([]byte, 2)
	var sizeNeed uint16
	var bufN uint16
	buf := make([]byte, govpn.MTU)
	for {
		<-ready
		if sizeNbuf != 2 {
			n, err = conn.Read(sizeBuf[sizeNbuf:2])
			if err != nil {
				break
			}
			sizeNbuf += n
			if sizeNbuf != 2 {
				sink <- nil
				continue
			}
			sizeNeed = binary.BigEndian.Uint16(sizeBuf)
			if int(sizeNeed) > govpn.MTU-2 {
				log.Println("Invalid TCP size, skipping")
				sizeNbuf = 0
				sink <- nil
				continue
			}
			bufN = 0
		}
	ReadMore:
		if sizeNeed != bufN {
			n, err = conn.Read(buf[bufN:sizeNeed])
			if err != nil {
				break
			}
			bufN += uint16(n)
			goto ReadMore
		}
		sizeNbuf = 0
		sink <- buf[:sizeNeed]
	}
}
