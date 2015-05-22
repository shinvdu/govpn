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
	"errors"
	"net"
)

var (
	egdPath string
)

func EGDInit(path string) {
	egdPath = path
}

// Read n bytes from EGD, blocking mode.
func EGDRead(b []byte) error {
	c, err := net.Dial("unix", egdPath)
	if err != nil {
		return err
	}
	defer c.Close()
	c.Write([]byte{0x02, byte(len(b))})
	r, err := c.Read(b)
	if err != nil {
		return err
	}
	if r != len(b) {
		return errors.New("Got less bytes than expected from EGD")
	}
	return nil
}
