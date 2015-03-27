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
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

var (
	MTU       int
	Timeout   int
	Noncediff int
	Version   string
)

// Call external program/script.
// You have to specify path to it and (inteface name as a rule) something
// that will be the first argument when calling it. Function will return
// it's output and possible error.
func ScriptCall(path, ifaceName string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		return nil, err
	}
	out, err := exec.Command(path, ifaceName).CombinedOutput()
	if err != nil {
		log.Println("Script error", path, err, string(out))
	}
	return out, err
}

// Read authentication key from the file.
// Key is 64 hexadecimal chars long.
func KeyRead(path string) *[KeySize]byte {
	keyData, err := ioutil.ReadFile(path)
	if err != nil {
		panic("Unable to read keyfile: " + err.Error())
	}
	if len(keyData) < 64 {
		panic("Key must be 64 hex characters long")
	}
	keyDecoded, err := hex.DecodeString(string(keyData[0:64]))
	if err != nil {
		panic("Unable to decode the key: " + err.Error())
	}
	key := new([KeySize]byte)
	copy(key[:], keyDecoded)
	return key
}

// Zero each byte
func sliceZero(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = '\x00'
	}
}
