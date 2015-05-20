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
	"bytes"
	"crypto/sha512"
	"io/ioutil"
	"log"
	"strings"

	"github.com/agl/ed25519"
	"golang.org/x/crypto/pbkdf2"
)

const (
	PBKDF2Iters = 1 << 16
)

// Create verifier from supplied password for given PeerId.
func NewVerifier(id *PeerId, password string) (*[ed25519.PublicKeySize]byte, *[ed25519.PrivateKeySize]byte) {
	r := pbkdf2.Key(
		[]byte(password),
		id[:],
		PBKDF2Iters,
		ed25519.PrivateKeySize,
		sha512.New,
	)
	defer sliceZero(r)
	src := bytes.NewBuffer(r)
	pub, priv, err := ed25519.GenerateKey(src)
	if err != nil {
		log.Fatalln("Unable to generate Ed25519 keypair", err)
	}
	return pub, priv
}

// Read string from the file, trimming newline.
func StringFromFile(path string) string {
	s, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalln("Can not read string from", path, err)
	}
	return strings.TrimRight(string(s), "\n")
}
