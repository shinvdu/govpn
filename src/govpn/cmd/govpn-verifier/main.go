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

// Verifier generator and validator for GoVPN VPN daemon.
package main

import (
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"govpn"
)

var (
	IDRaw        = flag.String("id", "", "Client identification")
	keyPath      = flag.String("key", "", "Path to passphrase file")
	verifierPath = flag.String("verifier", "", "Optional path to verifier")
)

func main() {
	flag.Parse()
	id, err := govpn.IDDecode(*IDRaw)
	if err != nil {
		log.Fatalln(err)
	}
	pub, _ := govpn.NewVerifier(id, govpn.StringFromFile(*keyPath))
	if *verifierPath == "" {
		fmt.Println(hex.EncodeToString(pub[:]))
	} else {
		verifier, err := hex.DecodeString(govpn.StringFromFile(*verifierPath))
		if err != nil {
			log.Fatalln("Can not decode verifier:", err)
		}
		fmt.Println(subtle.ConstantTimeCompare(verifier[:], pub[:]) == 1)
	}
}
