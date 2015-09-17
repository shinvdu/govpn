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
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"time"

	"github.com/agl/ed25519"

	"govpn"
)

const (
	RefreshRate = time.Minute
)

var (
	confs    map[govpn.PeerId]*govpn.PeerConf
	idsCache govpn.CipherCache
)

func confRead() map[govpn.PeerId]*govpn.PeerConf {
	data, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Fatalln("Unable to read configuration:", err)
	}
	confsRaw := new(map[string]govpn.PeerConf)
	err = json.Unmarshal(data, confsRaw)
	if err != nil {
		log.Fatalln("Unable to parse configuration:", err)
	}

	confs := make(map[govpn.PeerId]*govpn.PeerConf, len(*confsRaw))
	for peerIdRaw, pc := range *confsRaw {
		peerId, err := govpn.IDDecode(peerIdRaw)
		if err != nil {
			log.Fatalln("Invalid peer ID:", peerIdRaw, err)
		}
		conf := govpn.PeerConf{
			Id:    peerId,
			Name:  pc.Name,
			Up:    pc.Up,
			Down:  pc.Down,
			Noise: pc.Noise,
			CPR:   pc.CPR,
		}
		if pc.TimeoutInt <= 0 {
			pc.TimeoutInt = govpn.TimeoutDefault
		}
		conf.Timeout = time.Second * time.Duration(pc.TimeoutInt)

		if len(pc.Verifier) != ed25519.PublicKeySize*2 {
			log.Fatalln("Verifier must be 64 hex characters long")
		}
		keyDecoded, err := hex.DecodeString(string(pc.Verifier))
		if err != nil {
			log.Fatalln("Unable to decode the key:", err.Error(), pc.Verifier)
		}
		conf.DSAPub = new([ed25519.PublicKeySize]byte)
		copy(conf.DSAPub[:], keyDecoded)

		confs[*peerId] = &conf
	}
	return confs
}

func confRefresh() {
	confs = confRead()
	ids := make([]govpn.PeerId, 0, len(confs))
	for peerId, _ := range confs {
		ids = append(ids, peerId)
	}
	idsCache.Update(ids)
}

func confInit() {
	idsCache = govpn.NewCipherCache(nil)
	confRefresh()
	go func() {
		for {
			time.Sleep(RefreshRate)
			confRefresh()
		}
	}()
}
