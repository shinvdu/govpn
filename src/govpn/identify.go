/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2016 Sergey Matveev <stargrave@stargrave.org>

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
	"crypto/subtle"
	"encoding/hex"
	"log"
	"sync"

	"golang.org/x/crypto/xtea"
)

const (
	IDSize = 128 / 8
)

type PeerId [IDSize]byte

func (id PeerId) String() string {
	return hex.EncodeToString(id[:])
}

func (id PeerId) MarshalJSON() ([]byte, error) {
	return []byte(`"` + id.String() + `"`), nil
}

type CipherCache struct {
	c map[PeerId]*xtea.Cipher
	l sync.RWMutex
}

func NewCipherCache(peerIds []PeerId) *CipherCache {
	cc := CipherCache{c: make(map[PeerId]*xtea.Cipher, len(peerIds))}
	cc.Update(peerIds)
	return &cc
}

// Remove disappeared keys, add missing ones with initialized ciphers.
func (cc *CipherCache) Update(peerIds []PeerId) {
	available := make(map[PeerId]struct{})
	for _, peerId := range peerIds {
		available[peerId] = struct{}{}
	}
	cc.l.Lock()
	for k, _ := range cc.c {
		if _, exists := available[k]; !exists {
			log.Println("Cleaning key:", k)
			delete(cc.c, k)
		}
	}
	for peerId, _ := range available {
		if _, exists := cc.c[peerId]; !exists {
			log.Println("Adding key", peerId)
			cipher, err := xtea.NewCipher(peerId[:])
			if err != nil {
				panic(err)
			}
			cc.c[peerId] = cipher
		}
	}
	cc.l.Unlock()
}

// Try to find peer's identity (that equals to an encryption key)
// by taking first blocksize sized bytes from data at the beginning
// as plaintext and last bytes as cyphertext.
func (cc *CipherCache) Find(data []byte) *PeerId {
	if len(data) < xtea.BlockSize*2 {
		return nil
	}
	buf := make([]byte, xtea.BlockSize)
	cc.l.RLock()
	for pid, cipher := range cc.c {
		cipher.Decrypt(buf, data[len(data)-xtea.BlockSize:])
		if subtle.ConstantTimeCompare(buf, data[:xtea.BlockSize]) == 1 {
			ppid := PeerId(pid)
			cc.l.RUnlock()
			return &ppid
		}
	}
	cc.l.RUnlock()
	return nil
}
