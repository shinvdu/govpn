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
	"encoding/base64"
	"encoding/binary"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/xtea"
)

const (
	IDSize = 128 / 8
)

type PeerId [IDSize]byte

func (id PeerId) String() string {
	return base64.RawStdEncoding.EncodeToString(id[:])
}

func (id PeerId) MarshalJSON() ([]byte, error) {
	return []byte(`"` + id.String() + `"`), nil
}

type CipherAndTimeSync struct {
	id PeerId
	c  *xtea.Cipher
	t  int
}

type CipherCache struct {
	c    map[PeerId]*CipherAndTimeSync
	list []*CipherAndTimeSync
	l    sync.RWMutex
}

func NewCipherCache() *CipherCache {
	return &CipherCache{c: make(map[PeerId]*CipherAndTimeSync)}
}

// Remove disappeared keys, add missing ones with initialized ciphers.
func (cc *CipherCache) Update(peers *map[PeerId]*PeerConf) {
	cc.l.Lock()
	defer cc.l.Unlock()
	changed := false
	for pid := range cc.c {
		if _, exists := (*peers)[pid]; !exists {
			log.Println("Cleaning key:", pid)
			delete(cc.c, pid)
			changed = true
		}
	}
	for pid, pc := range *peers {
		if entry, exists := cc.c[pid]; exists {
			entry.t = pc.TimeSync
		} else {
			log.Println("Adding key", pid)
			cipher, err := xtea.NewCipher(pid[:])
			if err != nil {
				panic(err)
			}
			cc.c[pid] = &CipherAndTimeSync{id: pid, c: cipher, t: pc.TimeSync}
			changed = true
		}
	}
	if changed || cc.list == nil {
		// Keep a compact slice for cache-friendly sequential scans.
		cc.list = make([]*CipherAndTimeSync, 0, len(cc.c))
		for _, entry := range cc.c {
			cc.list = append(cc.list, entry)
		}
	}
}

// If timeSync > 0, then XOR timestamp with the data.
func AddTimeSync(ts int, data []byte) {
	if ts == 0 {
		return
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(time.Now().Unix()/int64(ts)*int64(ts)))
	for i := 0; i < 8; i++ {
		data[i] ^= buf[i]
	}
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
	for _, entry := range cc.list {
		entry.c.Decrypt(buf, data[len(data)-xtea.BlockSize:])
		AddTimeSync(entry.t, buf)
		if subtle.ConstantTimeCompare(buf, data[:xtea.BlockSize]) == 1 {
			ppid := entry.id
			cc.l.RUnlock()
			return &ppid
		}
	}
	cc.l.RUnlock()
	return nil
}
